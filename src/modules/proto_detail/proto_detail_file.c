/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file proto_detail_file.c
 * @brief Detail handler for files
 *
 * @copyright 2017 The FreeRADIUS server project.
 * @copyright 2017 Alan DeKok (aland@deployingradius.com)
 */

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>

#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>

#include "proto_detail.h"

#include <netdb.h>

#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_GLOB_H
#include <glob.h>
#else
#error proto_detail_file requires <glob.h>
#endif

DIAG_OFF(unused-macros)
#if 0
/*
 *	When we want detailed debugging here, without detailed server
 *	debugging.
 */
#define MPRINT DEBUG
#else
#define MPRINT DEBUG3
#endif
DIAG_ON(unused-macros)

/*
 *	For talloc names, ".name = detail_file", and dl.c prepends "proto_", and appends "_t".
 */
typedef struct proto_detail_work_s proto_detail_file_t;

/*
 *	@todo - this should really now be a different data structure
 */
typedef struct proto_detail_work_thread_s proto_detail_file_thread_t;

static void work_init(proto_detail_file_thread_t *thread);
static void mod_vnode_delete(fr_event_list_t *el, int fd, UNUSED int fflags, void *ctx);

static const CONF_PARSER file_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_file_t, filename ) },

	{ FR_CONF_OFFSET("filename_work", FR_TYPE_STRING, proto_detail_file_t, filename_work ) },

	{ FR_CONF_OFFSET("poll_interval", FR_TYPE_UINT32, proto_detail_file_t, poll_interval), .dflt = "5" },

	{ FR_CONF_OFFSET("immediate", FR_TYPE_BOOL, proto_detail_file_t, immediate) },

	CONF_PARSER_TERMINATOR
};


/*
 *	All of the decoding is done by proto_detail and proto_detail_work
 */
static int mod_decode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	proto_detail_file_t const     	*inst = talloc_get_type_abort_const(instance, proto_detail_file_t);

	return inst->parent->work_io->decode(inst->parent->work_io_instance, request, data, data_len);
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_detail_file_thread_t  *thread = talloc_get_type_abort(li->thread_instance, proto_detail_file_thread_t);

	return thread->listen->app_io->write(thread->listen, packet_ctx, request_time, buffer, buffer_len, written);
}

static void mod_vnode_extend(fr_listen_t *li, UNUSED uint32_t fflags)
{
	proto_detail_file_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_file_thread_t);

	bool has_worker = false;

	pthread_mutex_lock(&thread->worker_mutex);
	has_worker = (thread->num_workers != 0);
	pthread_mutex_unlock(&thread->worker_mutex);

	if (has_worker) return;

	if (thread->ev) fr_event_timer_delete(&thread->ev);

	work_init(thread);
}

/** Open a detail listener
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_detail_file_t const  *inst = talloc_get_type_abort_const(li->app_io_instance, proto_detail_file_t);
	proto_detail_file_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_file_thread_t);

	if (inst->poll_interval == 0) {
		int oflag;

#ifdef O_EVTONLY
		oflag = O_EVTONLY;
#else
		oflag = O_RDONLY;
#endif
		li->fd = thread->fd = open(inst->directory, oflag);
	} else {
		li->fd = thread->fd = open("/dev/null", O_RDONLY);
	}
	if (thread->fd < 0) {
		cf_log_err(inst->cs, "Failed opening %s: %s", inst->directory, fr_syserror(errno));
		return -1;
	}

	thread->inst = inst;
	thread->name = talloc_typed_asprintf(thread, "detail_file polling for files matching %s", inst->filename);
	thread->vnode_fd = -1;
	pthread_mutex_init(&thread->worker_mutex, NULL);

	return 0;
}

/*
 *	The "detail.work" file doesn't exist.  Let's see if we can rename one.
 */
static int work_rename(proto_detail_file_thread_t *thread)
{
	proto_detail_file_t const *inst = thread->inst;
	unsigned int	i;
	int		found;
	time_t		chtime;
	char const	*filename;
	glob_t		files;
	struct stat	st;

	DEBUG3("proto_detail (%s): polling for detail files in %s",
	       thread->name, inst->directory);

	memset(&files, 0, sizeof(files));
	if (glob(inst->filename, 0, NULL, &files) != 0) {
	noop:
		DEBUG3("proto_detail (%s): no matching files for %s",
		       thread->name, inst->filename);
		globfree(&files);
		return -1;
	}

	/*
	 *	Loop over the glob'd files, looking for the
	 *	oldest one.
	 */
	chtime = 0;
	found = -1;
	for (i = 0; i < files.gl_pathc; i++) {
		if (stat(files.gl_pathv[i], &st) < 0) continue;

		if ((i == 0) || (st.st_ctime < chtime)) {
			chtime = st.st_ctime;
			found = i;
		}
	}

	/*
	 *	No matching files, reset the timer and continue.
	 */
	if (found < 0) goto noop;

	/*
	 *	Rename detail to detail.work
	 */
	filename = files.gl_pathv[found];

	DEBUG("proto_detail (%s): Renaming %s -> %s", thread->name, filename, inst->filename_work);
	if (rename(filename, inst->filename_work) < 0) {
		ERROR("detail (%s): Failed renaming %s to %s: %s",
		      thread->name, filename, inst->filename_work, fr_syserror(errno));
		goto noop;
	}

	globfree(&files);	/* Shouldn't be using anything in files now */

	/*
	 *	The file should now exist, return the open'd FD.
	 */
	return open(inst->filename_work, inst->mode);
}

/*
 *	Start polling again after a timeout.
 */
static void work_retry_timer(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	proto_detail_file_thread_t *thread = talloc_get_type_abort(uctx, proto_detail_file_thread_t);

	work_init(thread);
}

/*
 *	The "detail.work" file exists, and is open in the 'fd'.
 */
static int work_exists(proto_detail_file_thread_t *thread, int fd)
{
	proto_detail_file_t const *inst = thread->inst;
	bool			opened = false;
	proto_detail_work_thread_t     *work;
	fr_listen_t		*li = NULL;
	struct stat		st;

	fr_event_vnode_func_t	funcs = { .delete = mod_vnode_delete };

	DEBUG3("proto_detail (%s): Trying to lock %s", thread->name, inst->filename_work);

	/*
	 *	"detail.work" exists, try to lock it.
	 */
	if (rad_lockfd_nonblock(fd, 0) < 0) {
		fr_time_t delay;

		DEBUG3("proto_detail (%s): Failed locking %s: %s",
		       thread->name, inst->filename_work, fr_syserror(errno));

		close(fd);

		delay = thread->lock_interval;

		/*
		 *	Set the next interval, and ensure that we
		 *	don't do massive busy-polling.
		 */
		thread->lock_interval += thread->lock_interval / 2;
		if (thread->lock_interval > ((fr_time_delta_t) 30) * NSEC) thread->lock_interval = ((fr_time_delta_t) 30) * NSEC;

		DEBUG3("proto_detail (%s): Waiting %d.%06ds for lock on file %s",
		       thread->name, (int) (delay / NSEC), (int) ((delay % NSEC) / 1000), inst->filename_work);

		if (fr_event_timer_in(thread, thread->el, &thread->ev,
				      delay, work_retry_timer, thread) < 0) {
			ERROR("Failed inserting retry timer for %s", inst->filename_work);
		}
		return 0;
	}

	DEBUG3("proto_detail (%s): Obtained lock and starting to process file %s",
	       thread->name, inst->filename_work);

	/*
	 *	Ignore empty files.
	 */
	if (fstat(fd, &st) < 0) {
		ERROR("Failed opening %s: %s", inst->filename_work,
		      fr_syserror(errno));
		unlink(inst->filename_work);
		close(fd);
		return 1;
	}

	if (!st.st_size) {
		DEBUG3("proto_detail (%s): %s file is empty, ignoring it.",
		       thread->name, inst->filename_work);
		unlink(inst->filename_work);
		close(fd);
		return 1;
	}

	/*
	 *	This listener is allocated in a thread-specific
	 *	context, so it doesn't need a destructor,
	 */
	MEM(li = talloc_zero(NULL, fr_listen_t));

	/*
	 *	Create a new listener, and insert it into the
	 *	scheduler.  Shamelessly copied from proto_detail.c
	 *	mod_open(), with changes.
	 *
	 *	This listener is parented from the worker.  So that
	 *	when the worker goes away, so does the listener.
	 */
	li->app_io = inst->parent->work_io;

	li->app = inst->parent->self;
	li->app_instance = inst->parent;
	li->server_cs = inst->parent->server_cs;

	/*
	 *	The worker may be in a different thread, so avoid
	 *	talloc threading issues by using a NULL TALLOC_CTX.
	 */
	MEM(li->thread_instance = work = talloc_zero(li, proto_detail_work_thread_t));

	li->app_io_instance = inst->parent->work_io_instance;
	work->inst = li->app_io_instance;
	work->file_parent = thread;
	work->ev = NULL;

	li->fd = work->fd = dup(fd);
	if (work->fd < 0) {
		DEBUG("proto_detail (%s): Failed opening %s: %s",
		      thread->name, inst->filename_work, fr_syserror(errno));

		close(fd);
		talloc_free(li);
		return -1;
	}

	/*
	 *	Don't do anything until the file has been deleted.
	 *
	 *	@todo - ensure that proto_detail_work is done the file...
	 *	maybe by creating a new instance?
	 */
	if (fr_event_filter_insert(thread, NULL, thread->el, fd, FR_EVENT_FILTER_VNODE,
				   &funcs, NULL, thread) < 0) {
		PERROR("Failed adding work socket to event loop");
		close(fd);
		talloc_free(li);
		return -1;
	}

	/*
	 *	Remember this for later.
	 */
	thread->vnode_fd = fd;

	/*
	 *	For us, this is the worker listener.
	 *	For the worker, this is it's own parent
	 */
	thread->listen = li;

	work->filename_work = talloc_strdup(work, inst->filename_work);

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = inst->parent->max_packet_size;
	li->num_messages = inst->parent->num_messages;

	pthread_mutex_lock(&thread->worker_mutex);
	thread->num_workers++;
	pthread_mutex_unlock(&thread->worker_mutex);

	/*
	 *	Open the detail.work file.
	 */
	if (li->app_io->open(li) < 0) {
		ERROR("Failed opening %s", li->app_io->name);
		goto error;
	}
	opened = true;

	fr_assert(li->app_io->get_name);
	li->name = li->app_io->get_name(li);

	if (!fr_schedule_listen_add(inst->parent->sc, li)) {
	error:
		if (fr_event_fd_delete(thread->el, thread->vnode_fd, FR_EVENT_FILTER_VNODE) < 0) {
			PERROR("Failed removing DELETE callback when opening work file");
		}
		close(thread->vnode_fd);
		thread->vnode_fd = -1;

		if (opened) {
			(void) li->app_io->close(li);
			thread->listen = NULL;
			li = NULL;
		}

		talloc_free(li);
		return -1;
	}

	/*
	 *	Tell the worker to clean itself up.
	 */
	work->listen = li;

	return 0;
}


static void mod_vnode_delete(fr_event_list_t *el, int fd, UNUSED int fflags, void *ctx)
{
	proto_detail_file_thread_t *thread = talloc_get_type_abort(ctx, proto_detail_file_thread_t);
	proto_detail_file_t const *inst = thread->inst;

	DEBUG("proto_detail (%s): Deleted %s", thread->name, inst->filename_work);

	/*
	 *	Silently ignore notifications from the directory.  We
	 *	didn't ask for them, but libkqueue delivers them to
	 *	us.
	 */
	if (fd == thread->fd) return;

	if (fd != thread->vnode_fd) {
		ERROR("Received DELETE for FD %d, when we were expecting one on FD %d - ignoring it",
		      fd, thread->vnode_fd);
		return;
	}

	if (fr_event_fd_delete(el, fd, FR_EVENT_FILTER_VNODE) < 0) {
		PERROR("Failed removing DELETE callback after deletion");
	}
	close(fd);
	thread->vnode_fd = -1;

	/*
	 *	Re-initialize the state machine.
	 *
	 *	Note that a "delete" may be the result of an atomic
	 *	"move", which both deletes the old file, and creates
	 *	the new one.
	 */
	work_init(thread);
}


static void work_init(proto_detail_file_thread_t *thread)
{
	proto_detail_file_t const *inst = thread->inst;
	int fd, rcode;
	bool has_worker;

	pthread_mutex_lock(&thread->worker_mutex);
	has_worker = (thread->num_workers != 0);
	pthread_mutex_unlock(&thread->worker_mutex);

	/*
	 *	The worker is still processing the file, poll until
	 *	it's done.
	 */
	if (has_worker) {
		DEBUG3("proto_detail (%s): worker %s is still alive, waiting for it to finish.",
		       thread->name, inst->filename_work);
		goto delay;
	}

	fr_assert(thread->vnode_fd < 0);

	/*
	 *	See if there is a "detail.work" file.  If not, try to
	 *	rename an existing file to "detail.work".
	 */
	DEBUG3("Trying to open %s", inst->filename_work);
	fd = open(inst->filename_work, inst->mode);

	/*
	 *	If the work file didn't exist, try to rename detail* ->
	 *	detail.work, and return the newly opened file.
	 */
	if (fd < 0) {
		if (errno != ENOENT) {
			DEBUG("proto_detail (%s): Failed opening %s: %s",
			      thread->name, inst->filename_work,
			      fr_syserror(errno));
			goto delay;
		}

retry:
		fd = work_rename(thread);
	}

	/*
	 *	The work file still doesn't exist.  Go set up timers,
	 *	or wait for an event which signals us that something
	 *	in the directory changed.
	 */
	if (fd < 0) {
		/*
		 *	Wait for the directory to change before
		 *	looking for another "detail" file.
		 */
		if (!inst->poll_interval) return;

delay:
		/*
		 *	Check every N seconds.
		 */
		DEBUG3("Waiting %d.000000s for new files in %s", inst->poll_interval, thread->name);

		if (fr_event_timer_in(thread, thread->el, &thread->ev,
				      fr_time_delta_from_sec(inst->poll_interval), work_retry_timer, thread) < 0) {
			ERROR("Failed inserting poll timer for %s", inst->filename_work);
		}
		return;
	}

	thread->lock_interval = NSEC / 10;

	/*
	 *	It exists, go process it!
	 *
	 *	We will get back to the main loop when the
	 *	"detail.work" file is deleted.
	 */
	rcode = work_exists(thread, fd);
	if (rcode < 0) goto delay;

	/*
	 *	The file was empty, so we try to get another one.
	 */
	if (rcode == 1) goto retry;

	/*
	 *	Otherwise the child is successfully processing the
	 *	file.
	 */
}


/** Set the event list for a new IO instance
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, UNUSED void *nr)
{
	proto_detail_file_t const  *inst = talloc_get_type_abort_const(li->app_io_instance, proto_detail_file_t);
	proto_detail_file_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_file_thread_t);

	thread->el = el;

	if (inst->immediate) {
		work_init(thread);
		return;
	}

	/*
	 *	Delay for a bit, before reading the detail files.
	 *	This gives the server time to call
	 *	rad_suid_down_permanent(), and for /proc/PID to
	 *	therefore change permissions, so that libkqueue can
	 *	read it.
	 */
	if (fr_event_timer_in(thread, thread->el, &thread->ev,
			      fr_time_delta_from_sec(1), work_retry_timer, thread) < 0) {
		ERROR("Failed inserting poll timer for %s", thread->filename_work);
	}
}


static char const *mod_name(fr_listen_t *li)
{
	proto_detail_file_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_file_thread_t);

	return thread->name;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);
	dl_module_inst_t const	*dl_inst;
	char			*p;

#ifdef __linux__
	/*
	 *	The kqueue API takes an FD, but inotify requires a filename.
	 *	libkqueue uses /proc/PID/fd/# to look up the FD -> filename mapping.
	 *
	 *	However, if you start the server as "root", and then swap to "radiusd",
	 *	/proc/PID will be owned by "root" for security reasons.  The only way
	 *	to make /proc/PID owned by "radiusd" is to set the DUMPABLE flag.
	 *
	 *	Instead of making the poor sysadmin figure this out,
	 *	we check for this situation, and give them a
	 *	descriptive message telling them what to do.
	 */
	if (!main_config->allow_core_dumps &&
	    main_config->uid_is_set &&
	    main_config->server_uid != 0) {
		cf_log_err(cs, "Cannot start detail file reader due to Linux limitations.");
		cf_log_err(cs, "Please set 'allow_core_dumps = true' in the main configuration file.");
		return -1;
	}
#endif

	/*
	 *	Find the dl_module_inst_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_module_instance_by_data(instance);
	fr_assert(dl_inst);

#ifndef __linux__
	/*
	 *	Linux inotify works.  So we allow poll_interval==0
	 */
	FR_INTEGER_BOUND_CHECK("poll_interval", inst->poll_interval, >=, 1);
#endif
	FR_INTEGER_BOUND_CHECK("poll_interval", inst->poll_interval, <=, 3600);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_detail_t);
	inst->cs = cs;

	inst->directory = p = talloc_strdup(inst, inst->filename);

	p = strrchr(p, '/');
	if (!p) {
		cf_log_err(cs, "Filename must contain '/'");
		return -1;
	}

	*p = '\0';

	if (!inst->filename_work) {
		inst->filename_work = talloc_typed_asprintf(inst, "%s/detail.work", inst->directory);
	}

	/*
	 *	We need this for the lock.
	 */
	inst->mode = O_RDWR;

	return 0;
}

static int mod_close(fr_listen_t *li)
{
	proto_detail_file_t const  *inst = talloc_get_type_abort_const(li->app_io_instance, proto_detail_file_t);
	proto_detail_file_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_file_thread_t);

	if (thread->nr) (void) fr_network_socket_delete(thread->nr, inst->parent->listen);

	/*
	 *	@todo - have our OWN event loop for timers, and a
	 *	"copy timer from -> to, which means we only have to
	 *	delete our child event loop from the parent on close.
	 */
	close(thread->fd);

	if (thread->vnode_fd >= 0) {
		if (thread->nr) {
			(void) fr_network_socket_delete(thread->nr, inst->parent->listen);
		} else {
			if (fr_event_fd_delete(thread->el, thread->vnode_fd, FR_EVENT_FILTER_VNODE) < 0) {
				PERROR("Failed removing DELETE callback on detach");
			}
		}
		close(thread->vnode_fd);
		thread->vnode_fd = -1;

		pthread_mutex_destroy(&thread->worker_mutex);
	}

	return 0;
}


/** Private interface for use by proto_detail_file
 *
 */
extern fr_app_io_t proto_detail_file;
fr_app_io_t proto_detail_file = {
	.magic			= RLM_MODULE_INIT,
	.name			= "detail_file",
	.config			= file_listen_config,
	.inst_size		= sizeof(proto_detail_file_t),
	.thread_inst_size	= sizeof(proto_detail_file_thread_t),
	.bootstrap		= mod_bootstrap,

	.default_message_size	= 65536,
	.default_reply_size	= 32,

	.open			= mod_open,
	.close			= mod_close,
	.vnode			= mod_vnode_extend,
	.decode			= mod_decode,
	.write			= mod_write,
	.event_list_set		= mod_event_list_set,
	.get_name		= mod_name,
};
