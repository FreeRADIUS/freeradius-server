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
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_detail.h"

#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_GLOB_H
#include <glob.h>
#else
#error proto_detail_file requires <glob.h>
#endif

#if 0
/*
 *	When we want detailed debugging here, without detailed server
 *	debugging.
 */
#define MPRINT DEBUG
#else
#define MPRINT DEBUG3
#endif

/*
 *	For talloc names, ".name = detail_file", and dl.c prepends "proto_", and appends "_t".
 */
typedef struct proto_detail_work_t proto_detail_file_t;

static void work_init(proto_detail_file_t *inst);
static void mod_vnode_delete(fr_event_list_t *el, int fd, UNUSED int fflags, void *ctx);

static const CONF_PARSER file_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_file_t, filename ) },

	{ FR_CONF_OFFSET("filename.work", FR_TYPE_STRING, proto_detail_work_t, filename_work ) },

	{ FR_CONF_OFFSET("track", FR_TYPE_BOOL, proto_detail_file_t, track_progress ) },

	{ FR_CONF_OFFSET("poll_interval", FR_TYPE_UINT32, proto_detail_file_t, poll_interval ) },

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

static ssize_t mod_write(void *instance, void *packet_ctx,
			 fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_detail_file_t const     	*inst = talloc_get_type_abort_const(instance, proto_detail_file_t);

	return inst->parent->work_io->write(inst->parent->work_io_instance, packet_ctx, request_time, buffer, buffer_len);
}

static void mod_vnode_extend(void *instance, UNUSED uint32_t fflags)
{
	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);

	DEBUG("Directory %s changed", inst->directory);

	/*
	 *	@todo - troll for detail.work file.  Allocate new
	 *	proto_detail_work_t, fill it in, and start up the new
	 *	detail worker.
	 */
}

/** Open a detail listener
 *
 * @param[in] instance of the detail worker.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);
	int oflag;

#ifdef O_EVTONLY
	oflag = O_EVTONLY;
#else
	oflag = O_RDONLY;
#endif

	inst->fd = open(inst->directory, oflag);
	if (inst->fd < 0) {
		cf_log_err(inst->cs, "Failed opening %s: %s", inst->directory, fr_syserror(errno));
		return -1;
	}

	rad_assert(inst->name == NULL);
	inst->name = talloc_asprintf(inst, "detail directory %s", inst->directory);

	DEBUG("Listening on %s bound to virtual server %s FD %d",
	      inst->name, cf_section_name2(inst->parent->server_cs), inst->fd);

	return 0;
}

/** Get the file descriptor for this IO instance
 *
 * @param[in] instance of the detail worker
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_detail_file_t const *inst = talloc_get_type_abort_const(instance, proto_detail_file_t);

	return inst->fd;
}

/*
 *	The "detail.work" file doesn't exist.  Let's see if we can rename one.
 */
static int work_rename(proto_detail_file_t *inst)
{
	unsigned int	i;
	int		found;
	time_t		chtime;
	char const	*filename;
	glob_t		files;
	struct stat	st;

	DEBUG2("proto_detail (%s): polling for detail files in %s",
	       inst->name, inst->directory);

	memset(&files, 0, sizeof(files));
	if (glob(inst->filename, 0, NULL, &files) != 0) {
	noop:
		// @todo - insert timers to re-do the rename
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

	DEBUG("proto_detail (%s): Renaming %s -> %s", inst->name, filename, inst->filename_work);
	if (rename(filename, inst->filename_work) < 0) {
		ERROR("detail (%s): Failed renaming %s to %s: %s",
		      inst->name, filename, inst->filename_work, fr_syserror(errno));
		goto noop;
	}

	globfree(&files);	/* Shouldn't be using anything in files now */

	/*
	 *	The file should now exist.
	 */
	return 0;
}

/*
 *	Start polling again after a timeout.
 */
static void work_retry_timer(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	proto_detail_file_t *inst = talloc_get_type_abort(uctx, proto_detail_file_t);

	work_init(inst);
}

/*
 *	The "detail.work" file exists.
 */
static void work_exists(proto_detail_file_t *inst, int fd)
{
	proto_detail_work_t	*work;
	fr_listen_t		*listen;

	fr_event_vnode_func_t	funcs = { .delete = mod_vnode_delete };

	/*
	 *	"detail.work" exists, try to lock it.
	 */
	if (rad_lockfd_nonblock(fd, 0) < 0) {
		struct timeval when, now;

		DEBUG("Failed locking %s: %s", inst->filename_work, fr_syserror(errno));

		close(fd);

		when.tv_sec = 0;
		when.tv_usec = USEC / 10;

		DEBUG3("Waiting %d.%06ds for lock on file %s",
		       (int) when.tv_sec, (int) when.tv_usec, inst->filename_work);

		fr_timeval_add(&when, &when, &now);

		if (fr_event_timer_insert(inst, inst->el, &inst->ev,
					  &when, work_retry_timer, inst) < 0) {
			ERROR("Failed inserting retry timer for %s", inst->filename_work);
		}
		return;
	}

	DEBUG3("Obtained lock and processing file %s", inst->filename_work);

	/*
	 *	The worker may be in a different thread, so avoid
	 *	talloc threading issues by using a NULL TALLOC_CTX.
	 */
	work = talloc(NULL, proto_detail_work_t);
	if (!work) {
		DEBUG("Failed allocating memory");
		return;
	}

	memcpy(work, inst->parent->work_submodule->data, sizeof(*work));

	/*
	 *	Tell the worker to clean itself up.
	 */
	work->free_on_close = true;

	work->fd = dup(fd);

	/*
	 *	Don't do anything until the file has been deleted.
	 *
	 *	@todo - ensure that proto_detail_work is done the file...
	 *	maybe by creating a new instance?
	 */
	if (fr_event_filter_insert(inst, inst->el, fd, FR_EVENT_FILTER_VNODE,
				   &funcs, NULL, inst) < 0) {
		ERROR("Failed adding work socket to event loop: %s", fr_strerror());
		goto error;
	}

	/*
	 *	Create a new listener, and insert it into the
	 *	scheduler.  Shameless copied from proto_detail.c
	 *	mod_open(), with changes.
	 *
	 *	This listener is parented from the worker.  So that
	 *	when the worker goes away, so does the listener.
	 */
	listen = talloc_zero(work, fr_listen_t);

	listen->app_io = inst->parent->work_io;
	listen->app_io_instance = work;

	listen->app = inst->parent->self;
	listen->app_instance = inst->parent;
	listen->server_cs = inst->parent->server_cs;

	/*
	 *	Yuck.
	 */
	inst->parent->work_io_instance = work;

	work->filename_work = talloc_strdup(work, inst->filename_work);

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	listen->default_message_size = inst->parent->max_packet_size;
	listen->num_messages = inst->parent->num_messages;

	/*
	 *	Open the detail.work file.
	 */
	if (listen->app_io->open(listen->app_io_instance) < 0) {
		ERROR("Failed opening %s", listen->app_io->name);
		goto error;
	}

	if (!fr_schedule_socket_add(inst->parent->sc, listen)) {
	error:
		(void) fr_event_fd_delete(inst->el, fd, FR_EVENT_FILTER_VNODE);
		close(fd);

		(void) fr_event_fd_delete(inst->el, work->fd, FR_EVENT_FILTER_VNODE);
		(void) fr_event_fd_delete(inst->el, work->fd, FR_EVENT_FILTER_IO);
		close(work->fd);
		talloc_free(work);
		return;
	}

	return;
}


static void mod_vnode_delete(fr_event_list_t *el, int fd, UNUSED int fflags, void *ctx)
{
	proto_detail_file_t *inst = talloc_get_type_abort(ctx, proto_detail_file_t);

	DEBUG("Deleted %s", inst->filename_work);

	(void) fr_event_fd_delete(el, fd, FR_EVENT_FILTER_VNODE);

	/*
	 *	The worker may or may not still exist if the file was
	 *	deleted.
	 */
	inst->parent->work_io_instance = NULL;

	/*
	 *	Re-initialize the state machine.
	 *
	 *	Note that a "delete" may be the result of an atomic
	 *	"move", which both deletes the old file, and creates
	 *	the new one.
	 */
	work_init(inst);
}


static void work_init(proto_detail_file_t *inst)
{
	int fd, tries;

	tries = 0;

	/*
	 *	See if there is a "detail.work" file.  If not, try to
	 *	rename an existing file to "detail.work".
	 */
redo:
	DEBUG3("Trying to open %s", inst->filename_work);
	fd = open(inst->filename_work, inst->mode);
	if (fd < 0) {
		struct timeval when, now;

		/*
		 *	Rename a "detail*" to "detail.work" file.
		 */
		if (work_rename(inst) == 0) {
			tries++;
			if (tries < 5) goto redo;
		}

		/*
		 *	Check every N seconds.
		 */
		when.tv_sec = inst->poll_interval;
		when.tv_usec = 0;

		DEBUG3("Waiting %d.%06ds for new files in %s",
		       (int) when.tv_sec, (int) when.tv_usec, inst->name);

		gettimeofday(&now, NULL);

		fr_timeval_add(&when, &when, &now);

		if (fr_event_timer_insert(inst, inst->el, &inst->ev,
					  &when, work_retry_timer, inst) < 0) {
			ERROR("Failed inserting poll timer for %s", inst->filename_work);
		}
		return;
	}

	/*
	 *	It exists, go process it!
	 *
	 *	We will get back to the main loop when the
	 *	"detail.work" file is deleted.
	 */
	work_exists(inst, fd);
}


/** Set the event list for a new IO instance
 *
 * @param[in] instance of the detail worker
 * @param[in] el the event list
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);

	inst->el = el;

	/*
	 *	Initialize the work state machine.
	 */
	work_init(inst);
}


static int mod_instantiate(UNUSED void *instance, UNUSED CONF_SECTION *cs)
{
//	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);


	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);
	dl_instance_t const	*dl_inst;
	char			*p;

	/*
	 *	Find the dl_instance_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_instance_find(instance);
	rad_assert(dl_inst);

	FR_INTEGER_BOUND_CHECK("poll_interval", inst->poll_interval, >=, 1);
	FR_INTEGER_BOUND_CHECK("poll_interval", inst->poll_interval, <=, 3600);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_detail_t);
	inst->cs = cs;
	inst->fd = -1;

	inst->directory = p = talloc_strdup(inst, inst->filename);

	p = strrchr(p, '/');
	if (!p) {
		cf_log_err(cs, "Filename must contain '/'");
		return -1;
	}

	*p = '\0';

	DEBUG("Directory %s", inst->directory);

	if (!inst->filename_work) {
		inst->filename_work = talloc_asprintf(inst, "%s/detail.work", inst->directory);
	}

	/*
	 *	We need this for the lock.
	 */
	inst->mode = O_RDWR;

	return 0;
}

static int mod_detach(void *instance)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);

	/*
	 *	@todo - have our OWN event loop for timers, and a
	 *	"copy timer from -> to, which means we only have to
	 *	delete our child event loop from the parent on close.
	 */

	close(inst->fd);
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
	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 256,
	.default_reply_size	= 32,

	.open			= mod_open,
	.vnode			= mod_vnode_extend,
	.decode			= mod_decode,
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
