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
#include <freeradius-devel/rad_assert.h>
#include "proto_detail.h"

#include <fcntl.h>
#include <sys/stat.h>

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

static const CONF_PARSER file_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_file_t, filename ) },

	{ FR_CONF_OFFSET("filename.work", FR_TYPE_STRING, proto_detail_work_t, filename_work ) },

	{ FR_CONF_OFFSET("track", FR_TYPE_BOOL, proto_detail_file_t, track_progress ) },

	CONF_PARSER_TERMINATOR
};


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


static void mod_vnode_delete(UNUSED fr_event_list_t *el, UNUSED int sockfd, UNUSED int fflags, void *ctx)
{
	proto_detail_file_t *inst = talloc_get_type_abort(ctx, proto_detail_file_t);

	DEBUG("Deleted %s", inst->filename_work);

	/*
	 *	@todo - troll for detail.work file.  Allocate new
	 *	proto_detail_work_t, fill it in, and start up the new
	 *	detail worker.
	 */
}


/** Set the event list for a new IO instance
 *
 * @param[in] instance of the detail worker
 * @param[in] el the event list
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el)
{
	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);
	proto_detail_work_t *work = talloc_get_type_abort(inst->parent->work_io_instance, proto_detail_work_t);
	fr_event_vnode_func_t	funcs = { .delete = mod_vnode_delete };
	int fd;

	inst->el = el;

	/*
	 *	See if there is a "detail.work" file.  If so, fire off proto_detail_work.
	 */
	fd = open(inst->filename_work, work->mode);
	if (fd < 0) {
		DEBUG("No work file %s, starting to poll", inst->filename_work);
		return;
	}

	/*
	 *	Don't do anything until the file has been deleted.
	 *
	 *	@todo - ensure that proto_detail_work is done the file...
	 *	maybe by creating a new instance?
	 */
	if (fr_event_filter_insert(inst, el, fd, FR_EVENT_FILTER_VNODE,
				   &funcs, NULL, inst) < 0) {
		ERROR("Failed adding worker socket to event loop: %s", fr_strerror());
		return;
	}
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

	if (!inst->filename_work) {
		inst->filename_work = talloc_asprintf(inst, "%s/detail.work", inst->directory);
	}


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
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
