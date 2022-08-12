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
 * @file proto_load_step.c
 * @brief Generic protocol load generator
 *
 * @copyright 2019 The FreeRADIUS server project.
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 */
#include <netdb.h>
#include <fcntl.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/load.h>

#include "proto_load.h"

extern fr_app_io_t proto_load_step;

typedef struct proto_load_step_s proto_load_step_t;

typedef struct {
	fr_event_list_t			*el;			//!< event list
	fr_network_t			*nr;			//!< network handler

	char const			*name;			//!< socket name
	bool				done;
	bool				suspended;

	fr_time_t			recv_time;		//!< recv time of the last packet

	proto_load_step_t const      	*inst;
	fr_load_t			*l;			//!< load generation handler
	fr_load_config_t		load;			//!< load configuration
	fr_stats_t			stats;			//!< statistics for this socket

	int				fd;			//!< for CSV files
	fr_event_timer_t const		*ev;			//!< for writing statistics

	fr_listen_t			*parent;		//!< master IO handler
} proto_load_step_thread_t;

struct proto_load_step_s {
	proto_load_t			*parent;

	CONF_SECTION			*cs;			//!< our configuration

	char const     			*filename;		//!< where to read input packet from
	fr_pair_list_t			pair_list;		//!< for input packet

	int				code;
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes

	RADCLIENT			*client;		//!< static client

	fr_load_config_t		load;			//!< load configuration
	bool				repeat;			//!, do we repeat the load generation
	char const     			*csv;			//!< where to write CSV stats
};


static const CONF_PARSER load_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, proto_load_step_t, filename) },
	{ FR_CONF_OFFSET("csv", FR_TYPE_STRING, proto_load_step_t, csv) },

	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_load_step_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) } ,

	{ FR_CONF_OFFSET("start_pps", FR_TYPE_UINT32, proto_load_step_t, load.start_pps) },
	{ FR_CONF_OFFSET("max_pps", FR_TYPE_UINT32, proto_load_step_t, load.max_pps) },
	{ FR_CONF_OFFSET("duration", FR_TYPE_TIME_DELTA, proto_load_step_t, load.duration) },
	{ FR_CONF_OFFSET("step", FR_TYPE_UINT32, proto_load_step_t, load.step) },
	{ FR_CONF_OFFSET("max_backlog", FR_TYPE_UINT32, proto_load_step_t, load.milliseconds) },
	{ FR_CONF_OFFSET("parallel", FR_TYPE_UINT32, proto_load_step_t, load.parallel) },
	{ FR_CONF_OFFSET("repeat", FR_TYPE_BOOL, proto_load_step_t, repeat) },

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_load_step_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_load_step_t);
	proto_load_step_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_load_step_thread_t);
	fr_io_address_t			*address, **address_p;

	if (thread->done) return -1;

	/*
	 *	Suspend reading on the FD, because we let the timers
	 *	take over the load generation.
	 */
	if (!thread->suspended) {
		static fr_event_update_t pause[] = {
			FR_EVENT_SUSPEND(fr_event_io_func_t, read),
			FR_EVENT_SUSPEND(fr_event_io_func_t, write),
			{ 0 }
		};

		if (fr_event_filter_update(thread->el, li->fd, FR_EVENT_FILTER_IO, pause) < 0) {
			fr_assert(0);
		}

		thread->suspended = true;
	}

	*leftover = 0;		/* always for load generation */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_radius.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;

	memset(address, 0, sizeof(*address));
	address->socket.inet.src_ipaddr.af = AF_INET;
	address->socket.inet.dst_ipaddr.af = AF_INET;
	address->radclient = inst->client;

	*recv_time_p = thread->recv_time;

	if (buffer_len < 1) {
		DEBUG2("proto_load_step read buffer is too small for input packet");
		return 0;
	}

	buffer[0] = 0;

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_load_step - reading packet for %s",
	       thread->name);

	return 1;
}


static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, fr_time_t request_time,
			 UNUSED uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_load_step_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_load_step_thread_t);
	fr_load_reply_t state;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_radius
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	/*
	 *	Tell the load generatopr subsystem that we have a
	 *	reply.  Then if the load test is done, exit the
	 *	server.
	 */
	state = fr_load_generator_have_reply(thread->l, request_time);
	if (state == FR_LOAD_DONE) {
		if (!thread->inst->repeat) {
			thread->done = true;
		} else {
			(void) fr_load_generator_stop(thread->l); /* ensure l->ev is gone */
			(void) fr_load_generator_start(thread->l);
		}
	}

	return buffer_len;
}


/** Open a load listener
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_load_step_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_load_step_t);
	proto_load_step_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_load_step_thread_t);

	fr_ipaddr_t			ipaddr;

	/*
	 *	We never read or write to this file, but we need a
	 *	readable FD in order to bootstrap the process.
	 */
	li->fd = open(inst->filename, O_RDONLY);

	memset(&ipaddr, 0, sizeof(ipaddr));
	ipaddr.af = AF_INET;
	li->app_io_addr = fr_socket_addr_alloc_inet_src(li, IPPROTO_UDP, 0, &ipaddr, 0);

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = talloc_typed_asprintf(thread, "load_step from filename %s", inst->filename);
	thread->parent = talloc_parent(li);

	return 0;
}


/** Generate traffic.
 *
 */
static int mod_generate(fr_time_t now, void *uctx)
{
	fr_listen_t			*li = uctx;
	proto_load_step_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_load_step_thread_t);

	thread->recv_time = now;

	/*
	 *	Tell the network side to call our read routine.
	 */
	fr_network_listen_read(thread->nr, thread->parent);

	return 0;
}


static void write_stats(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	proto_load_step_thread_t	*thread = uctx;
	size_t len;
	char buffer[1024];

	(void) fr_event_timer_in(thread, el, &thread->ev, fr_time_delta_from_sec(1), write_stats, thread);

	len = fr_load_generator_stats_sprint(thread->l, now, buffer, sizeof(buffer));
	if (write(thread->fd, buffer, len) < 0) {
		DEBUG("Failed writing to %s - %s", thread->inst->csv, fr_syserror(errno));
	}
}


/** Decode the packet
 *
 */
static int mod_decode(void const *instance, request_t *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{
	proto_load_step_t const	*inst = talloc_get_type_abort_const(instance, proto_load_step_t);
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = inst->parent->dict;

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	if (inst->code) request->packet->code = inst->code;
	request->packet->id = fr_rand() & 0xff;
	request->reply->id = request->packet->id;
	memset(request->packet->vector, 0, sizeof(request->packet->vector));

	request->packet->data = talloc_zero_array(request->packet, uint8_t, 1);
	request->packet->data_len = 1;

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_radius_ok().
	 */
	(void) fr_pair_list_copy(request->request_ctx, &request->request_pairs, &inst->pair_list);

	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(RADCLIENT *, address->radclient);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	REQUEST_VERIFY(request);

	return 0;
}

/** Set the event list for a new socket
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	proto_load_step_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_load_step_t);
	proto_load_step_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_load_step_thread_t);
	size_t len;
	char buffer[256];

	thread->el = el;
	thread->nr = nr;
	thread->inst = inst;
	thread->load = inst->load;

	thread->l = fr_load_generator_create(thread, el, &thread->load, mod_generate, li);
	if (!thread->l) return;

	(void) fr_load_generator_start(thread->l);

	if (!inst->csv) return;

	thread->fd = open(inst->csv, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (thread->fd < 0) {
		ERROR("Failed opening %s - %s", inst->csv, fr_syserror(errno));
		return;
	}

	(void) fr_event_timer_in(thread, thread->el, &thread->ev, fr_time_delta_from_sec(1), write_stats, thread);

	len = fr_load_generator_stats_sprint(thread->l, fr_time(), buffer, sizeof(buffer));
	if (write(thread->fd, buffer, len) < 0) {
		DEBUG("Failed writing to %s - %s", thread->inst->csv, fr_syserror(errno));
	}
}

static char const *mod_name(fr_listen_t *li)
{
	proto_load_step_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_load_step_thread_t);

	return thread->name;
}


static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_load_step_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_load_step_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	dl_module_inst_t const	*dl_inst;

	/*
	 *	Find the dl_module_inst_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_module_instance_by_data(inst);
	fr_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_load_t);
	inst->cs = conf;

	FR_INTEGER_BOUND_CHECK("start_pps", inst->load.start_pps, >=, 10);
	FR_INTEGER_BOUND_CHECK("start_pps", inst->load.start_pps, <, 400000);

	FR_INTEGER_BOUND_CHECK("step", inst->load.step, >=, 1);
	FR_INTEGER_BOUND_CHECK("step", inst->load.step, <, 100000);

	if (inst->load.max_pps > 0) FR_INTEGER_BOUND_CHECK("max_pps", inst->load.max_pps, >, inst->load.start_pps);
	FR_INTEGER_BOUND_CHECK("max_pps", inst->load.max_pps, <, 100000);

	FR_TIME_DELTA_BOUND_CHECK("duration", inst->load.duration, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("duration", inst->load.duration, <, fr_time_delta_from_sec(10000));


	FR_INTEGER_BOUND_CHECK("parallel", inst->load.parallel, >=, 1);
	FR_INTEGER_BOUND_CHECK("parallel", inst->load.parallel, <, 1000);

	FR_INTEGER_BOUND_CHECK("max_backlog", inst->load.milliseconds, >=, 1);
	FR_INTEGER_BOUND_CHECK("max_backlog", inst->load.milliseconds, <, 100000);

	return 0;
}

static RADCLIENT *mod_client_find(fr_listen_t *li, UNUSED fr_ipaddr_t const *ipaddr, UNUSED int ipproto)
{
	proto_load_step_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_load_step_t);

	return inst->client;
}


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_load_step_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_load_step_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	RADCLIENT		*client;
	fr_pair_t		*vp;

	fr_pair_list_init(&inst->pair_list);
	inst->client = client = talloc_zero(inst, RADCLIENT);
	if (!inst->client) return 0;

	client->ipaddr.af = AF_INET;
	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = inst->filename;
	client->secret = talloc_strdup(client, "testing123");
	client->nas_type = talloc_strdup(client, "load");
	client->use_connected = false;

	if (inst->filename) {
		FILE *fp;
		bool done = false;

		fp = fopen(inst->filename, "r");
		if (!fp) {
			cf_log_err(conf, "Failed opening %s - %s",
				   inst->filename, fr_syserror(errno));
			return -1;
		}

		if (fr_pair_list_afrom_file(inst, inst->parent->dict, &inst->pair_list, fp, &done) < 0) {
			cf_log_perr(conf, "Failed reading %s", inst->filename);
			fclose(fp);
			return -1;
		}

		fclose(fp);
	}

	vp = fr_pair_find_by_da(&inst->pair_list, NULL, inst->parent->attr_packet_type);
	if (vp) inst->code = vp->vp_uint32;

	return 0;
}

fr_app_io_t proto_load_step = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "load_step",
		.config			= load_listen_config,
		.inst_size		= sizeof(proto_load_step_t),
		.thread_inst_size	= sizeof(proto_load_step_thread_t),
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate
	},
	.default_message_size	= 4096,
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.event_list_set		= mod_event_list_set,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,

	.decode			= mod_decode,
};
