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
 * @file proto_radius_load.c
 * @brief RADIUS load generator
 *
 * @copyright 2019 The FreeRADIUS server project.
 * @copyright 2019 Network RADIUS SARL <legal@networkradius.com>
 */
#include <netdb.h>
#include <fcntl.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/load.h>
#include <freeradius-devel/server/rad_assert.h>

#include "proto_radius.h"

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t proto_radius_load_dict[];
fr_dict_autoload_t proto_radius_load_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_radius_load_dict_attr[];
fr_dict_attr_autoload_t proto_radius_load_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

extern fr_app_io_t proto_radius_load;

typedef struct proto_radius_load_s proto_radius_load_t;

typedef struct {
	fr_event_list_t			*el;			//!< event list
	fr_network_t			*nr;			//!< network handler

	char const			*name;			//!< socket name

	fr_time_t			recv_time;		//!< recv time of the last packet

	proto_radius_load_t const      	*inst;
	fr_load_t			*l;			//!< load generation handler
	fr_load_config_t		load;			//!< load configuration
	fr_stats_t			stats;			//!< statistics for this socket

	int				fd;			//!< for CSV files
	fr_event_timer_t const		*ev;			//!< for writing statistics

	int				sockets[2];
	fr_listen_t			*parent;		//!< master IO handler
} proto_radius_load_thread_t;

struct proto_radius_load_s {
	CONF_SECTION			*cs;			//!< our configuration

	char const     			*filename;		//!< where to read input packets from
	uint8_t				*packet;		//!< encoded packet read from the file
	size_t				packet_len;		//!< length of packet

	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes

	RADCLIENT			*client;		//!< static client

	fr_load_config_t		load;			//!< load configuration

	char const     			*csv;			//!< where to write CSV stats
};


static const CONF_PARSER load_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT, proto_radius_load_t, filename) },
	{ FR_CONF_OFFSET("csv", FR_TYPE_STRING, proto_radius_load_t, csv) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_radius_load_t, max_packet_size), .dflt = "4096" } ,
	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_radius_load_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) } ,

	{ FR_CONF_OFFSET("start_pps", FR_TYPE_UINT32, proto_radius_load_t, load.start_pps) },
	{ FR_CONF_OFFSET("max_pps", FR_TYPE_UINT32, proto_radius_load_t, load.max_pps) },
	{ FR_CONF_OFFSET("duration", FR_TYPE_UINT32, proto_radius_load_t, load.duration) },
	{ FR_CONF_OFFSET("step", FR_TYPE_UINT32, proto_radius_load_t, load.step) },
	{ FR_CONF_OFFSET("max_backlog", FR_TYPE_UINT32, proto_radius_load_t, load.milliseconds) },
	{ FR_CONF_OFFSET("parallel", FR_TYPE_UINT32, proto_radius_load_t, load.parallel) },

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_radius_load_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_load_t);
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);
	fr_io_address_t			*address, **address_p;

	size_t				packet_len;
	fr_time_t			timestamp;

	fr_time_t			*recv_time_p;

	*leftover = 0;		/* always for load generation */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_radius.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;

	recv_time_p = *recv_time;

	memset(address, 0, sizeof(*address));
	address->src_ipaddr.af = AF_INET;
	address->dst_ipaddr.af = AF_INET;
	address->radclient = inst->client;

	timestamp = thread->recv_time;

	if (buffer_len < inst->packet_len) {
		DEBUG2("proto_radius_load read buffer is too small for input packet");
		return 0;
	}

	memcpy(buffer, inst->packet, inst->packet_len);
	packet_len = inst->packet_len;

	// @todo - try for some variation in the packet

	/*
	 *	The packet is always OK for RADIUS.
	 */

	*recv_time_p = timestamp;

	/*
	 *	proto_radius sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_radius_load - Received %s ID %d length %d %s",
	       fr_packet_codes[buffer[0]], buffer[1],
	       (int) packet_len, thread->name);

	return packet_len;
}


static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, fr_time_t request_time,
			 UNUSED uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);
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
		fr_exit_now(1);
	}

	return buffer_len;
}


/** Open a load listener for RADIUS
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_radius_load_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_load_t);
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);

	fr_ipaddr_t			ipaddr;
	CONF_ITEM			*ci;
	CONF_SECTION			*server_cs;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, (int *) &thread->sockets) < 0) {
		PERROR("Failed opening /dev/null: %s", fr_syserror(errno));
		return -1;
	}

	li->fd = thread->sockets[0];

	memset(&ipaddr, 0, sizeof(ipaddr));
	ipaddr.af = AF_INET;
	li->app_io_addr = fr_app_io_socket_addr(li, IPPROTO_UDP, &ipaddr, 0);

	ci = cf_parent(inst->cs); /* listen { ... } */
	rad_assert(ci != NULL);
	ci = cf_parent(ci);
	rad_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	thread->name = talloc_typed_asprintf(thread, "load generation from file %s", inst->filename);
	thread->parent = talloc_parent(li);

	DEBUG("Listening on radius address %s bound to virtual server %s",
	      thread->name, cf_section_name2(server_cs));

	return 0;
}


/** Open a load listener for RADIUS
 *
 */
static int mod_close(fr_listen_t *li)
{
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);

	/*
	 *	Close the second socket.
	 */
	close(thread->sockets[1]);
	return 0;
}

/** Generate traffic.
 *
 */
static int mod_generate(fr_time_t now, void *uctx)
{
	fr_listen_t			*li = uctx;
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);

	thread->recv_time = now;

	/*
	 *	Tell the network side to call our read routine.
	 */
	fr_network_listen_read(thread->nr, thread->parent);

	return 0;
}


static void write_stats(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	proto_radius_load_thread_t	*thread = uctx;
	size_t len;
	fr_load_stats_t const *stats;
	char buffer[1024];
	double now_f, last_send_f;

	(void) fr_event_timer_in(thread, el, &thread->ev, NSEC, write_stats, thread);

	stats = fr_load_generator_stats(thread->l);

	now_f = now - stats->start;
	now_f /= NSEC;

	last_send_f = stats->last_send - stats->start;
	last_send_f /= NSEC;

	len = snprintf(buffer, sizeof(buffer),
		       "%f,%f,"
		       "%" PRIu64 ",%" PRIu64 ",%d,"
		       "%d,%d,"
		       "%d,%d,"
		       "%d,%d,%d,%d,%d,%d,%d,%d\n",
		       now_f, last_send_f,
		       stats->rtt, stats->rttvar, stats->pps,
		       stats->sent, stats->received,
		       stats->ema, stats->max_backlog,
		       stats->times[0], stats->times[1], stats->times[2], stats->times[3],
		       stats->times[4], stats->times[5], stats->times[6], stats->times[7]);
	if (write(thread->fd, buffer, len) < 0) {
		DEBUG("Failed writing to %s - %s", thread->inst->csv, fr_syserror(errno));
	}
}


/** Set the event list for a new socket
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	proto_radius_load_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_load_t);
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);
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

	(void) fr_event_timer_in(thread, thread->el, &thread->ev, NSEC, write_stats, thread);

	len = snprintf(buffer, sizeof(buffer), "\"time\",\"last_packet\",\"rtt\",\"rttvar\",\"pps\",\"sent\",\"received\",\"ema_backlog\",\"max_backlog\",\"usec\",\"10us\",\"100us\",\"ms\",\"10ms\",\"100ms\",\"s\",\"10s\"\n");
	if (write(thread->fd, buffer, len) < 0) {
		DEBUG("Failed writing to %s - %s", thread->inst->csv, fr_syserror(errno));
	}
}

static char const *mod_name(fr_listen_t *li)
{
	proto_radius_load_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_load_thread_t);

	return thread->name;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_radius_load_t	*inst = talloc_get_type_abort(instance, proto_radius_load_t);

	inst->cs = cs;

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	FR_INTEGER_BOUND_CHECK("start_pps", inst->load.start_pps, >=, 10);
	FR_INTEGER_BOUND_CHECK("start_pps", inst->load.start_pps, <, 100000);

	FR_INTEGER_BOUND_CHECK("step", inst->load.step, >=, 1);
	FR_INTEGER_BOUND_CHECK("step", inst->load.step, <, 100000);

	if (inst->load.max_pps > 0) FR_INTEGER_BOUND_CHECK("max_pps", inst->load.max_pps, >, inst->load.start_pps);
	FR_INTEGER_BOUND_CHECK("max_pps", inst->load.max_pps, <, 100000);

	FR_INTEGER_BOUND_CHECK("duration", inst->load.duration, >=, 1);
	FR_INTEGER_BOUND_CHECK("duration", inst->load.duration, <, 10000);


	FR_INTEGER_BOUND_CHECK("parallel", inst->load.parallel, >=, 1);
	FR_INTEGER_BOUND_CHECK("parallel", inst->load.parallel, <, 1000);

	FR_INTEGER_BOUND_CHECK("max_backlog", inst->load.milliseconds, >=, 1);
	FR_INTEGER_BOUND_CHECK("max_backlog", inst->load.milliseconds, <, 100000);

	return 0;
}

static RADCLIENT *mod_client_find(fr_listen_t *li, UNUSED fr_ipaddr_t const *ipaddr, UNUSED int ipproto)
{
	proto_radius_load_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_load_t);

	return inst->client;
}


static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	proto_radius_load_t	*inst = talloc_get_type_abort(instance, proto_radius_load_t);
	RADCLIENT		*client;
	FILE			*fp;
	bool			done;
	VALUE_PAIR		*vp, *vps = NULL;
	ssize_t			packet_len;
	int			code = FR_CODE_ACCESS_REQUEST;

	inst->client = client = talloc_zero(inst, RADCLIENT);
	if (!inst->client) return 0;

	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = inst->filename;
	client->secret = talloc_strdup(client, "testing123");
	client->nas_type = talloc_strdup(client, "load");
	client->use_connected = false;

	fp = fopen(inst->filename, "r");
	if (!fp) {
		cf_log_err(cs, "Failed reading %s - %s",
			   inst->filename, fr_syserror(errno));
		return -1;
	}

	if (fr_pair_list_afrom_file(inst, dict_radius, &vps, fp, &done) < 0) {
		cf_log_err(cs, "Failed reading %s - %s",
			   inst->filename, fr_strerror());
		fclose(fp);
		return -1;
	}

	fclose(fp);

	MEM(inst->packet = talloc_zero_array(inst, uint8_t, inst->max_packet_size));

	vp = fr_pair_find_by_da(vps, attr_packet_type, TAG_ANY);
	if (vp) code = vp->vp_uint32;

	/*
	 *	Encode the packet.
	 */
	packet_len = fr_radius_encode(inst->packet, inst->max_packet_size, NULL,
				      client->secret, talloc_array_length(client->secret),
				      code, 0, vps);
	if (packet_len <= 0) {
		cf_log_err(cs, "Failed encoding packet from %s - %s",
			   inst->filename, fr_strerror());
		return -1;
	}

	inst->packet_len = packet_len;

	return 0;
}

fr_app_io_t proto_radius_load = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_load",
	.config			= load_listen_config,
	.inst_size		= sizeof(proto_radius_load_t),
	.thread_inst_size	= sizeof(proto_radius_load_thread_t),
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,
	.track_duplicates	= false,

	.open			= mod_open,
	.close			= mod_close,
	.read			= mod_read,
	.write			= mod_write,
	.event_list_set		= mod_event_list_set,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
