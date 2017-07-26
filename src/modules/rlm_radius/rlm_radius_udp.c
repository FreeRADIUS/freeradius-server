// @todo - finish it!
// * implement remove(), which removes packets from the tracking tree
// * don't make request_io_ctx talloc'd from rlm_radius_link_t, as the link can be used
// * for other connections.  it's simpler to just have one remove() func, than to muck with
//   more allocations and talloc destructors.
// * add fd_active / fd_idle callbacks.  They will suppress the 'idle' call in rlm_radius
// - i.e. if UDP wants to send a Status-Server, it can't be idle...
// figure out a way to tell rlm_radius that the connection is zombie / alive?

/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_radius_udp.c
 * @brief RADIUS UDP transport
 *
 * @copyright 2017  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/connection.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_radius.h"
#include "track.h"

/** Static configuration for the module.
 *
 */
typedef struct rlm_radius_udp_t {
	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server
	fr_ipaddr_t		src_ipaddr;		//!< IP we open our socket on
	uint16_t		dst_port;		//!< port of the home server
	char const		*secret;		//!< shared secret

	char const		*interface;		//!< Interface to bind to.

	uint32_t		recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t		send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t		max_packet_size;	//!< maximum packet size

	bool			recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool			send_buff_is_set;	//!< Whether we were provided with a send_buf
} rlm_radius_udp_t;


/** Per-thread configuration for the module.
 *
 *  This data structure holds the connections, etc. for this IO submodule.
 */
typedef struct rlm_radius_udp_thread_t {
	rlm_radius_udp_t	*inst;			//!< IO submodule instance
	fr_event_list_t		*el;			//!< event list

	bool			pending;		//!< are there pending requests?
	fr_dlist_t		queued;			//!< queued requests for some new connection

	fr_dlist_t		active;	       	//!< active connections
} rlm_radius_udp_thread_t;

typedef struct rlm_radius_udp_connection_t {
	rlm_radius_udp_t const	*inst;		//!< our module instance
	fr_connection_t		*conn;		//!< Connection to our destination.

	fr_dlist_t		entry;		//!< in the linked list of connections

	struct timeval		last_sent_with_reply;	//!< most recent sent time which had a reply

	bool			pending;	//!< are there packets pending?
	fr_dlist_t		queued;		//!< list of packets queued for sending
	fr_dlist_t		sent;		//!< list of sent packets

	uint32_t		max_packet_size; //!< our max packet size. may be different from the parent...
	int			fd;		//!< file descriptor

	fr_ipaddr_t		dst_ipaddr;	//!< IP of the home server. stupid 'const' issues..
	uint16_t		dst_port;	//!< port of the home server
	fr_ipaddr_t		src_ipaddr;	//!< my source IP
	uint16_t	       	src_port;	//!< my source port

	// @todo - track status-server, open, signaling, etc.

	uint8_t			*buffer;	//!< receive buffer
	size_t			buflen;		//!< receive buffer length

	rlm_radius_id_t		*id[FR_MAX_PACKET_CODE]; //!< ID tracking
} rlm_radius_udp_connection_t;


/** Link a packet to a connection
 *
 */
typedef struct rlm_radius_udp_request_t {
	fr_dlist_t		entry;		//!< in the connection list of packets

	rlm_radius_udp_connection_t	*c;		//!< the connection
	rlm_radius_request_t	*rr;		//!< the ID tracking, resend count, etc.

} rlm_radius_udp_request_t;


static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, dst_ipaddr), },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, dst_ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_radius_udp_t, dst_port) },

	{ FR_CONF_OFFSET("secret", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_radius_udp_t, secret) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, rlm_radius_udp_t, interface) },

	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, rlm_radius_udp_t, recv_buff) },
	{ FR_CONF_IS_SET_OFFSET("send_buff", FR_TYPE_UINT32, rlm_radius_udp_t, send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, rlm_radius_udp_t, max_packet_size),
	  .dflt = "4096" },

	{ FR_CONF_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("src_ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("src_ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, src_ipaddr) },

	CONF_PARSER_TERMINATOR
};


static rlm_radius_udp_connection_t *mod_connect(rlm_radius_udp_t *inst, rlm_radius_udp_thread_t *t)
{
	rlm_radius_udp_connection_t *c;

	c = talloc_zero(t, rlm_radius_udp_connection_t);
	c->dst_ipaddr = inst->dst_ipaddr;
	c->dst_port = inst->dst_port;
	c->src_ipaddr = inst->src_ipaddr;
	c->src_port = 0;

	return c;
}


static int mod_push(void *instance, REQUEST *request, rlm_radius_link_t *link, void *thread)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	rlm_radius_udp_thread_t *t = talloc_get_type_abort(thread, rlm_radius_udp_thread_t);
	rlm_radius_udp_request_t *u = link->request_io_ctx;
	rlm_radius_udp_connection_t *c;
	fr_dlist_t *entry;

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_MAX_PACKET_CODE);

	entry = FR_DLIST_FIRST(t->active);
	if (!entry) {
		c = mod_connect(inst, t);
		if (!c) {
			RDEBUG("Failed initializing new connection");
			return -1;
		}
	}

	/*
	 *	Now that we have a connection, use it to send packets.
	 */
	c = fr_ptr_to_type(rlm_radius_udp_connection_t, entry, entry);
	(void) talloc_get_type_abort(c, rlm_radius_udp_connection_t);

	u->c = c;

	if (c->pending) {
		fr_dlist_insert_head(&c->queued, &u->entry);
		return 0;
	}

	// @todo - try to write to the socket.  If we can, return instead of adding it to the queue

	c->pending = true;
	fr_dlist_insert_head(&c->queued, &u->entry);
//	mod_fd_active(c);

	return 0;
}


/** Bootstrap the module
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf    our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(UNUSED void *instance, UNUSED CONF_SECTION *conf)
{
//	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	return 0;
}


/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	/*
	 *	Ensure that we have a destination address.
	 */
	if (inst->dst_ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "A value must be given for 'ipaddr'");
		return -1;
	}

	/*
	 *	If src_ipaddr isn't set, make sure it's INADDR_ANY, of
	 *	the same address family as dst_ipaddr.
	 */
	if (inst->src_ipaddr.af == AF_UNSPEC) {
		memset(&inst->src_ipaddr, 0, sizeof(inst->src_ipaddr));

		inst->src_ipaddr.af = inst->dst_ipaddr.af;

		if (inst->src_ipaddr.af == AF_INET) {
			inst->src_ipaddr.prefix = 32;
		} else {
			inst->src_ipaddr.prefix = 128;
		}
	}

	else if (inst->src_ipaddr.af != inst->dst_ipaddr.af) {
		cf_log_err(conf, "The 'ipaddr' and 'src_ipaddr' configuration items must be both of the same address family");
		return -1;
	}

	if (!inst->dst_port) {
		cf_log_err(conf, "A value must be given for 'port'");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	return 0;
}


/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_radius_udp_thread_t *t = thread;

	(void) talloc_set_type(t, rlm_radius_udp_thread_t);
	t->inst = instance;
	t->el = el;

	t->pending = false;
	FR_DLIST_INIT(t->queued);
	FR_DLIST_INIT(t->active);

	// @todo - get parent, and initialize the list of IDs by code, from what is permitted by rlm_radius

	// start the connection

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern fr_radius_client_io_t rlm_radius_udp;
fr_radius_client_io_t rlm_radius_udp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_udp",
	.inst_size	= sizeof(rlm_radius_udp_t),
	.request_inst_size = sizeof(rlm_radius_udp_request_t),
	.thread_inst_size	= sizeof(rlm_radius_udp_thread_t),

	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.thread_instantiate = mod_thread_instantiate,

	.push		= mod_push,
};
