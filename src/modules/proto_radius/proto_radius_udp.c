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
 * @file proto_radius_udp.c
 * @brief RADIUS handler for UDP.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/track.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

typedef struct {
	int				if_index;

	fr_ipaddr_t			src_ipaddr;
	fr_ipaddr_t			dst_ipaddr;
	uint16_t			src_port;
	uint16_t 			dst_port;

	fr_time_t			timestamp;

	RADCLIENT			*client;
} proto_radius_udp_address_t;

typedef struct {
	proto_radius_t	const		*parent;		//!< The module that spawned us!

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request

	fr_ipaddr_t			ipaddr;			//!< Ipaddr to listen on.

	bool				ipaddr_is_set;		//!< ipaddr config item is set.
	bool				ipv4addr_is_set;	//!< ipv4addr config item is set.
	bool				ipv6addr_is_set;	//!< ipv6addr config item is set.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint16_t			port;			//!< Port to listen on.
	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.
	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.

	fr_tracking_t			*ft;			//!< tracking table
	uint32_t			cleanup_delay;		//!< cleanup delay for Access-Request packets
} proto_radius_udp_t;

static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_IS_SET_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_radius_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_radius_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_radius_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_radius_udp_t, port) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, proto_radius_udp_t, recv_buff) },

	{ FR_CONF_OFFSET("cleanup_delay", FR_TYPE_UINT32, proto_radius_udp_t, cleanup_delay), .dflt = "5" },

	CONF_PARSER_TERMINATOR
};

static void mod_cleanup_delay(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	fr_tracking_entry_t *track = uctx;
	// proto_radius_udp_t const *inst = talloc_parent(track->ft);

	(void) fr_radius_tracking_entry_delete(track->ft, track);
}

/** Return the src address associated with the packet_ctx
 *
 */
static int mod_src_address(fr_socket_addr_t *src, UNUSED void const *instance, void const *packet_ctx)
{
	fr_tracking_entry_t const		*track = packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	memset(src, 0, sizeof(*src));

	src->proto = IPPROTO_UDP;
	memcpy(&src->ipaddr, &address->src_ipaddr, sizeof(src->ipaddr));

	return 0;
}

/** Return the dst address associated with the packet_ctx
 *
 */
static int mod_dst_address(fr_socket_addr_t *dst, UNUSED void const *instance, void const *packet_ctx)
{
	fr_tracking_entry_t const		*track = packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	memset(dst, 0, sizeof(*dst));

	dst->proto = IPPROTO_UDP;
	memcpy(&dst->ipaddr, &address->dst_ipaddr, sizeof(dst->ipaddr));

	return 0;
}

/** Return the client associated with the packet_ctx
 *
 */
static RADCLIENT *mod_client(UNUSED void const *instance, void const *packet_ctx)
{
	fr_tracking_entry_t const		*track = packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	return address->client;
}

static ssize_t mod_read(void const *instance, void **packet_ctx, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_udp_t const	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	ssize_t				data_size;
	size_t				packet_len;
	decode_fail_t			reason;

	struct timeval			timestamp;
	fr_tracking_status_t		tracking_status;
	fr_tracking_entry_t		*track;
	proto_radius_udp_address_t	address;

	data_size = udp_recv(inst->sockfd, buffer, buffer_len, 0,
			     &address.src_ipaddr, &address.src_port,
			     &address.dst_ipaddr, &address.dst_port,
			     &address.if_index, &timestamp);
	if (data_size <= 0) return data_size;

	packet_len = data_size;

	/*
	 *	If it's not a RADIUS packet, ignore it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, false, &reason)) return 0;

	address.timestamp = fr_time();

	/*
	 *	Lookup the client - Must exist to continue.
	 */
	address.client = client_find(NULL, &address.src_ipaddr, IPPROTO_UDP);
	if (!address.client) {
		ERROR("Unknown client at address %pV:%u.  Ignoring...",
		      fr_box_ipaddr(address.src_ipaddr), address.src_port);

		return 0;
	}

	/*
	 *	If the signature fails validation, ignore it.
	 */
	if (fr_radius_verify(buffer, NULL,
			     (uint8_t const *)address.client->secret,
			     talloc_array_length(address.client->secret)) < 0) {
		return 0;
	}

	tracking_status = fr_radius_tracking_entry_insert(&track, inst->ft, buffer, address.timestamp, &address);
	switch (tracking_status) {
	case FR_TRACKING_ERROR:
	case FR_TRACKING_UNUSED:
		return -1;	/* Fatal */

		/*
		 *	If the entry already has a cleanup delay, we
		 *	extend the cleanup delay.  i.e. the cleanup
		 *	delay is from the last reply we sent, not from
		 *	the first one.
		 */
	case FR_TRACKING_SAME:
		if (track->ev) {
			struct timeval tv;

			gettimeofday(&tv, NULL);
			tv.tv_sec += inst->cleanup_delay;

			(void) fr_event_timer_insert(inst->el, mod_cleanup_delay, track, &tv, &track->ev);
		}
		return 0;

	/*
	 *	Delete any pre-existing cleanup_delay timers.
	 */
	case FR_TRACKING_DIFFERENT:
		if (track->ev) (void) fr_event_timer_delete(inst->el, &track->ev);
		break;

	case FR_TRACKING_NEW:
		break;
	}

	*packet_ctx = track;

	return packet_len;
}

static ssize_t mod_write(void const *instance, void *packet_ctx,
			 fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_udp_t const	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	fr_tracking_entry_t		*track = packet_ctx;
	proto_radius_udp_address_t	*address = track->src_dst;

	ssize_t				data_size;
	fr_time_t			reply_time;
	struct timeval			tv;

	/*
	 *	The original packet has changed.  Suppress the write,
	 *	as the client will never accept the response.
	 */
	if (track->timestamp != request_time) return buffer_len;

	/*
	 *	Figure out when we've sent the reply.
	 */
	 reply_time = fr_time();

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	if (buffer_len >= 20) {
		data_size = udp_send(inst->sockfd, buffer, buffer_len, 0,
				     &address->dst_ipaddr, address->dst_port,
				     address->if_index,
				     &address->src_ipaddr, address->src_port);
	} else {
		/*
		 *	Otherwise lie, and say we've written it all...
		 */
		data_size = buffer_len;
	}

	/*
	 *	Most packets are cleaned up immediately.  Also, if
	 *	cleanup_delay = 0, then we even clean up
	 *	Access-Request packets immediately.
	 */
	 if ((track->data[0] != FR_CODE_ACCESS_REQUEST) || !inst->el) {
		(void) fr_radius_tracking_entry_delete(inst->ft, track);
		return data_size;
	}

	 /*
	  *	Add the reply to the tracking entry.
	  */
	 if (fr_radius_tracking_entry_reply(inst->ft, track, reply_time,
					    buffer, buffer_len) < 0) {
		(void) fr_radius_tracking_entry_delete(inst->ft, track);
		return data_size;
	 }

	 /*
	  *	@todo - Move event timers to fr_time_t
	  */
	 gettimeofday(&tv, NULL);

	 tv.tv_sec += inst->cleanup_delay;

	 /*
	  *	Clean up after a while.
	  */
	 if (fr_event_timer_insert(inst->el, mod_cleanup_delay, track, &tv, &track->ev) < 0) {
		(void) fr_radius_tracking_entry_delete(inst->ft, track);
		return data_size;
	 }

	return data_size;
}

/** Open a UDP listener for RADIUS
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	int				sockfd = 0;
	uint16_t			port = inst->port;

	sockfd = fr_socket_server_udp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		ERROR("%s", fr_strerror());
	error:
		return -1;
	}

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		ERROR("Failed binding socket: %s", fr_strerror());
		goto error;
	}

	inst->sockfd = sockfd;

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	return inst->sockfd;
}


/** Set the event list for a new socket
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @param[in] el the event list
 */
static void mod_event_list_set(void const *instance, fr_event_list_t *el)
{
	proto_radius_udp_t *inst;

	memcpy(&inst, &instance, sizeof(inst)); /* const issues */

	inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	/*
	 *	Only Access-Request gets a cleanup delay.
	 */
	if (!inst->parent->code_allowed[FR_CODE_ACCESS_REQUEST]) return;

	/*
	 *	And then, only if it is non-zero.
	 */
	if (!inst->cleanup_delay) return;

	inst->el = el;
}


static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	/*
	 *	Default to all IPv6 interfaces (it's the future)
	 */
	if (!inst->ipaddr_is_set && !inst->ipv4addr_is_set && !inst->ipv6addr_is_set) {
		inst->ipaddr.af = AF_INET6;
		inst->ipaddr.prefix = 128;
		inst->ipaddr.addr.v6 = in6addr_any;	/* in6addr_any binds to all addresses */
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (!inst->port) {
		struct servent *s;

		if (!inst->port_name) {
			cf_log_err(cs, "No 'port' specified in 'udp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "udp");
		if (!s) {
			cf_log_err(cs, "Unknown value for 'port_name = %s", inst->port_name);
			return -1;
		}

		inst->port = ntohl(s->s_port);
	}

	FR_INTEGER_BOUND_CHECK("cleanup_delay", inst->cleanup_delay, <=, 30);

	inst->ft = fr_radius_tracking_create(inst, sizeof(proto_radius_udp_address_t), inst->parent->code_allowed);
	if (!inst->ft) {
		cf_log_err(cs, "Failed to create tracking table: %s", fr_strerror());
	}

	return 0;
}

static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	dl_instance_t const	*dl_inst;

	/*
	 *	Find the dl_instance_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_instance_find(instance);
	rad_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_radius_t);

	return 0;
}

/** Private interface for use by proto_radius
 *
 */
extern proto_radius_app_io_t proto_radius_app_io_private;
proto_radius_app_io_t proto_radius_app_io_private = {
	.client			= mod_client,
	.src			= mod_src_address,
	.dst			= mod_dst_address
};

extern fr_app_io_t proto_radius_udp;
fr_app_io_t proto_radius_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_radius_udp_t),
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,
	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
