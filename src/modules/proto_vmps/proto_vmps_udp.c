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
 * @file proto_vmps_udp.c
 * @brief VMPS handler for UDP.
 *
 * @copyright 2016 The Freeradius server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_vmps.h"

typedef struct {
	proto_vmps_t	const		*parent;		//!< The module that spawned us!

	int				sockfd;

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
} proto_vmps_udp_t;

static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_IS_SET_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_vmps_udp_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_vmps_udp_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_vmps_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_vmps_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_vmps_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_vmps_udp_t, port) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, proto_vmps_udp_t, recv_buff) },

	CONF_PARSER_TERMINATOR
};


/** Return the src address associated with the packet_ctx
 *
 */
static int mod_src_address(fr_socket_addr_t *src, UNUSED void const *instance, void const *packet_ctx)
{
	fr_ip_srcdst_t const *ip = packet_ctx;

	memset(src, 0, sizeof(*src));

	src->proto = IPPROTO_UDP;
	memcpy(&src->ipaddr, &ip->src_ipaddr, sizeof(src->ipaddr));

	return 0;
}

/** Return the dst address associated with the packet_ctx
 *
 */
static int mod_dst_address(fr_socket_addr_t *dst, UNUSED void const *instance, void const *packet_ctx)
{
	fr_ip_srcdst_t const *ip = packet_ctx;

	memset(dst, 0, sizeof(*dst));

	dst->proto = IPPROTO_UDP;
	memcpy(&dst->ipaddr, &ip->dst_ipaddr, sizeof(dst->ipaddr));

	return 0;
}


/** Decode the packet.
 *
 */
static int mod_decode(UNUSED void const *instance, UNUSED REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{
#if 0
//	proto_vmps_udp_t const *inst = talloc_get_type_abort_const(instance, proto_vmps_udp_t);
	fr_ip_srcdst_t *ip;
	uint8_t *packet;
	size_t packet_len;

	ip = talloc_memdup(request, request->async->packet_ctx, sizeof(*ip));
	if (!ip) return -1;

	request->async->packet_ctx = ip;

	packet = data + sizeof(*ip);
	packet_len = data_len - sizeof(*ip);

	// decode the packet into attributes.
#endif

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, UNUSED REQUEST *request, UNUSED uint8_t *buffer, UNUSED size_t buffer_len)
{
#if 0
//	proto_vmps_udp_t const *inst = talloc_get_type_abort_const(instance, proto_vmps_udp_t);
	fr_ip_srcdst_t *ip;
	uint8_t *packet;
	size_t packet_len;

	ip = request->async->packet_ctx;
	packet = buffer + sizeof(*ip);
	packet_len = buffer_len - sizeof(*ip);

	memcpy(buffer, ip, sizeof(*ip));

	// encode packet in buffer
#endif

	return 0;
}

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority, bool *is_dup)
{
	proto_vmps_udp_t const		*inst = talloc_get_type_abort(instance, proto_vmps_udp_t);
	fr_ip_srcdst_t			*ip;
	uint8_t				*packet;
	size_t				packet_len;
	ssize_t				data_size;
	struct timeval			timestamp;

	ip = (fr_ip_srcdst_t *) buffer; /* @todo - should be aligned */
	packet = buffer + sizeof(*ip);
	packet_len = buffer_len - sizeof(*ip);
	*leftover = 0;
	*is_dup = false;

	data_size = udp_recv(inst->sockfd, packet, packet_len, 0,
			     &ip->src_ipaddr, &ip->src_port,
			     &ip->dst_ipaddr, &ip->dst_port,
			     &ip->if_index, &timestamp);
	if (data_size <= 0) return data_size;

	packet_len = data_size;

	/*
	 *	If it's not a VMPS packet, ignore it.
	 */
	if (!fr_vqp_ok(packet, &packet_len)) return 0;

	*packet_ctx = ip;
	*recv_time = NULL;
	*priority = PRIORITY_NORMAL;

	return packet_len + sizeof(*ip);
}

static ssize_t mod_write(void *instance, void *packet_ctx,
			 UNUSED fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_vmps_udp_t	*inst = talloc_get_type_abort(instance, proto_vmps_udp_t);
	fr_ip_srcdst_t		*ip = packet_ctx;
	uint8_t			*packet;
	size_t			packet_len;
	ssize_t			data_size;

	rad_assert(packet_ctx == buffer);

	/*
	 *	Don't reply.
	 */
	if (buffer_len == 1) return buffer_len;

	packet = buffer + sizeof(*ip);
	packet_len = buffer_len - sizeof(*ip);


	/*
	 *	Only write replies if they're VMPS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = udp_send(inst->sockfd, packet, packet_len, 0,
			     &ip->dst_ipaddr, ip->dst_port,
			     ip->if_index,
			     &ip->src_ipaddr, ip->src_port);
	if (data_size < 0) return data_size;

	/*
	 *	Tell the caller we've written it all.
	 */
	return buffer_len;
}

/** Open a UDP listener for VMPS
 *
 * @param[in] instance of the VMPS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_vmps_udp_t		*inst = talloc_get_type_abort(instance, proto_vmps_udp_t);

	int				sockfd = 0;
	uint16_t			port = inst->port;

	sockfd = fr_socket_server_udp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		PERROR("Failed creating UDP socket");
	error:
		return -1;
	}

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		PERROR("Failed binding socket");
		goto error;
	}

	inst->sockfd = sockfd;

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the VMPS UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_vmps_udp_t const *inst = talloc_get_type_abort_const(instance, proto_vmps_udp_t);

	return inst->sockfd;
}


static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	proto_vmps_udp_t *inst = talloc_get_type_abort(instance, proto_vmps_udp_t);

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

	return 0;
}

static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_vmps_udp_t	*inst = talloc_get_type_abort(instance, proto_vmps_udp_t);
	dl_instance_t const	*dl_inst;

	/*
	 *	Find the dl_instance_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_instance_find(instance);
	rad_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_vmps_t);

	return 0;
}

static int mod_detach(void *instance)
{
	proto_vmps_udp_t	*inst = talloc_get_type_abort(instance, proto_vmps_udp_t);

	/*
	 *	@todo - have our OWN event loop for timers, and a
	 *	"copy timer from -> to, which means we only have to
	 *	delete our child event loop from the parent on close.
	 */

	close(inst->sockfd);
	return 0;
}


/** Private interface for use by proto_vmps
 *
 */
extern proto_vmps_app_io_t proto_vmps_app_io_private;
proto_vmps_app_io_t proto_vmps_app_io_private = {
	.src			= mod_src_address,
	.dst			= mod_dst_address
};

extern fr_app_io_t proto_vmps_udp;
fr_app_io_t proto_vmps_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "vmps_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_vmps_udp_t),
	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,
	.open			= mod_open,
	.read			= mod_read,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.write			= mod_write,
	.fd			= mod_fd,
};
