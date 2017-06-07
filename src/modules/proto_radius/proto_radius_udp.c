/*
 * proto_radius_udp.c	RADIUS handler for UDP
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2016 The FreeRADIUS server project
 * Copyright 2016 Alan DeKok <aland@deployingradius.com>
 */

#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

typedef struct {
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
	/*
	 *	SHIT
	 */
	uint8_t const			*secret;
	size_t				secret_len;

	uint8_t				original[20];
	uint8_t				id;

	struct sockaddr_storage		src;
	socklen_t			salen;
} fr_proto_radius_udp_ctx_t;

static const CONF_PARSER udp_listen_conf[] = {
	{ FR_CONF_IS_SET_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, fr_proto_radius_udp_ctx_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, fr_proto_radius_udp_ctx_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, fr_proto_radius_udp_ctx_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, fr_proto_radius_udp_ctx_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, fr_proto_radius_udp_ctx_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, fr_proto_radius_udp_ctx_t, port) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, fr_proto_radius_udp_ctx_t, recv_buff) },
	CONF_PARSER_TERMINATOR
};

static ssize_t mod_read(void *ctx, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_size;
	size_t packet_len;
	fr_proto_radius_udp_ctx_t *pc = ctx;
	decode_fail_t reason;

	pc->salen = sizeof(pc->src);

	data_size = recvfrom(pc->sockfd, buffer, buffer_len, 0, (struct sockaddr *) &pc->src, &pc->salen);
	if (data_size <= 0) return data_size;

	packet_len = data_size;

	/*
	 *	If it's not a RADIUS packet, ignore it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, false, &reason)) {
		return 0;
	}

	/*
	 *	If the signature fails validation, ignore it.
	 */
	if (fr_radius_verify(buffer, NULL, pc->secret, pc->secret_len) < 0) {
		return 0;
	}

	pc->id = buffer[1];
	memcpy(pc->original, buffer, sizeof(pc->original));

	return packet_len;
}


static ssize_t mod_write(void *ctx, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_size;
	fr_proto_radius_udp_ctx_t *pc = ctx;

	pc->salen = sizeof(pc->src);

	/*
	 *	@todo - do more stuff
	 */
	data_size = sendto(pc->sockfd, buffer, buffer_len, 0, (struct sockaddr *) &pc->src, pc->salen);
	if (data_size <= 0) return data_size;

	/*
	 *	@todo - post-write cleanups
	 */

	return data_size;
}

static int mod_instantiate(CONF_SECTION *cs, void *instance)
{
	fr_proto_radius_udp_ctx_t	*inst = instance;

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
			cf_log_err_cs(cs, "No 'port' specified in 'udp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "udp");
		if (!s) {
			cf_log_err_cs(cs, "Unknown value for 'port_name = %s", inst->port_name);
			return -1;
		}

		inst->port = ntohl(s->s_port);
	}

	inst->secret = (uint8_t const *) "testing123";
	inst->secret_len = 10;

	return 0;
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
	fr_proto_radius_udp_ctx_t	*inst = instance;

	int				sockfd = 0;

	sockfd = fr_socket_server_udp(&inst->ipaddr, &inst->port, inst->port_name, true);
	if (sockfd < 0) {
		ERROR("%s", fr_strerror());
	error:
		return -1;
	}

	if (fr_socket_bind(sockfd, &inst->ipaddr, &inst->port, inst->interface) < 0) {
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
static int mod_fd(void *instance)
{
	fr_proto_radius_udp_ctx_t	*inst = instance;

	return inst->sockfd;
}

extern fr_app_io_t proto_radius_udp;
fr_app_io_t proto_radius_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.config			= udp_listen_conf,
	.inst_size		= sizeof(fr_proto_radius_udp_ctx_t),
	.instantiate		= mod_instantiate,
	.op 			= {
		.name			= "radius_udp",
		.default_message_size	= 4096,
		.open			= mod_open,
		.read			= mod_read,
		.write			= mod_write,
		.fd			= mod_fd,
	}
};
