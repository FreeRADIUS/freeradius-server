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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/transport.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

typedef struct {
	int			sockfd;		//!< Socket the packet was received on.

	uint8_t const		*secret;
	size_t			secret_len;

	uint8_t			original[20];
	uint8_t			id;

	struct sockaddr_storage	src;
	socklen_t		salen;
} fr_packet_ctx_t;

/** Basic config for a UDP listen socket
 *
 */
typedef struct {
	fr_ipaddr_t		ipaddr;			//!< Ipaddr to listen on.

	bool			ipaddr_is_set;		//!< ipaddr config item is set.
	bool			ipv4addr_is_set;	//!< ipv4addr config item is set.
	bool			ipv6addr_is_set;	//!< ipv6addr config item is set.

	char const		*interface;		//!< Interface to bind to.

	uint16_t		port;			//!< Port to listen on.
	uint32_t		recv_buff;		//!< How big the kernel's receive buffer should be.
	bool			recv_buff_is_set;	//!< Whether we were provided with a receive buffer value.
} fr_proto_radius_udp_conf_t;

static const CONF_PARSER udp_listen_conf[] = {
	{ FR_CONF_IS_SET_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, fr_proto_radius_udp_conf_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, fr_proto_radius_udp_conf_t, ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, fr_proto_radius_udp_conf_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, fr_proto_radius_udp_conf_t, interface) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, fr_proto_radius_udp_conf_t, port) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, fr_proto_radius_udp_conf_t, recv_buff) },
	CONF_PARSER_TERMINATOR
};

static ssize_t mod_read(int sockfd, void *ctx, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_size;
	size_t packet_len;
	fr_packet_ctx_t *pc = ctx;
	decode_fail_t reason;

	pc->salen = sizeof(pc->src);

	data_size = recvfrom(sockfd, buffer, buffer_len, 0, (struct sockaddr *) &pc->src, &pc->salen);
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
	if (!fr_radius_verify(buffer, NULL, pc->secret, pc->secret_len)) {
		return 0;
	}

	pc->id = buffer[1];
	memcpy(pc->original, buffer, sizeof(pc->original));

	return packet_len;
}


static ssize_t mod_write(int sockfd, void *ctx, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_size;
	fr_packet_ctx_t *pc = ctx;

	pc->salen = sizeof(pc->src);

	/*
	 *	@todo - do more stuff
	 */
	data_size = sendto(sockfd, buffer, buffer_len, 0, (struct sockaddr *) &pc->src, pc->salen);
	if (data_size <= 0) return data_size;

	/*
	 *	@todo - post-write cleanups
	 */

	return data_size;
}

/*
 *	We'll figure out how to fix this later...
 */
static fr_transport_t proto_radius_udp_transport = {
	.name			= "radius_udp",
	.default_message_size	= 4096,
	.read			= mod_read,
	.write			= mod_write,
};


/** Open a UDP listener for RADIUS
 *
 */
static int mod_open(TALLOC_CTX *ctx, int *sockfd_p, void **transport_ctx,
		    fr_transport_t **transport_p, CONF_SECTION *listen, bool verify_config)
{
	CONF_SECTION 			*cs;
	fr_proto_radius_udp_conf_t	*config;

	/*
	 *	We know our name, so we don't need to re-parse the
	 *	"transport" config item
	 */
	cs = cf_subsection_find_next(listen, NULL, "udp");

	/*
	 *	Be gentle...
	 */
	if (!cs) {
		cs = listen;
	} else {
		cf_log_info(cs, "    udp {");
	}

	config = talloc_zero(ctx, fr_proto_radius_udp_conf_t);
	if (cf_section_parse(config, config, cs, udp_listen_conf) < 0) return -1;

	/*
	 *	Default to all IPv6 interfaces (it's the future)
	 */
	if (!config->ipaddr_is_set && !config->ipv4addr_is_set && !config->ipv6addr_is_set) {
		config->ipaddr.af = AF_INET6;
		config->ipaddr.prefix = 128;
		config->ipaddr.addr.v6 = in6addr_any;	/* in6addr_any binds to all addresses */
	}

	if (config->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", config->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", config->recv_buff, <=, INT_MAX);
	}

	if (cs != listen) cf_log_info(cs, "    }");

	/*
	 *	If we're only checking the configuration, don't open
	 *	sockets.
	 */
	if (verify_config) return 0;

	*transport_p = &proto_radius_udp_transport;
	*sockfd_p = -1;
	*transport_ctx = talloc_strdup(ctx, "testing");
	if (!*transport_ctx) {
		cf_log_err_cs(cs, "Failed allocating memory");
		talloc_free(config);
		return -1;
	}

	/*
	 *	Allocate fr_app_t
	 *	open sockets
	 *	create transport structure.
	 */

	return 0;
}

extern fr_app_io_t proto_radius_udp;
fr_app_io_t proto_radius_udp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_udp",
	.open		= mod_open,
};
