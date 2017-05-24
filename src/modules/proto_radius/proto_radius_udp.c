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

typedef struct fr_packet_ctx_t {
	int		sockfd;

	uint8_t const	*secret;
	size_t		secret_len;

	uint8_t		original[20];
	uint8_t		id;

	struct sockaddr_storage src;
	socklen_t	salen;
} fr_packet_ctx_t;


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
static int mod_open(TALLOC_CTX *ctx, int *sockfd_p, void **transport_ctx, fr_transport_t **transport_p, CONF_SECTION *listen, bool verify_config)
{
	int rcode;
	uint16_t port;
	uint32_t recv_buff;
#if 0
	char const *interface;
	CONF_PAIR *cp;
#endif
	CONF_SECTION *cs;
	fr_ipaddr_t ipaddr;

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

	/*
	 *	Try IPv4 first
	 */
	memset(&ipaddr, 0, sizeof(ipaddr));
	ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);

	rcode = cf_pair_parse(NULL, cs, "ipaddr", FR_ITEM_POINTER(FR_TYPE_COMBO_IP_ADDR, &ipaddr), NULL, T_INVALID);
	if (rcode < 0) return -1;
	if (rcode != 0) rcode = cf_pair_parse(NULL, cs, "ipv4addr",
					      FR_ITEM_POINTER(FR_TYPE_IPV4_ADDR, &ipaddr), NULL, T_INVALID);
	if (rcode < 0) return -1;
	if (rcode != 0) rcode = cf_pair_parse(NULL, cs, "ipv6addr",
					      FR_ITEM_POINTER(FR_TYPE_IPV6_ADDR, &ipaddr), NULL, T_INVALID);
	if (rcode < 0) return -1;
	/*
	 *	Default to all IPv6 interfaces (it's the future)
	 */
	if (rcode != 0) {
		memset(&ipaddr, 0, sizeof(ipaddr));
		ipaddr.af = AF_INET6;
		ipaddr.prefix = 128;
		ipaddr.addr.v6 = in6addr_any;	/* in6addr_any binds to all addresses */
	}

	rcode = cf_pair_parse(NULL, cs, "port", FR_ITEM_POINTER(FR_TYPE_UINT16, &port), "0", T_BARE_WORD);
	if (rcode < 0) return -1;

	rcode = cf_pair_parse(NULL, cs, "recv_buff", FR_ITEM_POINTER(FR_TYPE_UINT32, &recv_buff), "0", T_BARE_WORD);
	if (rcode < 0) return -1;
	if (recv_buff) {
		FR_INTEGER_BOUND_CHECK("recv_buff", recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", recv_buff, <=, INT_MAX);
	}

#if 0
	/*
	 *	If we can bind to interfaces, do so,
	 *	else don't.
	 */
	cp = cf_pair_find(cs, "interface");
	interface = NULL;
	if (cp) {
		char const *value = cf_pair_value(cp);
		if (!value) {
			cf_log_err_cp(cp, "Must specify a value for 'interface'");
			return -1;
		}
		interface = value;
	}
#endif

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
