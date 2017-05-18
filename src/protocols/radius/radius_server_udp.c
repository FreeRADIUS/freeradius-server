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
 *
 * @brief RADIUS Server UDP front-end
 * @file protocols/radius/radius_server_udp.c
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/io/transport.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/inet.h>
#include <freeradius-devel/radius/radius.h>

#ifndef RDEBUG
#define RDEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#endif

#ifndef DEBUG
#define DEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#endif

typedef struct fr_packet_ctx_t {
	int		sockfd;

	uint8_t const	*secret;
	size_t		secret_len;

	uint8_t		original[20];
	uint8_t		id;

	struct sockaddr_storage src;
	socklen_t	salen;
} fr_packet_ctx_t;


static int mod_decode(void const *ctx, uint8_t *const data, size_t data_len, REQUEST *request)
{
	fr_packet_ctx_t const *pc = ctx;

	RDEBUG("\t\tDECODE <<< request %zd - %p data %p size %zd\n", request->number, pc, data, data_len);

	return 0;
}

static ssize_t mod_encode(void const *ctx, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	fr_packet_ctx_t const *pc = ctx;

	RDEBUG("\t\tENCODE >>> request %zd - data %p %p room %zd\n", request->number, pc, buffer, buffer_len);

	if (buffer_len < 20) return -1;

	buffer[0] = FR_CODE_ACCESS_ACCEPT;
	buffer[1] = pc->id;
	buffer[2] = 0;
	buffer[3] = 20;

	(void) fr_radius_sign(buffer, pc->original, pc->secret, pc->secret_len);

	return 20;
}

static size_t mod_nak(void const *ctx, uint8_t *const packet, size_t packet_len, UNUSED uint8_t *reply, UNUSED size_t reply_len)
{
	DEBUG("\t\tNAK !!! request %d - data %p %p size %zd\n", packet[1], ctx, packet, packet_len);

	return 10;
}

static fr_transport_final_t mod_process(REQUEST *request, fr_transport_action_t action)
{
	RDEBUG("\t\tPROCESS --- request %zd action %d\n", request->number, action);

	return FR_TRANSPORT_REPLY;
}

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

extern fr_transport_t fr_radius_server_udp;
fr_transport_t fr_radius_server_udp = {
	.name			= "radius_server_udp",
	.id			= 1,		/* @todo fix me later */
	.default_message_size	= 4096,
	.read			= mod_read,
	.write			= mod_write,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.nak			= mod_nak,
	.process		= mod_process
};
