/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/radius/client.c
 * @brief Functions to support RADIUS bio handlers for client sockets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radius/client.h>
#include <freeradius-devel/radius/client_udp.h>
#include <freeradius-devel/radius/client_tcp.h>
#include <freeradius-devel/radius/client_priv.h>

fr_bio_packet_t *fr_radius_client_bio_alloc(TALLOC_CTX *ctx, fr_radius_client_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_assert(fd_cfg->type == FR_BIO_FD_CONNECTED);

	if (fd_cfg->path || fd_cfg->filename) return NULL;

	if (fd_cfg->socket_type == SOCK_DGRAM) return fr_radius_client_udp_bio_alloc(ctx, cfg, fd_cfg);

	return fr_radius_client_tcp_bio_alloc(ctx, cfg, fd_cfg);
}

static int _radius_client_fd_bio_free(fr_radius_client_fd_bio_t *my)
{
	if (fr_bio_shutdown(my->common.bio) < 0) return -1;

	if (fr_bio_free(my->common.bio) < 0) return -1;

	return 0;
}


fr_radius_client_fd_bio_t *fr_radius_client_fd_bio_alloc(TALLOC_CTX *ctx, size_t read_size, fr_radius_client_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_radius_client_fd_bio_t *my;
	fr_bio_t *fd, *mem;

	fr_assert(fd_cfg->type == FR_BIO_FD_CONNECTED);

	my = talloc_zero(ctx, fr_radius_client_fd_bio_t);
	if (!my) return NULL;

	my->fd = fd = fr_bio_fd_alloc(my, NULL, fd_cfg, 0);
	if (!fd) {
	fail:
		talloc_free(my);
		return NULL;
	}
	my->fd = fd;

	my->mem = mem = fr_bio_mem_alloc(ctx, read_size, 2 * 4096, fd);
	if (!mem) goto fail;

	my->cfg = *cfg;
	mem->uctx = &my->cfg.verify;

	my->common.bio = mem;
	my->common.release = fr_radius_client_fd_bio_release;

	talloc_set_destructor(my, _radius_client_fd_bio_free);

	return my;
}

int fr_radius_client_fd_bio_write(fr_radius_client_fd_bio_t *my, UNUSED void *packet_ctx, fr_radius_packet_t *packet, fr_pair_list_t *list)
{
	ssize_t slen;

	fr_assert(!packet->data);

	fr_assert(packet->code > 0);
	fr_assert(packet->code < FR_RADIUS_CODE_MAX);

	/*
	 *	@todo - Allocate when the socket is opened, so we don't check it for every packet.
	 */
	if (!my->codes[packet->code] && !(my->codes[packet->code] = fr_radius_id_alloc(my))) return -1;

	if (fr_radius_code_id_pop(my->codes, packet) < 0) return -1;

	/*
	 *	Encode the packet.
	 */
	if (fr_radius_packet_encode(packet, list, NULL, (char const *) my->cfg.verify.secret) < 0) {
	fail:
		fr_radius_code_id_push(my->codes, packet);
		return -1;
	}

	if (fr_radius_packet_sign(packet, NULL, (char const *) my->cfg.verify.secret) < 0) goto fail;

	slen = fr_bio_write(my->common.bio, &packet->socket, packet->data, packet->data_len);
	if (slen <= 0) goto fail;

	return 0;
}

static const fr_radius_packet_code_t allowed_replies[FR_RADIUS_CODE_MAX] = {
	[FR_RADIUS_CODE_ACCESS_ACCEPT]		= FR_RADIUS_CODE_ACCESS_REQUEST,
	[FR_RADIUS_CODE_ACCESS_CHALLENGE]	= FR_RADIUS_CODE_ACCESS_REQUEST,
	[FR_RADIUS_CODE_ACCESS_REJECT]		= FR_RADIUS_CODE_ACCESS_REQUEST,

	[FR_RADIUS_CODE_ACCOUNTING_RESPONSE]	= FR_RADIUS_CODE_ACCOUNTING_REQUEST,

	[FR_RADIUS_CODE_COA_ACK]		= FR_RADIUS_CODE_COA_REQUEST,
	[FR_RADIUS_CODE_COA_NAK]		= FR_RADIUS_CODE_COA_REQUEST,

	[FR_RADIUS_CODE_DISCONNECT_ACK]		= FR_RADIUS_CODE_DISCONNECT_REQUEST,
	[FR_RADIUS_CODE_DISCONNECT_NAK]		= FR_RADIUS_CODE_DISCONNECT_REQUEST,

	[FR_RADIUS_CODE_PROTOCOL_ERROR]		= FR_RADIUS_CODE_PROTOCOL_ERROR,	/* Any */
};

int fr_radius_client_fd_bio_read(fr_bio_packet_t *bio, UNUSED void *packet_ctx, fr_radius_packet_t **packet_p,
				 fr_pair_list_t *out)
{
	int code;
	ssize_t slen;
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);
	fr_radius_packet_t *packet, *reply;
	fr_bio_fd_packet_ctx_t fd_ctx;

	slen = fr_bio_read(my->common.bio, &fd_ctx, &my->buffer, sizeof(my->buffer));
	if (!slen) return 0;

	if (slen < 0) {
		fr_assert(slen != fr_bio_error(IO_WOULD_BLOCK));

		return slen;
	}

	/*
	 *	We now have a complete packet in our buffer.  Check if it is one we expect.
	 */
	if (!my->buffer[0] || (my->buffer[0] >= FR_RADIUS_CODE_MAX)) {
		return 0;
	}

	/*
	 *	Is the code an allowed reply code?
	 */
	code = allowed_replies[my->buffer[0]];
	if (!code) return 0;

	/*
	 *	It's a reply, but not a permitted reply to a particular request.
	 *
	 *	@todo - for protocol error, look up original packet code <sigh>
	 */
	packet = fr_radius_code_id_find(my->codes, code, my->buffer[1]);
	if (!packet) return 0;

	if (fr_radius_verify(my->buffer, packet->data + 4,
			     my->cfg.verify.secret, my->cfg.verify.secret_len,
			     my->cfg.verify.require_message_authenticator) < 0) {
		return 0;
	}

	/*
	 *	@todo - if we already have a reply then don't decode
	 *	it.  Just return "whoops, no packet".
	 *
	 *	@todo - provide an API to expire the outgoing packet.
	 *
	 *	@todo - provide an API to run timers for a particular packet.
	 *
	 *	Any retries, etc. are part of packet->uctx
	 */
	if (fr_radius_code_id_push(my->codes, packet) < 0) {
		fr_assert(0);
	}

	/*
	 *	Allocate the new request data structure
	 */
	reply = fr_radius_packet_alloc(packet, false);
	if (!reply) return -1;

	reply->socket = fd_ctx.socket;
	reply->timestamp = fd_ctx.when;

	reply->data = talloc_memdup(reply, my->buffer, slen);
	if (!reply->data) {
		talloc_free(reply);
		return -1;
	}
	reply->data_len = slen;

	reply->code = reply->data[0];
	reply->id = reply->data[1];
	memcpy(reply->vector, reply->data + 4, sizeof(reply->vector));

	/*
	 *	If this fails, we're out of memory.
	 */
	if (fr_radius_decode_simple(reply, out, reply->data, reply->data_len,
				    packet->vector, (char const *) my->cfg.verify.secret) < 0) {
		fr_assert(0);
	}

	reply->uctx = packet->uctx;
	*packet_p = reply;

	return 1;
}

/** Release (or cancel) an outgoing packet.
 *
 */
int fr_radius_client_fd_bio_release(fr_bio_packet_t *bio, UNUSED void *packet_ctx, fr_radius_packet_t *packet)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	fr_assert(packet->id >= 0);

	if (fr_radius_code_id_find(my->codes, packet->code, packet->id) != packet) {
		return -1;
	}

	if (fr_radius_code_id_push(my->codes, packet) < 0) return -1;

	return 0;
}

fr_bio_t *fr_radius_client_bio_get_fd(fr_bio_packet_t *bio)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	return my->fd;
}
