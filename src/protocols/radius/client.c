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
	int i;
	fr_radius_client_fd_bio_t *my;

	fr_assert(fd_cfg->type == FR_BIO_FD_CONNECTED);

	my = talloc_zero(ctx, fr_radius_client_fd_bio_t);
	if (!my) return NULL;

	/*
	 *	Allocate tracking for all of the packets.
	 */
	for (i = 1; i < FR_RADIUS_CODE_MAX; i++) {
		if (!cfg->allowed[i]) continue;

		my->codes[i] = fr_radius_id_alloc(my);
		if (!my->codes[i]) goto fail;
	}

	my->fd = fr_bio_fd_alloc(my, NULL, fd_cfg, 0);
	if (!my->fd) {
	fail:
		talloc_free(my);
		return NULL;
	}

	my->fd_info = fr_bio_fd_info(my->fd);
	fr_assert(my->fd_info != NULL);

	my->reply_socket = my->fd_info->socket;
	if ((my->reply_socket.af == AF_INET) || (my->reply_socket.af == AF_INET6)) {
		fr_socket_addr_swap(&my->reply_socket, &my->fd_info->socket);
	}

	my->mem = fr_bio_mem_alloc(my, read_size, 2 * 4096, my->fd);
	if (!my->mem) goto fail;

	my->cfg = *cfg;
	my->mem->uctx = &my->cfg.verify;

	my->common.bio = my->mem;

	talloc_set_destructor(my, _radius_client_fd_bio_free);

	return my;
}

int fr_radius_client_fd_bio_write(fr_radius_client_fd_bio_t *my, fr_packet_t *packet, fr_pair_list_t *list)
{
	ssize_t slen;
	fr_radius_client_packet_ctx_t *ctx;

	fr_assert(!packet->data);

	fr_assert(packet->code > 0);
	fr_assert(packet->code < FR_RADIUS_CODE_MAX);

	if (!my->codes[packet->code]) {
		fr_strerror_printf("Outgoing packet code %s is disallowed by the configuration",
				   fr_radius_packet_name[packet->code]);
		return -1;
	}

	if (fr_radius_code_id_pop(my->codes, packet) < 0) {
		fr_strerror_const("All IDs are in use");
		return -1;
	}

	/*
	 *	Initialize our client retry data structure.
	 */
	ctx = packet->uctx;
	ctx->retry_ctx = NULL;
	ctx->packet = packet;
	ctx->reply = NULL;

	/*
	 *	Encode the packet.
	 */
	if (fr_packet_encode(packet, list, NULL, (char const *) my->cfg.verify.secret) < 0) {
	fail:
		fr_radius_code_id_push(my->codes, packet);
		return -1;
	}

	if (fr_packet_sign(packet, NULL, (char const *) my->cfg.verify.secret) < 0) goto fail;

	slen = fr_bio_write(my->common.bio, ctx, packet->data, packet->data_len);
	if (slen <= 0) goto fail;

	return 0;
}

#if 0
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

static void radius_client_retry_sent(UNUSED fr_bio_t *bio, void *packet_ctx, UNUSED const void *buffer, UNUSED size_t size,
				     fr_bio_retry_entry_t *retry_ctx)
{
	fr_radius_client_packet_ctx_t *ctx = packet_ctx;

	ctx->retry_ctx = retry_ctx;
}

static bool radius_client_retry_response(fr_bio_t *bio, fr_bio_retry_entry_t **item_p, void *packet_ctx, const void *buffer, UNUSED size_t size)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_client_packet_ctx_t *ctx, *reply_ctx;
	unsigned int code;
	uint8_t *data = UNCONST(uint8_t *, buffer); /* @todo - for verify() */
	fr_packet_t *packet;

	/*
	 *	We now have a complete packet in our buffer.  Check if it is one we expect.
	 */
	if (!data[0] || (data[0] >= FR_RADIUS_CODE_MAX)) {
		return false;
	}

	/*
	 *	Is the code an allowed reply code?
	 */
	code = allowed_replies[data[0]];
	if (!code) return false;

	/*
	 *	It's a reply, but not a permitted reply to a particular request.
	 *
	 *	@todo - for protocol error, look up original packet code <sigh>
	 */
	packet = fr_radius_code_id_find(my->codes, code, data[1]);
	if (!packet) return false;

	ctx = packet->uctx;
	reply_ctx = packet_ctx;

	/*
	 *	No reply yet, verify the response packet, and save it for later.
	 */
	if (!ctx->reply) {
		if (fr_radius_verify(data, packet->data + 4,
				     my->cfg.verify.secret, my->cfg.verify.secret_len,
				     my->cfg.verify.require_message_authenticator) < 0) {
			return false;
		}

		*item_p = ctx->retry_ctx;

		reply_ctx->packet = packet;
		return true;
	}

	/*
	 *	The reply has the correct ID / Code, but it's not the
	 *	same as our previous reply: ignore it.
	 */
	if (memcmp(buffer, ctx->reply, RADIUS_HEADER_LENGTH) != 0) return false;
	
	/*
	 *	Tell the caller that it's a duplicate reply.
	 */
	*item_p = ctx->retry_ctx;
	return false;
}

static void radius_client_retry_release(fr_bio_t *bio, void *packet_ctx, UNUSED const void *buffer, UNUSED size_t size, UNUSED fr_bio_retry_release_reason_t reason)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_client_packet_ctx_t *ctx = packet_ctx;

	fr_radius_code_id_push(my->codes, ctx->packet);
}
#endif

int fr_radius_client_fd_bio_read(fr_bio_packet_t *bio, fr_packet_t **packet_p,
				 TALLOC_CTX *pair_ctx, fr_pair_list_t *out)
{
	ssize_t slen;
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);
	fr_packet_t *packet, *reply;
	fr_radius_client_packet_ctx_t ctx = {};

	/*
	 *	We read the response packet ctx into our local structure.  If we have a real response, we will
	 *	swap to using the request context, and not the response context.
	 */
	slen = fr_bio_read(my->common.bio, &ctx, &my->buffer, sizeof(my->buffer));
	if (!slen) return 0;

	if (slen < 0) {
		fr_assert(slen != fr_bio_error(IO_WOULD_BLOCK));
		return slen;
	}

	packet = ctx.packet;
	fr_assert(packet != NULL);

	/*
	 *	Allocate the new request data structure
	 */
	reply = fr_packet_alloc(packet, false);
	if (!reply) return -1;
	ctx.reply = reply;

	/*
	 *	This is for connected sockets.
	 */
	reply->socket = my->reply_socket;
	reply->timestamp = fr_time();

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
	if (fr_radius_decode_simple(pair_ctx, out, reply->data, reply->data_len,
				    packet->vector, (char const *) my->cfg.verify.secret) < 0) {
		fr_assert(0);
	}

	reply->uctx = packet->uctx;
	*packet_p = reply;

	return 1;
}

fr_bio_t *fr_radius_client_bio_get_fd(fr_bio_packet_t *bio)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	return my->fd;
}
