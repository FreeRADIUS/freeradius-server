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

#include <freeradius-devel/protocol/radius/rfc2865.h>

static void radius_client_retry_sent(fr_bio_t *bio, void *packet_ctx, const void *buffer, UNUSED size_t size,
				     fr_bio_retry_entry_t *retry_ctx);
static bool radius_client_retry_response(fr_bio_t *bio, fr_bio_retry_entry_t **retry_ctx_p, UNUSED void *packet_ctx, const void *buffer, UNUSED size_t size);
static void radius_client_retry_release(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, UNUSED fr_bio_retry_release_reason_t reason);

fr_bio_packet_t *fr_radius_client_bio_alloc(TALLOC_CTX *ctx, fr_radius_client_config_t *cfg, fr_bio_fd_config_t const *fd_cfg)
{
	fr_assert(fd_cfg->type == FR_BIO_FD_CONNECTED);

	if (fd_cfg->path || fd_cfg->filename) {
		fr_strerror_const("Domain sockets and files are not supported");
		return NULL;
	}

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
		if (!cfg->outgoing[i]) continue;

		my->codes[i] = fr_radius_id_alloc(my);
		if (!my->codes[i]) goto fail;
	}

	my->fd = fr_bio_fd_alloc(my, fd_cfg, 0);
	if (!my->fd) {
	fail:
		talloc_free(my);
		return NULL;
	}

	/*
	 *	So that read / write pause / resume callbacks can find us
	 */
	my->fd->uctx = my;

	/*
	 *	Set up read / write blocked / resume callbacks.
	 */
	if (cfg->pause_resume_cfg.write_blocked || cfg->pause_resume_cfg.read_blocked) {
		fr_radius_client_bio_cb_set((fr_bio_packet_t *) my, &cfg->pause_resume_cfg);
	}

	my->info.fd_info = fr_bio_fd_info(my->fd);
	fr_assert(my->info.fd_info != NULL);

	my->reply_socket = my->info.fd_info->socket;
	if ((my->reply_socket.af == AF_INET) || (my->reply_socket.af == AF_INET6)) {
		fr_socket_addr_swap(&my->reply_socket, &my->info.fd_info->socket);
	}

	my->mem = fr_bio_mem_alloc(my, read_size, 2 * 4096, my->fd);
	if (!my->mem) goto fail;
	my->mem->uctx = &my->cfg.verify;

	my->retry = fr_bio_retry_alloc(my, 256, radius_client_retry_sent, radius_client_retry_response,
				       NULL, radius_client_retry_release, &cfg->retry_cfg, my->mem);
	if (!my->retry) goto fail;
	my->retry->uctx = my;
	
	my->cfg = *cfg;

	my->common.bio = my->retry;

	/*
	 *	Set up the connected status.
	 */
	my->info.connected = (my->info.fd_info->type == FR_BIO_FD_CONNECTED) && (my->info.fd_info->state == FR_BIO_FD_STATE_OPEN);

	talloc_set_destructor(my, _radius_client_fd_bio_free);

	return my;
}

int fr_radius_client_fd_bio_write(fr_radius_client_fd_bio_t *my, void *request_ctx, fr_packet_t *packet, fr_pair_list_t *list)
{
	ssize_t slen;
	uint8_t *end;
	fr_radius_id_ctx_t *id_ctx;

	fr_assert(!packet->data);

	fr_assert(packet->code > 0);
	fr_assert(packet->code < FR_RADIUS_CODE_MAX);

	if (!my->codes[packet->code]) {
		fr_strerror_printf("Outgoing packet code %s is disallowed by the configuration",
				   fr_radius_packet_name[packet->code]);
		return fr_bio_error(GENERIC);
	}

	id_ctx = fr_radius_code_id_pop(my->codes, packet);
	if (!id_ctx) {
		/*
		 *	Try to cancel the oldest one.
		 */
		if (fr_bio_retry_entry_cancel(my->retry, NULL) < 1) {
		all_ids_used:
			my->all_ids_used = true;

			if (my->common.cb.write_blocked) my->common.cb.write_blocked(&my->common);

			fr_strerror_const("All IDs are in use");
			return fr_bio_error(GENERIC);
		}

		id_ctx = fr_radius_code_id_pop(my->codes, packet);
		if (!id_ctx) goto all_ids_used;
	}
	id_ctx->request_ctx = request_ctx;
	fr_assert(id_ctx->packet == packet);

	/*
	 *	@todo - just create the random auth vector here?
	 */
	if ((packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) ||
	    (packet->code == FR_RADIUS_CODE_STATUS_SERVER)) {
		memcpy(my->buffer + 4, packet->vector, sizeof(packet->vector));
	}

	/*
	 *	Encode the packet.
	 */
	slen = fr_radius_encode(my->buffer, sizeof(my->buffer), NULL,
				(char const *) my->cfg.verify.secret, my->cfg.verify.secret_len,
				packet->code, packet->id, list);
	if (slen < 0) {
	fail:
		fr_radius_code_id_push(my->codes, packet);
		return fr_bio_error(GENERIC);
	}

	end = my->buffer + slen;

	/*
	 *	Add our own Proxy-State if requested.
	 *
	 *	@todo - don't add Proxy-State for status checks, which could also be Access-Request or
	 *	Accounting-Request.  Note also that Status-Server packets should bypass the normal write
	 *	routines, and instead be run by internal timers.
	 */
	if (my->cfg.add_proxy_state && (packet->code != FR_RADIUS_CODE_STATUS_SERVER) && ((end + 6) < (my->buffer + sizeof(my->buffer)))) {
		end[0] = FR_PROXY_STATE;
		end[1] = 6;
		memcpy(&end[2], &my->cfg.proxy_state, sizeof(my->cfg.proxy_state));

		end += 6;
	}

	packet->data_len = end - my->buffer;
	fr_nbo_from_uint64(my->buffer + 2, packet->data_len);

	packet->data = talloc_array(packet, uint8_t, packet->data_len);
	if (!packet->data) goto fail;

	slen = fr_radius_sign(my->buffer, NULL,
				(uint8_t const *) my->cfg.verify.secret, my->cfg.verify.secret_len);
	if (slen < 0) goto fail;

	slen = fr_bio_write(my->common.bio, &packet->socket, my->buffer, packet->data_len);
	if (slen < 0) {
		fr_radius_code_id_push(my->codes, packet);
		return slen;
	}

	/*
	 *	Only after successful write do we copy the data back to the packet structure.
	 */
	memcpy(packet->data, my->buffer, packet->data_len);
	memcpy(packet->vector, packet->data + 4, RADIUS_AUTH_VECTOR_LENGTH);

	/*
	 *	We are using an outgoing memory bio, which takes care of writing partial packets.  As a
	 *	result, our call to the bio will always return that a full packet was written.
	 */
	fr_assert((size_t) slen == packet->data_len);

	my->info.outstanding++;

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

static void radius_client_retry_sent(fr_bio_t *bio, void *packet_ctx, const void *buffer, UNUSED size_t size,
				     fr_bio_retry_entry_t *retry_ctx)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_id_ctx_t *id_ctx;
	uint8_t const *data = buffer;

	id_ctx = fr_radius_code_id_find(my->codes, data[0], data[1]);
	fr_assert(id_ctx != NULL);

	id_ctx->packet = packet_ctx;
	id_ctx->retry_ctx = retry_ctx;

	retry_ctx->uctx = id_ctx;

	(void) fr_bio_retry_entry_start(bio, retry_ctx, &my->cfg.retry[data[0]]);

	/*
	 *	@todo - set this for Accounting-Request packets which have Acct-Delay-Time we need to track
	 *	where the Acct-Delay-Time is in the packet, along with its original value, and then we can use
	 *	the #fr_retry_t to discover how many seconds to add to Acct-Delay-Time.
	 */
	retry_ctx->rewrite = NULL;

//	if (buffer[0] != FR_RADIUS_CODE_ACCOUNTING_REQUEST) return;
}


static bool radius_client_retry_response(fr_bio_t *bio, fr_bio_retry_entry_t **retry_ctx_p, void *packet_ctx, const void *buffer, UNUSED size_t size)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	unsigned int code;
	uint8_t *data = UNCONST(uint8_t *, buffer); /* @todo - for verify() */
	fr_radius_id_ctx_t *id_ctx;
	fr_packet_t *response = packet_ctx;

	/*
	 *	We now have a complete packet in our buffer.  Check if it is one we expect.
	 */
	fr_assert(data[0] > 0);
	fr_assert(data[0] < FR_RADIUS_CODE_MAX);

	/*
	 *	Is the code an allowed reply code?
	 */
	code = allowed_replies[data[0]];
	if (!code) return false;

	/*
	 *	It's a reply, but not a permitted reply to a particular request.
	 *
	 *	@todo - Status-Server.  And for protocol error, look up original packet code
	 */
	id_ctx = fr_radius_code_id_find(my->codes, code, data[1]);
	if (!id_ctx) return false;

	/*
	 *	No reply yet, verify the response packet, and save it for later.
	 */
	if (!id_ctx->response) {
		if (fr_radius_verify(data, id_ctx->packet->data + 4,
				     my->cfg.verify.secret, my->cfg.verify.secret_len,
				     my->cfg.verify.require_message_authenticator) < 0) {
			return false;
		}

		*retry_ctx_p = id_ctx->retry_ctx;
		response->uctx = id_ctx->packet;

		fr_assert(my->info.outstanding > 0);
		my->info.outstanding--;
		return true;
	}

	/*
	 *	The reply has the correct ID / Code, but it's not the
	 *	same as our previous reply: ignore it.
	 */
	if (memcmp(buffer, id_ctx->response->data, RADIUS_HEADER_LENGTH) != 0) return false;
	
	/*
	 *	Tell the caller that it's a duplicate reply.
	 */
	*retry_ctx_p = id_ctx->retry_ctx;
	return false;
}

static void radius_client_retry_release(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, UNUSED fr_bio_retry_release_reason_t reason)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_id_ctx_t *id_ctx = retry_ctx->uctx;

	fr_assert(id_ctx->packet == retry_ctx->packet_ctx);

	fr_radius_code_id_push(my->codes, id_ctx->packet);

	/*
	 *	We're no longer retrying this packet.
	 *
	 *	However, we leave id_ctx->request_ctx and id_ctx->packet around, because the other code still
	 *	needs it.
	 */
	id_ctx->request_ctx = NULL;
	id_ctx->retry_ctx = NULL;

	/*
	 *	IO was blocked due to IDs.  We now have a free ID, so perhaps we can resume writes.  But only
	 *	if the IO handlers didn't mark us as "write blocked".
	 */
	if (my->all_ids_used) {
		my->all_ids_used = false;

		if (!my->common.write_blocked && my->common.cb.write_resume) my->common.cb.write_resume(&my->common);
	}
}

/** Cancel one packet.
 *
 *  The packet can have a reply, or not.  It doesn't matter.
 *
 *  This also frees any IDs associated with the packet.
 */
int fr_radius_client_fd_bio_cancel(fr_bio_packet_t *bio, fr_packet_t *packet)
{
	fr_radius_id_ctx_t *id_ctx;
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	if (!my->retry) return 0;

	id_ctx = fr_radius_code_id_find(my->codes, packet->code, packet->id);
	if (!id_ctx || !id_ctx->retry_ctx) return 0;

	fr_assert(id_ctx->packet == packet);

	if (fr_bio_retry_entry_cancel(my->retry, id_ctx->retry_ctx) < 0) return -1;

	id_ctx->retry_ctx = NULL;
	id_ctx->packet = NULL;

	return 0;
}

int fr_radius_client_fd_bio_read(fr_bio_packet_t *bio, void **request_ctx_p, fr_packet_t **packet_p,
				 UNUSED TALLOC_CTX *out_ctx, fr_pair_list_t *out)
{
	ssize_t slen;
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);
	fr_packet_t *reply, *original;

	/*
	 *	We don't need to set up response.socket for connected bios.
	 */
	fr_packet_t response = {};

	/*
	 *	We read the response packet ctx into our local structure.  If we have a real response, we will
	 *	swap to using the request context, and not the response context.
	 */
	slen = fr_bio_read(my->common.bio, &response, &my->buffer, sizeof(my->buffer));
	if (!slen) return 0;

	if (slen < 0) {
		fr_assert(slen != fr_bio_error(IO_WOULD_BLOCK));
		return slen;
	}

	original = response.uctx;

	/*
	 *	Allocate the new request data structure
	 */
	reply = fr_packet_alloc(original, false);
	if (!reply) return -1;

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
	if (fr_radius_decode_simple(original, out, reply->data, reply->data_len,
				    original->vector, (char const *) my->cfg.verify.secret) < 0) {
		talloc_free(reply);
		return -1;
	}

	*request_ctx_p = original->uctx;
	*packet_p = reply;

	return 1;
}

fr_bio_t *fr_radius_client_bio_get_fd(fr_bio_packet_t *bio)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	return my->fd;
}

size_t fr_radius_client_bio_outstanding(fr_bio_packet_t *bio)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	return my->info.outstanding;
}

fr_radius_client_bio_info_t const *fr_radius_client_bio_info(fr_bio_packet_t *bio)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	return &my->info;
}


int fr_radius_client_bio_force_id(fr_bio_packet_t *bio, int code, int id)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	if (!code || (code >= FR_RADIUS_CODE_MAX)) {
		fr_strerror_const("Invalid packet code");
		return -1;
	}

	if ((id < 0) || (id > 256)) {
		fr_strerror_const("Invalid ID");
		return -1;
	}

	return fr_radius_code_id_force(my->codes, code, id);
}


/** Try to connect a socket.
 *
 *  Calls fr_bio_fd_connect()
 *
 *  @param bio	the packet bio
 *  @return
 *	- 0 for "connected, can continue"
 *	- fr_bio_error(IO_WOULD_BLOCK) for "not yet connected, please try again"
 *	- <0 for other fr_bio_error()
 *
 */
int fr_radius_client_bio_connect(fr_bio_packet_t *bio)
{
	int rcode;
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	if (my->info.connected) return 0;

	switch (my->info.fd_info->type) {
	default:
		fr_strerror_const("Invalid RADIUS client bio for connect");
		return fr_bio_error(GENERIC);

	case FR_BIO_FD_UNCONNECTED:
		return 0;

	case FR_BIO_FD_CONNECTED:
		break;
	}

	switch(my->info.fd_info->state) {
	case FR_BIO_FD_STATE_INVALID:
		fr_strerror_const("Invalid RADIUS client bio state");
		return fr_bio_error(GENERIC);

	case FR_BIO_FD_STATE_CLOSED:
		fr_strerror_const("RADIUS client bio is closed");
		return fr_bio_error(GENERIC);

	case FR_BIO_FD_STATE_OPEN:
		return 0;

	case FR_BIO_FD_STATE_CONNECTING:
		break;
	}

	/*
	 *	Try to connect it.
	 */
	rcode = fr_bio_fd_connect(my->fd);

	my->info.connected = (rcode == 0);
	return rcode;
}

static void fr_radius_client_bio_write_resume(fr_bio_t *bio)
{
	fr_radius_client_fd_bio_t *my = bio->uctx;

	/*
	 *	IO is unblocked, but we don't have any free IDs.  So we can't yet resume writes.
	 */
	if (my->all_ids_used) return;

	my->common.write_blocked = false;

	my->common.cb.write_resume(&my->common);
}

int fr_radius_client_bio_cb_set(fr_bio_packet_t *bio, fr_bio_packet_cb_funcs_t const *cb)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);
	fr_bio_cb_funcs_t bio_cb = {};

	/*
	 *	If we have a "blocked" function, we must have a "resume" function, and vice versa.
	 */
	fr_assert((cb->write_blocked != NULL) == (cb->write_resume != NULL));
	fr_assert((cb->read_blocked != NULL) == (cb->read_resume != NULL));

#undef SET
#define SET(_x) if (cb->_x) bio_cb._x = fr_bio_packet_ ## _x

	SET(write_blocked);
	if (cb->write_resume) bio_cb.write_resume = fr_radius_client_bio_write_resume;

	SET(read_blocked);
	SET(read_resume);

	return fr_bio_cb_set(my->fd, &bio_cb);
}
