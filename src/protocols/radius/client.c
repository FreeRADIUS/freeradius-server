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
#include <freeradius-devel/protocol/radius/rfc2866.h>

typedef struct {
	uint32_t	initial;	//!< initial value
	uint32_t	start;		//!< Unix time we started sending this packet

	size_t		offset;		//!< offset to Acct-Delay-Time value
} fr_radius_client_bio_retry_t;

static void radius_client_retry_sent(fr_bio_t *bio, void *packet_ctx, const void *buffer, UNUSED size_t size,
				     fr_bio_retry_entry_t *retry_ctx);
static bool radius_client_retry_response(fr_bio_t *bio, fr_bio_retry_entry_t **retry_ctx_p, UNUSED void *packet_ctx, const void *buffer, UNUSED size_t size);
static void radius_client_retry_release(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, UNUSED fr_bio_retry_release_reason_t reason);
static ssize_t radius_client_retry(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, UNUSED const void *buffer, NDEBUG_UNUSED size_t size);

static void fr_radius_client_bio_connect_timer(fr_event_list_t *el, fr_time_t now, void *uctx);

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
	fr_bio_retry_rewrite_t rewrite = NULL;

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

	my->info.fd_info = fr_bio_fd_info(my->fd);
	fr_assert(my->info.fd_info != NULL);

	my->reply_socket = my->info.fd_info->socket;
	if ((my->reply_socket.af == AF_INET) || (my->reply_socket.af == AF_INET6)) {
		fr_socket_addr_swap(&my->reply_socket, &my->info.fd_info->socket);
	}

	my->mem = fr_bio_mem_alloc(my, read_size, 2 * 4096, my->fd);
	if (!my->mem) goto fail;

	my->mem->uctx = my;

	if (cfg->packet_cb_cfg.retry) rewrite = radius_client_retry;

	/*
	 *	We allocate a retry BIO even for TCP, as we want to be able to timeout the packets.
	 */
	if (cfg->retry_cfg.el) {
		my->retry = fr_bio_retry_alloc(my, 256, radius_client_retry_sent, radius_client_retry_response,
					       rewrite, radius_client_retry_release, &cfg->retry_cfg, my->mem);
		if (!my->retry) goto fail;

		my->retry->uctx = my;

		my->info.retry_info = fr_bio_retry_info(my->retry);
		fr_assert(my->info.retry_info != NULL);

		my->common.bio = my->retry;

	} else {
		/*
		 *	No timers for retries, we just use a memory buffer for outbound packets.
		 */
		my->common.bio = my->mem;
	}

	my->cfg = *cfg;

	/*
	 *	Inform the packet BIO about our application callbacks.
	 */
	my->common.cb = cfg->packet_cb_cfg;

	/*
	 *	Initialize the packet handlers in each BIO.
	 */
	fr_bio_packet_init(&my->common);

	talloc_set_destructor(my, _radius_client_fd_bio_free);

	/*
	 *	Set up the connected status.
	 */
	my->info.connected = false;

	/*
	 *	If we're supposed to be connected (but aren't), then ensure that we don't keep trying to
	 *	connect forever.
	 */
	if ((my->info.fd_info->type == FR_BIO_FD_CONNECTED) && !my->info.connected &&
	    fr_time_delta_ispos(cfg->connection_timeout) && cfg->retry_cfg.el) {
		if (fr_event_timer_in(my, cfg->el, &my->common.ev, cfg->connection_timeout, fr_radius_client_bio_connect_timer, my) < 0) {
			talloc_free(my);
			return NULL;
		}
	}

	my->proto_ctx = (fr_radius_ctx_t) {
		.secret = (char const *) my->cfg.verify.secret,
		.secret_length = my->cfg.verify.secret_len,
		.secure_transport = false,
		.proxy_state = my->cfg.proxy_state,
	};

	my->info.last_idle = fr_time();

	return my;
}

int fr_radius_client_fd_bio_write(fr_radius_client_fd_bio_t *my, void *pctx, fr_packet_t *packet, fr_pair_list_t *list)
{
	ssize_t slen;
	fr_radius_id_ctx_t *id_ctx;

	fr_assert(!packet->data);

	fr_assert(packet->code > 0);
	fr_assert(packet->code < FR_RADIUS_CODE_MAX);
	fr_assert(!my->common.write_blocked);

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
		if (!my->retry || fr_bio_retry_entry_cancel(my->retry, NULL) < 1) {
		all_ids_used:
			my->all_ids_used = true;

			/*
			 *	Tell the application to stop writing data to the BIO.
			 */
			if (my->common.cb.write_blocked) my->common.cb.write_blocked(&my->common);

			fr_strerror_const("All IDs are in use");
			return fr_bio_error(GENERIC);
		}

		id_ctx = fr_radius_code_id_pop(my->codes, packet);
		if (!id_ctx) goto all_ids_used;
	}
	id_ctx->request_ctx = pctx;
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
	slen = fr_radius_encode(&FR_DBUFF_TMP(my->buffer, sizeof(my->buffer)), list, &(fr_radius_encode_ctx_t) {
			.common = &my->proto_ctx,
			.request_authenticator = NULL,
			.rand_ctx = (fr_fast_rand_t) {
				.a = fr_rand(),
				.b = fr_rand(),
			},
			.code = packet->code,
			.id = packet->id,
			.add_proxy_state = my->cfg.add_proxy_state,
		});
	if (slen < 0) {
	fail:
		fr_radius_code_id_push(my->codes, packet);
		return fr_bio_error(GENERIC);
	}

	fr_assert(slen >= RADIUS_HEADER_LENGTH);
	packet->data_len = slen;

	slen = fr_radius_sign(my->buffer, NULL,
				(uint8_t const *) my->cfg.verify.secret, my->cfg.verify.secret_len);
	if (slen < 0) goto fail;

	/*
	 *	The other BIOs will take care of calling fr_radius_client_bio_write_blocked() when the write
	 *	is blocked.
	 *
	 *	The "next" BIO is a memory one, which can store the entire packet.  So write() never returns a
	 *	partial packet.
	 */
	slen = fr_bio_write(my->common.bio, &packet->socket, my->buffer, packet->data_len);
	if (slen < 0) {
		fr_assert((slen != fr_bio_error(IO_WOULD_BLOCK)) || my->common.write_blocked);

		fr_radius_code_id_push(my->codes, packet);
		return slen;
	}

	fr_assert((size_t) slen == packet->data_len);

	/*
	 *	We only allocate packet data after writing it to the socket.  If the write fails, we avoid a
	 *	memory alloc / free.
	 */
	packet->data = talloc_array(packet, uint8_t, packet->data_len);
	if (!packet->data) goto fail;

	/*
	 *	Only after successful write do we copy the data back to the packet structure.
	 */
	memcpy(packet->data, my->buffer, packet->data_len);
	memcpy(packet->vector, packet->data + 4, RADIUS_AUTH_VECTOR_LENGTH);

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

static ssize_t radius_client_retry(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, UNUSED const void *buffer, NDEBUG_UNUSED size_t size)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_id_ctx_t *id_ctx = retry_ctx->uctx;
	fr_packet_t *packet = id_ctx->packet;

	fr_assert(packet->data_len == size);

	fr_assert(my->cfg.packet_cb_cfg.retry);

	my->cfg.packet_cb_cfg.retry(&my->common, id_ctx->packet);

	/*
	 *	Note do do NOT ball fr_bio_write(), because that will treat the packet as a new one!
	 */
	return fr_bio_retry_rewrite(bio, retry_ctx, packet->data, packet->data_len);
}


static ssize_t radius_client_rewrite_acct(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, UNUSED const void *buffer, NDEBUG_UNUSED size_t size)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_client_bio_retry_t *acct = retry_ctx->rewrite_ctx;
	fr_radius_id_ctx_t *id_ctx = retry_ctx->uctx;
	fr_radius_id_ctx_t my_id_ctx = *id_ctx;
	fr_packet_t *packet = id_ctx->packet;
	uint8_t *ptr = packet->data + acct->offset;
	uint32_t now, delay;

	fr_assert(packet->data_len == size);

	/*
	 *	Change IDs, since we're changing the value of Acct-Delay-Time
	 */
	fr_radius_code_id_push(my->codes, packet);

	id_ctx = fr_radius_code_id_pop(my->codes, packet);
	if (!id_ctx) return fr_bio_error(GENERIC); /* at the minimum, we should get the ID we just pushed */

	/*
	 *	Update the ID context, and tell the retry context that the ID context has changed.
	 */
	id_ctx->request_ctx = my_id_ctx.request_ctx;
	retry_ctx->uctx = id_ctx;

	now = fr_time_to_sec(retry_ctx->retry.updated);
	fr_assert(now >= acct->start);
	fr_assert((now - acct->start) < (1 << 20)); /* just for pairanoia */

	delay = acct->initial + (now - acct->start);

	fr_nbo_from_uint32(ptr, delay);

	/*
	 *	Sign the updated packet.
	 */
	(void) fr_radius_sign(packet->data, NULL,
			      (uint8_t const *) my->cfg.verify.secret, my->cfg.verify.secret_len);

	/*
	 *	Signal that the packet has been retried.
	 */
	if (my->cfg.packet_cb_cfg.retry) my->cfg.packet_cb_cfg.retry(&my->common, id_ctx->packet);

	/*
	 *	Note do do NOT ball fr_bio_write(), because that will treat the packet as a new one!
	 */
	return fr_bio_retry_rewrite(bio, retry_ctx, packet->data, packet->data_len);
}


static void radius_client_retry_sent(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size,
				     fr_bio_retry_entry_t *retry_ctx)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_id_ctx_t *id_ctx;
	uint8_t const *data = buffer;
	uint8_t const *end;
	fr_radius_client_bio_retry_t *acct;

	id_ctx = fr_radius_code_id_find(my->codes, data[0], data[1]);
	fr_assert(id_ctx != NULL);

	id_ctx->packet = packet_ctx;
	id_ctx->retry_ctx = retry_ctx;

	retry_ctx->uctx = id_ctx;

	(void) fr_bio_retry_entry_init(bio, retry_ctx, &my->cfg.retry[data[0]]);

	my->info.outstanding++;
	my->info.last_sent = retry_ctx->retry.start;
	if (fr_time_lteq(my->info.first_sent, my->info.last_idle)) my->info.first_sent = my->info.last_sent;

	/*
	 *	For Accounting-Request packets which have Acct-Delay-Time, we need to track where the
	 *	Acct-Delay-Time is in the packet, along with its original value, and then we can use the
	 *	#fr_retry_t to discover how many seconds to add to Acct-Delay-Time.
	 */
	retry_ctx->rewrite = NULL;

	if ((data[0] != FR_RADIUS_CODE_ACCOUNTING_REQUEST) || (my->cfg.retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc == 1)) return;

	end = data + size;
	data += RADIUS_HEADER_LENGTH;

	/*
	 *	Find the Acct-Delay-Time attribute.  If it doesn't exist, we don't update it on retransmits.
	 *
	 *	@todo - maybe if it doesn't exist, we look for Event-Timestamp?  And add one if necessary?
	 */
	while (data < end) {
		if (data[0] == FR_ACCT_DELAY_TIME) break;

		data += data[1];
	}

	if ((data == end) || (data[1] != 6)) return;

	acct = retry_ctx->rewrite_ctx = talloc_zero(my, fr_radius_client_bio_retry_t);
	if (!acct) return;

	/*
	 *	Set up the retry handler with initial data.
	 */
	retry_ctx->rewrite = radius_client_rewrite_acct;

	data += 2;

	acct->initial = fr_nbo_to_uint32(data);
	acct->start = fr_time_to_sec(retry_ctx->retry.start);
	acct->offset = (size_t) (data - (uint8_t const *) buffer);
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
		fr_bio_retry_entry_t *retry;

		if (fr_radius_verify(data, id_ctx->packet->data + 4,
				     my->cfg.verify.secret, my->cfg.verify.secret_len,
				     my->cfg.verify.require_message_authenticator,
				     my->cfg.verify.limit_proxy_state) < 0) {
			return false;
		}

		retry = *retry_ctx_p = id_ctx->retry_ctx;

		if (fr_time_gt(retry->retry.start, my->info.mrs_time)) my->info.mrs_time = retry->retry.start;
		my->info.last_reply = fr_time(); /* @todo - cache this so read() doesn't call time? */

		*retry_ctx_p = id_ctx->retry_ctx;
		response->uctx = id_ctx->packet;
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
	my->info.last_reply = fr_time(); /* @todo - cache this so read() doesn't call time? */
	return false;
}

static void radius_client_retry_release(fr_bio_t *bio, fr_bio_retry_entry_t *retry_ctx, fr_bio_retry_release_reason_t reason)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio->uctx, fr_radius_client_fd_bio_t);
	fr_radius_id_ctx_t *id_ctx = retry_ctx->uctx;
	fr_packet_t *packet = id_ctx->packet;

	fr_assert(id_ctx->packet == retry_ctx->packet_ctx);

	fr_radius_code_id_push(my->codes, id_ctx->packet);

	/*
	 *	Free any pending rewrite CTX.
	 */
	TALLOC_FREE(retry_ctx->rewrite_ctx);

	/*
	 *	We're no longer retrying this packet.
	 *
	 *	However, we leave id_ctx->request_ctx and id_ctx->packet around, because the other code still
	 *	needs it.
	 */
	id_ctx->request_ctx = NULL;
	id_ctx->retry_ctx = NULL;

	/*
	 *	Tell the application that this packet did not see a reply/
	 */
	if (my->cfg.packet_cb_cfg.release && (reason == FR_BIO_RETRY_NO_REPLY)) my->cfg.packet_cb_cfg.release(&my->common, packet);

	fr_assert(my->info.outstanding > 0);
	my->info.outstanding--;

	/*
	 *	IO was blocked due to IDs.  We now have a free ID, so we resume the normal write process.
	 */
	if (my->all_ids_used) {
		my->all_ids_used = false;

		/*
		 *	Tell the application to resume writing to the BIO.
		 */
		if (my->common.cb.write_resume) my->common.cb.write_resume(&my->common);

	} else if (!my->info.outstanding) {
		my->info.last_idle = fr_time();
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

	id_ctx = fr_radius_code_id_find(my->codes, packet->code, packet->id);

	if (!id_ctx || !id_ctx->retry_ctx) return 0;
	fr_assert(id_ctx->packet == packet);

	if (!my->retry) goto done;

	if (fr_bio_retry_entry_cancel(my->retry, id_ctx->retry_ctx) < 0) return -1;

done:
	id_ctx->retry_ctx = NULL;
	id_ctx->packet = NULL;

	return 0;
}

int fr_radius_client_fd_bio_read(fr_bio_packet_t *bio, void **pctx_p, fr_packet_t **packet_p,
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

	*pctx_p = original->uctx;
	*packet_p = reply;

	return 1;
}

size_t fr_radius_client_bio_outstanding(fr_bio_packet_t *bio)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(bio, fr_radius_client_fd_bio_t);

	/*
	 *	@todo - add API for ID allocation to track this.
	 */
	if (!my->retry) return 0;

	return fr_bio_retry_outstanding(my->retry);
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

/** We failed to connect in the given timeout, the connection is dead.
 *
 */
static void fr_radius_client_bio_connect_timer(NDEBUG_UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(uctx, fr_radius_client_fd_bio_t);

	fr_assert(!my->retry || (my->info.retry_info->el == el));

	if (my->common.cb.failed) my->common.cb.failed(&my->common);
}


void fr_radius_client_bio_connect(NDEBUG_UNUSED fr_event_list_t *el, NDEBUG_UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_radius_client_fd_bio_t *my = talloc_get_type_abort(uctx, fr_radius_client_fd_bio_t);

	fr_assert(my->common.cb.connected);
	fr_assert(!my->retry || (my->info.retry_info->el == el));
	fr_assert(my->info.fd_info->socket.fd == fd);

	/*
	 *	The socket is already connected, tell the application.  This happens when the FD bio opens an
	 *	unconnected socket.  It calls our connected routine before the application has a chance to
	 *	call our connect routine.
	 */
	if (my->info.connected) return;

	/*
	 *	We don't pass the callbacks to fr_bio_fd_alloc(), so it can't call our connected routine.
	 *	As a result, we have to check if the FD is open, and then call it ourselves.
	 */
	if (my->info.fd_info->state == FR_BIO_FD_STATE_OPEN) {
		fr_bio_packet_connected(my->fd);
		return;
	}

	fr_assert(my->info.fd_info->type == FR_BIO_FD_CONNECTED);
	fr_assert(my->info.fd_info->state == FR_BIO_FD_STATE_CONNECTING);

	/*
	 *	Try to connect it.  Any magic handling is done in the callbacks.
	 */
	(void) fr_bio_fd_connect(my->fd);
}
