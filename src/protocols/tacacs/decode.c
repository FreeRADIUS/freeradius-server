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
 * @file protocols/tacacs/decode.c
 * @brief Low-Level TACACS+ decoding functions
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/tacacs/dictionary.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/struct.h>

#include "tacacs.h"
#include "attrs.h"

#define PACKET_HEADER_CHECKER(msg, leastwise) \
	if (remaining < leastwise) { \
		fr_strerror_printf(#msg" packet is too small: %d < %d", remaining, leastwise); \
		return -1; \
	} \
	remaining -= leastwise;

#define DECODE_GET_FIELD(attr, field) \
	vp = fr_pair_afrom_da(ctx, attr); \
	if (!vp) goto oom; \
	vp->vp_uint8 = field; \
	fr_cursor_append(&cursor, vp);

/**
 *	Decode a TACACS+ 'arg_N' fields.
 */
static int tacacs_decode_args(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *da,
				uint8_t arg_cnt, uint8_t *arg_body, uint8_t **args_data, uint16_t *remaining)
{
	char *p = (char *)*args_data;
	VALUE_PAIR *vp;

	/*
	 *	No one? Just get out!
	 */
	if (!arg_cnt) return 0;

	/*
	 *	Then, do the dirty job...
	 */
	*remaining -= arg_cnt;

	for (uint8_t i = 0; i < arg_cnt; i++) {
		uint8_t arg_len = *(arg_body + i);

		fr_assert(arg_len <= *remaining);

		if (arg_len > *remaining) {
			fr_strerror_printf("'%s' length overflows the remaining data in the packet: %d > %d",
					da->name, arg_len, *remaining);
			return -1;
		}

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) {
			fr_strerror_printf("Out of Memory");
			return -1;
		}

		fr_pair_value_bstrndup(vp, p, arg_len, true);
		fr_cursor_append(cursor, vp);
		p          += arg_len;
		*remaining -= arg_len;
		*args_data  = (uint8_t *)p;
	}

	return 0;
}

/**
 *	Decode a TACACS+ field.
 */
static int tacacs_decode_field(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *da,
				uint8_t **field_data, uint16_t field_len, uint16_t *remaining)
{
	uint8_t *p = *field_data;
	VALUE_PAIR *vp;

	fr_assert(field_len <= *remaining);

	if (field_len > *remaining) {
		fr_strerror_printf("'%s' length overflows the remaining data in the packet: %d > %d",
				   da->name, field_len, *remaining);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_printf("Out of Memory");
		return -1;
	}

	if (field_len) {
		fr_pair_value_bstrndup(vp, (char const *)p, field_len, true);
		p          += field_len;
		*remaining -= field_len;
		*field_data = p;
	}

	fr_cursor_append(cursor, vp);

	return 0;
}

/**
 *	Decode a TACACS+ packet
 */
ssize_t fr_tacacs_decode(TALLOC_CTX *ctx, uint8_t const *buffer, size_t buffer_len, UNUSED const uint8_t *original, char const * const secret, size_t secret_len, VALUE_PAIR **vps)
{
	fr_dict_attr_t const *tlv;
	fr_tacacs_packet_t   *pkt;
	fr_cursor_t          cursor;
	VALUE_PAIR           *vp;
	uint8_t              *p;
	uint16_t             remaining;
	uint8_t              *our_buffer;

	/*
	 *	We need that to decrypt the body content.
	 */
	our_buffer = talloc_memdup(ctx, buffer, buffer_len);
	if (!our_buffer) {
	oom:
		fr_strerror_printf("Out of Memory");
		return -1;
	}

	/*
	 * 3.4. The TACACS+ Packet Header
	 *
	 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
	 * +----------------+----------------+----------------+----------------+
	 * |major  | minor  |                |                |                |
	 * |version| version|      type      |     seq_no     |   flags        |
	 * +----------------+----------------+----------------+----------------+
	 * |                                                                   |
	 * |                            session_id                             |
	 * +----------------+----------------+----------------+----------------+
	 * |                                                                   |
	 * |                              length                               |
	 * +----------------+----------------+----------------+----------------+
	 */
	fr_cursor_init(&cursor, vps);

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	if (fr_struct_from_network(ctx, &cursor, attr_tacacs_packet, our_buffer, buffer_len, &tlv, NULL, NULL) < 0) {
		fr_strerror_printf("Problems to decode %s using fr_struct_from_network()", attr_tacacs_packet->name);
		return -1;
	}

	pkt       = (fr_tacacs_packet_t *)our_buffer;
	remaining = ntohl(pkt->hdr.length);

	/*
	 *	3.6. Encryption
	 */
	if (pkt->hdr.flags == FR_TAC_PLUS_ENCRYPTED_MULTIPLE_CONNECTIONS_FLAG) {
		uint8_t *body = (our_buffer + sizeof(fr_tacacs_packet_hdr_t));

		fr_assert(secret != NULL);
		fr_assert(secret_len > 0);

		if (!secret || secret_len < 1) {
			fr_strerror_printf("Packet is encrypted, but no secret is set.");
			return -1;
		}

		if (fr_tacacs_body_xor(pkt, body, ntohl(pkt->hdr.length), secret, secret_len) < 0) return -1;
	}

	switch (pkt->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(pkt)) {
			/**
			 * 4.1. The Authentication START Packet Body
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |    action      |    priv_lvl    |  authen_type   | authen_service |
			 * +----------------+----------------+----------------+----------------+
			 * |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
			 * +----------------+----------------+----------------+----------------+
			 * |    user ...
			 * +----------------+----------------+----------------+----------------+
			 * |    port ...
			 * +----------------+----------------+----------------+----------------+
			 * |    rem_addr ...
			 * +----------------+----------------+----------------+----------------+
			 * |    data...
			 * +----------------+----------------+----------------+----------------+
			 */

			PACKET_HEADER_CHECKER("Authentication START", 8)
			DECODE_GET_FIELD(attr_tacacs_packet_body_type, FR_TACACS_PACKET_BODY_TYPE_START);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_GET_FIELD(attr_tacacs_action, pkt->authen.start.action);
			DECODE_GET_FIELD(attr_tacacs_privilege_level, pkt->authen.start.priv_lvl);
			DECODE_GET_FIELD(attr_tacacs_authentication_type, pkt->authen.start.authen_type);
			DECODE_GET_FIELD(attr_tacacs_authentication_service, pkt->authen.start.authen_service);

			/*
			 *	Decode 4 fields, based on their "length"
			 */
			p = pkt->authen.start.body;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_user_name, &p,
						pkt->authen.start.user_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_client_port, &p,
						pkt->authen.start.port_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_remote_address, &p,
						pkt->authen.start.rem_addr_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_data, &p,
						pkt->authen.start.data_len, &remaining) < 0) {
				return -1;
			}
		} else if (packet_is_authen_continue(pkt)) {
			/*
			 * 4.3. The Authentication CONTINUE Packet Body
			 *
			 * This packet is sent from the client to the server following the receipt of
			 * a REPLY packet.
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |          user_msg len           |            data_len             |
			 * +----------------+----------------+----------------+----------------+
			 * |     flags      |  user_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |    data ...
			 * +----------------+
			 */

			PACKET_HEADER_CHECKER("Authentication CONTINUE", 5);
			DECODE_GET_FIELD(attr_tacacs_packet_body_type, FR_TACACS_PACKET_BODY_TYPE_CONTINUE);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = pkt->authen.cont.body;
			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_user_message, &p,
					ntohs(pkt->authen.cont.user_msg_len), &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_data, &p,
					ntohs(pkt->authen.cont.data_len), &remaining) < 0) return -1;

			DECODE_GET_FIELD(attr_tacacs_authentication_flags, pkt->authen.cont.flags);
		} else if (packet_is_authen_reply(pkt)) {
			/*
			 * 4.2. The Authentication REPLY Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |     status     |      flags     |        server_msg_len           |
			 * +----------------+----------------+----------------+----------------+
			 * |           data_len              |        server_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |           data ...
			 * +----------------+----------------+
			 */

			PACKET_HEADER_CHECKER("Authentication REPLY", 6);
			DECODE_GET_FIELD(attr_tacacs_packet_body_type, FR_TACACS_PACKET_BODY_TYPE_REPLY);

			DECODE_GET_FIELD(attr_tacacs_authentication_status, pkt->authen.reply.status);
			DECODE_GET_FIELD(attr_tacacs_authentication_flags, pkt->authen.reply.flags);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = pkt->authen.reply.body;
			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_server_message, &p,
					htons(pkt->authen.reply.server_msg_len), &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_data, &p,
					htons(pkt->authen.reply.data_len), &remaining) < 0) return -1;
		} else {
			/* Never */
			fr_assert(1);
		}
		break;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(pkt)) {
			/*
			 * 5.1. The Authorization REQUEST Packet Body
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |  authen_method |    priv_lvl    |  authen_type   | authen_service |
			 * +----------------+----------------+----------------+----------------+
			 * |    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
			 * +----------------+----------------+----------------+----------------+
			 * |   user ...
			 * +----------------+----------------+----------------+----------------+
			 * |   port ...
			 * +----------------+----------------+----------------+----------------+
			 * |   rem_addr ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_2 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N ...
			 * +----------------+----------------+----------------+----------------+
			 */

			PACKET_HEADER_CHECKER("Authorization REQUEST", 8);

			vp = fr_pair_afrom_da(ctx, attr_tacacs_packet_body_type);
			if (!vp) goto oom;
			vp->vp_uint8 = FR_TACACS_PACKET_BODY_TYPE_REQUEST;
			fr_cursor_append(&cursor, vp);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_GET_FIELD(attr_tacacs_authentication_method, pkt->author.req.authen_method);
			DECODE_GET_FIELD(attr_tacacs_privilege_level, pkt->author.req.priv_lvl);
			DECODE_GET_FIELD(attr_tacacs_authentication_type, pkt->author.req.authen_type);
			DECODE_GET_FIELD(attr_tacacs_authentication_service, pkt->author.req.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 */
			p = (pkt->author.req.body + pkt->author.req.arg_cnt);
			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_user_name, &p,
						pkt->author.req.user_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_client_port, &p,
						pkt->author.req.port_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_remote_address, &p,
						pkt->author.req.rem_addr_len, &remaining) < 0) return -1;

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, &cursor, attr_tacacs_argument_list,
					pkt->author.req.arg_cnt, pkt->author.req.body, &p, &remaining) < 0) return -1;
		} else if (packet_is_author_response(pkt)) {
			/*
			 * 5.2. The Authorization RESPONSE Packet Body
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |    status      |     arg_cnt    |         server_msg len          |
			 * +----------------+----------------+----------------+----------------+
			 * +            data_len             |    arg_1_len   |    arg_2_len   |
			 * +----------------+----------------+----------------+----------------+
			 * |      ...       |   arg_N_len    |         server_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |   data ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_2 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N ...
			 * +----------------+----------------+----------------+----------------+
			 */

			PACKET_HEADER_CHECKER("Authorization RESPONSE", 6);
			DECODE_GET_FIELD(attr_tacacs_packet_body_type, FR_TACACS_PACKET_BODY_TYPE_RESPONSE);

			/*
			 *	Decode 1 octets
			 */
			DECODE_GET_FIELD(attr_tacacs_authorization_status, pkt->author.res.status);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = (pkt->author.res.body + pkt->author.res.arg_cnt);
			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_server_message, &p,
						htons(pkt->author.res.server_msg_len), &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_data, &p,
						htons(pkt->author.res.data_len), &remaining) < 0) return -1;

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, &cursor, attr_tacacs_argument_list,
					pkt->author.res.arg_cnt, pkt->author.res.body, &p, &remaining) < 0) return -1;
		} else {
			/* never */
			fr_assert(1);
		}
		break;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(pkt)) {
			/**
			 * 6.1. The Account REQUEST Packet Body
			 *
			 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |      flags     |  authen_method |    priv_lvl    |  authen_type   |
			 * +----------------+----------------+----------------+----------------+
			 * | authen_service |    user_len    |    port_len    |  rem_addr_len  |
			 * +----------------+----------------+----------------+----------------+
			 * |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N_len    |    user ...
			 * +----------------+----------------+----------------+----------------+
			 * |   port ...
			 * +----------------+----------------+----------------+----------------+
			 * |   rem_addr ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_2 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N ...
			 * +----------------+----------------+----------------+----------------+
			 */

			PACKET_HEADER_CHECKER("Accounting REQUEST", 9);
			DECODE_GET_FIELD(attr_tacacs_packet_body_type, FR_TACACS_PACKET_BODY_TYPE_REQUEST);

			/*
			 *	Decode 5 octets of various flags.
			 */
			DECODE_GET_FIELD(attr_tacacs_accounting_flags, pkt->acct.req.flags);
			DECODE_GET_FIELD(attr_tacacs_authentication_method, pkt->acct.req.authen_method);
			DECODE_GET_FIELD(attr_tacacs_privilege_level, pkt->acct.req.priv_lvl);
			DECODE_GET_FIELD(attr_tacacs_authentication_type, pkt->acct.req.authen_type);
			DECODE_GET_FIELD(attr_tacacs_authentication_service, pkt->acct.req.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 */
			p = (pkt->acct.req.body + pkt->acct.req.arg_cnt);
			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_user_name, &p,
						pkt->acct.req.user_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_client_port, &p,
						pkt->acct.req.port_len, &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_remote_address, &p,
						pkt->acct.req.rem_addr_len, &remaining) < 0) return -1;

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, &cursor, attr_tacacs_argument_list,
					pkt->acct.req.arg_cnt, pkt->acct.req.body, &p, &remaining) < 0) return -1;
		} else if (packet_is_acct_reply(pkt)) {
			/**
			 * 6.2. The Accounting REPLY Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |         server_msg len          |            data_len             |
			 * +----------------+----------------+----------------+----------------+
			 * |     status     |         server_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |     data ...
			 * +----------------+
			 */

			PACKET_HEADER_CHECKER("Accounting REPLY", 5);
			DECODE_GET_FIELD(attr_tacacs_packet_body_type, FR_TACACS_PACKET_BODY_TYPE_REPLY);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = pkt->acct.reply.body;
			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_server_message, &p,
					htons(pkt->acct.reply.server_msg_len), &remaining) < 0) return -1;

			if (tacacs_decode_field(ctx, &cursor, attr_tacacs_data, &p,
					htons(pkt->acct.reply.data_len), &remaining) < 0) return -1;

			/* Decode 1 octet */
			vp = fr_pair_afrom_da(ctx, attr_tacacs_accounting_status);
			if (!vp) goto oom;
			vp->vp_uint8 = pkt->acct.reply.status;
			fr_cursor_append(&cursor, vp);
		} else {
			/* never */
			fr_assert(1);
		}
		break;
	default:
		fr_strerror_printf("decode: Unsupported TACACS+ type %u", pkt->hdr.type);
		return -1;
	}

	fr_assert(remaining == 0); /* Good enough */

	return buffer_len;
}

/*
 *	Test points for protocol decode
 */
static ssize_t fr_tacacs_decode_proto(TALLOC_CTX *ctx, VALUE_PAIR **vps, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_tacacs_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_tacacs_ctx_t);

	return fr_tacacs_decode(ctx, data, data_len, NULL, test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), vps);
}

static int _encode_test_ctx(fr_tacacs_ctx_t *proto_ctx)
{
	talloc_const_free(proto_ctx->secret);

	fr_tacacs_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_tacacs_ctx_t *test_ctx;

	if (fr_tacacs_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_tacacs_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->secret = talloc_strdup(test_ctx, "testing123");
	test_ctx->root = fr_dict_root(dict_tacacs);
	talloc_set_destructor(test_ctx, _encode_test_ctx);

	*out = test_ctx;

	return 0;
}

extern fr_test_point_proto_decode_t tacacs_tp_decode_proto;
fr_test_point_proto_decode_t tacacs_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_tacacs_decode_proto
};
