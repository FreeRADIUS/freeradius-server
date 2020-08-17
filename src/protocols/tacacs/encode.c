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
 * @file protocols/tacacs/encode.c
 * @brief Low-Level TACACS+ encode functions
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

/**
 *	Encode a TACACS+ 'arg_N' fields.
 */
static uint8_t tacacs_encode_body_arg_n_len(VALUE_PAIR *vps, fr_dict_attr_t const *da, uint8_t **body, uint8_t const *end)
{
	uint8_t *p = *body;
	uint8_t arg_cnt = 0;
	size_t total = 0;
	VALUE_PAIR *vp;
	fr_cursor_t cursor;

	fr_assert(body != NULL);

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (arg_cnt == 255) break;

		if (vp->da != da) continue;

		if (vp->vp_length > 0xff) continue;

		if ((p + 1 + vp->vp_length + total) > end) break;

		/* Append the <arg_N_len> fields length */
		*p++ = vp->vp_length;
		total += vp->vp_length;
		arg_cnt++;
	}

	*body = p;

	return arg_cnt;
}

static void tacacs_encode_body_arg_n(VALUE_PAIR *vps, fr_dict_attr_t const *da, uint8_t **body, uint8_t const *end)
{
	uint8_t *p = *body;
	uint8_t arg_cnt = 0;
	VALUE_PAIR *vp;
	fr_cursor_t cursor;

	fr_assert(body != NULL);

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (arg_cnt == 255) break;

		if (vp->da != da) continue;

		if (vp->vp_length > 0xff) continue;

		if ((p + vp->vp_length) > end) break;

		/* Append the <arg_N> field */
		memcpy(p, vp->vp_strvalue, vp->vp_length);
		p += vp->vp_length;
	}

	*body = p;
}

/*
 *	Encode a TACACS+ field.
 */
static ssize_t tacacs_encode_field(VALUE_PAIR *vps, fr_dict_attr_t const *da, uint8_t **data, uint8_t const *end, size_t max_len)
{
	VALUE_PAIR *vp;
	uint8_t *p = *data;

	vp = fr_pair_find_by_da(vps, da, TAG_ANY);
	if (!vp || !vp->vp_length) return 0;

	if (vp->vp_length > max_len) return 0;
	if ((p + vp->vp_length) > end) return 0;

	memcpy(p, vp->vp_strvalue, vp->vp_length);
	p += vp->vp_length;
	*data = p;

	return vp->vp_length;
}

/*
 *	Magic macros to keep things happy.
 *
 *	Note that the various fields are optional.  If the caller
 *	doesn't specify them, then they don't get encoded.
 */
#define ENCODE_FIELD_UINT8(_field, _da) do { \
	vp = fr_pair_find_by_da(vps, _da, TAG_ANY); \
	if (vp) _field = vp->vp_uint8; \
} while (0)

#define ENCODE_FIELD_STRING8(_field, _da) _field = tacacs_encode_field(vps, _da, &p, end, 0xff)
#define ENCODE_FIELD_STRING16(_field, _da) _field = htons(tacacs_encode_field(vps, _da, &p, end, 0xffff))

/**
 *	Encode VPS into a raw TACACS packet.
 */
ssize_t fr_tacacs_encode(uint8_t *buffer, size_t buffer_len, char const *secret, size_t secret_len, VALUE_PAIR *vps)
{
	VALUE_PAIR		*vp;
	fr_tacacs_packet_t 	*packet;
	fr_cursor_t		cursor;
	fr_da_stack_t 		da_stack;
	uint8_t 		*p;
	uint8_t const		*end = buffer + buffer_len;
	ssize_t			len = 0;
	size_t 			packet_len = 0;

	if (!vps) {
		fr_strerror_printf("Cannot encode empty packet");
		return -1;
	}

	/*
	 *	Find the first attribute which is parented by TACACS-Packet.
	 */
	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->parent == attr_tacacs_packet) break;
	}

	if (!vp) {
		fr_strerror_printf("No TACACS+ %s in the attribute list",
			attr_tacacs_packet->name);
		return -1;
	}

	fr_proto_da_stack_build(&da_stack, attr_tacacs_packet);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	len = fr_struct_to_network(buffer, buffer_len, &da_stack, 0, &cursor, NULL, NULL);
	if (len != sizeof(fr_tacacs_packet_hdr_t)) {
		fr_strerror_printf("Failed encoding %s using fr_struct_to_network()",
				   attr_tacacs_packet->name);
		return -1;
	}

	/*
	 *	@todo - have this function take a `uint8_t const
	 *	*original` argument.  We can then automatically fill
	 *	in fields such as sequence number and session ID based
	 *	on the original packet.
	 */

	/*
	 *	Handle directly in the allocated buffer
	 */
	packet = (fr_tacacs_packet_t *)buffer;

	/*
	 *	Encode 8 octets of various fields not members of STRUCT
	 */
	switch (packet->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		/*
		 * seq_no
		 *
		 * This is the sequence number of the current packet for the current session.
		 * The first packet in a session MUST have the sequence number 1 and each
		 * subsequent packet will increment the sequence number by one. Thus clients
		 * only send packets containing odd sequence numbers, and TACACS+ servers only
		 * send packets containing even sequence numbers.
		 */
		if (packet_is_authen_start_request(packet)) { /* Start */
			/**
			 * 4.1. The Authentication START Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
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

			/*
			 *	Encode 4 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->authen.start.action, attr_tacacs_action);
			ENCODE_FIELD_UINT8(packet->authen.start.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->authen.start.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->authen.start.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 4 mandatory fields.
			 */
			p = packet->authen.start.body;
			ENCODE_FIELD_STRING8(packet->authen.start.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->authen.start.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->authen.start.rem_addr_len, attr_tacacs_remote_address);
			ENCODE_FIELD_STRING8(packet->authen.start.data_len, attr_tacacs_data);

		} else if (packet_is_authen_continue(packet)) {
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

			/*
			 *	Encode 2 mandatory fields.
			 */
			p = packet->authen.cont.body;
			ENCODE_FIELD_STRING16(packet->authen.cont.user_msg_len, attr_tacacs_user_message);
			ENCODE_FIELD_STRING16(packet->authen.cont.data_len, attr_tacacs_data);

			/*
			 *	Look at the abort flag after encoding the fields.
			 */
			ENCODE_FIELD_UINT8(packet->authen.cont.flags, attr_tacacs_authentication_flags);

		} else if (packet_is_authen_reply(packet)) {
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

			ENCODE_FIELD_UINT8(packet->authen.reply.status, attr_tacacs_authentication_status);
			ENCODE_FIELD_UINT8(packet->authen.reply.flags, attr_tacacs_authentication_flags);

			/*
			 *	Encode 2 mandatory fields.
			 */
			p = packet->authen.reply.body;
			ENCODE_FIELD_STRING16(packet->authen.reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->authen.reply.data_len, attr_tacacs_data);

		} else {
		unknown_packet:
			fr_strerror_printf("Unknown packet type");
			return -1;
		}

		break;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(packet)) {
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

			/*
			 *	Encode 4 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->author.req.authen_method, attr_tacacs_authentication_method);
			ENCODE_FIELD_UINT8(packet->author.req.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->author.req.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->author.req.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			p = packet->author.req.body;
			packet->author.req.arg_cnt = tacacs_encode_body_arg_n_len(vps, attr_tacacs_argument_list, &p, end);

			/*
			 *	Encode 3 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->author.req.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->author.req.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->author.req.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->author.req.arg_cnt > 0) {
				tacacs_encode_body_arg_n(vps, attr_tacacs_argument_list, &p, end);
			}

		} else if (packet_is_author_response(packet)) {
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

			ENCODE_FIELD_UINT8(packet->author.res.status, attr_tacacs_authorization_status);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			p = packet->author.res.body;
			packet->author.res.arg_cnt = tacacs_encode_body_arg_n_len(vps, attr_tacacs_argument_list, &p, end);

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->author.res.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->author.res.data_len, attr_tacacs_data);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->author.res.arg_cnt > 0) {
				tacacs_encode_body_arg_n(vps, attr_tacacs_argument_list, &p, end);
			}
		} else {
			goto unknown_packet;
		}

		break;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(packet)) {
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

			/*
			 *	Encode 5 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->acct.req.flags, attr_tacacs_accounting_flags);
			ENCODE_FIELD_UINT8(packet->acct.req.authen_method, attr_tacacs_authentication_method);
			ENCODE_FIELD_UINT8(packet->acct.req.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->acct.req.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->acct.req.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			p = packet->acct.req.body;
			packet->acct.req.arg_cnt = tacacs_encode_body_arg_n_len(vps, attr_tacacs_argument_list, &p, end);

			/*
			 *	Encode 3 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->acct.req.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->acct.req.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->acct.req.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->acct.req.arg_cnt > 0) {
				tacacs_encode_body_arg_n(vps, attr_tacacs_argument_list, &p, end);
			}
		} else if (packet_is_acct_reply(packet)) {
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

			/*
			 *	Encode 2 mandatory fields.
			 */
			p = packet->acct.reply.body;
			ENCODE_FIELD_STRING16(packet->acct.reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->acct.reply.data_len, attr_tacacs_data);

			ENCODE_FIELD_UINT8(packet->acct.reply.status, attr_tacacs_accounting_status);
		} else {
			goto unknown_packet;
		}
		break;

	default:
		fr_strerror_printf("encode: TACACS+ type %u", packet->hdr.type);
		return -1;
	}

	fr_assert(p <= end);

	/*
	 *	The packet length we store in the header doesn't
	 *	include the size of the header.  But we tell the
	 *	caller about the total length of the packet.
	 */
	packet_len = p - buffer;
	fr_assert(packet_len < FR_TACACS_MAX_PACKET_SIZE);
	packet->hdr.length = htonl(packet_len - sizeof(fr_tacacs_packet_hdr_t));

	/*
	 *	3.6. Encryption
	 *
	 *	Packets are encrypted if the unencrypted flag is clear.
	 */
	if ((packet->hdr.flags & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0) {
		uint8_t *body = (buffer + sizeof(fr_tacacs_packet_hdr_t));

		fr_assert(secret != NULL);
		fr_assert(secret_len > 0);

		if (!secret || secret_len < 1) {
			fr_strerror_printf("Packet is supposed to be encrypted, but no secret is set.");
			return -1;
		}

		if (fr_tacacs_body_xor(packet, body, ntohl(packet->hdr.length), secret, secret_len) != 0) return -1;
	}

	FR_PROTO_HEX_DUMP((const uint8_t *)packet, packet_len, "fr_tacacs_packet_t (encoded)");

	return packet_len;
}

/*
 *	Test points for protocol encode
 */
static ssize_t fr_tacacs_encode_proto(UNUSED TALLOC_CTX *ctx, VALUE_PAIR *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	fr_tacacs_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_tacacs_ctx_t);

	return fr_tacacs_encode(data, data_len, test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), vps);
}

static int _encode_test_ctx(fr_tacacs_ctx_t *proto_ctx)
{
	talloc_const_free(proto_ctx->secret);

	fr_tacacs_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
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

/*
 *	Test points
 */
extern fr_test_point_proto_encode_t tacacs_tp_encode_proto;
fr_test_point_proto_encode_t tacacs_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_tacacs_encode_proto
};
