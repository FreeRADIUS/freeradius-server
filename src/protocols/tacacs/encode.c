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
static size_t tacacs_encode_body_arg_n_len(VALUE_PAIR *vps, fr_dict_attr_t const *da, uint8_t **body)
{
	VALUE_PAIR *vp;
	fr_cursor_t	cursor;
	size_t 	arg_cnt = 0;
	uint8_t *p = *body;

	fr_assert(body != NULL);

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		if (vp->da != da) continue;

		fr_assert(vp->vp_length <= 0xff);

		if (vp->vp_length > 0xff) {
			fr_strerror_printf("The TACACS+ attribute %s overflows the values (%ld > 255)",
				da->name, vp->vp_length);
			return -1;
		}

		/* Append the <arg_N_len> fields length */
		*p++     = vp->vp_length;
		arg_cnt += 1;
	}

	if (!arg_cnt) return 0;

	*body = p;

	return arg_cnt;
}

static size_t tacacs_encode_body_arg_n(VALUE_PAIR *vps, fr_dict_attr_t const *da, uint8_t **body)
{
	VALUE_PAIR *vp;
	fr_cursor_t	cursor;
	size_t body_args_len = 0;

	fr_assert(*body != NULL);

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		if (vp->da != da) continue;

		/* Append the <arg_N> fields */
		memcpy(*body + body_args_len, vp->vp_strvalue, vp->vp_length);
		body_args_len += vp->vp_length;
	}

	return body_args_len;
}

/*
 *	Encode a TACACS+ field.
 */
static ssize_t tacacs_encode_field(VALUE_PAIR *vps, fr_dict_attr_t const *da, uint8_t **field_data, uint16_t *body_len, size_t max_len)
{
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_da(vps, da, TAG_ANY);
	if (!vp) return 0;

	fr_assert(vp->vp_length <= max_len);

	if (vp->vp_length > max_len) {
		fr_strerror_printf("The TACACS+ attribute %s overflows the values (%ld > %ld)",
			da->name, vp->vp_length, max_len);
		return -1;
	}

	if (vp->vp_length > 0) {
		uint8_t *p = *field_data;

		memcpy(p, vp->vp_strvalue, vp->vp_length);
		p          += vp->vp_length;
		*field_data = p;
		*body_len  += vp->vp_length;
	}

	return vp->vp_length;
}

/**
 *	Encode VPS into a raw TACACS packet.
 */
ssize_t fr_tacacs_encode(uint8_t *buffer, size_t buffer_len, char const * const secret, size_t secret_len, VALUE_PAIR *vps)
{
	VALUE_PAIR		*vp;
	fr_tacacs_packet_t 	*packet;
	fr_cursor_t		cursor;
	fr_da_stack_t 		da_stack;
	uint8_t 		*p;
	uint16_t		length_hdr = 0;
	uint16_t		length_body = 0;
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

	/*
	 *	For simplicity, we allow the caller to omit things
	 *	that they don't care about.
	 */
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
	length_hdr = fr_struct_to_network(buffer, buffer_len, &da_stack, 0, &cursor, NULL, NULL);

	fr_assert(length_hdr == sizeof(fr_tacacs_packet_hdr_t));

	if (length_hdr != sizeof(fr_tacacs_packet_hdr_t)) {
		fr_strerror_printf("Problems to encode %s using fr_struct_to_network()",
					attr_tacacs_packet->name);
		return -1;
	}

	/*
	 *	Handle directly in the allocated buffer
	 */
	packet = (fr_tacacs_packet_t *)buffer;

	/*
	 *	Encode 8 octets of various fields not members of STRUCT
	 */
	switch (packet->hdr.type) {
	case TAC_PLUS_AUTHEN:
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

			length_hdr += offsetof(fr_tacacs_packet_authen_start_hdr_t, body);

			/*
			 *	Encode 4 octets of various flags.
			 */
			vp = fr_pair_find_by_da(vps, attr_tacacs_action, TAG_ANY);
			if (!vp) {
			invalid_authen_req:
				fr_strerror_printf("Invalid TACACS+ Authentication Request packet");
				return -1;
			}
			packet->authen.start.action = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_privilege_level, TAG_ANY);
			if (!vp) goto invalid_authen_req;
			packet->authen.start.priv_lvl = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_type, TAG_ANY);
			if (!vp) goto invalid_authen_req;
			packet->authen.start.authen_type = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_service, TAG_ANY);
			if (!vp) goto invalid_authen_req;
			packet->authen.start.authen_service = vp->vp_uint8;

			/*
			 *	Encode 4 fields, based on their "length"
			 */
			p = packet->authen.start.body;

			len = tacacs_encode_field(vps, attr_tacacs_user_name, &p, &length_body, 0xff);
			if (len < 0) goto invalid_authen_req;
			packet->authen.start.user_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_client_port, &p, &length_body, 0xff);
			if (len < 0) goto invalid_authen_req;
			packet->authen.start.port_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_remote_address, &p, &length_body, 0xff);
			if (len < 0) goto invalid_authen_req;
			packet->authen.start.rem_addr_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_data, &p, &length_body, 0xff);
			if (len < 0) goto invalid_authen_req;
			packet->authen.start.data_len = len;
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

			length_hdr += offsetof(fr_tacacs_packet_authen_cont_hdr_t, body);

			/*
			 *	Encode 2 fields, based on their 'length'
			 */
			p = packet->authen.cont.body;

			len = tacacs_encode_field(vps, attr_tacacs_user_message, &p, &length_body, 0xffff);
			if (len < 0) {
			invalid_authen_cont:
				fr_strerror_printf("Invalid TACACS+ Authentication Continue packet");
				return -1;
			}
			packet->authen.cont.user_msg_len = htons(len);

			len = tacacs_encode_field(vps, attr_tacacs_data, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_authen_cont;
			packet->authen.cont.data_len = htons(len);

			/*
			 *	Look at the abort flag after decoding the fields.
			 */
			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_flags, TAG_ANY);
			if (!vp) goto invalid_authen_cont;
			packet->authen.cont.flags = vp->vp_uint8;
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

			length_hdr += offsetof(fr_tacacs_packet_authen_reply_hdr_t, body);

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_status, TAG_ANY);
			if (!vp) {
			invalid_authen_reply:
				fr_strerror_printf("Invalid TACACS+ Authorization Reply packet");
				return -1;
			}
			packet->authen.reply.status = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_flags, TAG_ANY);
			if (!vp) goto invalid_authen_reply;
			packet->authen.reply.flags = vp->vp_uint8;

			/*
			 *	Encode 2 fields, based on their 'length'
			 */
			p = packet->authen.reply.body;

			len = tacacs_encode_field(vps, attr_tacacs_server_message, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_authen_reply;
			packet->authen.reply.server_msg_len = htons(len);

			len = tacacs_encode_field(vps, attr_tacacs_data, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_authen_reply;
			packet->authen.reply.data_len = htons(len);
		} else {
			/* Never */
			fr_assert(1);
		}

		break;

	case TAC_PLUS_AUTHOR:
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

			length_hdr += offsetof(fr_tacacs_packet_author_req_hdr_t, body);

			/*
			 *	Encode 4 octets of various flags.
			 */
			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_method, TAG_ANY);
			if (!vp) {
			invalid_author_req:
				fr_strerror_printf("Invalid TACACS+ Authorization REQUEST packet");
				return -1;
			}
			packet->author.req.authen_method = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_privilege_level, TAG_ANY);
			if (!vp) goto invalid_author_req;
			packet->author.req.priv_lvl = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_type, TAG_ANY);
			if (!vp) goto invalid_author_req;
			packet->author.req.authen_type = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_service, TAG_ANY);
			if (!vp) goto invalid_author_req;
			packet->author.req.authen_service = vp->vp_uint8;

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			p = packet->author.req.body;

			len = tacacs_encode_body_arg_n_len(vps, attr_tacacs_argument_list, &p);
			if (len < 0) goto invalid_author_req;
			packet->author.req.arg_cnt = len;

			/*
			 *	Encode 3 fields, based on their "length"
			 */
			len = tacacs_encode_field(vps, attr_tacacs_user_name, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_author_req;
			packet->author.req.user_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_client_port, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_author_req;
			packet->author.req.port_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_remote_address, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_author_req;
			packet->author.req.rem_addr_len = len;

			/*
			 * Append 'args_body' to the end of buffer
			 */
			if (packet->author.req.arg_cnt > 0) {
				length_body += (packet->author.req.arg_cnt + tacacs_encode_body_arg_n(vps, attr_tacacs_argument_list, &p));
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

			length_hdr += offsetof(fr_tacacs_packet_author_res_hdr_t, body);

			vp = fr_pair_find_by_da(vps, attr_tacacs_authorization_status, TAG_ANY);
			if (!vp) {
			invalid_author_res:
				fr_strerror_printf("Invalid TACACS+ Authorization Response packet");
				return -1;
			}
			packet->author.res.status = vp->vp_uint8;

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			p = packet->author.res.body;
			len = tacacs_encode_body_arg_n_len(vps, attr_tacacs_argument_list, &p);
			if (len < 0) goto invalid_author_res;
			packet->author.res.arg_cnt = len;

			/*
			 *	Encode 2 fields, based on their "length"
			 */
			len = tacacs_encode_field(vps, attr_tacacs_server_message, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_author_res;
			packet->author.res.server_msg_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_data, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_author_res;
			packet->author.res.data_len = len;

			/*
			 * Append 'args_body' to the end of buffer
			 */
			if (packet->author.res.arg_cnt > 0) {
				length_body += (packet->author.res.arg_cnt + tacacs_encode_body_arg_n(vps, attr_tacacs_argument_list, &p));
			}
		} else {
			/* never */
			fr_assert(1);
		}

		break;

	case TAC_PLUS_ACCT:
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

			length_hdr += offsetof(fr_tacacs_packet_acct_req_hdr_t, body);

			/*
			 *	Encode 5 octets of various flags.
			 */
			vp = fr_pair_find_by_da(vps, attr_tacacs_accounting_flags, TAG_ANY);
			if (!vp) {
			invalid_acct_req:
				fr_strerror_printf("Invalid TACACS+ Accounting REQUEST packet");
				return -1;
			}
			packet->acct.req.flags = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_method, TAG_ANY);
			if (!vp) goto invalid_acct_req;
			packet->acct.req.authen_method = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_privilege_level, TAG_ANY);
			if (!vp) goto invalid_acct_req;
			packet->acct.req.priv_lvl = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_type, TAG_ANY);
			if (!vp) goto invalid_acct_req;
			packet->acct.req.authen_type = vp->vp_uint8;

			vp = fr_pair_find_by_da(vps, attr_tacacs_authentication_service, TAG_ANY);
			if (!vp) goto invalid_acct_req;
			packet->acct.req.authen_service = vp->vp_uint8;

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			p = packet->acct.req.body;

			len = tacacs_encode_body_arg_n_len(vps, attr_tacacs_argument_list, &p);
			if (len < 0) goto invalid_acct_req;
			packet->acct.req.arg_cnt = len;

			/*
			 *	Encode 3 fields, based on their "length"
			 */
			len = tacacs_encode_field(vps, attr_tacacs_user_name, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_acct_req;
			packet->acct.req.user_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_client_port, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_acct_req;
			packet->acct.req.port_len = len;

			len = tacacs_encode_field(vps, attr_tacacs_remote_address, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_acct_req;
			packet->acct.req.rem_addr_len = len;

			/*
			 * Append 'args_body' to the end of buffer
			 */
			if (packet->acct.req.arg_cnt > 0) {
				length_body += (packet->acct.req.arg_cnt + tacacs_encode_body_arg_n(vps, attr_tacacs_argument_list, &p));
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

			length_hdr += offsetof(fr_tacacs_packet_acct_reply_hdr_t, body);

			/*
			 *	Encode 2 fields, based on their 'length'
			 */
			p = packet->acct.reply.body;

			len = tacacs_encode_field(vps, attr_tacacs_server_message, &p, &length_body, 0xffff);
			if (len < 0) {
			invalid_acct_reply:
				fr_strerror_printf("Invalid TACACS+ Accounting Reply packet");
				return -1;
			}
			packet->acct.reply.server_msg_len = htons(len);

			len = tacacs_encode_field(vps, attr_tacacs_data, &p, &length_body, 0xffff);
			if (len < 0) goto invalid_acct_reply;
			packet->acct.reply.data_len = htons(len);

			vp = fr_pair_find_by_da(vps, attr_tacacs_accounting_status, TAG_ANY);
			if (!vp) goto invalid_acct_reply;
			packet->acct.reply.status = vp->vp_uint8;
		} else {
			/* never */
			fr_assert(1);
		}
		break;

	default:
		fr_strerror_printf("encode: TACACS+ type %u", packet->hdr.type);
		return -1;
	}

	fr_assert(length_hdr + length_body < TACACS_MAX_PACKET_SIZE);

	packet->hdr.length = htonl(length_hdr - sizeof(fr_tacacs_packet_hdr_t) + length_body);
	packet_len = (length_hdr + length_body);

	if (packet_len > buffer_len) {
		fr_strerror_printf("TACACS+ packet overflows %ld of %ld bytes",
				(buffer_len - packet_len), buffer_len);
		return -1;
	}

	/*
	 *	3.6. Encryption
	 */
	if (packet->hdr.flags == TAC_PLUS_ENCRYPTED_MULTIPLE_CONNECTIONS_FLAG) {
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
