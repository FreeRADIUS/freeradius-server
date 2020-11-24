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
#include <freeradius-devel/protocol/tacacs/tacacs.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/struct.h>

#include "tacacs.h"
#include "attrs.h"

#define PACKET_HEADER_CHECK(_msg) do { \
	if (p > end) { \
		fr_strerror_printf("Header for %s is too small (%zu < %zu)", _msg, end - (uint8_t const *) pkt, p - (uint8_t const *) pkt); \
		goto fail; \
	} \
} while (0)

#define ARG_COUNT_CHECK(_msg, _arg_cnt) do { \
	if ((p + _arg_cnt) > end) { \
		fr_strerror_printf("Argument count %u overflows the remaining data in the packet", _arg_cnt); \
		goto fail; \
	} \
	p += _arg_cnt; \
} while (0)

#define DECODE_FIELD_UINT8(_da, _field) do { \
	vp = fr_pair_afrom_da(ctx, _da); \
	if (!vp) goto fail; \
	vp->vp_uint8 = _field; \
	fr_cursor_append(cursor, vp); \
} while (0)

#define DECODE_FIELD_STRING8(_da, _field) do { \
	if (tacacs_decode_field(ctx, cursor, _da, &p, \
	    _field, end) < 0) goto fail; \
} while (0)

#define DECODE_FIELD_STRING16(_da, _field) do { \
	if (tacacs_decode_field(ctx, cursor, _da, &p, \
	    ntohs(_field), end) < 0) goto fail; \
} while (0)


/**
 *	Decode a TACACS+ 'arg_N' fields.
 */
static int tacacs_decode_args(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *da,
			      uint8_t arg_cnt, uint8_t const *arg_list, uint8_t const **data, uint8_t const *end)
{
	uint8_t i;
	uint8_t const *p = *data;
	fr_pair_t *vp;

	/*
	 *	No one? Just get out!
	 */
	if (!arg_cnt) return 0;

	if ((p + arg_cnt) > end) {
		fr_strerror_printf("Argument count %u overflows the remaining data in the packet", arg_cnt);
		return -1;
	}

	/*
	 *	Then, do the dirty job...
	 */
	for (i = 0; i < arg_cnt; i++) {
		if ((p + arg_list[i]) > end) {
			fr_strerror_printf("'%s' argument %u length %u overflows the remaining data in the packet",
					   da->name, i, arg_list[i]);
			return -1;
		}

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) {
			fr_strerror_printf("Out of Memory");
			return -1;
		}

		fr_pair_value_bstrndup(vp, (char const *) p, arg_list[i], true);
		fr_cursor_append(cursor, vp);
		p += arg_list[i];
		*data  = p;
	}

	return 0;
}

/**
 *	Decode a TACACS+ field.
 */
static int tacacs_decode_field(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *da,
				uint8_t const **field_data, uint16_t field_len, uint8_t const *end)
{
	uint8_t const *p = *field_data;
	fr_pair_t *vp;

	if ((p + field_len) > end) {
		fr_strerror_printf("'%s' length %u overflows the remaining data in the packet",
				   da->name, field_len);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_printf("Out of Memory");
		return -1;
	}

	if (field_len) {
		if (da->type == FR_TYPE_STRING) {
			fr_pair_value_bstrndup(vp, (char const *)p, field_len, true);
		} else if (da->type == FR_TYPE_OCTETS) {
			fr_pair_value_memdup(vp, p, field_len, true);
		} else {
			fr_assert(0);
		}
		p += field_len;
		*field_data = p;
	}

	fr_cursor_append(cursor, vp);

	return 0;
}

/**
 *	Decode a TACACS+ packet
 */
ssize_t fr_tacacs_decode(TALLOC_CTX *ctx, uint8_t const *buffer, size_t buffer_len, UNUSED const uint8_t *original, char const * const secret, size_t secret_len, fr_cursor_t *cursor)
{
	fr_dict_attr_t const	*tlv;
	fr_tacacs_packet_t const *pkt;
	fr_pair_t		*vp;
	uint8_t const  		*p, *end;
	uint8_t			*decrypted = NULL;

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
	pkt = (fr_tacacs_packet_t const *) buffer;
	end = buffer + buffer_len;

	/*
	 *	Check that we have a full TACACS+ header before
	 *	decoding anything.
	 */
	if (buffer_len < sizeof(pkt->hdr)) {
		fr_strerror_printf("Packet is too small (%zu < 12) to be TACACS+.", buffer_len);
		return -1;
	}

	/*
	 *	TACACS major / minor version MUST be 12.0 or 12.1
	 */
	if (!((buffer[0] == 0xc0) || (buffer[0] == 0xc1))) {
		fr_strerror_printf("Unsupported TACACS+ version %02x", buffer[0]);
		return -1;
	}

	/*
	 *	There's no reason to accept 64K TACACS+ packets.
	 *
	 *	In any case, the largest possible packet has the
	 *	header, plus 2 16-bit fields, plus 255 8-bit fields,
	 *	which is a bit under 2^18.
	 */
	if ((buffer[8] != 0) || (buffer[9] != 0)) {
		fr_strerror_printf("Packet is too large.  Our limit is 64K");
		return -1;
	}

	/*
	 *	As a stream protocol, the TACACS+ packet MUST fit
	 *	exactly into however many bytes we read.
	 */
	if ((buffer + sizeof(pkt->hdr) + ntohl(pkt->hdr.length)) != end) {
		fr_strerror_printf("Packet does not exactly fill buffer");
		return -1;
	}

	/*
	 *	There are only 3 types of packets which are supported.
	 */
	if (!((pkt->hdr.type == FR_TAC_PLUS_AUTHEN) ||
	      (pkt->hdr.type == FR_TAC_PLUS_AUTHOR) ||
	      (pkt->hdr.type == FR_TAC_PLUS_ACCT))) {
		fr_strerror_printf("Unknown packet type %u", pkt->hdr.type);
		return -1;
	}

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	if (fr_struct_from_network(ctx, cursor, attr_tacacs_packet, buffer, buffer_len, &tlv, NULL, NULL) < 0) {
		fr_strerror_printf("Problems to decode %s using fr_struct_from_network()", attr_tacacs_packet->name);
		return -1;
	}

	/*
	 *	3.6. Encryption
	 *
	 *	Packets are encrypted if the unencrypted flag is clear.
	 */
	if ((pkt->hdr.flags & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0) {
		size_t length;

		if (!secret || secret_len < 1) {
			fr_strerror_printf("Packet is encrypted, but no secret is set.");
			return -1;
		}

		length = ntohl(pkt->hdr.length);

		/*
		 *	We need that to decrypt the body content.
		 */
		decrypted = talloc_memdup(ctx, buffer, buffer_len);
		if (!decrypted) {
			fr_strerror_printf("Out of Memory");
			return -1;
		}

		pkt = (fr_tacacs_packet_t const *) decrypted;
		end = decrypted + buffer_len;

		if (fr_tacacs_body_xor(pkt, decrypted + sizeof(pkt->hdr), length, secret, secret_len) < 0) {
		fail:
			talloc_free(decrypted);
			return -1;
		}
	}

	switch (pkt->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(pkt)) {
			uint8_t want;

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
			p = pkt->authen.start.body;
			PACKET_HEADER_CHECK("Authentication Start");

			if ((pkt->hdr.ver.minor == 0) &&
			    (pkt->authen.start.authen_type != FR_AUTHENTICATION_TYPE_VALUE_ASCII)) {
				fr_strerror_printf("TACACS+ minor version 1 MUST be used for non-ASCII authentication methods");
				goto fail;
			}

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_START);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_action, pkt->authen.start.action);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->authen.start.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->authen.start.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->authen.start.authen_service);

			/*
			 *	Decode 4 fields, based on their "length"
			 */
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->authen.start.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->authen.start.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->authen.start.rem_addr_len);

			/*
			 *	Check the length on the various
			 *	authentication types.
			 */
			switch (pkt->authen.start.authen_type) {
			default:
				want = 255;
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_CHAP:
				want = 1 + 8 + 16; /* id + 8 octets of challenge + 16 hash */
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_MSCHAP:
				want = 1 + 8 + 49; /* id + 8 octets of challenge + 49 MS-CHAP stuff */
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_MSCHAPV2:
				want = 1 + 16 + 49; /* id + 16 octets of challenge + 49 MS-CHAP stuff */
				break;
			}

			/*
			 *	If we have enough data, decode it as
			 *	the claimed authentication type.
			 *	Otherwise, decode it as an unknown
			 *	attribute.
			 */
			if (pkt->authen.start.data_len <= want) {
				DECODE_FIELD_STRING8(attr_tacacs_data, pkt->authen.start.data_len);
			} else {
				fr_dict_attr_t *da;

				da = fr_dict_unknown_attr_afrom_da(ctx, attr_tacacs_data);
				if (da) {
					DECODE_FIELD_STRING8(da, pkt->authen.start.data_len);
					talloc_free(da); /* the VP makes it's own copy */
				}
				da->flags.is_raw = 1;
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

			/*
			 *	Version 1 is ONLY used for PAP / CHAP
			 *	/ MS-CHAP start and reply packets.
			 */
			if (pkt->hdr.ver.minor != 0) {
			invalid_version:
				fr_strerror_printf("Invalid TACACS+ version");
				goto fail;
			}

			p = pkt->authen.cont.body;
			PACKET_HEADER_CHECK("Authentication Continue");

			if (pkt->authen.start.authen_type != FR_AUTHENTICATION_TYPE_VALUE_ASCII) {
				fr_strerror_printf("Authentication-Continue packets MUST NOT be used for PAP, CHAP, MS-CHAP");
				goto fail;
			}

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_CONTINUE);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_user_message, pkt->authen.cont.user_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->authen.cont.data_len);

			/*
			 *	And finally the flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authentication_continue_flags, pkt->authen.cont.flags);

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

			/*
			 *	We don't care about versions for replies.
			 *	We just echo whatever was sent in the request.
			 */

			p = pkt->authen.reply.body;
			PACKET_HEADER_CHECK("Authentication Reply");
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REPLY);

			DECODE_FIELD_UINT8(attr_tacacs_authentication_status, pkt->authen.reply.status);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_flags, pkt->authen.reply.flags);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->authen.reply.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->authen.reply.data_len);

		} else {
		unknown_packet:
			fr_strerror_printf("Unknown packet type");
			goto fail;
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

			if (pkt->hdr.ver.minor != 0) goto invalid_version;

			p = pkt->author.req.body;
			PACKET_HEADER_CHECK("Authorization REQUEST");
			ARG_COUNT_CHECK("Authorization REQUEST", pkt->author.req.arg_cnt);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REQUEST);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authentication_method, pkt->author.req.authen_method);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->author.req.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->author.req.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->author.req.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 */
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->author.req.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->author.req.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->author.req.rem_addr_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, cursor, attr_tacacs_argument_list,
					       pkt->author.req.arg_cnt, pkt->author.req.body, &p, end) < 0) goto fail;

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

			/*
			 *	We don't care about versions for replies.
			 *	We just echo whatever was sent in the request.
			 */

			p = pkt->author.res.body;
			PACKET_HEADER_CHECK("Authorization RESPONSE");
			ARG_COUNT_CHECK("Authorization REQUEST", pkt->author.res.arg_cnt);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_RESPONSE);

			/*
			 *	Decode 1 octets
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authorization_status, pkt->author.res.status);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->author.res.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->author.res.data_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, cursor, attr_tacacs_argument_list,
					pkt->author.res.arg_cnt, pkt->author.res.body, &p, end) < 0) goto fail;

		} else {
			goto unknown_packet;
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

			if (pkt->hdr.ver.minor != 0) goto invalid_version;

			p = pkt->acct.req.body;
			PACKET_HEADER_CHECK("Accounting REQUEST");
			ARG_COUNT_CHECK("Accounting REQUEST", pkt->acct.req.arg_cnt);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REQUEST);

			/*
			 *	Decode 5 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_accounting_flags, pkt->acct.req.flags);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_method, pkt->acct.req.authen_method);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->acct.req.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->acct.req.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->acct.req.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 */
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->acct.req.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->acct.req.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->acct.req.rem_addr_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, cursor, attr_tacacs_argument_list,
					pkt->acct.req.arg_cnt, pkt->acct.req.body, &p, end) < 0) goto fail;

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

			/*
			 *	We don't care about versions for replies.
			 *	We just echo whatever was sent in the request.
			 */

			p = pkt->acct.reply.body;
			PACKET_HEADER_CHECK("Accounting REPLY");
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REPLY);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->acct.reply.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->acct.reply.data_len);

			/* Decode 1 octet */
			DECODE_FIELD_UINT8(attr_tacacs_accounting_status, pkt->acct.reply.status);
		} else {
			goto unknown_packet;
		}
		break;
	default:
		fr_strerror_printf("decode: Unsupported TACACS+ type %u", pkt->hdr.type);
		goto fail;
	}

	talloc_free(decrypted);
	return buffer_len;
}

/*
 *	Test points for protocol decode
 */
static ssize_t fr_tacacs_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *list, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_tacacs_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_tacacs_ctx_t);
	fr_cursor_t cursor;

	fr_pair_list_init(list);
	fr_cursor_init(&cursor, list);

	return fr_tacacs_decode(ctx, data, data_len, NULL, test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), &cursor);
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
