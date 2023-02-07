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
 * @copyright 2017 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/tacacs/tacacs.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/struct.h>

#include "tacacs.h"
#include "attrs.h"

int fr_tacacs_packet_to_code(fr_tacacs_packet_t const *pkt)
{
	switch (pkt->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		if (pkt->hdr.seq_no == 1) return FR_PACKET_TYPE_VALUE_AUTHENTICATION_START;

		if ((pkt->hdr.seq_no & 0x01) == 1) {
			if (pkt->authen_cont.flags == FR_TAC_PLUS_CONTINUE_FLAG_UNSET) return FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE;

			if (pkt->authen_cont.flags == FR_TAC_PLUS_CONTINUE_FLAG_ABORT) return FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE_ABORT;

			fr_strerror_printf("Invalid value %u for authentication continue flag", pkt->authen_cont.flags);
			return -1;
		}

		switch (pkt->authen_reply.status) {
		case FR_TAC_PLUS_AUTHEN_STATUS_PASS:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_PASS;

		case FR_TAC_PLUS_AUTHEN_STATUS_FAIL:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_FAIL;

		case FR_TAC_PLUS_AUTHEN_STATUS_GETDATA:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_GETDATA;

		case FR_TAC_PLUS_AUTHEN_STATUS_GETUSER:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_GETUSER;

		case FR_TAC_PLUS_AUTHEN_STATUS_GETPASS:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_GETPASS;

		case FR_TAC_PLUS_AUTHEN_STATUS_RESTART:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_RESTART;

		case FR_TAC_PLUS_AUTHEN_STATUS_ERROR:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY_ERROR;

		default:
			break;
		}

		fr_strerror_printf("Invalid value %u for authentication reply status", pkt->authen_reply.status);
		return -1;

	case FR_TAC_PLUS_AUTHOR:
		if ((pkt->hdr.seq_no & 0x01) == 1) {
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST;
		}

		switch (pkt->author_reply.status) {
		case FR_TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_REPLY_PASS_ADD;

		case FR_TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_REPLY_PASS_REPLACE;

		case FR_TAC_PLUS_AUTHOR_STATUS_FAIL:
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_REPLY_FAIL;

		default:
			break;
		}

		fr_strerror_printf("Invalid value %u for authorization reply status", pkt->author_reply.status);
		return -1;

	case FR_TAC_PLUS_ACCT:
		if ((pkt->hdr.seq_no & 0x01) == 1) {
			return FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST;
		}

		switch (pkt->acct_reply.status) {
		case FR_TAC_PLUS_ACCT_STATUS_SUCCESS:
			return FR_PACKET_TYPE_VALUE_ACCOUNTING_REPLY_SUCCESS;

		case FR_TAC_PLUS_ACCT_STATUS_ERROR:
			return FR_PACKET_TYPE_VALUE_ACCOUNTING_REPLY_ERROR;

		default:
			break;
		}

		fr_strerror_printf("Invalid value %u for accounting reply status", pkt->acct_reply.status);
		return -1;

	default:
		fr_strerror_const("Invalid header type");
		return -1;
	}
}

#define PACKET_HEADER_CHECK(_msg) do { \
	if (p > end) { \
		fr_strerror_printf("Header for %s is too small (%zu < %zu)", _msg, end - (uint8_t const *) pkt, p - (uint8_t const *) pkt); \
		goto fail; \
	} \
} while (0)

#define ARG_COUNT_CHECK(_msg, _arg_cnt) do { \
	if ((p + _arg_cnt) > end) { \
		fr_strerror_printf("Argument count %u overflows the remaining data (%zu) in the %s packet", _arg_cnt, end - p, _msg); \
		goto fail; \
	} \
	p += _arg_cnt; \
} while (0)

#define DECODE_FIELD_UINT8(_da, _field) do { \
	vp = fr_pair_afrom_da(ctx, _da); \
	if (!vp) goto fail; \
	vp->vp_uint8 = _field; \
	fr_pair_append(out, vp); \
} while (0)

#define DECODE_FIELD_STRING8(_da, _field) do { \
	if (tacacs_decode_field(ctx, out, _da, &p, \
	    _field, end) < 0) goto fail; \
} while (0)

#define DECODE_FIELD_STRING16(_da, _field) do { \
	if (tacacs_decode_field(ctx, out, _da, &p, \
	    ntohs(_field), end) < 0) goto fail; \
} while (0)

#define BODY(_x) (((uint8_t const *) pkt) + sizeof(pkt->hdr) + sizeof(pkt->_x))

/**
 *	Decode a TACACS+ 'arg_N' fields.
 */
static int tacacs_decode_args(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			      uint8_t arg_cnt, uint8_t const *arg_list, uint8_t const *data, uint8_t const *end)
{
	uint8_t i;
	uint8_t const *p = data;
	fr_pair_t *vp;

	/*
	 *	No one? Just get out!
	 */
	if (!arg_cnt) return 0;

	if ((p + arg_cnt) > end) {
		fr_strerror_printf("Argument count %u overflows the remaining data (%zu) in the packet", arg_cnt, p - end);
		return -1;
	}

	/*
	 *	Check for malformed packets before anything else.
	 */
	for (i = 0; i < arg_cnt; i++) {
		if ((p + arg_list[i]) > end) {
			fr_strerror_printf("'%s' argument %u length %u overflows the remaining data (%zu) in the packet",
					   parent->name, i, arg_list[i], end - p);
			return -1;
		}

		p += arg_list[i];
	}
	p = data;

	/*
	 *	Then, do the dirty job of creating attributes.
	 */
	for (i = 0; i < arg_cnt; i++) {
		uint8_t const *value, *name_end, *arg_end;
		fr_dict_attr_t const *da;
		uint8_t buffer[256];

		if (arg_list[i] < 2) goto next; /* skip malformed */

		memcpy(buffer, p, arg_list[i]);
		buffer[arg_list[i]] = '\0';

		arg_end = buffer + arg_list[i];

		for (value = buffer, name_end = NULL; value < arg_end; value++) {
			/*
			 *	RFC 8907 Section 3.7 says control
			 *	characters MUST be excluded.
			 */
			if (*value < ' ') goto next;

			if ((*value == '=') || (*value == '*')) {
				name_end = value;
				buffer[value - buffer] = '\0';
				value++;
				break;
			}
		}

		/*
		 *	Skip fields which aren't in "name=value" or "name*value" format.
		 */
		if (!name_end) goto next;

		da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_tacacs), (char *) buffer);
		if (!da) {
		raw:
			/*
			 *	Dupe the whole thing so that we have:
			 *
			 *	Argument-List += "name=value"
			 */
			da = parent;
			value = p;
			arg_end = p + arg_list[i];
		}

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) {
			fr_strerror_const("Out of Memory");
			return -1;

		}

		/*
		 *	If it's OCTETS or STRING type, then just copy
		 *	the value verbatim.  But if it's zero length,
		 *	then don't do anything.
		 *
		 *	Note that we copy things manually here because
		 *	we don't want the OCTETS type to be parsed as
		 *	hex.  And, we don't want the string type to be
		 *	unescaped.
		 */
		if (da->type == FR_TYPE_OCTETS) {
			if ((arg_end > value) &&
			    (fr_pair_value_memdup(vp, value, arg_end - value, true) < 0)) {
				goto fail;
			}

		} else if (da->type == FR_TYPE_STRING) {
			if ((arg_end > value) &&
			    (fr_pair_value_bstrndup(vp, (char const *) value, arg_end - value, true) < 0)) {
				goto fail;
			}

		} else {
			/*
			 *	Parse the string, and try to convert it to the
			 *	underlying data type.  If it can't be
			 *	converted as a data type, just convert it as
			 *	Argument-List.
			 *
			 *	And if that fails, just ignore it completely.
			 */
			if (fr_pair_value_from_str(vp, (char const *) value, arg_end - value, NULL, true) < 0) {
			fail:
				talloc_free(vp);
				if (da != parent) goto raw;

				goto next;
			}
		}

		fr_pair_append(out, vp);

	next:
		p += arg_list[i];
	}

	return 0;
}

/**
 *	Decode a TACACS+ field.
 */
static int tacacs_decode_field(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *da,
				uint8_t const **field_data, uint16_t field_len, uint8_t const *end)
{
	uint8_t const *p = *field_data;
	fr_pair_t *vp;

	if ((p + field_len) > end) {
		fr_strerror_printf("'%s' length %u overflows the remaining data (%zu) in the packet",
				   da->name, field_len, end - p);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_const("Out of Memory");
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

	fr_pair_append(out, vp);

	return 0;
}

/**
 *	Decode a TACACS+ packet
 */
ssize_t fr_tacacs_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *buffer, size_t buffer_len,
			 const uint8_t *original, char const * const secret, size_t secret_len, int *code)
{
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
		fr_strerror_const("Packet is too large.  Our limit is 64K");
		return -1;
	}

	/*
	 *	As a stream protocol, the TACACS+ packet MUST fit
	 *	exactly into however many bytes we read.
	 */
	if ((buffer + sizeof(pkt->hdr) + ntohl(pkt->hdr.length)) != end) {
		fr_strerror_const("Packet does not exactly fill buffer");
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
	 *	Check that the session IDs are correct.
	 */
	if (original && (memcmp(original + 4, buffer + 4, 4) != 0)) {
		fr_strerror_printf("Session ID %08x does not match expected number %08x",
				   fr_nbo_to_uint32(buffer + 4), fr_nbo_to_uint32(original + 4));
		return -1;
	}

	if (!secret && packet_is_encrypted(pkt)) {
		fr_strerror_const("Packet is encrypted, but there is no secret to decrypt it");
		return -1;
	}

	if (secret && !packet_is_encrypted(pkt)) {
		fr_strerror_const("Packet is clear-text but we expected it to be encrypted");
		return -1;
	}

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	if (fr_struct_from_network(ctx, out, attr_tacacs_packet, buffer, buffer_len, false, NULL, NULL, NULL) < 0) {
		fr_strerror_printf("Failed decoding TACACS header - %s", fr_strerror());
		return -1;
	}

	/*
	 *	3.6. Encryption
	 *
	 *	If there's a secret, we alway decrypt the packets.
	 */
	if (secret) {
		size_t length;

		if (!secret_len) {
			fr_strerror_const("Packet should be encrypted, but the secret has zero length");
			return -1;
		}

		length = ntohl(pkt->hdr.length);

		/*
		 *	We need that to decrypt the body content.
		 */
		decrypted = talloc_memdup(ctx, buffer, buffer_len);
		if (!decrypted) {
			fr_strerror_const("Out of Memory");
			return -1;
		}

		pkt = (fr_tacacs_packet_t const *) decrypted;
		end = decrypted + buffer_len;

		if (fr_tacacs_body_xor(pkt, decrypted + sizeof(pkt->hdr), length, secret, secret_len) < 0) {
		fail:
			talloc_free(decrypted);
			return -1;
		}

		decrypted[3] |= FR_TAC_PLUS_UNENCRYPTED_FLAG;

		FR_PROTO_HEX_DUMP(decrypted, buffer_len, "fr_tacacs_packet_t (unencrypted)");

		if (code) {
			*code = fr_tacacs_packet_to_code((fr_tacacs_packet_t const *) decrypted);
			if (*code < 0) return -1;
		}
	}

#ifndef NDEBUG
	if (fr_debug_lvl >= L_DBG_LVL_4) fr_tacacs_packet_log_hex(&default_log, pkt);
#endif

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
			p = BODY(authen_start);
			PACKET_HEADER_CHECK("Authentication Start");

#if 0
			if ((pkt->hdr.ver.minor == 0) &&
			    (pkt->authen_start.authen_type != FR_AUTHENTICATION_TYPE_VALUE_ASCII)) {
				fr_strerror_const("TACACS+ minor version 1 MUST be used for non-ASCII authentication methods");
				goto fail;
			}
#endif

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_START);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_action, pkt->authen_start.action);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->authen_start.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->authen_start.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->authen_start.authen_service);

			/*
			 *	Decode 4 fields, based on their "length"
			 */
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->authen_start.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->authen_start.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->authen_start.rem_addr_len);

			/*
			 *	Check the length on the various
			 *	authentication types.
			 */
			switch (pkt->authen_start.authen_type) {
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
			if (pkt->authen_start.data_len <= want) {
				DECODE_FIELD_STRING8(attr_tacacs_data, pkt->authen_start.data_len);
			} else {
				fr_dict_attr_t *da;

				da = fr_dict_unknown_attr_afrom_da(ctx, attr_tacacs_data);
				if (da) {
					da->flags.is_raw = 1;
					DECODE_FIELD_STRING8(da, pkt->authen_start.data_len);
					talloc_free(da); /* the VP makes it's own copy */
				}

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
				fr_strerror_const("Invalid TACACS+ version");
				goto fail;
			}

			p = BODY(authen_cont);
			PACKET_HEADER_CHECK("Authentication Continue");

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_CONTINUE);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_user_message, pkt->authen_cont.user_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->authen_cont.data_len);

			/*
			 *	And finally the flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authentication_continue_flags, pkt->authen_cont.flags);

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

			p = BODY(authen_reply);
			PACKET_HEADER_CHECK("Authentication Reply");
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REPLY);

			DECODE_FIELD_UINT8(attr_tacacs_authentication_status, pkt->authen_reply.status);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_flags, pkt->authen_reply.flags);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->authen_reply.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->authen_reply.data_len);

		} else {
			fr_strerror_const("Unknown authentication packet");
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

			p = BODY(author_req);
			PACKET_HEADER_CHECK("Authorization REQUEST");
			ARG_COUNT_CHECK("Authorization REQUEST", pkt->author_req.arg_cnt);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REQUEST);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authentication_method, pkt->author_req.authen_method);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->author_req.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->author_req.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->author_req.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 */
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->author_req.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->author_req.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->author_req.rem_addr_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, out, attr_tacacs_argument_list,
					       pkt->author_req.arg_cnt, BODY(author_req), p, end) < 0) goto fail;

		} else if (packet_is_author_reply(pkt)) {
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

			p = BODY(author_reply);
			PACKET_HEADER_CHECK("Authorization RESPONSE");
			ARG_COUNT_CHECK("Authorization REQUEST", pkt->author_reply.arg_cnt);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_RESPONSE);

			/*
			 *	Decode 1 octets
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authorization_status, pkt->author_reply.status);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->author_reply.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->author_reply.data_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, out, attr_tacacs_argument_list,
					pkt->author_reply.arg_cnt, BODY(author_reply), p, end) < 0) goto fail;

		} else {
			fr_strerror_const("Unknown authorization packet");
			goto fail;
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

			p = BODY(acct_req);
			PACKET_HEADER_CHECK("Accounting REQUEST");
			ARG_COUNT_CHECK("Accounting REQUEST", pkt->acct_req.arg_cnt);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REQUEST);

			/*
			 *	Decode 5 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_accounting_flags, pkt->acct_req.flags);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_method, pkt->acct_req.authen_method);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->acct_req.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->acct_req.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->acct_req.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 */
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->acct_req.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->acct_req.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->acct_req.rem_addr_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, out, attr_tacacs_argument_list,
					pkt->acct_req.arg_cnt, BODY(acct_req), p, end) < 0) goto fail;

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

			p = BODY(acct_reply);
			PACKET_HEADER_CHECK("Accounting REPLY");
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REPLY);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->acct_reply.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->acct_reply.data_len);

			/* Decode 1 octet */
			DECODE_FIELD_UINT8(attr_tacacs_accounting_status, pkt->acct_reply.status);
		} else {
			fr_strerror_const("Unknown accounting packet");
			goto fail;
		}
		break;
	default:
		fr_strerror_printf("decode: Unsupported packet type %u", pkt->hdr.type);
		goto fail;
	}

	talloc_free(decrypted);
	return buffer_len;
}

/*
 *	Test points for protocol decode
 */
static ssize_t fr_tacacs_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_tacacs_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_tacacs_ctx_t);

	return fr_tacacs_decode(ctx, out, data, data_len, NULL,
				test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), false);
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
