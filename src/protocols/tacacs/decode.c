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

			fr_strerror_printf("Invalid value %d for authentication continue flag", pkt->authen_cont.flags);
			return -1;
		}

		switch (pkt->authen_reply.status) {
		case FR_TAC_PLUS_AUTHEN_STATUS_PASS:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_PASS;

		case FR_TAC_PLUS_AUTHEN_STATUS_FAIL:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_FAIL;

		case FR_TAC_PLUS_AUTHEN_STATUS_GETDATA:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETDATA;

		case FR_TAC_PLUS_AUTHEN_STATUS_GETUSER:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETUSER;

		case FR_TAC_PLUS_AUTHEN_STATUS_GETPASS:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETPASS;

		case FR_TAC_PLUS_AUTHEN_STATUS_RESTART:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_RESTART;

		case FR_TAC_PLUS_AUTHEN_STATUS_ERROR:
			return FR_PACKET_TYPE_VALUE_AUTHENTICATION_ERROR;

		default:
			break;
		}

		fr_strerror_printf("Invalid value %d for authentication reply status", pkt->authen_reply.status);
		return -1;

	case FR_TAC_PLUS_AUTHOR:
		if ((pkt->hdr.seq_no & 0x01) == 1) {
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST;
		}

		switch (pkt->author_reply.status) {
		case FR_TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_ADD;

		case FR_TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_REPLACE;

		case FR_TAC_PLUS_AUTHOR_STATUS_FAIL:
			return FR_PACKET_TYPE_VALUE_AUTHORIZATION_FAIL;

		default:
			break;
		}

		fr_strerror_printf("Invalid value %d for authorization reply status", pkt->author_reply.status);
		return -1;

	case FR_TAC_PLUS_ACCT:
		if ((pkt->hdr.seq_no & 0x01) == 1) {
			return FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST;
		}

		switch (pkt->acct_reply.status) {
		case FR_TAC_PLUS_ACCT_STATUS_SUCCESS:
			return FR_PACKET_TYPE_VALUE_ACCOUNTING_SUCCESS;

		case FR_TAC_PLUS_ACCT_STATUS_ERROR:
			return FR_PACKET_TYPE_VALUE_ACCOUNTING_ERROR;

		default:
			break;
		}

		fr_strerror_printf("Invalid value %d for accounting reply status", pkt->acct_reply.status);
		return -1;

	default:
		fr_strerror_const("Invalid header type");
		return -1;
	}
}

#define PACKET_HEADER_CHECK(_msg, _hdr) do { \
	p = buffer + FR_HEADER_LENGTH; \
	if (sizeof(_hdr) > (size_t) (end - p)) { \
		fr_strerror_printf("Header for %s is too small (%zu < %zu)", _msg, (size_t) (end - (uint8_t const *) pkt), (size_t) (p - (uint8_t const *) pkt)); \
		goto fail; \
	} \
	body = p + sizeof(_hdr); \
	data_len = sizeof(_hdr); \
} while (0)

/*
 *	Check argv[i] after the user_msg / server_msg / argc lengths have been added to data_len
 */
#define ARG_COUNT_CHECK(_msg, _hdr) do { \
	fr_assert(p == (uint8_t const *) &(_hdr)); \
	if (data_len > (size_t) (end - p)) { \
		fr_strerror_printf("Argument count %u overflows the remaining data (%zu) in the %s packet", _hdr.arg_cnt, (size_t) (end - p), _msg); \
		goto fail; \
	} \
	argv = body; \
	attrs = buffer + FR_HEADER_LENGTH + data_len; \
	body += _hdr.arg_cnt; \
	p = attrs; \
	for (unsigned int i = 0; i < _hdr.arg_cnt; i++) { \
		if (_hdr.arg_len[i] > (size_t) (end - p)) { \
			fr_strerror_printf("Argument %u length %u overflows packet", i, _hdr.arg_len[i]); \
			goto fail; \
		} \
		p += _hdr.arg_len[i]; \
	} \
} while (0)

#define DECODE_FIELD_UINT8(_da, _field) do { \
	vp = fr_pair_afrom_da(ctx, _da); \
	if (!vp) goto fail; \
	PAIR_ALLOCED(vp); \
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

/** Decode a TACACS+ 'arg_N' fields.
 *
 */
static int tacacs_decode_args(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			      uint8_t arg_cnt, uint8_t const *argv, uint8_t const *attrs, NDEBUG_UNUSED uint8_t const *end)
{
	uint8_t i;
	bool append = false;
	uint8_t const *p = attrs;
	fr_pair_t *vp;
	fr_pair_t *vendor = NULL;
	fr_dict_attr_t const *root;

	/*
	 *	No one? Just get out!
	 */
	if (!arg_cnt) return 0;

	/*
	 *	Try to decode as nested attributes.  If we can't, everything is
	 *
	 *		Argument-List = "foo=bar"
	 */
	if (parent) {
		vendor = fr_pair_find_by_da(out, NULL, parent);
		if (!vendor) {
			vendor = fr_pair_afrom_da(ctx, parent);
			if (!vendor) return -1;
			PAIR_ALLOCED(vendor);

			append = true;
		}
	}

	root = fr_dict_root(dict_tacacs);

	/*
	 *	Then, do the dirty job of creating attributes.
	 */
	for (i = 0; i < arg_cnt; i++) {
		uint8_t const *value, *name_end, *arg_end;
		fr_dict_attr_t const *da;
		fr_pair_list_t *dst;
		uint8_t buffer[256];

		fr_assert((p + argv[i]) <= end);

		if (argv[i] < 2) goto next; /* skip malformed */

		memcpy(buffer, p, argv[i]);
		buffer[argv[i]] = '\0';

		arg_end = buffer + argv[i];

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

		/*
		 *	Prefer to decode from the attribute root, first.
		 */
		da = fr_dict_attr_by_name(NULL, root, (char *) buffer);
		if (da) {
			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) goto oom;
			PAIR_ALLOCED(vp);

			dst = out;
			goto decode;
		}

		/*
		 *	If the attribute isn't in the main dictionary,
		 *	maybe it's in the vendor dictionary?
		 */
		if (vendor) {
			da = fr_dict_attr_by_name(NULL, parent, (char *) buffer);
			if (!da) goto raw;

			vp = fr_pair_afrom_da(vendor, da);
			if (!vp) goto oom;
			PAIR_ALLOCED(vp);

			dst = &vendor->vp_group;

		decode:
			/*
			 *      If it's OCTETS or STRING type, then just copy the value verbatim, as the
			 *      contents are (should be?) binary-safe.  But if it's zero length, then don't need to
			 *      copy anything.
			 *
			 *      Note that we copy things manually here because
			 *      we don't want the OCTETS type to be parsed as
			 *      hex.  And, we don't want the string type to be
			 *      unescaped.
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

			} else if (arg_end == value) {
				/*
				 *	Any other leaf type MUST have non-zero contents.
				 */
				talloc_free(vp);
				goto raw;

			} else {
				/*
				 *      Parse the string, and try to convert it to the
				 *      underlying data type.  If it can't be
				 *      converted as a data type, just convert it as
				 *      Argument-List.
				 *
				 *      And if that fails, just ignore it completely.
				 */
				if (fr_pair_value_from_str(vp, (char const *) value, arg_end - value, NULL, true) < 0) {
					talloc_free(vp);
					goto raw;
				}

				/*
				 *	Else it parsed fine, append it to the output vendor list.
				 */
			}

			fr_pair_append(dst, vp);

		} else {
		raw:
			vp = fr_pair_afrom_da(ctx, attr_tacacs_argument_list);
			if (!vp) {
			oom:
				fr_strerror_const("Out of Memory");
			fail:
				if (append) {
					talloc_free(vendor);
				} else {
					talloc_free(vp);
				}
				return -1;
			}
			PAIR_ALLOCED(vp);

			value = p;
			arg_end = p + argv[i];

			if ((arg_end > value) &&
			    (fr_pair_value_bstrndup(vp, (char const *) value, arg_end - value, true) < 0)) {
				goto fail;
			}

			fr_pair_append(out, vp);
		}

	next:
		p += argv[i];
	}

	if (append) {
		if (fr_pair_list_num_elements(&vendor->vp_group) > 0) {
			fr_pair_append(out, vendor);
		} else {
			talloc_free(vendor);
		}
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

	if (field_len > (end - p)) {
		fr_strerror_printf("'%s' length %u overflows the remaining data (%zu) in the packet",
				   da->name, field_len, (size_t) (end - p));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_const("Out of Memory");
		return -1;
	}
	PAIR_ALLOCED(vp);

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
ssize_t fr_tacacs_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *vendor,
			 uint8_t const *buffer, size_t buffer_len,
			 const uint8_t *original, char const * const secret, size_t secret_len, int *code)
{
	fr_tacacs_packet_t const *pkt;
	fr_pair_t		*vp;
	size_t			data_len;
	uint8_t const  		*p, *body, *argv, *attrs, *end;
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

	/*
	 *	p	miscellaneous pointer for decoding things
	 *	body	points to just past the (randomly sized) per-packet header,
	 *		where the various user / server messages are.
	 *		sometimes this is after "argv".
	 *	argv	points to the array of argv[i] length entries
	 *	attrs	points to the attributes we need to decode as "foo=bar".
	 */
	argv = attrs = NULL;
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
	if (!(pkt->hdr.ver.major == 12 && (pkt->hdr.ver.minor == 0 || pkt->hdr.ver.minor == 1))) {
		fr_strerror_printf("Unsupported TACACS+ version %d.%d (%02x)", pkt->hdr.ver.major, pkt->hdr.ver.minor, buffer[0]);
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
		fr_strerror_printf("Unknown packet type %d", pkt->hdr.type);
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

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	if (fr_struct_from_network(ctx, out, attr_tacacs_packet, buffer, buffer_len, NULL, NULL, NULL) < 0) {
		fr_strerror_printf("Failed decoding TACACS header - %s", fr_strerror());
		return -1;
	}

	/*
	 *	3.6. Encryption
	 *
	 *	If there's a secret, we always decrypt the packets.
	 */
	if (secret && packet_is_encrypted(pkt)) {
		size_t length;

		if (!secret_len) {
			fr_strerror_const("Packet should be encrypted, but the secret has zero length");
			return -1;
		}

		length = ntohl(pkt->hdr.length);

		/*
		 *	We need that to decrypt the body content.
		 *
		 *	@todo - use thread-local storage to avoid allocations?
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

		buffer = decrypted;
	}

#ifndef NDEBUG
	if (fr_debug_lvl >= L_DBG_LVL_4) fr_tacacs_packet_log_hex(&default_log, pkt, (end - buffer));
#endif

	if (code) {
		*code = fr_tacacs_packet_to_code((fr_tacacs_packet_t const *) buffer);
		if (*code < 0) goto fail;
	}

	switch (pkt->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(pkt)) {
			uint8_t want;
			bool raw;
			fr_dict_attr_t const *da, *challenge;

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
			PACKET_HEADER_CHECK("Authentication-Start", pkt->authen_start);

			data_len += p[4] + p[5] + p[6] + p[7];
			if (data_len > (size_t) (end - p)) {
			overflow:
				if ((buffer[3] & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0) {
				bad_secret:
					fr_strerror_const("Invalid packet after decryption - is the secret key incorrect?");
					goto fail;
				}

				fr_strerror_const("Data overflows the packet");
				goto fail;
			}
			if (data_len < (size_t) (end - p)) {
			underflow:
				if ((buffer[3] & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0) goto bad_secret;

				fr_strerror_const("Data underflows the packet");
				goto fail;
			}

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_START);

			/*
			 *	Decode 4 octets of various flags.
			 */
			DECODE_FIELD_UINT8(attr_tacacs_action, pkt->authen_start.action);
			DECODE_FIELD_UINT8(attr_tacacs_privilege_level, pkt->authen_start.priv_lvl);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_type, pkt->authen_start.authen_type);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_service, pkt->authen_start.authen_service);

			/*
			 *	Decode 3 fields, based on their "length"
			 *	user and rem_addr are optional - indicated by zero length
			 */
			p = body;
			if (pkt->authen_start.user_len > 0) DECODE_FIELD_STRING8(attr_tacacs_user_name,
										 pkt->authen_start.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->authen_start.port_len);
			if (pkt->authen_start.rem_addr_len > 0) DECODE_FIELD_STRING8(attr_tacacs_remote_address,
										     pkt->authen_start.rem_addr_len);

			/*
			 *	Check the length on the various
			 *	authentication types.
			 */
			raw = false;
			challenge = NULL;

			switch (pkt->authen_start.authen_type) {
			default:
				raw = true;
				want = pkt->authen_start.data_len;
				da = attr_tacacs_data;
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_PAP:
				want = pkt->authen_start.data_len;
				da = attr_tacacs_user_password;
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_CHAP:
				want = 1 + 16; /* id + HOPEFULLY 8 octets of challenge + 16 hash */
				da = attr_tacacs_chap_password;
				challenge = attr_tacacs_chap_challenge;
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_MSCHAP:
				want = 1 + 49; /* id + HOPEFULLY 8 octets of challenge + 49 MS-CHAP stuff */
				da = attr_tacacs_mschap_response;
				challenge = attr_tacacs_mschap_challenge;
				break;

			case FR_AUTHENTICATION_TYPE_VALUE_MSCHAPV2:
				want = 1 + 49; /* id + HOPEFULLY 16 octets of challenge + 49 MS-CHAP stuff */
				da = attr_tacacs_mschap2_response;
				challenge = attr_tacacs_mschap_challenge;
				break;
			}

			/*
			 *	If we have enough data, decode it as
			 *	the claimed authentication type.
			 *
			 *	Otherwise, decode the entire field as an unknown
			 *	attribute.
			 */
			if (raw || (pkt->authen_start.data_len < want)) {
				fr_dict_attr_t *da_unknown;

				da_unknown = fr_dict_attr_unknown_raw_afrom_num(ctx, fr_dict_root(dict_tacacs),
										attr_tacacs_data->attr);
				if (!da_unknown) goto fail;

				want = pkt->authen_start.data_len;

				DECODE_FIELD_STRING8(da_unknown, want);
				talloc_free(da_unknown);

			} else if (!challenge) {
				DECODE_FIELD_STRING8(da, want);

			} else if (pkt->authen_start.data_len == want)  {
				fr_strerror_printf("%s has zero length", challenge->name);
				goto fail;

			} else { /* 1 of ID + ??? of challenge + (want-1) of data */
				uint8_t challenge_len = pkt->authen_start.data_len - want;
				uint8_t hash[50];

				/*
				 *	Rework things to make sense.
				 *	RFC 8079 says that MS-CHAP responses should follow RFC 2433 and 2759
				 *	which have "Flags" at the end.
				 *	RADIUS attributes expect "Flags" after the ID as per RFC 2548.
				 *	Re-arrange to make things consistent.
				 */
				hash[0] = p[0];
				switch (pkt->authen_start.authen_type) {
				case FR_AUTHENTICATION_TYPE_VALUE_MSCHAP:
				case FR_AUTHENTICATION_TYPE_VALUE_MSCHAPV2:
					hash[1] = p[want - 1];
					memcpy(hash + 2, p + 1 + challenge_len, want - 2);
					break;

				default:
					memcpy(hash + 1, p + 1 + challenge_len, want - 1);
					break;
				}

				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) goto fail;
				PAIR_ALLOCED(vp);

				fr_pair_append(out, vp);

				/*
				 *	ID + hash
				 */
				if (fr_pair_value_memdup(vp, hash, want, true) < 0) goto fail;

				/*
				 *	And then the challenge.
				 */
				vp = fr_pair_afrom_da(ctx, challenge);
				if (!vp) goto fail;
				PAIR_ALLOCED(vp);

				fr_pair_append(out, vp);

				if (fr_pair_value_memdup(vp, p + 1, challenge_len, true) < 0) goto fail;

				p += pkt->authen_start.data_len;
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

			PACKET_HEADER_CHECK("Authentication-Continue", pkt->authen_cont);
			data_len += fr_nbo_to_uint16(p) + fr_nbo_to_uint16(p + 2);
			if (data_len > (size_t) (end - p)) goto overflow;
			if (data_len < (size_t) (end - p)) goto underflow;

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_CONTINUE);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = body;
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
			PACKET_HEADER_CHECK("Authentication-Reply", pkt->authen_reply);
			data_len += fr_nbo_to_uint16(p + 2) + fr_nbo_to_uint16(p + 4);
			if (data_len > (size_t) (end - p)) goto overflow;
			if (data_len < (size_t) (end - p)) goto underflow;

			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_REPLY);

			DECODE_FIELD_UINT8(attr_tacacs_authentication_status, pkt->authen_reply.status);
			DECODE_FIELD_UINT8(attr_tacacs_authentication_flags, pkt->authen_reply.flags);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = body;
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

			PACKET_HEADER_CHECK("Authorization-Request", pkt->author_req);
			data_len += p[4] + p[5] + p[6] + p[7];

			ARG_COUNT_CHECK("Authorization-Request", pkt->author_req);

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
			 *	rem_addr is optional - indicated by zero length
			 */
			p = body;
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->author_req.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->author_req.port_len);
			if (pkt->author_req.rem_addr_len > 0) DECODE_FIELD_STRING8(attr_tacacs_remote_address,
										   pkt->author_req.rem_addr_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, out, vendor,
					       pkt->author_req.arg_cnt, argv, attrs, end) < 0) goto fail;

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

			PACKET_HEADER_CHECK("Authorization-Reply", pkt->author_reply);
			data_len += p[1] + fr_nbo_to_uint16(p + 2) + fr_nbo_to_uint16(p + 4);

			ARG_COUNT_CHECK("Authorization-Reply", pkt->author_reply);
			DECODE_FIELD_UINT8(attr_tacacs_packet_body_type, FR_PACKET_BODY_TYPE_RESPONSE);

			/*
			 *	Decode 1 octets
			 */
			DECODE_FIELD_UINT8(attr_tacacs_authorization_status, pkt->author_reply.status);

			/*
			 *	Decode 2 fields, based on their "length"
			 */
			p = body;
			DECODE_FIELD_STRING16(attr_tacacs_server_message, pkt->author_reply.server_msg_len);
			DECODE_FIELD_STRING16(attr_tacacs_data, pkt->author_reply.data_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, out, vendor,
					       pkt->author_reply.arg_cnt, argv, attrs, end) < 0) goto fail;

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

			PACKET_HEADER_CHECK("Accounting-Request", pkt->acct_req);
			data_len += p[5] + p[6] + p[7] + p[8];
			if (data_len > (size_t) (end - p)) goto overflow;
			/* can't check for underflow, as we have argv[argc] */

			ARG_COUNT_CHECK("Accounting-Request", pkt->acct_req);

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
			p = body;
			DECODE_FIELD_STRING8(attr_tacacs_user_name, pkt->acct_req.user_len);
			DECODE_FIELD_STRING8(attr_tacacs_client_port, pkt->acct_req.port_len);
			DECODE_FIELD_STRING8(attr_tacacs_remote_address, pkt->acct_req.rem_addr_len);

			/*
			 *	Decode 'arg_N' arguments (horrible format)
			 */
			if (tacacs_decode_args(ctx, out, vendor,
					       pkt->acct_req.arg_cnt, argv, attrs, end) < 0) goto fail;

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

			PACKET_HEADER_CHECK("Accounting-Reply", pkt->acct_reply);
			data_len += fr_nbo_to_uint16(p) + fr_nbo_to_uint16(p + 2);
			if (data_len > (size_t) (end - p)) goto overflow;
			if (data_len < (size_t) (end - p)) goto underflow;

			p = BODY(acct_reply);
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
		fr_strerror_printf("decode: Unsupported packet type %d", pkt->hdr.type);
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
	fr_dict_attr_t const *dv;

	dv = fr_dict_attr_by_name(NULL, fr_dict_root(dict_tacacs), "Test");
	fr_assert(!dv || (dv->type == FR_TYPE_VENDOR));

	return fr_tacacs_decode(ctx, out, dv, data, data_len, NULL,
				test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), NULL);
}

static int _encode_test_ctx(fr_tacacs_ctx_t *proto_ctx)
{
	talloc_const_free(proto_ctx->secret);

	fr_tacacs_global_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_tacacs_ctx_t *test_ctx;

	if (fr_tacacs_global_init() < 0) return -1;

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
