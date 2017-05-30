/*
 * tacacs.c	Low-level TACACS+ functions.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2017 The FreeRADIUS server project
 * Copyright 2017 Network RADIUS SARL <info@networkradius.com>
 */

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/net.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/log.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/tacacs.h>

#include "tacacs.h"

fr_dict_attr_t const *dict_tacacs_root = NULL;

tacacs_type_t tacacs_type(RADIUS_PACKET const * const packet)
{
	VALUE_PAIR const *vp;

	vp = fr_pair_find_by_child_num(packet->vps, dict_tacacs_root, FR_TACACS_PACKET_TYPE, TAG_ANY);
	rad_assert(vp != NULL);

	return (tacacs_type_t)vp->vp_uint8;
}

char const * tacacs_lookup_packet_code(RADIUS_PACKET const * const packet)
{
	fr_dict_attr_t const *da;
	fr_dict_enum_t const *dv;
	tacacs_type_t type;

	type = tacacs_type(packet);

	da = fr_dict_attr_child_by_num(dict_tacacs_root, FR_TACACS_PACKET_TYPE);
	rad_assert(da != NULL);
	dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(type));
	rad_assert(dv != NULL);

	return dv->alias;
}

uint32_t tacacs_session_id(RADIUS_PACKET const * const packet)
{
	VALUE_PAIR const *vp;

	vp = fr_pair_find_by_child_num(packet->vps, dict_tacacs_root, FR_TACACS_SESSION_ID, TAG_ANY);
	rad_assert(vp != NULL);

	return vp->vp_uint32;
}

static bool tacacs_ok(RADIUS_PACKET const * const packet, bool from_client)
{
	tacacs_packet_t *pkt = (tacacs_packet_t *)packet->data;
	size_t hdr_len, len;

	if (pkt->hdr.ver.major != TAC_PLUS_MAJOR_VER || pkt->hdr.ver.minor & 0xe) {	/* minor == {0,1} */
		fr_strerror_printf("Unsupported version %u.%u", pkt->hdr.ver.major, pkt->hdr.ver.minor);
		return false;
	}

	hdr_len = ntohl(pkt->hdr.length);

	switch (pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		if ((from_client && pkt->hdr.seq_no % 2 != 1) || (!from_client && pkt->hdr.seq_no % 2 != 0)) {
bad_seqno:
			fr_strerror_printf("Invalid sequence number %u (from_client = %s)", pkt->hdr.seq_no, from_client ? "true" : "false");
			return false;
		}
		if (pkt->hdr.seq_no == 255) {
			fr_strerror_printf("client sent seq_no set to 255");
			return false;
		}

		break;
	case TAC_PLUS_AUTHOR:
	case TAC_PLUS_ACCT:
		if ((from_client && pkt->hdr.seq_no != 1) || (!from_client && pkt->hdr.seq_no != 2))
			goto bad_seqno;
		break;
	}

	/* this occurs when we want to indicate we do not support the request */
	if (hdr_len == 0)
		return true;

	switch (pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		switch (pkt->hdr.seq_no) {
		case 1:
			len = pkt->authen.start.user_len + pkt->authen.start.port_len + pkt->authen.start.rem_addr_len + pkt->authen.start.data_len;
			if (len + offsetof(tacacs_packet_authen_start_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Authen START Header/Body size mismatch");
				return false;
			}
			break;
		default:
			if (from_client) {
				len = ntohs(pkt->authen.cont.user_msg_len) + ntohs(pkt->authen.cont.data_len);
				if (len + offsetof(tacacs_packet_authen_cont_hdr_t, body) != hdr_len) {
					fr_strerror_printf("Authen CONTINUE Header/Body size mismatch");
					return false;
				}
			} else {
				len = ntohs(pkt->authen.reply.server_msg_len) + ntohs(pkt->authen.reply.data_len);
				if (len + offsetof(tacacs_packet_authen_reply_hdr_t, body) != hdr_len) {
					fr_strerror_printf("Authen REPLY Header/Body size mismatch");
					return false;
				}
			}
		}
		break;
	case TAC_PLUS_AUTHOR:
		if (from_client) {
			len = pkt->author.req.user_len + pkt->author.req.port_len + pkt->author.req.rem_addr_len + pkt->author.req.arg_cnt;
			for (unsigned int i = 0; i < pkt->author.req.arg_cnt; i++)
				len += pkt->author.req.body[i];
			if (len + offsetof(tacacs_packet_author_req_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Author REQUEST Header/Body size mismatch");
				return false;
			}
		} else {
			len = pkt->author.res.server_msg_len + pkt->author.res.data_len + pkt->author.res.arg_cnt;
			for (unsigned int i = 0; i < pkt->author.res.arg_cnt; i++)
				len += pkt->author.res.body[i];
			if (len + offsetof(tacacs_packet_author_res_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Author RESPONSE Header/Body size mismatch");
				return false;
			}
		}
		break;
	case TAC_PLUS_ACCT:
		if (from_client) {
			uint8_t flags;

			len = pkt->acct.req.user_len + pkt->acct.req.port_len + pkt->acct.req.rem_addr_len + pkt->acct.req.arg_cnt;
			for (unsigned int i = 0; i < pkt->acct.req.arg_cnt; i++)
				len += pkt->acct.req.body[i];
			if (len + offsetof(tacacs_packet_acct_req_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Acct REQUEST Header/Body size mismatch");
				return false;
			}

			flags = pkt->acct.req.flags & 0xe;
			if (flags == 0x0 || flags == 0x6 || flags == 0xc || flags == 0xe) {
				/* FIXME send to client TACACS-Accounting-Status Error */
				fr_strerror_printf("Acct RESPONSE invalid flags set");
				return false;
			}
		} else {
			len = pkt->acct.res.server_msg_len + pkt->acct.res.data_len;
			if (len + offsetof(tacacs_packet_acct_res_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Acct RESPONSE Header/Body size mismatch");
				return false;
			}
		}
		break;
	}

	return true;
}

static int tacacs_xor(RADIUS_PACKET * const packet, char const *secret)
{
	tacacs_packet_t *pkt = (tacacs_packet_t *)packet->data;
	uint8_t pad[MD5_DIGEST_LENGTH];
	uint8_t *buf;
	int secret_len;
	int pad_offset;

	if (!secret) {
		if (pkt->hdr.flags & TAC_PLUS_UNENCRYPTED_FLAG)
			return 0;
		else {
			fr_strerror_printf("Packet is encrypted but no secret for the client is set");
			return -1;
		}
	}

	if (pkt->hdr.flags & TAC_PLUS_UNENCRYPTED_FLAG) {
		fr_strerror_printf("Packet is unencrypted but a secret has been set for the client");
		return -1;
	}

	secret_len = strlen(secret);
	pad_offset = sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version) + sizeof(pkt->hdr.seq_no);

	/* MD5_1 = MD5{session_id, key, version, seq_no} */
	/* MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1} */
	buf = talloc_array(NULL, uint8_t, pad_offset + MD5_DIGEST_LENGTH);

	memcpy(&buf[0], &pkt->hdr.session_id, sizeof(pkt->hdr.session_id));
	memcpy(&buf[sizeof(pkt->hdr.session_id)], secret, secret_len);
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len], &pkt->hdr.version, sizeof(pkt->hdr.version));
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version)], &pkt->hdr.seq_no, sizeof(pkt->hdr.seq_no));
	fr_md5_calc(pad, buf, pad_offset);

	size_t pos = sizeof(tacacs_packet_hdr_t);
	do {
		for (size_t i = 0; i < MD5_DIGEST_LENGTH && pos < packet->data_len; i++, pos++)
			packet->data[pos] ^= pad[i];

		if (pos == packet->data_len)
			break;

		memcpy(&buf[pad_offset], pad, MD5_DIGEST_LENGTH);
		fr_md5_calc(pad, buf, pad_offset + MD5_DIGEST_LENGTH);
	} while (1);

	talloc_free(buf);

	return 0;
}

int tacacs_encode(RADIUS_PACKET * const packet, char const * const secret)
{
	uint8_t			*ptr;
	uint16_t		length_hdr;
	uint16_t		length_body;
	VALUE_PAIR const	*vp;
	vp_cursor_t		cursor;
	tacacs_packet_t		*pkt;
	struct {
		VALUE_PAIR const	*server_msg;
		VALUE_PAIR const	*data;
	}			field = {0};
	uint8_t			status = 0;
	tacacs_authen_reply_flags_t authen_reply_flags = TAC_PLUS_REPLY_FLAG_UNSET;

	/*
	 *	Not zero'd to catch bugs via tacacs_ok()
	 */
	uint8_t data[sizeof(tacacs_packet_t)];

	/*
	 *	Use memory on the stack, until we know how
	 *	large the packet will be.
	 */
	pkt = (tacacs_packet_t *)data;

	pkt->hdr.ver.major = TAC_PLUS_MAJOR_VER;

	pkt->hdr.flags = (secret)
		? TAC_PLUS_ENCRYPTED_MULTIPLE_CONNECTIONS_FLAG
		: TAC_PLUS_UNENCRYPTED_FLAG;

	length_body = 0;
	for (vp = fr_pair_cursor_init(&cursor, &packet->vps); vp != NULL; vp = fr_pair_cursor_next(&cursor)) {
		VERIFY_VP(vp);

		if (!vp->da->flags.internal) continue;

		switch (vp->da->attr) {
		case FR_TACACS_VERSION_MINOR:
			pkt->hdr.ver.minor = vp->vp_uint8;
			break;
		case FR_TACACS_PACKET_TYPE:
			pkt->hdr.type = vp->vp_uint8;
			break;
		case FR_TACACS_SEQUENCE_NUMBER:
			pkt->hdr.seq_no = vp->vp_uint8;
			break;
		case FR_TACACS_SESSION_ID:
			pkt->hdr.session_id = htonl(vp->vp_uint32);
			break;
		case FR_TACACS_AUTHENTICATION_STATUS:
			pkt->authen.reply.status = vp->vp_uint8;
			status = vp->vp_uint8;
			break;
		case FR_TACACS_AUTHENTICATION_FLAGS:
			authen_reply_flags |= vp->vp_uint8;
			break;
		case FR_TACACS_AUTHORIZATION_STATUS:
			pkt->author.res.status = vp->vp_uint8;
			status = vp->vp_uint8;
			break;
		case FR_TACACS_ACCOUNTING_STATUS:
			pkt->acct.res.status = vp->vp_uint8;
			status = vp->vp_uint8;
			break;
		case FR_TACACS_SERVER_MESSAGE:
			length_body += vp->vp_length;
			field.server_msg = vp;
			break;
		case FR_TACACS_DATA:
			length_body += vp->vp_length;
			field.data = vp;
			break;
		default:
			WARN("Unhandled %s", vp->da->name);
		}
	}

	length_hdr = sizeof(tacacs_packet_hdr_t);
	switch (pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		length_hdr += offsetof(tacacs_packet_authen_reply_hdr_t, body);
		pkt->authen.reply.flags = authen_reply_flags;
		pkt->authen.reply.server_msg_len = htons(0);
		pkt->authen.reply.data_len = htons(0);
		break;
	case TAC_PLUS_AUTHOR:
		length_hdr += offsetof(tacacs_packet_author_res_hdr_t, body);
		pkt->author.res.arg_cnt = 0;
		pkt->author.res.server_msg_len = htons(0);
		pkt->author.res.data_len = htons(0);
		break;
	case TAC_PLUS_ACCT:
		length_hdr += offsetof(tacacs_packet_acct_res_hdr_t, body);
		pkt->acct.res.server_msg_len = htons(0);
		pkt->acct.res.data_len = htons(0);
		break;
	/* unsupported type as per draft-ietf-opsawg-tacacs section 3.6 */
	default:
fail:
		length_hdr = sizeof(tacacs_packet_hdr_t);
		length_body = 0;
		goto cook;
	}

	/* if status is unset then send failure to client */
	if (!status)
		goto fail;

cook:
	rad_assert(length_hdr + length_body < TACACS_MAX_PACKET_SIZE);

	pkt->hdr.length = htonl(length_hdr - sizeof(tacacs_packet_hdr_t) + length_body);

	/*
	 *	Fill in the rest of the fields, and copy the data over
	 *	from the local stack to the newly allocated memory.
	 *
	 *	Yes, all this 'memcpy' is slow, but it means
	 *	that we only allocate the minimum amount of
	 *	memory for a request.
	 */
	packet->data_len = length_hdr + length_body;
	packet->data = talloc_array(packet, uint8_t, packet->data_len);
	if (!packet->data) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	memcpy(packet->data, pkt, length_hdr);

	pkt = (tacacs_packet_t *)packet->data;

	ptr = packet->data;
	ptr += length_hdr;

	if (!length_body)
		goto skip_fields;

	if (field.server_msg) {
		switch (pkt->hdr.type) {
		case TAC_PLUS_AUTHEN:
			pkt->authen.reply.server_msg_len = htons(field.server_msg->vp_length);
			break;
		case TAC_PLUS_AUTHOR:
			pkt->author.res.server_msg_len = htons(field.server_msg->vp_length);
			break;
		case TAC_PLUS_ACCT:
			pkt->acct.res.server_msg_len = htons(field.server_msg->vp_length);
			break;
		}
		memcpy(ptr, field.server_msg->vp_octets, field.server_msg->vp_length);
		ptr += field.server_msg->vp_length;
	}
	if (field.data) {
		switch (pkt->hdr.type) {
		case TAC_PLUS_AUTHEN:
			pkt->authen.reply.data_len = htons(field.data->vp_length);
			break;
		case TAC_PLUS_AUTHOR:
			pkt->author.res.data_len = htons(field.data->vp_length);
			break;
		case TAC_PLUS_ACCT:
			pkt->acct.res.data_len = htons(field.data->vp_length);
			break;
		}
		memcpy(ptr, field.data->vp_octets, field.data->vp_length);
	}
skip_fields:

	return 0;
}


static int tacacs_decode_field(TALLOC_CTX *ctx, vp_cursor_t *cursor, unsigned int attr, char const *field_name,
			       uint8_t **field_data, size_t field_len, size_t *remaining)
{
	uint8_t *p;
	VALUE_PAIR *vp;

	p = *field_data;

	/*
	 *	This field doesn't exist.  Ignore it.
	 */
	if (!field_len) return 0;

	if (*remaining < field_len) {
		fr_strerror_printf("%s length overflows the remaining data in the packet: %zu > %zu",
				   field_name, field_len, *remaining);
		return -1;
	}

	vp = fr_pair_afrom_child_num(ctx, dict_tacacs_root, attr);
	if (!vp) return -1;

	fr_pair_value_bstrncpy(vp, p, field_len);
	p += field_len;
	*remaining -= field_len;
	fr_pair_cursor_append(cursor, vp);

	*field_data = p;

	return 0;
}



int tacacs_decode(RADIUS_PACKET * const packet)
{
	int i;
	tacacs_packet_t *pkt;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	uint8_t *p;
	uint32_t session_id;
	size_t remaining;

	if (!dict_tacacs_root) return -1;

	fr_pair_cursor_init(&cursor, &packet->vps);

	/*
	 *	There MUST be at least a TACACS packert header, and
	 *	packet->data_len == sizeof(pkt) + htonl(pkt->length),
	 *	which is enforced in tacacs_read_packet().
	 */
	pkt = (tacacs_packet_t *)packet->data;

	remaining = ntohl(pkt->hdr.length);

	vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_VERSION_MINOR);
	if (!vp) return -1;
	vp->vp_uint8 = pkt->hdr.ver.minor;
	fr_pair_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_PACKET_TYPE);
	if (!vp) return -1;
	vp->vp_uint8 = pkt->hdr.type;
	fr_pair_cursor_append(&cursor, vp);

	packet->code = pkt->hdr.type;

	vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_SEQUENCE_NUMBER);
	if (!vp) return -1;
	vp->vp_uint8 = pkt->hdr.seq_no;
	fr_pair_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_SESSION_ID);
	if (!vp) return -1;
	vp->vp_uint32 = ntohl(pkt->hdr.session_id);
	fr_pair_cursor_append(&cursor, vp);
	session_id = vp->vp_uint32;

	switch ((tacacs_type_t)pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		switch (pkt->hdr.seq_no) {
		case 1:
			if (remaining < 8) {
				fr_strerror_printf("Authentication START packet is too small: %zu < 8",
						   remaining);
				return -1;
			}
			remaining -= 8;

			/*
			 *	Decode 4 octets of various flags.
			 */
			vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_ACTION);
			if (!vp) return -1;
			vp->vp_uint8 = pkt->authen.start.action;
			fr_pair_cursor_append(&cursor, vp);

			vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_PRIVILEGE_LEVEL);
			if (!vp) return -1;
			vp->vp_uint8 = pkt->authen.start.priv_lvl;
			fr_pair_cursor_append(&cursor, vp);

			vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_TYPE);
			if (!vp) return -1;
			vp->vp_uint8 = pkt->authen.start.authen_type;
			fr_pair_cursor_append(&cursor, vp);

			vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_SERVICE);
			if (!vp) return -1;
			vp->vp_uint8 = pkt->authen.start.authen_service;
			fr_pair_cursor_append(&cursor, vp);

			/*
			 *	Decode 4 fields, based on their "length"
			 */
			p = pkt->authen.start.body;

			if (tacacs_decode_field(packet, &cursor, FR_TACACS_USER_NAME, "User",
						&p, pkt->authen.start.user_len, &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, FR_TACACS_CLIENT_PORT, "Port",
						&p, pkt->authen.start.port_len, &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, FR_TACACS_REMOTE_ADDRESS, "Remote address",
						&p, pkt->authen.start.rem_addr_len, &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, FR_TACACS_DATA, "Data",
						&p, pkt->authen.start.data_len, &remaining) < 0) {
				return -1;
			}
			break;

		default:
			if (remaining < 5) {
				fr_strerror_printf("Authentication CONTINUE packet is too small: %zu < 5",
						   remaining);
				return -1;
			}
			remaining -= 5;

			/*
			 *	Decode 2 fields, based on their 'length'
			 */
			p = pkt->authen.cont.body;

			if (tacacs_decode_field(packet, &cursor, FR_TACACS_USER_MESSAGE, "User message",
						&p, ntohs(pkt->authen.cont.user_msg_len), &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, FR_TACACS_DATA, "Data",
						&p, ntohs(pkt->authen.cont.data_len), &remaining) < 0) {
				return -1;
			}

			/*
			 *	Look at the abort flag after decoding the fields.
			 */
			if (pkt->authen.cont.flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
				if (!ntohs(pkt->authen.cont.data_len) ||
				    !(vp = fr_pair_cursor_last(&cursor))) {
					fr_strerror_printf("Client aborted authentication session %u with no message", session_id);
					return -2;
				}

				if (ntohs(pkt->authen.cont.data_len) > 128) {
					fr_strerror_printf("Client aborted authentication session %u with too long message", session_id);
					return -2;
				}
					    
				fr_strerror_printf("Client aborted authentication session %u with message %s",
						   session_id, vp->vp_strvalue);
				return -2;
			}
		}
		break;

	case TAC_PLUS_AUTHOR:
		if (remaining < 8) {
			fr_strerror_printf("Authorization REQUEST packet is too small: %zu < 8",
					   remaining);
			return -1;
		}
		remaining -= 8;

		if (remaining < pkt->author.req.arg_cnt) {
			fr_strerror_printf("Authorization REQUEST packet arguments are smaller than arg_ctx: %zu < %u",
					   remaining, pkt->author.req.arg_cnt);
			return -1;
		}
		remaining -= pkt->author.req.arg_cnt;

		/*
		 *	Skip the header and the N arguments.
		 */
		p = pkt->author.req.body;
		p += pkt->author.req.arg_cnt;

		/*
		 *	Decode 4 octets of various flags.
		 */
		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_METHOD);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->author.req.authen_method;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_PRIVILEGE_LEVEL);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->author.req.priv_lvl;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_TYPE);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->author.req.authen_type;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_SERVICE);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->author.req.authen_service;
		fr_pair_cursor_append(&cursor, vp);

		/*
		 *	Decode 3 fields, based on their "length"
		 */
		if (tacacs_decode_field(packet, &cursor, FR_TACACS_USER_NAME, "User",
					&p, pkt->author.req.user_len, &remaining) < 0) {
			return -1;
		}

		if (tacacs_decode_field(packet, &cursor, FR_TACACS_CLIENT_PORT, "Port",
					&p, pkt->authen.start.port_len, &remaining) < 0) {
			return -1;
		}

		if (tacacs_decode_field(packet, &cursor, FR_TACACS_REMOTE_ADDRESS, "Remote address",
					&p, pkt->authen.start.rem_addr_len, &remaining) < 0) {
			return -1;
		}

		/* FIXME fully support arg */
		p =  pkt->author.req.body;
		for (i = 0; i < pkt->author.req.arg_cnt; i++) {
			if (remaining < p[i]) {
				fr_strerror_printf("Authorization REQUEST packet argument %d overflows the packet: %u > %zu",
						   i, p[i], remaining);
				return -1;
			}
			remaining -= p[i];
		}
		break;

	case TAC_PLUS_ACCT:
		if (remaining < 9) {
			fr_strerror_printf("Accounting REQUEST packet is too small: %zu < 9",
					   remaining);
			return -1;
		}
		remaining -= 9;

		if (remaining < pkt->author.req.arg_cnt) {
			fr_strerror_printf("Accounting REQUEST packet arguments are smaller than arg_ctx: %zu < %u",
					   remaining, pkt->author.req.arg_cnt);
			return -1;
		}
		remaining -= pkt->author.req.arg_cnt;

		/*
		 *	Skip the header and the N arguments.
		 */
		p = pkt->acct.req.body;
		p += pkt->acct.req.arg_cnt;

		/*
		 *	Decode 8 octets of various fields.
		 */
		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_ACCOUNTING_FLAGS);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->acct.req.flags;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_METHOD);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->acct.req.authen_method;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_PRIVILEGE_LEVEL);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->acct.req.priv_lvl;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_TYPE);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->acct.req.authen_type;
		fr_pair_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_AUTHENTICATION_SERVICE);
		if (!vp) return -1;
		vp->vp_uint8 = pkt->acct.req.authen_service;
		fr_pair_cursor_append(&cursor, vp);

		/*
		 *	Decode 3 fields, based on their "length"
		 */
		if (tacacs_decode_field(packet, &cursor, FR_TACACS_USER_NAME, "User",
					&p, pkt->acct.req.user_len, &remaining) < 0) {
			return -1;
		}

		if (tacacs_decode_field(packet, &cursor, FR_TACACS_CLIENT_PORT, "Port",
					&p, pkt->acct.req.port_len, &remaining) < 0) {
			return -1;
		}

		if (tacacs_decode_field(packet, &cursor, FR_TACACS_REMOTE_ADDRESS, "Remote address",
					&p, pkt->acct.req.rem_addr_len, &remaining) < 0) {
			return -1;
		}

		/* FIXME fully support arg */
		p =  pkt->acct.req.body;
		for (i = 0; i < pkt->acct.req.arg_cnt; i++) {
			if (remaining < p[i]) {
				fr_strerror_printf("Accounting REQUEST packet argument %d overflows the packet: %u > %zu",
						   i, p[i], remaining);
				return -1;
			}
			remaining -= p[i];
		}
		break;
	default:
		fr_strerror_printf("Unsupported TACACS+ type %u", pkt->hdr.type);
		return -1;
	}

	return 0;
}

/*
 *	Receives a packet, assuming that the RADIUS_PACKET structure
 *	has been filled out already.
 *
 *	This ASSUMES that the packet is allocated && fields
 *	initialized.
 *
 *	This ASSUMES that the socket is marked as O_NONBLOCK, which
 *	the function above does set, if your system supports it.
 *
 *	Calling this function MAY change sockfd,
 *	if src_ipaddr.af == AF_UNSPEC.
 */
int tacacs_read_packet(RADIUS_PACKET * const packet, char const * const secret)
{
	ssize_t len;

	/*
	 *	No data allocated.  Read the 12-byte header into
	 *	a temporary buffer.
	 */
	if (!packet->data) {
		tacacs_packet_hdr_t *hdr;
		size_t packet_len;

		/* borrow vector to bring in the header for later talloc */
		rad_assert(sizeof(tacacs_packet_hdr_t) <= AUTH_VECTOR_LEN);

		/*
		 *	Only read enough data to get the TACACS+ header.
		 */
		 len = recv(packet->sockfd, packet->vector + packet->data_len,
			   sizeof(tacacs_packet_hdr_t) - packet->data_len, 0);
		if (len == 0) return -2; /* clean close */

#ifdef ECONNRESET
		if ((len < 0) && (errno == ECONNRESET)) { /* forced */
			return -2;
		}
#endif

		if (len < 0) {
			fr_strerror_printf("Error receiving packet: %s", fr_syserror(errno));
			return -1;
		}

		packet->data_len += len;
		if (packet->data_len < sizeof(tacacs_packet_hdr_t)) { /* want more data */
			return 0;
		}

		rad_assert(packet->data_len == sizeof(tacacs_packet_hdr_t));

		/*
		 *	We now have the full packet header.  Let's go
		 *	check it.
		 */
		hdr = (tacacs_packet_hdr_t *)packet->vector;

		packet_len = ntohl(hdr->length);
		if (packet_len + sizeof(tacacs_packet_hdr_t) > TACACS_MAX_PACKET_SIZE) {
			fr_strerror_printf("Discarding packet: Larger than limitation of " STRINGIFY(MAX_PACKET_LEN) " bytes");
			return -1;
		}

		packet_len += sizeof(tacacs_packet_hdr_t);

		packet->data = talloc_array(packet, uint8_t, packet_len);
		if (!packet->data) {
			fr_strerror_printf("Out of memory");
			return -1;
		}

		/*
		 *	We have room for a full packet, but we've only
		 *	read in th eheader so far.
		 */
		packet->data_len = packet_len;
		packet->partial = sizeof(tacacs_packet_hdr_t);
		memcpy(packet->data, packet->vector, sizeof(tacacs_packet_hdr_t));
	}

	/*
	 *	Try to read more data.
	 */
	len = recv(packet->sockfd, packet->data + packet->partial,
		   packet->data_len - packet->partial, 0);
	if (len == 0) return -2; /* clean close */

#ifdef ECONNRESET
	if ((len < 0) && (errno == ECONNRESET)) { /* forced */
		return -2;
	}
#endif

	if (len < 0) {
		fr_strerror_printf("Error receiving packet: %s", fr_syserror(errno));
		return -1;
	}

	packet->partial += len;

	if (packet->partial < packet->data_len) {
		return 0;
	}

	if (tacacs_xor(packet, secret) < 0) {
		fr_strerror_printf("Failed decryption of TACACS request: %s", fr_syserror(errno));
		return -1;
	}

#ifndef NDEBUG
	if ((fr_debug_lvl > 3) && fr_log_fp) fr_radius_print_hex(packet);
#endif

	/*
	 *	See if it's a well-formed TACACS packet.
	 */
	if (!tacacs_ok(packet, true)) {
		return -1;
	}

	/*
	 *	Explicitly set the VP list to empty.
	 */
	packet->vps = NULL;

	if (fr_debug_lvl) {
		char ip_buf[INET6_ADDRSTRLEN], buffer[256];

		if (packet->src_ipaddr.af != AF_UNSPEC) {
			inet_ntop(packet->src_ipaddr.af,
				  &packet->src_ipaddr.addr,
				  ip_buf, sizeof(ip_buf));
			snprintf(buffer, sizeof(buffer), "host %s port %d",
				 ip_buf, packet->src_port);
		} else {
			snprintf(buffer, sizeof(buffer), "socket %d",
				 packet->sockfd);
		}

	}

	gettimeofday(&packet->timestamp, NULL);

	return 1;	/* done reading the packet */
}

int tacacs_send(RADIUS_PACKET * const packet, RADIUS_PACKET const * const original, char const * const secret)
{
	uint8_t			vminor;
	tacacs_type_t		type;
	uint8_t			seq_no;
	VALUE_PAIR 		*vp;

	vp = fr_pair_find_by_child_num(original->vps, dict_tacacs_root, FR_TACACS_VERSION_MINOR, TAG_ANY);
	rad_assert(vp != NULL);
	vminor = vp->vp_uint8;

	vp = fr_pair_afrom_da(packet, vp->da);
	if (!vp) return -1;
	vp->vp_uint8 = vminor;
	fr_pair_add(&packet->vps, vp);

	type = tacacs_type(original);

	vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_PACKET_TYPE);
	vp->vp_uint8 = type;
	fr_pair_add(&packet->vps, vp);

	vp = fr_pair_find_by_child_num(original->vps, dict_tacacs_root, FR_TACACS_SEQUENCE_NUMBER, TAG_ANY);
	rad_assert(vp != NULL);
	seq_no = vp->vp_uint8 + 1;	/* we catch client 255 on ingress */

	vp = fr_pair_afrom_da(packet, vp->da);
	if (!vp) return -1;
	vp->vp_uint8 = seq_no;
	fr_pair_add(&packet->vps, vp);

	vp = fr_pair_afrom_child_num(packet, dict_tacacs_root, FR_TACACS_SESSION_ID);
	if (!vp) return -1;
	vp->vp_uint32 = tacacs_session_id(original);
	fr_pair_add(&packet->vps, vp);

	if (tacacs_encode(packet, secret) < 0) {
		fr_strerror_printf("Failed encoding TACACS reply: %s", fr_syserror(errno));
		return -1;
	}

#ifndef NDEBUG
	if ((fr_debug_lvl > 3) && fr_log_fp) fr_radius_print_hex(packet);
#endif

	rad_assert(tacacs_ok(packet, false) == true);

	if (tacacs_xor(packet, secret) < 0) {
		fr_strerror_printf("Failed encryption of TACACS reply: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	@fixme: EINTR and retry
	 */
	return write(packet->sockfd, packet->data, packet->data_len);
}
