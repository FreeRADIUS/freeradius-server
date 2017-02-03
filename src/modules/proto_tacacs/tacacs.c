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

extern fr_dict_attr_t const *dict_tacacs_root;

tacacs_type_t tacacs_type(RADIUS_PACKET const * const packet)
{
	fr_dict_attr_t const *da;
	VALUE_PAIR const *vp;

	da = fr_dict_attr_by_name(NULL, "TACACS-Packet-Type");
	rad_assert(da != NULL);
	vp = fr_pair_find_by_da(packet->vps, da, TAG_ANY);
	rad_assert(vp != NULL);

	return (tacacs_type_t)vp->vp_byte;
}

char const * tacacs_lookup_packet_code(RADIUS_PACKET const * const packet)
{
	fr_dict_attr_t const *da;
	fr_dict_enum_t const *dv;
	tacacs_type_t type;

	type = tacacs_type(packet);

	da = fr_dict_attr_by_name(NULL, "TACACS-Packet-Type");
	rad_assert(da != NULL);
	dv = fr_dict_enum_by_da(NULL, da, type);
	rad_assert(dv != NULL);

	return dv->name;
}

uint32_t tacacs_session_id(RADIUS_PACKET const * const packet)
{
	fr_dict_attr_t const *da;
	VALUE_PAIR const *vp;

	da = fr_dict_attr_by_name(NULL, "TACACS-Session-Id");
	rad_assert(da != NULL);
	vp = fr_pair_find_by_da(packet->vps, da, TAG_ANY);
	rad_assert(vp != NULL);

	return vp->vp_integer;
}

static bool tacacs_ok(RADIUS_PACKET const * const packet, bool from_client)
{
	tacacs_packet_t *pkt = (tacacs_packet_t *)packet->data;
	size_t hdr_len, len;

	if (pkt->hdr.ver.major != TAC_PLUS_MAJOR_VER || pkt->hdr.ver.minor & 0xe) {	/* minor == {0,1} */
		ERROR("Unsupported version %u.%u", pkt->hdr.ver.major, pkt->hdr.ver.minor);
		return false;
	}

	hdr_len = ntohl(pkt->hdr.length);

	switch (pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		if ((from_client && pkt->hdr.seq_no % 2 != 1) || (!from_client && pkt->hdr.seq_no % 2 != 0)) {
bad_seqno:
			ERROR("Invalid sequence number %u (from_client = %s)", pkt->hdr.seq_no, from_client ? "true" : "false");
			return false;
		}
		if (pkt->hdr.seq_no == 255) {
			ERROR("client sent seq_no set to 255");
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
				ERROR("Authen START Header/Body size mismatch");
				return false;
			}
			break;
		default:
			if (from_client) {
				len = ntohs(pkt->authen.cont.user_msg_len) + ntohs(pkt->authen.cont.data_len);
				if (len + offsetof(tacacs_packet_authen_cont_hdr_t, body) != hdr_len) {
					ERROR("Authen CONTINUE Header/Body size mismatch");
					return false;
				}
			} else {
				len = ntohs(pkt->authen.reply.server_msg_len) + ntohs(pkt->authen.reply.data_len);
				if (len + offsetof(tacacs_packet_authen_reply_hdr_t, body) != hdr_len) {
					ERROR("Authen REPLY Header/Body size mismatch");
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
				ERROR("Author REQUEST Header/Body size mismatch");
				return false;
			}
		} else {
			len = pkt->author.res.server_msg_len + pkt->author.res.data_len + pkt->author.res.arg_cnt;
			for (unsigned int i = 0; i < pkt->author.res.arg_cnt; i++)
				len += pkt->author.res.body[i];
			if (len + offsetof(tacacs_packet_author_res_hdr_t, body) != hdr_len) {
				ERROR("Author RESPONSE Header/Body size mismatch");
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
				ERROR("Acct REQUEST Header/Body size mismatch");
				return false;
			}

			flags = pkt->acct.req.flags & 0xe;
			if (flags == 0x0 || flags == 0x6 || flags == 0xc || flags == 0xe) {
				/* FIXME send to client TACACS-Accounting-Status Error */
				ERROR("Acct RESPONSE invalid flags set");
				return false;
			}
		} else {
			len = pkt->acct.res.server_msg_len + pkt->acct.res.data_len;
			if (len + offsetof(tacacs_packet_acct_res_hdr_t, body) != hdr_len) {
				ERROR("Acct RESPONSE Header/Body size mismatch");
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
			ERROR("Packet is encrypted but no secret for the client is set");
			return -1;
		}
	}

	if (pkt->hdr.flags & TAC_PLUS_UNENCRYPTED_FLAG) {
		ERROR("Packet is unencrypted but a secret has been set for the client");
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
		case PW_TACACS_VERSION_MINOR:
			pkt->hdr.ver.minor = vp->vp_byte;
			break;
		case PW_TACACS_PACKET_TYPE:
			pkt->hdr.type = vp->vp_byte;
			break;
		case PW_TACACS_SEQUENCE_NUMBER:
			pkt->hdr.seq_no = vp->vp_byte;
			break;
		case PW_TACACS_SESSION_ID:
			pkt->hdr.session_id = htonl(vp->vp_integer);
			break;
		case PW_TACACS_AUTHENTICATION_STATUS:
			pkt->authen.reply.status = vp->vp_byte;
			status = vp->vp_byte;
			break;
		case PW_TACACS_AUTHENTICATION_FLAGS:
			authen_reply_flags |= vp->vp_byte;
			break;
		case PW_TACACS_AUTHORIZATION_STATUS:
			pkt->author.res.status = vp->vp_byte;
			status = vp->vp_byte;
			break;
		case PW_TACACS_ACCOUNTING_STATUS:
			pkt->acct.res.status = vp->vp_byte;
			status = vp->vp_byte;
			break;
		case PW_TACACS_SERVER_MESSAGE:
			length_body += vp->vp_length;
			field.server_msg = vp;
			break;
		case PW_TACACS_DATA:
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
			pkt->authen.reply.data_len = htons(field.server_msg->vp_length);
			break;
		case TAC_PLUS_AUTHOR:
			pkt->author.res.data_len = htons(field.server_msg->vp_length);
			break;
		case TAC_PLUS_ACCT:
			pkt->acct.res.data_len = htons(field.server_msg->vp_length);
			break;
		}
		memcpy(ptr, field.data->vp_octets, field.data->vp_length);
		ptr += field.data->vp_length;
	}
skip_fields:

	return 0;
}

static int pair_make(VALUE_PAIR **vp, RADIUS_PACKET *packet, char const *name)
{
	char buffer[256];

	*vp = fr_pair_make(packet, NULL, name, NULL, T_OP_EQ);
	if (!*vp) {
		strlcpy(buffer, fr_strerror(), sizeof(buffer));
		fr_strerror_printf("Cannot decode packet due to internal error: %s", buffer);
		return -1;
	}

	return 0;
}

int tacacs_decode(RADIUS_PACKET * const packet)
{
	tacacs_packet_t *pkt = (tacacs_packet_t *)packet->data;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	uint8_t *p;
	VALUE_PAIR *data = NULL;
	uint32_t session_id;

	fr_pair_cursor_init(&cursor, &packet->vps);

	if (pair_make(&vp, packet, "TACACS-Version-Minor") < 0)
		return -1;
	vp->vp_byte = pkt->hdr.ver.minor;
	fr_pair_cursor_append(&cursor, vp);

	if (pair_make(&vp, packet, "TACACS-Packet-Type") < 0)
		return -1;
	vp->vp_byte = pkt->hdr.type;
	fr_pair_cursor_append(&cursor, vp);

	packet->code = pkt->hdr.type;

	if (pair_make(&vp, packet, "TACACS-Sequence-Number") < 0)
		return -1;
	vp->vp_byte = pkt->hdr.seq_no;
	fr_pair_cursor_append(&cursor, vp);

	if (pair_make(&vp, packet, "TACACS-Session-Id") < 0)
		return -1;
	vp->vp_integer = ntohl(pkt->hdr.session_id);
	fr_pair_cursor_append(&cursor, vp);
	session_id = vp->vp_integer;

	switch ((tacacs_type_t)pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		switch (pkt->hdr.seq_no) {
		case 1:
			p = pkt->authen.start.body;

			if (pair_make(&vp, packet, "TACACS-Action") < 0)
				return -1;
			vp->vp_byte = pkt->authen.start.action;
			fr_pair_cursor_append(&cursor, vp);

			if (pair_make(&vp, packet, "TACACS-Privilege-Level") < 0)
				return -1;
			vp->vp_byte = pkt->authen.start.priv_lvl;
			fr_pair_cursor_append(&cursor, vp);

			if (pair_make(&vp, packet, "TACACS-Authentication-Type") < 0)
				return -1;
			vp->vp_byte = pkt->authen.start.authen_type;
			fr_pair_cursor_append(&cursor, vp);

			if (pair_make(&vp, packet, "TACACS-Authentication-Service") < 0)
				return -1;
			vp->vp_byte = pkt->authen.start.authen_service;
			fr_pair_cursor_append(&cursor, vp);

			if (pkt->authen.start.user_len) {
				if (pair_make(&vp, packet, "TACACS-User-Name") < 0)
					return -1;
				fr_pair_value_bstrncpy(vp, p, pkt->authen.start.user_len);
				p += vp->vp_length;
				fr_pair_cursor_append(&cursor, vp);
			}

			if (pkt->authen.start.port_len) {
				if (pair_make(&vp, packet, "TACACS-Client-Port") < 0)
					return -1;
				fr_pair_value_bstrncpy(vp, p, pkt->authen.start.port_len);
				p += vp->vp_length;
				fr_pair_cursor_append(&cursor, vp);
			}

			if (pkt->authen.start.rem_addr_len) {
				if (pair_make(&vp, packet, "TACACS-Remote-Address") < 0)
					return -1;
				fr_pair_value_bstrncpy(vp, p, pkt->authen.start.rem_addr_len);
				p += vp->vp_length;
				fr_pair_cursor_append(&cursor, vp);
			}

			if (pkt->authen.start.data_len) {
				if (pair_make(&vp, packet, "TACACS-Data") < 0)
					return -1;
				fr_pair_value_bstrncpy(vp, p, pkt->authen.start.data_len);
				p += vp->vp_length;
				fr_pair_cursor_append(&cursor, vp);
			}

			break;
		default:
			p = pkt->authen.cont.body;

			if (pkt->authen.cont.user_msg_len) {
				if (pair_make(&vp, packet, "TACACS-User-Message") < 0)
					return -1;
				fr_pair_value_bstrncpy(vp, p, ntohs(pkt->authen.cont.user_msg_len));
				p += vp->vp_length;
				fr_pair_cursor_append(&cursor, vp);
			}

			if (pkt->authen.cont.data_len) {
				if (pair_make(&vp, packet, "TACACS-Data") < 0)
					return -1;
				fr_pair_value_bstrncpy(vp, p, ntohs(pkt->authen.cont.data_len));
				p += vp->vp_length;
				fr_pair_cursor_append(&cursor, vp);

				data = vp;
			}

			if (pkt->authen.cont.flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
				WARN("Client aborted authentication session %u: %s", session_id, data ? data->vp_strvalue : NULL);
				return -2;
			}
		}
		break;
	case TAC_PLUS_AUTHOR:
		p = pkt->author.req.body;
		p += pkt->author.req.arg_cnt;

		if (pair_make(&vp, packet, "TACACS-Authentication-Method") < 0)
			return -1;
		vp->vp_byte = pkt->author.req.authen_method;
		fr_pair_cursor_append(&cursor, vp);

		if (pair_make(&vp, packet, "TACACS-Privilege-Level") < 0)
			return -1;
		vp->vp_byte = pkt->author.req.priv_lvl;
		fr_pair_cursor_append(&cursor, vp);

		if (pair_make(&vp, packet, "TACACS-Authentication-Type") < 0)
			return -1;
		vp->vp_byte = pkt->author.req.authen_type;
		fr_pair_cursor_append(&cursor, vp);

		if (pair_make(&vp, packet, "TACACS-Authentication-Service") < 0)
			return -1;
		vp->vp_byte = pkt->author.req.authen_service;
		fr_pair_cursor_append(&cursor, vp);

		if (pkt->author.req.user_len) {
			if (pair_make(&vp, packet, "TACACS-User-Name") < 0)
				return -1;
			fr_pair_value_bstrncpy(vp, p, pkt->author.req.user_len);
			p += vp->vp_length;
			fr_pair_cursor_append(&cursor, vp);
		}

		if (pkt->author.req.port_len) {
			if (pair_make(&vp, packet, "TACACS-Client-Port") < 0)
				return -1;
			fr_pair_value_bstrncpy(vp, p, pkt->author.req.port_len);
			p += vp->vp_length;
			fr_pair_cursor_append(&cursor, vp);
		}

		if (pkt->author.req.rem_addr_len) {
			if (pair_make(&vp, packet, "TACACS-Remote-Address") < 0)
				return -1;
			fr_pair_value_bstrncpy(vp, p, pkt->author.req.rem_addr_len);
			p += vp->vp_length;
			fr_pair_cursor_append(&cursor, vp);
		}

		/* FIXME support arg */

		break;
	case TAC_PLUS_ACCT:
		p = pkt->acct.req.body;
		p += pkt->acct.req.arg_cnt;

		if (pkt->acct.req.flags & TAC_PLUS_ACCT_FLAG_START) {
			if (pair_make(&vp, packet, "TACACS-Accounting-Flags") < 0)
				return -1;
			vp->vp_byte = TAC_PLUS_ACCT_FLAG_START;
			fr_pair_cursor_append(&cursor, vp);
		}
		if (pkt->acct.req.flags & TAC_PLUS_ACCT_FLAG_STOP) {
			if (pair_make(&vp, packet, "TACACS-Accounting-Flags") < 0)
				return -1;
			vp->vp_byte = TAC_PLUS_ACCT_FLAG_STOP;
			fr_pair_cursor_append(&cursor, vp);
		}
		if (pkt->acct.req.flags & TAC_PLUS_ACCT_FLAG_WATCHDOG) {
			if (pair_make(&vp, packet, "TACACS-Accounting-Flags") < 0)
				return -1;
			vp->vp_byte = TAC_PLUS_ACCT_FLAG_WATCHDOG;
			fr_pair_cursor_append(&cursor, vp);
		}

		if (pair_make(&vp, packet, "TACACS-Authentication-Method") < 0)
			return -1;
		vp->vp_byte = pkt->acct.req.authen_method;
		fr_pair_cursor_append(&cursor, vp);

		if (pair_make(&vp, packet, "TACACS-Privilege-Level") < 0)
			return -1;
		vp->vp_byte = pkt->acct.req.priv_lvl;
		fr_pair_cursor_append(&cursor, vp);

		if (pair_make(&vp, packet, "TACACS-Authentication-Type") < 0)
			return -1;
		vp->vp_byte = pkt->acct.req.authen_type;
		fr_pair_cursor_append(&cursor, vp);

		if (pair_make(&vp, packet, "TACACS-Authentication-Service") < 0)
			return -1;
		vp->vp_byte = pkt->acct.req.authen_service;
		fr_pair_cursor_append(&cursor, vp);

		if (pkt->acct.req.user_len) {
			if (pair_make(&vp, packet, "TACACS-User-Name") < 0)
				return -1;
			fr_pair_value_bstrncpy(vp, p, pkt->acct.req.user_len);
			p += vp->vp_length;
			fr_pair_cursor_append(&cursor, vp);
		}

		if (pkt->acct.req.port_len) {
			if (pair_make(&vp, packet, "TACACS-Client-Port") < 0)
				return -1;
			fr_pair_value_bstrncpy(vp, p, pkt->acct.req.port_len);
			p += vp->vp_length;
			fr_pair_cursor_append(&cursor, vp);
		}

		if (pkt->acct.req.rem_addr_len) {
			if (pair_make(&vp, packet, "TACACS-Remote-Address") < 0)
				return -1;
			fr_pair_value_bstrncpy(vp, p, pkt->acct.req.rem_addr_len);
			p += vp->vp_length;
			fr_pair_cursor_append(&cursor, vp);
		}

		/* FIXME support arg */

		break;
	default:
		ERROR("Unsupported TACACS+ type %u", pkt->hdr.type);
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
		int packet_len;

		/* borrow vector to bring in the header for later talloc */
		rad_assert(sizeof(tacacs_packet_hdr_t) <= AUTH_VECTOR_LEN);

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

		hdr = (tacacs_packet_hdr_t *)packet->vector;
		packet_len = sizeof(tacacs_packet_hdr_t) + ntohl(hdr->length);

		/*
		 *	If the packet is too big, then the socket is bad.
		 */
		if (packet_len > TACACS_MAX_PACKET_SIZE) {
			fr_strerror_printf("Discarding packet: Larger than limitation of " STRINGIFY(MAX_PACKET_LEN) " bytes");
			return -1;
		}

		packet->data = talloc_array(packet, uint8_t, packet_len);
		if (!packet->data) {
			fr_strerror_printf("Out of memory");
			return -1;
		}

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
		fr_strerror_printf("Failed validation of TACACS request (incorrect secret?)");
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
				  &packet->src_ipaddr.ipaddr,
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
	fr_dict_attr_t const	*da;
	VALUE_PAIR 		*vp;

	da = fr_dict_attr_by_name(NULL, "TACACS-Version-Minor");
	rad_assert(da != NULL);
	vp = fr_pair_find_by_da(original->vps, da, TAG_ANY);
	rad_assert(vp != NULL);
	vminor = vp->vp_byte;

	vp = fr_pair_afrom_da(packet, da);
	if (!vp)
		return -1;
	vp->vp_byte = vminor;
	fr_pair_add(&packet->vps, vp);

	type = tacacs_type(original);

	if (pair_make(&vp, packet, "TACACS-Packet-Type") < 0)
		return -1;
	vp->vp_byte = type;
	fr_pair_add(&packet->vps, vp);

	da = fr_dict_attr_by_name(NULL, "TACACS-Sequence-Number");
	rad_assert(da != NULL);
	vp = fr_pair_find_by_da(original->vps, da, TAG_ANY);
	rad_assert(vp != NULL);
	seq_no = vp->vp_byte + 1;	/* we catch client 255 on ingress */

	vp = fr_pair_afrom_da(packet, da);
	if (!vp)
		return -1;
	vp->vp_byte = seq_no;
	fr_pair_add(&packet->vps, vp);

	if (pair_make(&vp, packet, "TACACS-Session-Id") < 0)
		return -1;
	vp->vp_integer = tacacs_session_id(original);
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

	return write(packet->sockfd, packet->data, packet->data_len);
}
