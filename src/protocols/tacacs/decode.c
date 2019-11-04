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
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/protocol/tacacs/dictionary.h>

#include "tacacs.h"
#include "attrs.h"

static int tacacs_decode_field(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *da,
			       char const *field_name, uint8_t **field_data, size_t field_len, size_t *remaining)
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

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_printf("Out of Memory");
		return -1;
	}

	fr_pair_value_bstrncpy(vp, p, field_len);
	p += field_len;
	*remaining -= field_len;
	fr_cursor_append(cursor, vp);

	*field_data = p;

	return 0;
}

int fr_tacacs_packet_decode(RADIUS_PACKET * const packet)
{
	int i;
	fr_tacacs_packet_t *pkt;
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	uint8_t *p;
	uint32_t session_id;
	size_t remaining;

	fr_cursor_init(&cursor, &packet->vps);

	/*
	 *	There MUST be at least a TACACS packert header, and
	 *	packet->data_len == sizeof(pkt) + htonl(pkt->length),
	 *	which is enforced in fr_tacacs_packet_recv().
	 */
	pkt = (fr_tacacs_packet_t *)packet->data;

	remaining = ntohl(pkt->hdr.length);

	vp = fr_pair_afrom_da(packet, attr_tacacs_version_minor);
	if (!vp) {
	oom:
		fr_strerror_printf("Out of Memory");
		return -1;
	}
	vp->vp_uint8 = pkt->hdr.ver.minor;
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_da(packet, attr_tacacs_packet_type);
	if (!vp) goto oom;
	vp->vp_uint8 = pkt->hdr.type;
	fr_cursor_append(&cursor, vp);

	packet->code = pkt->hdr.type;

	vp = fr_pair_afrom_da(packet, attr_tacacs_sequence_number);
	if (!vp) goto oom;
	vp->vp_uint8 = pkt->hdr.seq_no;
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_da(packet, attr_tacacs_session_id);
	if (!vp) goto oom;
	vp->vp_uint32 = ntohl(pkt->hdr.session_id);
	fr_cursor_append(&cursor, vp);
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
			vp = fr_pair_afrom_da(packet, attr_tacacs_action);
			if (!vp) goto oom;
			vp->vp_uint8 = pkt->authen.start.action;
			fr_cursor_append(&cursor, vp);

			vp = fr_pair_afrom_da(packet, attr_tacacs_privilege_level);
			if (!vp) goto oom;
			vp->vp_uint8 = pkt->authen.start.priv_lvl;
			fr_cursor_append(&cursor, vp);

			vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_type);
			if (!vp) goto oom;
			vp->vp_uint8 = pkt->authen.start.authen_type;
			fr_cursor_append(&cursor, vp);

			vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_service);
			if (!vp) goto oom;
			vp->vp_uint8 = pkt->authen.start.authen_service;
			fr_cursor_append(&cursor, vp);

			/*
			 *	Decode 4 fields, based on their "length"
			 */
			p = pkt->authen.start.body;

			if (tacacs_decode_field(packet, &cursor, attr_tacacs_user_name, "User",
						&p, pkt->authen.start.user_len, &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, attr_tacacs_client_port, "Port",
						&p, pkt->authen.start.port_len, &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, attr_tacacs_remote_address, "Remote address",
						&p, pkt->authen.start.rem_addr_len, &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, attr_tacacs_data, "Data",
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

			if (tacacs_decode_field(packet, &cursor, attr_tacacs_user_message, "User message",
						&p, ntohs(pkt->authen.cont.user_msg_len), &remaining) < 0) {
				return -1;
			}

			if (tacacs_decode_field(packet, &cursor, attr_tacacs_data, "Data",
						&p, ntohs(pkt->authen.cont.data_len), &remaining) < 0) {
				return -1;
			}

			/*
			 *	Look at the abort flag after decoding the fields.
			 */
			if (pkt->authen.cont.flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
				if (!ntohs(pkt->authen.cont.data_len) ||
				    !(vp = fr_cursor_tail(&cursor))) {
					fr_strerror_printf("Client aborted authentication session %u "
							   "with no message", session_id);
					return -2;
				}

				if (ntohs(pkt->authen.cont.data_len) > 128) {
					fr_strerror_printf("Client aborted authentication session %u "
							   "with too long message", session_id);
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
		vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_method);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->author.req.authen_method;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_privilege_level);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->author.req.priv_lvl;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_type);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->author.req.authen_type;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_service);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->author.req.authen_service;
		fr_cursor_append(&cursor, vp);

		/*
		 *	Decode 3 fields, based on their "length"
		 */
		if (tacacs_decode_field(packet, &cursor, attr_tacacs_user_name, "User",
					&p, pkt->author.req.user_len, &remaining) < 0) {
			return -1;
		}

		if (tacacs_decode_field(packet, &cursor, attr_tacacs_client_port, "Port",
					&p, pkt->authen.start.port_len, &remaining) < 0) {
			return -1;
		}

		if (tacacs_decode_field(packet, &cursor, attr_tacacs_remote_address, "Remote address",
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
		vp = fr_pair_afrom_da(packet, attr_tacacs_accounting_flags);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->acct.req.flags;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_method);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->acct.req.authen_method;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_privilege_level);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->acct.req.priv_lvl;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_type);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->acct.req.authen_type;
		fr_cursor_append(&cursor, vp);

		vp = fr_pair_afrom_da(packet, attr_tacacs_authentication_service);
		if (!vp) goto oom;
		vp->vp_uint8 = pkt->acct.req.authen_service;
		fr_cursor_append(&cursor, vp);

		/*
		 *	Decode 3 fields, based on their "length"
		 */
		if (tacacs_decode_field(packet, &cursor, attr_tacacs_user_name, "User",
					&p, pkt->acct.req.user_len, &remaining) < 0) return -1;

		if (tacacs_decode_field(packet, &cursor, attr_tacacs_client_port, "Port",
					&p, pkt->acct.req.port_len, &remaining) < 0) return -1;

		if (tacacs_decode_field(packet, &cursor, attr_tacacs_remote_address, "Remote address",
					&p, pkt->acct.req.rem_addr_len, &remaining) < 0) return -1;

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
