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
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/tacacs/dictionary.h>

#include "tacacs.h"
#include "attrs.h"

int fr_tacacs_packet_encode(RADIUS_PACKET * const packet, char const * const secret, UNUSED size_t secret_len)
{
	uint8_t			*ptr;
	uint16_t		length_hdr;
	uint16_t		length_body;
	VALUE_PAIR const	*vp;
	fr_cursor_t		cursor;
	fr_tacacs_packet_t	*pkt;
	struct {
		VALUE_PAIR const	*server_msg;
		VALUE_PAIR const	*data;
	} field = {0};

	uint8_t			status = 0;

	tacacs_authen_reply_flags_t authen_reply_flags = TAC_PLUS_REPLY_FLAG_UNSET;

	/*
	 *	Not zero'd to catch bugs via tacacs_packet_verify()
	 */
	uint8_t data[sizeof(fr_tacacs_packet_t)];

	/*
	 *	Use memory on the stack, until we know how
	 *	large the packet will be.
	 */
	pkt = (fr_tacacs_packet_t *)data;

	pkt->hdr.ver.major = TAC_PLUS_MAJOR_VER;

	pkt->hdr.flags = (secret)
		? TAC_PLUS_ENCRYPTED_MULTIPLE_CONNECTIONS_FLAG
		: TAC_PLUS_UNENCRYPTED_FLAG;

	length_body = 0;
	for (vp = fr_cursor_init(&cursor, &packet->vps);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);

		if (!vp->da->flags.internal) continue;

		if (vp->da == attr_tacacs_version_minor) {
			pkt->hdr.ver.minor = vp->vp_uint8;
		} else if (vp->da == attr_tacacs_packet_type) {
			pkt->hdr.type = vp->vp_uint8;
		} else if (vp->da == attr_tacacs_sequence_number) {
			pkt->hdr.seq_no = vp->vp_uint8;
		} else if (vp->da == attr_tacacs_session_id) {
			pkt->hdr.session_id = htonl(vp->vp_uint32);
		} else if (vp->da == attr_tacacs_authentication_status) {
			pkt->authen.reply.status = vp->vp_uint8;
			status = vp->vp_uint8;
		} else if (vp->da == attr_tacacs_authentication_flags) {
			authen_reply_flags |= vp->vp_uint8;
		} else if (vp->da == attr_tacacs_authorization_status) {
			pkt->author.res.status = vp->vp_uint8;
			status = vp->vp_uint8;
		} else if (vp->da == attr_tacacs_accounting_status) {
			pkt->acct.res.status = vp->vp_uint8;
			status = vp->vp_uint8;
		} else if (vp->da == attr_tacacs_server_message) {
			length_body += vp->vp_length;
			field.server_msg = vp;
		} else if (vp->da == attr_tacacs_data) {
			length_body += vp->vp_length;
			field.data = vp;
		} else {
			WARN("Unhandled %s", vp->da->name);
		}
	}

	length_hdr = sizeof(fr_tacacs_packet_hdr_t);
	switch (pkt->hdr.type) {
	case TAC_PLUS_AUTHEN:
		length_hdr += offsetof(fr_tacacs_packet_authen_reply_hdr_t, body);
		pkt->authen.reply.flags = authen_reply_flags;
		pkt->authen.reply.server_msg_len = htons(0);
		pkt->authen.reply.data_len = htons(0);
		break;

	case TAC_PLUS_AUTHOR:
		length_hdr += offsetof(fr_tacacs_packet_author_res_hdr_t, body);
		pkt->author.res.arg_cnt = 0;
		pkt->author.res.server_msg_len = htons(0);
		pkt->author.res.data_len = htons(0);
		break;

	case TAC_PLUS_ACCT:
		length_hdr += offsetof(fr_tacacs_packet_acct_res_hdr_t, body);
		pkt->acct.res.server_msg_len = htons(0);
		pkt->acct.res.data_len = htons(0);
		break;

	/* unsupported type as per draft-ietf-opsawg-tacacs section 3.6 */
	default:
fail:
		length_hdr = sizeof(fr_tacacs_packet_hdr_t);
		length_body = 0;
		goto cook;
	}

	/* if status is unset then send failure to client */
	if (!status)
		goto fail;

cook:
	fr_assert(length_hdr + length_body < TACACS_MAX_PACKET_SIZE);

	pkt->hdr.length = htonl(length_hdr - sizeof(fr_tacacs_packet_hdr_t) + length_body);

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

	pkt = (fr_tacacs_packet_t *)packet->data;

	ptr = packet->data;
	ptr += length_hdr;

	if (!length_body) goto skip_fields;

	if (field.server_msg) {
		switch (pkt->hdr.type) {
		default:
			fr_strerror_printf("Invalid packet type %i", pkt->hdr.type);
			talloc_free(packet->data);
			return -1;

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
		default:
			fr_assert(0);
			break;

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
