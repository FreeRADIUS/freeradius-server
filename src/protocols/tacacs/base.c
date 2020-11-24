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
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/protocol/tacacs/dictionary.h>
#include <freeradius-devel/protocol/tacacs/freeradius.internal.h>

#include "tacacs.h"
#include "attrs.h"

fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t libfreeradius_tacacs_dict[];
fr_dict_autoload_t libfreeradius_tacacs_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },

	{ NULL }
};

fr_dict_attr_t const *attr_tacacs_accounting_flags;
fr_dict_attr_t const *attr_tacacs_accounting_status;
fr_dict_attr_t const *attr_tacacs_action;
fr_dict_attr_t const *attr_tacacs_authentication_flags;
fr_dict_attr_t const *attr_tacacs_authentication_continue_flags;
fr_dict_attr_t const *attr_tacacs_authentication_method;
fr_dict_attr_t const *attr_tacacs_authentication_service;
fr_dict_attr_t const *attr_tacacs_authentication_status;
fr_dict_attr_t const *attr_tacacs_authentication_type;
fr_dict_attr_t const *attr_tacacs_authorization_status;
fr_dict_attr_t const *attr_tacacs_argument_list;
fr_dict_attr_t const *attr_tacacs_client_port;
fr_dict_attr_t const *attr_tacacs_data;
fr_dict_attr_t const *attr_tacacs_flags;
fr_dict_attr_t const *attr_tacacs_length;
fr_dict_attr_t const *attr_tacacs_packet;
fr_dict_attr_t const *attr_tacacs_packet_body_type;
fr_dict_attr_t const *attr_tacacs_packet_type;
fr_dict_attr_t const *attr_tacacs_privilege_level;
fr_dict_attr_t const *attr_tacacs_remote_address;
fr_dict_attr_t const *attr_tacacs_sequence_number;
fr_dict_attr_t const *attr_tacacs_server_message;
fr_dict_attr_t const *attr_tacacs_session_id;
fr_dict_attr_t const *attr_tacacs_user_message;
fr_dict_attr_t const *attr_tacacs_user_name;
fr_dict_attr_t const *attr_tacacs_version_major;
fr_dict_attr_t const *attr_tacacs_version_minor;

extern fr_dict_attr_autoload_t libfreeradius_tacacs_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_tacacs_dict_attr[] = {
	{ .out = &attr_tacacs_accounting_flags, .name = "Accounting-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_accounting_status, .name = "Accounting-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_action, .name = "Action", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_flags, .name = "Authentication-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_continue_flags, .name = "Authentication-Continue-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_method, .name = "Authentication-Method", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_service, .name = "Authentication-Service", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_status, .name = "Authentication-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_type, .name = "Authentication-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authorization_status, .name = "Authorization-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_argument_list, .name = "ArgumentList", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_client_port, .name = "Client-Port", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "Data", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_flags, .name = "Packet.Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_length, .name = "Packet.Length", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet, .name = "Packet", .type = FR_TYPE_STRUCT, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet_body_type, .name = "Packet-Body-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_privilege_level, .name = "Privilege-Level", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_remote_address, .name = "Remote-Address", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_sequence_number, .name = "Packet.Sequence-Number", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_session_id, .name = "Packet.Session-Id", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_message, .name = "User-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_version_major, .name = "Packet.Version-Major", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_version_minor, .name = "Packet.Version-Minor", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ NULL }
};

char const *fr_tacacs_packet_codes[] = {
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_START] = "Authentication-Start",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE] = "Authentication-Continue",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY] = "Authentication-Reply",
	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST] = "Authorization-Request",
	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_REPLY] = "Authorization-Reply",
	[FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST] = "Accounting-Request",
	[FR_PACKET_TYPE_VALUE_ACCOUNTING_REPLY] = "Accounting-Reply",
};


int fr_tacacs_init(void)
{
	if (fr_dict_autoload(libfreeradius_tacacs_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_tacacs_dict_attr) < 0) return -1;

	return 0;
}

void fr_tacacs_free(void)
{
	fr_dict_autofree(libfreeradius_tacacs_dict);
}

int fr_tacacs_body_xor(fr_tacacs_packet_t const *pkt, uint8_t *body, size_t body_len, char const *secret, size_t secret_len)
{
	uint8_t pad[MD5_DIGEST_LENGTH];
	uint8_t *buf;
	int pad_offset;

	if (!secret) {
		if (pkt->hdr.flags & FR_TAC_PLUS_UNENCRYPTED_FLAG)
			return 0;
		else {
			fr_strerror_printf("Packet is encrypted but no secret for the client is set");
			return -1;
		}
	}

	if (pkt->hdr.flags & FR_TAC_PLUS_UNENCRYPTED_FLAG) {
		fr_strerror_printf("Packet is unencrypted but a secret has been set for the client");
		return -1;
	}

	pad_offset = sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version) + sizeof(pkt->hdr.seq_no);

	/* MD5_1 = MD5{session_id, key, version, seq_no} */
	/* MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1} */
	buf = talloc_array(NULL, uint8_t, pad_offset + MD5_DIGEST_LENGTH);

	memcpy(&buf[0], &pkt->hdr.session_id, sizeof(pkt->hdr.session_id));
	memcpy(&buf[sizeof(pkt->hdr.session_id)], secret, secret_len);
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len], &pkt->hdr.version, sizeof(pkt->hdr.version));
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version)], &pkt->hdr.seq_no, sizeof(pkt->hdr.seq_no));

	fr_md5_calc(pad, buf, pad_offset);

	size_t pos = 0;
	do {
		for (size_t i = 0; i < MD5_DIGEST_LENGTH && pos < body_len; i++, pos++)
			body[pos] ^= pad[i];

		if (pos == body_len)
			break;

		memcpy(&buf[pad_offset], pad, MD5_DIGEST_LENGTH);
		fr_md5_calc(pad, buf, pad_offset + MD5_DIGEST_LENGTH);
	} while (1);

	talloc_free(buf);

	return 0;
}

/**
 *	Return how long a TACACS+ packet is
 *
 *	Note that we only look at the 12 byte packet header.  We don't
 *	(yet) do validation on authentication / authorization /
 *	accounting headers.  The packet may still be determined later
 *	to be invalid.
 *
 * @param buffer	to check
 * @param buffer_len	length of the buffer
 * @return
 *	>0		size of the TACACS+ packet.  We want.  MAY be larger than "buffer_len"
 *	<=0		error, packet should be discarded.
 */
ssize_t fr_tacacs_length(uint8_t const *buffer, size_t buffer_len)
{
	fr_tacacs_packet_t const *pkt = (fr_tacacs_packet_t const *) buffer;
	size_t length, want;

	/*
	 *	Check that we have a full TACACS+ header before
	 *	decoding anything.
	 */
	if (buffer_len < sizeof(pkt->hdr)) {
		return sizeof(pkt->hdr);
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
	 */
	if ((buffer[8] != 0) || (buffer[9] != 0)) {
		fr_strerror_printf("Packet is too large.  Our limit is 64K");
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

	length = sizeof(pkt->hdr) + ntohl(pkt->hdr.length);

	if (buffer_len < length) return length;

	/*
	 *	We want at least the headers for the various packet
	 *	types.  Note that we do NOT check the lengths in the
	 *	headers against buffer / buffer_len.  That process is
	 *	complex and error-prone.  It's best to leave it in one
	 *	place: fr_tacacs_decode().
	 */
	switch (pkt->hdr.type) {
	default:
		fr_assert(0);	/* should have been caught above */
		return -1;

	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->authen.start);

		} else if (packet_is_authen_continue(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->authen.cont);

		} else {
			fr_assert(packet_is_authen_reply(pkt));
			want = sizeof(pkt->hdr) + sizeof(pkt->authen.reply);
		}
		break;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->author.req);
		} else {
			fr_assert(packet_is_author_response(pkt));
			want = sizeof(pkt->hdr) + sizeof(pkt->author.res);
		}
		break;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->acct.req);
		} else {
			fr_assert(packet_is_acct_reply(pkt));
			want = sizeof(pkt->hdr) + sizeof(pkt->acct.reply);
		}
		break;
	}

	if (want > length) {
		fr_strerror_printf("Packet is too small.  Want %zu, got %zu", want, length);
		return -1;
	}

	return length;
}
