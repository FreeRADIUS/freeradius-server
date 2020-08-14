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
	{ .out = &attr_tacacs_accounting_flags, .name = "TACACS-Accounting-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_accounting_status, .name = "TACACS-Accounting-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_action, .name = "TACACS-Action", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_flags, .name = "TACACS-Authentication-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_continue_flags, .name = "TACACS-Authentication-Continue-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_method, .name = "TACACS-Authentication-Method", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_service, .name = "TACACS-Authentication-Service", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_status, .name = "TACACS-Authentication-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_type, .name = "TACACS-Authentication-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authorization_status, .name = "TACACS-Authorization-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_argument_list, .name = "TACACS-ArgumentList", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_client_port, .name = "TACACS-Client-Port", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "TACACS-Data", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_flags, .name = "TACACS-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_length, .name = "TACACS-Length", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet, .name = "TACACS-Packet", .type = FR_TYPE_STRUCT, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet_body_type, .name = "TACACS-Packet-Body-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet_type, .name = "TACACS-Packet-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_privilege_level, .name = "TACACS-Privilege-Level", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_remote_address, .name = "TACACS-Remote-Address", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_sequence_number, .name = "TACACS-Sequence-Number", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "TACACS-Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_session_id, .name = "TACACS-Session-Id", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_message, .name = "TACACS-User-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_name, .name = "TACACS-User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_version_major, .name = "TACACS-Version-Major", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_version_minor, .name = "TACACS-Version-Minor", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ NULL }
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

int fr_tacacs_body_xor(fr_tacacs_packet_t *pkt, uint8_t *body, size_t body_len, char const *secret, size_t secret_len)
{
	uint8_t pad[MD5_DIGEST_LENGTH];
	uint8_t *buf;
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
