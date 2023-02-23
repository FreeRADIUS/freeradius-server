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
 * @copyright 2017 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/struct.h>

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
fr_dict_attr_t const *attr_tacacs_version_major;
fr_dict_attr_t const *attr_tacacs_version_minor;

fr_dict_attr_t const *attr_tacacs_user_name;
fr_dict_attr_t const *attr_tacacs_user_password;
fr_dict_attr_t const *attr_tacacs_chap_password;
fr_dict_attr_t const *attr_tacacs_chap_challenge;
fr_dict_attr_t const *attr_tacacs_mschap_response;
fr_dict_attr_t const *attr_tacacs_mschap2_response;
fr_dict_attr_t const *attr_tacacs_mschap_challenge;

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
	{ .out = &attr_tacacs_argument_list, .name = "Argument-List", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
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

	{ .out = &attr_tacacs_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_mschap_response, .name = "MS-CHAP-Response", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_mschap2_response, .name = "MS-CHAP2-Response", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_mschap_challenge, .name = "MS-CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ NULL }
};

char const *fr_tacacs_packet_names[FR_TACACS_CODE_MAX] = {
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_START]		= "Authentication-Start",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_PASS]		= "Authentication-Pass",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_FAIL]		= "Authentication-Fail",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETDATA]		= "Authentication-GetData",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETUSER]		= "Authentication-GetUser",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETPASS]		= "Authentication-GetPass",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_RESTART]		= "Authentication-Restart",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_ERROR]		= "Authentication-Error",

	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE]		= "Authentication-Continue",
	[FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE_ABORT]	= "Authentication-Continue-Abort",

	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST]		= "Authorization-Request",
	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_ADD]		= "Authorization-Pass-Add",
	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_REPLACE]	= "Authorization-Pass-Replace",
	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_FAIL]		= "Authorization-Fail",
	[FR_PACKET_TYPE_VALUE_AUTHORIZATION_ERROR]		= "Authorization-Error",

	[FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST]		= "Accounting-Request",
	[FR_PACKET_TYPE_VALUE_ACCOUNTING_SUCCESS]		= "Accounting-Success",
	[FR_PACKET_TYPE_VALUE_ACCOUNTING_ERROR]			= "Accounting-Error",
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

/** XOR the body based on the secret key.
 *
 *  This function encrypts (or decrypts) TACACS+ packets, and sets the "encrypted" flag.
 */
int fr_tacacs_body_xor(fr_tacacs_packet_t const *pkt, uint8_t *body, size_t body_len, char const *secret, size_t secret_len)
{
	uint8_t pad[MD5_DIGEST_LENGTH];
	uint8_t *buf, *end;
	int pad_offset;

	/*
	 *	Do some basic sanity checks.
	 */
	if (!secret_len) {
		fr_strerror_const("Failed to encrypt/decrept the packet, as the secret has zero length.");
		return -1;
	}

	pad_offset = sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version) + sizeof(pkt->hdr.seq_no);

	/* MD5_1 = MD5{session_id, key, version, seq_no} */
	/* MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1} */
	buf = talloc_array(NULL, uint8_t, pad_offset + MD5_DIGEST_LENGTH);
	if (!buf) return -1;

	memcpy(&buf[0], &pkt->hdr.session_id, sizeof(pkt->hdr.session_id));
	memcpy(&buf[sizeof(pkt->hdr.session_id)], secret, secret_len);
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len], &pkt->hdr.version, sizeof(pkt->hdr.version));
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version)], &pkt->hdr.seq_no, sizeof(pkt->hdr.seq_no));

	fr_md5_calc(pad, buf, pad_offset);

	end = body + body_len;
	while (body < end) {
		size_t i;

		for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
			*body ^= pad[i];

			if (++body == end) goto done;
		}

		memcpy(&buf[pad_offset], pad, MD5_DIGEST_LENGTH);
		fr_md5_calc(pad, buf, pad_offset + MD5_DIGEST_LENGTH);
	}

done:
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
		fr_strerror_const("Packet is too large.  Our limit is 64K");
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
			want = sizeof(pkt->hdr) + sizeof(pkt->authen_start);

		} else if (packet_is_authen_continue(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->authen_cont);

		} else {
			fr_assert(packet_is_authen_reply(pkt));
			want = sizeof(pkt->hdr) + sizeof(pkt->authen_reply);
		}
		break;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->author_req);
		} else {
			fr_assert(packet_is_author_reply(pkt));
			want = sizeof(pkt->hdr) + sizeof(pkt->author_reply);
		}
		break;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(pkt)) {
			want = sizeof(pkt->hdr) + sizeof(pkt->acct_req);
		} else {
			fr_assert(packet_is_acct_reply(pkt));
			want = sizeof(pkt->hdr) + sizeof(pkt->acct_reply);
		}
		break;
	}

	if (want > length) {
		fr_strerror_printf("Packet is too small.  Want %zu, got %zu", want, length);
		return -1;
	}

	return length;
}

static void print_hex(fr_log_t const *log, char const *file, int line, char const *prefix, uint8_t const *data, size_t datalen, uint8_t const *end)
{
	if ((data + datalen) > end) {
		fr_assert(data <= end);

		if (data > end) return;

		fr_log(log, L_DBG, file, line, "%s TRUNCATED field says %zu, but only %zu left in the packet",
		       prefix, datalen, end - data);

		datalen = end - data;
	}

	if (!datalen) return;

	fr_log_hex(log, L_DBG, file, line, data, datalen, "%s", prefix);
}

static void print_ascii(fr_log_t const *log, char const *file, int line, char const *prefix, uint8_t const *data, size_t datalen, uint8_t const *end)
{
	uint8_t const *p;

	fr_assert((data + datalen) <= end);

	if (!datalen) return;

	if (datalen > 80) {
	hex:
		print_hex(log, file, line, prefix, data, datalen, end);
		return;
	}

	for (p = data; p < (data + datalen); p++) {
		if ((*p < 0x20) || (*p > 0x80)) goto hex;
	}

	fr_log(log, L_DBG, file, line, "%s %.*s", prefix, (int) datalen, (char const *) data);
}

static void print_args(fr_log_t const *log, char const *file, int line, size_t arg_cnt, uint8_t const *argv, uint8_t const *start, uint8_t const *end)
{
	size_t i;
	uint8_t const *p;
	char prefix[64];

	if (argv + arg_cnt > end) {
		fr_log(log, L_DBG, file, line, "      ARG cnt overflows packet");
		return;
	}

	p = start;
	for (i = 0; i < arg_cnt; i++) {
		if (p == end) {
			fr_log(log, L_DBG, file, line, "      ARG[%zu] is at EOF", i);
			return;
		}

		if ((p + argv[i]) > end) {
			fr_log(log, L_DBG, file, line, "      ARG[%zu] overflows packet", i);
			print_hex(log, file, line, "                     ", p, end - p, end);
			return;
		}

		snprintf(prefix, sizeof(prefix), "      arg[%zu]            ", i);
		prefix[21] = '\0';

		print_ascii(log, file, line, prefix, p, argv[i], end);

		p += argv[i];
	}
}

void _fr_tacacs_packet_log_hex(fr_log_t const *log, fr_tacacs_packet_t const *packet, char const *file, int line)
{
	size_t length;
	uint8_t const *p = (uint8_t const *) packet;
	uint8_t const *hdr, *end, *args;

	/*
	 *	It has to be at least 12 bytes long.
	 */
	fr_log(log, L_DBG, file, line, "  major  %u", (p[0] & 0xf0) >> 4);
	fr_log(log, L_DBG, file, line, "  minor  %u", (p[0] & 0x0f));

	fr_log(log, L_DBG, file, line, "  type   %02x", p[1]);
	fr_log(log, L_DBG, file, line, "  seq_no %02x", p[2]);
	fr_log(log, L_DBG, file, line, "  flags  %02x", p[3]);

	fr_log(log, L_DBG, file, line, "  sessid %08x", fr_nbo_to_uint32(p + 4));
	fr_log(log, L_DBG, file, line, "  length %08x", fr_nbo_to_uint32(p + 8));

	fr_log(log, L_DBG, file, line, "  body");
	length = fr_nbo_to_uint32(p + 8);

	if ((p[3] & 0x01) == 0) {
		fr_log(log, L_DBG, file, line, "  ... encrypted ...");
		return;
	}

	if (length > 65535) {
		fr_log(log, L_DBG, file, line, "      TOO LARGE");
		return;
	}

	p += 12;
	hdr = p;
	end = hdr + length;

#define OVERFLOW8(_field, _name) do { \
	if ((p + _field) > end) { \
		fr_log(log, L_DBG, file, line, "      " STRINGIFY(_name) " overflows packet!"); \
		return; \
	} \
	p += _field; \
    } while (0)

#define OVERFLOW16(_field, _name) do { \
	if ((p + fr_nbo_to_uint16(_field)) > end) { \
		fr_log(log, L_DBG, file, line, "      " STRINGIFY(_name) " overflows packet!"); \
		return; \
	} \
	p += fr_nbo_to_uint16(_field); \
    } while (0)

#define REQUIRE(_length) do { \
	if ((end - hdr) < _length) { \
		print_hex(log, file, line, "      TRUNCATED     ", hdr, end - hdr, end); \
		return; \
	} \
    } while (0)

	switch (packet->hdr.type) {
		default:
			print_hex(log, file, line, "      data   ", p, length, end);
			return;

	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(packet)) {
			fr_log(log, L_DBG, file, line, "      authentication-start");

			REQUIRE(8);

			fr_log(log, L_DBG, file, line, "      action          %02x", hdr[0]);
			fr_log(log, L_DBG, file, line, "      priv_lvl        %02x", hdr[1]);
			fr_log(log, L_DBG, file, line, "      authen_type     %02x", hdr[2]);
			fr_log(log, L_DBG, file, line, "      authen_service  %02x", hdr[3]);
			fr_log(log, L_DBG, file, line, "      user_len        %02x", hdr[4]);
			fr_log(log, L_DBG, file, line, "      port_len        %02x", hdr[5]);
			fr_log(log, L_DBG, file, line, "      rem_addr_len    %02x", hdr[6]);
			fr_log(log, L_DBG, file, line, "      data_len        %02x", hdr[7]);
			p = hdr + 8;

			/*
			 *	Do some sanity checks on the lengths.
			 */
			OVERFLOW8(hdr[4], user_len);
			OVERFLOW8(hdr[5], port_len);
			OVERFLOW8(hdr[6], rem_addr_len);
			OVERFLOW8(hdr[7], data_len);

			p = hdr + 8;
			if (p >= end) return;

			print_ascii(log, file, line, "      user           ", p, hdr[4], end);
			p += hdr[4];

			print_ascii(log, file, line, "      port           ", p, hdr[5], end);
			p += hdr[5];

			print_ascii(log, file, line, "      rem_addr       ", p, hdr[6], end);
			p += hdr[6];

			/* coverity[tainted_data] */
			print_hex(log, file, line, "      data           ", p, hdr[7], end); /* common auth flows */

		} else if (packet_is_authen_continue(packet)) {
			fr_log(log, L_DBG, file, line, "      authentication-continue");

			REQUIRE(5);

			fr_log(log, L_DBG, file, line, "      user_msg_len    %04x", fr_nbo_to_uint16(hdr));
			fr_log(log, L_DBG, file, line, "      data_len        %04x", fr_nbo_to_uint16(hdr + 2));
			fr_log(log, L_DBG, file, line, "      flags           %02x", hdr[4]);
			p = hdr + 5;

			/*
			 *	Do some sanity checks on the lengths.
			 */
			OVERFLOW16(hdr, user_msg_len);
			OVERFLOW16(hdr + 2, data_len);

			p = hdr + 5;
			if (p >= end) return;

			print_ascii(log, file, line, "      user_msg       ", p, fr_nbo_to_uint16(hdr), end);
			p += fr_nbo_to_uint16(hdr + 2);

			print_hex(log, file, line, "      data           ", p, fr_nbo_to_uint16(hdr + 2), end);

		} else {
			fr_assert(packet_is_authen_reply(packet));

			fr_log(log, L_DBG, file, line, "      authentication-reply");

			REQUIRE(6);

			fr_log(log, L_DBG, file, line, "      status          %02x", hdr[0]);
			fr_log(log, L_DBG, file, line, "      flags           %02x", hdr[1]);
			fr_log(log, L_DBG, file, line, "      server_msg_len  %04x", fr_nbo_to_uint16(hdr + 2));
			fr_log(log, L_DBG, file, line, "      data_len        %04x", fr_nbo_to_uint16(hdr + 4));
			p = hdr + 6;

			/*
			 *	Do some sanity checks on the lengths.
			 */
			OVERFLOW16(hdr + 2, server_msg_len);
			OVERFLOW16(hdr + 4, data_len);

			p = hdr + 6;
			if (p >= end) return;

			print_ascii(log, file, line, "      server_msg     ", p, fr_nbo_to_uint16(hdr + 2), end);
			p += fr_nbo_to_uint16(hdr + 2);

			print_hex(log, file, line, "      data           ", p, fr_nbo_to_uint16(hdr + 4), end);
		}
		break;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(packet)) {
			fr_log(log, L_DBG, file, line, "      authorization-request");
			REQUIRE(8);

			fr_log(log, L_DBG, file, line, "      auth_method     %02x", hdr[0]);
			fr_log(log, L_DBG, file, line, "      priv_lvl        %02x", hdr[1]);
			fr_log(log, L_DBG, file, line, "      authen_type     %02x", hdr[2]);
			fr_log(log, L_DBG, file, line, "      authen_service  %02x", hdr[3]);
			fr_log(log, L_DBG, file, line, "      user_len        %02x", hdr[4]);
			fr_log(log, L_DBG, file, line, "      port_len        %02x", hdr[5]);
			fr_log(log, L_DBG, file, line, "      rem_addr_len    %02x", hdr[6]);
			fr_log(log, L_DBG, file, line, "      arg_cnt         %02x", hdr[7]);
			p = hdr + 8;
			args = p;

			OVERFLOW8(hdr[4], user_len);
			OVERFLOW8(hdr[5], port_len);
			OVERFLOW8(hdr[6], rem_addr_len);
			OVERFLOW8(hdr[7], arg_cnt);

			print_hex(log, file, line, "      argc           ", p, hdr[7], end);

			p = hdr + 8 + hdr[7];
			print_ascii(log, file, line, "      user           ", p, hdr[4], end);
			p += hdr[4];

			print_ascii(log, file, line, "      port           ", p, hdr[5], end);
			p += hdr[5];

			print_ascii(log, file, line, "      rem_addr       ", p, hdr[6], end);
			p += hdr[6];

			print_args(log, file, line, hdr[7], args, p, end);

		} else {
			fr_log(log, L_DBG, file, line, "      authorization-reply");

			fr_assert(packet_is_author_reply(packet));

			REQUIRE(6);

			fr_log(log, L_DBG, file, line, "      status          %02x", hdr[0]);
			fr_log(log, L_DBG, file, line, "      arg_cnt         %02x", hdr[1]);
			fr_log(log, L_DBG, file, line, "      server_msg_len  %04x", fr_nbo_to_uint16(hdr + 2));
			fr_log(log, L_DBG, file, line, "      data_len        %04x", fr_nbo_to_uint16(hdr + 4));
			p = hdr + 6;
			args = p;

			OVERFLOW8(hdr[1], arg_cnt);
			OVERFLOW16(hdr + 2, server_msg_len);
			OVERFLOW16(hdr + 4, data_len);

			print_hex(log, file, line, "      argc           ", p, hdr[1], end);

			p = hdr + 6 + hdr[1];
			print_ascii(log, file, line, "      server_msg     ", p, fr_nbo_to_uint16(hdr + 2), end);
			p += fr_nbo_to_uint16(hdr + 2);

			print_ascii(log, file, line, "      data           ", p, fr_nbo_to_uint16(hdr + 4), end);
			p += fr_nbo_to_uint16(hdr + 4);

			print_args(log, file, line, hdr[1], args, p, end);
		}
		break;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(packet)) {
			fr_log(log, L_DBG, file, line, "      accounting-request");

			REQUIRE(9);

			fr_log(log, L_DBG, file, line, "      flags           %02x", hdr[0]);
			fr_log(log, L_DBG, file, line, "      auth_method     %02x", hdr[1]);
			fr_log(log, L_DBG, file, line, "      priv_lvl        %02x", hdr[2]);
			fr_log(log, L_DBG, file, line, "      authen_type     %02x", hdr[3]);
			fr_log(log, L_DBG, file, line, "      authen_service  %02x", hdr[4]);
			fr_log(log, L_DBG, file, line, "      user_len        %02x", hdr[5]);
			fr_log(log, L_DBG, file, line, "      port_len        %02x", hdr[6]);
			fr_log(log, L_DBG, file, line, "      rem_addr_len    %02x", hdr[7]);
			fr_log(log, L_DBG, file, line, "      arg_cnt         %02x", hdr[8]);
			p = hdr + 8;
			args = p;

			OVERFLOW8(hdr[4], arg_cnt);
			OVERFLOW8(hdr[5], user_len);
			OVERFLOW8(hdr[6], port_len);
			OVERFLOW8(hdr[7], rem_addr_len);

			print_hex(log, file, line, "      argc           ", p, hdr[8], end);

			p = hdr + 8 + hdr[7];
			print_ascii(log, file, line, "      user           ", p, hdr[4], end);
			p += hdr[5];

			print_ascii(log, file, line, "      port           ", p, hdr[5], end);
			p += hdr[6];

			print_ascii(log, file, line, "      rem_addr       ", p, hdr[6], end);
			p += hdr[7];

			print_args(log, file, line, hdr[8], args, p, end);
		} else {
			fr_log(log, L_DBG, file, line, "      accounting-reply");
			fr_assert(packet_is_acct_reply(packet));

			fr_log(log, L_DBG, file, line, "      authentication-reply");

			REQUIRE(5);

			fr_log(log, L_DBG, file, line, "      server_msg_len  %04x", fr_nbo_to_uint16(hdr));
			fr_log(log, L_DBG, file, line, "      data_len        %04x", fr_nbo_to_uint16(hdr + 2));
			fr_log(log, L_DBG, file, line, "      status          %02x", hdr[0]);
			p = hdr + 5;

			/*
			 *	Do some sanity checks on the lengths.
			 */
			OVERFLOW16(hdr, server_msg_len);
			OVERFLOW16(hdr + 2, data_len);

			p = hdr + 5;
			if (p >= end) return;

			print_ascii(log, file, line, "      server_msg     ", p, fr_nbo_to_uint16(hdr), end);
			p += fr_nbo_to_uint16(hdr);

			print_hex(log, file, line, "      data           ", p, fr_nbo_to_uint16(hdr + 2), end);
		}
		break;
	}
}
