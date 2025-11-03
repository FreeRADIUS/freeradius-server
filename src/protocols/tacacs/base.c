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

static uint32_t instance_count = 0;
static bool	instantiated = false;

fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t libfreeradius_tacacs_dict[];
fr_dict_autoload_t libfreeradius_tacacs_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },

	DICT_AUTOLOAD_TERMINATOR
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
	DICT_AUTOLOAD_TERMINATOR
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
		fr_strerror_printf("Unknown packet type %d", pkt->hdr.type);
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

static void print_hex(fr_log_t const *log, char const *file, int line, char const *prefix, uint8_t const *data, size_t datalen)
{
	if (!datalen) return;

	fr_log_hex(log, L_DBG, file, line, data, datalen, "%s", prefix);
}

static void print_ascii(fr_log_t const *log, char const *file, int line, char const *prefix, uint8_t const *data, size_t datalen)
{
	uint8_t const *p;

	if (!datalen) return;

	if (datalen > 80) {
	hex:
		print_hex(log, file, line, prefix, data, datalen);
		return;
	}

	for (p = data; p < (data + datalen); p++) {
		if ((*p < 0x20) || (*p > 0x80)) goto hex;
	}

	fr_log(log, L_DBG, file, line, "%s %.*s", prefix, (int) datalen, (char const *) data);
}

#define CHECK(_length) do { \
	size_t plen = _length; \
	if ((size_t) (end - p) < plen) { \
		fr_log_hex(log, L_DBG, file, line, p, end - p, "%s", "      TRUNCATED     "); \
		return; \
	} \
	data = p; \
	data_len = plen; \
	p += plen; \
    } while (0)

#undef ASCII
#define ASCII(_prefix, _field) do { \
	CHECK(_field); \
	print_ascii(log, file, line, _prefix, data, data_len); \
   } while (0)

#undef HEXIT
#define HEXIT(_prefix, _field) do { \
	CHECK(_field); \
	print_hex(log, file, line, _prefix, data, data_len); \
   } while (0)

#define PRINT(_fmt, ...) fr_log(log, L_DBG, file, line, _fmt, ## __VA_ARGS__)

static void print_args(fr_log_t const *log, char const *file, int line, size_t arg_cnt, uint8_t const *argv, uint8_t const *start, uint8_t const *end)
{
	size_t i, data_len;
	uint8_t const *p;
	uint8_t const *data;
	char prefix[64];

	if (argv + arg_cnt > end) {
		PRINT("      ARG cnt overflows packet");
		return;
	}

	p = start;
	for (i = 0; i < arg_cnt; i++) {
		if (p == end) {
			PRINT("      ARG[%zu] is at EOF", i);
			return;
		}

		if ((end - p) < argv[i]) {
			PRINT("      ARG[%zu] overflows packet", i);
			print_hex(log, file, line, "                     ", p, end - p);
			return;
		}

		snprintf(prefix, sizeof(prefix), "      arg[%zu]            ", i);
		prefix[21] = '\0';

		ASCII(prefix, argv[i]);
	}
}

void _fr_tacacs_packet_log_hex(fr_log_t const *log, fr_tacacs_packet_t const *packet, size_t packet_len, char const *file, int line)
{
	size_t length, data_len;
	uint8_t const *p = (uint8_t const *) packet;
	uint8_t const *hdr, *end, *args;
	uint8_t const *data;

	end = ((uint8_t const *) packet) + packet_len;

	if (packet_len < 12) {
		print_hex(log, file, line, "header ", p, packet_len);
		return;
	}

	/*
	 *	It has to be at least 12 bytes long.
	 */
	PRINT("  major  %d", (p[0] & 0xf0) >> 4);
	PRINT("  minor  %d", (p[0] & 0x0f));

	PRINT("  type   %02x", p[1]);
	PRINT("  seq_no %02x", p[2]);
	PRINT("  flags  %02x", p[3]);

	PRINT("  sessid %08x", fr_nbo_to_uint32(p + 4));
	PRINT("  length %08x", fr_nbo_to_uint32(p + 8));

	PRINT("  body");
	length = fr_nbo_to_uint32(p + 8);

	if ((p[3] & 0x01) == 0) {
		PRINT("  ... encrypted ...");
		return;
	}

	if (length > 65535) {
		PRINT("      TOO LARGE");
		return;
	}

	p += 12;
	hdr = p;

	if ((p + length) != end) {
		PRINT("length field does not match input packet length %08lx", packet_len - 12);
		return;
	}

#define REQUIRE(_length) do { \
	size_t plen = _length; \
	if ((size_t) (end - hdr) < plen) { \
		print_hex(log, file, line, "      TRUNCATED     ", hdr, end - hdr); \
		return; \
	} \
	p = hdr + plen; \
    } while (0)

	switch (packet->hdr.type) {
	default:
		print_hex(log, file, line, "      data   ", p, length);
		return;

	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(packet)) {
			PRINT("      authentication-start");

			REQUIRE(8);

			PRINT("      action          %02x", hdr[0]);
			PRINT("      priv_lvl        %02x", hdr[1]);
			PRINT("      authen_type     %02x", hdr[2]);
			PRINT("      authen_service  %02x", hdr[3]);
			PRINT("      user_len        %02x", hdr[4]);
			PRINT("      port_len        %02x", hdr[5]);
			PRINT("      rem_addr_len    %02x", hdr[6]);
			PRINT("      data_len        %02x", hdr[7]);

			ASCII("      user           ", hdr[4]);
			ASCII("      port           ", hdr[5]);
			ASCII("      rem_addr       ", hdr[6]);
			HEXIT("      data           ", hdr[7]); /* common auth flows */

		} else if (packet_is_authen_continue(packet)) {
			PRINT("      authentication-continue");

			REQUIRE(5);

			PRINT("      user_msg_len    %04x", fr_nbo_to_uint16(hdr));
			PRINT("      data_len        %04x", fr_nbo_to_uint16(hdr + 2));
			PRINT("      flags           %02x", hdr[4]);

			ASCII("      user_msg       ", fr_nbo_to_uint16(hdr));
			HEXIT("      data           ", fr_nbo_to_uint16(hdr + 2));

		} else {
			fr_assert(packet_is_authen_reply(packet));

			PRINT("      authentication-reply");

			REQUIRE(6);

			PRINT("      status          %02x", hdr[0]);
			PRINT("      flags           %02x", hdr[1]);
			PRINT("      server_msg_len  %04x", fr_nbo_to_uint16(hdr + 2));
			PRINT("      data_len        %04x", fr_nbo_to_uint16(hdr + 4));

			ASCII("      server_msg     ", fr_nbo_to_uint16(hdr + 2));
			HEXIT("      data           ", fr_nbo_to_uint16(hdr + 4));
		}

		fr_assert(p == end);
		break;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(packet)) {
			PRINT("      authorization-request");
			REQUIRE(8);

			PRINT("      auth_method     %02x", hdr[0]);
			PRINT("      priv_lvl        %02x", hdr[1]);
			PRINT("      authen_type     %02x", hdr[2]);
			PRINT("      authen_service  %02x", hdr[3]);
			PRINT("      user_len        %02x", hdr[4]);
			PRINT("      port_len        %02x", hdr[5]);
			PRINT("      rem_addr_len    %02x", hdr[6]);
			PRINT("      arg_cnt         %02x", hdr[7]);
			args = p;

			HEXIT("      argc           ", hdr[7]);
			ASCII("      user           ", hdr[4]);
			ASCII("      port           ", hdr[5]);
			ASCII("      rem_addr       ", hdr[6]);

			print_args(log, file, line, hdr[7], args, p, end);

		} else {
			PRINT("      authorization-reply");

			fr_assert(packet_is_author_reply(packet));

			REQUIRE(6);

			PRINT("      status          %02x", hdr[0]);
			PRINT("      arg_cnt         %02x", hdr[1]);
			PRINT("      server_msg_len  %04x", fr_nbo_to_uint16(hdr + 2));
			PRINT("      data_len        %04x", fr_nbo_to_uint16(hdr + 4));
			args = p;

			HEXIT("      argc           ", hdr[1]);
			ASCII("      server_msg     ", fr_nbo_to_uint16(hdr + 2));
			ASCII("      data           ", fr_nbo_to_uint16(hdr + 4));

			print_args(log, file, line, hdr[1], args, p, end);
		}
		break;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(packet)) {
			PRINT("      accounting-request");

			REQUIRE(9);

			PRINT("      flags           %02x", hdr[0]);
			PRINT("      auth_method     %02x", hdr[1]);
			PRINT("      priv_lvl        %02x", hdr[2]);
			PRINT("      authen_type     %02x", hdr[3]);
			PRINT("      authen_service  %02x", hdr[4]);
			PRINT("      user_len        %02x", hdr[5]);
			PRINT("      port_len        %02x", hdr[6]);
			PRINT("      rem_addr_len    %02x", hdr[7]);
			PRINT("      arg_cnt         %02x", hdr[8]);
			args = p;

			HEXIT("      argc           ", hdr[8]);
			ASCII("      user           ", hdr[5]);
			ASCII("      port           ", hdr[6]);
			ASCII("      rem_addr       ", hdr[7]);

			print_args(log, file, line, hdr[8], args, p, end);
		} else {
			PRINT("      accounting-reply");
			fr_assert(packet_is_acct_reply(packet));

			PRINT("      authentication-reply");

			REQUIRE(5);

			PRINT("      server_msg_len  %04x", fr_nbo_to_uint16(hdr));
			PRINT("      data_len        %04x", fr_nbo_to_uint16(hdr + 2));
			PRINT("      status          %02x", hdr[0]);

			ASCII("      server_msg     ", fr_nbo_to_uint16(hdr));
			HEXIT("      data           ", fr_nbo_to_uint16(hdr + 2));

			fr_assert(p == end);
		}
		break;
	}
}

int fr_tacacs_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(libfreeradius_tacacs_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_tacacs_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_tacacs_dict);
		goto fail;
	}

	instantiated = true;
	return 0;
}

void fr_tacacs_global_free(void)
{
	if (!instantiated) return;

	fr_assert(instance_count > 0);

	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_tacacs_dict);
	instantiated = false;
}

static bool attr_valid(fr_dict_attr_t *da)
{
	fr_dict_attr_flags_t *flags = &da->flags;

	/*
	 *	No arrays in TACACS+
	 */
	if (flags->array) {
		fr_strerror_const("Attributes with flag 'array' cannot be used in TACACS+");
		return false;
	}

	if ((strcmp(da->name, "Packet") == 0) &&
	    (da->depth == 1)) {
		if (da->type != FR_TYPE_STRUCT) {
			fr_strerror_const("The top 'Packet' attribute must of type 'struct'");
			return false;
		}

		return true;
	}

	/*
	 *	The top-level Packet is a STRUCT which contains
	 *	MEMBERs with defined values.
	 */
	if (!flags->name_only && (da->parent->type != FR_TYPE_STRUCT)) {
		fr_strerror_const("Attributes in TACACS+ cannot have assigned values.  Use DEFINE, not ATTRIBUTE");
		return false;
	}

	switch (da->type) {
	case FR_TYPE_STRUCTURAL_EXCEPT_GROUP:
	case FR_TYPE_INTERNAL:
		fr_strerror_printf("Attributes of type '%s' cannot be used in TACACS+", fr_type_to_str(da->type));
		return false;

	default:
		break;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_tacacs_dict_protocol;
fr_dict_protocol_t libfreeradius_tacacs_dict_protocol = {
	.name = "tacacs",
	.default_type_size = 4,
	.default_type_length = 4,
	.attr = {
		.valid = attr_valid,
	},

	.init = fr_tacacs_global_init,
	.free = fr_tacacs_global_free,
};
