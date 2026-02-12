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
 * @file protocols/radius/base.c
 * @brief Functions to send/receive radius packets.
 *
 * @copyright 2000-2003,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <fcntl.h>
#include <ctype.h>

#include "attrs.h"
#include "radius.h"

#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

static uint32_t instance_count = 0;
static bool	instantiated = false;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;

extern fr_dict_autoload_t libfreeradius_radius_dict[];
fr_dict_autoload_t libfreeradius_radius_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },

	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_packet_authentication_vector;
fr_dict_attr_t const *attr_chap_challenge;
fr_dict_attr_t const *attr_chargeable_user_identity;
fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_message_authenticator;
fr_dict_attr_t const *attr_state;
fr_dict_attr_t const *attr_vendor_specific;
fr_dict_attr_t const *attr_nas_filter_rule;

extern fr_dict_attr_autoload_t libfreeradius_radius_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_radius_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_packet_authentication_vector, .name = "Packet-Authentication-Vector", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chargeable_user_identity, .name = "Chargeable-User-Identity", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_VSA, .dict = &dict_radius },
	{ .out = &attr_nas_filter_rule, .name = "NAS-Filter-Rule", .type = FR_TYPE_STRING, .dict = &dict_radius },

	DICT_AUTOLOAD_TERMINATOR
};

/*
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF		if (fr_debug_lvl) fr_strerror_printf
#define FR_DEBUG_STRERROR_PRINTF_PUSH		if (fr_debug_lvl) fr_strerror_printf_push

fr_table_num_sorted_t const fr_radius_require_ma_table[] = {
	{ L("auto"),		FR_RADIUS_REQUIRE_MA_AUTO		},
	{ L("false"),		FR_RADIUS_REQUIRE_MA_NO			},
	{ L("no"),		FR_RADIUS_REQUIRE_MA_NO			},
	{ L("true"),		FR_RADIUS_REQUIRE_MA_YES		},
	{ L("yes"),		FR_RADIUS_REQUIRE_MA_YES		},
};
size_t fr_radius_require_ma_table_len = NUM_ELEMENTS(fr_radius_require_ma_table);

fr_table_num_sorted_t const fr_radius_limit_proxy_state_table[] = {
	{ L("auto"),		FR_RADIUS_LIMIT_PROXY_STATE_AUTO	},
	{ L("false"),		FR_RADIUS_LIMIT_PROXY_STATE_NO		},
	{ L("no"),		FR_RADIUS_LIMIT_PROXY_STATE_NO		},
	{ L("true"),		FR_RADIUS_LIMIT_PROXY_STATE_YES		},
	{ L("yes"),		FR_RADIUS_LIMIT_PROXY_STATE_YES		},
};
size_t fr_radius_limit_proxy_state_table_len = NUM_ELEMENTS(fr_radius_limit_proxy_state_table);

fr_table_num_sorted_t const fr_radius_request_name_table[] = {
	{ L("acct"),		FR_RADIUS_CODE_ACCOUNTING_REQUEST	},
	{ L("auth"),		FR_RADIUS_CODE_ACCESS_REQUEST		},
	{ L("auto"),		FR_RADIUS_CODE_UNDEFINED		},
	{ L("challenge"),	FR_RADIUS_CODE_ACCESS_CHALLENGE		},
	{ L("coa"),		FR_RADIUS_CODE_COA_REQUEST		},
	{ L("disconnect"),	FR_RADIUS_CODE_DISCONNECT_REQUEST	},
	{ L("status"),		FR_RADIUS_CODE_STATUS_SERVER		}
};
size_t fr_radius_request_name_table_len = NUM_ELEMENTS(fr_radius_request_name_table);

char const *fr_radius_packet_name[FR_RADIUS_CODE_MAX] = {
	"",					//!< 0
	"Access-Request",
	"Access-Accept",
	"Access-Reject",
	"Accounting-Request",
	"Accounting-Response",
	"Accounting-Status",
	"Password-Request",
	"Password-Accept",
	"Password-Reject",
	"Accounting-Message",			//!< 10
	"Access-Challenge",
	"Status-Server",
	"Status-Client",
	"14",
	"15",
	"16",
	"17",
	"18",
	"19",
	"20",					//!< 20
	"Resource-Free-Request",
	"Resource-Free-Response",
	"Resource-Query-Request",
	"Resource-Query-Response",
	"Alternate-Resource-Reclaim-Request",
	"NAS-Reboot-Request",
	"NAS-Reboot-Response",
	"28",
	"Next-Passcode",
	"New-Pin",				//!< 30
	"Terminate-Session",
	"Password-Expired",
	"Event-Request",
	"Event-Response",
	"35",
	"36",
	"37",
	"38",
	"39",
	"Disconnect-Request",			//!< 40
	"Disconnect-ACK",
	"Disconnect-NAK",
	"CoA-Request",
	"CoA-ACK",
	"CoA-NAK",
	"46",
	"47",
	"48",
	"49",
	"IP-Address-Allocate",			//!< 50
	"IP-Address-Release",
	"Protocol-Error",
};


/** If we get a reply, the request must come from one of a small
 * number of packet types.
 */
const fr_radius_packet_code_t allowed_replies[FR_RADIUS_CODE_MAX] = {
	[FR_RADIUS_CODE_ACCESS_ACCEPT]		= FR_RADIUS_CODE_ACCESS_REQUEST,
	[FR_RADIUS_CODE_ACCESS_CHALLENGE]	= FR_RADIUS_CODE_ACCESS_REQUEST,
	[FR_RADIUS_CODE_ACCESS_REJECT]		= FR_RADIUS_CODE_ACCESS_REQUEST,

	[FR_RADIUS_CODE_ACCOUNTING_RESPONSE]	= FR_RADIUS_CODE_ACCOUNTING_REQUEST,

	[FR_RADIUS_CODE_COA_ACK]		= FR_RADIUS_CODE_COA_REQUEST,
	[FR_RADIUS_CODE_COA_NAK]		= FR_RADIUS_CODE_COA_REQUEST,

	[FR_RADIUS_CODE_DISCONNECT_ACK]		= FR_RADIUS_CODE_DISCONNECT_REQUEST,
	[FR_RADIUS_CODE_DISCONNECT_NAK]		= FR_RADIUS_CODE_DISCONNECT_REQUEST,

	[FR_RADIUS_CODE_PROTOCOL_ERROR]		= FR_RADIUS_CODE_PROTOCOL_ERROR,	/* Any */
};

FR_DICT_ATTR_FLAG_FUNC(fr_radius_attr_flags_t, abinary)
FR_DICT_ATTR_FLAG_FUNC(fr_radius_attr_flags_t, concat)

static int dict_flag_encrypt(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const encrypted[] = {
		{ L("Ascend-Secret"),	RADIUS_FLAG_ENCRYPT_ASCEND_SECRET },
		{ L("Tunnel-Password"),	RADIUS_FLAG_ENCRYPT_TUNNEL_PASSWORD },
		{ L("User-Password"),	RADIUS_FLAG_ENCRYPT_USER_PASSWORD}
	};
	static size_t encrypted_len = NUM_ELEMENTS(encrypted);

	fr_radius_attr_flags_encrypt_t encrypt;
	fr_radius_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);

	encrypt = fr_table_value_by_str(encrypted, value, RADIUS_FLAG_ENCRYPT_INVALID);
	if (encrypt == RADIUS_FLAG_ENCRYPT_INVALID) {
		fr_strerror_printf("Unknown encryption type '%s'", value);
		return -1;
	}

	flags->encrypt = encrypt;

	return 0;
}

FR_DICT_ATTR_FLAG_FUNC(fr_radius_attr_flags_t, extended)
FR_DICT_ATTR_FLAG_FUNC(fr_radius_attr_flags_t, has_tag)
FR_DICT_ATTR_FLAG_FUNC(fr_radius_attr_flags_t, long_extended)

static fr_dict_flag_parser_t const radius_flags[] = {
	{ L("abinary"),			{ .func = dict_flag_abinary } },
	{ L("concat"),			{ .func = dict_flag_concat } },
	{ L("encrypt"),			{ .func = dict_flag_encrypt, .needs_value = true } },
	{ L("extended"),		{ .func = dict_flag_extended } },
	{ L("has_tag"),			{ .func = dict_flag_has_tag } },
	{ L("long_extended"),		{ .func = dict_flag_long_extended } }
};

int fr_radius_allow_reply(int code, bool allowed[static FR_RADIUS_CODE_MAX])
{
	int i;

	if ((code <= 0) || (code >= FR_RADIUS_CODE_MAX)) return -1;

	for (i = 1; i < FR_RADIUS_CODE_MAX; i++) {
		allowed[i] |= (allowed_replies[i] == (fr_radius_packet_code_t) code);
	}

	return 0;
}

/**  Do Ascend-Send / Recv-Secret calculation.
 *
 * The secret is hidden by xoring with a MD5 digest created from
 * the RADIUS shared secret and the authentication vector.
 * We put them into MD5 in the reverse order from that used when
 * encrypting passwords to RADIUS.
 */
ssize_t fr_radius_ascend_secret(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen,
				char const *secret, size_t secret_len, uint8_t const *vector)
{
	fr_md5_ctx_t		*md5_ctx;
	size_t			i;
	uint8_t			digest[MD5_DIGEST_LENGTH];
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, sizeof(digest));

	md5_ctx = fr_md5_ctx_alloc_from_list();
	fr_md5_update(md5_ctx, vector, RADIUS_AUTH_VECTOR_LENGTH);
	fr_md5_update(md5_ctx, (uint8_t const *) secret, secret_len);
	fr_md5_final(digest, md5_ctx);
	fr_md5_ctx_free_from_list(&md5_ctx);

	if (inlen > sizeof(digest)) inlen = sizeof(digest);
	for (i = 0; i < inlen; i++) digest[i] ^= in[i];

	fr_dbuff_in_memcpy(&work_dbuff, digest, sizeof(digest));

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Basic validation of RADIUS packet header
 *
 * @note fr_strerror errors are only available if fr_debug_lvl > 0. This is to reduce CPU time
 *	consumed when discarding malformed packet.
 *
 * @param[in] sockfd we're reading from.
 * @param[out] src_ipaddr of the packet.
 * @param[out] src_port of the packet.
 * @param[out] code Pointer to where to write the packet code.
 * @return
 *	- -1 on failure.
 *	- 1 on decode error.
 *	- >= RADIUS_HEADER_LENGTH on success. This is the packet length as specified in the header.
 */
ssize_t fr_radius_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t *src_port, unsigned int *code)
{
	ssize_t			data_len, packet_len;
	uint8_t			header[4];

	data_len = udp_recv_peek(sockfd, header, sizeof(header), UDP_FLAGS_PEEK, src_ipaddr, src_port);
	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EINTR)) return 0;
		return -1;
	}

	/*
	 *	Too little data is available, discard the packet.
	 */
	if (data_len < 4) {
		char buffer[INET6_ADDRSTRLEN];

		FR_DEBUG_STRERROR_PRINTF("Expected at least 4 bytes of header data, got %zd bytes", data_len);
invalid:
		FR_DEBUG_STRERROR_PRINTF_PUSH("Invalid data from %s",
					      inet_ntop(src_ipaddr->af, &src_ipaddr->addr, buffer, sizeof(buffer)));
		(void) udp_recv_discard(sockfd);

		return 0;
	}

	/*
	 *	See how long the packet says it is.
	 */
	packet_len = (header[2] * 256) + header[3];

	/*
	 *	The length in the packet says it's less than
	 *	a RADIUS header length: discard it.
	 */
	if (packet_len < RADIUS_HEADER_LENGTH) {
		FR_DEBUG_STRERROR_PRINTF("Expected at least " STRINGIFY(RADIUS_HEADER_LENGTH)  " bytes of packet "
					 "data, got %zd bytes", packet_len);
		goto invalid;
	}

	/*
	 *	Enforce RFC requirements, for sanity.
	 *	Anything after 4k will be discarded.
	 */
	if (packet_len > MAX_PACKET_LEN) {
		FR_DEBUG_STRERROR_PRINTF("Length field value too large, expected maximum of "
					 STRINGIFY(MAX_PACKET_LEN) " bytes, got %zd bytes", packet_len);
		goto invalid;
	}

	*code = header[0];

	/*
	 *	The packet says it's this long, but the actual UDP
	 *	size could still be smaller.
	 */
	return packet_len;
}

/** Sign a previously encoded packet
 *
 * Calculates the request/response authenticator for packets which need it, and fills
 * in the message-authenticator value if the attribute is present in the encoded packet.
 *
 * @param[in,out] packet	(request or response).
 * @param[in] vector		original packet vector to use
 * @param[in] secret		to sign the packet with.
 * @param[in] secret_len	The length of the secret.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_sign(uint8_t *packet, uint8_t const *vector,
		   uint8_t const *secret, size_t secret_len)
{
	uint8_t		*msg, *end;
	size_t		packet_len = fr_nbo_to_uint16(packet + 2);

	/*
	 *	No real limit on secret length, this is just
	 *	to catch uninitialised fields.
	 */
	if (!fr_cond_assert(secret_len <= UINT16_MAX)) {
		fr_strerror_printf("Secret is too long.  Expected <= %u, got %zu",
				   (unsigned int) UINT16_MAX, secret_len);
		return -1;
	}

	if (packet_len < RADIUS_HEADER_LENGTH) {
		fr_strerror_const("Packet must be encoded before calling fr_radius_sign()");
		return -1;
	}

	/*
	 *	Find Message-Authenticator.  Its value has to be
	 *	calculated before we calculate the Request
	 *	Authenticator or the Response Authenticator.
	 */
	msg = packet + RADIUS_HEADER_LENGTH;
	end = packet + packet_len;

	while (msg < end) {
		if ((end - msg) < 2) goto invalid_attribute;

		if (msg[0] != FR_MESSAGE_AUTHENTICATOR) {
			if (msg[1] < 2) goto invalid_attribute;

			if ((msg + msg[1]) > end) {
			invalid_attribute:
				fr_strerror_printf("Invalid attribute at offset %zd", msg - packet);
				return -1;
			}
			msg += msg[1];
			continue;
		}

		if (msg[1] < 18) {
			fr_strerror_const("Message-Authenticator is too small");
			return -1;
		}

		switch (packet[0]) {
		case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
		case FR_RADIUS_CODE_DISCONNECT_REQUEST:
		case FR_RADIUS_CODE_COA_REQUEST:
			memset(packet + 4, 0, RADIUS_AUTH_VECTOR_LENGTH);
			break;

		case FR_RADIUS_CODE_ACCESS_ACCEPT:
		case FR_RADIUS_CODE_ACCESS_REJECT:
		case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
		case FR_RADIUS_CODE_DISCONNECT_ACK:
		case FR_RADIUS_CODE_DISCONNECT_NAK:
		case FR_RADIUS_CODE_COA_ACK:
		case FR_RADIUS_CODE_COA_NAK:
		case FR_RADIUS_CODE_PROTOCOL_ERROR:
			if (!vector) goto need_original;
			memcpy(packet + 4, vector, RADIUS_AUTH_VECTOR_LENGTH);
			break;

		case FR_RADIUS_CODE_ACCESS_REQUEST:
		case FR_RADIUS_CODE_STATUS_SERVER:
			/* packet + 4 MUST be the Request Authenticator filled with random data */
			break;

		default:
			goto bad_packet;
		}

		/*
		 *	Force Message-Authenticator to be zero,
		 *	calculate the HMAC, and put it into the
		 *	Message-Authenticator attribute.
		 */
		memset(msg + 2, 0, RADIUS_AUTH_VECTOR_LENGTH);
		fr_hmac_md5(msg + 2, packet, packet_len, secret, secret_len);
		break;
	}

	/*
	 *	Initialize the request authenticator.
	 */
	switch (packet[0]) {
	case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
	case FR_RADIUS_CODE_DISCONNECT_REQUEST:
	case FR_RADIUS_CODE_COA_REQUEST:
		memset(packet + 4, 0, RADIUS_AUTH_VECTOR_LENGTH);
		break;

	case FR_RADIUS_CODE_ACCESS_ACCEPT:
	case FR_RADIUS_CODE_ACCESS_REJECT:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
	case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
	case FR_RADIUS_CODE_DISCONNECT_ACK:
	case FR_RADIUS_CODE_DISCONNECT_NAK:
	case FR_RADIUS_CODE_COA_ACK:
	case FR_RADIUS_CODE_COA_NAK:
	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		if (!vector) {
		need_original:
			fr_strerror_const("Cannot sign response packet without a request packet");
			return -1;
		}
		memcpy(packet + 4, vector, RADIUS_AUTH_VECTOR_LENGTH);
		break;

		/*
		 *	The Request Authenticator is random numbers.
		 *	We don't need to sign anything else, so
		 *	return.
		 */
	case FR_RADIUS_CODE_ACCESS_REQUEST:
	case FR_RADIUS_CODE_STATUS_SERVER:
		return 0;

	default:
	bad_packet:
		fr_strerror_printf("Cannot sign unknown packet code %u", packet[0]);
		return -1;
	}

	/*
	 *	Request / Response Authenticator = MD5(packet + secret)
	 */
	{
		fr_md5_ctx_t	*md5_ctx;

		md5_ctx = fr_md5_ctx_alloc_from_list();
		fr_md5_update(md5_ctx, packet, packet_len);
		fr_md5_update(md5_ctx, secret, secret_len);
		fr_md5_final(packet + 4, md5_ctx);
		fr_md5_ctx_free_from_list(&md5_ctx);
	}

	return 0;
}

char const *fr_radius_decode_fail_reason[FR_RADIUS_FAIL_MAX + 1] = {
	[FR_RADIUS_FAIL_NONE] = "none",
	[FR_RADIUS_FAIL_MIN_LENGTH_PACKET] = "packet is smaller than the minimum packet length",
	[FR_RADIUS_FAIL_MAX_LENGTH_PACKET] = "packet is larger than the maximum packet length",
	[FR_RADIUS_FAIL_MIN_LENGTH_FIELD] = "header 'length' field has a value smaller than the minimum packet length",
	[FR_RADIUS_FAIL_MIN_LENGTH_MISMATCH] = "header 'length' field has a value larger than the received data",
	[FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE] = "unknown packet code",
	[FR_RADIUS_FAIL_UNEXPECTED_REQUEST_CODE] = "unexpected request code",
	[FR_RADIUS_FAIL_UNEXPECTED_RESPONSE_CODE] = "unexpected response code",
	[FR_RADIUS_FAIL_TOO_MANY_ATTRIBUTES] = "packet contains too many attributes",

	[FR_RADIUS_FAIL_INVALID_ATTRIBUTE] = "attribute number 0 is invalid",

	[FR_RADIUS_FAIL_HEADER_OVERFLOW] = "attribute header overflows the packet",
	[FR_RADIUS_FAIL_ATTRIBUTE_TOO_SHORT] = "attribute 'length' field contains invalid value",
	[FR_RADIUS_FAIL_ATTRIBUTE_OVERFLOW] = "attribute 'length' field overflows the packet",
	[FR_RADIUS_FAIL_ATTRIBUTE_DECODE] = "unable to decode attributes",

	[FR_RADIUS_FAIL_MA_INVALID_LENGTH] = "Message-Authenticate has invalid length",
	[FR_RADIUS_FAIL_MA_MISSING] = "Message-Authenticator is required for this packet, but it is missing",
	[FR_RADIUS_FAIL_MA_INVALID] = "Message-Authenticator fails verification. shared secret is incorrect",
	[FR_RADIUS_FAIL_PROXY_STATE_MISSING] = "Proxy-State is required for this request, but it is missing",

	[FR_RADIUS_FAIL_VERIFY] = "packet fails verification, shared secret is incorrect",
	[FR_RADIUS_FAIL_NO_MATCHING_REQUEST] = "did not find request which matched response",
	[FR_RADIUS_FAIL_IO_ERROR] = "IO error",
	[FR_RADIUS_FAIL_MAX] = "???",
};

/** See if the data pointed to by PTR is a valid RADIUS packet.
 *
 * @param[in] packet		to check.
 * @param[in,out] packet_len_p	The size of the packet data.
 * @param[in] max_attributes	to allow in the packet.
 * @param[in] require_message_authenticator	whether we require Message-Authenticator.
 * @param[in] reason		if not NULL, will have the failure reason written to where it points.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_radius_ok(uint8_t const *packet, size_t *packet_len_p,
		  uint32_t max_attributes, bool require_message_authenticator, fr_radius_decode_fail_t *reason)
{
	uint8_t	const		*attr, *end;
	size_t			totallen;
	bool			seen_ma = false;
	uint32_t		num_attributes;
	fr_radius_decode_fail_t failure = FR_RADIUS_FAIL_NONE;
	size_t			packet_len = *packet_len_p;

	/*
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (packet_len < RADIUS_HEADER_LENGTH) {
		failure = FR_RADIUS_FAIL_MIN_LENGTH_PACKET;
		goto finish;
	}


	/*
	 *	Check for packets with mismatched size.
	 *	i.e. We've received 128 bytes, and the packet header
	 *	says it's 256 bytes long.
	 */
	totallen = fr_nbo_to_uint16(packet + 2);

	/*
	 *	Code of 0 is not understood.
	 *	Code of 16 or greater is not understood.
	 */
	if ((packet[0] == 0) ||
	    (packet[0] >= FR_RADIUS_CODE_MAX)) {
		failure = FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE;
		goto finish;
	}

	switch (packet[0]) {
		/*
		 *	Message-Authenticator is required in Status-Server
		 *	packets, otherwise they can be trivially forged.
		 */
	case FR_RADIUS_CODE_STATUS_SERVER:
		require_message_authenticator = true;
		break;

		/*
		 *	Message-Authenticator may or may not be
		 *	required for Access-* packets.
		 */
	case FR_RADIUS_CODE_ACCESS_REQUEST:
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
	case FR_RADIUS_CODE_ACCESS_REJECT:
	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		break;

		/*
		 *	Message-Authenticator is not required for all other packets, but is required if the
		 *	caller asks for it.
		 */
	default:
		break;
	}

	/*
	 *	Repeat the length checks.  This time, instead of
	 *	looking at the data we received, look at the value
	 *	of the 'length' field inside of the packet.
	 *
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (totallen < RADIUS_HEADER_LENGTH) {
		failure = FR_RADIUS_FAIL_MIN_LENGTH_FIELD;
		goto finish;
	}

	/*
	 *	And again, for the value of the 'length' field.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	" ... and maximum length is 4096."
	 *
	 *	HOWEVER.  This requirement is for the network layer.
	 *	If the code gets here, we assume that a well-formed
	 *	packet is an OK packet.
	 *
	 *	We allow both the UDP data length, and the RADIUS
	 *	"length" field to contain up to 64K of data.
	 */

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"If the packet is shorter than the Length field
	 *	indicates, it MUST be silently discarded."
	 *
	 *	i.e. No response to the NAS.
	 */
	if (totallen > packet_len) {
		failure = FR_RADIUS_FAIL_MIN_LENGTH_MISMATCH;
		goto finish;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"Octets outside the range of the Length field MUST be
	 *	treated as padding and ignored on reception."
	 */
	if (totallen < packet_len) {
		*packet_len_p = packet_len = totallen;
	}

	/*
	 *	Walk through the packet's attributes, ensuring that
	 *	they add up EXACTLY to the size of the packet.
	 *
	 *	If they don't, then the attributes either under-fill
	 *	or over-fill the packet.  Any parsing of the packet
	 *	is impossible, and will result in unknown side effects.
	 *
	 *	This would ONLY happen with buggy RADIUS implementations,
	 *	or with an intentional attack.  Either way, we do NOT want
	 *	to be vulnerable to this problem.
	 */
	attr = packet + RADIUS_HEADER_LENGTH;
	end = packet + packet_len;
	num_attributes = 0;

	while (attr < end) {
		/*
		 *	We need at least 2 bytes to check the
		 *	attribute header.
		 */
		if ((end - attr) < 2) {
			failure = FR_RADIUS_FAIL_HEADER_OVERFLOW;
			goto finish;
		}

		/*
		 *	Attribute number zero is NOT defined.
		 */
		if (attr[0] == 0) {
			failure = FR_RADIUS_FAIL_INVALID_ATTRIBUTE;
			goto finish;
		}

		/*
		 *	Attributes are at LEAST as long as the ID & length
		 *	fields.  Anything shorter is an invalid attribute.
		 */
		if (attr[1] < 2) {
			failure = FR_RADIUS_FAIL_ATTRIBUTE_TOO_SHORT;
			goto finish;
		}

		/*
		 *	If there are fewer bytes in the packet than in the
		 *	attribute, it's a bad packet.
		 */
		if ((attr + attr[1]) > end) {
			failure = FR_RADIUS_FAIL_ATTRIBUTE_OVERFLOW;
			goto finish;
		}

		/*
		 *	Sanity check the attributes for length.
		 */
		switch (attr[0]) {
		default:	/* don't do anything by default */
			break;

			/*
			 *	If there's an EAP-Message, we require
			 *	a Message-Authenticator.
			 */
		case FR_EAP_MESSAGE:
			require_message_authenticator = true;
			break;

		case FR_MESSAGE_AUTHENTICATOR:
			if (attr[1] != 2 + RADIUS_AUTH_VECTOR_LENGTH) {
				failure = FR_RADIUS_FAIL_MA_INVALID_LENGTH;
				goto finish;
			}
			seen_ma = true;
			break;
		}

		attr += attr[1];
		num_attributes++;	/* seen one more attribute */
	}

	/*
	 *	If we're configured to look for a maximum number of
	 *	attributes, and we've seen more than that maximum,
	 *	then throw the packet away, as a possible DoS.
	 */
	if (num_attributes > max_attributes) {
		failure = FR_RADIUS_FAIL_TOO_MANY_ATTRIBUTES;
		goto finish;
	}

	/*
	 * 	http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 *
	 *	A packet with an EAP-Message attribute MUST also have
	 *	a Message-Authenticator attribute.
	 *
	 *	A Message-Authenticator all by itself is OK, though.
	 *
	 *	Similarly, Status-Server packets MUST contain
	 *	Message-Authenticator attributes.
	 */
	if (require_message_authenticator && !seen_ma) {
		failure = FR_RADIUS_FAIL_MA_MISSING;
		goto finish;
	}

finish:

	if (reason) *reason = failure;

	return (failure == FR_RADIUS_FAIL_NONE);
}


/** Verify a request / response packet
 *
 *  This function does its work by calling fr_radius_sign(), and then
 *  comparing the signature in the packet with the one we calculated.
 *  If they differ, there's a problem.
 *
 * @param[in] packet				the raw RADIUS packet (request or response)
 * @param[in] vector				the original packet vector
 * @param[in] secret				the shared secret
 * @param[in] secret_len			the length of the secret
 * @param[in] require_message_authenticator	whether we require Message-Authenticator.
 * @param[in] limit_proxy_state			whether we allow Proxy-State without Message-Authenticator.
 * @return
 *	< <0 on error (negative fr_radius_decode_fail_t)
 *	- 0 on success.
 */
int fr_radius_verify(uint8_t *packet, uint8_t const *vector,
		     uint8_t const *secret, size_t secret_len,
		     bool require_message_authenticator, bool limit_proxy_state)
{
	bool		found_message_authenticator = false;
	bool		found_proxy_state = false;
	int		rcode;
	int		code;
	uint8_t		*msg, *end;
	size_t		packet_len = fr_nbo_to_uint16(packet + 2);
	uint8_t		request_authenticator[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t		message_authenticator[RADIUS_AUTH_VECTOR_LENGTH];

	if (packet_len < RADIUS_HEADER_LENGTH) {
		fr_strerror_printf("invalid packet length %zu", packet_len);
		return -FR_RADIUS_FAIL_MIN_LENGTH_PACKET;
	}

	code = packet[0];
	if (!code || (code >= FR_RADIUS_CODE_MAX)) {
		fr_strerror_printf("Unknown reply code %d", code);
		return -FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE;
	}

	memcpy(request_authenticator, packet + 4, sizeof(request_authenticator));

	/*
	 *	Find Message-Authenticator.  Its value has to be
	 *	calculated before we calculate the Request
	 *	Authenticator or the Response Authenticator.
	 */
	msg = packet + RADIUS_HEADER_LENGTH;
	end = packet + packet_len;

	while (msg < end) {
		if ((end - msg) < 2) goto invalid_attribute;

		if (msg[0] != FR_MESSAGE_AUTHENTICATOR) {
			if (msg[1] < 2) goto invalid_attribute;

			/*
			 *	If we're not allowing Proxy-State without
			 *	Message-authenticator, we need to record
			 *	the fact we found Proxy-State.
			 */
			if (limit_proxy_state && (msg[0] == FR_PROXY_STATE)) found_proxy_state = true;

			if ((msg + msg[1]) > end) {
			invalid_attribute:
				fr_strerror_printf("invalid attribute at offset %zd", msg - packet);
				return -FR_RADIUS_FAIL_INVALID_ATTRIBUTE;
			}
			msg += msg[1];
			continue;
		}

		if (msg[1] < 18) {
			fr_strerror_const("too small Message-Authenticator");
			return -FR_RADIUS_FAIL_MA_INVALID_LENGTH;
		}

		/*
		 *	Found it, save a copy.
		 */
		memcpy(message_authenticator, msg + 2, sizeof(message_authenticator));
		found_message_authenticator = true;
		break;
	}

	if (packet[0] == FR_RADIUS_CODE_ACCESS_REQUEST) {
		if (limit_proxy_state && found_proxy_state && !found_message_authenticator) {
			fr_strerror_const("Proxy-State is not allowed without Message-Authenticator");
			return -FR_RADIUS_FAIL_MA_MISSING;
		}

	    	if (require_message_authenticator && !found_message_authenticator) {
			fr_strerror_const("Access-Request is missing the required Message-Authenticator attribute");
			return -FR_RADIUS_FAIL_MA_MISSING;
		}
	}

	/*
	 *	Overwrite the contents of Message-Authenticator
	 *	with the one we calculate.
	 */
	rcode = fr_radius_sign(packet, vector, secret, secret_len);
	if (rcode < 0) {
		fr_strerror_const_push("Failed calculating correct authenticator");
		return -FR_RADIUS_FAIL_VERIFY;
	}

	/*
	 *	Check the Message-Authenticator first.
	 *
	 *	If it's invalid, restore the original
	 *	Message-Authenticator and Request Authenticator
	 *	fields.
	 *
	 *	If it's valid the original and calculated
	 *	message authenticators are the same, so we don't
	 *	need to do anything.
	 */
	if ((msg < end) &&
	    (fr_digest_cmp(message_authenticator, msg + 2, sizeof(message_authenticator)) != 0)) {
		memcpy(msg + 2, message_authenticator, sizeof(message_authenticator));
		memcpy(packet + 4, request_authenticator, sizeof(request_authenticator));

		fr_strerror_const("invalid Message-Authenticator (shared secret is incorrect)");
		return -FR_RADIUS_FAIL_MA_INVALID;
	}

	/*
	 *	These are random numbers, so there's no point in
	 *	comparing them.
	 */
	if ((packet[0] == FR_RADIUS_CODE_ACCESS_REQUEST) || (packet[0] == FR_RADIUS_CODE_STATUS_SERVER)) {
		return 0;
	}

	/*
	 *	Check the Request Authenticator.
	 */
	if (fr_digest_cmp(request_authenticator, packet + 4, sizeof(request_authenticator)) != 0) {
		memcpy(packet + 4, request_authenticator, sizeof(request_authenticator));
		if (vector) {
			fr_strerror_const("invalid Response Authenticator (shared secret is incorrect)");
		} else {
			fr_strerror_const("invalid Request Authenticator (shared secret is incorrect)");
		}
		return -FR_RADIUS_FAIL_VERIFY;
	}

	return 0;
}

void *fr_radius_next_encodable(fr_dcursor_t *cursor, void *current, void *uctx);

void *fr_radius_next_encodable(fr_dcursor_t *cursor, void *current, void *uctx)
{
	fr_pair_t	*c = current;
	fr_dict_t	*dict = talloc_get_type_abort(uctx, fr_dict_t);

	while ((c = fr_dlist_next(cursor->dlist, c))) {
		PAIR_VERIFY(c);
		if ((c->da->dict == dict) &&
		    (!c->da->flags.internal || ((c->da->attr > FR_TAG_BASE) && (c->da->attr < (FR_TAG_BASE + 0x20))))) {
			break;
		}
	}

	return c;
}


ssize_t fr_radius_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_radius_encode_ctx_t *packet_ctx)
{
	ssize_t			slen;
	fr_pair_t const		*vp;
	fr_dcursor_t		cursor;
	fr_dbuff_t		work_dbuff, length_dbuff;

	/*
	 *	The RADIUS header can't do more than 64K of data.
	 */
	work_dbuff = FR_DBUFF_MAX(dbuff, 65535);

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, packet_ctx->code, packet_ctx->id);
	length_dbuff = FR_DBUFF(&work_dbuff);
	FR_DBUFF_IN_RETURN(&work_dbuff, (uint16_t) RADIUS_HEADER_LENGTH);

	switch (packet_ctx->code) {
	case FR_RADIUS_CODE_ACCESS_REQUEST:
	case FR_RADIUS_CODE_STATUS_SERVER:
		packet_ctx->request_authenticator = fr_dbuff_current(&work_dbuff);

		/*
		 *	Allow over-rides of the authentication vector for testing.
		 */
		vp = fr_pair_find_by_da(vps, NULL, attr_packet_authentication_vector);
		if (vp && (vp->vp_length >= RADIUS_AUTH_VECTOR_LENGTH)) {
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, RADIUS_AUTH_VECTOR_LENGTH);
		} else {
			int i;

			for (i = 0; i < 4; i++) {
				FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) fr_rand());
			}
		}
		break;

	case FR_RADIUS_CODE_ACCESS_ACCEPT:
	case FR_RADIUS_CODE_ACCESS_REJECT:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
	case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
	case FR_RADIUS_CODE_DISCONNECT_ACK:
	case FR_RADIUS_CODE_DISCONNECT_NAK:
	case FR_RADIUS_CODE_COA_ACK:
	case FR_RADIUS_CODE_COA_NAK:
	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		if (!packet_ctx->request_authenticator) {
			fr_strerror_const("Cannot encode response without request");
			return -1;
		}
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, packet_ctx->request_authenticator, RADIUS_AUTH_VECTOR_LENGTH);
		break;

	case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
	case FR_RADIUS_CODE_DISCONNECT_REQUEST:
		/*
		 *	Tunnel-Password encoded attributes are allowed
		 *	in CoA-Request packets, by RFC 5176 Section
		 *	3.6.  HOWEVER, the tunnel passwords are
		 *	"encrypted" using the Request Authenticator,
		 *	which is all zeros!  That makes them much
		 *	easier to decrypt.  The only solution here is
		 *	to say "don't do that!"
		 */
	case FR_RADIUS_CODE_COA_REQUEST:
		packet_ctx->request_authenticator = fr_dbuff_current(&work_dbuff);

		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, RADIUS_AUTH_VECTOR_LENGTH);
		break;

	default:
		fr_strerror_printf("Cannot encode unknown packet code %d", packet_ctx->code);
		return -1;
	}

	/*
	 *	Always add Message-Authenticator after the packet
	 *	header for insecure transport protocols.
	 */
	if (!packet_ctx->common->secure_transport) switch (packet_ctx->code) {
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
	case FR_RADIUS_CODE_ACCESS_REJECT:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
#ifdef NAS_VIOLATES_RFC
		/*
		 *	Allow ridiculous behavior for vendors who violate the RFCs.
		 *
		 *	But only if there's no EAP-Message in the packet.
		 */
		if (packet_ctx->allow_vulnerable_clients && !fr_pair_find_by_da(vps, NULL, attr_eap_message)) {
			break;
		}
		FALL_THROUGH;
#endif

	case FR_RADIUS_CODE_ACCESS_REQUEST:
	case FR_RADIUS_CODE_STATUS_SERVER:
	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_MESSAGE_AUTHENTICATOR, 0x12,
					 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
		packet_ctx->seen_message_authenticator = true;
		break;

	default:
		break;
	}

	/*
	 *	If we're sending Protocol-Error, add in
	 *	Original-Packet-Code manually.  If the user adds it
	 *	later themselves, well, too bad.
	 */
	if (packet_ctx->code == FR_RADIUS_CODE_PROTOCOL_ERROR) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_EXTENDED_ATTRIBUTE_1, 0x07, 0x04 /* Original-Packet-Code */,
					 0x00, 0x00, 0x00, packet_ctx->request_code);
	}

	/*
	 *	Loop over the reply attributes for the packet.
	 */
	fr_pair_dcursor_iter_init(&cursor, vps, fr_radius_next_encodable, dict_radius);
	while ((vp = fr_dcursor_current(&cursor))) {
		PAIR_VERIFY(vp);

		/*
		 *	Encode an individual VP
		 */
		slen = fr_radius_encode_pair(&work_dbuff, &cursor, packet_ctx);
		if (slen < 0) return slen;
	} /* done looping over all attributes */

	/*
	 *	Add Proxy-State to the end of the packet if the caller requested it.
	 */
	if (packet_ctx->add_proxy_state) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_PROXY_STATE, (uint8_t) (2 + sizeof(packet_ctx->common->proxy_state)));
		FR_DBUFF_IN_RETURN(&work_dbuff, packet_ctx->common->proxy_state);
	}

	/*
	 *	Fill in the length field we zeroed out earlier.
	 *
	 */
	fr_dbuff_in(&length_dbuff, (uint16_t) (fr_dbuff_used(&work_dbuff)));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "%s encoded packet", __FUNCTION__);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

ssize_t	fr_radius_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
			 uint8_t *packet, size_t packet_len,
			 fr_radius_decode_ctx_t *decode_ctx)
{
	ssize_t			slen;
	uint8_t const		*attr, *end;
	static const uint8_t   	zeros[RADIUS_AUTH_VECTOR_LENGTH] = {};

	decode_ctx->reason = FR_RADIUS_FAIL_NONE;

	if (!decode_ctx->request_authenticator) {
		switch (packet[0]) {
		case FR_RADIUS_CODE_ACCESS_REQUEST:
		case FR_RADIUS_CODE_STATUS_SERVER:
			decode_ctx->request_authenticator = packet + 4;
			break;

		case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
		case FR_RADIUS_CODE_COA_REQUEST:
		case FR_RADIUS_CODE_DISCONNECT_REQUEST:
			decode_ctx->request_authenticator = zeros;
			break;

		default:
			fr_strerror_const("No authentication vector passed for packet decode");
			decode_ctx->reason = FR_RADIUS_FAIL_NO_MATCHING_REQUEST;
			return -1;
		}
	}

	if (decode_ctx->request_code) {
		unsigned int code = packet[0];

		if (code >= FR_RADIUS_CODE_MAX) {
			decode_ctx->reason = FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE;
			return -1;
		}
		if (decode_ctx->request_code >= FR_RADIUS_CODE_MAX) {
			decode_ctx->reason = FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE;
			return -1;
		}

		if (!allowed_replies[code]) {
			decode_ctx->reason = FR_RADIUS_FAIL_UNEXPECTED_RESPONSE_CODE;
			return -1;
		}

		/*
		 *	Protocol error can reply to any packet.
		 *
		 *	Status-Server can get any reply.
		 *
		 *	Otherwise the reply code must be associated with the request code we sent.
		 */
		if ((allowed_replies[code] != decode_ctx->request_code) &&
		    (code != FR_RADIUS_CODE_PROTOCOL_ERROR) &&
		    (decode_ctx->request_code != FR_RADIUS_CODE_STATUS_SERVER)) {
			decode_ctx->reason = FR_RADIUS_FAIL_UNEXPECTED_RESPONSE_CODE;
			return -1;
		}
	}

	/*
	 *	We can skip verification for dynamic client checks, and where packets are unsigned as with
	 *	RADIUS/1.1.
	 */
	if (decode_ctx->verify) {
		if (!decode_ctx->request_authenticator) decode_ctx->request_authenticator = zeros;

		if (fr_radius_verify(packet, decode_ctx->request_authenticator,
				     (uint8_t const *) decode_ctx->common->secret, decode_ctx->common->secret_length,
				     decode_ctx->require_message_authenticator, decode_ctx->limit_proxy_state) < 0) {
			decode_ctx->reason = FR_RADIUS_FAIL_VERIFY;
			return -1;
		}
	}

	attr = packet + 20;
	end = packet + packet_len;

	/*
	 *	The caller MUST have called fr_radius_ok() first.  If
	 *	he doesn't, all hell breaks loose.
	 */
	while (attr < end) {
		slen = fr_radius_decode_pair(ctx, out, attr, (end - attr), decode_ctx);
		if (slen < 0) {
			decode_ctx->reason = FR_RADIUS_FAIL_ATTRIBUTE_DECODE;
			return slen;
		}

		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - attr))) {
			 return -slen;
		 }

		attr += slen;
		talloc_free_children(decode_ctx->tmp_ctx);
	}

	/*
	 *	We've parsed the whole packet, return that.
	 */
	return packet_len;
}

/** Simple wrapper for callers who just need a shared secret
 *
 */
ssize_t	fr_radius_decode_simple(TALLOC_CTX *ctx, fr_pair_list_t *out,
				uint8_t *packet, size_t packet_len,
				uint8_t const *vector, char const *secret)
{
	ssize_t rcode;
	fr_radius_ctx_t		common_ctx = {};
	fr_radius_decode_ctx_t	packet_ctx = {};

	common_ctx.secret = secret;
	common_ctx.secret_length = strlen(secret);

	packet_ctx.common = &common_ctx;
	packet_ctx.tmp_ctx = talloc(ctx, uint8_t);
	packet_ctx.request_authenticator = vector;
	packet_ctx.end = packet + packet_len;

	rcode = fr_radius_decode(ctx, out, packet, packet_len, &packet_ctx);
	talloc_free(packet_ctx.tmp_ctx);

	return rcode;
}

int fr_radius_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(libfreeradius_radius_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_radius_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_radius_dict);
		goto fail;
	}

	instantiated = true;
	return 0;
}

void fr_radius_global_free(void)
{
	if (!instantiated) return;

	if (--instance_count != 0) return;

	fr_dict_autofree(libfreeradius_radius_dict);
}

static bool attr_valid(fr_dict_attr_t *da)
{
	fr_radius_attr_flags_t const *flags = fr_radius_attr_flags(da);

	if (da->parent->type == FR_TYPE_STRUCT) {
		if (flags->extended) {
			fr_strerror_const("Attributes with 'extended' flag cannot be used inside of a 'struct'");
			return false;
		}

		if (flags->long_extended) {
			fr_strerror_const("Attributes with 'long_extended' flag cannot be used inside of a 'struct'");
			return false;
		}


		if (flags->concat) {
			fr_strerror_const("Attributes with 'concat' flag cannot be used inside of a 'struct'");
			return false;
		}

		if (flags->has_tag) {
			fr_strerror_const("Attributes with 'tag' flag cannot be used inside of a 'struct'");
			return false;
		}

		if (flags->abinary) {
			fr_strerror_const("Attributes with 'abinary' flag cannot be used inside of a 'struct'");
			return false;
		}

		if (flags->encrypt > 0) {
			fr_strerror_const("Attributes with 'encrypt' flag cannot be used inside of a 'struct'");
			return false;
		}

		return true;
	}

	if (da->flags.length > 253) {
		fr_strerror_printf("Attributes cannot be more than 253 octets in length");
		return false;
	}
	/*
	 *	Secret things are secret.
	 */
	if (flags->encrypt != 0) da->flags.secret = true;

	if (flags->concat) {
		if (!da->parent->flags.is_root) {
			fr_strerror_const("Attributes with the 'concat' flag MUST be at the root of the dictionary");
			return false;
		}

		if (da->type != FR_TYPE_OCTETS) {
			fr_strerror_const("Attributes with the 'concat' flag MUST be of data type 'octets'");
			return false;
		}

		return true;	/* can't use any other flag */
	}

	/*
	 *	Tagged attributes can only be of two data types.  They
	 *	can, however, be VSAs.
	 */
	if (flags->has_tag) {
		if ((da->type != FR_TYPE_UINT32) && (da->type != FR_TYPE_STRING)) {
			fr_strerror_printf("The 'has_tag' flag can only be used for attributes of type 'integer' "
					   "or 'string'");
			return false;
		}

		if (!(da->parent->flags.is_root ||
		      ((da->parent->type == FR_TYPE_VENDOR) &&
		       (da->parent->parent && da->parent->parent->type == FR_TYPE_VSA)))) {
			fr_strerror_const("The 'has_tag' flag can only be used with RFC and VSA attributes");
			return false;
		}

		return true;
	}

	if (flags->extended) {
		if (da->type != FR_TYPE_TLV) {
			fr_strerror_const("The 'long' or 'extended' flag can only be used for attributes of type 'tlv'");
			return false;
		}

		if (!da->parent->flags.is_root) {
			fr_strerror_const("The 'long' flag can only be used for top-level RFC attributes");
			return false;
		}

		return true;
	}

	/*
	 *	Stupid hacks for MS-CHAP-MPPE-Keys.  The User-Password
	 *	encryption method has no provisions for encoding the
	 *	length of the data.  For User-Password, the data is
	 *	(presumably) all printable non-zero data.  For
	 *	MS-CHAP-MPPE-Keys, the data is binary crap.  So... we
	 *	MUST specify a length in the dictionary.
	 */
	if ((flags->encrypt == RADIUS_FLAG_ENCRYPT_USER_PASSWORD) && (da->type != FR_TYPE_STRING)) {
		if (da->type != FR_TYPE_OCTETS) {
			fr_strerror_printf("The 'encrypt=User-Password' flag can only be used with "
					   "attributes of type 'string'");
			return false;
		}

		if (da->flags.length == 0) {
			fr_strerror_printf("The 'encrypt=User-Password' flag MUST be used with an explicit length for "
					   "'octets' data types");
			return false;
		}
	}

	switch (da->type) {
	case FR_TYPE_STRING:
		break;

	case FR_TYPE_TLV:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_UINT32:
	case FR_TYPE_OCTETS:
		if (flags->encrypt != RADIUS_FLAG_ENCRYPT_ASCEND_SECRET) break;
		FALL_THROUGH;

	default:
		if (flags->encrypt) {
			fr_strerror_printf("The 'encrypt' flag cannot be used with attributes of type '%s'",
					   fr_type_to_str(da->type));
			return false;
		}
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_radius_dict_protocol;
fr_dict_protocol_t libfreeradius_radius_dict_protocol = {
	.name = "radius",
	.default_type_size = 1,
	.default_type_length = 1,
	.attr = {
		.flags = {
			.table = radius_flags,
			.table_len = NUM_ELEMENTS(radius_flags),
			.len = sizeof(fr_radius_attr_flags_t),
		},
		.valid = attr_valid,
	},

	.init = fr_radius_global_init,
	.free = fr_radius_global_free,

	.decode = fr_radius_decode_foreign,
	.encode = fr_radius_encode_foreign,
};
