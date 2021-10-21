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

#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

static uint32_t instance_count = 0;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_radius;

extern fr_dict_autoload_t libfreeradius_radius_dict[];
fr_dict_autoload_t libfreeradius_radius_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_packet_authentication_vector;
fr_dict_attr_t const *attr_raw_attribute;
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
	{ NULL }
};

/** RADIUS on-the-wire format attribute sizes
 *
 * Holds the min/max sizes of all supported RADIUS attribute values as they
 * would be found in a RADIUS packet.
 *
 * These sizes may be different than the sizes of INTERNAL formats, PRESENTATION
 * formats and generic NETWORK formats.
 */
size_t const fr_radius_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_NULL]		= {~0, 0},	//!< Ensure array starts at 0 (umm?)

	[FR_TYPE_STRING]		= {0, ~0},
	[FR_TYPE_OCTETS]		= {0, ~0},

	[FR_TYPE_IPV4_ADDR]		= {4, 4},
	[FR_TYPE_IPV4_PREFIX]		= {6, 6},
	[FR_TYPE_IPV6_ADDR]		= {16, 16},
	[FR_TYPE_IPV6_PREFIX]		= {2, 18},
	[FR_TYPE_COMBO_IP_PREFIX]	= {6, 18},
	[FR_TYPE_COMBO_IP_ADDR]		= {4, 16},
	[FR_TYPE_IFID]			= {8, 8},
	[FR_TYPE_ETHERNET]		= {6, 6},

	[FR_TYPE_BOOL]			= {1, 1},
	[FR_TYPE_UINT8]			= {1, 1},
	[FR_TYPE_UINT16]		= {2, 2},
	[FR_TYPE_UINT32]		= {4, 4},
	[FR_TYPE_UINT64]		= {8, 8},

	[FR_TYPE_INT8]			= {1, 1},
	[FR_TYPE_INT16]			= {2, 2},
	[FR_TYPE_INT32]			= {4, 4},
	[FR_TYPE_INT64]			= {8, 8},

	[FR_TYPE_DATE]			= {2, 8},
	[FR_TYPE_TIME_DELTA]   		= {2, 8},

	[FR_TYPE_TLV]			= {2, ~0},
	[FR_TYPE_STRUCT]		= {1, ~0},

	[FR_TYPE_VSA]			= {4, ~0},

	[FR_TYPE_MAX]			= {~0, 0}	//!< Ensure array covers all types.
};

/*
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf_push

fr_table_num_sorted_t const fr_request_types[] = {
	{ L("acct"),	FR_RADIUS_CODE_ACCOUNTING_REQUEST	},
	{ L("auth"),	FR_RADIUS_CODE_ACCESS_REQUEST		},
	{ L("auto"),	FR_RADIUS_CODE_UNDEFINED		},
	{ L("challenge"),	FR_RADIUS_CODE_ACCESS_CHALLENGE	},
	{ L("coa"),	FR_RADIUS_CODE_COA_REQUEST		},
	{ L("disconnect"),	FR_RADIUS_CODE_DISCONNECT_REQUEST	},
	{ L("status"),	FR_RADIUS_CODE_STATUS_SERVER		}
};
size_t fr_request_types_len = NUM_ELEMENTS(fr_request_types);

char const *fr_packet_codes[FR_RADIUS_CODE_MAX] = {
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

bool const fr_request_packets[FR_RADIUS_CODE_MAX + 1] = {
	[FR_RADIUS_CODE_ACCESS_REQUEST] = true,
	[FR_RADIUS_CODE_ACCOUNTING_REQUEST] = true,
	[FR_RADIUS_CODE_STATUS_SERVER] = true,
	[FR_RADIUS_CODE_COA_REQUEST] = true,
	[FR_RADIUS_CODE_DISCONNECT_REQUEST] = true,
};


/** Return the on-the-wire length of an attribute value
 *
 * @param[in] vp to return the length of.
 * @return the length of the attribute.
 */
size_t fr_radius_attr_len(fr_pair_t const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		if (vp->da->flags.length) return vp->da->flags.length;	/* Variable type with fixed length */
		return vp->vp_length;

	case FR_TYPE_STRUCTURAL:
		fr_assert_fail(NULL);
		return 0;

	default:
		return fr_radius_attr_sizes[vp->vp_type][0];
	}
}

/**  Do Ascend-Send / Recv-Secret calculation.
 *
 * The secret is hidden by xoring with a MD5 digest created from
 * the RADIUS shared secret and the authentication vector.
 * We put them into MD5 in the reverse order from that used when
 * encrypting passwords to RADIUS.
 */
ssize_t fr_radius_ascend_secret(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen,
				char const *secret, uint8_t const vector[static RADIUS_AUTH_VECTOR_LENGTH])
{
	fr_md5_ctx_t		*md5_ctx;
	size_t			i;
	uint8_t			digest[MD5_DIGEST_LENGTH];
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, sizeof(digest));

	md5_ctx = fr_md5_ctx_alloc(true);
	fr_md5_update(md5_ctx, vector, RADIUS_AUTH_VECTOR_LENGTH);
	fr_md5_update(md5_ctx, (uint8_t const *) secret, talloc_array_length(secret) - 1);
	fr_md5_final(digest, md5_ctx);
	fr_md5_ctx_free(&md5_ctx);

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

		FR_DEBUG_STRERROR_PRINTF("Expected at least 4 bytes of header data, got %zu bytes", data_len);
invalid:
		FR_DEBUG_STRERROR_PRINTF("Invalid data from %s",
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
					 "data, got %zu bytes", packet_len);
		goto invalid;
	}

	/*
	 *	Enforce RFC requirements, for sanity.
	 *	Anything after 4k will be discarded.
	 */
	if (packet_len > MAX_PACKET_LEN) {
		FR_DEBUG_STRERROR_PRINTF("Length field value too large, expected maximum of "
					 STRINGIFY(MAX_PACKET_LEN) " bytes, got %zu bytes", packet_len);
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
 * @param[in] original		request (only if this is a response).
 * @param[in] secret		to sign the packet with.
 * @param[in] secret_len	The length of the secret.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_sign(uint8_t *packet, uint8_t const *original,
		   uint8_t const *secret, size_t secret_len)
{
	uint8_t		*msg, *end;
	size_t		packet_len = (packet[2] << 8) | packet[3];

	/*
	 *	No real limit on secret length, this is just
	 *	to catch uninitialised fields.
	 */
	if (!fr_cond_assert(secret_len <= UINT16_MAX)) {
		fr_strerror_printf("Secret is too long.  Expected <= %u, got %zu", UINT16_MAX, secret_len);
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
		case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
		case FR_RADIUS_CODE_DISCONNECT_ACK:
		case FR_RADIUS_CODE_DISCONNECT_NAK:
		case FR_RADIUS_CODE_COA_ACK:
		case FR_RADIUS_CODE_COA_NAK:
			if (!original) goto need_original;
			if (original[0] == FR_RADIUS_CODE_STATUS_SERVER) goto do_ack;
			FALL_THROUGH;

		case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
		case FR_RADIUS_CODE_DISCONNECT_REQUEST:
		case FR_RADIUS_CODE_COA_REQUEST:
			memset(packet + 4, 0, RADIUS_AUTH_VECTOR_LENGTH);
			break;

		case FR_RADIUS_CODE_ACCESS_ACCEPT:
		case FR_RADIUS_CODE_ACCESS_REJECT:
		case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		do_ack:
			if (!original) goto need_original;
			memcpy(packet + 4, original + 4, RADIUS_AUTH_VECTOR_LENGTH);
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
		if (!original) {
		need_original:
			fr_strerror_const("Cannot sign response packet without a request packet");
			return -1;
		}
		memcpy(packet + 4, original + 4, RADIUS_AUTH_VECTOR_LENGTH);
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

		md5_ctx = fr_md5_ctx_alloc(true);
		fr_md5_update(md5_ctx, packet, packet_len);
		fr_md5_update(md5_ctx, secret, secret_len);
		fr_md5_final(packet + 4, md5_ctx);
		fr_md5_ctx_free(&md5_ctx);
	}

	return 0;
}


/** See if the data pointed to by PTR is a valid RADIUS packet.
 *
 * @param[in] packet		to check.
 * @param[in,out] packet_len_p	The size of the packet data.
 * @param[in] max_attributes	to allow in the packet.
 * @param[in] require_ma	whether we require Message-Authenticator.
 * @param[in] reason		if not NULL, will have the failure reason written to where it points.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_radius_ok(uint8_t const *packet, size_t *packet_len_p,
		  uint32_t max_attributes, bool require_ma, decode_fail_t *reason)
{
	uint8_t	const		*attr, *end;
	size_t			totallen;
	bool			seen_ma = false;
	uint32_t		num_attributes;
	decode_fail_t		failure = DECODE_FAIL_NONE;
	size_t			packet_len = *packet_len_p;

	/*
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (packet_len < RADIUS_HEADER_LENGTH) {
		FR_DEBUG_STRERROR_PRINTF("packet is too short (received %zu < minimum 20)",
					 packet_len);
		failure = DECODE_FAIL_MIN_LENGTH_PACKET;
		goto finish;
	}


	/*
	 *	Check for packets with mismatched size.
	 *	i.e. We've received 128 bytes, and the packet header
	 *	says it's 256 bytes long.
	 */
	totallen = (packet[2] << 8) | packet[3];

	/*
	 *	Code of 0 is not understood.
	 *	Code of 16 or greate is not understood.
	 */
	if ((packet[0] == 0) ||
	    (packet[0] >= FR_RADIUS_CODE_MAX)) {
		FR_DEBUG_STRERROR_PRINTF("unknown packet code %d", packet[0]);
		failure = DECODE_FAIL_UNKNOWN_PACKET_CODE;
		goto finish;
	}

	/*
	 *	Message-Authenticator is required in Status-Server
	 *	packets, otherwise they can be trivially forged.
	 */
	if (packet[0] == FR_RADIUS_CODE_STATUS_SERVER) require_ma = true;

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
		FR_DEBUG_STRERROR_PRINTF("length in header is too small (length %zu < minimum 20)",
					 totallen);
		failure = DECODE_FAIL_MIN_LENGTH_FIELD;
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
	if (packet_len < totallen) {
		FR_DEBUG_STRERROR_PRINTF("packet is truncated (received %zu <  packet header length of %zu)",
					 packet_len, totallen);
		failure = DECODE_FAIL_MIN_LENGTH_MISMATCH;
		goto finish;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"Octets outside the range of the Length field MUST be
	 *	treated as padding and ignored on reception."
	 */
	if (packet_len > totallen) {
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
			FR_DEBUG_STRERROR_PRINTF("attribute header overflows the packet");
			failure = DECODE_FAIL_HEADER_OVERFLOW;
			goto finish;
		}

		/*
		 *	Attribute number zero is NOT defined.
		 */
		if (attr[0] == 0) {
			FR_DEBUG_STRERROR_PRINTF("invalid attribute 0 at offset %zd", attr - packet);
			failure = DECODE_FAIL_INVALID_ATTRIBUTE;
			goto finish;
		}

		/*
		 *	Attributes are at LEAST as long as the ID & length
		 *	fields.  Anything shorter is an invalid attribute.
		 */
		if (attr[1] < 2) {
			FR_DEBUG_STRERROR_PRINTF("attribute %u is too short at offset %zd",
						 attr[0], attr - packet);
			failure = DECODE_FAIL_ATTRIBUTE_TOO_SHORT;
			goto finish;
		}

		/*
		 *	If there are fewer bytes in the packet than in the
		 *	attribute, it's a bad packet.
		 */
		if ((attr + attr[1]) > end) {
			FR_DEBUG_STRERROR_PRINTF("attribute %u data overflows the packet starting at offset %zd",
					   attr[0], attr - packet);
			failure = DECODE_FAIL_ATTRIBUTE_OVERFLOW;
			goto finish;
		}

		/*
		 *	Sanity check the attributes for length.
		 */
		switch (attr[0]) {
		default:	/* don't do anything by default */
			break;

#if 0
			/*
			 *	Track this for prioritizing ongoing EAP sessions.
			 */
		case FR_STATE:
			if (attr[1] > 2) packet->rounds = attr[2];
			break;
#endif

			/*
			 *	If there's an EAP-Message, we require
			 *	a Message-Authenticator.
			 */
		case FR_EAP_MESSAGE:
			require_ma = true;
			break;

		case FR_MESSAGE_AUTHENTICATOR:
			if (attr[1] != 2 + RADIUS_AUTH_VECTOR_LENGTH) {
				FR_DEBUG_STRERROR_PRINTF("Message-Authenticator has invalid length (%d != 18) at offset %zd",
					   attr[1] - 2, attr - packet);
				failure = DECODE_FAIL_MA_INVALID_LENGTH;
				goto finish;
			}
			seen_ma = true;
			break;
		}

		attr += attr[1];
		num_attributes++;	/* seen one more attribute */
	}

	/*
	 *	If the attributes add up to a packet, it's allowed.
	 *
	 *	If not, we complain, and throw the packet away.
	 */
	if (attr != end) {
		FR_DEBUG_STRERROR_PRINTF("attributes do NOT exactly fill the packet");
		failure = DECODE_FAIL_ATTRIBUTE_UNDERFLOW;
		goto finish;
	}

	/*
	 *	If we're configured to look for a maximum number of
	 *	attributes, and we've seen more than that maximum,
	 *	then throw the packet away, as a possible DoS.
	 */
	if ((max_attributes > 0) &&
	    (num_attributes > max_attributes)) {
		FR_DEBUG_STRERROR_PRINTF("Possible DoS attack - too many attributes in request (received %d, max %d are allowed).",
					 num_attributes, max_attributes);
		failure = DECODE_FAIL_TOO_MANY_ATTRIBUTES;
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
	if (require_ma && !seen_ma) {
		FR_DEBUG_STRERROR_PRINTF("we equire Message-Authenticator attribute, but it is not in the packet");
		failure = DECODE_FAIL_MA_MISSING;
		goto finish;
	}

finish:

	if (reason) {
		*reason = failure;
	}
	return (failure == DECODE_FAIL_NONE);
}


/** Verify a request / response packet
 *
 *  This function does its work by calling fr_radius_sign(), and then
 *  comparing the signature in the packet with the one we calculated.
 *  If they differ, there's a problem.
 *
 * @param packet the raw RADIUS packet (request or response)
 * @param original the raw original request (if this is a response)
 * @param secret the shared secret
 * @param secret_len the length of the secret
 * @param[in] require_ma	whether we require Message-Authenticator.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_verify(uint8_t *packet, uint8_t const *original,
		     uint8_t const *secret, size_t secret_len, bool require_ma)
{
	bool found_ma;
	int rcode;
	uint8_t *msg, *end;
	size_t packet_len = (packet[2] << 8) | packet[3];
	uint8_t request_authenticator[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t message_authenticator[RADIUS_AUTH_VECTOR_LENGTH];

	if (packet_len < RADIUS_HEADER_LENGTH) {
		fr_strerror_printf("invalid packet length %zd", packet_len);
		return -1;
	}

	memcpy(request_authenticator, packet + 4, sizeof(request_authenticator));

	/*
	 *	Find Message-Authenticator.  Its value has to be
	 *	calculated before we calculate the Request
	 *	Authenticator or the Response Authenticator.
	 */
	msg = packet + RADIUS_HEADER_LENGTH;
	end = packet + packet_len;
	found_ma = false;

	while (msg < end) {
		if ((end - msg) < 2) goto invalid_attribute;

		if (msg[0] != FR_MESSAGE_AUTHENTICATOR) {
			if (msg[1] < 2) goto invalid_attribute;

			if ((msg + msg[1]) > end) {
			invalid_attribute:
				fr_strerror_printf("invalid attribute at offset %zd", msg - packet);
				return -1;
			}
			msg += msg[1];
			continue;
		}

		if (msg[1] < 18) {
			fr_strerror_const("too small Message-Authenticator");
			return -1;
		}

		/*
		 *	Found it, save a copy.
		 */
		memcpy(message_authenticator, msg + 2, sizeof(message_authenticator));
		found_ma = true;
		break;
	}

	if ((packet[0] == FR_RADIUS_CODE_ACCESS_REQUEST) &&
	    require_ma && !found_ma) {
		fr_strerror_const("Access-Request is missing the required Message-Authenticator attribute");
		return -1;
	}

	/*
	 *	Implement verification as a signature, followed by
	 *	checking our signature against the sent one.  This is
	 *	slightly more CPU work than having verify-specific
	 *	functions, but it ends up being cleaner in the code.
	 */
	rcode = fr_radius_sign(packet, original, secret, secret_len);
	if (rcode < 0) {
		fr_strerror_const_push("Failed calculating correct authenticator");
		return -1;
	}

	/*
	 *	Check the Message-Authenticator first.
	 *
	 *	If it's invalid, restore the original
	 *	Message-Authenticator and Request Authenticator
	 *	fields.
	 */
	if ((msg < end) &&
	    (fr_digest_cmp(message_authenticator, msg + 2, sizeof(message_authenticator)) != 0)) {
		memcpy(msg + 2, message_authenticator, sizeof(message_authenticator));
		memcpy(packet + 4, request_authenticator, sizeof(request_authenticator));

		fr_strerror_const("invalid Message-Authenticator (shared secret is incorrect)");
		return -1;
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
		if (original) {
			fr_strerror_const("invalid Response Authenticator (shared secret is incorrect)");
		} else {
			fr_strerror_const("invalid Request Authenticator (shared secret is incorrect)");
		}
		return -1;
	}

	return 0;
}

void *fr_radius_next_encodable(fr_dlist_head_t *list, void *to_eval, void *uctx);

void *fr_radius_next_encodable(fr_dlist_head_t *list, void *to_eval, void *uctx)
{
	fr_pair_t	*c;
	fr_dict_t	*dict = talloc_get_type_abort(uctx, fr_dict_t);

	if (!to_eval) return NULL;

	for (c = to_eval; c; c = fr_dlist_next(list, c)) {
		PAIR_VERIFY(c);
		if ((c->da->dict == dict) &&
		    (!c->da->flags.internal || ((c->da->attr > FR_TAG_BASE) && (c->da->attr < (FR_TAG_BASE + 0x20))))) {
			break;
		}
	}

	return c;
}


/** Encode VPS into a raw RADIUS packet.
 *
 */
ssize_t fr_radius_encode(uint8_t *packet, size_t packet_len, uint8_t const *original,
			 char const *secret, size_t secret_len, int code, int id, fr_pair_list_t *vps)
{
	return fr_radius_encode_dbuff(&FR_DBUFF_TMP(packet, packet_len), original, secret, secret_len, code, id, vps);
}

ssize_t fr_radius_encode_dbuff(fr_dbuff_t *dbuff, uint8_t const *original,
			 char const *secret, UNUSED size_t secret_len, int code, int id, fr_pair_list_t *vps)
{
	ssize_t			slen;
	fr_pair_t const	*vp;
	fr_dcursor_t		cursor;
	fr_radius_ctx_t		packet_ctx;
	fr_dbuff_t		work_dbuff, length_dbuff;

	memset(&packet_ctx, 0, sizeof(packet_ctx));
	packet_ctx.secret = secret;
	packet_ctx.rand_ctx.a = fr_rand();
	packet_ctx.rand_ctx.b = fr_rand();

	/*
	 *	The RADIUS header can't do more than 64K of data.
	 */
	work_dbuff = FR_DBUFF_MAX(dbuff, 65535);

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, code, id);
	length_dbuff = FR_DBUFF(&work_dbuff);
	FR_DBUFF_IN_RETURN(&work_dbuff, (uint16_t) RADIUS_HEADER_LENGTH);

	switch (code) {
	case FR_RADIUS_CODE_ACCESS_REQUEST:
	case FR_RADIUS_CODE_STATUS_SERVER:
		packet_ctx.disallow_tunnel_passwords = true;

		/*
		 *	Callers in these cases have preloaded the buffer with the authentication vector.
		 */
		FR_DBUFF_OUT_MEMCPY_RETURN(packet_ctx.vector, &work_dbuff, sizeof(packet_ctx.vector));
		break;

	case FR_RADIUS_CODE_ACCESS_REJECT:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
	case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
	case FR_RADIUS_CODE_COA_ACK:
	case FR_RADIUS_CODE_COA_NAK:
	case FR_RADIUS_CODE_DISCONNECT_ACK:
	case FR_RADIUS_CODE_DISCONNECT_NAK:
	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		packet_ctx.disallow_tunnel_passwords = true;
		FALL_THROUGH;

	case FR_RADIUS_CODE_ACCESS_ACCEPT:
		if (!original) {
			fr_strerror_const("Cannot encode response without request");
			return -1;
		}
		memcpy(packet_ctx.vector, original + 4, sizeof(packet_ctx.vector));
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, packet_ctx.vector, RADIUS_AUTH_VECTOR_LENGTH);
		break;

	case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
	case FR_RADIUS_CODE_DISCONNECT_REQUEST:
		packet_ctx.disallow_tunnel_passwords = true;
		FALL_THROUGH;

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
		memset(packet_ctx.vector, 0, sizeof(packet_ctx.vector));
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, RADIUS_AUTH_VECTOR_LENGTH);
		break;

	default:
		fr_strerror_printf("Cannot encode unknown packet code %d", code);
		return -1;
	}

	/*
	 *	If we're sending Protocol-Error, add in
	 *	Original-Packet-Code manually.  If the user adds it
	 *	later themselves, well, too bad.
	 */
	if (code == FR_RADIUS_CODE_PROTOCOL_ERROR) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_EXTENDED_ATTRIBUTE_1, 0x07, 0x04 /* Original-Packet-Code */,
					 0x00, 0x00, 0x00, original[0]);
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
		slen = fr_radius_encode_pair(&work_dbuff, &cursor, &packet_ctx);
		if (slen < 0) {
			if (slen == PAIR_ENCODE_SKIPPED) continue;
			return slen;
		}
	} /* done looping over all attributes */

	/*
	 *	Fill in the length field we zeroed out earlier.
	 *
	 */
	fr_dbuff_in(&length_dbuff, (uint16_t) (fr_dbuff_used(&work_dbuff)));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "%s encoded packet", __FUNCTION__);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Decode a raw RADIUS packet into VPs.
 *
 */
ssize_t fr_radius_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
			 uint8_t const *packet, size_t packet_len, uint8_t const *original,
			 char const *secret, UNUSED size_t secret_len)
{
	ssize_t			slen;
	uint8_t const		*attr, *end;
	fr_radius_ctx_t		packet_ctx;

	memset(&packet_ctx, 0, sizeof(packet_ctx));
	packet_ctx.tmp_ctx = talloc_init_const("tmp");
	packet_ctx.secret = secret;
	memcpy(packet_ctx.vector, original ? original + 4 : packet + 4, sizeof(packet_ctx.vector));

	attr = packet + 20;
	end = packet + packet_len;

	/*
	 *	The caller MUST have called fr_radius_ok() first.  If
	 *	he doesn't, all hell breaks loose.
	 */
	while (attr < end) {
		slen = fr_radius_decode_pair(ctx, out, dict_radius, attr, (end - attr), &packet_ctx);
		if (slen < 0) {
		fail:
			talloc_free(packet_ctx.tmp_ctx);
			talloc_free(packet_ctx.tags);
			return slen;
		}

		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - attr))) {
			 goto fail;
		 }

		attr += slen;
		talloc_free_children(packet_ctx.tmp_ctx);
	}

	/*
	 *	We've parsed the whole packet, return that.
	 */
	talloc_free(packet_ctx.tmp_ctx);
	talloc_free(packet_ctx.tags);
	return packet_len;
}

int fr_radius_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_radius_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_radius_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_radius_dict);
		return -1;
	}

	instance_count++;

	return 0;
}

void fr_radius_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_radius_dict);
}

static fr_table_num_ordered_t const subtype_table[] = {
	{ L("long-extended"),  		FLAG_LONG_EXTENDED_ATTR },
	{ L("extended"),       		FLAG_EXTENDED_ATTR },
	{ L("concat"),			FLAG_CONCAT },
	{ L("has_tag"),			FLAG_HAS_TAG },
	{ L("abinary"),			FLAG_ABINARY },
	{ L("has_tag,encrypt=2"),	FLAG_TAGGED_TUNNEL_PASSWORD },

	{ L("encrypt=1"),		FLAG_ENCRYPT_USER_PASSWORD },
	{ L("encrypt=2"),		FLAG_ENCRYPT_TUNNEL_PASSWORD },
	{ L("encrypt=3"),		FLAG_ENCRYPT_ASCEND_SECRET },

	/*
	 *	And some humanly-readable names
	 */
	{ L("encrypt=User-Password"),	FLAG_ENCRYPT_USER_PASSWORD },
	{ L("encrypt=Tunnel-Password"),	FLAG_ENCRYPT_TUNNEL_PASSWORD },
	{ L("encrypt=Ascend-Secret"),	FLAG_ENCRYPT_ASCEND_SECRET },
};

static bool attr_valid(UNUSED fr_dict_t *dict, fr_dict_attr_t const *parent,
		       UNUSED char const *name, UNUSED int attr, fr_type_t type, fr_dict_attr_flags_t *flags)
{
	if (parent->type == FR_TYPE_STRUCT) {
		if (flag_extended(flags)) {
			fr_strerror_const("Attributes of type 'extended' cannot be used inside of a 'struct'");
			return false;
		}

		/*
		 *	The "extra" flag signifies that the subtype
		 *	field is being used by the dictionaries
		 *	itself, for key fields, etc.
		 */
		if (flags->extra) return true;

		/*
		 *	All other flags are invalid inside of a struct.
		 */
		if (flags->subtype) {
			fr_strerror_const("Attributes inside of a 'struct' MUST NOT have flags set");
			return false;
		}

		return true;
	}

	/*
	 *	The 'extra flag is only for inside of structs and TLVs
	 *	with refs.  It shouldn't appear anywhere else.
	 */
	if (flags->extra) {
		fr_strerror_const("Unsupported extension.");
		return false;
	}

	if (flags->length > 253) {
		fr_strerror_printf("Attributes cannot be more than 253 octets in length");
		return false;
	}

	/*
	 *	No special flags, so we're OK.
	 *
	 *	If there is a subtype, it can only be of one kind.
	 */
	if (!flags->subtype) return true;

	if (flags->subtype > FLAG_ENCRYPT_ASCEND_SECRET) {
		fr_strerror_printf("Invalid flag value %u", flags->subtype);
		return false;
	}

	if (flag_concat(flags)) {
		if (!parent->flags.is_root) {
			fr_strerror_const("Attributes with the 'concat' flag MUST be at the root of the dictionary");
			return false;
		}

		if ((type != FR_TYPE_OCTETS) && (type != FR_TYPE_TLV)) {
			fr_strerror_const("Attributes with the 'concat' flag MUST be of data type 'octets' or 'tlv'");
			return false;
		}

		return true;	/* can't use any other flag */
	}

	/*
	 *	Tagged attributes can only be of two data types.  They
	 *	can, however, be VSAs.
	 */
	if (flag_has_tag(flags)) {
		if ((type != FR_TYPE_UINT32) && (type != FR_TYPE_STRING)) {
			fr_strerror_printf("The 'has_tag' flag can only be used for attributes of type 'integer' "
					   "or 'string'");
			return false;
		}

		if (!(parent->flags.is_root ||
		      ((parent->type == FR_TYPE_VENDOR) &&
		       (parent->parent && parent->parent->type == FR_TYPE_VSA)))) {
			fr_strerror_const("The 'has_tag' flag can only be used with RFC and VSA attributes");
			return false;
		}

		return true;
	}

	if (flag_extended(flags)) {
		if (type != FR_TYPE_TLV) {
			fr_strerror_const("The 'long' or 'extended' flag can only be used for attributes of type 'tlv'");
			return false;
		}

		if (!parent->flags.is_root) {
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
	if ((flags->subtype == FLAG_ENCRYPT_USER_PASSWORD) && (type != FR_TYPE_STRING)) {
		if (type != FR_TYPE_OCTETS) {
			fr_strerror_printf("The 'encrypt=1' flag can only be used with "
					   "attributes of type 'string'");
			return false;
		}

		if (flags->length == 0) {
			fr_strerror_printf("The 'encrypt=1' flag MUST be used with an explicit length for "
					   "'octets' data types");
			return false;
		}
	}

	switch (type) {
	case FR_TYPE_STRING:
		break;

	case FR_TYPE_TLV:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_UINT32:
	case FR_TYPE_OCTETS:
		if (flags->subtype != FLAG_ENCRYPT_ASCEND_SECRET) break;
		FALL_THROUGH;

	default:
		fr_strerror_printf("The 'encrypt' flag cannot be used with attributes of type '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
		return false;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_radius_dict_protocol;
fr_dict_protocol_t libfreeradius_radius_dict_protocol = {
	.name = "radius",
	.default_type_size = 1,
	.default_type_length = 1,
	.subtype_table = subtype_table,
	.subtype_table_len = NUM_ELEMENTS(subtype_table),
	.attr_valid = attr_valid,
};
