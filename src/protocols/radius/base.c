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
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <fcntl.h>
#include <ctype.h>

#include <freeradius-devel/util/base.h>

#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/udp.h>
#include "attrs.h"

static int instance_count = 0;

fr_dict_t *dict_freeradius;
fr_dict_t *dict_radius;

extern fr_dict_autoload_t libfreeradius_radius_dict[];
fr_dict_autoload_t libfreeradius_radius_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_raw_attribute;
fr_dict_attr_t const *attr_chap_challenge;
fr_dict_attr_t const *attr_chargeable_user_identity;
fr_dict_attr_t const *attr_eap_message;
fr_dict_attr_t const *attr_message_authenticator;
fr_dict_attr_t const *attr_state;
fr_dict_attr_t const *attr_vendor_specific;

extern fr_dict_attr_autoload_t libfreeradius_radius_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_radius_dict_attr[] = {
	{ .out = &attr_raw_attribute, .name = "Raw-Attribute", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chargeable_user_identity, .name = "Chargeable-User-Identity", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_VSA, .dict = &dict_radius },
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
	[FR_TYPE_INVALID]		= {~0, 0},	//!< Ensure array starts at 0 (umm?)

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

	[FR_TYPE_DATE]			= {4, 4},
	[FR_TYPE_ABINARY]		= {32, ~0},

	[FR_TYPE_TLV]			= {2, ~0},
	[FR_TYPE_STRUCT]		= {1, ~0},

	[FR_TYPE_EXTENDED]		= {2, ~0},
	[FR_TYPE_LONG_EXTENDED]		= {3, ~0},

	[FR_TYPE_VSA]			= {4, ~0},
	[FR_TYPE_EVS]			= {6, ~0},

	[FR_TYPE_MAX]			= {~0, 0}	//!< Ensure array covers all types.
};

/*
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf_push

FR_NAME_NUMBER const fr_request_types[] = {
	{ "auth",	FR_CODE_ACCESS_REQUEST },
	{ "challenge",	FR_CODE_ACCESS_CHALLENGE },
	{ "acct",	FR_CODE_ACCOUNTING_REQUEST },
	{ "status",	FR_CODE_STATUS_SERVER },
	{ "disconnect",	FR_CODE_DISCONNECT_REQUEST },
	{ "coa",	FR_CODE_COA_REQUEST },
	{ "auto",	FR_CODE_UNDEFINED },

	{ NULL, 0}
};

char const *fr_packet_codes[FR_MAX_PACKET_CODE] = {
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

bool const fr_request_packets[FR_CODE_MAX + 1] = {
	[FR_CODE_ACCESS_REQUEST] = true,
	[FR_CODE_ACCOUNTING_REQUEST] = true,
	[FR_CODE_STATUS_SERVER] = true,
	[FR_CODE_COA_REQUEST] = true,
	[FR_CODE_DISCONNECT_REQUEST] = true,
};

/*
 *	For request packets which have the Request Authenticator being
 *	all zeros.  We need to decode attributes using a Request
 *	Authenticator of all zeroes, but the actual Request
 *	Authenticator contains the signature of the packet, so we
 *	can't use that.
 */
static uint8_t nullvector[AUTH_VECTOR_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/** Return the on-the-wire length of an attribute value
 *
 * @param[in] vp to return the length of.
 * @return the length of the attribute.
 */
size_t fr_radius_attr_len(VALUE_PAIR const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		return vp->vp_length;

	default:
		return fr_radius_attr_sizes[vp->vp_type][0];

	case FR_TYPE_STRUCTURAL:
		if (!fr_cond_assert(0)) return 0;
	}
}

/**  Do Ascend-Send / Recv-Secret calculation.
 *
 * The secret is hidden by xoring with a MD5 digest created from
 * the RADIUS shared secret and the authentication vector.
 * We put them into MD5 in the reverse order from that used when
 * encrypting passwords to RADIUS.
 */
void fr_radius_ascend_secret(uint8_t *digest, uint8_t const *vector, char const *secret, uint8_t const *value)
{
	FR_MD5_CTX context;
	int	     i;

	fr_md5_init(&context);
	fr_md5_update(&context, vector, AUTH_VECTOR_LEN);
	fr_md5_update(&context, (uint8_t const *) secret, talloc_array_length(secret) - 1);
	fr_md5_final(digest, &context);

	for (i = 0; i < AUTH_VECTOR_LEN; i++ ) digest[i] ^= value[i];
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
 *	- >= RADIUS_HDR_LEN on success. This is the packet length as specified in the header.
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
	if (packet_len < RADIUS_HDR_LEN) {
		FR_DEBUG_STRERROR_PRINTF("Expected at least " STRINGIFY(RADIUS_HDR_LEN)  " bytes of packet "
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
 * @param packet the raw RADIUS packet (request or response)
 * @param original the raw original request (if this is a response)
 * @param secret the shared secret
 * @param secret_len the length of the secret
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_sign(uint8_t *packet, uint8_t const *original,
		   uint8_t const *secret, size_t secret_len)
{
	uint8_t *msg, *end;
	size_t packet_len = (packet[2] << 8) | packet[3];
	FR_MD5_CTX	context;

	if (packet_len < RADIUS_HDR_LEN) {
		fr_strerror_printf("Packet must be encoded before calling fr_radius_sign()");
		return -1;
	}

	/*
	 *	Find Message-Authenticator.  Its value has to be
	 *	calculated before we calculate the Request
	 *	Authenticator or the Response Authenticator.
	 */
	msg = packet + RADIUS_HDR_LEN;
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
			fr_strerror_printf("Message-Authenticator is too small");
			return -1;
		}

		switch (packet[0]) {
		case FR_CODE_ACCOUNTING_RESPONSE:
		case FR_CODE_DISCONNECT_ACK:
		case FR_CODE_DISCONNECT_NAK:
		case FR_CODE_COA_ACK:
		case FR_CODE_COA_NAK:
			if (!original) goto need_original;
			if (original[0] == FR_CODE_STATUS_SERVER) goto do_ack;
			/* FALL-THROUGH */

		case FR_CODE_ACCOUNTING_REQUEST:
		case FR_CODE_DISCONNECT_REQUEST:
		case FR_CODE_COA_REQUEST:
			memset(packet + 4, 0, AUTH_VECTOR_LEN);
			break;

		case FR_CODE_ACCESS_ACCEPT:
		case FR_CODE_ACCESS_REJECT:
		case FR_CODE_ACCESS_CHALLENGE:
		do_ack:
			if (!original) goto need_original;
			memcpy(packet + 4, original + 4, AUTH_VECTOR_LEN);
			break;

		case FR_CODE_ACCESS_REQUEST:
		case FR_CODE_STATUS_SERVER:
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
		memset(msg + 2, 0, AUTH_VECTOR_LEN);
		fr_hmac_md5(msg + 2, packet, packet_len, secret, secret_len);
		break;
	}

	/*
	 *	Initialize the request authenticator.
	 */
	switch (packet[0]) {
	case FR_CODE_ACCOUNTING_REQUEST:
	case FR_CODE_DISCONNECT_REQUEST:
	case FR_CODE_COA_REQUEST:
		memset(packet + 4, 0, AUTH_VECTOR_LEN);
		break;

	case FR_CODE_ACCESS_ACCEPT:
	case FR_CODE_ACCESS_REJECT:
	case FR_CODE_ACCESS_CHALLENGE:
	case FR_CODE_ACCOUNTING_RESPONSE:
	case FR_CODE_DISCONNECT_ACK:
	case FR_CODE_DISCONNECT_NAK:
	case FR_CODE_COA_ACK:
	case FR_CODE_COA_NAK:
	case FR_CODE_PROTOCOL_ERROR:
		if (!original) {
		need_original:
			fr_strerror_printf("Cannot sign response packet without a request packet");
			return -1;
		}
		memcpy(packet + 4, original + 4, AUTH_VECTOR_LEN);
		break;

		/*
		 *	The Request Authenticator is random numbers.
		 *	We don't need to sign anything else, so
		 *	return.
		 */
	case FR_CODE_ACCESS_REQUEST:
	case FR_CODE_STATUS_SERVER:
		return 0;

	default:
	bad_packet:
		fr_strerror_printf("Cannot sign unknown packet code %u", packet[0]);
		return -1;
	}

	/*
	 *	Request / Response Authenticator = MD5(packet + secret)
	 */
	fr_md5_init(&context);
	fr_md5_update(&context, packet, packet_len);
	fr_md5_update(&context, secret, secret_len);
	fr_md5_final(packet + 4, &context);

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
	if (packet_len < RADIUS_HDR_LEN) {
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
	    (packet[0] >= FR_MAX_PACKET_CODE)) {
		FR_DEBUG_STRERROR_PRINTF("unknown packet code %d", packet[0]);
		failure = DECODE_FAIL_UNKNOWN_PACKET_CODE;
		goto finish;
	}

	/*
	 *	Message-Authenticator is required in Status-Server
	 *	packets, otherwise they can be trivially forged.
	 */
	if (packet[0] == FR_CODE_STATUS_SERVER) require_ma = true;

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
	if (totallen < RADIUS_HDR_LEN) {
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
	attr = packet + RADIUS_HDR_LEN;
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
			if (attr[1] != 2 + AUTH_VECTOR_LEN) {
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
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_radius_verify(uint8_t *packet, uint8_t const *original,
		     uint8_t const *secret, size_t secret_len)
{
	int rcode;
	uint8_t *msg, *end;
	size_t packet_len = (packet[2] << 8) | packet[3];
	uint8_t request_authenticator[AUTH_VECTOR_LEN];
	uint8_t message_authenticator[AUTH_VECTOR_LEN];

	if (packet_len < RADIUS_HDR_LEN) {
		fr_strerror_printf("invalid packet length %zd", packet_len);
		return -1;
	}

	memcpy(request_authenticator, packet + 4, sizeof(request_authenticator));

	/*
	 *	Find Message-Authenticator.  Its value has to be
	 *	calculated before we calculate the Request
	 *	Authenticator or the Response Authenticator.
	 */
	msg = packet + RADIUS_HDR_LEN;
	end = packet + packet_len;

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
			fr_strerror_printf("too small Message-Authenticator");
			return -1;
		}

		/*
		 *	Found it, save a copy.
		 */
		memcpy(message_authenticator, msg + 2, sizeof(message_authenticator));
		break;
	}

	/*
	 *	Implement verification as a signature, followed by
	 *	checking our signature against the sent one.  This is
	 *	slightly more CPU work than having verify-specific
	 *	functions, but it ends up being cleaner in the code.
	 */
	rcode = fr_radius_sign(packet, original, secret, secret_len);
	if (rcode < 0) {
		fr_strerror_printf_push("Failed calculating correct authenticator");
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

		fr_strerror_printf("invalid Message-Authenticator (shared secret is incorrect)");
		return -1;
	}

	/*
	 *	These are random numbers, so there's no point in
	 *	comparing them.
	 */
	if ((packet[0] == FR_CODE_ACCESS_REQUEST) || (packet[0] == FR_CODE_STATUS_SERVER)) {
		return 0;
	}

	/*
	 *	Check the Request Authenticator.
	 */
	if (fr_digest_cmp(request_authenticator, packet + 4, sizeof(request_authenticator)) != 0) {
		memcpy(packet + 4, request_authenticator, sizeof(request_authenticator));
		if (original) {
			fr_strerror_printf("invalid Response Authenticator (shared secret is incorrect)");
		} else {
			fr_strerror_printf("invalid Request Authenticator (shared secret is incorrect)");
		}
		return -1;
	}

	return 0;
}

/** Encode VPS into a raw RADIUS packet.
 *
 */
ssize_t fr_radius_encode(uint8_t *packet, size_t packet_len, uint8_t const *original,
			 char const *secret, UNUSED size_t secret_len, int code, int id, VALUE_PAIR *vps)
{
	uint8_t			*ptr;
	int			total_length;
	int			len;
	VALUE_PAIR const	*vp;
	fr_cursor_t		cursor;
	fr_radius_ctx_t		packet_ctx;

	packet_ctx.secret = secret;
	packet_ctx.vector = packet + 4;

	/*
	 *	The RADIUS header can't do more than 64K of data.
	 */
	if (packet_len > 65535) packet_len = 65535;

	switch (code) {
	case FR_CODE_ACCESS_REQUEST:
	case FR_CODE_STATUS_SERVER:
		break;

	case FR_CODE_ACCESS_ACCEPT:
	case FR_CODE_ACCESS_REJECT:
	case FR_CODE_ACCESS_CHALLENGE:
	case FR_CODE_ACCOUNTING_RESPONSE:
	case FR_CODE_COA_ACK:
	case FR_CODE_COA_NAK:
	case FR_CODE_DISCONNECT_ACK:
	case FR_CODE_DISCONNECT_NAK:
	case FR_CODE_PROTOCOL_ERROR:
		if (!original) {
			fr_strerror_printf("Cannot encode response without request");
			return -1;
		}
		packet_ctx.vector = original + 4;
		memcpy(packet + 4, packet_ctx.vector, AUTH_VECTOR_LEN);
		break;

	case FR_CODE_ACCOUNTING_REQUEST:
		packet_ctx.vector = nullvector;
		memcpy(packet + 4, packet_ctx.vector, AUTH_VECTOR_LEN);
		break;

	case FR_CODE_COA_REQUEST:
	case FR_CODE_DISCONNECT_REQUEST:
		packet_ctx.vector = nullvector;
		memcpy(packet + 4, packet_ctx.vector, AUTH_VECTOR_LEN);
		break;

	default:
		fr_strerror_printf("Cannot encode unknown packet code %d", code);
		return -1;
	}

	packet[0] = code;
	packet[1] = id;
	packet[2] = 0;
	packet[3] = total_length = RADIUS_HDR_LEN;

	/*
	 *	Load up the configuration values for the user
	 */
	ptr = packet + RADIUS_HDR_LEN;

	/*
	 *	If we're sending Protocol-Error, add in
	 *	Original-Packet-Code manually.  If the user adds it
	 *	later themselves, well, too bad.
	 */
	if (code == FR_CODE_PROTOCOL_ERROR) {
		size_t room;

		room = (packet + packet_len) - ptr;
		if (room < 7) {
			fr_strerror_printf("Insufficient room to encode attributes");
			return -1;
		}

		ptr[0] = 241;
		ptr[1] = 7;
		ptr[2] = 4;	/* Original-Packet-Code */
		ptr[3] = 0;
		ptr[4] = 0;
		ptr[5] = 0;
		ptr[6] = original[0];

		ptr += 7;
		total_length += 7;
	}

	/*
	 *	Loop over the reply attributes for the packet.
	 */
	fr_cursor_init(&cursor, &vps);
	while ((vp = fr_cursor_current(&cursor))) {
		size_t		last_len, room;
		char const	*last_name = NULL;

		VP_VERIFY(vp);

		room = (packet + packet_len) - ptr;

		/*
		 *	Ignore non-wire attributes, but allow extended
		 *	attributes.
		 */
		if (vp->da->flags.internal) {
#ifndef NDEBUG
			/*
			 *	Permit the admin to send BADLY formatted
			 *	attributes with a debug build.
			 */
			if (vp->da == attr_raw_attribute) {
				if (vp->vp_length > room) {
					len = room;
				} else {
					len = vp->vp_length;
				}

				memcpy(ptr, vp->vp_octets, len);
				fr_cursor_next(&cursor);
				goto next;
			}
#endif
			fr_cursor_next(&cursor);
			continue;
		}

		/*
		 *	Set the Message-Authenticator to the correct
		 *	length and initial value.
		 */
		if (vp->da == attr_message_authenticator) {
			last_len = 16;
		} else {
			last_len = vp->vp_length;
		}
		last_name = vp->da->name;

		if (room <= 2) break;

		len = fr_radius_encode_pair(ptr, room, &cursor, &packet_ctx);
		if (len < 0) return -1;

		/*
		 *	Failed to encode the attribute, likely because
		 *	the packet is full.
		 */
		if (len == 0) {
			if (last_len != 0) {
				fr_strerror_printf("WARNING: Failed encoding attribute %s\n", last_name);
				break;
			} else {
				fr_strerror_printf("WARNING: Skipping zero-length attribute %s\n", last_name);
			}
		}

#ifndef NDEBUG
	next:			/* Used only for Raw-Attribute */
#endif
		ptr += len;
		total_length += len;
	} /* done looping over all attributes */

	/*
	 *	Fill in the rest of the fields, and copy the data over
	 *	from the local stack to the newly allocated memory.
	 *
	 *	Yes, all this 'memcpy' is slow, but it means
	 *	that we only allocate the minimum amount of
	 *	memory for a request.
	 */
	packet[2] = (total_length >> 8) & 0xff;
	packet[3] = total_length & 0xff;

	return total_length;
}

/** Decode a raw RADIUS packet into VPs.
 *
 */
ssize_t	fr_radius_decode(TALLOC_CTX *ctx, uint8_t *packet, size_t packet_len, uint8_t const *original,
			 char const *secret, UNUSED size_t secret_len, VALUE_PAIR **vps)
{
	ssize_t			slen;
	fr_cursor_t		cursor;
	uint8_t const		*attr, *end;
	fr_radius_ctx_t		packet_ctx;

	packet_ctx.secret = secret;
	packet_ctx.vector = original + 4;
	packet_ctx.root = fr_dict_root(fr_dict_internal);

	fr_cursor_init(&cursor, vps);

	attr = packet + 20;
	end = packet + packet_len;

	/*
	 *	The caller MUST have called fr_radius_ok() first.  If
	 *	he doesn't, all hell breaks loose.
	 */
	while (attr < end) {
		slen = fr_radius_decode_pair(ctx, &cursor, attr, (end - attr), &packet_ctx);
		if (slen < 0) return slen;

		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - attr))) return -1;

		attr += slen;
	}

	/*
	 *	We've parsed the whole packet, return that.
	 */
	return packet_len;
}


static void print_hex_data(uint8_t const *ptr, int attrlen, int depth)
{
	int i;
	static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

	for (i = 0; i < attrlen; i++) {
		if ((i > 0) && ((i & 0x0f) == 0x00))
			fprintf(fr_log_fp, "%.*s", depth, tabs);
		fprintf(fr_log_fp, "%02x ", ptr[i]);
		if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
	}
	if ((i & 0x0f) != 0) fprintf(fr_log_fp, "\n");
}

int fr_radius_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_radius_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_radius_dict_attr) < 0) return -1;

	return 0;
}

void fr_radius_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_radius_dict);
}

/** Print a raw RADIUS packet as hex.
 *
 */
void fr_radius_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len)
{
	int i;
	uint8_t const *attr, *end;

	if ((packet[0] > 0) && (packet[0] < FR_MAX_PACKET_CODE)) {
		fprintf(fp, "  Code:\t\t%s\n", fr_packet_codes[packet[0]]);
	} else {
		fprintf(fp, "  Code:\t\t%u\n", packet[0]);
	}

	fprintf(fp, "  Id:\t\t%u\n", packet[1]);
	fprintf(fp, "  Length:\t%u\n", ((packet[2] << 8) |
				   (packet[3])));
	fprintf(fp, "  Vector:\t");

	for (i = 4; i < 20; i++) {
		fprintf(fp, "%02x", packet[i]);
	}
	fprintf(fp, "\n");

	if (packet_len <= 20) return;

	for (attr = packet + 20, end = packet + packet_len;
	     attr < end;
	     attr += attr[1]) {
		int offset;
		unsigned int vendor = 0;

		fprintf(fp, "\t\t");

		fprintf(fp, "%02x  %02x  ", attr[0], attr[1]);

#ifndef NDEBUG
		if (attr[1] < 2) break; /* Coverity */
#endif

		if ((attr[0] == FR_VENDOR_SPECIFIC) &&
		    (attr[1] > 6)) {
			vendor = (attr[2] << 25) | (attr[3] << 16) | (attr[4] << 8) | attr[5];
			fprintf(fp, "%02x%02x%02x%02x (%u)  ",
				attr[2], attr[3], attr[4], attr[5], vendor);
			offset = 6;
		} else {
			offset = 2;
		}

		print_hex_data(attr + offset, attr[1] - offset, 3);
	}
}

