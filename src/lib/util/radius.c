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
 * @file radius.c
 * @brief Functions to send/receive radius packets.
 *
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <freeradius-devel/md5.h>
#include <freeradius-devel/udp.h>

#include <fcntl.h>
#include <ctype.h>

/*
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf

FR_NAME_NUMBER const fr_request_types[] = {
	{ "auth",	PW_CODE_ACCESS_REQUEST },
	{ "challenge",	PW_CODE_ACCESS_CHALLENGE },
	{ "acct",	PW_CODE_ACCOUNTING_REQUEST },
	{ "status",	PW_CODE_STATUS_SERVER },
	{ "disconnect",	PW_CODE_DISCONNECT_REQUEST },
	{ "coa",	PW_CODE_COA_REQUEST },
	{ "auto",	PW_CODE_UNDEFINED },

	{ NULL, 0}
};

/*
 *	The maximum number of attributes which we allow in an incoming
 *	request.  If there are more attributes than this, the request
 *	is rejected.
 *
 *	This helps to minimize the potential for a DoS, when an
 *	attacker spoofs Access-Request packets, which don't have a
 *	Message-Authenticator attribute.  This means that the packet
 *	is unsigned, and the attacker can use resources on the server,
 *	even if the end request is rejected.
 */
uint32_t fr_max_attributes = 0;


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
	"IP-Address-Allocate",
	"IP-Address-Release",			//!< 50
};


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
		FR_DEBUG_STRERROR_PRINTF("Invalid data from %s: %s",
					 inet_ntop(src_ipaddr->af, &src_ipaddr->ipaddr, buffer, sizeof(buffer)),
					 fr_strerror());
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

		if (msg[0] != PW_MESSAGE_AUTHENTICATOR) {
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
		case PW_CODE_ACCOUNTING_RESPONSE:
			if (!original) goto need_original;
			if (original[0] == PW_CODE_STATUS_SERVER) goto do_ack;
			goto do_response;

		case PW_CODE_ACCOUNTING_REQUEST:
		case PW_CODE_DISCONNECT_REQUEST:
		case PW_CODE_DISCONNECT_ACK:
		case PW_CODE_DISCONNECT_NAK:
		case PW_CODE_COA_REQUEST:
		case PW_CODE_COA_ACK:
		case PW_CODE_COA_NAK:
			if (!original) goto need_original;

		do_response:
			memset(packet + 4, 0, AUTH_VECTOR_LEN);
			break;

		case PW_CODE_ACCESS_ACCEPT:
		case PW_CODE_ACCESS_REJECT:
		case PW_CODE_ACCESS_CHALLENGE:
		do_ack:
			memcpy(packet + 4, original + 4, AUTH_VECTOR_LEN);
			break;

		case PW_CODE_ACCESS_REQUEST:
		case PW_CODE_STATUS_SERVER:
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
	case PW_CODE_ACCOUNTING_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
	case PW_CODE_COA_REQUEST:
		memset(packet + 4, 0, AUTH_VECTOR_LEN);
		break;

	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_REJECT:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_ACCOUNTING_RESPONSE:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
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
	case PW_CODE_ACCESS_REQUEST:
	case PW_CODE_STATUS_SERVER:
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
 * @param packet to check
 * @param[in,out] packet_len_p the size of the packet data
 * @param require_ma to require Message-Authenticator
 * @param reason if not NULL, will have the failure reason written to where it points.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_radius_ok(uint8_t const *packet, size_t *packet_len_p, bool require_ma, decode_fail_t *reason)
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
	if (packet[0] == PW_CODE_STATUS_SERVER) require_ma = true;

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
		case PW_STATE:
			if (attr[1] > 2) packet->rounds = attr[2];
			break;
#endif

			/*
			 *	If there's an EAP-Message, we require
			 *	a Message-Authenticator.
			 */
		case PW_EAP_MESSAGE:
			require_ma = true;
			break;

		case PW_MESSAGE_AUTHENTICATOR:
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
	if ((fr_max_attributes > 0) &&
	    (num_attributes > fr_max_attributes)) {
		FR_DEBUG_STRERROR_PRINTF("Possible DoS attack - too many attributes in request (received %d, max %d are allowed).",
					 num_attributes, fr_max_attributes);
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

		if (msg[0] != PW_MESSAGE_AUTHENTICATOR) {
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
		fr_strerror_printf("unknown packet code");
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
	if ((packet[0] == PW_CODE_ACCESS_REQUEST) || (packet[0] == PW_CODE_STATUS_SERVER)) {
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
	}

	return 0;
}
