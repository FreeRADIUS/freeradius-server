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

#ifdef WITH_UDPFROMTO
#include <freeradius-devel/udpfromto.h>
#endif

typedef struct radius_packet_t {
	uint8_t	code;
	uint8_t	id;
	uint8_t	length[2];
	uint8_t	vector[AUTH_VECTOR_LEN];
	uint8_t	data[1];
} radius_packet_t;

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
FILE *fr_log_fp = NULL;


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

static _Thread_local fr_randctx fr_rand_pool;		//!< A pool of pre-generated random integers
static _Thread_local bool fr_rand_initialized = false;

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

void fr_printf_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ((fr_debug_lvl == 0) || !fr_log_fp) {
		va_end(ap);
		return;
	}

	vfprintf(fr_log_fp, fmt, ap);
	va_end(ap);

	return;
}

void fr_radius_print_hex(RADIUS_PACKET const *packet)
{
	int i;

	if (!packet->data || !fr_log_fp) return;

	fprintf(fr_log_fp, "  Socket:\t%d\n", packet->sockfd);
#ifdef WITH_TCP
	fprintf(fr_log_fp, "  Proto:\t%d\n", packet->proto);
#endif

	if (packet->src_ipaddr.af == AF_INET) {
		char buffer[INET6_ADDRSTRLEN];

		fprintf(fr_log_fp, "  Src IP:\t%s\n",
			inet_ntop(packet->src_ipaddr.af,
				  &packet->src_ipaddr.ipaddr,
				  buffer, sizeof(buffer)));
		fprintf(fr_log_fp, "    port:\t%u\n", packet->src_port);

		fprintf(fr_log_fp, "  Dst IP:\t%s\n",
			inet_ntop(packet->dst_ipaddr.af,
				  &packet->dst_ipaddr.ipaddr,
				  buffer, sizeof(buffer)));
		fprintf(fr_log_fp, "    port:\t%u\n", packet->dst_port);
	}

	if (packet->data[0] < FR_MAX_PACKET_CODE) {
		fprintf(fr_log_fp, "  Code:\t\t(%d) %s\n", packet->data[0], fr_packet_codes[packet->data[0]]);
	} else {
		fprintf(fr_log_fp, "  Code:\t\t%u\n", packet->data[0]);
	}
	fprintf(fr_log_fp, "  Id:\t\t%u\n", packet->data[1]);
	fprintf(fr_log_fp, "  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	fprintf(fr_log_fp, "  Vector:\t");
	for (i = 4; i < 20; i++) {
		fprintf(fr_log_fp, "%02x", packet->data[i]);
	}
	fprintf(fr_log_fp, "\n");

	if (packet->data_len > 20) {
		int total;
		uint8_t const *ptr;
		fprintf(fr_log_fp, "  Data:");

		total = packet->data_len - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;
			unsigned int vendor = 0;

			fprintf(fr_log_fp, "\t\t");
			if (total < 2) { /* too short */
				fprintf(fr_log_fp, "%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					fprintf(fr_log_fp, "%02x ", ptr[i]);
				}
				break;
			}

			fprintf(fr_log_fp, "%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;

			if ((ptr[0] == PW_VENDOR_SPECIFIC) &&
			    (attrlen > 4)) {
				vendor = (ptr[3] << 16) | (ptr[4] << 8) | ptr[5];
				fprintf(fr_log_fp, "%02x%02x%02x%02x (%u)  ",
				       ptr[2], ptr[3], ptr[4], ptr[5], vendor);
				attrlen -= 4;
				ptr += 6;
				total -= 6;

			} else {
				ptr += 2;
				total -= 2;
			}

			print_hex_data(ptr, attrlen, 3);

			ptr += attrlen;
			total -= attrlen;
		}
	}
	fflush(stdout);
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

/** Wrapper for recvfrom, which handles recvfromto, IPv6, and all possible combinations
 *
 */
static ssize_t rad_recvfrom(int sockfd, RADIUS_PACKET *packet, int flags)
{
	ssize_t			data_len;

	data_len = fr_radius_recv_header(sockfd, &packet->src_ipaddr, &packet->src_port, &packet->code);
	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EINTR)) return 0;
		return -1;
	}

	if (data_len == 0) return -1; /* invalid packet */

	packet->data = talloc_array(packet, uint8_t, data_len);
	if (!packet->data) return -1;

	packet->data_len = data_len;

	return udp_recv(sockfd, packet->data, packet->data_len, flags,
			&packet->src_ipaddr, &packet->src_port,
			&packet->dst_ipaddr, &packet->dst_port,
			&packet->if_index, &packet->timestamp);
}

/** Sign a previously encoded packet
 *
 */
int fr_radius_packet_sign(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
		   char const *secret)
{
	radius_packet_t	*hdr = (radius_packet_t *)packet->data;

	/*
	 *	It wasn't assigned an Id, this is bad!
	 */
	if (packet->id < 0) {
		fr_strerror_printf("ERROR: RADIUS packets must be assigned an Id");
		return -1;
	}

	if (!packet->data || (packet->data_len < RADIUS_HDR_LEN) ||
	    (packet->offset < 0)) {
		fr_strerror_printf("ERROR: You must call fr_radius_encode() before fr_radius_packet_sign()");
		return -1;
	}

	/*
	 *	Set up the authentication vector with zero, or with
	 *	the original vector, prior to signing.
	 */
	switch (packet->code) {
	case PW_CODE_ACCOUNTING_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
	case PW_CODE_COA_REQUEST:
		memset(packet->vector, 0, AUTH_VECTOR_LEN);
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
			fr_strerror_printf("ERROR: Cannot sign response packet without a request packet");
			return -1;
		}
		memcpy(packet->vector, original->vector, AUTH_VECTOR_LEN);
		break;

	case PW_CODE_ACCESS_REQUEST:
	case PW_CODE_STATUS_SERVER:
		break;		/* packet->vector is already random bytes */
	}

	/*
	 *	If there's a Message-Authenticator, update it
	 *	now.
	 */
	if (packet->offset > 0) {
		uint8_t calc_auth_vector[AUTH_VECTOR_LEN];

		switch (packet->code) {
		case PW_CODE_ACCOUNTING_RESPONSE:
			if (original && original->code == PW_CODE_STATUS_SERVER) {
				goto do_ack;
			}

		case PW_CODE_ACCOUNTING_REQUEST:
		case PW_CODE_DISCONNECT_REQUEST:
		case PW_CODE_DISCONNECT_ACK:
		case PW_CODE_DISCONNECT_NAK:
		case PW_CODE_COA_REQUEST:
		case PW_CODE_COA_ACK:
		case PW_CODE_COA_NAK:
			memset(hdr->vector, 0, AUTH_VECTOR_LEN);
			break;

		do_ack:
		case PW_CODE_ACCESS_ACCEPT:
		case PW_CODE_ACCESS_REJECT:
		case PW_CODE_ACCESS_CHALLENGE:
			memcpy(hdr->vector, original->vector, AUTH_VECTOR_LEN);
			break;

		case PW_CODE_ACCESS_REQUEST:
		case PW_CODE_STATUS_SERVER:
			break;
		}

		/*
		 *	Calculate the HMAC, and put it
		 *	into the Message-Authenticator
		 *	attribute.
		 */
		fr_hmac_md5(calc_auth_vector, packet->data, packet->data_len,
			    (uint8_t const *) secret, talloc_array_length(secret) - 1);
		memcpy(packet->data + packet->offset + 2,
		       calc_auth_vector, AUTH_VECTOR_LEN);
	}

	/*
	 *	Copy the request authenticator over to the packet.
	 */
	memcpy(hdr->vector, packet->vector, AUTH_VECTOR_LEN);

	/*
	 *	Switch over the packet code, deciding how to
	 *	sign the packet.
	 */
	switch (packet->code) {
		/*
		 *	Request packets are not signed, but
		 *	have a random authentication vector.
		 */
	case PW_CODE_ACCESS_REQUEST:
	case PW_CODE_STATUS_SERVER:
		break;

		/*
		 *	Reply packets are signed with the
		 *	authentication vector of the request.
		 */
	default:
		{
			uint8_t digest[16];

			FR_MD5_CTX	context;
			fr_md5_init(&context);
			fr_md5_update(&context, packet->data, packet->data_len);
			fr_md5_update(&context, (uint8_t const *) secret,
				     talloc_array_length(secret) - 1);
			fr_md5_final(digest, &context);

			memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
			memcpy(packet->vector, digest, AUTH_VECTOR_LEN);
			break;
		}
	}/* switch over packet codes */

	return 0;
}

/** Reply to the request
 *
 * Also attach reply attribute value pairs and any user message provided.
 */
int fr_radius_packet_send(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
		   char const *secret)
{
	/*
	 *	Maybe it's a fake packet.  Don't send it.
	 */
	if (!packet || (packet->sockfd < 0)) {
		return 0;
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		/*
		 *	Encode the packet.
		 */
		if (fr_radius_encode(packet, original, secret) < 0) {
			return -1;
		}

		/*
		 *	Re-sign it, including updating the
		 *	Message-Authenticator.
		 */
		if (fr_radius_packet_sign(packet, original, secret) < 0) {
			return -1;
		}

		/*
		 *	If packet->data points to data, then we print out
		 *	the VP list again only for debugging.
		 */
	}

#ifndef NDEBUG
	if ((fr_debug_lvl > 3) && fr_log_fp) fr_radius_print_hex(packet);
#endif

#ifdef WITH_TCP
	/*
	 *	If the socket is TCP, call write().  Calling sendto()
	 *	is allowed on some platforms, but it's not nice.  Even
	 *	worse, if UDPFROMTO is defined, we *can't* use it on
	 *	TCP sockets.  So... just call write().
	 */
	if (packet->proto == IPPROTO_TCP) {
		ssize_t rcode;

		rcode = write(packet->sockfd, packet->data, packet->data_len);
		if (rcode >= 0) return rcode;

		fr_strerror_printf("sendto failed: %s", fr_syserror(errno));
		return -1;
	}
#endif

	/*
	 *	And send it on it's way.
	 */
	return udp_send(packet->sockfd, packet->data, packet->data_len, 0,
			&packet->src_ipaddr, packet->src_port, packet->if_index,
			&packet->dst_ipaddr, packet->dst_port);
}

/** Do a comparison of two authentication digests by comparing the FULL digest
 *
 * Otherwise, the server can be subject to timing attacks that allow attackers
 * find a valid message authenticator.
 *
 * http://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf
 */
int fr_radius_digest_cmp(uint8_t const *a, uint8_t const *b, size_t length)
{
	int result = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		result |= a[i] ^ b[i];
	}

	return result;		/* 0 is OK, !0 is !OK, just like memcmp */
}


/** Validates the requesting client NAS
 *
 * Calculates the request Authenticator based on the clients private key.
 */
static int calc_acctdigest(RADIUS_PACKET *packet, char const *secret)
{
	uint8_t		digest[AUTH_VECTOR_LEN];
	FR_MD5_CTX		context;

	/*
	 *	Zero out the auth_vector in the received packet.
	 *	Then append the shared secret to the received packet,
	 *	and calculate the MD5 sum. This must be the same
	 *	as the original MD5 sum (packet->vector).
	 */
	memset(packet->data + 4, 0, AUTH_VECTOR_LEN);

	/*
	 *  MD5(packet + secret);
	 */
	fr_md5_init(&context);
	fr_md5_update(&context, packet->data, packet->data_len);
	fr_md5_update(&context, (uint8_t const *) secret, talloc_array_length(secret) - 1);
	fr_md5_final(digest, &context);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	if (fr_radius_digest_cmp(digest, packet->vector, AUTH_VECTOR_LEN) != 0) return 2;
	return 0;
}


/** Validates the requesting client NAS
 *
 * Calculates the response Authenticator based on the clients
 * private key.
 */
static int calc_replydigest(RADIUS_PACKET *packet, RADIUS_PACKET *original,
			    char const *secret)
{
	uint8_t		calc_digest[AUTH_VECTOR_LEN];
	FR_MD5_CTX		context;

	/*
	 *	Very bad!
	 */
	if (original == NULL) {
		return 3;
	}

	/*
	 *  Copy the original vector in place.
	 */
	memcpy(packet->data + 4, original->vector, AUTH_VECTOR_LEN);

	/*
	 *  MD5(packet + secret);
	 */
	fr_md5_init(&context);
	fr_md5_update(&context, packet->data, packet->data_len);
	fr_md5_update(&context, (uint8_t const *) secret, talloc_array_length(secret) - 1);
	fr_md5_final(calc_digest, &context);

	/*
	 *  Copy the packet's vector back to the packet.
	 */
	memcpy(packet->data + 4, packet->vector, AUTH_VECTOR_LEN);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	if (fr_radius_digest_cmp(packet->vector, calc_digest, AUTH_VECTOR_LEN) != 0) return 2;
	return 0;
}


/** See how big of a packet is in the buffer.
 *
 * Packet is not 'const * const' because we may update data_len, if there's more data
 * in the UDP packet than in the RADIUS packet.
 *
 * @param data pointer to the packet buffer
 * @param data_len length of the packet buffer
 * @return
 *	<= 0 packet is bad.
 *      >0 how much of the data is a packet (can be larger than data_len)
 */
ssize_t fr_radius_len(uint8_t const *data, size_t data_len)
{
	size_t totallen;
	uint8_t const *attr, *end;

	/*
	 *	Want at least this much before doing anything else
	 */
	if (!data || (data_len < RADIUS_HDR_LEN)) return RADIUS_HDR_LEN;

	/*
	 *	We want at least this much data for a real RADIUS packet/
	 */
	totallen = (data[2] << 8) | data[3];
	if (data_len < totallen) return totallen;

	if (totallen == RADIUS_HDR_LEN) return totallen;

	attr = data + RADIUS_HDR_LEN;
	end = data + totallen;

	/*
	 *	Do a quick pass to sanity check it.
	 */
	while (attr < end) {
		if ((end - attr) < 2) return -(attr - data);

		if (attr[0] == 0) return -(attr - data);

		if (attr[1] < 2) return - (attr + 1 - data);

		if ((attr + attr[1]) > end) return -(attr + 1 - data);

		attr += attr[1];
	}

	return totallen;
}


/** See if the data pointed to by PTR is a valid RADIUS packet.
 *
 * Packet is not 'const * const' because we may update data_len, if there's more data
 * in the UDP packet than in the RADIUS packet.
 *
 * @param packet to check
 * @param require_ma to require Message-Authenticator
 * @param reason if not NULL, will have the failure reason written to where it points.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_radius_packet_ok(RADIUS_PACKET *packet, bool require_ma, decode_fail_t *reason)
{
	uint8_t			*attr;
	size_t			totallen;
	int			count;
	radius_packet_t		*hdr;
	char			host_ipaddr[INET6_ADDRSTRLEN];
	bool			seen_ma = false;
	uint32_t		num_attributes;
	decode_fail_t		failure = DECODE_FAIL_NONE;

	/*
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (packet->data_len < RADIUS_HDR_LEN) {
		FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: too short (received %zu < minimum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     packet->data_len, RADIUS_HDR_LEN);
		failure = DECODE_FAIL_MIN_LENGTH_PACKET;
		goto finish;
	}


	/*
	 *	Check for packets with mismatched size.
	 *	i.e. We've received 128 bytes, and the packet header
	 *	says it's 256 bytes long.
	 */
	totallen = (packet->data[2] << 8) | packet->data[3];
	hdr = (radius_packet_t *)packet->data;

	/*
	 *	Code of 0 is not understood.
	 *	Code of 16 or greate is not understood.
	 */
	if ((hdr->code == 0) ||
	    (hdr->code >= FR_MAX_PACKET_CODE)) {
		FR_DEBUG_STRERROR_PRINTF("Bad RADIUS packet from host %s: unknown packet code %d",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
			   hdr->code);
		failure = DECODE_FAIL_UNKNOWN_PACKET_CODE;
		goto finish;
	}

	/*
	 *	Message-Authenticator is required in Status-Server
	 *	packets, otherwise they can be trivially forged.
	 */
	if (hdr->code == PW_CODE_STATUS_SERVER) require_ma = true;

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
		FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: too short (length %zu < minimum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     totallen, RADIUS_HDR_LEN);
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
	if (packet->data_len < totallen) {
		FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: received %zu octets, packet length says %zu",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     packet->data_len, totallen);
		failure = DECODE_FAIL_MIN_LENGTH_MISMATCH;
		goto finish;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"Octets outside the range of the Length field MUST be
	 *	treated as padding and ignored on reception."
	 */
	if (packet->data_len > totallen) {
		/*
		 *	We're shortening the packet below, but just
		 *	to be paranoid, zero out the extra data.
		 */
		memset(packet->data + totallen, 0, packet->data_len - totallen);
		packet->data_len = totallen;
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
	attr = hdr->data;
	count = totallen - RADIUS_HDR_LEN;
	num_attributes = 0;

	while (count > 0) {
		/*
		 *	We need at least 2 bytes to check the
		 *	attribute header.
		 */
		if (count < 2) {
			FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: attribute header overflows the packet",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)));
			failure = DECODE_FAIL_HEADER_OVERFLOW;
			goto finish;
		}

		/*
		 *	Attribute number zero is NOT defined.
		 */
		if (attr[0] == 0) {
			FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: Invalid attribute 0",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)));
			failure = DECODE_FAIL_INVALID_ATTRIBUTE;
			goto finish;
		}

		/*
		 *	Attributes are at LEAST as long as the ID & length
		 *	fields.  Anything shorter is an invalid attribute.
		 */
		if (attr[1] < 2) {
			FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: attribute %u too short",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)),
				   attr[0]);
			failure = DECODE_FAIL_ATTRIBUTE_TOO_SHORT;
			goto finish;
		}

		/*
		 *	If there are fewer bytes in the packet than in the
		 *	attribute, it's a bad packet.
		 */
		if (count < attr[1]) {
			FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: attribute %u data overflows the packet",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)),
					   attr[0]);
			failure = DECODE_FAIL_ATTRIBUTE_OVERFLOW;
			goto finish;
		}

		/*
		 *	Sanity check the attributes for length.
		 */
		switch (attr[0]) {
		default:	/* don't do anything by default */
			break;

			/*
			 *	Track this for prioritizing ongoing EAP sessions.
			 */
		case PW_STATE:
			if (attr[1] > 2) packet->rounds = attr[2];
			break;

			/*
			 *	If there's an EAP-Message, we require
			 *	a Message-Authenticator.
			 */
		case PW_EAP_MESSAGE:
			require_ma = true;
			break;

		case PW_MESSAGE_AUTHENTICATOR:
			if (attr[1] != 2 + AUTH_VECTOR_LEN) {
				FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: Message-Authenticator has invalid length %d",
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     host_ipaddr, sizeof(host_ipaddr)),
					   attr[1] - 2);
				failure = DECODE_FAIL_MA_INVALID_LENGTH;
				goto finish;
			}
			seen_ma = true;
			break;
		}

		/*
		 *	FIXME: Look up the base 255 attributes in the
		 *	dictionary, and switch over their type.  For
		 *	integer/date/ip, the attribute length SHOULD
		 *	be 6.
		 */
		count -= attr[1];	/* grab the attribute length */
		attr += attr[1];
		num_attributes++;	/* seen one more attribute */
	}

	/*
	 *	If the attributes add up to a packet, it's allowed.
	 *
	 *	If not, we complain, and throw the packet away.
	 */
	if (count != 0) {
		FR_DEBUG_STRERROR_PRINTF("Malformed RADIUS packet from host %s: packet attributes do NOT exactly fill the packet",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)));
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
		FR_DEBUG_STRERROR_PRINTF("Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
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
		FR_DEBUG_STRERROR_PRINTF("Insecure packet from host %s:  Packet does not contain required Message-Authenticator attribute",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)));
		failure = DECODE_FAIL_MA_MISSING;
		goto finish;
	}

	/*
	 *	Fill RADIUS header fields
	 */
	packet->code = hdr->code;
	packet->id = hdr->id;
	memcpy(packet->vector, hdr->vector, AUTH_VECTOR_LEN);


	finish:

	if (reason) {
		*reason = failure;
	}
	return (failure == DECODE_FAIL_NONE);
}

/** Receive UDP client requests, and fill in the basics of a RADIUS_PACKET structure
 *
 */
RADIUS_PACKET *fr_radius_recv(TALLOC_CTX *ctx, int fd, int flags, bool require_ma)
{
	ssize_t data_len;
	RADIUS_PACKET		*packet;

	/*
	 *	Allocate the new request data structure
	 */
	packet = fr_radius_alloc(ctx, false);
	if (!packet) {
		fr_strerror_printf("out of memory");
		return NULL;
	}

	data_len = rad_recvfrom(fd, packet, flags);
	if (data_len < 0) {
		FR_DEBUG_STRERROR_PRINTF("Error receiving packet: %s", fr_syserror(errno));
		fr_radius_free(&packet);
		return NULL;
	}

#ifdef WITH_VERIFY_PTR
	/*
	 *	Double-check that the fields we want are filled in.
	 */
	if ((packet->src_ipaddr.af == AF_UNSPEC) ||
	    (packet->src_port == 0) ||
	    (packet->dst_ipaddr.af == AF_UNSPEC) ||
	    (packet->dst_port == 0)) {
		FR_DEBUG_STRERROR_PRINTF("Error receiving packet: %s", fr_syserror(errno));
		fr_radius_free(&packet);
		return NULL;
	}
#endif

	packet->data_len = data_len; /* unsigned vs signed */

	/*
	 *	If the packet is too big, then rad_recvfrom did NOT
	 *	allocate memory.  Instead, it just discarded the
	 *	packet.
	 */
	if (packet->data_len > MAX_PACKET_LEN) {
		FR_DEBUG_STRERROR_PRINTF("Discarding packet: Larger than RFC limitation of 4096 bytes");
		fr_radius_free(&packet);
		return NULL;
	}

	/*
	 *	Read no data.  Continue.
	 *	This check is AFTER the MAX_PACKET_LEN check above, because
	 *	if the packet is larger than MAX_PACKET_LEN, we also have
	 *	packet->data == NULL
	 */
	if ((packet->data_len == 0) || !packet->data) {
		FR_DEBUG_STRERROR_PRINTF("Empty packet: Socket is not ready");
		fr_radius_free(&packet);
		return NULL;
	}

	/*
	 *	See if it's a well-formed RADIUS packet.
	 */
	if (!fr_radius_packet_ok(packet, require_ma, NULL)) {
		fr_radius_free(&packet);
		return NULL;
	}

	/*
	 *	Remember which socket we read the packet from.
	 */
	packet->sockfd = fd;

	/*
	 *	FIXME: Do even more filtering by only permitting
	 *	certain IP's.  The problem is that we don't know
	 *	how to do this properly for all possible clients...
	 */

	/*
	 *	Explicitely set the VP list to empty.
	 */
	packet->vps = NULL;

#ifndef NDEBUG
	if ((fr_debug_lvl > 3) && fr_log_fp) fr_radius_print_hex(packet);
#endif

	return packet;
}

/** Verify the Request/Response Authenticator (and Message-Authenticator if present) of a packet
 *
 */
int fr_radius_packet_verify(RADIUS_PACKET *packet, RADIUS_PACKET *original, char const *secret)
{
	uint8_t		*ptr;
	int		length;
	int		attrlen;
	int		rcode;
	char		buffer[INET6_ADDRSTRLEN];

	if (!packet || !packet->data) return -1;

	/*
	 *	Before we allocate memory for the attributes, do more
	 *	sanity checking.
	 */
	ptr = packet->data + RADIUS_HDR_LEN;
	length = packet->data_len - RADIUS_HDR_LEN;
	while (length > 0) {
		uint8_t	msg_auth_vector[AUTH_VECTOR_LEN];
		uint8_t calc_auth_vector[AUTH_VECTOR_LEN];

		attrlen = ptr[1];

		switch (ptr[0]) {
		default:	/* don't do anything. */
			break;

			/*
			 *	Note that more than one Message-Authenticator
			 *	attribute is invalid.
			 */
		case PW_MESSAGE_AUTHENTICATOR:
			memcpy(msg_auth_vector, &ptr[2], sizeof(msg_auth_vector));
			memset(&ptr[2], 0, AUTH_VECTOR_LEN);

			switch (packet->code) {
			default:
				break;

			case PW_CODE_ACCOUNTING_RESPONSE:
				if (original &&
				    (original->code == PW_CODE_STATUS_SERVER)) {
					goto do_ack;
				}

			case PW_CODE_ACCOUNTING_REQUEST:
			case PW_CODE_DISCONNECT_REQUEST:
			case PW_CODE_COA_REQUEST:
				memset(packet->data + 4, 0, AUTH_VECTOR_LEN);
				break;

		do_ack:
			case PW_CODE_ACCESS_ACCEPT:
			case PW_CODE_ACCESS_REJECT:
			case PW_CODE_ACCESS_CHALLENGE:
			case PW_CODE_DISCONNECT_ACK:
			case PW_CODE_DISCONNECT_NAK:
			case PW_CODE_COA_ACK:
			case PW_CODE_COA_NAK:
				if (!original) {
					fr_strerror_printf("Cannot validate Message-Authenticator in response "
							   "packet without a request packet");
					return -1;
				}
				memcpy(packet->data + 4, original->vector, AUTH_VECTOR_LEN);
				break;
			}

			fr_hmac_md5(calc_auth_vector, packet->data, packet->data_len,
				    (uint8_t const *) secret, talloc_array_length(secret) - 1);
			if (fr_radius_digest_cmp(calc_auth_vector, msg_auth_vector,
						 sizeof(calc_auth_vector)) != 0) {
				fr_strerror_printf("Received packet from %s with invalid Message-Authenticator!  "
						   "(Shared secret is incorrect.)",
						   inet_ntop(packet->src_ipaddr.af,
							     &packet->src_ipaddr.ipaddr,
							     buffer, sizeof(buffer)));
				/* Silently drop packet, according to RFC 3579 */
				return -1;
			} /* else the message authenticator was good */

			/*
			 *	Reinitialize Authenticators.
			 */
			memcpy(&ptr[2], msg_auth_vector, AUTH_VECTOR_LEN);
			memcpy(packet->data + 4, packet->vector, AUTH_VECTOR_LEN);
			break;
		} /* switch over the attributes */

		ptr += attrlen;
		length -= attrlen;
	} /* loop over the packet, sanity checking the attributes */

	/*
	 *	It looks like a RADIUS packet, but we don't know what it is
	 *	so can't validate the authenticators.
	 */
	if ((packet->code == 0) || (packet->code >= FR_MAX_PACKET_CODE)) {
		fr_strerror_printf("Received Unknown packet code %d "
				   "from client %s port %d: Cannot validate Request/Response-Authenticator.",
				   packet->code,
				   inet_ntop(packet->src_ipaddr.af,
				             &packet->src_ipaddr.ipaddr,
				             buffer, sizeof(buffer)),
				   packet->src_port);
		return -1;
	}

	/*
	 *	Calculate and/or verify Request or Response Authenticator.
	 */
	switch (packet->code) {
	case PW_CODE_ACCESS_REQUEST:
	case PW_CODE_STATUS_SERVER:
		/*
		 *	The authentication vector is random
		 *	nonsense, invented by the client.
		 */
		break;

	case PW_CODE_COA_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
	case PW_CODE_ACCOUNTING_REQUEST:
		if (calc_acctdigest(packet, secret) > 1) {
			fr_strerror_printf("Received %s packet "
					   "from client %s with invalid Request-Authenticator!  "
					   "(Shared secret is incorrect.)",
					   fr_packet_codes[packet->code],
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)));
			return -1;
		}
		break;

		/* Verify the reply digest */
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_REJECT:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_ACCOUNTING_RESPONSE:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
		rcode = calc_replydigest(packet, original, secret);
		if (rcode > 1) {
			fr_strerror_printf("Received %s packet "
					   "from home server %s port %d with invalid Response-Authenticator!  "
					   "(Shared secret is incorrect.)",
					   fr_packet_codes[packet->code],
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)),
					   packet->src_port);
			return -1;
		}
		break;

	default:
		fr_strerror_printf("Received Unknown packet code %d "
				   "from client %s port %d: Cannot validate Request/Response-Authenticator",
				   packet->code,
				   inet_ntop(packet->src_ipaddr.af,
				             &packet->src_ipaddr.ipaddr,
				             buffer, sizeof(buffer)),
				   packet->src_port);
		return -1;
	}

	return 0;
}

/** Encode a packet
 *
 */
int fr_radius_encode(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
		     char const *secret)
{
	radius_packet_t		*hdr;
	uint8_t			*ptr;
	uint16_t		total_length;
	int			len;
	VALUE_PAIR const	*vp;
	vp_cursor_t		cursor;
	fr_radius_ctx_t encoder_ctx = { .packet = packet, .original = original, .secret = secret };

	/*
	 *	A 4K packet, aligned on 64-bits.
	 */
	uint64_t	data[MAX_PACKET_LEN / sizeof(uint64_t)];

	/*
	 *	Double-check some things based on packet code.
	 */
	switch (packet->code) {
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_REJECT:
	case PW_CODE_ACCESS_CHALLENGE:
		if (!original) {
			fr_strerror_printf("ERROR: Cannot sign response packet without a request packet");
			return -1;
		}
		break;

		/*
		 *	These packet vectors start off as all zero.
		 */
	case PW_CODE_ACCOUNTING_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
	case PW_CODE_COA_REQUEST:
		memset(packet->vector, 0, sizeof(packet->vector));
		break;

	default:
		break;
	}

	/*
	 *	Use memory on the stack, until we know how
	 *	large the packet will be.
	 */
	hdr = (radius_packet_t *) data;

	/*
	 *	Build standard header
	 */
	hdr->code = packet->code;
	hdr->id = packet->id;

	memcpy(hdr->vector, packet->vector, sizeof(hdr->vector));

	total_length = RADIUS_HDR_LEN;

	/*
	 *	Load up the configuration values for the user
	 */
	ptr = hdr->data;
	packet->offset = 0;

	/*
	 *	Loop over the reply attributes for the packet.
	 */
	fr_pair_cursor_init(&cursor, &packet->vps);
	while ((vp = fr_pair_cursor_current(&cursor))) {
		size_t		last_len, room;
		char const	*last_name = NULL;

		VERIFY_VP(vp);

		room = ((uint8_t *)data) + sizeof(data) - ptr;

		/*
		 *	Ignore non-wire attributes, but allow extended
		 *	attributes.
		 *
		 *	@fixme We should be able to get rid of this check
		 *	and just look at da->flags.internal
		 */
		if (vp->da->flags.internal || ((vp->da->vendor == 0) && (vp->da->attr >= 256))) {
#ifndef NDEBUG
			/*
			 *	Permit the admin to send BADLY formatted
			 *	attributes with a debug build.
			 */
			if (vp->da->attr == PW_RAW_ATTRIBUTE) {
				if (vp->vp_length > room) {
					len = room;
				} else {
					len = vp->vp_length;
				}

				memcpy(ptr, vp->vp_octets, len);
				fr_pair_cursor_next(&cursor);
				goto next;
			}
#endif
			fr_pair_cursor_next(&cursor);
			continue;
		}

		/*
		 *	Set the Message-Authenticator to the correct
		 *	length and initial value.
		 */
		if (!vp->da->vendor && (vp->da->attr == PW_MESSAGE_AUTHENTICATOR)) {
			/*
			 *	Cache the offset to the
			 *	Message-Authenticator
			 */
			packet->offset = total_length;
			last_len = 16;
		} else {
			last_len = vp->vp_length;
		}
		last_name = vp->da->name;

		if (room <= 2) break;

		len = fr_radius_encode_pair(ptr, room, &cursor, &encoder_ctx);
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
	packet->data_len = total_length;
	packet->data = talloc_array(packet, uint8_t, packet->data_len);
	if (!packet->data) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	memcpy(packet->data, hdr, packet->data_len);
	hdr = (radius_packet_t *) packet->data;

	total_length = htons(total_length);
	memcpy(hdr->length, &total_length, sizeof(total_length));

	return 0;
}

/** Calculate/check digest, and decode radius attributes
 *
 * @return
 *	- 0 on success
 *	- -1 on decoding error.
 */
int fr_radius_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, char const *secret)
{
	int			packet_length;
	uint32_t		num_attributes;
	uint8_t			*ptr;
	radius_packet_t		*hdr;
	VALUE_PAIR		*head = NULL;
	vp_cursor_t		cursor, out;
	fr_radius_ctx_t		decoder_ctx = {
					.original = original,
					.packet = packet,
					.secret = secret
				};
	/*
	 *	Extract attribute-value pairs
	 */
	hdr = (radius_packet_t *)packet->data;
	ptr = hdr->data;
	packet_length = packet->data_len - RADIUS_HDR_LEN;
	num_attributes = 0;

	fr_pair_cursor_init(&cursor, &head);

	/*
	 *	Loop over the attributes, decoding them into VPs.
	 */
	while (packet_length > 0) {
		ssize_t my_len;

		/*
		 *	This may return many VPs
		 */
		my_len = fr_radius_decode_pair(packet, &cursor, fr_dict_root(fr_dict_internal),
					       ptr, packet_length, &decoder_ctx);
		if (my_len < 0) {
			fr_pair_list_free(&head);
			return -1;
		}

		/*
		 *	This should really be an assertion.
		 */
		if (my_len == 0) break;

		/*
		 *	Count the ones which were just added
		 */
		while (fr_pair_cursor_next(&cursor)) num_attributes++;

		/*
		 *	VSA's may not have been counted properly in
		 *	fr_radius_packet_ok() above, as it is hard to count
		 *	then without using the dictionary.  We
		 *	therefore enforce the limits here, too.
		 */
		if ((fr_max_attributes > 0) && (num_attributes > fr_max_attributes)) {
			char host_ipaddr[INET6_ADDRSTRLEN];

			fr_pair_list_free(&head);
			fr_strerror_printf("Possible DoS attack from host %s: Too many attributes in request "
					   "(received %d, max %d are allowed)",
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     host_ipaddr, sizeof(host_ipaddr)),
					   num_attributes, fr_max_attributes);
			return -1;
		}

		ptr += my_len;
		packet_length -= my_len;
	}

	fr_pair_cursor_init(&out, &packet->vps);
	fr_pair_cursor_last(&out);		/* Move insertion point to the end of the list */
	fr_pair_cursor_merge(&out, head);

	/*
	 *	Merge information from the outside world into our
	 *	random pool.
	 */
	fr_rand_seed(packet->data, RADIUS_HDR_LEN);

	return 0;
}

/** Seed the random number generator
 *
 * May be called any number of times.
 */
void fr_rand_seed(void const *data, size_t size)
{
	uint32_t hash;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		int fd;

		memset(&fr_rand_pool, 0, sizeof(fr_rand_pool));

		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			size_t total;
			ssize_t this;

			total = 0;
			while (total < sizeof(fr_rand_pool.randrsl)) {
				this = read(fd, fr_rand_pool.randrsl,
					    sizeof(fr_rand_pool.randrsl) - total);
				if ((this < 0) && (errno != EINTR)) break;
				if (this > 0) total += this;
			}
			close(fd);
		} else {
			fr_rand_pool.randrsl[0] = fd;
			fr_rand_pool.randrsl[1] = time(NULL);
			fr_rand_pool.randrsl[2] = errno;
		}

		fr_randinit(&fr_rand_pool, 1);
		fr_rand_pool.randcnt = 0;
		fr_rand_initialized = 1;
	}

	if (!data) return;

	/*
	 *	Hash the user data
	 */
	hash = fr_rand();
	if (!hash) hash = fr_rand();
	hash = fr_hash_update(data, size, hash);

	fr_rand_pool.randmem[fr_rand_pool.randcnt] ^= hash;
}


/** Return a 32-bit random number
 *
 */
uint32_t fr_rand(void)
{
	uint32_t num;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		fr_rand_seed(NULL, 0);
	}

	num = fr_rand_pool.randrsl[fr_rand_pool.randcnt++];
	if (fr_rand_pool.randcnt >= 256) {
		fr_rand_pool.randcnt = 0;
		fr_isaac(&fr_rand_pool);
	}

	return num;
}


/** Allocate a new RADIUS_PACKET
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a REQUEST.
 * @param new_vector if true a new request authenticator will be generated.
 * @return
 *	- New RADIUS_PACKET.
 *	- NULL on error.
 */
RADIUS_PACKET *fr_radius_alloc(TALLOC_CTX *ctx, bool new_vector)
{
	RADIUS_PACKET	*rp;

	rp = talloc_zero(ctx, RADIUS_PACKET);
	if (!rp) {
		fr_strerror_printf("out of memory");
		return NULL;
	}
	rp->id = -1;
	rp->offset = -1;

	if (new_vector) {
		int i;
		uint32_t hash, base;

		/*
		 *	Don't expose the actual contents of the random
		 *	pool.
		 */
		base = fr_rand();
		for (i = 0; i < AUTH_VECTOR_LEN; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(rp->vector + i, &hash, sizeof(hash));
		}
	}
	fr_rand();		/* stir the pool again */

	return rp;
}

/** Allocate a new RADIUS_PACKET response
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a REQUEST.
 * @param packet The request packet.
 * @return
 *	- New RADIUS_PACKET.
 *	- NULL on error.
 */
RADIUS_PACKET *fr_radius_alloc_reply(TALLOC_CTX *ctx, RADIUS_PACKET *packet)
{
	RADIUS_PACKET *reply;

	if (!packet) return NULL;

	reply = fr_radius_alloc(ctx, false);
	if (!reply) return NULL;

	/*
	 *	Initialize the fields from the request.
	 */
	reply->sockfd = packet->sockfd;
	reply->dst_ipaddr = packet->src_ipaddr;
	reply->src_ipaddr = packet->dst_ipaddr;
	reply->dst_port = packet->src_port;
	reply->src_port = packet->dst_port;
	reply->if_index = packet->if_index;
	reply->id = packet->id;
	reply->code = 0; /* UNKNOWN code */
	memcpy(reply->vector, packet->vector,
	       sizeof(reply->vector));
	reply->vps = NULL;
	reply->data = NULL;
	reply->data_len = 0;

#ifdef WITH_TCP
	reply->proto = packet->proto;
#endif
	return reply;
}


/** Free a RADIUS_PACKET
 *
 */
void fr_radius_free(RADIUS_PACKET **radius_packet_ptr)
{
	RADIUS_PACKET *radius_packet;

	if (!radius_packet_ptr || !*radius_packet_ptr) return;
	radius_packet = *radius_packet_ptr;

	VERIFY_PACKET(radius_packet);

	fr_pair_list_free(&radius_packet->vps);

	talloc_free(radius_packet);
	*radius_packet_ptr = NULL;
}

/** Duplicate a RADIUS_PACKET
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a REQUEST.
 * @param in The packet to copy
 * @return
 *	- New RADIUS_PACKET.
 *	- NULL on error.
 */
RADIUS_PACKET *fr_radius_copy(TALLOC_CTX *ctx, RADIUS_PACKET const *in)
{
	RADIUS_PACKET *out;

	out = fr_radius_alloc(ctx, false);
	if (!out) return NULL;

	/*
	 *	Bootstrap by copying everything.
	 */
	memcpy(out, in, sizeof(*out));

	/*
	 *	Then reset necessary fields
	 */
	out->sockfd = -1;

	out->data = NULL;
	out->data_len = 0;

	out->vps = fr_pair_list_copy(out, in->vps);
	out->offset = 0;

	return out;
}
