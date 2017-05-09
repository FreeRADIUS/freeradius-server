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
 * @file packet.c
 * @brief Functions to deal with RADIUS_PACKET data structures.
 *
 * @copyright 2000-2017  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/udp.h>

#ifdef WITH_UDPFROMTO
#include <freeradius-devel/udpfromto.h>
#endif

#include <fcntl.h>
#include <ctype.h>

typedef struct radius_packet_t {
	uint8_t	code;
	uint8_t	id;
	uint8_t	length[2];
	uint8_t	vector[AUTH_VECTOR_LEN];
	uint8_t	data[1];
} radius_packet_t;

/*
 *	For request packets which have the Request Authenticator being
 *	all zeros.  We need to decode attributes using a Request
 *	Authenticator of all zeroes, but the actual Request
 *	Authenticator contains the signature of the packet, so we
 *	can't use that.
 */
static uint8_t nullvector[AUTH_VECTOR_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


/*
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf


/** Encode a packet
 *
 */
int fr_radius_packet_encode(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
		     char const *secret)
{
	radius_packet_t		*hdr;
	uint8_t			*ptr;
	uint16_t		total_length;
	int			len;
	VALUE_PAIR const	*vp;
	vp_cursor_t		cursor;
	fr_radius_ctx_t		packet_ctx;

	/*
	 *	A 4K packet, aligned on 64-bits.
	 */
	uint64_t	data[MAX_PACKET_LEN / sizeof(uint64_t)];

	packet_ctx.secret = secret;
	packet_ctx.vector = packet->vector;

	switch (packet->code) {
	case PW_CODE_ACCESS_REQUEST:
		break;
		
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_REJECT:
	case PW_CODE_ACCESS_CHALLENGE:
#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
#endif
#ifdef WITH_COA
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
#endif
		if (!original) {
			fr_strerror_printf("Cannot encode response without request");
			return -1;
		}
		packet_ctx.vector = original->vector;
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		packet_ctx.vector = nullvector;
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
		packet_ctx.vector = nullvector;
		break;
#endif

	default:
		fr_strerror_printf("Cannot decode unknown packet code %d", packet->code);
		return -1;
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
int fr_radius_packet_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, char const *secret)
{
	int			packet_length;
	uint32_t		num_attributes;
	uint8_t			*ptr;
	radius_packet_t		*hdr;
	VALUE_PAIR		*head = NULL;
	vp_cursor_t		cursor, out;
	fr_radius_ctx_t		packet_ctx;

	packet_ctx.secret = secret;
	packet_ctx.vector = packet->vector;

	switch (packet->code) {
	case PW_CODE_ACCESS_REQUEST:
		break;
		
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_REJECT:
	case PW_CODE_ACCESS_CHALLENGE:
#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
#endif
#ifdef WITH_COA
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
#endif
		if (!original) {
			fr_strerror_printf("Cannot decode response without request");
			return -1;
		}
		packet_ctx.vector = original->vector;
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		memset(packet->vector, 0, sizeof(packet->vector));
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
		memset(packet->vector, 0, sizeof(packet->vector));
		break;
#endif

	default:
		fr_strerror_printf("Cannot decode unknown packet code %d", packet->code);
		return -1;
	}

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
					       ptr, packet_length, &packet_ctx);
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
						     &packet->src_ipaddr.addr,
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
	char host_ipaddr[INET6_ADDRSTRLEN];

	if (!fr_radius_ok(packet->data, &packet->data_len, require_ma, reason)) {
		FR_DEBUG_STRERROR_PRINTF("Bad packet received from host %s - %s",
					 inet_ntop(packet->src_ipaddr.af,
						   &packet->src_ipaddr.addr,
						   host_ipaddr, sizeof(host_ipaddr)),
					 fr_strerror());
		return false;
	}

	/*
	 *	Fill RADIUS header fields
	 */
	packet->code = packet->data[0];
	packet->id = packet->data[1];
	memcpy(packet->vector, packet->data + 4, sizeof(packet->vector));
	return true;
}


/** Verify the Request/Response Authenticator (and Message-Authenticator if present) of a packet
 *
 */
int fr_radius_packet_verify(RADIUS_PACKET *packet, RADIUS_PACKET *original, char const *secret)
{
	uint8_t const	*original_data;
	char		buffer[INET6_ADDRSTRLEN];

	if (!packet->data) return -1;

	if (original) {
		original_data = original->data;
	} else {
		original_data = NULL;
	}

	if (fr_radius_verify(packet->data, original_data,
			     (uint8_t const *) secret, talloc_array_length(secret) - 1) < 0) {
		fr_strerror_printf("Received packet from %s with %s",
				   inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.addr,
					     buffer, sizeof(buffer)),
				   fr_strerror());
		return -1;
	}

	return 0;
}


/** Sign a previously encoded packet
 *
 */
int fr_radius_packet_sign(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
			  char const *secret)
{
	int rcode;
	uint8_t const *original_data;

	if (original) {
		original_data = original->data;
	} else {
		original_data = NULL;
	}

	/*
	 *	Copy the random vector to the packet.  Other packet
	 *	codes have the Request Authenticator be the packet
	 *	signature.
	 */
	if ((packet->code == PW_CODE_ACCESS_REQUEST) ||
	    (packet->code == PW_CODE_STATUS_SERVER)) {
		memcpy(packet->data + 4, packet->vector, sizeof(packet->vector));
	}

	rcode = fr_radius_sign(packet->data, original_data,
			       (uint8_t const *) secret, talloc_array_length(secret) - 1);
	if (rcode < 0) return rcode;

	memcpy(packet->vector, packet->data + 4, AUTH_VECTOR_LEN);
	return 0;
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


/** Receive UDP client requests, and fill in the basics of a RADIUS_PACKET structure
 *
 */
RADIUS_PACKET *fr_radius_packet_recv(TALLOC_CTX *ctx, int fd, int flags, bool require_ma)
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
	if (packet->sockfd < 0) {
		return 0;
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		/*
		 *	Encode the packet.
		 */
		if (fr_radius_packet_encode(packet, original, secret) < 0) {
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
				  &packet->src_ipaddr.addr,
				  buffer, sizeof(buffer)));
		fprintf(fr_log_fp, "    port:\t%u\n", packet->src_port);

		fprintf(fr_log_fp, "  Dst IP:\t%s\n",
			inet_ntop(packet->dst_ipaddr.af,
				  &packet->dst_ipaddr.addr,
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
