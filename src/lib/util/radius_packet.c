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
 * @file radius_packet.c
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
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf


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
int fr_radius_packet_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, char const *secret)
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
