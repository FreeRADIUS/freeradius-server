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
 * @file protocols/radius/packet.c
 * @brief Functions to deal with fr_radius_packet_t data structures.
 *
 * @copyright 2000-2017 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "attrs.h"

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/udpfromto.h>

#include <fcntl.h>
#include <ctype.h>

typedef struct {
	uint8_t	code;
	uint8_t	id;
	uint8_t	length[2];
	uint8_t	vector[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t	data[1];
} radius_packet_t;


/*
 *	Some messages get printed out only in debugging mode.
 */
#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf_push


/** Encode a packet
 *
 */
ssize_t fr_radius_packet_encode(fr_radius_packet_t *packet, fr_pair_list_t *list,
				fr_radius_packet_t const *original, char const *secret)
{
	uint8_t const *original_data;
	ssize_t slen;

	/*
	 *	A 4K packet, aligned on 64-bits.
	 */
	uint8_t	data[MAX_PACKET_LEN];

#ifndef NDEBUG
	if (fr_debug_lvl >= L_DBG_LVL_4) fr_radius_packet_log_hex(&default_log, packet);
#endif

	if (original) {
		original_data = original->data;
	} else {
		original_data = NULL;
	}

	/*
	 *	This has to be initialized for Access-Request packets
	 */
	memcpy(data + 4, packet->vector, sizeof(packet->vector));

	slen = fr_radius_encode(data, sizeof(data), original_data, secret, talloc_array_length(secret) - 1,
				packet->code, packet->id, list);
	if (slen < 0) return slen;

	/*
	 *	Fill in the rest of the fields, and copy the data over
	 *	from the local stack to the newly allocated memory.
	 *
	 *	Yes, all this 'memcpy' is slow, but it means
	 *	that we only allocate the minimum amount of
	 *	memory for a request.
	 */
	packet->data_len = (size_t) slen;
	packet->data = talloc_array(packet, uint8_t, packet->data_len);
	if (!packet->data) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	memcpy(packet->data, data, packet->data_len);

	return 0;
}

/** Calculate/check digest, and decode radius attributes
 *
 * @param[in] packet			to decode.
 * @param[in] list			to add pairs to.
 * @param[in] original			packet, if this is a reply.
 * @param[in] max_attributes		to decode.
 * @param[in] tunnel_password_zeros	set random elements of the tunnel password
 *					vectors to zero to aid in testing.
 * @param[in] secret			shared secret used for decoding encrypted
 *					password attributes.
 * @return
 *	- 0 on success
 *	- -1 on decoding error.
 */
int fr_radius_packet_decode(fr_radius_packet_t *packet, fr_pair_list_t *list,
			    fr_radius_packet_t *original,
			    uint32_t max_attributes, bool tunnel_password_zeros, char const *secret)
{
	int			packet_length;
	uint32_t		num_attributes;
	uint8_t			*ptr;
	radius_packet_t		*hdr;
	fr_pair_list_t		head;
	fr_dcursor_t		cursor, out;
	fr_radius_ctx_t		packet_ctx = {
					.secret = secret,
					.tunnel_password_zeros = tunnel_password_zeros
				};

	fr_pair_list_init(&head);
#ifndef NDEBUG
	if (fr_debug_lvl >= L_DBG_LVL_4) fr_radius_packet_log_hex(&default_log, packet);
#endif

	switch (packet->code) {
	case FR_CODE_ACCESS_REQUEST:
	case FR_CODE_STATUS_SERVER:
		memcpy(packet_ctx.vector, packet->vector, sizeof(packet_ctx.vector));
		break;

	case FR_CODE_ACCESS_ACCEPT:
	case FR_CODE_ACCESS_REJECT:
	case FR_CODE_ACCESS_CHALLENGE:
	case FR_CODE_ACCOUNTING_RESPONSE:
	case FR_CODE_COA_ACK:
	case FR_CODE_COA_NAK:
	case FR_CODE_DISCONNECT_ACK:
	case FR_CODE_DISCONNECT_NAK:
		/*
		 *	radsniff doesn't always have a response
		 */
		if (original) {
			memcpy(packet_ctx.vector, original->vector, sizeof(packet_ctx.vector));
		} else {
			memset(packet->vector, 0, sizeof(packet->vector));
			memset(packet_ctx.vector, 0, sizeof(packet_ctx.vector));
		}
		break;

	case FR_CODE_ACCOUNTING_REQUEST:
	case FR_CODE_COA_REQUEST:
	case FR_CODE_DISCONNECT_REQUEST:
		memset(packet->vector, 0, sizeof(packet->vector));
		memset(packet_ctx.vector, 0, sizeof(packet_ctx.vector));
		break;

	default:
		fr_strerror_printf("Cannot decode unknown packet code %d", packet->code);
		return -1;
	}

	packet_ctx.tmp_ctx = talloc(packet, uint8_t);

	/*
	 *	Extract attribute-value pairs
	 */
	hdr = (radius_packet_t *)packet->data;
	ptr = hdr->data;
	packet_length = packet->data_len - RADIUS_HEADER_LENGTH;
	num_attributes = 0;

	fr_dcursor_init(&cursor, &head);

	/*
	 *	Loop over the attributes, decoding them into VPs.
	 */
	while (packet_length > 0) {
		ssize_t my_len;

		/*
		 *	This may return many VPs
		 */
		my_len = fr_radius_decode_pair(packet, &cursor, dict_radius, ptr, packet_length, &packet_ctx);
		if (my_len < 0) {
		fail:
			talloc_free(packet_ctx.tmp_ctx);
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
		while (fr_dcursor_next(&cursor)) num_attributes++;

		/*
		 *	VSA's may not have been counted properly in
		 *	fr_radius_packet_ok() above, as it is hard to count
		 *	then without using the dictionary.  We
		 *	therefore enforce the limits here, too.
		 */
		if ((max_attributes > 0) && (num_attributes > max_attributes)) {
			char host_ipaddr[INET6_ADDRSTRLEN];

			fr_strerror_printf("Possible DoS attack from host %s: Too many attributes in request "
					   "(received %d, max %d are allowed)",
					   inet_ntop(packet->socket.inet.src_ipaddr.af,
						     &packet->socket.inet.src_ipaddr.addr,
						     host_ipaddr, sizeof(host_ipaddr)),
					   num_attributes, max_attributes);
			goto fail;
		}

		ptr += my_len;
		packet_length -= my_len;
		talloc_free_children(packet_ctx.tmp_ctx);
	}

	fr_dcursor_init(&out, list);
	fr_dcursor_tail(&out);		/* Move insertion point to the end of the list */
	fr_dcursor_head(&cursor);
	fr_dcursor_merge(&out, &cursor);

	/*
	 *	Merge information from the outside world into our
	 *	random pool.
	 */
	fr_rand_seed(packet->data, RADIUS_HEADER_LENGTH);
	talloc_free(packet_ctx.tmp_ctx);
	talloc_free(packet_ctx.tags);

	return 0;
}


/** See if the data pointed to by PTR is a valid RADIUS packet.
 *
 * Packet is not 'const * const' because we may update data_len, if there's more data
 * in the UDP packet than in the RADIUS packet.
 *
 * @param[in] packet		to check.
 * @param[in] max_attributes	to decode.
 * @param[in] require_ma	to require Message-Authenticator.
 * @param[out] reason		if not NULL, will have the failure reason written to where it points.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_radius_packet_ok(fr_radius_packet_t *packet, uint32_t max_attributes, bool require_ma, decode_fail_t *reason)
{
	char host_ipaddr[INET6_ADDRSTRLEN];

	if (!fr_radius_ok(packet->data, &packet->data_len, max_attributes, require_ma, reason)) {
		FR_DEBUG_STRERROR_PRINTF("Bad packet received from host %s",
					 inet_ntop(packet->socket.inet.src_ipaddr.af, &packet->socket.inet.src_ipaddr.addr,
						   host_ipaddr, sizeof(host_ipaddr)));
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
int fr_radius_packet_verify(fr_radius_packet_t *packet, fr_radius_packet_t *original, char const *secret)
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
		fr_strerror_printf_push("Received invalid packet from %s",
					inet_ntop(packet->socket.inet.src_ipaddr.af, &packet->socket.inet.src_ipaddr.addr,
						  buffer, sizeof(buffer)));
		return -1;
	}

	return 0;
}


/** Sign a previously encoded packet
 *
 */
int fr_radius_packet_sign(fr_radius_packet_t *packet, fr_radius_packet_t const *original,
			  char const *secret)
{
	int ret;
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
	if ((packet->code == FR_CODE_ACCESS_REQUEST) ||
	    (packet->code == FR_CODE_STATUS_SERVER)) {
		memcpy(packet->data + 4, packet->vector, sizeof(packet->vector));
	}

	ret = fr_radius_sign(packet->data, original_data,
			       (uint8_t const *) secret, talloc_array_length(secret) - 1);
	if (ret < 0) return ret;

	memcpy(packet->vector, packet->data + 4, RADIUS_AUTH_VECTOR_LENGTH);
	return 0;
}


/** Wrapper for recvfrom, which handles recvfromto, IPv6, and all possible combinations
 *
 */
static ssize_t rad_recvfrom(int sockfd, fr_radius_packet_t *packet, int flags)
{
	ssize_t			data_len;

	data_len = fr_radius_recv_header(sockfd, &packet->socket.inet.src_ipaddr, &packet->socket.inet.src_port, &packet->code);
	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EINTR)) return 0;
		return -1;
	}

	if (data_len == 0) return -1; /* invalid packet */

	packet->data = talloc_array(packet, uint8_t, data_len);
	if (!packet->data) return -1;

	packet->data_len = data_len;

	return udp_recv(sockfd, flags, &packet->socket, packet->data, packet->data_len, &packet->timestamp);
}


/** Receive UDP client requests, and fill in the basics of a fr_radius_packet_t structure
 *
 */
fr_radius_packet_t *fr_radius_packet_recv(TALLOC_CTX *ctx, int fd, int flags, uint32_t max_attributes, bool require_ma)
{
	ssize_t			data_len;
	fr_radius_packet_t	*packet;

	/*
	 *	Allocate the new request data structure
	 */
	packet = fr_radius_packet_alloc(ctx, false);
	if (!packet) {
		fr_strerror_const("out of memory");
		return NULL;
	}

	data_len = rad_recvfrom(fd, packet, flags);
	if (data_len < 0) {
		FR_DEBUG_STRERROR_PRINTF("Error receiving packet: %s", fr_syserror(errno));
		fr_radius_packet_free(&packet);
		return NULL;
	}

#ifdef WITH_VERIFY_PTR
	/*
	 *	Double-check that the fields we want are filled in.
	 */
	if ((packet->socket.inet.src_ipaddr.af == AF_UNSPEC) ||
	    (packet->socket.inet.src_port == 0) ||
	    (packet->socket.inet.dst_ipaddr.af == AF_UNSPEC) ||
	    (packet->socket.inet.dst_port == 0)) {
		FR_DEBUG_STRERROR_PRINTF("Error receiving packet: %s", fr_syserror(errno));
		fr_radius_packet_free(&packet);
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
		fr_radius_packet_free(&packet);
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
		fr_radius_packet_free(&packet);
		return NULL;
	}

	/*
	 *	See if it's a well-formed RADIUS packet.
	 */
	if (!fr_radius_packet_ok(packet, max_attributes, require_ma, NULL)) {
		fr_radius_packet_free(&packet);
		return NULL;
	}

	/*
	 *	Remember which socket we read the packet from.
	 */
	packet->socket.fd = fd;

	/*
	 *	FIXME: Do even more filtering by only permitting
	 *	certain IP's.  The problem is that we don't know
	 *	how to do this properly for all possible clients...
	 */

	return packet;
}

/** Reply to the request
 *
 * Also attach reply attribute value pairs and any user message provided.
 */
int fr_radius_packet_send(fr_radius_packet_t *packet, fr_pair_list_t *list,
			  fr_radius_packet_t const *original, char const *secret)
{
	/*
	 *	Maybe it's a fake packet.  Don't send it.
	 */
	if (packet->socket.fd < 0) {
		return 0;
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		/*
		 *	Encode the packet.
		 */
		if (fr_radius_packet_encode(packet, list, original, secret) < 0) {
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

	/*
	 *	If the socket is TCP, call write().  Calling sendto()
	 *	is allowed on some platforms, but it's not nice.
	 */
	if (packet->socket.proto == IPPROTO_TCP) {
		ssize_t ret;

		ret = write(packet->socket.fd, packet->data, packet->data_len);
		if (ret >= 0) return ret;

		fr_strerror_printf("sendto failed: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	And send it on it's way.
	 *
	 *	No need to call fr_socket_addr_swap as apparently
	 *	the address is already inverted.
	 */
	return udp_send(&packet->socket, 0, packet->data, packet->data_len);
}

void _fr_radius_packet_log_hex(fr_log_t const *log, fr_radius_packet_t const *packet, char const *file, int line)
{
	uint8_t const *attr, *end;
	char buffer[256];

	if (!packet->data) return;

	fr_log(log, L_DBG, file, line, "  Socket   : %d", packet->socket.fd);
	fr_log(log, L_DBG, file, line, "  Proto    : %d", packet->socket.proto);

	if ((packet->socket.inet.src_ipaddr.af == AF_INET) || (packet->socket.inet.src_ipaddr.af == AF_INET6)) {
		fr_log(log, L_DBG, file, line, "  Src IP   : %pV", fr_box_ipaddr(packet->socket.inet.src_ipaddr));
		fr_log(log, L_DBG, file, line, "  Src Port : %u", packet->socket.inet.src_port);
		fr_log(log, L_DBG, file, line, "  Dst IP   : %pV", fr_box_ipaddr(packet->socket.inet.dst_ipaddr));
		fr_log(log, L_DBG, file, line, "  Dst Port : %u", packet->socket.inet.dst_port);
	}

       if ((packet->data[0] > 0) && (packet->data[0] < FR_RADIUS_MAX_PACKET_CODE)) {
               fr_log(log, L_DBG, file, line, "  Code     : %s", fr_packet_codes[packet->data[0]]);
       } else {
               fr_log(log, L_DBG, file, line, "  Code     : %u", packet->data[0]);
       }

       fr_log(log, L_DBG, file, line, "  Id       : %u", packet->data[1]);
       fr_log(log, L_DBG, file, line, "  Length   : %u", ((packet->data[2] << 8) | (packet->data[3])));
       fr_log(log, L_DBG, file, line, "  Vector   : %pH", fr_box_octets(packet->data + 4, RADIUS_AUTH_VECTOR_LENGTH));

       if (packet->data_len <= 20) return;

       for (attr = packet->data + 20, end = packet->data + packet->data_len;
            attr < end;
            attr += attr[1]) {
               int		i, len, offset = 2;
               unsigned int	vendor = 0;
	       char		*p;

#ifndef NDEBUG
               if (attr[1] < 2) break; /* Coverity */
#endif

	       snprintf(buffer, sizeof(buffer), "%02x %02x  ", attr[0], attr[1]);
               if ((attr[0] == FR_VENDOR_SPECIFIC) &&
                   (attr[1] > 6)) {
                       vendor = (attr[2] << 25) | (attr[3] << 16) | (attr[4] << 8) | attr[5];

		       snprintf(buffer + 12, sizeof(buffer) - 12, "%02x%02x%02x%02x (%u)  ",
				attr[2], attr[3], attr[4], attr[5], vendor);
                       offset = 6;
               }
	       p = buffer + strlen(buffer);

	       len = attr[1] - offset;
	       if (len > 16) len = 16;

	       for (i = 0; i < len; i++) {
		       snprintf(p, buffer + sizeof(buffer) - p, "%02x ", attr[offset + i]);
		       p += 3;
	       }

	       fr_log(log, L_DBG, file, line, "      %s\n", buffer);
       }
}
