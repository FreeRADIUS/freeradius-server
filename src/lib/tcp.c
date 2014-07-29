/*
 * tcp.c	TCP-specific functions.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright (C) 2009 Dante http://dante.net
 */

RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#ifdef WITH_TCP

/* FIXME: into common RADIUS header? */
#define MAX_PACKET_LEN 4096

/*
 *	Open a socket TO the given IP and port.
 */
int fr_tcp_client_socket(fr_ipaddr_t *src_ipaddr,
			 fr_ipaddr_t *dst_ipaddr, uint16_t dst_port)
{
	int sockfd;
	struct sockaddr_storage salocal;
	socklen_t	salen;

	if (!dst_ipaddr) return -1;

	sockfd = socket(dst_ipaddr->af, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return sockfd;
	}

	/*
	 *	Allow the caller to bind us to a specific source IP.
	 */
	if (src_ipaddr && (src_ipaddr->af != AF_UNSPEC)) {
		if (!fr_ipaddr2sockaddr(src_ipaddr, 0, &salocal, &salen)) {
			close(sockfd);
			return -1;
		}

		if (bind(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
			fr_strerror_printf("Failure binding to IP: %s",
					   fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (!fr_ipaddr2sockaddr(dst_ipaddr, dst_port, &salocal, &salen)) {
		close(sockfd);
		return -1;
	}

	/*
	 *	FIXME: If EINPROGRESS, then tell the caller that
	 *	somehow.  The caller can then call connect() when the
	 *	socket is ready...
	 */
	if (connect(sockfd, (struct sockaddr *) &salocal, salen) < 0) {
		fr_strerror_printf("Failed in connect(): %s", fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}


RADIUS_PACKET *fr_tcp_recv(int sockfd, int flags)
{
	RADIUS_PACKET *packet = rad_alloc(NULL, false);

	if (!packet) return NULL;

	packet->sockfd = sockfd;

	if (fr_tcp_read_packet(packet, flags) != 1) {
		rad_free(&packet);
		return NULL;
	}

	return packet;
}


/*
 *	Receives a packet, assuming that the RADIUS_PACKET structure
 *	has been filled out already.
 *
 *	This ASSUMES that the packet is allocated && fields
 *	initialized.
 *
 *	This ASSUMES that the socket is marked as O_NONBLOCK, which
 *	the function above does set, if your system supports it.
 *
 *	Calling this function MAY change sockfd,
 *	if src_ipaddr.af == AF_UNSPEC.
 */
int fr_tcp_read_packet(RADIUS_PACKET *packet, int flags)
{
	ssize_t len;

	/*
	 *	No data allocated.  Read the 4-byte header into
	 *	a temporary buffer.
	 */
	if (!packet->data) {
		int packet_len;

		len = recv(packet->sockfd, packet->vector + packet->data_len,
			   4 - packet->data_len, 0);
		if (len == 0) return -2; /* clean close */

#ifdef ECONNRESET
		if ((len < 0) && (errno == ECONNRESET)) { /* forced */
			return -2;
		}
#endif

		if (len < 0) {
			fr_strerror_printf("Error receiving packet: %s",
				   fr_syserror(errno));
			return -1;
		}

		packet->data_len += len;
		if (packet->data_len < 4) { /* want more data */
			return 0;
		}

		packet_len = (packet->vector[2] << 8) | packet->vector[3];

		if (packet_len < RADIUS_HDR_LEN) {
			fr_strerror_printf("Discarding packet: Smaller than RFC minimum of 20 bytes");
			return -1;
		}

		/*
		 *	If the packet is too big, then the socket is bad.
		 */
		if (packet_len > MAX_PACKET_LEN) {
			fr_strerror_printf("Discarding packet: Larger than RFC limitation of 4096 bytes");
			return -1;
		}

		packet->data = talloc_array(packet, uint8_t, packet_len);
		if (!packet->data) {
			fr_strerror_printf("Out of memory");
			return -1;
		}

		packet->data_len = packet_len;
		packet->partial = 4;
		memcpy(packet->data, packet->vector, 4);
	}

	/*
	 *	Try to read more data.
	 */
	len = recv(packet->sockfd, packet->data + packet->partial,
		   packet->data_len - packet->partial, 0);
	if (len == 0) return -2; /* clean close */

#ifdef ECONNRESET
	if ((len < 0) && (errno == ECONNRESET)) { /* forced */
		return -2;
	}
#endif

	if (len < 0) {
		fr_strerror_printf("Error receiving packet: %s", fr_syserror(errno));
		return -1;
	}

	packet->partial += len;

	if (packet->partial < packet->data_len) {
		return 0;
	}

	/*
	 *	See if it's a well-formed RADIUS packet.
	 */
	if (!rad_packet_ok(packet, flags, NULL)) {
		return -1;
	}

	/*
	 *	Explicitly set the VP list to empty.
	 */
	packet->vps = NULL;

	if (fr_debug_flag) {
		char ip_buf[128], buffer[256];

		if (packet->src_ipaddr.af != AF_UNSPEC) {
			inet_ntop(packet->src_ipaddr.af,
				  &packet->src_ipaddr.ipaddr,
				  ip_buf, sizeof(ip_buf));
			snprintf(buffer, sizeof(buffer), "host %s port %d",
				 ip_buf, packet->src_port);
		} else {
			snprintf(buffer, sizeof(buffer), "socket %d",
				 packet->sockfd);
		}


		if (is_radius_code(packet->code)) {
			DEBUG("Received %s packet from %s",
			      fr_packet_codes[packet->code], buffer);
		} else {
			DEBUG("Received packet from %s code %d",
			      buffer, packet->code);
		}
		DEBUG(", id=%d, length=%zu\n", packet->id, packet->data_len);
	}

	return 1;		/* done reading the packet */
}

#endif /* WITH_TCP */
