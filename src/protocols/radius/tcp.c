/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/radius/packet.c
 * @brief TCP-specific functions.
 *
 * @copyright (C) 2009 Dante http://dante.net
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/server/tcp.h>

RADIUS_PACKET *fr_tcp_recv(int sockfd, int flags)
{
	RADIUS_PACKET *packet = fr_radius_alloc(NULL, false);

	if (!packet) return NULL;

	packet->socket.fd = sockfd;

	if (fr_tcp_read_packet(packet, RADIUS_MAX_ATTRIBUTES, flags) != 1) {
		fr_radius_packet_free(&packet);
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
int fr_tcp_read_packet(RADIUS_PACKET *packet, uint32_t max_attributes, bool require_ma)
{
	ssize_t len;

	/*
	 *	No data allocated.  Read the 4-byte header into
	 *	a temporary buffer.
	 */
	if (!packet->data) {
		int packet_len;

		len = recv(packet->socket.fd, packet->vector + packet->data_len,
			   4 - packet->data_len, 0);
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

		packet->data_len += len;
		if (packet->data_len < 4) { /* want more data */
			return 0;
		}

		packet_len = (packet->vector[2] << 8) | packet->vector[3];

		if (packet_len < RADIUS_HEADER_LENGTH) {
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
		memcpy(packet->data, packet->vector, 4);	//-V512
	}

	/*
	 *	Try to read more data.
	 */
	len = recv(packet->socket.fd, packet->data + packet->partial,
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
	if (!fr_radius_packet_ok(packet, max_attributes, require_ma, NULL)) {
		return -1;
	}

	/*
	 *	Explicitly set the VP list to empty.
	 */
	packet->vps = NULL;

	if (fr_debug_lvl) {
		char ip_buf[INET6_ADDRSTRLEN], buffer[256];

		if (packet->socket.inet.src_ipaddr.af != AF_UNSPEC) {
			inet_ntop(packet->socket.inet.src_ipaddr.af, &packet->socket.inet.src_ipaddr.addr, ip_buf, sizeof(ip_buf));
			snprintf(buffer, sizeof(buffer), "host %s port %d", ip_buf, packet->socket.inet.src_port);
		} else {
			snprintf(buffer, sizeof(buffer), "socket %d", packet->socket.fd);
		}

	}

	packet->timestamp = fr_time();

	return 1;		/* done reading the packet */
}
