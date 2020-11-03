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
 * @file protocols/dhcpv4/udp.c
 * @brief Send/recv DHCP packets using udp sockets.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */
#include "dhcpv4.h"
#include "attrs.h"

#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/udpfromto.h>
#include <freeradius-devel/util/syserror.h>

#include <stdint.h>
#include <stddef.h>
#include <talloc.h>


#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

/** Send DHCP packet using a connectionless UDP socket
 *
 * @param packet to send
 * @return
 *	- >= 0 if successful.
 *	- < 0 if failed.
 */
int fr_dhcpv4_udp_packet_send(fr_radius_packet_t *packet)
{
	int ret;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_dst;
	struct sockaddr_storage	src;
	socklen_t		sizeof_src;

	fr_ipaddr_to_sockaddr(&packet->socket.inet.src_ipaddr, packet->socket.inet.src_port, &src, &sizeof_src);
	fr_ipaddr_to_sockaddr(&packet->socket.inet.dst_ipaddr, packet->socket.inet.dst_port, &dst, &sizeof_dst);
	if (packet->data_len == 0) {
		fr_strerror_printf("No data to send");
		return -1;
	}

	errno = 0;

	ret = sendfromto(packet->socket.fd, packet->data, packet->data_len, 0, (struct sockaddr *)&src, sizeof_src,
			 (struct sockaddr *)&dst, sizeof_dst, packet->socket.inet.ifindex);
	if ((ret < 0) && errno) fr_strerror_printf("dhcp_send_socket: %s", fr_syserror(errno));

	return ret;
}

/** Receive DHCP packet using a connectionless UDP socket
 *
 * @param sockfd handle.
 * @return
 *	- pointer to fr_radius_packet_t if successful.
 *	- NULL if failed.
 */
fr_radius_packet_t *fr_dhcpv4_udp_packet_recv(int sockfd)
{
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src;
	socklen_t		sizeof_dst;
	fr_radius_packet_t		*packet;
	uint8_t			*data;
	ssize_t			data_len;
	fr_ipaddr_t		src_ipaddr, dst_ipaddr;
	uint16_t		src_port, dst_port;
	int			ifindex = 0;
	fr_time_t		when;

	data = talloc_zero_array(NULL, uint8_t, MAX_PACKET_SIZE);
	if (!data) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	sizeof_src = sizeof(src);
	sizeof_dst = sizeof(dst);
	data_len = recvfromto(sockfd, data, MAX_PACKET_SIZE, 0,
			      (struct sockaddr *)&src, &sizeof_src,
			      (struct sockaddr *)&dst, &sizeof_dst, &ifindex, &when);

	if (data_len <= 0) {
		fr_strerror_printf("Failed reading data from DHCP socket: %s", fr_syserror(errno));
		talloc_free(data);
		return NULL;
	}

	if (!fr_cond_assert(data_len <= (ssize_t)talloc_array_length(data))) {
		talloc_free(data);	/* Bounds check for tainted scalar (Coverity) */
		return NULL;
	}
	sizeof_dst = sizeof(dst);

	/*
	 *	This should never fail...
	 */
	if (getsockname(sockfd, (struct sockaddr *) &dst, &sizeof_dst) < 0) {
		fr_strerror_printf("getsockname failed: %s", fr_syserror(errno));
		talloc_free(data);
		return NULL;
	}

	fr_ipaddr_from_sockaddr(&dst, sizeof_dst, &dst_ipaddr, &dst_port);
	fr_ipaddr_from_sockaddr(&src, sizeof_src, &src_ipaddr, &src_port);

	if (!fr_dhcpv4_ok(data, data_len, NULL, NULL)) return NULL;

	packet = fr_dhcpv4_packet_alloc(data, data_len);
	if (!packet) return NULL;

	fr_socket_addr_init_inet(&packet->socket, IPPROTO_UDP, ifindex, &src_ipaddr, src_port, &dst_ipaddr, dst_port);

	talloc_steal(packet, data);
	packet->data = data;
	packet->socket.fd = sockfd;

	packet->timestamp = when;
	return packet;
}

