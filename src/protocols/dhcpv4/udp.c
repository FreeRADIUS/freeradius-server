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

#include <sys/ioctl.h>

#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HAVE_LINUX_IF_PACKET_H
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
#endif

#include <net/if_arp.h>

#ifdef SIOCSARP
/** Forcibly add an ARP entry so we can send unicast packets to hosts that don't have IP addresses yet
 *
 * @param[in] fd	to add arp entry on.
 * @param[in] interface	to add arp entry on.
 * @param[in] ip	to insert into ARP table.
 * @param[in] macaddr	to insert into ARP table.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dhcpv4_udp_add_arp_entry(int fd, char const *interface, fr_ipaddr_t const *ip, uint8_t macaddr[static 6])
{
	struct sockaddr_in *sin;
	struct arpreq req;

	if (!interface) {
		fr_strerror_printf("No interface specified.  Cannot update ARP table");
		return -1;
	}

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip->addr.v4.s_addr;

	strlcpy(req.arp_dev, interface, sizeof(req.arp_dev));

	memcpy(&req.arp_ha.sa_data, macaddr, 6);

	req.arp_flags = ATF_COM;
	if (ioctl(fd, SIOCSARP, &req) < 0) {
		fr_strerror_printf("Failed to add entry in ARP cache: %s (%d)", fr_syserror(errno), errno);
		return -1;
	}

	return 0;
}
#else
int fr_dhcpv4_udp_add_arp_entry(UNUSED int fd, UNUSED char const *interface,
				UNUSED fr_ipaddr_t const *ip, UNUSED uint8_t macaddr[static 6])
{
	fr_strerror_printf("Adding ARP entry is unsupported on this system");
	return -1;
}
#endif

/** Send DHCP packet using a connectionless UDP socket
 *
 * @param packet to send
 * @return
 *	- >= 0 if successful.
 *	- < 0 if failed.
 */
int fr_dhcpv4_udp_packet_send(RADIUS_PACKET *packet)
{
	int ret;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_dst;
	struct sockaddr_storage	src;
	socklen_t		sizeof_src;

	fr_ipaddr_to_sockaddr(&packet->src_ipaddr, packet->src_port, &src, &sizeof_src);
	fr_ipaddr_to_sockaddr(&packet->dst_ipaddr, packet->dst_port, &dst, &sizeof_dst);
	if (packet->data_len == 0) {
		fr_strerror_printf("No data to send");
		return -1;
	}

	errno = 0;

	ret = sendfromto(packet->sockfd, packet->data, packet->data_len, 0, (struct sockaddr *)&src, sizeof_src,
			 (struct sockaddr *)&dst, sizeof_dst, packet->if_index);
	if ((ret < 0) && errno) fr_strerror_printf("dhcp_send_socket: %s", fr_syserror(errno));

	return ret;
}

/** Receive DHCP packet using a connectionless UDP socket
 *
 * @param sockfd handle.
 * @return
 *	- pointer to RADIUS_PACKET if successful.
 *	- NULL if failed.
 */
RADIUS_PACKET *fr_dhcpv4_udp_packet_recv(int sockfd)
{
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src;
	socklen_t		sizeof_dst;
	RADIUS_PACKET		*packet;
	uint8_t			*data;
	ssize_t			data_len;
	fr_ipaddr_t		src_ipaddr, dst_ipaddr;
	uint16_t		src_port, dst_port;
	int			if_index = 0;
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
			      (struct sockaddr *)&dst, &sizeof_dst, &if_index, &when);

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

	packet->dst_port = dst_port;
	packet->src_port = src_port;

	packet->src_ipaddr = src_ipaddr;
	packet->dst_ipaddr = dst_ipaddr;

	talloc_steal(packet, data);
	packet->data = data;
	packet->sockfd = sockfd;
	packet->if_index = if_index;
	packet->timestamp = when;
	return packet;
}

