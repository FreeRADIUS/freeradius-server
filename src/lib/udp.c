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
 * @file udp.c
 * @brief Functions to send/receive UDP packets.
 *
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/udp.h>

/** Send a packet via a UDP socket.
 *
 * @param[in] sockfd we're reading from.
 * @param[in] flags to pass to send(), or sendto()
 * @param[in] src_ipaddr of the packet.
 * @param[in] src_port of the packet.
 * @param[in] if_index of the packet.
 * @param[in] dst_ipaddr of the packet.
 * @param[in] dst_port of the packet.
 * 
 *
 */
ssize_t udp_send(int sockfd, void *data, size_t data_len, int flags,
#ifdef WITH_UDPFROMTO
		 fr_ipaddr_t *src_ipaddr, uint16_t src_port, int if_index,
#else
		 UNUSED fr_ipaddr_t *src_ipaddr, UNUSED uint16_t src_port, UNUSED int if_index,
#endif
		 fr_ipaddr_t *dst_ipaddr, uint16_t dst_port)
{
	int rcode;

	if (flags & UDP_FLAGS_CONNECTED) {
		rcode = send(sockfd, data, data_len, 0);

	} else {
		struct sockaddr_storage	dst;
		socklen_t		sizeof_dst;

		/*
		 *	@fixme: We shoul probably just move to sockaddr_storage for
		 *	all IP address things.
		 */
		if (!fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &dst, &sizeof_dst)) {
			return -1;
		}

#ifdef WITH_UDPFROMTO
		/*
		 *	And if they don't specify a source IP address, don't
		 *	use udpfromto.
		 */
		if (((dst_ipaddr->af == AF_INET) || (dst_ipaddr->af == AF_INET6)) &&
		    (src_ipaddr->af != AF_UNSPEC) &&
		    !fr_is_inaddr_any(src_ipaddr)) {
			struct sockaddr_storage	src;
			socklen_t		sizeof_src;

			fr_ipaddr_to_sockaddr(src_ipaddr, src_port, &src, &sizeof_src);

			rcode = sendfromto(sockfd, data, data_len, 0,
					   (struct sockaddr *)&src, sizeof_src,
					   (struct sockaddr *)&dst, sizeof_dst, if_index);
		} else
#endif
			rcode = sendto(sockfd, data, data_len, 0,
				       (struct sockaddr *) &dst, sizeof_dst);
	}

	if (rcode < 0) fr_strerror_printf("udp_sendto failed: %s", fr_syserror(errno));

	return rcode;
}
