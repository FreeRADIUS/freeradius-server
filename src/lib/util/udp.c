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

/** Utility functions for managing UDP sockets
 *
 * @file src/lib/util/udp.c
 *
 * @copyright 2000-2003,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/udp.h>

#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf

/** Send a packet via a UDP socket.
 *
 * @param[in] socket		we're reading from.
 * @param[in] flags		to pass to send(), or sendto()
 * @param[in] data		to data to send
 * @param[in] data_len		length of data to send
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int udp_send(fr_socket_t const *socket, int flags, void *data, size_t data_len)
{
	int ret;

	if (unlikely(socket->proto != IPPROTO_UDP)) {
		fr_strerror_printf("Invalid proto type %u", socket->proto);
		return -1;
	}

	if (flags & UDP_FLAGS_CONNECTED) {
		ret = (send(socket->fd, data, data_len, 0) == (ssize_t)data_len) ? 0 : -1;
	} else {
		struct sockaddr_storage	dst, src;
		socklen_t		sizeof_dst, sizeof_src;

		if (fr_ipaddr_to_sockaddr(&dst, &sizeof_dst,
					  &socket->inet.dst_ipaddr, socket->inet.dst_port) < 0) return -1;
		if (fr_ipaddr_to_sockaddr(&src, &sizeof_src,
					  &socket->inet.src_ipaddr, socket->inet.src_port) < 0) return -1;

		ret = sendfromto(socket->fd, data, data_len, 0,
				 socket->inet.ifindex,
				 (struct sockaddr *)&src, sizeof_src,
				 (struct sockaddr *)&dst, sizeof_dst);
	}

	if (ret < 0) fr_strerror_printf("udp_send failed: %s", fr_syserror(errno));

	return ret;
}


/** Discard the next UDP packet
 *
 * @param[in] sockfd we're reading from.
 */
int udp_recv_discard(int sockfd)
{
	uint8_t			data[4];
	struct sockaddr_storage	src;
	socklen_t		sizeof_src = sizeof(src);

	return recvfrom(sockfd, data, sizeof(data), 0,
			(struct sockaddr *)&src, &sizeof_src);
}


/** Peek at the header of a UDP packet.
 *
 * @param[in] sockfd we're reading from.
 * @param[out] data pointer where data will be written
 * @param[in] data_len length of data to read
 * @param[in] flags for things
 * @param[out] src_ipaddr of the packet.
 * @param[out] src_port of the packet.
 */
ssize_t udp_recv_peek(int sockfd, void *data, size_t data_len, int flags, fr_ipaddr_t *src_ipaddr, uint16_t *src_port)
{
	ssize_t			peeked;
	struct sockaddr_storage	src;
	socklen_t		sizeof_src = sizeof(src);

	if (!src_ipaddr || ((flags & UDP_FLAGS_CONNECTED) != 0)) {
		peeked = recv(sockfd, data, data_len, MSG_PEEK);
		if (peeked < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) return 0;
			return -1;
		}

		return peeked;
	}

	peeked = recvfrom(sockfd, data, data_len, MSG_PEEK, (struct sockaddr *)&src, &sizeof_src);
	if (peeked < 0) {
		if ((errno == EAGAIN) || (errno == EINTR)) return 0;
		return -1;
	}

	/*
	 *	Convert AF.  If unknown, discard packet.
	 */
	if (fr_ipaddr_from_sockaddr(src_ipaddr, src_port, &src, sizeof_src) < 0) {
		FR_DEBUG_STRERROR_PRINTF("Unknown address family");
		(void) udp_recv_discard(sockfd);

		return -1;
	}

	return peeked;
}


/** Read a UDP packet
 *
 * @param[in] sockfd		we're reading from.
 * @param[in] flags		for things
 * @param[out] socket_out	Information about the src/dst address of the packet
 *				and the interface it was received on.
 * @param[out] data		pointer where data will be written
 * @param[in] data_len		length of data to read
 * @param[out] when		the packet was received.
 * @return
 *	- > 0 on success (number of bytes read).
 *	- < 0 on failure.
 */
ssize_t udp_recv(int sockfd, int flags,
		 fr_socket_t *socket_out, void *data, size_t data_len, fr_time_t *when)
{
	int			sock_flags = 0;
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src = sizeof(src);
	socklen_t		sizeof_dst = sizeof(dst);
	ssize_t			slen;

	if ((flags & UDP_FLAGS_PEEK) != 0) sock_flags |= MSG_PEEK;

	if (when) *when = 0;

	/*
	 *	Always initialise the output socket structure
	 */
	*socket_out = (fr_socket_t){
		.fd = sockfd,
		.proto = IPPROTO_UDP
	};

	/*
	 *	Connected sockets already know src/dst IP/port
	 */
	if ((flags & UDP_FLAGS_CONNECTED) != 0) {
		slen = recv(sockfd, data, data_len, sock_flags);
		if (slen <= 0) goto done;

		goto done;
	}

	/*
	 *	Receive the packet.  The OS will discard any data in the
	 *	packet after "len" bytes.
	 */
	slen = recvfromto(sockfd, data, data_len, sock_flags,
			  &socket_out->inet.ifindex,
			  (struct sockaddr *)&src, &sizeof_src,
			  (struct sockaddr *)&dst, &sizeof_dst,
			  when);
	if (slen <= 0) goto done;

	if (fr_ipaddr_from_sockaddr(&socket_out->inet.src_ipaddr, &socket_out->inet.src_port, &src, sizeof_src) < 0) {
		fr_strerror_printf_push("Failed converting src sockaddr to ipaddr");
		return -1;
	}
	if (fr_ipaddr_from_sockaddr(&socket_out->inet.dst_ipaddr, &socket_out->inet.dst_port, &dst, sizeof_dst) < 0) {
		fr_strerror_printf_push("Failed converting dst sockaddr to ipaddr");
		return -1;
	}

done:
	if (slen < 0) {
		if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) return 0;

		fr_strerror_printf("Failed reading socket: %s", fr_syserror(errno));
		return slen;
	}

	/*
	 *	We didn't get it from the kernel
	 *	so use our own time source.
	 */
	if (when && !*when) *when = fr_time();

	return slen;
}
