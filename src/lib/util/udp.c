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
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/udp.h>

/*
 *	This is easier than ifdef's in the function definition.
 */
#ifdef WITH_UDPFROMTO
#define UDP_UNUSED
#else
#define UDP_UNUSED UNUSED
#endif

#define FR_DEBUG_STRERROR_PRINTF if (fr_debug_lvl) fr_strerror_printf

/** Send a packet via a UDP socket.
 *
 * @param[in] sockfd we're reading from.
 * @param[in] data pointer to data to send
 * @param[in] data_len length of data to send
 * @param[in] flags to pass to send(), or sendto()
 * @param[in] src_ipaddr of the packet.
 * @param[in] src_port of the packet.
 * @param[in] if_index of the packet.
 * @param[in] dst_ipaddr of the packet.
 * @param[in] dst_port of the packet.
 */
ssize_t udp_send(int sockfd, void *data, size_t data_len, int flags,
		 UDP_UNUSED fr_ipaddr_t const *src_ipaddr, UDP_UNUSED uint16_t src_port, UDP_UNUSED int if_index,
		 fr_ipaddr_t const *dst_ipaddr, uint16_t dst_port)
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
		if (fr_ipaddr_to_sockaddr(dst_ipaddr, dst_port, &dst, &sizeof_dst) < 0) return -1;

#ifdef WITH_UDPFROMTO
		/*
		 *	And if they don't specify a source IP address, don't
		 *	use udpfromto.
		 */
		if ((src_ipaddr->af != AF_UNSPEC) && (dst_ipaddr->af != AF_UNSPEC) &&
		    !fr_ipaddr_is_inaddr_any(src_ipaddr)) {
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
	if (fr_ipaddr_from_sockaddr(&src, sizeof_src, src_ipaddr, src_port) < 0) {
		FR_DEBUG_STRERROR_PRINTF("Unknown address family");
		(void) udp_recv_discard(sockfd);

		return -1;
	}

	return peeked;
}


/** Read a UDP packet
 *
 * @param[in] sockfd we're reading from.
 * @param[out] data pointer where data will be written
 * @param[in] data_len length of data to read
 * @param[in] flags for things
 * @param[out] src_ipaddr of the packet.
 * @param[out] src_port of the packet.
 * @param[out] dst_ipaddr of the packet.
 * @param[out] dst_port of the packet.
 * @param[out] if_index of the interface that received the packet.
 * @param[out] when the packet was received.
 * @return
 *	- > 0 on success (number of bytes read).
 *	- < 0 on failure.
 */
ssize_t udp_recv(int sockfd, void *data, size_t data_len, int flags,
		 fr_ipaddr_t *src_ipaddr, uint16_t *src_port,
		 fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port, int *if_index,
		 fr_time_t *when)
{
	int			sock_flags = 0;
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src = sizeof(src);
	socklen_t		sizeof_dst = sizeof(dst);
	ssize_t			received;
	uint16_t		port;

	if ((flags & UDP_FLAGS_PEEK) != 0) sock_flags |= MSG_PEEK;

	if (when) *when = 0;

	/*
	 *	Connected sockets already know src/dst IP/port
	 */
	if ((flags & UDP_FLAGS_CONNECTED) != 0) {
		received = recv(sockfd, data, data_len, sock_flags);
		goto done;
	}

	/*
	 *	Receive the packet.  The OS will discard any data in the
	 *	packet after "len" bytes.
	 */
#ifdef WITH_UDPFROMTO
	if (dst_ipaddr) {
		received = recvfromto(sockfd, data, data_len, sock_flags,
				      (struct sockaddr *)&src, &sizeof_src,
				      (struct sockaddr *)&dst, &sizeof_dst,
				      if_index, when);
		if (received <= 0) goto done;
	} else {
		received = recvfrom(sockfd, data, data_len, sock_flags,
				    (struct sockaddr *)&src, &sizeof_src);
		if (received <= 0) goto done;
	}
#else
	received = recvfrom(sockfd, data, data_len, sock_flags,
			    (struct sockaddr *)&src, &sizeof_src);
	if (received <= 0) goto done;

	/*
	 *	Get the destination address, if requested.
	 */
	if (dst_ipaddr && (getsockname(sockfd, (struct sockaddr *)&dst, &sizeof_dst) < 0)) {
		return -1;
	}

	if (if_index) *if_index = 0;
#endif

	if (fr_ipaddr_from_sockaddr(&src, sizeof_src, src_ipaddr, &port) < 0) {
		fr_strerror_printf_push("Failed converting sockaddr to ipaddr");
		return -1;
	}

	*src_port = port;

	if (dst_ipaddr) {
		fr_ipaddr_from_sockaddr(&dst, sizeof_dst, dst_ipaddr, &port);
		*dst_port = port;
	}

done:
	if (received < 0) {
		if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) return 0;

		fr_strerror_printf("Failed reading socket: %s", fr_syserror(errno));
		return received;
	}

	/*
	 *	We didn't get it from the kernel
	 *	so use our own time source.
	 */
	if (when && !*when) *when = fr_time();

	return received;
}
