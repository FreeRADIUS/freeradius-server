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
#ifndef _FR_UDP_H
#define _FR_UDP_H
/**
 * $Id$
 *
 * @file include/udp.h
 * @brief Abstraction API for sending and receiving packets on UDP sockets.
 *
 * @copyright 2015  The FreeRADIUS server project
 */
RCSIDH(udp_h, "$Id$")

#include <freeradius-devel/libradius.h>

#ifdef WITH_UDPFROMTO
#include <freeradius-devel/udpfromto.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_FLAGS_NONE		(0)
#define UDP_FLAGS_CONNECTED	(1 << 0)
#define UDP_FLAGS_PEEK		(1 << 1)

ssize_t udp_send(int sockfd, void *data, size_t data_len, int flags,
		 fr_ipaddr_t const *src_ipaddr, uint16_t src_port, int if_index,
		 fr_ipaddr_t const *dst_ipaddr, uint16_t dst_port);

int udp_recv_discard(int sockfd);

ssize_t udp_recv_peek(int sockfd, void *data, size_t data_len, int flags, fr_ipaddr_t *src_ipaddr, uint16_t *src_port);

ssize_t udp_recv(int sockfd, void *data, size_t data_len, int flags,
		 fr_ipaddr_t *src_ipaddr, uint16_t *src_port,
		 fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port, int *if_index,
		 struct timeval *when);

#ifdef __cplusplus
}
#endif
#endif /* _FR_UDP_H */
