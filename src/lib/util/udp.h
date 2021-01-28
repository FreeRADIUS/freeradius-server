#pragma once
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

/** Utility functions for managing UDP sockets
 *
 * @file src/lib/util/udp.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(udp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/udpfromto.h>

#define UDP_FLAGS_NONE		(0)
#define UDP_FLAGS_CONNECTED	(1 << 0)
#define UDP_FLAGS_PEEK		(1 << 1)

int udp_send(fr_socket_t const *socket, int flags, void *data, size_t data_len);

int udp_recv_discard(int sockfd);

ssize_t udp_recv_peek(int sockfd, void *data, size_t data_len, int flags, fr_ipaddr_t *src_ipaddr, uint16_t *src_port);

ssize_t udp_recv(int sockfd, int flags,
		 fr_socket_t *socket_out, void *data, size_t data_len, fr_time_t *when);

#ifdef __cplusplus
}
#endif
