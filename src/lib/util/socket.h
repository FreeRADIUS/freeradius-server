#pragma once

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions for establishing and managing low level sockets
 *
 * @file src/lib/util/socket.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2015 The FreeRADIUS project
 */
RCSIDH(socket_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/time.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

bool		fr_socket_is_valid_proto(int proto);
int		fr_socket_client_unix(char const *path, bool async);
int		fr_socket_client_udp(fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t const *dst_ipaddr,
				     uint16_t dst_port, bool async);
int		fr_socket_client_tcp(fr_ipaddr_t const *src_ipaddr, fr_ipaddr_t const *dst_ipaddr,
				     uint16_t dst_port, bool async);
int		fr_socket_wait_for_connect(int sockfd, fr_time_delta_t timeout);

int		fr_socket_server_udp(fr_ipaddr_t const *ipaddr, uint16_t *port, char const *port_name, bool async);
int		fr_socket_server_tcp(fr_ipaddr_t const *ipaddr, uint16_t *port, char const *port_name, bool async);
int		fr_socket_bind(int sockfd, fr_ipaddr_t const *ipaddr, uint16_t *port, char const *interface);

#ifdef __cplusplus
}
#endif
