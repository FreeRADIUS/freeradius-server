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

/** API for sending and receiving packets on unconnected UDP sockets
 *
 * Like recvfrom, but also stores the destination IP address. Useful on multihomed hosts.
 *
 * @file src/lib/util/udpfromto.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(udpfromto_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/time.h>

#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>

int	udpfromto_init(int s);

int	recvfromto(int s, void *buf, size_t len, int flags,
		   int *ifindex,
	       	   struct sockaddr *from, socklen_t *fromlen,
		   struct sockaddr *to, socklen_t *tolen,
		   fr_time_t *when);

int	sendfromto(int s, void *buf, size_t len, int flags,
		   int ifindex,
		   struct sockaddr *from, socklen_t fromlen,
		   struct sockaddr *to, socklen_t tolen);
#ifdef __cplusplus
}
#endif
