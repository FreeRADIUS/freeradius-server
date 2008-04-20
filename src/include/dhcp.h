#ifndef FR_DHCP_H
#define FR_DHCP_H

/*
 * dhcp.h	Structures and prototypes for DHCP.
 *		Why DHCP in a RADIUS server?
 *		Why not?
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2008 The FreeRADIUS server project
 * Copyright 2008 Alan DeKok <aland@deployingradius.com>
 */
#include <freeradius-devel/ident.h>
RCSIDH(dhcp_h, "$Id$")

/*
 *	Not for production use.
 */
RADIUS_PACKET *fr_dhcp_recv(int sockfd);
int fr_dhcp_send(RADIUS_PACKET *packet);

int fr_dhcp_encode(RADIUS_PACKET *packet, RADIUS_PACKET *original);
int fr_dhcp_decode(RADIUS_PACKET *packet);

/*
 *	This is a horrible hack.
 */
#define PW_DHCP_OFFSET		(1024)
#define PW_DHCP_DISCOVER	(1024 + 1)
#define PW_DHCP_OFFER		(1024 + 2)
#define PW_DHCP_REQUEST		(1024 + 3)
#define PW_DHCP_DECLINE		(1024 + 4)
#define PW_DHCP_ACK		(1024 + 5)
#define PW_DHCP_NAK		(1024 + 6)
#define PW_DHCP_RELEASE		(1024 + 7)
#define PW_DHCP_INFORM		(1024 + 8)

#define DHCP_MAGIC_VENDOR (54)
#define DHCP2ATTR(x) ((DHCP_MAGIC_VENDOR << 16) | (x))
#define ATTR2DHCP(x) ((x) & 0xff)
#define IS_DHCP_ATTR(x) (VENDOR((x)->attribute) == DHCP_MAGIC_VENDOR)

#define PW_DHCP_OPTION_82 (82)
#define DHCP_PACK_OPTION1(x,y) ((x) | ((y) << 8))
#define DHCP_BASE_ATTR(x) (x & 0xff)
#define DHCP_UNPACK_OPTION1(x) (((x) & 0xff00) >> 8)

/*
 *	In src/lib/missing.c
 */
void
timeval2ntp(const struct timeval *tv, uint8_t *ntp);
void
ntp2timeval(struct timeval *tv, const char *ntp);

#endif /* FR_DHCP_H */
