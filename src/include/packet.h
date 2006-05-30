#ifndef LRAD_PACKET_H
#define LRAD_PACKET_H

/*
 * packet.h	Structures and prototypes
 *		for packet manipulation
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
 * Copyright 2001,2002,2003,2004,2005,2006  The FreeRADIUS server project
 */

uint32_t lrad_request_packet_hash(const RADIUS_PACKET *packet);
uint32_t lrad_reply_packet_hash(const RADIUS_PACKET *packet);
int lrad_packet_cmp(const RADIUS_PACKET *a, const RADIUS_PACKET *b);
void lrad_request_from_reply(RADIUS_PACKET *request,
			     const RADIUS_PACKET *reply);
int lrad_socket(lrad_ipaddr_t *ipaddr, int port);

#endif /* LRAD_PACKET_H */
