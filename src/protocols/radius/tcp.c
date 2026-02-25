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

/**
 * $Id$
 *
 * @file protocols/radius/packet.c
 * @brief TCP-specific functions.
 *
 * @copyright (C) 2009 Dante http://dante.net
 */
RCSID("$Id$")

#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/util/syserror.h>
#include "tcp.h"

/*
 *	This ASSUMES that the socket is marked as O_NONBLOCK, which
 *	the function above does set, if your system supports it.
 */
ssize_t fr_tcp_read_packet(int sockfd, uint8_t *buffer, size_t size, size_t *total, uint32_t max_attributes, bool require_message_authenticator)
{
	ssize_t slen;
	size_t packet_len, hdr_len;
	uint8_t *start, *end;

	fr_assert(*total < size);
	start = buffer + *total;
	end = buffer + size;

	slen = recv(sockfd, start, (size_t) (end - start), 0);
	if (slen <= 0) return -1;

	packet_len = *total + slen;

	/*
	 *	Not enough for a header, die.
	 */
	if (packet_len < 4) return 0;

	hdr_len = fr_nbo_to_uint16(buffer + 2);
	if ((hdr_len < RADIUS_HEADER_LENGTH) || (hdr_len >  RADIUS_MAX_PACKET_SIZE)) return -1;

	if (packet_len < hdr_len) {
		*total = packet_len;
		return 0;
	}

	/*
	 *	See if it's a well-formed RADIUS packet.
	 */
	if (!fr_radius_ok(buffer, &hdr_len, max_attributes, require_message_authenticator, NULL)) {
		return -1;
	}

	return hdr_len;
}
