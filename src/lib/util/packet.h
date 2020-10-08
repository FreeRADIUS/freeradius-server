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

/** Structures and functions for packet manipulation
 *
 * @file src/lib/util/packet.h
 *
 * @copyright 2001, 2002, 2003, 2004, 2005, 2006 The FreeRADIUS server project
 */
RCSIDH(packet_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/time.h>

#ifdef WITH_VERIFY_PTR
#  define PACKET_VERIFY(_x)	(void) talloc_get_type_abort_const(_x, RADIUS_PACKET)
#else
#  define PACKET_VERIFY(_x)	fr_cond_assert(_x)
#endif

#define RADIUS_AUTH_VECTOR_LENGTH		16

/*
 *	vector:		Request authenticator from access-request packet
 *			Put in there by rad_decode, and must be put in the
 *			response RADIUS_PACKET as well before calling fr_radius_packet_send
 *
 *	verified:	Filled in by rad_decode for accounting-request packets
 *
 *	data,data_len:	Used between fr_radius_recv and fr_radius_decode.
 */
typedef struct {
	int			sockfd;			//!< Socket this packet was read from.
	int			ifindex;		//!< Index of receiving interface.
	fr_ipaddr_t		src_ipaddr;		//!< Src IP address of packet.
	fr_ipaddr_t		dst_ipaddr;		//!< Dst IP address of packet.
	uint16_t		src_port;		//!< Src port of packet.
	uint16_t		dst_port;		//!< DST Port of packet.

	int			id;			//!< Packet ID (used to link requests/responses).
	unsigned int		code;			//!< Packet code (type).

	uint8_t			vector[RADIUS_AUTH_VECTOR_LENGTH];//!< RADIUS authentication vector.

	uint32_t       		count;			//!< Number of times we've seen this packet
	fr_time_t		timestamp;		//!< When we received the packet.
	uint8_t			*data;			//!< Packet data (body).
	size_t			data_len;		//!< Length of packet data.
	VALUE_PAIR		*vps;			//!< Result of decoding the packet into VALUE_PAIRs.

	uint32_t       		rounds;			//!< for State[0]

	size_t			partial;
	int			proto;
} RADIUS_PACKET;

RADIUS_PACKET	*fr_radius_alloc(TALLOC_CTX *ctx, bool new_vector);
RADIUS_PACKET	*fr_radius_alloc_reply(TALLOC_CTX *ctx, RADIUS_PACKET *);
RADIUS_PACKET	*fr_radius_copy(TALLOC_CTX *ctx, RADIUS_PACKET const *in);
void		fr_radius_packet_free(RADIUS_PACKET **);

#ifdef __cplusplus
}
#endif
