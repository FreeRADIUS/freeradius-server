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

/** fr_radius_packet_t alloc/free functions
 *
 * @file src/lib/util/packet.c
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/talloc.h>

/** Allocate a new fr_radius_packet_t
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a request_t.
 * @param new_vector if true a new request authenticator will be generated.
 * @return
 *	- New fr_radius_packet_t.
 *	- NULL on error.
 */
fr_radius_packet_t *fr_radius_packet_alloc(TALLOC_CTX *ctx, bool new_vector)
{
	fr_radius_packet_t	*rp;

	rp = talloc_zero(ctx, fr_radius_packet_t);
	if (!rp) {
		fr_strerror_const("out of memory");
		return NULL;
	}
	rp->id = -1;

	if (new_vector) fr_rand_buffer(rp->vector, sizeof(rp->vector));

	return rp;
}

/** Allocate a new fr_radius_packet_t response
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a request_t.
 * @param packet The request packet.
 * @return
 *	- New fr_radius_packet_t.
 *	- NULL on error.
 */
fr_radius_packet_t *fr_radius_packet_alloc_reply(TALLOC_CTX *ctx, fr_radius_packet_t *packet)
{
	fr_radius_packet_t *reply;

	if (!packet) return NULL;

	reply = fr_radius_packet_alloc(ctx, false);
	if (!reply) return NULL;

	/*
	 *	Initialize the fields from the request.
	 */
	fr_socket_addr_swap(&reply->socket, &packet->socket);
	reply->id = packet->id;
	reply->code = 0; /* UNKNOWN code */
	memset(reply->vector, 0, sizeof(reply->vector));
	reply->data = NULL;
	reply->data_len = 0;

	return reply;
}


/** Free a fr_radius_packet_t
 *
 */
void fr_radius_packet_free(fr_radius_packet_t **packet_p)
{
	fr_radius_packet_t *packet;

	if (!packet_p || !*packet_p) return;
	packet = *packet_p;

	PACKET_VERIFY(packet);

	talloc_free(packet);
	*packet_p = NULL;
}
