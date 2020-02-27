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

/** RADIUS_PACKET alloc/free functions
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

#include <talloc.h>

/** Allocate a new RADIUS_PACKET
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a REQUEST.
 * @param new_vector if true a new request authenticator will be generated.
 * @return
 *	- New RADIUS_PACKET.
 *	- NULL on error.
 */
RADIUS_PACKET *fr_radius_alloc(TALLOC_CTX *ctx, bool new_vector)
{
	RADIUS_PACKET	*rp;

	rp = talloc_zero(ctx, RADIUS_PACKET);
	if (!rp) {
		fr_strerror_printf("out of memory");
		return NULL;
	}
	rp->id = -1;

	if (new_vector) {
		fr_rand_buffer(rp->vector, sizeof(rp->vector));
	}

	return rp;
}

/** Allocate a new RADIUS_PACKET response
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a REQUEST.
 * @param packet The request packet.
 * @return
 *	- New RADIUS_PACKET.
 *	- NULL on error.
 */
RADIUS_PACKET *fr_radius_alloc_reply(TALLOC_CTX *ctx, RADIUS_PACKET *packet)
{
	RADIUS_PACKET *reply;

	if (!packet) return NULL;

	reply = fr_radius_alloc(ctx, false);
	if (!reply) return NULL;

	/*
	 *	Initialize the fields from the request.
	 */
	reply->sockfd = packet->sockfd;
	reply->dst_ipaddr = packet->src_ipaddr;
	reply->src_ipaddr = packet->dst_ipaddr;
	reply->dst_port = packet->src_port;
	reply->src_port = packet->dst_port;
	reply->if_index = packet->if_index;
	reply->id = packet->id;
	reply->code = 0; /* UNKNOWN code */
	memset(reply->vector, 0,
	       sizeof(reply->vector));
	reply->vps = NULL;
	reply->data = NULL;
	reply->data_len = 0;
	reply->proto = packet->proto;

	return reply;
}


/** Free a RADIUS_PACKET
 *
 */
void fr_radius_packet_free(RADIUS_PACKET **packet_p)
{
	RADIUS_PACKET *packet;

	if (!packet_p || !*packet_p) return;
	packet = *packet_p;

	PACKET_VERIFY(packet);

	fr_pair_list_free(&packet->vps);

	talloc_free(packet);
	*packet_p = NULL;
}

/** Duplicate a RADIUS_PACKET
 *
 * @param ctx the context in which the packet is allocated. May be NULL if
 *	the packet is not associated with a REQUEST.
 * @param in The packet to copy
 * @return
 *	- New RADIUS_PACKET.
 *	- NULL on error.
 */
RADIUS_PACKET *fr_radius_copy(TALLOC_CTX *ctx, RADIUS_PACKET const *in)
{
	RADIUS_PACKET *packet;

	packet = fr_radius_alloc(ctx, false);
	if (!packet) return NULL;

	/*
	 *	Bootstrap by copying everything.
	 */
	memcpy(packet, in, sizeof(*packet));

	/*
	 *	Then reset necessary fields
	 */
	packet->sockfd = -1;

	packet->data = NULL;
	packet->data_len = 0;

	if (fr_pair_list_copy(packet, &packet->vps, in->vps) < 0) {
		talloc_free(packet);
		return NULL;
	}

	return packet;
}
