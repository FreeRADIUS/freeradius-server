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

/**
 * $Id$
 *
 * @file protocols/radius/id.c
 * @brief Functions to allocate 8-bit IDs for a particular socket.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radius/id.h>

struct fr_radius_id_s {
	int			num_free_ids;	//!< number of used IDs

	int			free_start;
	int			free_end;

	fr_radius_id_ctx_t     	id[256];	//!< pointers to request / reply data

	int			free_ids[256];
};



/** Allocate a tracking structure for one packet code.
 *
 */
fr_radius_id_t *fr_radius_id_alloc(TALLOC_CTX *ctx)
{
	int i;
	fr_radius_id_t *track;

	track = talloc_zero(ctx, fr_radius_id_t);
	if (!track) return NULL;

	track->num_free_ids = 256;
	track->free_start = 0;
	track->free_end = 0;

	for (i = 0; i < 256; i++) {
		track->free_ids[i] = i;
	}

	return track;
}

/** Allocate an ID for a packet, using LRU
 *
 */
fr_radius_id_ctx_t *fr_radius_id_pop(fr_radius_id_t *track, fr_packet_t *packet)
{
	int id;

	id = track->free_ids[track->free_start];
	fr_assert(id >= 0);
	fr_assert(id < 256);

	fr_assert(!track->id[id].packet);

	track->free_ids[track->free_start] = -1;

	track->free_start++;
	track->free_start &= 0xff;

	fr_assert(track->num_free_ids > 0);
	track->num_free_ids--;

	track->id[id] = (fr_radius_id_ctx_t) {
		.packet = packet,
	};
	packet->id = id;

	return &track->id[id];
}

/** De-allocate an ID for a packet, using LRU
 *
 */
void fr_radius_id_push(fr_radius_id_t *track, fr_packet_t const *packet)
{
	fr_assert(packet->id >= 0);
	fr_assert(packet->id < 256);

	fr_assert(track->id[packet->id].packet == packet);
	fr_assert(track->num_free_ids < 256);
	fr_assert(track->free_start != track->free_end);
	fr_assert(track->free_end >= 0);
	fr_assert(track->free_end < 256);
	fr_assert(track->free_ids[track->free_end] == -1);

	track->free_ids[track->free_end] = packet->id;

	track->free_end++;
	track->free_end &= 0xff;

	track->id[packet->id].packet = NULL;
	track->num_free_ids++;
}

fr_radius_id_ctx_t *fr_radius_id_find(fr_radius_id_t *track, int id)
{
	fr_assert(id >= 0);
	fr_assert(id < 256);

	return &track->id[id];
}
