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

/**
 * $Id$
 *
 * @file protocols/radius/id.h
 * @brief RADIUS bio handlers for tracking 8-bit IDs
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(radius_id_h, "$Id$")

#include <freeradius-devel/radius/radius.h>

typedef struct fr_radius_id_s fr_radius_id_t;

typedef fr_radius_id_t *fr_radius_code_id_t[FR_RADIUS_CODE_MAX];

typedef struct {
	void		*request_ctx;		//!< for the application to track
	fr_packet_t	*packet;		//!< outgoing packet
	fr_packet_t	*response;		//!< response to outgoing packet
	void		*retry_ctx;		//!< to find the retry information
} fr_radius_id_ctx_t;

fr_radius_id_t	*fr_radius_id_alloc(TALLOC_CTX *ctx);

fr_radius_id_ctx_t *fr_radius_id_pop(fr_radius_id_t *track, fr_packet_t *packet) CC_HINT(nonnull);

void		fr_radius_id_push(fr_radius_id_t *track, fr_packet_t const *packet) CC_HINT(nonnull);

fr_radius_id_ctx_t *fr_radius_id_find(fr_radius_id_t *track, int id) CC_HINT(nonnull);

int		fr_radius_id_force(fr_radius_id_t *track, int id) CC_HINT(nonnull);

static inline CC_HINT(nonnull) int fr_radius_code_id_alloc(TALLOC_CTX *ctx, fr_radius_code_id_t codes, int code)
{
	fr_assert(code > 0);
	fr_assert(code < FR_RADIUS_CODE_MAX);

	fr_assert(!codes[code]);

	codes[code] = fr_radius_id_alloc(ctx);
	if (!codes[code]) return -1;

	return 0;
}

static inline CC_HINT(nonnull) fr_radius_id_ctx_t *fr_radius_code_id_pop(fr_radius_code_id_t codes, fr_packet_t *packet)
{
	fr_assert(packet->code > 0);
	fr_assert(packet->code < FR_RADIUS_CODE_MAX);

	fr_assert(codes[packet->code]);

	return fr_radius_id_pop(codes[packet->code], packet);
}

static inline CC_HINT(nonnull) void fr_radius_code_id_push(fr_radius_code_id_t codes, fr_packet_t const *packet)
{
	fr_assert(packet->code > 0);
	fr_assert(packet->code < FR_RADIUS_CODE_MAX);

	fr_assert(codes[packet->code]);

	fr_radius_id_push(codes[packet->code], packet);
}

static inline CC_HINT(nonnull) fr_radius_id_ctx_t *fr_radius_code_id_find(fr_radius_code_id_t codes, int code, int id)
{
	fr_assert(code > 0);
	fr_assert(code < FR_RADIUS_CODE_MAX);

	if (!codes[code]) return NULL;

	return fr_radius_id_find(codes[code], id);
}

static inline CC_HINT(nonnull) int fr_radius_code_id_force(fr_radius_code_id_t codes, int code, int id)
{
	fr_assert(code > 0);
	fr_assert(code < FR_RADIUS_CODE_MAX);

	if (!codes[code]) return -1;

	return fr_radius_id_force(codes[code], id);
}
