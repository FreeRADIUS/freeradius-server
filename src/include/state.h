#ifndef FR_STATE_H
#define FR_STATE_H

/*
 * state.h	handle multi-packet state
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
 * Copyright 2014 The FreeRADIUS server project
 * Copyright 2014 Alan DeKok <aland@deployingradius.com>
 */

RCSIDH(state_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_state_t fr_state_t;

fr_state_t *fr_state_init(TALLOC_CTX *ctx);
void fr_state_delete(fr_state_t *state);

void fr_state_discard(REQUEST *request, RADIUS_PACKET *original);

void fr_state_get_vps(REQUEST *request, RADIUS_PACKET *packet);
bool fr_state_put_vps(REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet);

void *fr_state_find_data(fr_state_t *state, REQUEST *request, RADIUS_PACKET *packet);
void *fr_state_get_data(fr_state_t *state, REQUEST *request, RADIUS_PACKET *packet);
bool fr_state_put_data(fr_state_t *state, REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet,
		       void *data, void (*free_data)(void *));

#ifdef __cplusplus
}
#endif

#endif /* FR_HASH_H */
