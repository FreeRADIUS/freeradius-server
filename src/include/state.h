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
#ifndef _FR_STATE_H
#define _FR_STATE_H
/**
 * $Id$
 *
 * @file include/stats.h
 * @brief Track overarching 'state' of the authentication session over multiple packets.
 *
 * @copyright 2014 The FreeRADIUS server project
 * @copyright 2014 Alan DeKok <aland@deployingradius.com>
 */
RCSIDH(state_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_state_tree_t fr_state_tree_t;
extern fr_state_tree_t *global_state;

fr_state_tree_t *fr_state_tree_init(TALLOC_CTX *ctx, uint32_t max_sessions, uint32_t timeout);

void fr_state_discard(fr_state_tree_t *state, REQUEST *request, RADIUS_PACKET *original);

void fr_state_to_request(fr_state_tree_t *state, REQUEST *request, RADIUS_PACKET *packet);
int fr_request_to_state(fr_state_tree_t *state, REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet);

/*
 *	Stats
 */
uint64_t fr_state_entries_created(fr_state_tree_t *state);
uint64_t fr_state_entries_timeout(fr_state_tree_t *state);
uint32_t fr_state_entries_tracked(fr_state_tree_t *state);

#ifdef __cplusplus
}
#endif
#endif /* _FR_STATE_H */
