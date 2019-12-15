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
 * @file lib/server/state.h
 * @brief Track overarching 'state' of the authentication session over multiple packets.
 *
 * @copyright 2014 The FreeRADIUS server project
 * @copyright 2014 Alan DeKok (aland@deployingradius.com)
 */
RCSIDH(state_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/server/request.h>

typedef struct fr_state_tree_s fr_state_tree_t;

fr_state_tree_t *fr_state_tree_init(TALLOC_CTX *ctx, fr_dict_attr_t const *da, bool thread_safe,
				    uint32_t max_sessions, uint32_t timeout, uint8_t server_id);

void	fr_state_discard(fr_state_tree_t *state, REQUEST *request);

void	fr_state_to_request(fr_state_tree_t *state, REQUEST *request);
int	fr_request_to_state(fr_state_tree_t *state, REQUEST *request);

void	fr_state_store_in_parent(REQUEST *request, void const *unique_ptr, int unique_int);
void	fr_state_restore_to_child(REQUEST *request, void const *unique_ptr, int unique_int);
void	fr_state_detach(REQUEST *request, bool will_free);
/*
 *	Stats
 */
uint64_t fr_state_entries_created(fr_state_tree_t *state);
uint64_t fr_state_entries_timeout(fr_state_tree_t *state);
uint32_t fr_state_entries_tracked(fr_state_tree_t *state);

#ifdef __cplusplus
}
#endif
