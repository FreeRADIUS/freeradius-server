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
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/tmpl.h>

typedef struct fr_state_tree_s fr_state_tree_t;

typedef struct {
	uint32_t		max_sessions;  	//!< maximum number of sessions
	uint32_t		max_rounds;	//!< maximum number of rounds before we give up
	uint32_t		context_id;	//!< internal number to help keep state trees separate
	fr_time_delta_t		timeout;	//!< idle timeout
	tmpl_t			*dedup_key;	//!< for tracking misbehaving supplicants
	uint8_t			server_id;	//!< for mangling State
	bool			thread_safe;	
} fr_state_config_t;

extern const conf_parser_t state_session_config[];

fr_state_tree_t *fr_state_tree_init(TALLOC_CTX *ctx, fr_dict_attr_t const *da, fr_state_config_t const *config);

void	fr_state_discard(fr_state_tree_t *state, request_t *request);

int	fr_state_restore(fr_state_tree_t *state, request_t *request);
int	fr_state_store(fr_state_tree_t *state, request_t *request);

void	fr_state_store_in_parent(request_t *request, void const *unique_ptr, int unique_int);
void	fr_state_restore_from_parent(request_t *child, void const *unique_ptr, int unique_int);
void	fr_state_discard_child(request_t *parent, void const *unique_ptr, int unique_int);

#ifdef __cplusplus
}
#endif
