/*
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
 */

/**
 * $Id$
 *
 * @file unlang/caller.c
 * @brief Unlang "caller" keyword evaluation.  Used for setting allowed parent protocols
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/state.h>

#include "caller_priv.h"
#include "unlang_priv.h"
#include "group_priv.h"

static unlang_action_t unlang_caller(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_caller_t			*gext = unlang_group_to_caller(g);

	fr_assert(g->num_children > 0); /* otherwise the compilation is broken */

	/*
	 *	No parent, or the dictionaries don't match.  Ignore it.
	 */
	if (!request->parent || (request->parent->dict != gext->dict)) {
		RDEBUG2("...");
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	/*
	 *	The dictionary matches.  Go recurse into its' children.
	 */
	return unlang_group(p_result, request, frame);
}


void unlang_caller_init(void)
{
	unlang_register(UNLANG_TYPE_CALLER,
			   &(unlang_op_t){
				.name = "caller",
				.interpret = unlang_caller,
				.debug_braces = true
			   });
}
