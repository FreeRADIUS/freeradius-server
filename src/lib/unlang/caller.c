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
 */
RCSID("$Id$")

#include <freeradius-devel/server/state.h>
#include "unlang_priv.h"
#include "group_priv.h"

static unlang_action_t unlang_caller(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;

	unlang_group_t			*g;

	g = unlang_generic_to_group(instruction);
	fr_assert(g->num_children > 0); /* otherwise the compilation is broken */

	/*
	 *	No parent, or the dictionaries don't match.  Ignore it.
	 */
	if (!request->parent || (request->parent->dict != g->dict)) {
		RDEBUG2("...");
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	/*
	 *	The dictionary matches.  Go recurse into its' children.
	 */
	return unlang_group(request, presult);
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
