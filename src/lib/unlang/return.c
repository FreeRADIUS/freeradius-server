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
 * @file unlang/return.c
 * @brief Unlang "return" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "return_priv.h"

unlang_action_t unlang_return(REQUEST *request, rlm_rcode_t *presult, int *priority)
{
	int			i;
	VALUE_PAIR		**copy_p;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;

	RDEBUG2("%s", unlang_ops[instruction->type].name);

	/*
	 *	Allow "return" in the middle of a "foreach".  Which is
	 *	also a "break".
	 */
	for (i = 8; i >= 0; i--) {
		copy_p = request_data_get(request, (void *)xlat_fmt_get_vp, i);
		if (copy_p) {
			if (instruction->type == UNLANG_TYPE_BREAK) {
				RDEBUG2("# break Foreach-Variable-%d", i);
				break;
			}
		}
	}

	stack->unwind = instruction->type;

	*presult = frame->result;
	*priority = frame->priority;

	return UNLANG_ACTION_BREAK;
}

void unlang_return_init(void)
{
	unlang_register(UNLANG_TYPE_RETURN,
			   &(unlang_op_t){
				.name = "return",
				.func = unlang_return,
			   });
}
