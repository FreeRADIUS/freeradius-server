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

unlang_action_t unlang_return(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	/*
	 *	As we're unwinding intermediary frames we
	 *	won't be taking their rcodes or priorities
	 *	into account.  We do however want to record
	 *	the current section rcode.
	 */
	*p_result = frame->section_result;

	/*
	 *	Stop at the next return point, or if we hit
	 *	the a top frame.
	 */
	return unwind_to_op_flag(NULL, request->stack, UNLANG_OP_FLAG_RETURN_POINT);
}

static unlang_t *unlang_compile_return(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, UNUSED CONF_ITEM const *ci)
{
	/*
	 *	These types are all parallel, and therefore can have a "return" in them.
	 */
	switch (parent->type) {
	case UNLANG_TYPE_LOAD_BALANCE:
	case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
	case UNLANG_TYPE_PARALLEL:
		break;

	default:
		parent->closed = true;
		break;
	}

	return unlang_compile_empty(parent, unlang_ctx, NULL, UNLANG_TYPE_RETURN);
}

void unlang_return_init(void)
{
	unlang_register(UNLANG_TYPE_RETURN,
			   &(unlang_op_t){
				.name = "return",
				.type = UNLANG_TYPE_RETURN,
				.flag = UNLANG_OP_FLAG_SINGLE_WORD,

				.compile = unlang_compile_return,
				.interpret = unlang_return,

				.unlang_size = sizeof(unlang_group_t),
				.unlang_name = "unlang_group_t",
			   });
}
