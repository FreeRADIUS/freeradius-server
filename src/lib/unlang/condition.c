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
 * @file unlang/condition.c
 * @brief Unlang "condition" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "condition_priv.h"
#include "group_priv.h"

typedef struct {
	fr_value_box_list_t	out;				//!< Head of the result of a nested
								///< expansion.
	unlang_result_t		result;				//!< Store the result of unlang expressions.
} unlang_frame_state_cond_t;

static unlang_action_t unlang_if_resume(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_cond_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_cond_t);
	fr_value_box_t			*box = fr_value_box_list_head(&state->out);
	bool				value;

	/*
	 *	Something in the conditional evaluation failed.
	 */
	if (state->result.rcode == RLM_MODULE_FAIL) {
		unlang_group_t *g = unlang_generic_to_group(frame->instruction);
		unlang_cond_t  *gext = unlang_group_to_cond(g);

		RDEBUG2("... failed to evaluate condition ...");

		if (!gext->has_else) RETURN_UNLANG_FAIL;
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	if (!box) {
		value = false;

	} else if (fr_value_box_list_next(&state->out, box) != NULL) {
		value = true;

	} else {
		value = fr_value_box_is_truthy(box);
	}

	if (!value) {
		RDEBUG2("...");
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	/*
	 *	Tell the main interpreter to skip over the else /
	 *	elsif blocks, as this "if" condition was taken.
	 */
	while (frame->next &&
	       ((frame->next->type == UNLANG_TYPE_ELSE) ||
		(frame->next->type == UNLANG_TYPE_ELSIF))) {
		frame->next = frame->next->next;
	}

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	return unlang_group(p_result, request, frame);
}

static unlang_action_t unlang_if(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_cond_t			*gext = unlang_group_to_cond(g);
	unlang_frame_state_cond_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_cond_t);

	fr_assert(gext->head != NULL);

	/*
	 *	If we always run this condition, then don't bother pushing anything onto the stack.
	 *
	 *	We still run this condition, even for "false" values, due to things like
	 *
	 *		if (0) { ... } elsif ....
	 */
	if (gext->is_truthy) {
		return unlang_group(p_result, request, frame);
	}

	frame_repeat(frame, unlang_if_resume);

	fr_value_box_list_init(&state->out);

	if (unlang_xlat_push(state, &state->result, &state->out,
			     request, gext->head, UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

void unlang_condition_init(void)
{
	unlang_register(UNLANG_TYPE_IF,
			   &(unlang_op_t){
				.name = "if",
				.type = UNLANG_TYPE_IF,
				.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

				.interpret = unlang_if,

				.unlang_size = sizeof(unlang_cond_t),
				.unlang_name = "unlang_cond_t",
				.pool_headers = 1 + 1 + (TMPL_POOL_DEF_HEADERS * 2),
				.pool_len = sizeof(map_t) + (TMPL_POOL_DEF_LEN * 2),

				.frame_state_size = sizeof(unlang_frame_state_cond_t),
				.frame_state_type = "unlang_frame_state_cond_t",
			   });

	unlang_register(UNLANG_TYPE_ELSE,
			   &(unlang_op_t){
				.name = "else",
				.type = UNLANG_TYPE_ELSE,
				.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

				.interpret = unlang_group,

				.unlang_size = sizeof(unlang_group_t),
				.unlang_name = "unlang_group_t"	
		   });

	unlang_register(UNLANG_TYPE_ELSIF,
			   &(unlang_op_t){
				.name = "elseif",
				.type = UNLANG_TYPE_ELSIF,
				.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

				.interpret = unlang_if,

				.unlang_size = sizeof(unlang_cond_t),
				.unlang_name = "unlang_cond_t",
				.pool_headers = 1 + 1 + (TMPL_POOL_DEF_HEADERS * 2),
				.pool_len = sizeof(map_t) + (TMPL_POOL_DEF_LEN * 2),

				.frame_state_size = sizeof(unlang_frame_state_cond_t),
				.frame_state_type = "unlang_frame_state_cond_t",
			   });
}
