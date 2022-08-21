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
	bool			success;			//!< If set, where to record the result
								///< of the execution.
} unlang_frame_state_cond_t;

static unlang_action_t unlang_if_resume(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_cond_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_cond_t);
	fr_value_box_t			*box = fr_dlist_head(&state->out);
	bool				value;

	if (!box) {
		value = false;

	} else if (fr_dlist_next(&state->out, box) != NULL) {
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

static unlang_action_t unlang_if(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_cond_t			*gext = unlang_group_to_cond(g);
	unlang_frame_state_cond_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_cond_t);

	/*
	 *	Migration support.
	 */
	if (!main_config->use_new_conditions) {
		fr_assert(gext->cond != NULL);

		if (!cond_eval(request, *p_result, gext->cond)) {
			RDEBUG2("...");
			return UNLANG_ACTION_EXECUTE_NEXT;
		}

		/*
		 *      Tell the main interpreter to skip over the else /
		 *      elsif blocks, as this "if" condition was taken.
		 */
		while (frame->next &&
		       ((frame->next->type == UNLANG_TYPE_ELSE) ||
			(frame->next->type == UNLANG_TYPE_ELSIF))) {
			frame->next = frame->next->next;
		}

		/*
		 *      We took the "if".  Go recurse into its' children.
		 */
		return unlang_group(p_result, request, frame);
	}

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

	/*
	 *	Make the rcode available to the caller.  Note that the caller can't call
	 *	unlang_interpret_stack_result(), as that returns the result from the xlat frame, and not from
	 *	the calling frame.
	 */
	request->rcode = *p_result;

	if (unlang_xlat_push(state, &state->success, &state->out,
			     request, gext->head, UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

void unlang_condition_init(void)
{
	unlang_register(UNLANG_TYPE_IF,
			   &(unlang_op_t){
				.name = "if",
				.interpret = unlang_if,
				.debug_braces = true,
				.frame_state_size = sizeof(unlang_frame_state_cond_t),
				.frame_state_type = "unlang_frame_state_cond_t",
			   });

	unlang_register(UNLANG_TYPE_ELSE,
			   &(unlang_op_t){
				.name = "else",
				.interpret = unlang_group,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_ELSIF,
			   &(unlang_op_t){
				.name = "elseif",
				.interpret = unlang_if,
				.debug_braces = true,
				.frame_state_size = sizeof(unlang_frame_state_cond_t),
				.frame_state_type = "unlang_frame_state_cond_t",
			   });
}
