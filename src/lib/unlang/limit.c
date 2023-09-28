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
 * @file unlang/limit.c
 * @brief Unlang "limit" keyword evaluation.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "group_priv.h"
#include "limit_priv.h"

typedef struct {
	uint32_t				active_callers;
} unlang_thread_limit_t;

typedef struct {
	unlang_thread_limit_t			*thread;
	uint32_t				limit;
	request_t				*request;

	fr_value_box_list_t			result;
} unlang_frame_state_limit_t;

/** Send a signal (usually stop) to a request
 *
 * @param[in] request		The current request.
 * @param[in] frame		current stack frame.
 * @param[in] action		to signal.
 */
static void unlang_limit_signal(UNUSED request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);

	if (action == FR_SIGNAL_CANCEL) {
		state->thread->active_callers--;
	}
}

static unlang_action_t unlang_limit_resume_done(UNUSED rlm_rcode_t *p_result, UNUSED request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);

	state->thread->active_callers--;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_limit_enforce(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);
	unlang_action_t			action;

	state->thread = unlang_thread_instance(frame->instruction);
	fr_assert(state->thread != NULL);

	if (state->thread->active_callers >= state->limit) return UNLANG_ACTION_FAIL;

	frame_repeat(frame, unlang_limit_resume_done);

	action = unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_STOP);

	state->thread->active_callers += (action == UNLANG_ACTION_PUSHED_CHILD);

	return action;
}

static unlang_action_t unlang_limit_xlat_done(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);
	fr_value_box_t			*box = fr_value_box_list_head(&state->result);

	/*
	 *	compile_limit() ensures that the tmpl is cast to uint32, so we don't have to do any more work here.
	 */
	state->limit = box->vb_uint32;

	return unlang_limit_enforce(p_result, request, frame);
}

static unlang_action_t unlang_limit(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g;
	unlang_limit_t			*gext;
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);

	g = unlang_generic_to_group(frame->instruction);
	gext = unlang_group_to_limit(g);

	state->request = request;

	if (!gext->vpt) {
		state->limit = gext->limit;
		return unlang_limit_enforce(p_result, request, frame);
	}

	fr_value_box_list_init(&state->result);

	if (unlang_tmpl_push(state, &state->result, request, gext->vpt, NULL) < 0) return UNLANG_ACTION_FAIL;

	frame_repeat(frame, unlang_limit_xlat_done);

	return UNLANG_ACTION_PUSHED_CHILD;
}


void unlang_limit_init(void)
{
	unlang_register(UNLANG_TYPE_LIMIT,
			   &(unlang_op_t){
				.name = "limit",
				.interpret = unlang_limit,
				.signal = unlang_limit_signal,
				.debug_braces = true,
				.frame_state_size = sizeof(unlang_frame_state_limit_t),
				.frame_state_type = "unlang_frame_state_limit_t",

				.thread_inst_size = sizeof(unlang_thread_limit_t),
				.thread_inst_type = "unlang_thread_limit_t",
			   });
}
