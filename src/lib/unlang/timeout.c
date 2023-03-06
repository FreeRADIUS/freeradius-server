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
 * @file unlang/timeout.c
 * @brief Unlang "timeout" keyword evaluation.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "group_priv.h"
#include "timeout_priv.h"

typedef struct {
	bool					success;
	int					depth;
	fr_time_delta_t				timeout;
	request_t				*request;
	rindent_t				indent;
	fr_event_timer_t const			*ev;

	fr_value_box_list_t			result;
} unlang_frame_state_timeout_t;

static void unlang_timeout_handler(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(ctx, unlang_frame_state_timeout_t);
	request_t			*request = talloc_get_type_abort(state->request, request_t);

	RDEBUG("Timeout reached, signalling interpreter to cancel child section.");

	/*
	 *	Has to be done BEFORE cancelling the frames, as one might be yielded.
	 */
	unlang_interpret_mark_runnable(request);

	/*
	 *	Signal all lower frames to exit.
	 */
	unlang_frame_signal(request, FR_SIGNAL_CANCEL, state->depth);
	state->success = false;
}

static unlang_action_t unlang_timeout_resume_done(UNUSED rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);

	if (!state->success) {
		RINDENT_RESTORE(request, &state->indent);

		RWDEBUG("Timeout exceeded");
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_timeout_set(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);
	unlang_group_t			*g;
	fr_time_t timeout;

	/*
	 *	Save current indentation for the error path.
	 */
	RINDENT_SAVE(&state->indent, request);

	timeout = fr_time_add(fr_time(), state->timeout);

	if (fr_event_timer_at(state, unlang_interpret_event_list(request), &state->ev, timeout,
			      unlang_timeout_handler, state) < 0) {
		RPEDEBUG("Failed inserting event");
		goto fail;
	}

	g = unlang_generic_to_group(frame->instruction);

	if (unlang_interpret_push(request, g->children, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME) < 0) {
	fail:
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	frame_repeat(frame, unlang_timeout_resume_done);
	state->success = true;

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_timeout_xlat_done(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);
	fr_value_box_t			*box = fr_value_box_list_head(&state->result);

	/*
	 *	compile_timeout() ensures that the tmpl is cast to time_delta, so we don't have to do any more work here.
	 */
	state->timeout = box->vb_time_delta;

	return unlang_timeout_set(p_result, request, frame);
}

static unlang_action_t unlang_timeout(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g;
	unlang_timeout_t		*gext;
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);
	unlang_stack_t			*stack = request->stack;

	g = unlang_generic_to_group(frame->instruction);
	gext = unlang_group_to_timeout(g);

	state->depth = stack->depth;
	state->request = request;

	if (!gext->vpt) {
		state->timeout = gext->timeout;
		return unlang_timeout_set(p_result, request, frame);
	}

	fr_value_box_list_init(&state->result);

	if (unlang_tmpl_push(state, &state->result, request, gext->vpt, NULL) < 0) return UNLANG_ACTION_FAIL;

	frame_repeat(frame, unlang_timeout_xlat_done);

	return UNLANG_ACTION_PUSHED_CHILD;
}


void unlang_timeout_init(void)
{
	unlang_register(UNLANG_TYPE_TIMEOUT,
			   &(unlang_op_t){
				.name = "timeout",
				.interpret = unlang_timeout,
				.debug_braces = true,
				.frame_state_size = sizeof(unlang_frame_state_timeout_t),
				.frame_state_type = "unlang_frame_state_timeout_t",
			   });
}
