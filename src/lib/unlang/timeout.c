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

#include <freeradius-devel/unlang/timeout.h>
#include "group_priv.h"
#include "timeout_priv.h"
#include "interpret_priv.h"

typedef struct {
	bool					success;
	int					depth;
	fr_time_delta_t				timeout;
	request_t				*request;
	rindent_t				indent;
	fr_timer_t				*ev;

	fr_value_box_list_t			result;

	unlang_t				*instruction;	//!< to run on timeout
} unlang_frame_state_timeout_t;

static void unlang_timeout_handler(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *ctx)
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

	if (!state->instruction) return;

	if (unlang_interpret_push_instruction(request, state->instruction, RLM_MODULE_FAIL, true) < 0) {
		REDEBUG("Failed pushing timeout instruction - cancelling the request");
		unlang_interpret_request_stop(request);
	}
}

static unlang_action_t unlang_timeout_resume_done(UNUSED rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);

	if (!state->success) {
		RINDENT_RESTORE(request, state);

		RWDEBUG("Timeout exceeded");
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_timeout_set(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);
	fr_time_t timeout;

	/*
	 *	Save current indentation for the error path.
	 */
	RINDENT_SAVE(state, request);

	timeout = fr_time_add(fr_time(), state->timeout);

	if (fr_timer_at(state, unlang_interpret_event_list(request)->tl, &state->ev, timeout,
			false, unlang_timeout_handler, state) < 0) {
		RPEDEBUG("Failed inserting event");
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	frame_repeat(frame, unlang_timeout_resume_done);
	state->success = true;

	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
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

/** When a timeout fires, run the given section.
 *
 * @param[in] request		to push timeout onto
 * @param[in] timeout		when to run the timeout
 * @param[in] cs		section to run when the timeout fires.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_timeout_section_push(request_t *request, CONF_SECTION *cs, fr_time_delta_t timeout)
{
	/** Static instruction for performing xlat evaluations
	 *
	 */
	static unlang_t timeout_instruction = {
		.type = UNLANG_TYPE_TIMEOUT,
		.name = "timeout",
		.debug_name = "timeout",
		.actions = {
			.actions = {
				[RLM_MODULE_REJECT]	= 0,
				[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,	/* Exit out of nested levels */
				[RLM_MODULE_OK]		= 0,
				[RLM_MODULE_HANDLED]	= 0,
				[RLM_MODULE_INVALID]	= 0,
				[RLM_MODULE_DISALLOW]	= 0,
				[RLM_MODULE_NOTFOUND]	= 0,
				[RLM_MODULE_NOOP]	= 0,
				[RLM_MODULE_UPDATED]	= 0
			},
			.retry = RETRY_INIT,
		},
	};

	unlang_frame_state_timeout_t	*state;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_t			*instruction;

	/*
	 *	Get the instruction we are supposed to run on timeout.
	 */
	instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
	if (!instruction) {
		REDEBUG("Failed to find pre-compiled unlang for section %s { ... }",
			cf_section_name1(cs));
		return -1;
	}

	/*
	 *	Push a new timeout frame onto the stack
	 */
	if (unlang_interpret_push(request, &timeout_instruction,
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, true) < 0) return -1;
	frame = &stack->frame[stack->depth];

	/*
	 *	Allocate its state, and set the timeout.
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_timeout_t));

	state->timeout = timeout;
	state->instruction = instruction;

	if (unlang_timeout_set(&request->rcode, request, frame) != UNLANG_ACTION_PUSHED_CHILD) {
		REDEBUG("Failed set timer for section %s { ... }",
			cf_section_name1(cs));
		return -1;
	}

	return 0;

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
