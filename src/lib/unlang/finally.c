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
 * @file unlang/finally.c
 * @brief Unlang "finally" keyword evaluation.  Used for running policy after a virtual server.
 *
 * @copyright 2025 Network RAIDUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/signal.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/unlang/unlang_priv.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/finally.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/timer.h>

typedef struct {
	fr_time_delta_t				min_time;	//!< minimum time to run the finally instruction.
	request_t				*request;
	unlang_t				*instruction;	//!< to run on timeout
} unlang_frame_state_finally_t;

static void unlang_timeout_handler(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *ctx)
{
	unlang_frame_state_finally_t	*state = talloc_get_type_abort(ctx, unlang_frame_state_finally_t);
	request_t			*request = talloc_get_type_abort(state->request, request_t);

	RDEBUG("Timeout reached, exiting finally section");

	/*
	 *	Cancels all frames (other than other finally sections)
	 *	and marks the request runnable again.
	 */
	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
}

static unlang_action_t unlang_finally(UNUSED rlm_rcode_t *p_result, request_t *request, UNUSED unlang_stack_frame_t *frame)
{
	unlang_frame_state_finally_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_finally_t);

	/*
	 *	Ensure the request has at least min_time to continue
	 *	executing before we cancel it.
	 */
	if (fr_time_delta_lt(state->min_time, fr_timer_remaining(request->timeout))) {
		if (unlikely(fr_timer_in(unlang_interpret_frame_talloc_ctx(request),
			     unlang_interpret_event_list(request)->tl, &request->timeout,
			     state->min_time, false, unlang_timeout_handler, state) < 0)) {
			unlang_interpret_signal(request, FR_SIGNAL_CANCEL); /* also stops the request and does cleanups */
			return UNLANG_ACTION_FAIL;
		}
	}

	if (unlikely(unlang_interpret_push_instruction(request, state->instruction, RLM_MODULE_NOOP, UNLANG_SUB_FRAME) < 0)) {
		unlang_interpret_signal(request, FR_SIGNAL_CANCEL); /* also stops the request and does cleanups */
	}

	/*
	 *	Set a timer to cancel the request.  If we don't do this
	 *	then the request may never finish.
	 */
	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Push a finally instructtion on the stack, to be evaluated as the stack is unwound
 *
 * @param[in] request		to push timeout onto
 * @param[in] instruction	to run as we unwind
 * @param[in] min_time		max time to wait for the finally instruction to finish.
 *				This only applies if the request timeout timer has already
 *				fired, or has less than max_time to execute. i.e. this is
 *				a guarantee of a minimum amount of time for the finally
 *				instruction to run.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_finally_push_instruction(request_t *request, void *instruction, fr_time_delta_t min_time, bool top_frame)
{
	/** Static instruction for performing xlat evaluations
	 *
	 */
	static unlang_t finally_instruction = {
		.type = UNLANG_TYPE_FINALLY,
		.name = "finally",
		.debug_name = "finally",
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
				[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,	/* Exit out of nested levels */
				[RLM_MODULE_UPDATED]	= 0
			},
			.retry = RETRY_INIT,
		},
	};

	unlang_frame_state_finally_t	*state;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;

	/*
	 *	Push a new finally frame onto the stack
	 *
	 *	This frame is uncancellable, and will always
	 *	execute before the request completes.
	 *
	 *	Its children are very much cancellable though
	 *	and will be cancelled if min_time or the request
	 *	timer expires.
	 */
	if (unlang_interpret_push(request, &finally_instruction,
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, top_frame) < 0) return -1;
	frame = &stack->frame[stack->depth];

	/*
	 *	Allocate its state
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_finally_t));
	state->instruction = instruction;
	state->request = request;
	state->min_time = min_time;

	frame_repeat(frame, unlang_finally);	/* execute immediately... or when unwinding */

	return 0;

}

void unlang_finally_init(void)
{
	unlang_register(UNLANG_TYPE_FINALLY,
			&(unlang_op_t){
				.name = "finally",
				.interpret = unlang_finally,
				.flag = UNLANG_OP_FLAG_NO_CANCEL,	/* No debug braces, the thing that's pushed in unlang finally should have braces */
				.frame_state_size = sizeof(unlang_frame_state_finally_t),
				.frame_state_type = "unlang_frame_state_finally_t",
			});
}
