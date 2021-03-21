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
 * @file unlang/function.c
 * @brief Unlang "function" keyword evaluation.

 * @copyright 2018,2021 The FreeRADIUS server project
 * @copyright 2018,2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "function.h"

/*
 *	Some functions differ mainly in their parsing
 */
typedef struct {
	unlang_function_t		func;			//!< To call when going down the stack.
	unlang_function_t		repeat;			//!< To call when going back up the stack.
	unlang_function_signal_t	signal;			//!< Signal function to call.
	void				*uctx;			//!< Uctx to pass to function.
} unlang_frame_state_func_t;

/** Static instruction for allowing modules/xlats to call functions within themselves, or submodules
 *
 */
static unlang_t function_instruction = {
	.type = UNLANG_TYPE_FUNCTION,
	.name = "function",
	.debug_name = "function",
	.actions = {
		[RLM_MODULE_REJECT]	= 0,
		[RLM_MODULE_FAIL]	= 0,
		[RLM_MODULE_OK]		= 0,
		[RLM_MODULE_HANDLED]	= 0,
		[RLM_MODULE_INVALID]	= 0,
		[RLM_MODULE_DISALLOW]	= 0,
		[RLM_MODULE_NOTFOUND]	= 0,
		[RLM_MODULE_NOOP]	= 0,
		[RLM_MODULE_UPDATED]	= 0
	}
};

/** Generic signal handler
 *
 * @param[in] request		being signalled.
 * @param[in] frame		being signalled.
 * @param[in] action		Type of signal.
 */
static void unlang_function_signal(request_t *request,
				   unlang_stack_frame_t *frame, fr_state_signal_t action)
{
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	if (!state->signal) return;

	state->signal(request, action, state->uctx);
}

/** Call a generic function
 *
 * @param[out] p_result		The frame result.
 * @param[in] request		The current request.
 * @param[in] frame		The current frame.
 */
static unlang_action_t unlang_function_call(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	unlang_action_t			ua;
	char const 			*caller;

	/*
	 *	Don't let the callback mess with the current
	 *	module permanently.
	 */
	caller = request->module;
	request->module = NULL;
	if (!is_repeatable(frame)) {
		ua = state->func(p_result, &frame->priority, request, state->uctx);
	} else {
		ua = state->repeat(p_result, &frame->priority, request, state->uctx);
	}
	request->module = caller;

	return ua;
}

/** Push a generic function onto the unlang stack
 *
 * These can be pushed by any other type of unlang op to allow a submodule or function
 * deeper in the C call stack to establish a new resumption point.
 *
 * @param[in] request	The current request.
 * @param[in] func	to call going up the stack.
 * @param[in] repeat	function to call going back down the stack (may be NULL).
 *			This may be the same as func.
 * @param[in] signal	function to call if the request is signalled.
 * @param[in] uctx	to pass to func.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_interpret_push_function(request_t *request, unlang_function_t func, unlang_function_t repeat,
				   unlang_function_signal_t signal, bool top_frame, void *uctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_func_t	*state;

	/*
	 *	Push module's function
	 */
	if (unlang_interpret_push(request, &function_instruction,
				  RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, top_frame) < 0) return -1;

	frame = &stack->frame[stack->depth];

	/*
	 *	Tell the interpreter to call unlang_function_call
	 *	again when going back up the stack.
	 */
	if (repeat) repeatable_set(frame);

	/*
	 *	Initialize state
	 */
	state = frame->state;
	state->func = func;
	state->repeat = repeat;
	state->signal = signal;
	state->uctx = uctx;

	return 0;
}

void unlang_function_init(void)
{
	unlang_register(UNLANG_TYPE_FUNCTION,
			   &(unlang_op_t){
				.name = "function",
				.interpret = unlang_function_call,
				.signal = unlang_function_signal,
				.debug_braces = false,
			        .frame_state_size = sizeof(unlang_frame_state_func_t),
				.frame_state_name = "unlang_frame_state_func_t",
			   });

}
