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
	char const			*func_name;		//!< Debug name for the function.
	unlang_function_t		repeat;			//!< To call when going back up the stack.
	char const			*repeat_name;		//!< Debug name for the repeat function.
	unlang_function_signal_t	signal;			//!< Signal function to call.
	char const			*signal_name;		//!< Debug name for the signal function.
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
		},
		.retry = RETRY_INIT,
	},
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

static unlang_action_t unlang_function_call_repeat(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	char const 			*caller;

	/*
	 *	Don't let the callback mess with the current
	 *	module permanently.
	 */
	caller = request->module;
	request->module = NULL;
	RDEBUG4("Calling repeat function %p (%s)", state->repeat, state->repeat_name);
	ua = state->repeat(p_result, &frame->priority, request, state->uctx);
	request->module = caller;

	return ua;
}

/** Call a generic function
 *
 * @param[out] p_result		The frame result.
 * @param[in] request		The current request.
 * @param[in] frame		The current frame.
 */
static unlang_action_t unlang_function_call(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	char const 			*caller;

	/*
	 *	Don't let the callback mess with the current
	 *	module permanently.
	 */
	caller = request->module;
	request->module = NULL;

	RDEBUG4("Calling function %p (%s)", state->func, state->func_name);
	ua = state->func(p_result, &frame->priority, request, state->uctx);
	switch (ua) {
	case UNLANG_ACTION_STOP_PROCESSING:
		break;

	/*
	 *	Similar functionality to the modcall code.
	 *	If we have a repeat function set and the
	 *	initial function is done, call the repeat
	 *	function using the C stack.
	 */
	case UNLANG_ACTION_CALCULATE_RESULT:
		if (state->repeat) unlang_function_call_repeat(p_result, request, frame);
		break;

	/*
	 *	Function pushed more children or yielded
	 *	setup our repeat function for when we
	 *	eventually start heading back up the stack.
	 */
	default:
		if (state->repeat) frame_repeat(frame, unlang_function_call_repeat);
	}
	request->module = caller;

	return ua;
}

/** Clear pending repeat function calls, and remove the signal handler.
 *
 * The function frame being modified must be at the top of the stack.
 *
 * @param[in] request	The current request.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int unlang_function_clear(request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_func_t	*state;

	if (frame->instruction->type != UNLANG_TYPE_FUNCTION) {
		RERROR("Can't clear function on non-function frame");
		return -1;
	}

	state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	state->repeat = NULL;
	state->signal = NULL;

	repeatable_clear(frame);

	return 0;
}

/** Set a new signal function for an existing function frame
 *
 * @private
 *
 * The function frame being modified must be at the top of the stack.
 *
 * @param[in] request		The current request.
 * @param[in] signal		The signal function to set.
 * @param[in] signal_name	Name of the signal function call (for debugging).
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int _unlang_function_signal_set(request_t *request, unlang_function_signal_t signal, char const *signal_name)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_func_t	*state;

	if (frame->instruction->type != UNLANG_TYPE_FUNCTION) {
		RERROR("Can't set repeat function on non-function frame");
		return -1;
	}

	state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	/*
	 *	If we're inside unlang_function_call,
	 *	it'll pickup state->repeat and do the right thing
	 *	once the current function returns.
	 */
	state->signal = signal;
	state->signal_name = signal_name;

	return 0;
}

/** Set a new repeat function for an existing function frame
 *
 * @private
 *
 * The function frame being modified must be at the top of the stack.
 *
 * @param[in] request		The current request.
 * @param[in] repeat		the repeat function to set.
 * @param[in] repeat_name	Name of the repeat function call (for debugging).
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int _unlang_function_repeat_set(request_t *request, unlang_function_t repeat, char const *repeat_name)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_func_t	*state;

	if (frame->instruction->type != UNLANG_TYPE_FUNCTION) {
		RERROR("Can't set repeat function on non-function frame");
		return -1;
	}

	state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	/*
	 *	If we're inside unlang_function_call,
	 *	it'll pickup state->repeat and do the right thing
	 *	once the current function returns.
	 */
	state->repeat = repeat;
	state->repeat_name = repeat_name;
	repeatable_set(frame);

	return 0;
}

/** Push a generic function onto the unlang stack
 *
 * @private
 *
 * These can be pushed by any other type of unlang op to allow a submodule or function
 * deeper in the C call stack to establish a new resumption point.
 *
 * @param[in] request		The current request.
 * @param[in] func		to call going up the stack.
 * @param[in] func_name		Name of the function call (for debugging).
 * @param[in] repeat		function to call going back down the stack (may be NULL).
 *				This may be the same as func.
 * @param[in] repeat_name	Name of the repeat function call (for debugging).
 * @param[in] signal		function to call if the request is signalled.
 * @param[in] signal_name	Name of the signal function call (for debugging).
 * @param[in] uctx		to pass to func(s).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
unlang_action_t _unlang_function_push(request_t *request,
				      unlang_function_t func, char const *func_name,
				      unlang_function_t repeat, char const *repeat_name,
				      unlang_function_signal_t signal, char const *signal_name,
				      bool top_frame, void *uctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_func_t	*state;

	/*
	 *	Push module's function
	 */
	if (unlang_interpret_push(request, &function_instruction,
				  RLM_MODULE_NOOP, UNLANG_NEXT_STOP, top_frame) < 0) return UNLANG_ACTION_FAIL;

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
	state->func_name = func_name;
	state->repeat = repeat;
	state->repeat_name = repeat_name;
	state->signal = signal;
	state->signal_name = signal_name;
	state->uctx = uctx;

	/*
	 *	Just skip to the repeat state directly
	 */
	if (!func && repeat) frame->process = unlang_function_call_repeat;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Custom frame state dumper
 *
 */
static void unlang_function_dump(request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	RDEBUG2("frame state");
	if (state->func)   RDEBUG2("function       %p (%s)", state->func, state->func_name);
	if (state->repeat) RDEBUG2("repeat         %p (%s)", state->repeat, state->repeat_name);
	if (state->signal) RDEBUG2("signal         %p (%s)", state->signal, state->signal_name);
}

void unlang_function_init(void)
{
	unlang_register(UNLANG_TYPE_FUNCTION,
			   &(unlang_op_t){
				.name = "function",
				.interpret = unlang_function_call,
				.signal = unlang_function_signal,
				.dump = unlang_function_dump,
				.debug_braces = false,
			        .frame_state_size = sizeof(unlang_frame_state_func_t),
				.frame_state_type = "unlang_frame_state_func_t",
			   });

}
