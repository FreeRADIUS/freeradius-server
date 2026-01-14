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

#include "action.h"
#include "unlang_priv.h"
#include "function.h"

#define FUNC(_state) *((void **)&state->func)
#define REPEAT(_state) *((void **)&state->repeat)

/*
 *	Some functions differ mainly in their parsing
 */
typedef struct {
	union {
		unlang_function_no_result_t	nres;		//!< To call when going down the stack.
		unlang_function_with_result_t	wres;		//!< To call when going down the stack.
	} func;
	char const			*func_name;		//!< Debug name for the function.

	union {
		unlang_function_no_result_t	nres;		//!< To call when going back up the stack.
		unlang_function_with_result_t	wres;		//!< To call when going back up the stack.
	} repeat;
	unlang_function_type_t		type;			//!< Record whether we need to call the
	char const			*repeat_name;		//!< Debug name for the repeat function.

	unlang_function_signal_t	signal;			//!< Signal function to call.
	fr_signal_t			sigmask;		//!< Signals to block.
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
	.actions = DEFAULT_MOD_ACTIONS,
};

/** Generic signal handler
 *
 * @param[in] request		being signalled.
 * @param[in] frame		being signalled.
 * @param[in] action		Type of signal.
 */
static void unlang_function_signal(request_t *request,
				   unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	if (!state->signal || (action & state->sigmask)) return;

	state->signal(request, action, state->uctx);
}


/*
 *	Don't let the callback mess with the current
 *	module permanently.
 */
#define STORE_CALLER \
	char const *caller; \
	caller = request->module; \
	request->module = NULL

#define RESTORE_CALLER \
	request->module = caller;

/** Call a generic function that produces a result
 *
 * @param[out] p_result		The frame result.
 * @param[in] request		The current request.
 * @param[in] frame		The current frame.
 */
static unlang_action_t call_with_result_repeat(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	unlang_function_with_result_t	func;

	STORE_CALLER;

	if (!REPEAT(state)) {
		RDEBUG4("Repeat function is NULL, likely due to previous yield, skipping call");
		ua = UNLANG_ACTION_CALCULATE_RESULT;
		goto done;
	}

again:
	RDEBUG4("Calling repeat function %p (%s)", REPEAT(state), state->repeat_name);

	/*
	 *	Only called once...
	 */
	func = state->repeat.wres;
	REPEAT(state) = NULL;
	state->repeat_name = NULL;
	ua = func(p_result, request, state->uctx);
	if (REPEAT(state)) { /* set again by func */
		switch (ua) {
		case UNLANG_ACTION_CALCULATE_RESULT:
			goto again;

		default:
			frame_repeat(frame, call_with_result_repeat);
		}
	}

done:
	RESTORE_CALLER;

	return ua;
}

/** Call a generic function that produces a result
 *
 * @param[out] p_result		The frame result.
 * @param[in] request		The current request.
 * @param[in] frame		The current frame.
 */
static unlang_action_t call_with_result(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	STORE_CALLER;

	RDEBUG4("Calling function %p (%s)", FUNC(state), state->func_name);
	ua = state->func.wres(p_result, request, state->uctx);
	FUNC(state) = NULL;
	state->func_name = NULL;
	if (REPEAT(state)) {
		switch (ua) {
		case UNLANG_ACTION_CALCULATE_RESULT:
			ua = call_with_result_repeat(p_result, request, frame);
			break;

		default:
			frame_repeat(frame, call_with_result_repeat);
		}
	}
	RESTORE_CALLER;

	return ua;
}

/** Call a generic function that produces a result
 *
 * @param[out] p_result		The frame result.
 * @param[in] request		The current request.
 * @param[in] frame		The current frame.
 */
static unlang_action_t call_no_result_repeat(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	unlang_function_no_result_t	func;

	STORE_CALLER;

	if (!REPEAT(state)) {
		RDEBUG4("Repeat function is NULL, likely due to previous yield, skipping call");
		ua = UNLANG_ACTION_CALCULATE_RESULT;
		goto done;
	}

again:
	RDEBUG4("Calling repeat function %p (%s)", REPEAT(state), state->repeat_name);

	/*
	 *	Only called once...
	 */
	func = state->repeat.nres;
	REPEAT(state) = NULL;
	state->repeat_name = NULL;
	ua = func(request, state->uctx);
	if (REPEAT(state)) { /* set again by func */
		switch (ua) {
		case UNLANG_ACTION_CALCULATE_RESULT:
			goto again;

		case UNLANG_ACTION_FAIL:
		no_action_fail:
			fr_assert_msg(0, "Function %s (%p) is not allowed to indicate failure via UNLANG_ACTION_FAIL",
				      state->repeat_name, REPEAT(state));
			ua = UNLANG_ACTION_CALCULATE_RESULT;
			break;

		default:
			frame_repeat(frame, call_no_result_repeat);
		}
	}

	if (ua == UNLANG_ACTION_FAIL) goto no_action_fail;

done:
	RESTORE_CALLER;

	return ua;
}

/** Call a generic function that produces a result
 *
 * @param[out] p_result		The frame result.
 * @param[in] request		The current request.
 * @param[in] frame		The current frame.
 */
static unlang_action_t call_no_result(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	STORE_CALLER;

	RDEBUG4("Calling function %p (%s)", FUNC(state), state->func_name);
	ua = state->func.nres(request, state->uctx);
	FUNC(state) = NULL;
	state->func_name = NULL;
	if (REPEAT(state)) {
		switch (ua) {
		case UNLANG_ACTION_CALCULATE_RESULT:
			ua = call_no_result_repeat(p_result, request, frame);
			break;

		case UNLANG_ACTION_FAIL:
		no_action_fail:
			fr_assert_msg(0, "Function is not allowed to indicate failure via UNLANG_ACTION_FAIL");
			ua = UNLANG_ACTION_CALCULATE_RESULT;
			break;

		default:
			frame_repeat(frame, call_no_result_repeat);
		}
	}
	if (ua == UNLANG_ACTION_FAIL) goto no_action_fail;

	RESTORE_CALLER;

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
	REPEAT(state) = NULL;
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
 * @param[in] sigmask		Signals to block.
 * @param[in] signal_name	Name of the signal function call (for debugging).
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int _unlang_function_signal_set(request_t *request, unlang_function_signal_t signal, fr_signal_t sigmask, char const *signal_name)
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
	state->sigmask = sigmask;
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
 * @param[in] type		Type of repeat function (with or without result).
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int _unlang_function_repeat_set(request_t *request, void *repeat, char const *repeat_name, unlang_function_type_t type)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_func_t	*state;

	if (frame->instruction->type != UNLANG_TYPE_FUNCTION) {
		RERROR("Can't set repeat function on non-function frame");
		return -1;
	}

	state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	if (unlikely(state->type != type)) {
		fr_assert_msg(0, "Function type mismatch \"%s\"", repeat_name);
		return -1;
	}

	/*
	 *	If we're inside unlang_function_call,
	 *	it'll pickup state->repeat and do the right thing
	 *	once the current function returns.
	 */
	REPEAT(state) = repeat;
	state->repeat_name = repeat_name;
	repeatable_set(frame);

	return 0;
}

static inline CC_HINT(always_inline)
unlang_action_t unlang_function_push_common(unlang_result_t *p_result,
					    request_t *request,
					    void *func,
					    char const *func_name,
					    void *repeat,
					    char const *repeat_name,
					    unlang_function_signal_t signal, fr_signal_t sigmask, char const *signal_name,
					    unlang_function_type_t type,
					    bool top_frame,
					    void *uctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_func_t	*state;

	if (!func && !repeat) {
		fr_assert_msg(0, "function push must push at least one function!");
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Push module's function
	 */
	if (unlang_interpret_push(p_result, request, &function_instruction,
				  FRAME_CONF(RLM_MODULE_NOOP, top_frame), UNLANG_NEXT_STOP) < 0) {
		return UNLANG_ACTION_FAIL;
	}

	frame = &stack->frame[stack->depth];

	/*
	 *	Initialize state
	 */
	state = frame->state;
	state->signal = signal;
	state->sigmask = sigmask;
	state->signal_name = signal_name;
	state->type = type;
	state->uctx = uctx;

	FUNC(state) = func;
	state->func_name = func_name;
	REPEAT(state) = repeat;
	state->repeat_name = repeat_name;

	if (repeat) repeatable_set(frame); /* execute on the way back up */

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Push a generic function onto the unlang stack with a result
 *
 * @private
 *
 * These can be pushed by any other type of unlang op to allow a submodule or function
 * deeper in the C call stack to establish a new resumption point.
 *
 * @param[in] p_result		Where to write the result of the function evaluation.
 *
 * @param[in] request		The current request.
 * @param[in] func		to call going up the stack.
 * @param[in] func_name		Name of the function call (for debugging).
 * @param[in] repeat		function to call going back down the stack (may be NULL).
 *				This may be the same as func.
 * @param[in] repeat_name	Name of the repeat function call (for debugging).
 * @param[in] signal		function to call if the request is signalled.
 * @param[in] sigmask		Signals to block.
 * @param[in] signal_name	Name of the signal function call (for debugging).
 * @param[in] top_frame		Return out of the unlang interpreter when popping this frame.
 * @param[in] uctx		to pass to func(s).
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t _unlang_function_push_with_result(unlang_result_t *p_result,
						  request_t *request,
						  unlang_function_with_result_t func, char const *func_name,
						  unlang_function_with_result_t repeat, char const *repeat_name,
						  unlang_function_signal_t signal, fr_signal_t sigmask, char const *signal_name,
						  bool top_frame, void *uctx)
{
	unlang_action_t ua;
	unlang_stack_frame_t *frame;

	ua = unlang_function_push_common(p_result,
					 request,
					 (void *) func, func_name,
					 (void *) repeat, repeat_name,
					 signal, sigmask, signal_name,
					 UNLANG_FUNCTION_TYPE_WITH_RESULT, top_frame, uctx);

	if (unlikely(ua == UNLANG_ACTION_FAIL)) return UNLANG_ACTION_FAIL;

	frame = frame_current(request);
	if (!func && repeat) {
		frame->process = call_with_result_repeat;
	} else {
		frame->process = call_with_result;
	}

	return ua;
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
 * @param[in] sigmask		Signals to block.
 * @param[in] signal_name	Name of the signal function call (for debugging).
 * @param[in] top_frame		Return out of the unlang interpreter when popping this frame.
 * @param[in] uctx		to pass to func(s).
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t _unlang_function_push_no_result(request_t *request,
						unlang_function_no_result_t func, char const *func_name,
						unlang_function_no_result_t repeat, char const *repeat_name,
						unlang_function_signal_t signal, fr_signal_t sigmask, char const *signal_name,
						bool top_frame, void *uctx)
{
	unlang_action_t ua;
	unlang_stack_frame_t *frame;

	ua = unlang_function_push_common(NULL,
					 request,
					 (void *) func, func_name,
					 (void *) repeat, repeat_name,
					 signal, sigmask, signal_name,
					 UNLANG_FUNCTION_TYPE_NO_RESULT, top_frame, uctx);

	if (unlikely(ua == UNLANG_ACTION_FAIL)) return UNLANG_ACTION_FAIL;

	frame = frame_current(request);
	if (!func && repeat) {
		frame->process = call_no_result_repeat;
	}

	/* frame->process = call_no_result - This is the default, we don't need to set it again */

	return ua;
}

/** Custom frame state dumper
 *
 */
static void unlang_function_dump(request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);

	RDEBUG2("frame state");
	if (FUNC(state))   RDEBUG2("function       %p (%s)", FUNC(state), state->func_name);
	if (REPEAT(state)) RDEBUG2("repeat         %p (%s)", REPEAT(state), state->repeat_name);
	if (state->signal) RDEBUG2("signal         %p (%s)", state->signal, state->signal_name);
}

void unlang_function_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "function",
			.type = UNLANG_TYPE_FUNCTION,
			.flag = UNLANG_OP_FLAG_RETURN_POINT | UNLANG_OP_FLAG_INTERNAL,

			.interpret = call_no_result,
			.signal = unlang_function_signal,
			.dump = unlang_function_dump,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",

			.frame_state_size = sizeof(unlang_frame_state_func_t),
			.frame_state_type = "unlang_frame_state_func_t",
		});
}
