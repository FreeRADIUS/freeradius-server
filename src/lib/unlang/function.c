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

 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include "unlang_priv.h"

/*
 *	Some functions differ mainly in their parsing
 */
typedef struct {
	unlang_function_t		func;			//!< To call when going down the stack.
	unlang_function_t		repeat;			//!< To call when going back up the stack.
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

/** Call a generic function
 *
 * @param[in] request	The current request.
 * @param[out] presult	The frame result.  Always set to RLM_MODULE_OK (fixme?).
 * @param[out] priority of the result.
 */
static unlang_action_t unlang_function_call(REQUEST *request,
					    rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
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
		ua = state->func(request, presult, priority, state->uctx);
	} else {
		ua = state->repeat(request, presult, priority, state->uctx);
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
 * @param[in] uctx	to pass to func.
 */
void unlang_interpret_push_function(REQUEST *request, unlang_function_t func, unlang_function_t repeat, void *uctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_func_t	*state;

	/*
	 *	Push module's function
	 */
	unlang_interpret_push(request, &function_instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, false);
	frame = &stack->frame[stack->depth];

	/*
	 *	Tell the interpreter to call unlang_function_call
	 *	again when going back up the stack.
	 */
	if (repeat) repeatable_set(frame);

	/*
	 *	Allocate state
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_func_t));

	state->func = func;
	state->repeat = repeat;
	state->uctx = uctx;
}

void unlang_function_init(void)
{
	unlang_register(UNLANG_TYPE_FUNCTION,
			   &(unlang_op_t){
				.name = "function",
				.func = unlang_function_call,
				.debug_braces = false
			   });

}
