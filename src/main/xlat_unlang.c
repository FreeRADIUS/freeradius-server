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
 * @file xlat_unlang.c
 * @brief Integration between the unlang interpreter and xlats
 *
 * @copyright 2018  The FreeRADIUS server project
 * @copyright 2018  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>
#include "unlang_priv.h"	/* Fixme - Should create a proper semi-public interface for the interpret */

/** Hold the result of an inline xlat expansion
 *
 */
typedef struct {
	fr_value_box_t		*result;			//!< Where to store the result of the
								///< xlat expansion. This is usually discarded.
} unlang_stack_state_xlat_inline_t;

/** State of an xlat expansion
 *
 * State of one level of nesting within an xlat expansion.
 */
typedef struct {
	TALLOC_CTX		*ctx;				//!< to allocate boxes and values in.
	xlat_exp_t const	*exp;
	fr_cursor_t		values;				//!< Values aggregated so far.

	/*
	 *	For func and alternate
	 */
	fr_value_box_t		*rhead;				//!< Head of the result of a nested
								///< expansion.
	fr_cursor_t		result;				//!< Result cursor, mainly useful for
								///< asynchronous xlat functions.
	bool			alternate;			//!< record which alternate branch we
								///< previously took.
} unlang_stack_state_xlat_t;

/** Static instruction for performing xlat evaluations
 *
 */
static unlang_t xlat_instruction = {
	.type = UNLANG_TYPE_XLAT,
	.name = "xlat",
	.debug_name = "xlat",
	.actions = {
		[RLM_MODULE_REJECT]	= 0,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,	/* Exit out of nested levels */
		[RLM_MODULE_OK]		= 0,
		[RLM_MODULE_HANDLED]	= 0,
		[RLM_MODULE_INVALID]	= 0,
		[RLM_MODULE_USERLOCK]	= 0,
		[RLM_MODULE_NOTFOUND]	= 0,
		[RLM_MODULE_NOOP]	= 0,
		[RLM_MODULE_UPDATED]	= 0
	},
};

/** Push a pre-compiled xlat onto the stack for evaluation
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		to push xlat onto.
 * @param[in] exp		node to evaluate.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if this is the shallowest nesting level.
 *				Set to UNLANG_SUB_FRAME if this is a nested expansion.
 */
static void unlang_push_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
			     REQUEST *request, xlat_exp_t const *exp, bool top_frame)
{

	unlang_stack_state_xlat_t	*state;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;

	/*
	 *	Push a new xlat eval frame onto the stack
	 */
	unlang_push(stack, &xlat_instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, top_frame);
	frame = &stack->frame[stack->depth];

	/*
	 *	Allocate its state, and setup a cursor for the xlat nodes
	 */
	frame->state = state = talloc_zero(stack, unlang_stack_state_xlat_t);
	state->exp = exp;

	fr_cursor_init(&state->values, out);

	state->ctx = ctx;
}

/** Push a pre-compiled xlat and resumption state onto the stack for evaluation
 *
 * In order to use the async unlang processor the calling module needs to establish
 * a resumption point, as the call to an xlat function may require yielding control
 * back to the interpreter.
 *
 * To simplify the calling conventions, this function is provided to first push a
 * resumption stack frame for the module, and then push an xlat stack frame.
 *
 * After pushing those frames the function updates the stack pointer to jump over
 * the resumption frame and execute the xlat interpreter.
 *
 * When the xlat interpreter finishes, and pops the xlat frame, the unlang interpreter
 * will then call the module resumption frame, allowing the module to continue exectuion.
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] xlat		to evaluate.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] signal		to call on unlang_action().
 * @param[in] uctx		to pass to the callbacks.
 * @return
 *	- RLM_MODULE_YIELD if the xlat would perform blocking I/O
 *	- A return code representing the result of the xla
 */
rlm_rcode_t unlang_push_module_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
				    REQUEST *request, xlat_exp_t const *xlat,
				    fr_unlang_module_resume_t callback,
				    fr_unlang_module_signal_t signal, void *uctx)
{
	/*
	 *	Push the resumption point
	 */
	(void) unlang_module_yield(request, callback, signal, uctx);

	/*
	 *	Push the xlat function
	 */
	unlang_push_xlat(ctx, out, request, xlat, true);

	/*
	 *	Execute the xlat frame we just pushed onto the stack.
	 */
	return unlang_run(request);
}

/** Stub function for calling the xlat interpreter
 *
 * Calls the xlat interpreter and translates its wants and needs into
 * unlang_action_t codes.
 */
static unlang_action_t unlang_xlat(REQUEST *request,
				   rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_stack_state_xlat_t	*xs = talloc_get_type_abort(frame->state, unlang_stack_state_xlat_t);
	xlat_exp_t const		*child = NULL;
	xlat_action_t			xa;

	if (frame->repeat) {
		fr_cursor_init(&xs->result, &xs->rhead);
		xa = xlat_frame_eval_repeat(xs->ctx, &xs->values,
					    &child, &xs->alternate,
					    request, &xs->exp,
					    &xs->result);
	} else {
		xa = xlat_frame_eval(xs->ctx, &xs->values, &child, request, &xs->exp);
	}

	switch (xa) {
	case XLAT_ACTION_PUSH_CHILD:
		rad_assert(child);

		frame->repeat = true;
		unlang_push_xlat(xs->ctx, &xs->rhead, request, child, false);
		return UNLANG_ACTION_PUSHED_CHILD;

	case XLAT_ACTION_YIELD:
		return UNLANG_ACTION_YIELD;

	case XLAT_ACTION_DONE:
		return UNLANG_ACTION_CALCULATE_RESULT;

	case XLAT_ACTION_FAIL:
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	rad_assert(0);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_xlat_resume(REQUEST *request, rlm_rcode_t *presult, UNUSED void *resume_ctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_resume_t			*mr = unlang_generic_to_resume(instruction);
	unlang_stack_state_xlat_t	*xs = talloc_get_type_abort(frame->state, unlang_stack_state_xlat_t);
	xlat_action_t			xa;

	xa = xlat_frame_eval_resume(xs->ctx, &xs->values, mr->callback, xs->exp, request, &xs->result, mr->resume_ctx);
	switch (xa) {
	case XLAT_ACTION_YIELD:
		*presult = RLM_MODULE_YIELD;
		return UNLANG_ACTION_YIELD;

	case XLAT_ACTION_DONE:
		*presult = RLM_MODULE_OK;
		return UNLANG_ACTION_CALCULATE_RESULT;

	case XLAT_ACTION_PUSH_CHILD:
		rad_assert(0);
		/* FALL-THROUGH */

	case XLAT_ACTION_FAIL:
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	/* Don't set default */
	}

	/* garbage xlat action */

	rad_assert(0);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Evaluates "naked" xlats in the config
 *
 */
static unlang_action_t unlang_xlat_inline(REQUEST *request,
					  UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_xlat_inline_t	*mx = unlang_generic_to_xlat_inline(instruction);

	if (!mx->exec) {
		TALLOC_CTX *pool;
		unlang_stack_state_xlat_inline_t *state;

		MEM(frame->state = state = talloc_zero(stack, unlang_stack_state_xlat_inline_t));
		MEM(pool = talloc_pool(frame->state, 1024));	/* Pool to absorb some allocs */

		unlang_push_xlat(pool, &state->result, request, mx->exp, false);
		return UNLANG_ACTION_PUSHED_CHILD;
	} else {
		RDEBUG("`%s`", mx->xlat_name);
		radius_exec_program(request, NULL, 0, NULL, request, mx->xlat_name, request->packet->vps,
				    false, true, EXEC_TIMEOUT);
		return UNLANG_ACTION_CONTINUE;
	}
}

/** Register xlat operation with the interpreter
 *
 */
void xlat_unlang_init(void)
{
	unlang_op_register(UNLANG_TYPE_XLAT,
			   &(unlang_op_t){
				.name = "xlat_eval",
				.func = unlang_xlat,
				.resume = unlang_xlat_resume,
				.debug_braces = false
			   });


	unlang_op_register(UNLANG_TYPE_XLAT_INLINE,
			   &(unlang_op_t){
				.name = "xlat_inline",
				.func = unlang_xlat_inline,
				.debug_braces = false
			   });
}
