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
 * @file unlang/tmpl.c
 * @brief Defines functions for calling vp_tmpl_t asynchronously
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/server/exec.h>
#include "tmpl_priv.h"

/** Push a tmpl onto the stack for evaluation
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		The value_box created from the tmpl
 * @param[in] request		The current request.
 * @param[in] tmpl		the tmpl to expand
 */
void unlang_tmpl_push(TALLOC_CTX *ctx, fr_value_box_t **out, REQUEST *request, vp_tmpl_t const *tmpl)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
									       unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut;

	static unlang_t tmpl_instruction = {
		.type = UNLANG_TYPE_TMPL,
		.name = "tmpl",
		.debug_name = "tmpl",
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
	};

	state->out = out;
	state->ctx = ctx;

	MEM(ut = talloc(state, unlang_tmpl_t));
	ut->self = tmpl_instruction;
	ut->tmpl = tmpl;

	/*
	 *	Push a new tmpl frame onto the stack
	 */
	unlang_interpret_push(request, unlang_tmpl_to_generic(ut), RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, false);
}

/** Wrapper to call a resumption function after a tmpl has been expanded
 *
 */
static unlang_action_t unlang_tmpl_resume(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	if (state->resume) {
		rlm_rcode_t			rcode;

		if (state->out) *state->out = state->box;

		rcode = state->resume(request, state->rctx);
		*presult = rcode;
		if (rcode == RLM_MODULE_YIELD) return UNLANG_ACTION_YIELD;
	} else {
		*presult = RLM_MODULE_OK;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}


/** Wrapper to call exec after a tmpl has been expanded
 *
 */
static unlang_action_t unlang_tmpl_exec_resume(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	if (fr_exec_nowait(request, state->box, NULL) < 0) {
		REDEBUG("Failed executing program - %s", fr_strerror());
		*presult = RLM_MODULE_FAIL;
	} else {
		*presult = RLM_MODULE_OK;
	}

	/*
	 *	state->resume MUST be NULL, as we don't yet support
	 *	exec from unlang_tmpl_push().
	 */

	return UNLANG_ACTION_CALCULATE_RESULT;
}


rlm_rcode_t unlang_tmpl_yield(REQUEST *request, fr_unlang_tmpl_resume_t resume, void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	state->rctx = rctx;
	state->resume = resume;

	frame->interpret = unlang_tmpl_resume;

	/*
	 *	We set the repeatable flag here, so that the resume
	 *	function is always called going back up the stack.
	 *	This setting is normally done in the intepreter.
	 *	However, the caller of this function may call us, and
	 *	then push *other* things onto the stack.  Which means
	 *	that the interpreter never gets a chance to set this
	 *	flag.
	 */
	frame->interpret = unlang_tmpl_resume;
	repeatable_set(frame);
	return RLM_MODULE_YIELD;
}

static unlang_action_t unlang_tmpl(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut = unlang_generic_to_tmpl(frame->instruction);

	/*
	 *	If we're not called from unlang_tmpl_push(), then
	 *	ensure that we clean up the resulting value boxes.
	 */
	if (!state->ctx) state->ctx = state;

	if (!tmpl_async_required(ut->tmpl)) {
		if (!ut->inline_exec) {
			if (tmpl_aexpand_type(state->ctx, &state->box, FR_TYPE_STRING, request, ut->tmpl, NULL, NULL) < 0) {
				REDEBUG("Failed expanding %s - %s", ut->tmpl->name, fr_strerror());
				*presult = RLM_MODULE_FAIL;
			}

			*presult = RLM_MODULE_OK;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	Inline exec's are only called from in-line
		 *	text in the configuration files.
		 */
		frame->interpret = unlang_tmpl_exec_resume;

		repeatable_set(frame);
		unlang_xlat_push(state->ctx, &state->box, request, ut->tmpl->tmpl_xlat, false);
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	XLAT structs are allowed.
	 */
	if (ut->tmpl->type == TMPL_TYPE_XLAT_STRUCT) {
		frame->interpret = unlang_tmpl_resume;
		repeatable_set(frame);
		unlang_xlat_push(state->ctx, &state->box, request, ut->tmpl->tmpl_xlat, false);
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	Exec isn't done yet.
	 */
	if (ut->tmpl->type == TMPL_TYPE_EXEC) {
		REDEBUG("Asynchronous exec is not supported");
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (ut->tmpl->type == TMPL_TYPE_XLAT) {
		REDEBUG("Xlat expansions MUST be compiled before being run asynchronously");
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Attribute expansions, etc. don't require YIELD.
	 */
	REDEBUG("Internal error - template '%s' should not require async", ut->tmpl->name);
	*presult = RLM_MODULE_FAIL;
	return UNLANG_ACTION_CALCULATE_RESULT;
}


void unlang_tmpl_init(void)
{
	unlang_register(UNLANG_TYPE_TMPL,
			   &(unlang_op_t){
				.name = "tmpl",
				.interpret = unlang_tmpl,
				.frame_state_size = sizeof(unlang_frame_state_tmpl_t),
				.frame_state_name = "unlang_frame_state_tmpl_t",
			   });
}
