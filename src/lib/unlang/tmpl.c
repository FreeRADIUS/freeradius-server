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
#include "tmpl_priv.h"

/** Push a tmpl onto the stack for evaluation
 *
 * @param[out] out		The value_box created from the tmpl
 * @param[in] request		The current request.
 * @param[in] tmpl		the tmpl to expand
 */
void unlang_tmpl_push(fr_value_box_t **out, REQUEST *request, vp_tmpl_t const *tmpl)
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
	rlm_rcode_t			rcode;

	rad_assert(state->resume != NULL);

	rcode = state->resume(request, state->rctx);
	*presult = rcode;
	if (rcode == RLM_MODULE_YIELD) return UNLANG_ACTION_YIELD;

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

static unlang_action_t unlang_tmpl(UNUSED REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut = unlang_generic_to_tmpl(frame->instruction);

	if (!state->out) {
		state->out = fr_value_box_alloc(state, FR_TYPE_STRING, NULL, false);
	}

	if (!tmpl_async_required(ut->tmpl)) {
		if (tmpl_aexpand_type(request, state->out, FR_TYPE_STRING, request, ut->tmpl, NULL, NULL) < 0) {
			REDEBUG("Failed expanding %s - %s", ut->tmpl->name, fr_strerror());
			*presult = RLM_MODULE_FAIL;
		}

		*presult = RLM_MODULE_OK;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	REDEBUG("Async xlats are not implemented!");

	/*
	 *	Not implemented.
	 */
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
