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
 * @file unlang/module.c
 * @brief Defines functions for calling modules asynchronously
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/xlat.h>
#include "unlang_priv.h"

/*
 *	Lock the mutex for the module
 */
static inline void safe_lock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_lock(instance->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static inline void safe_unlock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_unlock(instance->mutex);
}

static unlang_action_t unlang_module(REQUEST *request,
					  rlm_rcode_t *presult, int *priority)
{
	unlang_module_t		*sp;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_module_t	*ms;
	int				stack_depth = stack->depth;
	char const 			*caller;

#ifndef NDEBUG
	int unlang_indent		= request->log.unlang_indent;
#endif

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = unlang_generic_to_module(instruction);
	rad_assert(sp);

	RDEBUG4("[%i] %s - %s (%s)", stack->depth, __FUNCTION__,
		sp->module_instance->name, sp->module_instance->module->name);

	/*
	 *	Return administratively configured return code
	 */
	if (sp->module_instance->force) {
		*presult = request->rcode = sp->module_instance->code;
		goto done;
	}

	frame->state = ms = talloc_zero(stack, unlang_frame_state_module_t);

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	ms->thread = module_thread_instance_find(sp->module_instance);
	rad_assert(ms->thread != NULL);

	/*
	 *	For logging unresponsive children.
	 */
	ms->thread->total_calls++;

	caller = request->module;
	request->module = sp->module_instance->name;
	safe_lock(sp->module_instance);	/* Noop unless instance->mutex set */
	*presult = sp->method(sp->module_instance->dl_inst->data, ms->thread->data, request);
	safe_unlock(sp->module_instance);
	request->module = caller;

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked", sp->module_instance->module->name);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	if (*presult == RLM_MODULE_YIELD) {
		ms->thread->active_callers++;
		goto done;
	}

	/*
	 *	Module execution finished, ident should be the same.
	 */
	rad_assert(unlang_indent == request->log.unlang_indent);

	rad_assert(*presult >= RLM_MODULE_REJECT);
	rad_assert(*presult < RLM_MODULE_NUMCODES);
	*priority = instruction->actions[*presult];

	request->rcode = *presult;

done:
	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));

	switch (*presult) {
	case RLM_MODULE_YIELD:
		if (stack_depth < stack->depth) return UNLANG_ACTION_PUSHED_CHILD;
		rad_assert(stack_depth == stack->depth);
		return UNLANG_ACTION_YIELD;

	default:
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_module_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] rctx		createed by #unlang_module.
 * @param[in] action		to signal.
 */
static void unlang_module_signal(REQUEST *request, void *rctx, fr_state_signal_t action)
{
	unlang_stack_frame_t		*frame;
	unlang_stack_t			*stack = request->stack;
	unlang_resume_t			*mr;
	unlang_module_t		*mc;
	char const 			*caller;

	unlang_frame_state_module_t	*ms = NULL;

	rad_assert(stack->depth > 0);

	frame = &stack->frame[stack->depth];

	mr = unlang_generic_to_resume(frame->instruction);
	if (!mr->signal) return;

	mc = unlang_generic_to_module(mr->parent);
	ms = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	caller = request->module;
	request->module = mc->module_instance->name;
	((fr_unlang_module_signal_t)mr->signal)(request,
						mc->module_instance->dl_inst->data, ms->thread->data,
						rctx, action);
	request->module = caller;
}

static unlang_action_t unlang_module_resume(REQUEST *request, rlm_rcode_t *presult, UNUSED void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_resume_t			*mr = unlang_generic_to_resume(instruction);
	unlang_module_t		*mc = unlang_generic_to_module(mr->parent);
	int				stack_depth = stack->depth;
	char const			*caller;

	unlang_frame_state_module_t	*ms = NULL;

	rad_assert(mr->parent->type == UNLANG_TYPE_MODULE);

	ms = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	caller = request->module;
	request->module = mc->module_instance->name;
	safe_lock(mc->module_instance);
	*presult = request->rcode = ((fr_unlang_module_resume_t)mr->callback)(request,
									      mc->module_instance->dl_inst->data,
									      ms->thread->data, mr->rctx);
	safe_unlock(mc->module_instance);
	request->module = caller;

	if (*presult != RLM_MODULE_YIELD) ms->thread->active_callers--;

	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));

	switch (*presult) {
	case RLM_MODULE_YIELD:
		if (stack_depth < stack->depth) return UNLANG_ACTION_PUSHED_CHILD;
		rad_assert(stack_depth == stack->depth);
		return UNLANG_ACTION_YIELD;

	default:
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
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
 * @param[in] ctx		To allocate talloc value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] exp		XLAT expansion to evaluate.
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] rctx		to pass to the resume() and signal() callbacks.
 * @return
 *	- RLM_MODULE_YIELD.
 */
rlm_rcode_t unlang_module_push_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
				    REQUEST *request, xlat_exp_t const *exp,
				    fr_unlang_module_resume_t resume,
				    fr_unlang_module_signal_t signal, void *rctx)
{
	/*
	 *	Push the resumption point
	 */
	(void) unlang_module_yield(request, resume, signal, rctx);

	/*
	 *	Push the xlat function
	 */
	unlang_xlat_push(ctx, out, request, exp, true);

	return RLM_MODULE_YIELD;	/* This may allow us to do optimisations in future */
}

void unlang_module_init(void)
{
	unlang_op_register(UNLANG_TYPE_MODULE,
			   &(unlang_op_t){
				.name = "module",
				.func = unlang_module,
				.signal = unlang_module_signal,
				.resume = unlang_module_resume
			   });
}
