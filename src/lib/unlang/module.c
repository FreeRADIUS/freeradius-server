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
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/request_data.h>

#include "module_priv.h"

#include "tmpl.h"

static unlang_action_t unlang_module_resume(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame);
static void unlang_module_event_retry_handler(UNUSED fr_timer_list_t *tl, fr_time_t now, void *ctx);

/** Push a module or submodule onto the stack for evaluation
 *
 * @param[out] p_result		Where to write the result of calling the module.
 * @param[in] request		The current request.
 * @param[in] mi		Instance of the module to call.
 * @param[in] method		to call.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_module_push(unlang_result_t *p_result, request_t *request,
		       module_instance_t *mi, module_method_t method, bool top_frame)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_module_t	*state;
	unlang_module_t			*mc;

	/*
	 *	We need to have a unlang_module_t to push on the
	 *	stack.  The only sane way to do it is to attach it to
	 *	the frame state.
	 */
	MEM(mc = talloc(stack, unlang_module_t));	/* Still gets allocated from the stack pool */
	*mc = (unlang_module_t){
		.self = {
			.type = UNLANG_TYPE_MODULE,
			.name = mi->name,
			.debug_name = mi->name,
			.actions = MOD_ACTIONS_FAIL_TIMEOUT_RETURN,
		},
		.mmc = {
			.mi = mi,
			.mmb = {
				.method = method
			}
		}
	};
	unlang_type_init(&mc->self, NULL, UNLANG_TYPE_MODULE);

	/*
	 *	Push a new module frame onto the stack
	 */
	if (unlang_interpret_push(p_result, request, unlang_module_to_generic(mc),
				  FRAME_CONF(RLM_MODULE_NOT_SET, top_frame), UNLANG_NEXT_STOP) < 0) {
		return -1;
	}

	frame = &stack->frame[stack->depth];
	state = frame->state;
	*state = (unlang_frame_state_module_t){
		.thread = module_thread(mi)
	};

	/*
	 *	Bind the temporary unlang_module_t to the frame state.
	 *
	 *	There aren't _that_ many children in the stack context.
	 *	so we should be ok.
	 *
	 *	Hopefully in future versions of talloc the O(n) problem
	 *	will be fixed for stealing.
	 */
	talloc_steal(state, mc);

	return 0;
}

/** Change the resume function of a module.
 *
 * @param[in] request		The current request.
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int unlang_module_set_resume(request_t *request, module_method_t resume)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state;

	/*
	 *	Can't resume if it isn't yielded.
	 */
	if (!is_yielded(frame)) return -1;

	/*
	 *	It must be yielded in a module.
	 */
	if (frame->instruction->type != UNLANG_TYPE_MODULE) return -1;

	state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	state->resume = resume;

	return 0;
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
 * will then call the module resumption frame, allowing the module to continue execution.
 *
 * @param[in] ctx		To allocate talloc value boxes and values in.
 * @param[out] p_result		Whether xlat evaluation was successful.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] exp		XLAT expansion to evaluate.
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] sigmask		Set of signals to block.  For example if we wanted to only allow
 *				FR_SIGNAL_CANCEL, we'd pass ~FR_SIGNAL_CANCEL to block the other
 *				signals.
 * @param[in] rctx		to pass to the resume() and signal() callbacks.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD
 */
unlang_action_t unlang_module_yield_to_xlat(TALLOC_CTX *ctx, unlang_result_t *p_result, fr_value_box_list_t *out,
					    request_t *request, xlat_exp_head_t const *exp,
					    module_method_t resume,
					    unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	/*
	 *	Push the resumption point BEFORE pushing the xlat onto
	 *	the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, sigmask, rctx);

	/*
	 *	Push the xlat function
	 */
	if (unlang_xlat_push(ctx, p_result, out, request, exp, false) < 0) RETURN_UNLANG_ACTION_FATAL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Push a pre-compiled tmpl and resumption state onto the stack for evaluation
 *
 * In order to use the async unlang processor the calling module needs to establish
 * a resumption point, as the call to an xlat function may require yielding control
 * back to the interpreter.
 *
 * To simplify the calling conventions, this function is provided to first push a
 * resumption stack frame for the module, and then push a tmpl stack frame.
 *
 * After pushing those frames the function updates the stack pointer to jump over
 * the resumption frame and execute the tmpl expansion.
 *
 * When the tmpl interpreter finishes, and pops the tmpl frame, the unlang interpreter
 * will then call the module resumption frame, allowing the module to continue execution.
 *
 * @param[in] ctx		To allocate talloc value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] vpt		the tmpl to expand
 * @param[in] args		Arguments which control how to evaluate the various
 *				types of xlats.
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] sigmask		Set of signals to block.  For example if we wanted to only allow
 *				FR_SIGNAL_CANCEL, we'd pass ~FR_SIGNAL_CANCEL to block the other
 *				signals.
 * @param[in] rctx		to pass to the resume() and signal() callbacks.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD
 */
unlang_action_t unlang_module_yield_to_tmpl(TALLOC_CTX *ctx, fr_value_box_list_t *out,
					    request_t *request, tmpl_t const *vpt,
					    unlang_tmpl_args_t *args,
					    module_method_t resume,
					    unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	/*
	 *	Push the resumption point BEFORE pushing the xlat onto
	 *	the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, sigmask, rctx);

	/*
	 *	Push the xlat function
	 */
	if (unlang_tmpl_push(ctx, NULL, out, request, vpt, args, UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

unlang_action_t unlang_module_yield_to_section(unlang_result_t *p_result,
					       request_t *request, CONF_SECTION *subcs,
					       rlm_rcode_t default_rcode,
					       module_method_t resume,
					       unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	/*
	 *	When we yield to a section, the request->rcode
	 *	should be set to the default rcode, so that
	 *	conditional checks work correctly.
	 */
	RDEBUG3("Resetting request->rcode to %s", fr_table_str_by_value(rcode_table, default_rcode, "<invalid>"));
	request->rcode = default_rcode;

	if (!subcs) {
		unlang_stack_t			*stack = request->stack;
		unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
		unlang_module_t			*m;
		unlang_frame_state_module_t	*state;

		fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
		m = unlang_generic_to_module(frame->instruction);

		/*
		 *	Pretend as if we called the section
		 *	and used the default rcode value.
		 */
		frame->scratch_result = (unlang_result_t) {.rcode = default_rcode, .priority = MOD_ACTION_NOT_SET };

		state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

		/*
		 *	We must pass a pointer to the scratch
		 *	rcode here, as we're pretending we're
		 *	executing the resume function using the
		 *	interpreter, which means it must modify
		 *	the scratch result for the frame, and
		 *	_NOT_ what was passed in for p_result.
		 */
		return resume(&frame->scratch_result,
			      MODULE_CTX(m->mmc.mi, module_thread(m->mmc.mi)->data,
			      		 state->env_data, rctx),
			      request);
	}

	/*
	 *	Push the resumption point BEFORE adding the subsection
	 *	to the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, sigmask, rctx);

	if (unlang_interpret_push_section(p_result, request, subcs,
					  FRAME_CONF(default_rcode, UNLANG_SUB_FRAME)) < 0) {
		RETURN_UNLANG_ACTION_FATAL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Run the retry handler.  Called from an async signal handler.
 *
 */
void unlang_module_retry_now(module_ctx_t const *mctx, request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	if (!state->retry_cb) return;

	/*
	 *	Assert that we have the right things.  Note that this function should only be called when the
	 *	retry is being used as an expiry time, i.e. mrc==1.  If the module has its own retry handlers,
	 *	then this function must not be called.
	 */
	fr_assert(state->retry.config != NULL);
	fr_assert(state->retry.config->mrc == 1);
	fr_assert(state->rctx == mctx->rctx);
	fr_assert(state->request == request);

	/*
	 *	Update the time as to when the retry is being called.  This is the main purpose of the
	 *	function.
	 */
	state->retry.updated = fr_time();

	state->retry_cb(mctx, request, &state->retry);

}

/** Cancel the retry timer on resume
 *
 */
static unlang_action_t unlang_module_retry_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	/*
	 *	Cancel the timers, and clean up any associated retry configuration.
	 */
	talloc_const_free(state->ev);
	state->ev = NULL;
	state->retry_cb = NULL;
	state->retry.config = NULL;

	return state->retry_resume(p_result, mctx, request);
}

/** Yield a request back to the interpreter, with retries
 *
 * This passes control of the request back to the unlang interpreter, setting
 * callbacks to execute when the request is 'signalled' asynchronously, or when
 * the retry timer hits.
 *
 * @note The module function which calls #unlang_module_yield_to_retry should return control
 *	of the C stack to the unlang interpreter immediately after calling #unlang_module_yield_to_retry.
 *	A common pattern is to use ``return unlang_module_yield_to_retry(...)``.
 *
 * @param[in] request		The current request.
 * @param[in] resume		Called on unlang_interpret_mark_runnable().
 * @param[in] retry		Called on when a retry timer hits
 * @param[in] signal		Called on unlang_action().
 * @param[in] sigmask		Set of signals to block.  For example if we wanted to only allow
 *				FR_SIGNAL_CANCEL, we'd pass ~FR_SIGNAL_CANCEL to block the other
 *				signals.
 * @param[in] rctx		to pass to the callbacks.
 * @param[in] retry_cfg		to set up the retries
 * @return
 *	- UNLANG_ACTION_YIELD on success
 *	- UNLANG_ACTION_FAIL on failure
 */
unlang_action_t	unlang_module_yield_to_retry(request_t *request, module_method_t resume, unlang_module_retry_t retry,
					     unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx,
					     fr_retry_config_t const *retry_cfg)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_module_t			*m;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	fr_assert(stack->depth > 0);
	fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
	m = unlang_generic_to_module(frame->instruction);

	fr_assert(!state->retry_cb);

	state->retry_cb = retry;
	state->retry_resume = resume;		// so that we can cancel the retry timer
	state->rctx = rctx;

	state->request = request;
	state->mi = m->mmc.mi;

	/*
	 *	Allow unlang statements to override the module configuration.  i.e. if we already have a
	 *	timer from unlang, then just use that.
	 */
	if (!state->retry.config) {
		fr_retry_init(&state->retry, fr_time(), retry_cfg);

		if (fr_timer_at(state, unlang_interpret_event_list(request)->tl, &state->ev,
				state->retry.next,
				false, unlang_module_event_retry_handler, request) < 0) {
			RPEDEBUG("Failed inserting event");
			return UNLANG_ACTION_FAIL;
		}
	}

	return unlang_module_yield(request, unlang_module_retry_resume, signal, sigmask, rctx);
}


/** Yield a request back to the interpreter from within a module
 *
 * This passes control of the request back to the unlang interpreter, setting
 * callbacks to execute when the request is 'signalled' asynchronously, or whatever
 * timer or I/O event the module was waiting for occurs.
 *
 * @note The module function which calls #unlang_module_yield should return control
 *	of the C stack to the unlang interpreter immediately after calling #unlang_module_yield.
 *	A common pattern is to use ``return unlang_module_yield(...)``.
 *
 * @param[in] request		The current request.
 * @param[in] resume		Called on unlang_interpret_mark_runnable().
 * @param[in] signal		Called on unlang_action().
 * @param[in] sigmask		Set of signals to block.  For example if we wanted to only allow
 *				FR_SIGNAL_CANCEL, we'd pass ~FR_SIGNAL_CANCEL to block the other
 *				signals.
 * @param[in] rctx		to pass to the callbacks.
 * @return
 *	- UNLANG_ACTION_YIELD.
 *	- UNLANG_ACTION_FAIL if this is not a module frame.
 */
unlang_action_t unlang_module_yield(request_t *request,
				    module_method_t resume, unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state;

	REQUEST_VERIFY(request);	/* Check the yielded request is sane */

	if (frame->instruction->type != UNLANG_TYPE_MODULE) {
		fr_assert_msg(0, "unlang_module_yield called on a non-module frame");
		return UNLANG_ACTION_FAIL;
	}

	state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	state->rctx = rctx;
	state->resume = resume;

#ifndef NDEBUG
	/*
	 *	We can't do asynchronous signals if the module is not thread safe.
	 *
	 *	Right now, none of the modules marked THREAD_UNSAFE call yield, or set signal callbacks.
	 *	Which means that this code doesn't affect anything.
	 *
	 *	At some point if we do have modules which take signals and which are not thread safe, then
	 *	those modules have to ensure that their signal handlers do any locking necessary.
	 */
	if (signal) {
		unlang_module_t	*m;

		m = unlang_generic_to_module(frame->instruction);
		fr_assert(m);

		fr_assert((m->mmc.mi->exported->flags & MODULE_TYPE_THREAD_UNSAFE) == 0);
	}
#endif

	state->signal = signal;
	state->sigmask = sigmask;

	/*
	 *	We set the repeatable flag here,
	 *	so that the resume function is always
	 *	called going back up the stack.
	 */
	frame_repeat(frame, unlang_module_resume);

	return UNLANG_ACTION_YIELD;
}

/*
 *	Lock the mutex for the module
 */
static inline CC_HINT(always_inline) void safe_lock(module_instance_t *mi)
{
	if ((mi->exported->flags & MODULE_TYPE_THREAD_UNSAFE) != 0) pthread_mutex_lock(&mi->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static inline CC_HINT(always_inline) void safe_unlock(module_instance_t *mi)
{
	if ((mi->exported->flags & MODULE_TYPE_THREAD_UNSAFE) != 0) pthread_mutex_unlock(&mi->mutex);
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #unlang_module_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] frame		current stack frame.
 * @param[in] action		to signal.
 */
static void unlang_module_signal(request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_module_t			*m = unlang_generic_to_module(frame->instruction);
	char const			*caller;

	if (!state->signal) return;

	if (action == FR_SIGNAL_CANCEL) {
		/*
		 *	Cancel the retry timer, if it is set.
		 *
		 *	Because cancellation functions and actual unwinding are done separately
		 *	the retry timer can fire after the module has been cancelled.
		 */
		TALLOC_FREE(state->ev);
	}

	/*
	 *	Async calls can't push anything onto the unlang stack, so we just use a local "caller" here.
	 */
	caller = request->module;
	request->module = m->mmc.mi->name;

	/*
	 *	Call the signal routines.  Note that signals are
	 *	explicitely asynchronous, even if the module has
	 *	declared itself to be MODULE_TYPE_THREAD_UNSAFE.
	 */
	if (!(action & state->sigmask)) state->signal(MODULE_CTX(m->mmc.mi, state->thread->data, state->env_data, state->rctx), request, action);

	if (action == FR_SIGNAL_CANCEL) {
		/*
		 *	One fewer caller for this module.  Since this module
		 *	has been cancelled, decrement the active callers and
		 *	ignore any future signals.
		 */
		state->thread->active_callers--;
		state->signal = NULL;
	}

	request->module = caller;

}

/** Cleanup after a module completes
 *
 */
static unlang_action_t unlang_module_done(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

#ifndef NDEBUG
	fr_assert(state->unlang_indent == request->log.indent.unlang);
#endif

	fr_assert(p_result->rcode >= RLM_MODULE_NOT_SET);
	fr_assert(p_result->rcode < RLM_MODULE_NUMCODES);

	RDEBUG("%s (%s)", frame->instruction->name ? frame->instruction->name : "",
	       fr_table_str_by_value(mod_rcode_table, p_result->rcode, "<invalid>"));

	request->module = state->previous_module;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Cleanup after a yielded module completes
 *
 */
static unlang_action_t unlang_module_resume_done(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	state->thread->active_callers--;

	return unlang_module_done(p_result, request, frame);
}

/** Wrapper to call a module's resumption function
 *
 * This is called _after_ the module first yields, and again after any
 * other yields.
 */
static unlang_action_t unlang_module_resume(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_module_t			*m = unlang_generic_to_module(frame->instruction);
	module_method_t			resume;
	unlang_action_t			ua;

	fr_assert(state->resume != NULL);

	resume = state->resume;

	/*
	 *	The module *MUST* explicitly set the resume
	 *	function when yielding or pushing children
	 *	if it wants to be called again later.
	 */
	state->resume = NULL;

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	safe_lock(m->mmc.mi);
	ua = resume(p_result, MODULE_CTX(m->mmc.mi, state->thread->data,
		    state->env_data, state->rctx), request);
	safe_unlock(m->mmc.mi);

	switch (ua) {
	case UNLANG_ACTION_YIELD:
		/*
		 *	The module yielded but didn't set a
		 *	resume function, this means it's done
		 *	and when the I/O operation completes
		 *	it shouldn't be called again.
		 */
		if (!state->resume) {
			frame_repeat(frame, unlang_module_resume_done);
		} else {
			repeatable_set(frame);
		}
		return UNLANG_ACTION_YIELD;

	/*
	 *	The module is done (for now).
	 *	But, running it pushed one or more asynchronous
	 *	calls onto the stack for evaluation.
	 *	These need to be run before the module resumes
	 *	or the next unlang instruction is processed.
	 */
	case UNLANG_ACTION_PUSHED_CHILD:
		/*
		 *	The module pushed a child and didn't
		 *	set a resume function, this means
		 *	it's done, and we won't call it again
		 *	but we still need to do some cleanup
		 *	after the child returns.
		 */
		if (!state->resume) {
			frame_repeat(frame, unlang_module_resume_done);
		} else {
			repeatable_set(frame);
		}
		return UNLANG_ACTION_PUSHED_CHILD;

	case UNLANG_ACTION_CALCULATE_RESULT:
		/*
		 *	Module set a resume function but
		 *	didn't yield or push additional
		 *	children.
		 *
		 *	Evaluate the function now and
		 *	use the result as the final result.
		 */
		if (state->resume) return unlang_module_resume(p_result, request, frame);
		request->module = state->previous_module;
		break;

	case UNLANG_ACTION_FAIL:
		p_result->rcode = RLM_MODULE_FAIL;
		request->module = state->previous_module;
		break;

	/*
	 *	Module indicates we shouldn't process its rcode
	 */
	case UNLANG_ACTION_EXECUTE_NEXT:
		break;
	}

	unlang_module_resume_done(p_result, request, frame);
	request->module = state->previous_module;

	return ua;
}

/** Call the callback registered for a retry event
 *
 * @param[in] tl	the event timer was inserted into.
 * @param[in] now	The current time, as held by the event_list.
 * @param[in] ctx	the stack frame
 *
 */
static void unlang_module_event_retry_handler(UNUSED fr_timer_list_t *tl, fr_time_t now, void *ctx)
{
	request_t			*request = talloc_get_type_abort(ctx, request_t);
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	switch (fr_retry_next(&state->retry, now)) {
	case FR_RETRY_CONTINUE:
		if (state->retry_cb) {
			/*
			 *	Call the module retry handler, with the state of the retry.  On MRD / MRC, the
			 *	module is made runnable again, and the "resume" function is called.
			 */
			state->retry_cb(MODULE_CTX(state->mi, state->thread, state->env_data, state->rctx), state->request, &state->retry);
		} else {
			/*
			 *	For signals, the module will get either a RETRY
			 *	signal, or a TIMEOUT signal (also for max count).
			 *
			 *	The signal handler should generally change the resume
			 *	function, and mark the request as runnable.  We
			 *	probably don't want the module to do tons of work in
			 *	the signal handler, as it's called from the event
			 *	loop.  And doing so could affect the other event
			 *	timers.
			 *
			 *	Note also that we call frame->signal(), and not
			 *	unlang_interpret_signal().  That is because we want to
			 *	signal only the module.  We know that the other frames
			 *	on the stack can't handle this particular signal.  So
			 *	there's no point in calling them.  Or, if sections
			 *	have their own retry handlers, then we don't want to
			 *	signal those _other_ retry handlers with _our_ signal.
			 */
			frame->signal(request, frame, FR_SIGNAL_RETRY);
		}

		/*
		 *	Reset the timer.
		 */
		if (fr_timer_at(state, unlang_interpret_event_list(request)->tl, &state->ev, state->retry.next,
				false, unlang_module_event_retry_handler, request) < 0) {
			RPEDEBUG("Failed inserting event");
			unlang_interpret_mark_runnable(request); /* and let the caller figure out what's up */
		}
		return;

	case FR_RETRY_MRD:
		RDEBUG("Reached max_rtx_duration (%pVs > %pVs) - sending timeout",
			fr_box_time_delta(fr_time_sub(now, state->retry.start)), fr_box_time_delta(state->retry.config->mrd));
		break;

	case FR_RETRY_MRC:
		RDEBUG("Reached max_rtx_count %u- sending timeout",
		        state->retry.config->mrc);
		break;
	}

	/*
	 *	Run the retry handler on MRD / MRC, too.
	 */
	if (state->retry_cb) {
		state->retry_cb(MODULE_CTX(state->mi, state->thread, state->env_data, state->rctx), state->request, &state->retry);
	} else {
		frame->signal(request, frame, FR_SIGNAL_TIMEOUT);
	}

	/*
	 *	On final timeout, always mark the request as runnable.
	 */
	unlang_interpret_mark_runnable(request);
}

static unlang_action_t unlang_module(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_module_t			*m;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_action_t			ua;
	fr_time_t			now = fr_time_wrap(0);

	p_result->rcode = RLM_MODULE_NOOP;
	state->previous_module = request->module;

#ifndef NDEBUG
	state->unlang_indent = request->log.indent.unlang;
#endif
	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	m = unlang_generic_to_module(frame->instruction);
	fr_assert(m);

	RDEBUG4("[%i] %s - %s (%s)", stack_depth_current(request), __FUNCTION__,
		m->mmc.mi->module->exported->name, m->mmc.mi->name);

	/*
	 *	Return administratively configured return code
	 */
	if (m->mmc.mi->force) {
		p_result->rcode = m->mmc.mi->code;
		ua = UNLANG_ACTION_CALCULATE_RESULT;
		goto done;
	}

	if (m->mmc.mmb.method_env) {
		if (!state->env_data) {
			ua = call_env_expand(state, request, &state->env_result, &state->env_data, m->call_env);
			switch (ua) {
			case UNLANG_ACTION_FAIL:
				goto fail;

			case UNLANG_ACTION_PUSHED_CHILD:
				frame_repeat(frame, unlang_module);
				return UNLANG_ACTION_PUSHED_CHILD;

			default:
				break;
			}
		}

		/*
		 *	Fail the module call on callenv failure
		 */
		if (state->env_result != CALL_ENV_SUCCESS) return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	state->thread = module_thread(m->mmc.mi);
	fr_assert(state->thread != NULL);

	/*
	 *	For logging unresponsive children.
	 */
	state->thread->total_calls++;

	/*
	 *	If we're doing retries, remember when we started
	 *	running the module.
	 */
	if (fr_time_delta_ispos(frame->instruction->actions.retry.irt)) now = fr_time();

	/*
	 *	Pre-allocate an rctx for the module, if it has one.
	 */
	fr_assert_msg(state->rctx == NULL, "rctx should be NULL for initial module call");
	{
		size_t size = 0;
		char const *type;

		/*
		 *	Use the module method binding's rctx size in preference
		 *	to the one set for the module as a whole.
		 */
		if (m->mmc.mmb.rctx_size) {
			size = m->mmc.mmb.rctx_size;
			type = m->mmc.mmb.rctx_type;
		/*
		 *	Use the rctx from the module_t
		 *
		 *	The module is still fine to allocate the rctx itself
		 *	in the first module method call.
		 */
		} else if(m->mmc.mi->exported->rctx_size) {
			size = m->mmc.mi->exported->rctx_size;
			type = m->mmc.mi->exported->rctx_type;
		} else {
			size = 0;
			type = NULL;
		}

		if (size > 0) {
			MEM(state->rctx = talloc_zero_array(state, uint8_t, size));
			if (!type) {
				talloc_set_name(state->rctx, "%s_rctx_t", m->mmc.mi->name);
			} else {
				talloc_set_name_const(state->rctx, type);
			}
		}
	}

	request->module = m->mmc.mi->name;
	safe_lock(m->mmc.mi);	/* Noop unless instance->mutex set */
	ua = m->mmc.mmb.method(p_result,
			       MODULE_CTX(m->mmc.mi, state->thread->data, state->env_data, state->rctx),
			       request);
	safe_unlock(m->mmc.mi);

	switch (ua) {
	case UNLANG_ACTION_YIELD:
		state->thread->active_callers++;

		/*
		 *	The module yielded but didn't set a
		 *	resume function, this means it's done
		 *	and when the I/O operation completes
		 *	it shouldn't be called again.
		 */
		if (!state->resume) {
			frame_repeat(frame, unlang_module_resume_done);
		} else {
			frame_repeat(frame, unlang_module_resume);
		}

		/*
		 *	If we have retry timers, then start the retries.
		 */
		if (fr_time_delta_ispos(frame->instruction->actions.retry.irt)) {
			fr_assert(fr_time_gt(now, fr_time_wrap(0)));

			fr_retry_init(&state->retry, now, &frame->instruction->actions.retry);

			if (fr_timer_at(state, unlang_interpret_event_list(request)->tl,
					&state->ev, state->retry.next,
					false, unlang_module_event_retry_handler, request) < 0) {
				RPEDEBUG("Failed inserting event");
				goto fail;
			}
		}

		return UNLANG_ACTION_YIELD;

	/*
	 *	The module is done (for now).
	 *	But, running it pushed one or more asynchronous
	 *	calls onto the stack for evaluation.
	 *	These need to be run before the module resumes
	 *	or the next unlang instruction is processed.
	 */
	case UNLANG_ACTION_PUSHED_CHILD:
		/*
		 *	The module pushed a child and didn't
		 *	set a resume function, this means
		 *	it's done, and we won't call it again
		 *	but we still need to do some cleanup
		 *	after the child returns.
		 */
		if (!state->resume) {
			frame_repeat(frame, unlang_module_done);
		} else {
			repeatable_set(frame);
		}
		return UNLANG_ACTION_PUSHED_CHILD;

	case UNLANG_ACTION_CALCULATE_RESULT:
		/*
		 *	Module set a resume function but
		 *	didn't yield or push additional
		 *	children.
		 *
		 *	Evaluate the function now and
		 *	use the result as the final result.
		 */
		if (state->resume) {
			frame->process = unlang_module_resume;	/* unlang_module_resume will assume this is set */
			return unlang_module_resume(p_result, request, frame);
		}
		break;

	case UNLANG_ACTION_FAIL:
	fail:
		p_result->rcode = RLM_MODULE_FAIL;
		break;

	/*
	 *	Module indicates we shouldn't process its rcode
	 */
	case UNLANG_ACTION_EXECUTE_NEXT:
		break;
	}

done:
	request->module = state->previous_module;
	unlang_module_done(p_result, request, frame);
	return ua;
}

void unlang_module_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "module",
			.type = UNLANG_TYPE_MODULE,

			/*
			 *	- UNLANG_OP_FLAG_RCODE_SET
			 *	  Set request->rcode to be the rcode from the module.
			 *	- UNLANG_OP_FLAG_RETURN_POINT
			 *	  Set the return point to be the module.
			 */
			.flag = UNLANG_OP_FLAG_RCODE_SET |
				UNLANG_OP_FLAG_RETURN_POINT |
				UNLANG_OP_FLAG_INTERNAL,

			.interpret = unlang_module,
			.signal = unlang_module_signal,

			.unlang_size = sizeof(unlang_module_t),
			.unlang_name = "unlang_module_t",

			.frame_state_size = sizeof(unlang_frame_state_module_t),
			.frame_state_type = "unlang_frame_state_module_t",
		});
}
