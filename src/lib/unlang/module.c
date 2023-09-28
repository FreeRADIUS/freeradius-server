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
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/call_env.h>

#include "module_priv.h"
#include "subrequest_priv.h"

#include "tmpl.h"

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct {
	request_t			*request;	//!< Request this event pertains to.
	int				fd;		//!< File descriptor to wait on.
	unlang_module_timeout_t		timeout;	//!< Function to call on timeout.
	unlang_module_fd_event_t	fd_read;	//!< Function to call when FD is readable.
	unlang_module_fd_event_t	fd_write;	//!< Function to call when FD is writable.
	unlang_module_fd_event_t	fd_error;	//!< Function to call when FD has errored.
	dl_module_inst_t		*dl_inst;	//!< Module instance to pass to callbacks.
							///< Use dl_inst->data to get instance data.
	void				*thread;	//!< Thread specific module instance.
	void				*env_data;	//!< Per call environment data.
	void const			*rctx;		//!< rctx data to pass to callbacks.
	fr_event_timer_t const		*ev;		//!< Event in this worker's event heap.
} unlang_module_event_t;

static unlang_action_t unlang_module_resume(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame);

/** Call the callback registered for a read I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_module_event_t structure holding callbacks.
 */
static void unlang_event_fd_read_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_module_event_t *ev = talloc_get_type_abort(ctx, unlang_module_event_t);

	fr_assert(ev->fd == fd);

	ev->fd_read(MODULE_CTX(ev->dl_inst, ev->thread, ev->env_data, UNCONST(void *, ev->rctx)), ev->request, fd);
}

/** Frees an unlang event, removing it from the request's event loop
 *
 * @param[in] ev	The event to free.
 *
 * @return 0
 */
static int _unlang_event_free(unlang_module_event_t *ev)
{
	if (ev->request) (void) request_data_get(ev->request, ev->rctx, UNLANG_TYPE_MODULE);

	if (ev->ev) {
		(void) fr_event_timer_delete(&(ev->ev));
		return 0;
	}

	if (ev->fd >= 0) {
		if (!ev->request) return 0;
		(void) fr_event_fd_delete(unlang_interpret_event_list(ev->request), ev->fd, FR_EVENT_FILTER_IO);
	}

	return 0;
}

/** Call the callback registered for a timeout event
 *
 * @param[in] el	the event timer was inserted into.
 * @param[in] now	The current time, as held by the event_list.
 * @param[in] ctx	unlang_module_event_t structure holding callbacks.
 *
 */
static void unlang_module_event_timeout_handler(UNUSED fr_event_list_t *el, fr_time_t now, void *ctx)
{
	unlang_module_event_t *ev = talloc_get_type_abort(ctx, unlang_module_event_t);

	ev->timeout(MODULE_CTX(ev->dl_inst, ev->thread, ev->env_data, UNCONST(void *, ev->rctx)), ev->request, now);
	talloc_free(ev);
}

/** Set a timeout for the request.
 *
 * Used when a module needs wait for an event.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * param[in] request		the current request.
 * param[in] callback		to call.
 * param[in] rctx		to pass to the callback.
 * param[in] timeout		when to call the timeout (i.e. now + timeout).
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_module_timeout_add(request_t *request, unlang_module_timeout_t callback,
			      void const *rctx, fr_time_t when)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_module_event_t		*ev;
	unlang_module_t			*mc;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	fr_assert(stack->depth > 0);
	fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
	mc = unlang_generic_to_module(frame->instruction);

	ev = talloc(request, unlang_module_event_t);
	if (!ev) return -1;

	*ev = (unlang_module_event_t){
		.request = request,
		.fd = -1,
		.timeout = callback,
		.dl_inst = mc->instance->dl_inst,
		.thread = state->thread,
		.env_data = state->env_data,
		.rctx = rctx
	};

	if (fr_event_timer_at(request, unlang_interpret_event_list(request), &ev->ev,
			      when, unlang_module_event_timeout_handler, ev) < 0) {
		RPEDEBUG("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	(void) request_data_talloc_add(request, rctx, UNLANG_TYPE_MODULE, unlang_module_event_t, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Delete a previously set timeout callback
 *
 * @param[in] request	The current request.
 * @param[in] ctx	a local context for the callback.
 * @return
 *	- -1 on error.
 *	- 0 on success.
 */
int unlang_module_timeout_delete(request_t *request, void const *ctx)
{
	unlang_module_event_t *ev;

	ev = request_data_get(request, ctx, UNLANG_TYPE_MODULE);
	if (!ev) return -1;
	talloc_free(ev);

	return 0;
}

/** Call the callback registered for a write I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_module_event_t structure holding callbacks.
 */
static void unlang_event_fd_write_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_module_event_t *ev = talloc_get_type_abort(ctx, unlang_module_event_t);
	fr_assert(ev->fd == fd);

	ev->fd_write(MODULE_CTX(ev->dl_inst, ev->thread, ev->env_data, UNCONST(void *, ev->rctx)), ev->request, fd);
}

/** Call the callback registered for an I/O error event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] ctx	unlang_module_event_t structure holding callbacks.
 */
static void unlang_event_fd_error_handler(UNUSED fr_event_list_t *el, int fd,
					  UNUSED int flags, UNUSED int fd_errno, void *ctx)
{
	unlang_module_event_t *ev = talloc_get_type_abort(ctx, unlang_module_event_t);

	fr_assert(ev->fd == fd);

	ev->fd_error(MODULE_CTX(ev->dl_inst, ev->thread, ev->env_data, UNCONST(void *, ev->rctx)), ev->request, fd);
}


/** Set a callback for the request.
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * @param[in] request		The current request.
 * @param[in] read		callback.  Used for receiving and demuxing/decoding data.
 * @param[in] write		callback.  Used for writing and encoding data.
 *				Where a 3rd party library is used, this should be the function
 *				issuing queries, and writing data to the socket.  This should
 *				not be done in the module itself.
 *				This allows write operations to be retried in some instances,
 *				and means if the write buffer is full, the request is kept in
 *				a suspended state.
 * @param[in] error		callback.  If the fd enters an error state.  Should cleanup any
 *				handles wrapping the file descriptor, and any outstanding requests.
 * @param[in] rctx		for the callback.
 * @param[in] fd		to watch.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_module_fd_add(request_t *request,
			unlang_module_fd_event_t read,
			unlang_module_fd_event_t write,
			unlang_module_fd_event_t error,
			void const *rctx, int fd)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_module_event_t		*ev;
	unlang_module_t			*mc;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_module_t);

	fr_assert(stack->depth > 0);

	fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
	mc = unlang_generic_to_module(frame->instruction);

	ev = talloc_zero(request, unlang_module_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_read = read;
	ev->fd_write = write;
	ev->fd_error = error;
	ev->dl_inst = mc->instance->dl_inst;
	ev->thread = state->thread;
	ev->env_data = state->env_data;
	ev->rctx = rctx;

	/*
	 *	Register for events on the file descriptor
	 */
	if (fr_event_fd_insert(request, unlang_interpret_event_list(request), fd,
			       ev->fd_read ? unlang_event_fd_read_handler : NULL,
			       ev->fd_write ? unlang_event_fd_write_handler : NULL,
			       ev->fd_error ? unlang_event_fd_error_handler: NULL,
			       ev) < 0) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_talloc_add(request, rctx, fd, unlang_module_event_t, ev, true, false, false);
	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Delete a previously set file descriptor callback
 *
 * param[in] request the request
 * param[in] fd the file descriptor
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_module_fd_delete(request_t *request, void const *ctx, int fd)
{
	unlang_module_event_t *ev;

	ev = request_data_get(request, ctx, fd);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

/** Push a module or submodule onto the stack for evaluation
 *
 * @param[out] p_result		Where to write the result of calling the module.
 * @param[in] request		The current request.
 * @param[in] module_instance	Instance of the module to call.
 * @param[in] method		to call.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_module_push(rlm_rcode_t *p_result, request_t *request,
		       module_instance_t *module_instance, module_method_t method, bool top_frame)
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
			.name = module_instance->name,
			.debug_name = module_instance->name,
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
					[RLM_MODULE_UPDATED]	= 0
				},
				.retry = RETRY_INIT,
			},
		},
		.instance = module_instance,
		.method = method
	};

	/*
	 *	Push a new module frame onto the stack
	 */
	if (unlang_interpret_push(request, unlang_module_to_generic(mc),
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, top_frame) < 0) {
		return -1;
	}

	frame = &stack->frame[stack->depth];
	state = frame->state;
	*state = (unlang_frame_state_module_t){
		.p_result = p_result,
		.thread = module_thread(module_instance)
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
 * will then call the module resumption frame, allowing the module to continue exectuion.
 *
 * @param[in] ctx		To allocate talloc value boxes and values in.
 * @param[out] p_success	Whether xlat evaluation was successful.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] exp		XLAT expansion to evaluate.
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] sigmask		Signals to block.
 * @param[in] rctx		to pass to the resume() and signal() callbacks.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD
 */
unlang_action_t unlang_module_yield_to_xlat(TALLOC_CTX *ctx, bool *p_success, fr_value_box_list_t *out,
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
	if (unlang_xlat_push(ctx, p_success, out, request, exp, false) < 0) return UNLANG_ACTION_STOP_PROCESSING;

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
 * will then call the module resumption frame, allowing the module to continue exectuion.
 *
 * @param[in] ctx		To allocate talloc value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] vpt		the tmpl to expand
 * @param[in] args		Arguments which control how to evaluate the various
 *				types of xlats.
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] sigmask		Signals to block.
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
	if (unlang_tmpl_push(ctx, out, request, vpt, args) < 0) {
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

unlang_action_t unlang_module_yield_to_section(rlm_rcode_t *p_result,
					       request_t *request, CONF_SECTION *subcs,
					       rlm_rcode_t default_rcode,
					       module_method_t resume,
					       unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	if (!subcs) {
		unlang_stack_t		*stack = request->stack;
		unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
		unlang_module_t		*mc;
		unlang_frame_state_module_t	*state;

		fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
		mc = unlang_generic_to_module(frame->instruction);

		/*
		 *	Be transparent to the resume function.
		 *	frame->result will be overwritten
		 *	anyway when we return.
		 */
		stack->result = frame->result = default_rcode;
		state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

		return resume(p_result,
			      MODULE_CTX(mc->instance->dl_inst, module_thread(mc->instance)->data,
			      		 state->env_data, rctx),
			      request);
	}

	/*
	 *	Push the resumption point BEFORE adding the subsection
	 *	to the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, sigmask, rctx);

	if (unlang_interpret_push_section(request, subcs,
					  default_rcode, UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_STOP_PROCESSING;

	return UNLANG_ACTION_PUSHED_CHILD;
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
 * @param[in] sigmask		Set of signals to block.
 * @param[in] rctx		to pass to the callbacks.
 * @return
 *	- UNLANG_ACTION_YIELD.
 */
unlang_action_t unlang_module_yield(request_t *request,
				    module_method_t resume, unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	REQUEST_VERIFY(request);	/* Check the yielded request is sane */

	state->rctx = rctx;
	state->resume = resume;
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
	if ((mi->module->type & MODULE_TYPE_THREAD_UNSAFE) != 0) pthread_mutex_lock(&mi->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static inline CC_HINT(always_inline) void safe_unlock(module_instance_t *mi)
{
	if ((mi->module->type & MODULE_TYPE_THREAD_UNSAFE) != 0) pthread_mutex_unlock(&mi->mutex);
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
	unlang_module_t			*mc = unlang_generic_to_module(frame->instruction);
	char const			*caller;

	if (!state->signal) return;

	/*
	 *	Async calls can't push anything onto the unlang stack, so we just use a local "caller" here.
	 */
	caller = request->module;
	request->module = mc->instance->name;
	safe_lock(mc->instance);
	if (!(action & state->sigmask)) state->signal(MODULE_CTX(mc->instance->dl_inst, state->thread->data, state->env_data, state->rctx), request, action);
	safe_unlock(mc->instance);
	request->module = caller;

	/*
	 *	One fewer caller for this module.  Since this module
	 *	has been cancelled, decrement the active callers and
	 *	ignore any future signals.
	 */
	if (action == FR_SIGNAL_CANCEL) {
		state->thread->active_callers--;
		state->signal = NULL;
	}
}

/** Cleanup after a module completes
 *
 */
static unlang_action_t unlang_module_done(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	rlm_rcode_t			rcode = state-> set_rcode ? state->rcode : *p_result;

#ifndef NDEBUG
	fr_assert(state->unlang_indent == request->log.unlang_indent);
#endif

	fr_assert(rcode >= RLM_MODULE_REJECT);
	fr_assert(rcode < RLM_MODULE_NOT_SET);

	RDEBUG("%s (%s)", frame->instruction->name ? frame->instruction->name : "",
	       fr_table_str_by_value(mod_rcode_table, rcode, "<invalid>"));

	if (state->p_result) *state->p_result = rcode;	/* Inform our caller if we have one */
	*p_result = rcode;
	request->module = state->previous_module;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Cleanup after a yielded module completes
 *
 */
static unlang_action_t unlang_module_resume_done(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
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
static unlang_action_t unlang_module_resume(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_module_t			*mc = unlang_generic_to_module(frame->instruction);
	module_method_t		resume;
	unlang_action_t			ua;

	/*
	 *	Update the rcode from any child calls that
	 *	may have been performed. The module still
	 *	has a chance to override this rcode if it
	 *	wants, but process modules in particular
	 *	expect to see the result of child
	 *	evaluations available to them in p_result.
	 */
	state->rcode = *p_result < RLM_MODULE_NUMCODES ? *p_result : RLM_MODULE_NOOP;

	fr_assert(state->resume != NULL);

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	request->module = mc->instance->name;

	resume = state->resume;
	/*
	 *	The module *MUST* explicitly set the resume
	 *	function when yielding or pushing children
	 *	if it wants to be called again later.
	 */
	state->resume = NULL;

	safe_lock(mc->instance);
	ua = resume(&state->rcode, MODULE_CTX(mc->instance->dl_inst, state->thread->data,
					      state->env_data, state->rctx), request);
	safe_unlock(mc->instance);

	if (request->master_state == REQUEST_STOP_PROCESSING) ua = UNLANG_ACTION_STOP_PROCESSING;

	switch (ua) {
	case UNLANG_ACTION_STOP_PROCESSING:
		RWARN("Module %s or worker signalled to stop processing request", mc->instance->module->name);
		if (state->p_result) *state->p_result = state->rcode;
		state->thread->active_callers--;
		*p_result = state->rcode;
		request->module = state->previous_module;
		return UNLANG_ACTION_STOP_PROCESSING;

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
			state->set_rcode = false;	/* Preserve the child rcode */
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

	case UNLANG_ACTION_UNWIND:
		request->module = state->previous_module;
		break;

	case UNLANG_ACTION_FAIL:
		*p_result = RLM_MODULE_FAIL;
		request->module = state->previous_module;
		break;

	case UNLANG_ACTION_EXECUTE_NEXT:	/* Not valid */
		fr_assert(0);
		*p_result = RLM_MODULE_FAIL;
		break;
	}

	unlang_module_resume_done(p_result, request, frame);
	request->module = state->previous_module;

	return ua;
}

/** Call the callback registered for a retry event
 *
 * @param[in] el	the event timer was inserted into.
 * @param[in] now	The current time, as held by the event_list.
 * @param[in] ctx	the stack frame
 *
 */
static void unlang_module_event_retry_handler(UNUSED fr_event_list_t *el, fr_time_t now, void *ctx)
{
	request_t			*request = talloc_get_type_abort(ctx, request_t);
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	/*
	 *	The module will get either a RETRY signal, or a
	 *	TIMEOUT signal (also for max count).
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
	 *	signal those _other_ retry handles with _our_ signal.
	 */
	switch (fr_retry_next(&state->retry, now)) {
	case FR_RETRY_CONTINUE:
		frame->signal(request, frame, FR_SIGNAL_RETRY);

		/*
		 *	Reset the timer.
		 */
		if (fr_event_timer_at(request, unlang_interpret_event_list(request), &state->ev, state->retry.next,
				      unlang_module_event_retry_handler, request) < 0) {
			RPEDEBUG("Failed inserting event");
			unlang_interpret_mark_runnable(request); /* and let the caller figure out what's up */
		}
		return;

	case FR_RETRY_MRD:
		REDEBUG("Reached max_rtx_duration (%pVs > %pVs) - sending timeout signal",
			fr_box_time_delta(fr_time_sub(now, state->retry.start)), fr_box_time_delta(state->retry.config->mrd));
		break;

	case FR_RETRY_MRC:
		REDEBUG("Reached max_rtx_count (%u > %u) - sending timeout signal",
		        state->retry.count, state->retry.config->mrc);
		break;
	}

	frame->signal(request, frame, FR_SIGNAL_TIMEOUT);
}

static unlang_action_t unlang_module(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_module_t			*mc;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_action_t			ua;
	fr_time_t			now = fr_time_wrap(0);

	*p_result = state->rcode = RLM_MODULE_NOOP;
	state->set_rcode = true;
	state->previous_module = request->module;

#ifndef NDEBUG
	state->unlang_indent = request->log.unlang_indent;
#endif
	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	mc = unlang_generic_to_module(frame->instruction);
	fr_assert(mc);

	RDEBUG4("[%i] %s - %s (%s)", stack_depth_current(request), __FUNCTION__,
		mc->instance->name, mc->instance->module->name);

	state->p_result = NULL;

	/*
	 *	Return administratively configured return code
	 */
	if (mc->instance->force) {
		state->rcode = mc->instance->code;
		ua = UNLANG_ACTION_CALCULATE_RESULT;
		goto done;
	}

	if (mc->method_env) {
		if (!state->env_data) {
			ua = call_env_expand(state, request, &state->env_result, &state->env_data, mc->method_env, &mc->call_env_parsed);
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
		if (state->env_result != CALL_ENV_SUCCESS) RETURN_MODULE_FAIL;
	}

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	state->thread = module_thread(mc->instance);
	fr_assert(state->thread != NULL);

	/*
	 *	Don't allow returning _through_ modules
	 */
	return_point_set(frame_current(request));

	/*
	 *	For logging unresponsive children.
	 */
	state->thread->total_calls++;

	/*
	 *	If we're doing retries, remember when we started
	 *	running the module.
	 */
	if (fr_time_delta_ispos(frame->instruction->actions.retry.irt)) now = fr_time();

	request->module = mc->instance->name;
	safe_lock(mc->instance);	/* Noop unless instance->mutex set */
	ua = mc->method(&state->rcode,
			MODULE_CTX(mc->instance->dl_inst, state->thread->data, state->env_data, NULL),
			request);
	safe_unlock(mc->instance);

	if (request->master_state == REQUEST_STOP_PROCESSING) ua = UNLANG_ACTION_STOP_PROCESSING;

	switch (ua) {
	/*
	 *	It is now marked as "stop" when it wasn't before, we
	 *	must have been blocked.
	 */
	case UNLANG_ACTION_STOP_PROCESSING:
		RWARN("Module %s became unblocked", mc->instance->module->name);
		if (state->p_result) *state->p_result = state->rcode;
		*p_result = state->rcode;
		request->module = state->previous_module;
		return UNLANG_ACTION_STOP_PROCESSING;

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

			(void) fr_retry_init(&state->retry, now, &frame->instruction->actions.retry); /* can't fail */

			if (fr_event_timer_at(request, unlang_interpret_event_list(request),
					      &state->ev, state->retry.next,
					      unlang_module_event_retry_handler, request) < 0) {
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
			state->set_rcode = false;	/* Preserve the child rcode */
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

	case UNLANG_ACTION_UNWIND:
		break;

	case UNLANG_ACTION_FAIL:
	fail:
		*p_result = RLM_MODULE_FAIL;
		break;

	case UNLANG_ACTION_EXECUTE_NEXT:
		fr_assert(0);
		*p_result = RLM_MODULE_FAIL;
		break;
	}

done:
	request->module = state->previous_module;
	unlang_module_done(p_result, request, frame);
	return ua;
}

void unlang_module_init(void)
{
	unlang_register(UNLANG_TYPE_MODULE,
			   &(unlang_op_t){
				.name = "module",
				.interpret = unlang_module,
				.signal = unlang_module_signal,
				.frame_state_size = sizeof(unlang_frame_state_module_t),
				.frame_state_type = "unlang_frame_state_module_t",
			   });
}
