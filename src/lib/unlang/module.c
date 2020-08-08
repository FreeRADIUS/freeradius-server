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

#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/unlang/base.h>
#include "unlang_priv.h"
#include "module_priv.h"
#include "subrequest_priv.h"
#include "tmpl.h"

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct {
	REQUEST				*request;	//!< Request this event pertains to.
	int				fd;		//!< File descriptor to wait on.
	fr_unlang_module_timeout_t	timeout;	//!< Function to call on timeout.
	fr_unlang_module_fd_event_t	fd_read;	//!< Function to call when FD is readable.
	fr_unlang_module_fd_event_t	fd_write;	//!< Function to call when FD is writable.
	fr_unlang_module_fd_event_t	fd_error;	//!< Function to call when FD has errored.
	void const			*inst;		//!< Module instance to pass to callbacks.
	void				*thread;	//!< Thread specific module instance.
	void const			*ctx;		//!< ctx data to pass to callbacks.
	fr_event_timer_t const		*ev;		//!< Event in this worker's event heap.
} unlang_module_event_t;

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
	void *mutable_ctx;
	void *mutable_inst;

	fr_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_read(&(module_ctx_t){ .instance = mutable_inst, .thread = ev->thread }, ev->request, mutable_ctx, fd);
}

/** Frees an unlang event, removing it from the request's event loop
 *
 * @param[in] ev	The event to free.
 *
 * @return 0
 */
static int _unlang_event_free(unlang_module_event_t *ev)
{
	if (ev->request) (void) request_data_get(ev->request, ev->ctx, UNLANG_TYPE_MODULE);

	if (ev->ev) {
		(void) fr_event_timer_delete(&(ev->ev));
		return 0;
	}

	if (ev->fd >= 0) {
		if (!ev->request || !ev->request->el) return 0;

		(void) fr_event_fd_delete(ev->request->el, ev->fd, FR_EVENT_FILTER_IO);
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
	void *mutable_ctx;
	void *mutable_inst;

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->timeout(&(module_ctx_t){ .instance = mutable_inst, .thread = ev->thread }, ev->request, mutable_ctx, now);
	talloc_free(ev);
}

/** Set a timeout for the request.
 *
 * Used when a module needs wait for an event.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_resumable().
 *
 * param[in] request		the current request.
 * param[in] callback		to call.
 * param[in] ctx		for the callback.
 * param[in] timeout		when to call the timeout (i.e. now + timeout).
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_module_timeout_add(REQUEST *request, fr_unlang_module_timeout_t callback,
			      void const *ctx, fr_time_t when)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_module_event_t		*ev;
	unlang_module_t			*sp;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state,
								    unlang_frame_state_module_t);

	fr_assert(stack->depth > 0);
	fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
	sp = unlang_generic_to_module(frame->instruction);

	ev = talloc_zero(request, unlang_module_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout = callback;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = state->thread;
	ev->ctx = ctx;

	if (fr_event_timer_at(request, request->el, &ev->ev,
			      when, unlang_module_event_timeout_handler, ev) < 0) {
		RPEDEBUG("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	(void) request_data_talloc_add(request, ctx, UNLANG_TYPE_MODULE, unlang_module_event_t, ev, true, false, false);

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
int unlang_module_timeout_delete(REQUEST *request, void const *ctx)
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
	void *mutable_ctx;
	void *mutable_inst;

	fr_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_write(&(module_ctx_t){ .instance = mutable_inst, .thread = ev->thread }, ev->request, mutable_ctx, fd);
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
	void *mutable_ctx;
	void *mutable_inst;

	fr_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_error(&(module_ctx_t){ .instance = mutable_inst, .thread = ev->thread }, ev->request, mutable_ctx, fd);
}


/** Set a callback for the request.
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_resumable().
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
 * @param[in] ctx		for the callback.
 * @param[in] fd		to watch.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_module_fd_add(REQUEST *request,
			fr_unlang_module_fd_event_t read,
			fr_unlang_module_fd_event_t write,
			fr_unlang_module_fd_event_t error,
			void const *ctx, int fd)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_module_event_t		*ev;
	unlang_module_t			*sp;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state,
								    unlang_frame_state_module_t);

	fr_assert(stack->depth > 0);

	fr_assert(frame->instruction->type == UNLANG_TYPE_MODULE);
	sp = unlang_generic_to_module(frame->instruction);

	ev = talloc_zero(request, unlang_module_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_read = read;
	ev->fd_write = write;
	ev->fd_error = error;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = state->thread;
	ev->ctx = ctx;

	/*
	 *	Register for events on the file descriptor
	 */
	if (fr_event_fd_insert(request, request->el, fd,
			       ev->fd_read ? unlang_event_fd_read_handler : NULL,
			       ev->fd_write ? unlang_event_fd_write_handler : NULL,
			       ev->fd_error ? unlang_event_fd_error_handler: NULL,
			       ev) < 0) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_talloc_add(request, ctx, fd, unlang_module_event_t, ev, true, false, false);
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
int unlang_module_fd_delete(REQUEST *request, void const *ctx, int fd)
{
	unlang_module_event_t *ev;

	ev = request_data_get(request, ctx, fd);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

/** Push a module or submodule onto the stack for evaluation
 *
 * @param[out] out		Where to write the result of calling the module.
 * @param[in] request		The current request.
 * @param[in] module_instance	Instance of the module to call.
 * @param[in] method		to call.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 */
void unlang_module_push(rlm_rcode_t *out, REQUEST *request,
			module_instance_t *module_instance, module_method_t method, bool top_frame)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_module_t	*state;
	unlang_module_t			*sp;

	static unlang_t module_instruction = {
		.type = UNLANG_TYPE_MODULE,
		.name = "module",
		.debug_name = "module",
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
	};

	/*
	 *	Allocate a state for module.
	 */
	MEM(state = talloc_zero(stack, unlang_frame_state_module_t));
	state->presult = out;
	state->thread = module_thread(module_instance);
	fr_assert(state->thread != NULL);

	/*
	 *	We need to have a unlang_module_t to push on the
	 *	stack.  The only sane way to do it is to attach it to
	 *	the frame state.
	 */
	MEM(sp = talloc_zero(state, unlang_module_t));	/* Free at the same time as the state */
	sp->self = module_instruction;
	sp->self.name = module_instance->name;
	sp->self.debug_name = sp->self.name;
	sp->module_instance = module_instance;
	sp->method = method;

	/*
	 *	Push a new module frame onto the stack
	 */
	unlang_interpret_push(request, unlang_module_to_generic(sp), RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, top_frame);
	frame = &stack->frame[stack->depth];
	TALLOC_FREE(frame->state); /* was allocated for us, but we have our own version */
	frame->state = state;
}

/** Allocate a subrequest to run through a virtual server at some point in the future
 *
 * @param[in] parent		to hang sub request off of.
 * @param[in] namespace		the child will operate in.
 * @return
 *	- A new child request.
 *	- NULL on failure.
 */
REQUEST *unlang_module_subrequest_alloc(REQUEST *parent, fr_dict_t const *namespace)
{
	return unlang_io_subrequest_alloc(parent, namespace, UNLANG_NORMAL_CHILD);
}

/** Yield, spawning a child request, and resuming once the child request is complete
 *
 * @param[in] out		Final rcode from when evaluation of the child request finishes.
 * @param[out] child		to yield to.  The child knows about the parent,
 *				which is why the parent isn't passed explicitly.
 * @param[in] resume		function to call when the child has finished executing.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] session		control values.  Whether we restore/store session info.
 * @param[in] rctx		to pass to the resume() and signal() callbacks.
 * @return
 *	- RLM_MODULE_YIELD.
 */
rlm_rcode_t unlang_module_yield_to_subrequest(rlm_rcode_t *out, REQUEST *child,
					      fr_unlang_module_resume_t resume,
					      fr_unlang_module_signal_t signal,
					      unlang_subrequest_session_t const *session,
					      void *rctx)
{
	/*
	 *	Push the resumption point BEFORE adding the subrequest
	 *	to the parents stack.
	 */
	(void) unlang_module_yield(child->parent, resume, signal, rctx);

	/*
	 *	Push the subrequest and immediately run it.
	 */
	unlang_subrequest_push(out, child, session, UNLANG_SUB_FRAME);

	return RLM_MODULE_YIELD;
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
rlm_rcode_t unlang_module_yield_to_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
					REQUEST *request, xlat_exp_t const *exp,
					fr_unlang_module_resume_t resume,
					fr_unlang_module_signal_t signal, void *rctx)
{
	/*
	 *	Push the resumption point BEFORE pushing the xlat onto
	 *	the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, rctx);

	/*
	 *	Push the xlat function
	 */
	unlang_xlat_push(ctx, out, request, exp, false);

	return RLM_MODULE_YIELD;
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
 * @param[out] status		exit status of the program
 * @param[in] request		The current request.
 * @param[in] vpt		the tmpl to expand
 * @param[in] vps		the input VPs.  May be NULL
 * @param[in] resume		function to call when the XLAT expansion is complete.
 * @param[in] signal		function to call if a signal is received.
 * @param[in] rctx		to pass to the resume() and signal() callbacks.
 * @return
 *	- RLM_MODULE_YIELD.
 */
rlm_rcode_t unlang_module_yield_to_tmpl(TALLOC_CTX *ctx, fr_value_box_t **out, int *status,
					REQUEST *request, tmpl_t const *vpt,
					VALUE_PAIR *vps,
					fr_unlang_module_resume_t resume,
					fr_unlang_module_signal_t signal, void *rctx)
{
	/*
	 *	Push the resumption point BEFORE pushing the xlat onto
	 *	the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, rctx);

	/*
	 *	Push the xlat function
	 */
	unlang_tmpl_push(ctx, out, request, vpt, vps, status);

	return RLM_MODULE_YIELD;
}

rlm_rcode_t unlang_module_yield_to_section(REQUEST *request, CONF_SECTION *subcs,
					   rlm_rcode_t default_rcode,
					   fr_unlang_module_resume_t resume,
					   fr_unlang_module_signal_t signal, void *rctx)
{
	if (!subcs) {
		unlang_stack_t		*stack = request->stack;
		unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
		unlang_t		*instruction = frame->instruction;
		unlang_module_t	*sp;

		fr_assert(instruction->type == UNLANG_TYPE_MODULE);
		sp = unlang_generic_to_module(instruction);

		/*
		 *	Be transparent to the resume function.
		 *	frame->result will be overwritten
		 *	anyway when we return.
		 */
		request->rcode = frame->result = default_rcode;

		return resume(&(module_ctx_t){
				.instance = sp->module_instance->dl_inst->data,
				.thread = module_thread(sp->module_instance)->data
			      }, request, rctx);
	}

	/*
	 *	Push the resumption point BEFORE adding the subsection
	 *	to the parents stack.
	 */
	(void) unlang_module_yield(request, resume, signal, rctx);

	unlang_interpret_push_section(request, subcs, default_rcode, UNLANG_SUB_FRAME);

	return RLM_MODULE_YIELD;
}

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

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_module_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 */
static void unlang_module_signal(REQUEST *request, fr_state_signal_t action)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_module_t			*sp = unlang_generic_to_module(frame->instruction);

	if (!state->signal) return;

	request->module = sp->module_instance->name;
	state->signal(&(module_ctx_t) { .instance = sp->module_instance->dl_inst->data, .thread = state->thread->data},
		      request, state->rctx, action);
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


/** Return UNLANG_CALCULATE_RESULT only for async async calls
 *
 */
static unlang_action_t unlang_module_resume_final(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

	request->rcode = state->rcode;
	if (state->presult) *state->presult = state->rcode;

	*presult = state->rcode;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Wrapper to call a module's resumption function
 *
 */
static unlang_action_t unlang_module_resume(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	unlang_module_t			*sp = unlang_generic_to_module(frame->instruction);
	char const 			*caller;
	rlm_rcode_t			rcode;
	int				stack_depth = stack->depth;

	fr_assert(state->resume != NULL);

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	caller = request->module;
	request->module = sp->module_instance->name;

	safe_lock(sp->module_instance);
	rcode = request->rcode = state->resume(&(module_ctx_t){
							.instance = sp->module_instance->dl_inst->data,
					       		.thread = state->thread->data
					       }, request, state->rctx);
	safe_unlock(sp->module_instance);
	request->module = caller;

	/*
	 *	It is now marked as "stop" when it wasn't before, we
	 *	must have been blocked.  We do NOT decrement
	 *	"active_callers" if it's already been cancelled in a
	 *	signal.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked", sp->module_instance->module->name);
		if (state->presult) *state->presult = rcode;

		if (state->signal) state->thread->active_callers--;

		*presult = rcode;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	RDEBUG2("%s (%s)", frame->instruction->name ? frame->instruction->name : "",
		fr_table_str_by_value(mod_rcode_table, rcode, "<invalid>"));

	if (rcode == RLM_MODULE_YIELD) {
		if (stack_depth < stack->depth) return UNLANG_ACTION_PUSHED_CHILD;
		fr_assert(stack_depth == stack->depth);
		*presult = rcode;
		return UNLANG_ACTION_YIELD;
	}

	state->thread->active_callers--;

	/*
	 *	The module is done.  But, running it pushed one or
	 *	more asynchronous calls onto the stack.  These need to
	 *	be run before the next module runs.
	 */
	if (stack_depth < stack->depth) {
		state->rcode = rcode;
		repeatable_set(frame);
		frame->interpret = unlang_module_resume_final;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	request->rcode = rcode;
	if (state->presult) *state->presult = rcode;

	*presult = rcode;
	return UNLANG_ACTION_CALCULATE_RESULT;
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
 * @param[in] resume		Called on unlang_interpret_resumable().
 * @param[in] signal		Called on unlang_action().
 * @param[in] rctx		to pass to the callbacks.
 * @return
 *	- RLM_MODULE_YIELD on success.
 *	- RLM_MODULE_FAIL (or asserts) if the current frame is not a module call or
 *	  resume frame.
 */
rlm_rcode_t unlang_module_yield(REQUEST *request,
				fr_unlang_module_resume_t resume, fr_unlang_module_signal_t signal, void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state,
								    unlang_frame_state_module_t);

	REQUEST_VERIFY(request);	/* Check the yielded request is sane */

	state->rctx = rctx;
	state->resume = resume;
	state->signal = signal;

	/*
	 *	We set the repeatable flag here, so that the resume
	 *	function is always called going back up the stack.
	 *	This setting is normally done in the intepreter.
	 *	However, the caller of this function may call us, and
	 *	then push *other* things onto the stack.  Which means
	 *	that the interpreter never gets a chance to set this
	 *	flag.
	 */
	frame->interpret = unlang_module_resume;
	repeatable_set(frame);
	return RLM_MODULE_YIELD;
}

static unlang_action_t unlang_module(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_module_t			*sp;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_module_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);
	int				stack_depth = stack->depth;
	char const 			*caller;
	rlm_rcode_t			rcode;

#ifndef NDEBUG
	int unlang_indent		= request->log.unlang_indent;
#endif

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = unlang_generic_to_module(instruction);
	fr_assert(sp);

	RDEBUG4("[%i] %s - %s (%s)", stack->depth, __FUNCTION__,
		sp->module_instance->name, sp->module_instance->module->name);

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	state->thread = module_thread(sp->module_instance);
	state->presult = NULL;
	fr_assert(state->thread != NULL);

	/*
	 *	Return administratively configured return code
	 */
	if (sp->module_instance->force) {
		rcode = sp->module_instance->code;
		goto done;
	}

	/*
	 *	For logging unresponsive children.
	 */
	state->thread->total_calls++;

	caller = request->module;
	request->module = sp->module_instance->name;
	safe_lock(sp->module_instance);	/* Noop unless instance->mutex set */
	rcode = sp->method(&(module_ctx_t){
				.instance = sp->module_instance->dl_inst->data,
				.thread = state->thread->data
			   }, request);
	safe_unlock(sp->module_instance);
	request->module = caller;

	/*
	 *	It is now marked as "stop" when it wasn't before, we
	 *	must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked", sp->module_instance->module->name);
		if (state->presult) *state->presult = rcode;

		*presult = rcode;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	/*
	 *	Must be left at RDEBUG() level otherwise RDEBUG becomes pointless
	 */
	RDEBUG("%s (%s)", instruction->name ? instruction->name : "",
	       fr_table_str_by_value(mod_rcode_table, rcode, "<invalid>"));


	if (rcode == RLM_MODULE_YIELD) {
		state->thread->active_callers++;
		if (stack_depth < stack->depth) return UNLANG_ACTION_PUSHED_CHILD;
		fr_assert(stack_depth == stack->depth);
		*presult = rcode;
		frame->interpret = unlang_module_resume;
		return UNLANG_ACTION_YIELD;
	}

done:
	fr_assert(unlang_indent == request->log.unlang_indent);
	fr_assert(rcode >= RLM_MODULE_REJECT);
	fr_assert(rcode < RLM_MODULE_NUMCODES);

	/*
	 *	The module is done.  But, running it pushed one or
	 *	more asynchronous calls onto the stack.  These need to
	 *	be run before the next module runs.
	 */
	if (stack_depth < stack->depth) {
		state->rcode = rcode;
		repeatable_set(frame);
		frame->interpret = unlang_module_resume_final;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	request->rcode = rcode;
	if (state->presult) *state->presult = rcode;

	*presult = rcode;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

void unlang_module_init(void)
{
	unlang_register(UNLANG_TYPE_MODULE,
			   &(unlang_op_t){
				.name = "module",
				.interpret = unlang_module,
				.signal = unlang_module_signal,
				.frame_state_size = sizeof(unlang_frame_state_module_t),
				.frame_state_name = "unlang_frame_state_module_t",
			   });
}
