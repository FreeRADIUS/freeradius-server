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
 * @file unlang/xlat.c
 * @brief Integration between the unlang interpreter and xlats
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include "unlang_priv.h"	/* Fixme - Should create a proper semi-public interface for the interpret */

/** Hold the result of an inline xlat expansion
 *
 */
typedef struct {
	fr_value_box_t		*result;			//!< Where to store the result of the
								///< xlat expansion. This is usually discarded.
} unlang_frame_state_xlat_inline_t;

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
	bool			alternate;			//!< record which alternate branch we
								///< previously took.
	xlat_func_resume_t	resume;				//!< called on resume
	xlat_func_signal_t	signal;				//!< called on signal
	void			*rctx;				//!< for resume / signal
} unlang_frame_state_xlat_t;

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct {
	REQUEST				*request;			//!< Request this event pertains to.
	int				fd;				//!< File descriptor to wait on.
	fr_unlang_xlat_timeout_t	timeout;			//!< Function to call on timeout.
	fr_unlang_xlat_fd_event_t	fd_read;			//!< Function to call when FD is readable.
	fr_unlang_xlat_fd_event_t	fd_write;			//!< Function to call when FD is writable.
	fr_unlang_xlat_fd_event_t	fd_error;			//!< Function to call when FD has errored.
	void const			*inst;				//!< Module instance to pass to callbacks.
	void				*thread;			//!< Thread specific xlat instance.
	void const			*ctx;				//!< ctx data to pass to callbacks.
	fr_event_timer_t const		*ev;				//!< Event in this worker's event heap.
} unlang_xlat_event_t;


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
		[RLM_MODULE_DISALLOW]	= 0,
		[RLM_MODULE_NOTFOUND]	= 0,
		[RLM_MODULE_NOOP]	= 0,
		[RLM_MODULE_UPDATED]	= 0
	},
};

/** Frees an unlang event, removing it from the request's event loop
 *
 * @param[in] ev	The event to free.
 *
 * @return 0
 */
static int _unlang_xlat_event_free(unlang_xlat_event_t *ev)
{
	if (ev->ev) {
		(void) fr_event_timer_delete(&(ev->ev));
		return 0;
	}

	if (ev->fd >= 0) {
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
static void unlang_xlat_event_timeout_handler(UNUSED fr_event_list_t *el, fr_time_t now, void *ctx)
{
	unlang_xlat_event_t *ev = talloc_get_type_abort(ctx, unlang_xlat_event_t);

	void *mutable_ctx;
	void *mutable_inst;

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->timeout(ev->request, mutable_inst, ev->thread, mutable_ctx, now);

	/* Remove old references from the request */
	if (!fr_cond_assert(request_data_get(ev->request, ev->ctx, -1) == ev)) return;
	talloc_free(ev);
}

int unlang_xlat_event_timeout_add(REQUEST *request, fr_unlang_xlat_timeout_t callback,
				  void const *ctx, fr_time_t when)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_xlat_event_t		*ev;
	unlang_frame_state_xlat_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_xlat_t);

	rad_assert(stack->depth > 0);
	rad_assert(frame->instruction->type == UNLANG_TYPE_XLAT);

	ev = talloc_zero(request, unlang_xlat_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout = callback;
	ev->inst = state->exp->inst;
	ev->thread = xlat_thread_instance_find(state->exp);
	ev->ctx = ctx;

	if (fr_event_timer_at(request, request->el, &ev->ev, when, unlang_xlat_event_timeout_handler, ev) < 0) {
		RPEDEBUG("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	(void) request_data_talloc_add(request, ctx, -1, unlang_xlat_event_t, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_xlat_event_free);

	return 0;
}

/** Remove a pending timer
 *
 * @param[in] request	The current request.
 * @param[in] ctx	that was provided to #unlang_xlat_event_timeout_add.
 * @return
 *	- 0 if there was a pending timer and it was removed.
 *      - -1 if there was no pending timer.
 */
int unlang_xlat_event_timeout_delete(REQUEST *request, void *ctx)
{
	unlang_xlat_event_t *xev = request_data_get(request, ctx, -1);

	if (xev) {
		talloc_free(xev);
		return 0;
	}

	return -1;
}

/** Push a pre-compiled xlat onto the stack for evaluation
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		to push xlat onto.
 * @param[in] exp		node to evaluate.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 */
void unlang_xlat_push(TALLOC_CTX *ctx, fr_value_box_t **out,
		      REQUEST *request, xlat_exp_t const *exp, bool top_frame)
{

	unlang_frame_state_xlat_t	*state;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;

	/*
	 *	Push a new xlat eval frame onto the stack
	 */
	unlang_interpret_push(request, &xlat_instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, top_frame);
	frame = &stack->frame[stack->depth];

	/*
	 *	Allocate its state, and setup a cursor for the xlat nodes
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_xlat_t));
	state->exp = talloc_get_type_abort_const(exp, xlat_exp_t);	/* Ensure the node is valid */

	fr_cursor_talloc_init(&state->values, out, fr_value_box_t);

	state->ctx = ctx;
}

/** Stub function for calling the xlat interpreter
 *
 * Calls the xlat interpreter and translates its wants and needs into
 * unlang_action_t codes.
 */
static unlang_action_t unlang_xlat(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_xlat_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_xlat_t);
	xlat_exp_t const		*child = NULL;
	xlat_action_t			xa;
	fr_value_box_t			*box;

	if (is_repeatable(frame)) {
		xa = xlat_frame_eval_repeat(state->ctx, &state->values, &child,
					    &state->alternate, request, &state->exp, &state->rhead);
	} else {
		xa = xlat_frame_eval(state->ctx, &state->values, &child, request, &state->exp);
	}

	switch (xa) {
	case XLAT_ACTION_PUSH_CHILD:
		rad_assert(child);

		repeatable_set(frame);

		/*
		 *	Clear out the results of any previous expansions
		 *	at this level.  A frame may be used to evaluate
		 *	multiple sibling nodes.
		 */
		talloc_list_free(&state->rhead);
		unlang_xlat_push(state->ctx, &state->rhead, request, child, false);
		return UNLANG_ACTION_PUSHED_CHILD;

	case XLAT_ACTION_PUSH_CHILD_GROUP:
		rad_assert(child);

		repeatable_set(frame);

		/*
		 *	Clear out the results of any previous expansions
		 *	at this level.  A frame may be used to evaluate
		 *	multiple sibling nodes.
		 */
		talloc_list_free(&state->rhead);

		/*
		 *	The called function can't pass us a value box,
		 *	so we have to create it ourselves.
		 */
		box = fr_value_box_alloc(state->ctx, FR_TYPE_GROUP, NULL, false);
		fr_cursor_append(&state->values, box);

		unlang_xlat_push(state->ctx, &box->vb_group, request, child, false);
		return UNLANG_ACTION_PUSHED_CHILD;

	case XLAT_ACTION_YIELD:
		if (!state->resume) {
			RWDEBUG("Missing call to unlang_xlat_yield()");
			goto fail;
		}
		return UNLANG_ACTION_YIELD;

	case XLAT_ACTION_DONE:
		*presult = RLM_MODULE_OK;
		return UNLANG_ACTION_CALCULATE_RESULT;

	case XLAT_ACTION_FAIL:
		fail:
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	rad_assert(0);
	*presult = RLM_MODULE_FAIL;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Send a signal (usually stop) to a request that's running an xlat expansions
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #xlat_func_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] action		What the request should do (the type of signal).
 */
static void unlang_xlat_signal(REQUEST *request, fr_state_signal_t action)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_xlat_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_xlat_t);

	if (!state->signal) return;

	xlat_signal(state->signal, state->exp, request, state->rctx, action);
}

/** Called when we're ready to resume processing the request
 *
 * @param[in] request	to resume processing.
 * @param[in] presult	the result of the xlat function.
 *			  - RLM_MODULE_OK on success.
 *			  - RLM_MODULE_FAIL on failure.
 *			  - RLM_MODULE_YIELD if additional asynchronous
 *			    operations need to be performed.
 * @return
 *	- UNLANG_ACTION_YIELD	if yielding.
 *	- UNLANG_ACTION_CALCULATE_RESULT if done.
 */
static unlang_action_t unlang_xlat_resume(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_xlat_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_xlat_t);
	xlat_action_t			xa;

	rad_assert(state->resume != NULL);

	xa = xlat_frame_eval_resume(state->ctx, &state->values,
				    state->resume, state->exp,
				    request, &state->rhead, state->rctx);
	switch (xa) {
	case XLAT_ACTION_YIELD:
		return UNLANG_ACTION_YIELD;

	case XLAT_ACTION_DONE:
		*presult = RLM_MODULE_OK;
		return UNLANG_ACTION_CALCULATE_RESULT;

	case XLAT_ACTION_PUSH_CHILD:
	case XLAT_ACTION_PUSH_CHILD_GROUP:
		rad_assert(0);
		/* FALL-THROUGH */

	case XLAT_ACTION_FAIL:
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	/* DON'T SET DEFAULT */
	}

	rad_assert(0);		/* Garbage xlat action */

	*presult = RLM_MODULE_FAIL;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Yield a request back to the interpreter from within a module
 *
 * This passes control of the request back to the unlang interpreter, setting
 * callbacks to execute when the request is 'signalled' asynchronously, or whatever
 * timer or I/O event the module was waiting for occurs.
 *
 * @note The module function which calls #unlang_module_yield should return control
 *	of the C stack to the unlang interpreter immediately after calling #unlang_xlat_yield.
 *	A common pattern is to use ``return unlang_xlat_yield(...)``.
 *
 * @param[in] request		The current request.
 * @param[in] resume		Called on unlang_interpret_resumable().
 * @param[in] signal		Called on unlang_action().
 * @param[in] rctx		to pass to the callbacks.
 * @return always returns RLM_MODULE_YIELD.
 */
xlat_action_t unlang_xlat_yield(REQUEST *request,
				xlat_func_resume_t resume, xlat_func_signal_t signal,
				void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_xlat_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_xlat_t);

	frame->interpret = unlang_xlat_resume;

	/*
	 *	Over-ride whatever functions were there before.
	 */
	state->resume = resume;
	state->signal =signal;
	state->rctx = rctx;

	return XLAT_ACTION_YIELD;
}

/** Evaluates "naked" xlats in the config
 *
 */
static unlang_action_t unlang_xlat_inline(REQUEST *request, UNUSED rlm_rcode_t *presult)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_xlat_inline_t	*mx = unlang_generic_to_xlat_inline(instruction);

	if (!mx->exec) {
		TALLOC_CTX *pool;
		unlang_frame_state_xlat_inline_t *state;

		MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_xlat_inline_t));
		MEM(pool = talloc_pool(frame->state, 1024));	/* Pool to absorb some allocs */

		unlang_xlat_push(pool, &state->result, request, mx->exp, false);
		return UNLANG_ACTION_PUSHED_CHILD;
	} else {
		RDEBUG2("`%s`", mx->xlat_name);
		radius_exec_program(request, NULL, 0, NULL, request, mx->xlat_name, request->packet->vps,
				    false, true, fr_time_delta_from_sec(EXEC_TIMEOUT));
		return UNLANG_ACTION_EXECUTE_NEXT;
	}
}

/** Register xlat operation with the interpreter
 *
 */
void unlang_xlat_init(void)
{
	unlang_register(UNLANG_TYPE_XLAT,
			   &(unlang_op_t){
				.name = "xlat_eval",
				.interpret = unlang_xlat,
				.signal = unlang_xlat_signal,
				.debug_braces = false,
				.frame_state_size = sizeof(unlang_frame_state_xlat_t),
				.frame_state_name = "unlang_frame_state_xlat_t",
			   });


	unlang_register(UNLANG_TYPE_XLAT_INLINE,
			   &(unlang_op_t){
				.name = "xlat_inline",
				.interpret = unlang_xlat_inline,
				.debug_braces = false
			   });
}
