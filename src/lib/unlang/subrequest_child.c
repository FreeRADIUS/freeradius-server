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
 * @file unlang/subrequest.c
 * @brief Unlang "subrequest" and "detach" keyword evaluation.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/server/state.h>
#include "interpret_priv.h"
#include "subrequest_child_priv.h"

/** Holds a synthesised instruction that we insert into the parent request
 *
 */
static unlang_subrequest_t	*subrequest_instruction;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t subrequest_dict[];
fr_dict_autoload_t subrequest_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *request_attr_request_lifetime;

extern fr_dict_attr_autoload_t subrequest_dict_attr[];
fr_dict_attr_autoload_t subrequest_dict_attr[] = {
	{ .out = &request_attr_request_lifetime, .name = "Request-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

/** Event handler to free a detached child
 *
 */
static void unlang_detached_max_request_time(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	request_t *request = talloc_get_type_abort(uctx, request_t);

	RDEBUG("Reached Request-Lifetime.  Forcibly stopping request");

	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);	/* Request should now be freed */
}

/** Initialize a detached child
 *
 *  Detach it from the parent, set up it's lifetime, and mark it as
 *  runnable.
 */
int unlang_subrequest_lifetime_set(request_t *request)
{
	fr_pair_t		*vp;

	/*
	 *	Set Request Lifetime
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, request_attr_request_lifetime);
	if (!vp || (vp->vp_uint32 > 0)) {
		fr_time_delta_t when = fr_time_delta_wrap(0);
		const fr_event_timer_t **ev_p;

		if (!vp) {
			when = fr_time_delta_add(when, fr_time_delta_from_sec(30)); /* default to 30s if not set */

		} else if (vp->vp_uint32 > 3600) {
			RWDEBUG("Request-Timeout can be no more than 3600 seconds");
			when = fr_time_delta_add(when, fr_time_delta_from_sec(3600));

		} else if (vp->vp_uint32 < 5) {
			RWDEBUG("Request-Timeout can be no less than 5 seconds");
			when = fr_time_delta_add(when ,fr_time_delta_from_sec(5));

		} else {
			when = fr_time_delta_from_sec(vp->vp_uint32);
		}

		ev_p = talloc_size(request, sizeof(*ev_p));
		memset(ev_p, 0, sizeof(*ev_p));

		if (fr_event_timer_in(request, unlang_interpret_event_list(request), ev_p, when,
				      unlang_detached_max_request_time, request) < 0) {
			talloc_free(ev_p);
			return -1;
		}
	}

	return 0;
}

/** Process a detach signal in the child
 *
 * This processes any detach signals the child receives
 * The child doesn't actually do the detaching
 */
static void unlang_subrequest_child_signal(request_t *request, fr_signal_t action, UNUSED void *uctx)
{
	unlang_frame_state_subrequest_t	*state;

	/*
	 *	We're already detached so we don't
	 *	need to notify the parent we're
	 *	waking up, and we don't need to detach
	 *	again...
	 */
	if (!request->parent) return;

	state = talloc_get_type_abort(frame_current(request->parent)->state, unlang_frame_state_subrequest_t);

	/*
	 *	Ignore signals which aren't detach, and ar
	 *	and ignore the signal if we have no parent.
	 */
	switch (action) {
	case FR_SIGNAL_DETACH:
		/*
		 *	Place child's state back inside the parent
		 */
		if (state->session.enable) fr_state_store_in_parent(request,
								    state->session.unique_ptr,
								    state->session.unique_int);

		if (!fr_cond_assert(unlang_subrequest_lifetime_set(request) == 0)) {
			REDEBUG("Child could not be detached");
			return;
		}
		FALL_THROUGH;

	case FR_SIGNAL_CANCEL:
		RDEBUG3("Removing subrequest from parent, and marking parent as runnable");

		/*
		 *	Indicate to the parent there's no longer a child
		 */
		state->child = NULL;

		/*
		 *	Tell the parent to resume
		 */
		unlang_interpret_mark_runnable(request->parent);
		break;

	default:
		return;
	}
}

/** When the child is done, tell the parent that we've exited.
 *
 * This is pushed as a frame at the top of the child's stack, so when
 * the child is done executing, it runs this to inform the parent
 * that its done.
 */
static unlang_action_t unlang_subrequest_child_done(rlm_rcode_t *p_result,
						    UNUSED int *p_priority, request_t *request, void *uctx)
{
	unlang_frame_state_subrequest_t	*state;

	/*
	 *	Child was detached, nothing more to do.
	 *
	 *	This frame was left on the stack when the child
	 *	detached.  It's normally meant to trigger a
	 *	resume in the parent, but as there is no parent
	 *	it just becomes a noop and gets popped.
	 *
	 *	This is cheaper/less complex then rooting it
	 *	out at detach time and unsetting the repeat
	 *	function.
	 */
	if (!request->parent) return UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	'state' in this context, is the frame state
	 *	in the parent request, so we cannot examine it
	 *	until AFTER we've determined there is still
	 *	a parent, else the memory could've been freed.
	 *
	 *	i.e. don't move the get_type_abort call onto
	 *	the same line as the state variable declaration.
	 */
	state = talloc_get_type_abort(uctx, unlang_frame_state_subrequest_t);

	/*
	 *	Place child state back inside the parent
	 */
	if (state->session.enable) fr_state_store_in_parent(request,
							    state->session.unique_ptr,
							    state->session.unique_int);
	/*
	 *	Record the child's result
	 */
	if (state->p_result) *state->p_result = *p_result;

	/*
	 *	Resume the parent
	 */
	unlang_interpret_mark_runnable(request->parent);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a resumption frame onto a child's stack
 *
 * This is necessary so that the child informs its parent when it's done/detached
 * and so that the child responds to detach signals.
 */
int unlang_subrequest_child_push_resume(request_t *child, unlang_frame_state_subrequest_t *state)
{
	/*
	 *	Push a resume frame into the child
	 */
	if (unlang_function_push(child, NULL,
				 unlang_subrequest_child_done,
				 unlang_subrequest_child_signal,
				 ~(FR_SIGNAL_DETACH | FR_SIGNAL_CANCEL),
				 UNLANG_TOP_FRAME,
				 state) < 0) return -1;

	return_point_set(frame_current(child));	/* Stop return going through the resumption frame */

	return 0;
}

/** Function to run in the context of the parent on resumption
 *
 */
static unlang_action_t unlang_subrequest_calculate_result(rlm_rcode_t *p_result, UNUSED request_t *request,
							  unlang_stack_frame_t *frame)
{
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);

	if (*p_result == RLM_MODULE_NOT_SET) *p_result = RLM_MODULE_NOOP;

	if (state->free_child) unlang_subrequest_detach_and_free(&state->child);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Function called by the unlang interpreter to start the child running
 *
 * The reason why we do this on the unlang stack is so that _this_ frame
 * is marked as resumable in the parent, not whatever frame was previously
 * being processed by the interpreter when the parent was called.
 *
 * i.e. after calling unlang_subrequest_child_push, the code in the parent
 * can call UNLANG_ACTION_PUSHED_CHILD, which will result in _this_ frame
 * being executed, and _this_ frame can yield.
 */
unlang_action_t unlang_subrequest_child_run(UNUSED rlm_rcode_t *p_result, UNUSED request_t *request,
					    unlang_stack_frame_t *frame)
{
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	request_t			*child = state->child;

	/*
	 *	No parent means this is a pre-detached child
	 *	so the parent should continue executing.
	 */
	if (!child || !child->parent) return UNLANG_ACTION_CALCULATE_RESULT;


	/*
	 *	Ensure we restore the session state information
	 *      into the child.
	 */
	if (state->session.enable) fr_state_restore_to_child(child,
							     state->session.unique_ptr,
							     state->session.unique_int);
	/*
	 *	Ensures the child is setup correctly and adds
	 *	it into the runnable queue of whatever owns
	 *	the interpreter.
	 */
	interpret_child_init(child);

	/*
	 *	Don't run this function again on resumption
	 */
	if (frame->process == unlang_subrequest_child_run) frame->process = unlang_subrequest_calculate_result;
	repeatable_set(frame);

	return UNLANG_ACTION_YIELD;
}

/** Push a pre-existing child back onto the stack as a subrequest
 *
 * The child *MUST* have been allocated with unlang_io_subrequest_alloc, or something
 * that calls it.
 *
 * After the child is no longer required it *MUST* be freed with #unlang_subrequest_detach_and_free.
 * It's not enough to free it with talloc_free.
 *
 * This function should be called _before_ pushing any additional frames onto the child's
 * stack for it to execute.
 *
 * The parent should return UNLANG_ACTION_PUSHED_CHILD, when it's done setting up the
 * child request.  It should NOT return UNLANG_ACTION_YIELD.
 *
 * @param[in] out		Where to write the result of the subrequest.
 * @param[in] child		to push.
 * @param[in] session		control values.  Whether we restore/store session info.
 * @param[in] free_child	automatically free the child when it's finished executing.
 *				This is useful if extracting the result from the child is
 *				done using the child's stack, and so the parent never needs
 *				to access it.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_subrequest_child_push(rlm_rcode_t *out, request_t *child,
				 unlang_subrequest_session_t const *session,
				 bool free_child, bool top_frame)
{
	unlang_frame_state_subrequest_t	*state;
	unlang_stack_frame_t		*frame;

	/*
	 *	Push a new subrequest frame onto the stack
	 *
	 *	This allocates memory for the frame state
	 *	which we fill in below.
	 */
	if (unlang_interpret_push(child->parent, &subrequest_instruction->group.self,
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, top_frame) < 0) {
		return -1;
	}

	frame = frame_current(child->parent);
	frame->process = unlang_subrequest_child_run;

	/*
	 *	Setup the state for the subrequest
	 */
	state = talloc_get_type_abort(frame_current(child->parent)->state, unlang_frame_state_subrequest_t);
	state->p_result = out;
	state->child = child;
	state->session = *session;
	state->free_child = free_child;

	if (!fr_cond_assert_msg(stack_depth_current(child) == 0,
				"Child stack depth must be 0 (not %d), when subrequest_child_push is called",
				stack_depth_current(child))) return -1;

	/*
	 *	Push a resumption frame onto the stack
	 *	so the child calls its parent when it's
	 *	complete.
	 */
	if (unlang_subrequest_child_push_resume(child, state) < 0) return -1;

	return 0;
}

int unlang_subrequest_child_push_and_detach(request_t *request)
{
	/*
	 *	Ensures the child is setup correctly and adds
	 *	it into the runnable queue of whatever owns
	 *	the interpreter.
	 */
	interpret_child_init(request);

	if ((unlang_subrequest_lifetime_set(request) < 0) || (request_detach(request) < 0)) {
		RPEDEBUG("Failed detaching request");
		return -1;
	}

	return 0;
}

int unlang_subrequest_child_op_init(void)
{
	if (fr_dict_autoload(subrequest_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(subrequest_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}

	/*
	 *	Needs to be dynamically allocated
	 *	so that talloc_get_type works
	 *	correctly.
	 */
	MEM(subrequest_instruction = talloc(NULL, unlang_subrequest_t));
	*subrequest_instruction = (unlang_subrequest_t){
		.group = {
			.self = {
				.type = UNLANG_TYPE_SUBREQUEST,
				.name = "subrequest",
				.debug_name = "subrequest",
				.actions = {
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
					.retry = RETRY_INIT,
				},
			}
		}
	};

	return 0;
}

void unlang_subrequest_child_op_free(void)
{
	fr_dict_autofree(subrequest_dict);
	talloc_free(subrequest_instruction);
}
