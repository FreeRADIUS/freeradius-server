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
 * @file unlang/child_request.c
 * @brief Common child request management code.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/signal.h>

#include "lib/server/rcode.h"
#include "lib/util/talloc.h"
#include "unlang_priv.h"
#include "child_request_priv.h"

typedef struct {
	unlang_child_request_t *cr;		//!< A pointer to memory in the parent's frame state
						///< allocated for this child to write results to.
} unlang_frame_state_child_request_t;

fr_table_num_ordered_t const unlang_child_states_table[] = {
	{ L("CANCELLED"),		CHILD_CANCELLED	},
	{ L("DETACH"),			CHILD_DETACHED	},
	{ L("DONE"),			CHILD_DONE	},
	{ L("EXITED"),			CHILD_EXITED	},
	{ L("INIT"),			CHILD_INIT	},
	{ L("RUNNABLE"),		CHILD_RUNNABLE	}
};
size_t unlang_child_states_table_len = NUM_ELEMENTS(unlang_child_states_table);

/** Process a detach signal in the child
 *
 * This processes any detach signals the child receives
 * The child doesn't actually do the detaching
 */
static void unlang_child_request_signal(request_t *request, UNUSED unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_child_request_t *state;
	unlang_child_request_t *cr;

	/*
	 *	We're already detached so we don't
	 *	need to notify the parent we're
	 *	waking up, and we don't need to detach
	 *	again...
	 */
	if (request_is_detached(request)) return;

	state = talloc_get_type_abort(frame->state, unlang_frame_state_child_request_t);
	cr = state->cr;	/* Can't use talloc_get_type_abort, may be an array element */

	/*
	 *	Ignore signals which aren't detach, and ar
	 *	and ignore the signal if we have no parent.
	 */
	switch (action) {
	case FR_SIGNAL_DETACH:
		/*
		 *	Place child's state back inside the parent
		 */
		if (cr->config.session_unique_ptr) fr_state_store_in_parent(request,
									    cr->config.session_unique_ptr,
									    cr->num);

		RDEBUG3("Detached - Removing subrequest from parent, and marking parent as runnable");

		/*
		 *	Indicate to the parent there's no longer a child
		 */
		cr->state = CHILD_DETACHED;

		/*
		 *	Don't run the request-done frame, the request will have been
		 *	detached by whatever signalled us, so we can't inform the parent
		 *	when we exit.
		 */
		repeatable_clear(frame);

		/*
		 *	Tell the parent to resume if all the request's siblings are done
		 */
		if (!cr->sibling_count || (--(*cr->sibling_count) == 0)) unlang_interpret_mark_runnable(request->parent);
		break;

	/*
	 *	This frame is not cancellable, so FR_SIGNAL_CANCEL
	 *	does nothing.  If the child is cancelled in its
	 *	entirety, then its stack will unwind up to this point
	 *	and unlang_subrequest_child_done will mark the
	 *	parent as runnable.  We don't need to do anything here.
	 *
	 *	We set the state for debugging purposes, and to reduce
	 *	the amount of work we do in unlang_subrequest_child_done.
	 */
	case FR_SIGNAL_CANCEL:
		cr->state = CHILD_CANCELLED;
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
static unlang_action_t unlang_child_request_done(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_child_request_t *state = talloc_get_type_abort(frame->state, unlang_frame_state_child_request_t);
	unlang_child_request_t *cr = state->cr; /* Can't use talloc_get_type_abort, may be an array element */

	/*
	 *	The repeat function for this frame should've
	 *	been cleared, so this function should not run
	 *	for detached requests.
	 */
	fr_assert(!request_is_detached(request));

	switch (cr->state) {
	case CHILD_RUNNABLE:
		/*
		 *	Place child state back inside the parent
		 */
		if (cr->config.session_unique_ptr) {
			fr_state_store_in_parent(request,
						 cr->config.session_unique_ptr,
						 cr->num);
		}

		/*
		 *	Record the child's result and the last
		 *	priority. For parallel, this lets one
		 *	child be used to control the rcode of
		 *	the parallel keyword.
		 */
		cr->result.rcode = *p_result;
		cr->result.priority = frame->priority;
		if (cr->result.p_result) *(cr->result.p_result) = cr->result.rcode;
		break;

	case CHILD_CANCELLED:
		/*
		 *	Child session state is no longer consistent
		 *	after cancellation, so discard it.
		 */
		if (cr->config.session_unique_ptr) {
			fr_state_discard_child(request->parent, cr->config.session_unique_ptr, cr->num);
		}
		break;

	default:
		fr_assert_msg(0, "child %s resumed top frame with invalid state %s",
			      request->name,
			      fr_table_str_by_value(unlang_child_states_table, cr->state, "<INVALID>"));
	}

	cr->state = CHILD_EXITED;

	/*
	 *	Tell the parent to resume if all the request's siblings are done
	 */
	if (!cr->sibling_count || (--(*cr->sibling_count) == 0)) {
		RDEBUG3("All children have exited, marking parent %s as runnable", request->parent->name);
		unlang_interpret_mark_runnable(request->parent);
	} else {
		RDEBUG3("Child %s exited, %u sibling(s) remaining",
			request->name,
			*cr->sibling_count);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a resumption frame onto a child's stack
 *
 * Push a frame onto the stack of the child to inform the parent when it's complete.
 * An additional frame is pushed onto the child's stack by the 'run' function which
 * executes in the context of the parent.
 *
 * @param[in] cr	state for this child request.  This is a pointer
 *			to a structure in the parent's frame state.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int unlang_child_request_stack_init(unlang_child_request_t *cr)
{
	request_t				*child = cr->request;
	unlang_frame_state_child_request_t	*state;
	unlang_stack_frame_t			*frame;

	static unlang_t inform_parent = {
		.type = UNLANG_TYPE_CHILD_REQUEST,
		.name = "child-request",
		.debug_name = "child-request-resume",
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
		}
	};

	/* Sets up the frame for us to use immediately */
	if (unlikely(unlang_interpret_push_instruction(child, &inform_parent, RLM_MODULE_NOOP, true) < 0)) {
		return -1;
	}

	frame = frame_current(child);
	state = frame->state;
	state->cr = cr;
	repeatable_set(frame);	/* Run this on the way back up */

	return 0;
}

/** Initialize a child request
 *
 * This initializes the child request result and configuration structure,
 * and pushes a resumption frame onto the child's stack.
 *
 * @param[in] ctx			Memory to use for any additional memory allocated
 *					to the unlang_child_request_t.
 * @param[out] out			Child request to initialize.
 * @param[in] child			The child request to initialize.
 * @param[in] p_result			Where to write out the rcode from the child.
 * @param[in,out] sibling_count		If non-null the bumber of siblings.  This is incremented
 *					for each child created.
 * @param[in] unique_session_ptr	Unique session pointer for this child.
 *					If NULL session data won't be stored/restored for the child.
 * @param[in] free_child		Free the child when done?
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_child_request_init(TALLOC_CTX *ctx, unlang_child_request_t *out, request_t *child,
			      rlm_rcode_t *p_result, unsigned int *sibling_count, void const *unique_session_ptr, bool free_child)
{
	*out = (unlang_child_request_t){
		.name = talloc_bstrdup(ctx, child->name),
		.num = sibling_count ? (*sibling_count)++ : 0,
		.request = child,
		.state = CHILD_INIT,
		.sibling_count = sibling_count,
		.config = {
			.session_unique_ptr = unique_session_ptr,
			.free_child = free_child
		},
		.result = {
			.p_result = p_result,
			.rcode = RLM_MODULE_NOT_SET
		}
	};

	return unlang_child_request_stack_init(out);
}

int unlang_child_request_op_init(void)
{
	unlang_register(UNLANG_TYPE_CHILD_REQUEST,
			&(unlang_op_t){
				.name = "child-request",
				.interpret = unlang_child_request_done,
				.signal = unlang_child_request_signal,
				/*
				 *	Frame can't be cancelled, because children need to
				 *	write out status to the parent.  If we don't do this,
				 *	then all children must be detachable and must detach
				 *	so they don't try and write out status to a "done"
				 *	parent.
				 *
				 *	It's easier to allow the child/parent relationship
				 *	to end normally so that non-detachable requests are
				 *	guaranteed the parent still exists.
				 */
				.flag = UNLANG_OP_FLAG_NO_CANCEL,
				.frame_state_size = sizeof(unlang_frame_state_child_request_t),
				.frame_state_type = "unlang_frame_state_child_request_t"
			});

	return 0;
}
