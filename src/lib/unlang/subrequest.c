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
 * @copyright 2006-2019 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/action.h>
#include "unlang_priv.h"
#include "interpret_priv.h"
#include "subrequest_priv.h"
#include "child_request_priv.h"

/** Send a signal from parent request to subrequest
 *
 */
static void unlang_subrequest_signal(UNUSED request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_child_request_t		*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t			*child = talloc_get_type_abort(cr->request, request_t);

	switch (cr->state) {
	case CHILD_DETACHED:
		RDEBUG3("subrequest detached during its execution - Not sending signal to child");
		return;

	case CHILD_CANCELLED:
		RDEBUG3("subrequest is cancelled - Not sending signal to child");
		return;

	default:
		break;
	}

	/*
	 *	Parent should never receive a detach
	 *	signal whilst the child is running.
	 *
	 *	Only the child receives a detach
	 *	signal when the detach keyword is used.
	 */
	fr_assert(action != FR_SIGNAL_DETACH);

	/*
	 *	If the server is stopped, inside a breakpoint,
	 *	whilst processing a child, on resumption both
	 *	requests (parent and child) may need to be
	 *	cancelled as they've both hit max request_time.
	 *
	 *	Sometimes the child will run to completion before
	 *	the cancellation is processed, but the parent
	 *	will still be cancelled.
	 *
	 *	When the parent is cancelled this function is
	 *	executed, which will signal an already stopped
	 *	child to cancel itself.
	 *
	 *	This triggers asserts in the time tracking code.
	 *
	 *	...so we check to see if the child is done before
	 *	sending a signal.
	 */
	if (unlang_request_is_done(child)) return;

	/*
	 *	Forward other signals to the child
	 */
	unlang_interpret_signal(child, action);
}

/** Parent being resumed after a child completes
 *
 */
static unlang_action_t unlang_subrequest_parent_resume(rlm_rcode_t *p_result, request_t *request,
						       unlang_stack_frame_t *frame)
{
	unlang_group_t				*g = unlang_generic_to_group(frame->instruction);
	unlang_child_request_t			*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t				*child = cr->request;
	unlang_subrequest_t			*gext;

	/*
	 *	Child detached
	 */
	if (cr->state == CHILD_DETACHED) {
		RDEBUG3("subrequest detached during its execution - Not updating rcode or reply attributes");

		/*
		 *	If the child detached the subrequest section
		 *	should become entirely transparent, and
		 *	should not update the section rcode.
		 */
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	RDEBUG3("subrequest completeed with rcode %s",
		fr_table_str_by_value(mod_rcode_table, cr->result.rcode, "<invalid>"));

	/*
	 *	FIXME - We should pass in priority
	 */
	*p_result = cr->result.rcode;
	frame->result.priority = cr->result.priority;

	/*
	 *	If there's a no destination tmpl, we're done.
	 */
	if (!child->reply) {
		unlang_subrequest_detach_and_free(&child);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Otherwise... copy reply attributes into the
	 *	specified destination.
	 */
	gext = unlang_group_to_subrequest(g);
	if (gext->dst) {
		fr_pair_t		*vp = NULL;
		tmpl_dcursor_ctx_t	cc;
		fr_dcursor_t		cursor;

		/*
		 *	Use callback to build missing destination container.
		 */
		vp = tmpl_dcursor_build_init(NULL, request, &cc, &cursor, request, gext->dst, tmpl_dcursor_pair_build, NULL);
		if (!vp) {
			RPDEBUG("Discarding subrequest attributes - Failed allocating groups");
			*p_result = RLM_MODULE_FAIL;
			tmpl_dcursor_clear(&cc);
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		MEM(fr_pair_list_copy(vp, &vp->vp_group, &child->reply_pairs) >= 0);

		tmpl_dcursor_clear(&cc);
	}

	unlang_subrequest_detach_and_free(&child);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Allocates a new subrequest and initialises it
 *
 */
static unlang_action_t unlang_subrequest_init(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_child_request_t	*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t		*child;
	fr_pair_t		*vp;

	unlang_group_t		*g;
	unlang_subrequest_t	*gext;

	/*
	 *	This should only be set for manually pushed subrequests
	 */
	fr_assert(!cr->config.free_child);

	/*
	 *	Initialize the state
	 */
	g = unlang_generic_to_group(frame->instruction);
	if (!g->num_children) {
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	gext = unlang_group_to_subrequest(g);
	child = unlang_io_subrequest_alloc(request, gext->dict, UNLANG_DETACHABLE);
	if (!child) {
	fail:
		*p_result = cr->result.rcode = RLM_MODULE_FAIL;
		if (cr->result.p_result) *cr->result.p_result = *p_result;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
	/*
	 *	Set the packet type.
	 */
	MEM(vp = fr_pair_afrom_da(child->request_ctx, gext->attr_packet_type));
	if (gext->type_enum) {
		child->packet->code = vp->vp_uint32 = gext->type_enum->value->vb_uint32;
	} else {
		fr_dict_enum_value_t const	*type_enum;
		fr_pair_t		*attr;

		if (tmpl_find_vp(&attr, request, gext->vpt) < 0) {
			RDEBUG("Failed finding attribute %s", gext->vpt->name);
			goto fail;
		}

		if (tmpl_attr_tail_da(gext->vpt)->type == FR_TYPE_STRING) {
			type_enum = fr_dict_enum_by_name(gext->attr_packet_type, attr->vp_strvalue, attr->vp_length);
			if (!type_enum) {
				RDEBUG("Unknown Packet-Type %pV", &attr->data);
				goto fail;
			}

			child->packet->code = vp->vp_uint32 = type_enum->value->vb_uint32;
		} else {
			fr_value_box_t box;

			fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
			if (fr_value_box_cast(request, &box, FR_TYPE_UINT32, NULL, &attr->data) < 0) {
				RDEBUG("Failed casting value from %pV to data type uint32", &attr->data);
				goto fail;
			}

			/*
			 *	Check that the value is known to the server.
			 *
			 *	If it isn't known, then there's no
			 *	"recv foo" section for it and we can't
			 *	do anything with this packet.
			 */
			type_enum = fr_dict_enum_by_value(gext->attr_packet_type, &box);
			if (!type_enum) {
				RDEBUG("Invalid value %pV for Packet-Type", &box);
				goto fail;
			}

			child->packet->code = vp->vp_uint32 = box.vb_uint32;
		}

	}
	fr_pair_append(&child->request_pairs, vp);

	if ((gext->src) && (tmpl_copy_pair_children(child->request_ctx, &child->request_pairs, request, gext->src) < -1)) {
		RPEDEBUG("Failed copying source attributes into subrequest");
		goto fail;
	}

	/*
	 *	Setup the child so it'll inform us when
	 *	it resumes, or if it detaches.
	 *
	 *	frame->instruction should be consistent
	 *	as it's allocated by the unlang compiler.
	 */
	if (unlang_child_request_init(cr, cr, child, NULL, NULL, frame->instruction, false) < 0) goto fail;

	/*
	 *	Push the first instruction the child's
	 *	going to run.
	 */
	if (unlang_interpret_push(child, g->children,
				  FRAME_CONF(RLM_MODULE_NOT_SET, UNLANG_SUB_FRAME),
				  UNLANG_NEXT_SIBLING) < 0) goto fail;

	/*
	 *	Finally, setup the function that will be
	 *	called when the child indicates the
	 *	parent should be resumed.
	 */
	frame_repeat(frame, unlang_subrequest_parent_resume);

	/*
	 *	This is a common function, either pushed
	 *	onto the parent's stack, or called directly
	 *	from the subrequest instruction..
	 */
	return unlang_subrequest_child_run(p_result, request, frame);	/* returns UNLANG_ACTION_YIELD */
}

/** Free a child request, detaching it from its parent and freeing allocated memory
 *
 * @param[in] child to free.
 */
void unlang_subrequest_detach_and_free(request_t **child)
{
	request_detach(*child);
	talloc_free(*child);
	*child = NULL;
}

/** Allocate a subrequest to run through a virtual server at some point in the future
 *
 * @param[in] parent		to hang sub request off of.
 * @param[in] namespace		the child will operate in.
 * @return
 *	- A new child request.
 *	- NULL on failure.
 */
request_t *unlang_subrequest_alloc(request_t *parent, fr_dict_t const *namespace)
{
	return unlang_io_subrequest_alloc(parent, namespace, UNLANG_NORMAL_CHILD);
}


/** Function to run in the context of the parent on resumption
 *
 * @note Only executes if unlang_subrequest_child_push was called, not with the normal subrequest keyword.
 */
static unlang_action_t unlang_subrequest_child_done(rlm_rcode_t *p_result, UNUSED request_t *request,
						    unlang_stack_frame_t *frame)
{
	unlang_child_request_t		*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);

	if (cr->result.rcode == RLM_MODULE_NOT_SET) {
		*p_result = cr->result.rcode = RLM_MODULE_NOOP;
	}

	if (cr->result.p_result) *cr->result.p_result = cr->result.rcode;
	cr->result.priority = frame->result.priority;

	/*
	 *	We can free the child here as we're its parent
	 */
	if (cr->config.free_child) {
		if (request_is_detachable(cr->request)) {
			unlang_subrequest_detach_and_free(&cr->request);
		} else {
			TALLOC_FREE(cr->request);
		}
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Function called by the unlang interpreter, or manually to start the child running
 *
 * The reason why we do this on the unlang stack is so that _this_ frame
 * is marked as resumable in the parent, not whatever frame was previously
 * being processed by the interpreter when the parent was called.
 *
 * i.e. after calling unlang_subrequest_child_push, the code in the parent
 * can call UNLANG_ACTION_PUSHED_CHILD, which will result in _this_ frame
 * being executed, and _this_ frame can yield.
 *
 * @note Called from the parent to start a child running.
 */
unlang_action_t unlang_subrequest_child_run(UNUSED rlm_rcode_t *p_result, UNUSED request_t *request,
					    unlang_stack_frame_t *frame)
{
	unlang_child_request_t		*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t			*child = cr->request;

	/*
	 *	No parent means this is a pre-detached child
	 *	so the parent should continue executing.
	 */
	if (!child || !child->parent) return UNLANG_ACTION_CALCULATE_RESULT;


	/*
	 *	Ensure we restore the session state information
	 *      into the child.
	 */
	if (cr->config.session_unique_ptr) fr_state_restore_to_child(child,
								     cr->config.session_unique_ptr,
								     cr->num);
	/*
	 *	Ensures the child is setup correctly and adds
	 *	it into the runnable queue of whatever owns
	 *	the interpreter.
	 */
	interpret_child_init(child);

	/*
	 *	This function is being called by something
	 *	other than the subrequest keyword.
	 *
	 *	Set a different resumption function that
	 *	just writes the final rcode out.
	 */
	if (frame->process == unlang_subrequest_child_run) {
		frame_repeat(frame, unlang_subrequest_child_done);
	}

	cr->state = CHILD_RUNNABLE;

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
 * @param[in] p_result			Where to write the result of the subrequest.
 * @param[in] child			to push.
 * @param[in] unique_session_ptr	Unique identifier for child's session data.
 * @param[in] free_child		automatically free the child when it's finished executing.
 *					This is useful if extracting the result from the child is
 *					done using the child's stack, and so the parent never needs
 *					to access it.
 * @param[in] top_frame			Set to UNLANG_TOP_FRAME if the interpreter should return.
 *					Set to UNLANG_SUB_FRAME if the interprer should continue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */

int unlang_subrequest_child_push(request_t *child,
				 rlm_rcode_t *p_result, void const *unique_session_ptr, bool free_child, bool top_frame)
{
	unlang_child_request_t	*cr;
	unlang_stack_frame_t	*frame;

	static unlang_t subrequest_instruction = {
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
		}
	};

	fr_assert_msg(free_child || child->parent, "Child's request pointer must not be NULL when calling subrequest_child_push");

	if (!fr_cond_assert_msg(stack_depth_current(child) == 0,
				"Child stack depth must be 0 (not %d), when calling subrequest_child_push",
				stack_depth_current(child))) return -1;

	/*
	 *	Push a new subrequest frame onto the stack
	 *	of the parent.
	 *
	 *	This allocates memory for the frame state
	 *	which we fill in below.
	 *
	 *	This frame executes once the subrequest has
	 *	completed.
	 */
	if (unlang_interpret_push(child->parent, &subrequest_instruction,
				  FRAME_CONF(RLM_MODULE_NOT_SET, top_frame), UNLANG_NEXT_STOP) < 0) {
		return -1;
	}

	frame = frame_current(child->parent);
	frame->process = unlang_subrequest_child_run;

	/*
	 *	Setup the state for the subrequest
	 */
	cr = talloc_get_type_abort(frame_current(child->parent)->state, unlang_child_request_t);

	/*
	 *	Initialise our frame state, and push the first
	 *	instruction onto the child's stack.
	 *
	 *	This instruction will mark the parent as runnable
	 *	when it executed.
	 */
	if (unlang_child_request_init(cr, cr, child, p_result, NULL, unique_session_ptr, free_child) < 0) return -1;

	return 0;
}

/** Add a child request to the runnable queue
 *
 * @param[in] request		to add to the runnable queue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_subrequest_child_push_and_detach(request_t *request)
{
	/*
	 *	Ensures the child is setup correctly and adds
	 *	it into the runnable queue of whatever owns
	 *	the interpreter.
	 */
	interpret_child_init(request);

	if (request_detach(request) < 0) {
		RPEDEBUG("Failed detaching request");
		return -1;
	}

	return 0;
}

/** Initialise subrequest ops
 *
 */
int unlang_subrequest_op_init(void)
{
	unlang_register(UNLANG_TYPE_SUBREQUEST,
			&(unlang_op_t){
				.name = "subrequest",
				.interpret = unlang_subrequest_init,
				.signal = unlang_subrequest_signal,
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
				.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET | UNLANG_OP_FLAG_NO_FORCE_UNWIND,
				.frame_state_size = sizeof(unlang_child_request_t),
				.frame_state_type = "unlang_child_request_t",
			});

	if (unlang_child_request_op_init() < 0) return -1;

	return 0;
}
