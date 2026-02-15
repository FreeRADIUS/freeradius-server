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
 * @file unlang/parallel.c
 * @brief Implementation of the unlang "parallel" keyword.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */


RCSID("$Id$")

#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/signal.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/table.h>

#include "action.h"
#include "interpret.h"
#include "mod_action.h"
#include "subrequest.h"
#include "interpret_priv.h"
#include "unlang_priv.h"
#include "parallel_priv.h"
#include "child_request_priv.h"

/** Cancel a specific child
 *
 * For most states we just change the current state to CANCELLED. For the RUNNABLE state
 * we need to signal the child to cancel itself.
 *
 * We don't free any requests here, we just mark them up so their rcodes are ignored when
 * the parent is resumed, the parent then frees the child, once we're sure its done being
 * run through the intepreter.
 */
static inline CC_HINT(always_inline) void unlang_parallel_cancel_child(unlang_parallel_state_t *state, unlang_child_request_t *cr)
{
	request_t *child;
	request_t *request;
	unlang_child_request_state_t child_state = cr->state;

	switch (cr->state) {
	case CHILD_INIT:
		cr->state = CHILD_CANCELLED;
		fr_assert(!cr->request);
		return;

	case CHILD_EXITED:
		cr->state = CHILD_CANCELLED;	/* Don't process its return code */
		break;

	case CHILD_RUNNABLE:	/* Don't check runnable_id, may be yielded */
		fr_assert(cr->request);

		/*
		 *	Signal the child to stop
		 *
		 *	The signal function cleans up the request
		 *	and signals anything that was tracking it
		 *	that it's now complete.
		 */

		child = cr->request;

		unlang_interpret_signal(child, FR_SIGNAL_CANCEL);

		/*
		 *	We don't free the request here, we wait
		 *	until it signals us that it's done.
		 */
		break;

	case CHILD_DONE:
		cr->state = CHILD_CANCELLED;
		break;

	case CHILD_DETACHED:	/* Can't signal detached requests*/
		fr_assert(!cr->request);
		return;

	case CHILD_CANCELLED:
		break;

	case CHILD_FREED:
		return;
	}

	request = cr->request->parent;
	RDEBUG3("parallel - child %s (%d/%d) CANCELLED, previously %s",
		cr->name, cr->num, state->num_children,
		fr_table_str_by_value(unlang_child_states_table, child_state, "<INVALID>"));
}

/** Send a signal from parent request to all of it's children
 *
 */
static void unlang_parallel_signal(UNUSED request_t *request,
				   unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_parallel_state_t	*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);
	unsigned int	i;

	/*
	 *	Signal any runnable children to get them to exit
	 */
	if (action == FR_SIGNAL_CANCEL) {
		for (i = 0; i < state->num_children; i++) unlang_parallel_cancel_child(state, &state->children[i]);

		/*
		 *	If we're cancelled, then we fail, just to be safe.
		 */
		state->result = UNLANG_RESULT_RCODE(RLM_MODULE_FAIL);
		return;
	}

	/*
	 *	Signal all of the runnable/running children.
	 */
	for (i = 0; i < state->num_children; i++) {
		if (state->children[i].state != CHILD_RUNNABLE) continue;

		unlang_interpret_signal(state->children[i].request, action);
	}
}


static unlang_action_t unlang_parallel_resume(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_parallel_state_t		*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);
	unsigned int			i;

	fr_assert(state->num_runnable == 0);

	for (i = 0; i < state->num_children; i++) {
		unlang_child_request_t	*cr = &state->children[i];

		if (state->children[i].state != CHILD_EXITED) continue;

		REQUEST_VERIFY(state->children[i].request);

		RDEBUG3("parallel - child %s (%d/%d) DONE",
			state->children[i].name,
			i + 1, state->num_children);

		state->children[i].state = CHILD_DONE;

		/*
		 *	Over-ride "return" and "reject".  A "return"
		 *	in a child of a parallel just stops the child.
		 *	It doesn't stop the parent.
		 */
		if (cr->result.priority == MOD_ACTION_RETURN) {
			cr->result.priority = MOD_ACTION_NOT_SET;

		} else if (cr->result.priority == MOD_ACTION_REJECT) {
			cr->result = UNLANG_RESULT_RCODE(RLM_MODULE_REJECT);

		} else {
			fr_assert(cr->result.priority != MOD_ACTION_RETRY);
			fr_assert(MOD_ACTION_VALID(cr->result.priority));
		}

		/*
		 *	Do priority over-ride.
		 */
		if (cr->result.priority > state->result.priority) {
			RDEBUG4("** [%i] %s - overwriting existing result (%s %s) from higher priority to (%s %s)",
				stack_depth_current(request), __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, state->result.rcode, "<invalid>"),
				mod_action_name[state->result.priority],
				fr_table_str_by_value(mod_rcode_table, cr->result.rcode, "<invalid>"),
				mod_action_name[cr->result.priority]);
			state->result = cr->result;
		}
	}

	/*
	 *	Reap the children....
	 */
	for (i = 0; i < state->num_children; i++) {
		if (!state->children[i].request) continue;

		fr_assert(!unlang_request_is_scheduled(state->children[i].request));

		unlang_subrequest_detach_and_free(&state->children[i].request);

		state->children[i].state = CHILD_FREED;
	}

	*p_result = state->result;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_parallel(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t const			*instruction;
	unlang_group_t			*g;
	unlang_parallel_t		*gext;
	unlang_parallel_state_t		*state;
	int				i;
	size_t				num_children;

	g = unlang_generic_to_group(frame->instruction);

	num_children = unlang_list_num_elements(&g->children);
	if (num_children == 0) RETURN_UNLANG_NOOP;

	gext = unlang_group_to_parallel(g);

	/*
	 *	Allocate an array for the children.
	 */
	MEM(frame->state = state = _talloc_zero_pooled_object(request,
							      sizeof(unlang_parallel_state_t) +
							      (sizeof(state->children[0]) * num_children),
							      "unlang_parallel_state_t",
							      num_children,
							      (talloc_array_length(request->name) * 2)));
	if (!state) {
		return UNLANG_ACTION_FAIL;
	}

	(void) talloc_set_type(state, unlang_parallel_state_t);
	state->result = UNLANG_RESULT_NOT_SET;
	state->detach = gext->detach;
	state->clone = gext->clone;
	state->num_children = unlang_list_num_elements(&g->children);

	/*
	 *	Initialize all of the children.
	 */
	for (i = 0, instruction = unlang_list_head(&g->children);
	     instruction != NULL;
	     i++, instruction = unlang_list_next(&g->children, instruction)) {
		request_t			*child;
		unlang_result_t			*child_result;

		MEM(child = unlang_io_subrequest_alloc(request,
						   request->proto_dict, state->detach));
		child->packet->code = request->packet->code;

		RDEBUG3("parallel - child %s (%d/%d) INIT",
			child->name,
			i + 1, state->num_children);

		if (state->clone) {
			/*
			*	Note that we do NOT copy the
			*	Session-State list!  That
			*	contains state information for
			*	the parent.
			*/
			if ((fr_pair_list_copy(child->request_ctx,
					       &child->request_pairs,
					       &request->request_pairs) < 0) ||
			    (fr_pair_list_copy(child->reply_ctx,
					       &child->reply_pairs,
					       &request->reply_pairs) < 0) ||
			    (fr_pair_list_copy(child->control_ctx,
					       &child->control_pairs,
					       &request->control_pairs) < 0)) {
				REDEBUG("failed copying lists to child");
			error:
				talloc_free(child);

				/*
				 *	Remove all previously
				 *	spawned children.
				 */
				for (--i; i >= 0; i--) {
					unlang_subrequest_detach_and_free(&state->children[i].request);
					state->children[i].state = CHILD_FREED;
				}

				return UNLANG_ACTION_FAIL;
			}
		}

		/*
		 *	Initialise our frame state, and push the first
		 *	instruction onto the child's stack.
		 *
		 *	This instruction will mark the parent as runnable
		 *	when it is executed.
		 *
		 *	We only do this if the requests aren't detached.
		 *	If they are detached, this repeat function would
		 *	be immediately disabled, so no point...
		 */
		if (!state->detach) {
			if (unlang_child_request_init(state, &state->children[i], child, NULL, &state->num_runnable,
						      frame_current(request)->instruction, false) < 0) goto error;
			fr_assert(state->children[i].state == CHILD_INIT);
			child_result = &state->children[i].result;
			state->children[i].result = UNLANG_RESULT_NOT_SET;

		} else {
			state->children[i].num = i;
			state->children[i].request = child;
			child_result = NULL;
		}

		/*
		 *	Push the first instruction for the child to run,
		 *	which in case of parallel, is the child's
		 *	subsection within the parallel block.
		 */
		if (unlang_interpret_push(child_result, child,
					  instruction,
					  FRAME_CONF(RLM_MODULE_NOOP, state->detach ? UNLANG_TOP_FRAME : UNLANG_SUB_FRAME),
					  UNLANG_NEXT_STOP) < 0) {
			unlang_subrequest_detach_and_free(&state->children[i].request);
			state->children[i].state = CHILD_FREED;
			child = NULL;
			goto error;
		}
	}

	/*
	 *	Now we're sure all the children are initialised
	 *	start them running.
	 */
	if (state->detach) {
		for (i = 0; i < (int)state->num_children; i++) {
			if (RDEBUG_ENABLED3) {
				request_t *parent = request;

				request = state->children[i].request;
				RDEBUG3("parallel - child %s (%d/%d) DETACHED",
					request->name,
					i + 1, state->num_children);
				request = parent;
			}

			/*
			 *	Adds to the runnable queue
			 */
			interpret_child_init(state->children[i].request);

			/*
			 *	Converts to a detached request
			 */
			unlang_interpret_signal(state->children[i].request, FR_SIGNAL_DETACH);
		}

		/*
		 *	We are now done, all the children are detached
		 *	so we don't need to wait around for them to complete.
		 */
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	for (i = 0; i < (int)state->num_children; i++) {
		/*
		 *	Ensure we restore the session state information
		 *      into the child.
		 */
		if (state->children[i].config.session_unique_ptr) {
			fr_state_restore_from_parent(state->children[i].request,
						  state->children[i].config.session_unique_ptr,
						  state->children[i].num);
		}

		/*
		 *	Ensures the child is setup correctly and adds
		 *	it into the runnable queue of whatever owns
		 *	the interpreter.
		 */
		interpret_child_init(state->children[i].request);
		state->children[i].state = CHILD_RUNNABLE;
	}

	/*
	 *	Don't call this function again when the parent resumes,
	 *	instead call a function to process the results
	 *	of the children.
	 */
	frame_repeat(frame, unlang_parallel_resume);

	/*
	 *	Yield to the children
	 *
	 *	They scamper off to play on their own when they're all done,
	 *	the last one tells the parent, so it can resume,
	 *	and gather up the results, and mercilessly reap the children.
	 */
	return UNLANG_ACTION_YIELD;
}

static unlang_t *unlang_compile_parallel(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION			*cs = cf_item_to_section(ci);
	unlang_t			*c;
	char const			*name2;

	unlang_group_t			*g;
	unlang_parallel_t		*gext;

	bool				clone = true;
	bool				detach = false;

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	/*
	 *	Parallel sections can create empty child requests, if
	 *	the admin demands it.  Otherwise, the principle of
	 *	least surprise is to copy the whole request, reply,
	 *	and config items.
	 */
	name2 = cf_section_name2(cs);
	if (name2) {
		if (strcmp(name2, "empty") == 0) {
			clone = false;

		} else if (strcmp(name2, "detach") == 0) {
			detach = true;

		} else {
			cf_log_err(cs, "Invalid argument '%s'", name2);
			cf_log_err(ci, DOC_KEYWORD_REF(parallel));
			return NULL;
		}

	}

	/*
	 *	We can do "if" in parallel with other "if", but we
	 *	cannot do "else" in parallel with "if".
	 */
	if (!unlang_compile_limit_subsection(cs, cf_section_name1(cs))) {
		return NULL;
	}

	c = unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_PARALLEL);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_parallel(g);
	gext->clone = clone;
	gext->detach = detach;

	return c;
}

void unlang_parallel_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "parallel",
			.type = UNLANG_TYPE_PARALLEL,	
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET | UNLANG_OP_FLAG_NO_FORCE_UNWIND,

			.compile = unlang_compile_parallel,
			.interpret = unlang_parallel,
			.signal = unlang_parallel_signal,

			.unlang_size = sizeof(unlang_parallel_t),
			.unlang_name = "unlang_parallel_t"
		});
}
