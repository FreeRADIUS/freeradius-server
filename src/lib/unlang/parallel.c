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

#include "function.h"
#include "interpret_priv.h"
#include "module_priv.h"
#include "parallel_priv.h"
#include "subrequest_priv.h"
#include "unlang_priv.h"


/** Cancel a specific child
 *
 */
static inline CC_HINT(always_inline) void unlang_parallel_cancel_child(unlang_parallel_state_t *state, int i)
{
	request_t *child = state->children[i].request;
	request_t *request = child->parent;	/* For debug messages */

	switch (state->children[i].state) {
	case CHILD_INIT:
	case CHILD_EXITED:
		fr_assert(!state->children[i].request);
		state->children[i].state = CHILD_CANCELLED;
		break;

	case CHILD_RUNNABLE:	/* Don't check runnable_id, may be yielded */
		/*
		 *	Signal the child to stop
		 */
		unlang_interpret_signal(child, FR_SIGNAL_CANCEL);

		/*
		 *	Remove it from the runnable heap
		 */
		(void)fr_heap_extract(child->parent->backlog, child);

		/*
		 *	Free it.
		 */
		TALLOC_FREE(state->children[i].request);
		break;

	case CHILD_DONE:
		fr_assert(!fr_heap_entry_inserted(child->runnable_id));

		/*
		 *	Completed children just get freed
		 */
		TALLOC_FREE(state->children[i].request);
		break;

	case CHILD_DETACHED:
	case CHILD_CANCELLED:
		return;
	}

	RDEBUG3("parallel - child %s (%d/%d) CANCELLED",
		state->children[i].name,
		i + 1, state->num_children);
	state->children[i].state = CHILD_CANCELLED;
}

#if 0
/** Cancel all the child's siblings
 *
 * Siblings will be excluded from final result calculation for the parallel section.
 */
static void unlang_parallel_cancel_siblings(request_t *request)
{
	unlang_stack_t		*stack = request->parent->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_parallel_state_t	*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);
	int i;

	for (i = 0; i < state->num_children; i++) {
		if (state->children[i].request == request) continue;	/* Don't cancel this one */

		unlang_parallel_cancel_child(state, i);
	}
}
#endif

/** Signal handler to deal with UNLANG_ACTION_DETACH
 *
 * When a request detaches we need
 */
static void unlang_parallel_child_signal(request_t *request, fr_state_signal_t action, void *uctx)
{
	unlang_parallel_child_t		*child = uctx;
	unlang_stack_frame_t		*frame;
	unlang_parallel_state_t		*state;

	if (action != FR_SIGNAL_DETACH) return;

	frame = unlang_current_frame(request->parent);
	state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);

	RDEBUG3("parallel - child %s (%d/%d) DETACHED",
		request->name,
		child->num + 1, state->num_children);

	child->state = CHILD_DETACHED;
	child->request = NULL;
	state->num_complete++;

	/*
	 *	All children exited, resume the parent
	 */
	if (state->num_complete == state->num_children) {
		RDEBUG3("Signalling parent %s that all children have EXITED or DETACHED", request->parent->name);
		unlang_interpret_mark_runnable(request->parent);
	}

	return;
}

/** When the chld is done, tell the parent that we've exited.
 *
 */
static unlang_action_t unlang_parallel_child_done(UNUSED rlm_rcode_t *p_result, UNUSED int *p_priority, request_t *request, void *uctx)
{
	unlang_parallel_child_t *child = uctx;

	/*
	 *	If we have a parent, then we're running synchronously
	 *	with it.  Tell the parent that we've exited, and it
	 *	can continue.
	 *
	 *	Otherwise we're a detached child, and we don't tell
	 *	the parent anything.  Because we have that kind of
	 *	relationship.
	 *
	 *	Note that we call unlang_interpret_mark_runnable() here
	 *	because unlang_parallel_process() calls
	 *	unlang_interpret(), and NOT child->async->process.
	 */
	if (child->state == CHILD_RUNNABLE) {
		/*
		 *	Reach into the parent to get the unlang_parallel_state_t
		 *      for the whole parallel block.
		 */
		unlang_stack_frame_t		*frame = unlang_current_frame(request->parent);
		unlang_parallel_state_t		*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);

		RDEBUG3("parallel - child %s (%d/%d) EXITED",
			request->name,
			child->num + 1, state->num_children);

		child->state = CHILD_EXITED;
		state->num_complete++;

		/*
		 *	All children exited, resume the parent
		 */
		if (state->num_complete == state->num_children) {
			RDEBUG3("Signalling parent %s that all children have EXITED or DETACHED", request->parent->name);
			unlang_interpret_mark_runnable(request->parent);
		}
	}

	/*
	 *	Don't change frame->result, it's the result of the child.
	 */
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_parallel_resume(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_parallel_state_t		*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);

	int				i, priority;
	rlm_rcode_t			result;

	for (i = 0; i < state->num_children; i++) {
		if (!state->children[i].request) continue;

		fr_assert(state->children[i].state == CHILD_EXITED);
		REQUEST_VERIFY(state->children[i].request);

		RDEBUG3("parallel - child %s (%d/%d) DONE",
			state->children[i].name,
			i + 1, state->num_children);

		state->children[i].state = CHILD_DONE;

		priority = ((unlang_stack_t *)state->children[i].request->stack)->priority;
		result = ((unlang_stack_t *)state->children[i].request->stack)->result;

		/*
		 *	Return isn't allowed to make it back
		 *	to the parent... Not sure this is
		 *      the correct behaviour, but it's what
		 *      was there before.
		 */
		if (priority == MOD_ACTION_RETURN) {
			priority = 0;
		} else if (priority == MOD_ACTION_REJECT) {
			result = RLM_MODULE_REJECT;
			priority = 0;
		}

		/*
		 *	Do priority over-ride.
		 */
		if (priority > state->priority) {
			state->result = result;
			state->priority = priority;

			RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
				unlang_current_depth(request), __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, result, "<invalid>"),
				priority);
		}
	}

	/*
	 *	Reap the children....
	 */
	for (i = 0; i < state->num_children; i++) {
		if (!state->children[i].request) continue;

		fr_assert(!fr_heap_entry_inserted(state->children[i].request->runnable_id));
		TALLOC_FREE(state->children[i].request);
	}

	*p_result = state->result;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Run one or more sub-sections from the parallel section.
 *
 */
static unlang_action_t unlang_parallel_process(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_parallel_state_t		*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);
	request_t			*child;
	int				i;

	/*
	 *	If the children should be created detached, we return
	 *	"noop".  This function then creates the children,
	 *	detaches them, and returns.
	 */
	if (state->detach) {
		state->priority = 0;
		state->result = RLM_MODULE_NOOP;
	}

	/*
	 *	Loop over all the children.
	 *
	 *	We always service the parallel section from top to
	 *	bottom, and we always service all of it.
	 */
	for (i = 0; i < state->num_children; i++) {
		fr_assert(state->children[i].instruction != NULL);
		child = unlang_io_subrequest_alloc(request,
						   request->dict, state->detach);
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
				REDEBUG("failed copying lists to clone");
			error:
				/*
				 *	Detached children which have
				 *	already been created are
				 *	allowed to continue.
				 */
				if (!state->detach) {
					/*
					 *	Remove the current child
					 */
					if (fr_heap_entry_inserted(child->runnable_id)) {
						(void)fr_heap_extract(request->backlog, child);
					}
					talloc_free(child);

					/*
					 *	Remove all previously
					 *	spawned children.
					 */
					for (--i; i >= 0; i--) {
						child = state->children[i].request;
						if (fr_heap_entry_inserted(child->runnable_id)) {
							(void)fr_heap_extract(request->backlog, child);
						}
						talloc_free(child);
					}
				}

				*p_result = RLM_MODULE_FAIL;
				return UNLANG_ACTION_CALCULATE_RESULT;
			}
		}

		/*
		 *	Child starts detached, the parent knows
		 *	and can exit immediately once all
		 *	the children are initialised.
		 */
		if (state->detach) {
			if (RDEBUG_ENABLED3) {
				request_t *parent = request;

				request = child;
				RDEBUG3("parallel - child %s (%d/%d) DETACHED",
					request->name,
					i + 1, state->num_children);
				request = parent;
			}

			state->children[i].state = CHILD_DETACHED;

			/*
			 *	Detach the child, and insert
			 *	it into the backlog.
			 */
			if (unlang_detached_child_init(child) < 0) {
				talloc_free(child);

				*p_result = RLM_MODULE_FAIL;
				return UNLANG_ACTION_CALCULATE_RESULT;
			}
		/*
		 *	If the children don't start detached
		 *	push a function onto the stack to
		 *	notify the parent when the child is
		 *	done.
		 */
		} else {
			unlang_stack_frame_t *child_frame;

			if (unlang_interpret_push_function(child,
		    					   NULL,
		    					   unlang_parallel_child_done,
		    					   unlang_parallel_child_signal,
		    					   UNLANG_TOP_FRAME,
		    					   &state->children[i]) < 0) goto error;
			child_frame = unlang_current_frame(child);
			return_point_set(child_frame);		/* Don't unwind this frame */

			state->children[i].num = i;
			state->children[i].name = talloc_bstrdup(state, child->name);
			state->children[i].request = child;
			state->children[i].state = CHILD_RUNNABLE;
			unlang_interpret_child_init(child);
		}

		/*
		 *	Push the first instruction for
		 *      the child to run.
		 */
		if (unlang_interpret_push(child,
					  state->children[i].instruction, RLM_MODULE_FAIL,
					  UNLANG_NEXT_STOP,
					  state->detach ? UNLANG_TOP_FRAME : UNLANG_SUB_FRAME) < 0) goto error;
	}

	/*
	 *	If all children start detached,
	 *	then we're done.
	 */
	if (state->detach) return UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	Don't call this function again when
	 *      the parent resumes, instead call
	 *	a function to process the results
	 *	of the children.
	 */
	frame->process = unlang_parallel_resume;

	/*
	 *	Yield to the children
	 *
	 *	They scamper off to play on their
	 *	own when they're all done, the last
	 *	one tells the parent, so it can resume,
	 *	and gather up all the results.
	 */
	return UNLANG_ACTION_YIELD;
}

/** Send a signal from parent request to all of it's children
 *
 */
static void unlang_parallel_signal(UNUSED request_t *request,
				   unlang_stack_frame_t *frame, fr_state_signal_t action)
{
	unlang_parallel_state_t	*state = talloc_get_type_abort(frame->state, unlang_parallel_state_t);
	int			i;

	if (action == FR_SIGNAL_CANCEL) {
		for (i = 0; i < state->num_children; i++) unlang_parallel_cancel_child(state, i);

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

static unlang_action_t unlang_parallel(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t const			*instruction;
	unlang_group_t			*g;
	unlang_parallel_t		*gext;
	unlang_parallel_state_t		*state;

	int				i;

	g = unlang_generic_to_group(frame->instruction);
	if (!g->num_children) {
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	gext = unlang_group_to_parallel(g);

	/*
	 *	Allocate an array for the children.
	 */
	MEM(frame->state = state = _talloc_zero_pooled_object(request,
							      sizeof(unlang_parallel_state_t) +
							      (sizeof(state->children[0]) * g->num_children),
							      "unlang_parallel_state_t",
							      g->num_children,
							      (talloc_array_length(request->name) * 2)));
	if (!state) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	};

	(void) talloc_set_type(state, unlang_parallel_state_t);
	state->result = RLM_MODULE_FAIL;
	state->priority = -1;				/* as-yet unset */
	state->detach = gext->detach;
	state->clone = gext->clone;
	state->num_children = g->num_children;

	/*
	 *	Initialize all of the children.
	 */
	for (i = 0, instruction = g->children; instruction != NULL; i++, instruction = instruction->next) {
		state->children[i].state = CHILD_INIT;
		state->children[i].instruction = instruction;
	}

	frame->process = unlang_parallel_process;
	return unlang_parallel_process(p_result, request, frame);
}

void unlang_parallel_init(void)
{
	unlang_register(UNLANG_TYPE_PARALLEL,
			   &(unlang_op_t){
				.name = "parallel",
				.interpret = unlang_parallel,
				.signal = unlang_parallel_signal,
				.debug_braces = true
			   });
}
