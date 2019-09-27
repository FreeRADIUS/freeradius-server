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

#include "unlang_priv.h"
#include "parallel_priv.h"
#include "subrequest_priv.h"
#include "module_priv.h"

/** When the chld is done, tell the parent that we've exited.
 *
 */
static unlang_action_t unlang_parallel_child_done(REQUEST *request, UNUSED rlm_rcode_t *presult, UNUSED int *priority, void *uctx)
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
	 *	Note that we call unlang_interpret_resumable() here
	 *	because unlang_parallel_run() calls
	 *	unlang_interpret_run(), and NOT child->async->process.
	 */
	if (request->parent) {
		child->state = CHILD_EXITED;
		unlang_interpret_resumable(request->parent);
	}

	/*
	 *	Don't change frame->result, it's the result of the child.
	 */

	return UNLANG_ACTION_CALCULATE_RESULT;
}


/** Run one or more sub-sections from the parallel section.
 *
 */
static rlm_rcode_t unlang_parallel_run(REQUEST *request, unlang_parallel_t *state)
{
	int			i, priority;
	rlm_rcode_t		result;
	unlang_parallel_child_state_t done = CHILD_DONE; /* hope that we're done */
	REQUEST			*child;

	/*
	 *	The children are created all detached.  We just return
	 *	"noop".
	 */
	if (state->g->detach) {
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
		switch (state->children[i].state) {
			/*
			 *	Create the child and then run it.
			 */
		case CHILD_INIT:
			RDEBUG3("parallel child %d is INIT", i + 1);
			rad_assert(state->children[i].instruction != NULL);
			child = unlang_io_subrequest_alloc(request,
							   request->dict, state->g->detach);
			child->packet->code = request->packet->code;

			if (state->g->clone) {
				/*
				 *	Note that we do NOT copy the
				 *	Session-State list!  That
				 *	contains state information for
				 *	the parent.
				 */
				if ((fr_pair_list_copy(child->packet,
						       &child->packet->vps,
						       request->packet->vps) < 0) ||
				    (fr_pair_list_copy(child->reply,
						       &child->reply->vps,
						       request->reply->vps) < 0) ||
				    (fr_pair_list_copy(child,
						       &child->control,
						       request->control) < 0)) {
					REDEBUG("failed copying lists to clone");
					for (i = 0; i < state->num_children; i++) TALLOC_FREE(state->children[i].child);
					return RLM_MODULE_FAIL;
				}
			}

			/*
			 *	Push a top frame, followed by a frame
			 *	which signals us that the child is
			 *	done, followed by the instruction to
			 *	run in the child.
			 */
			unlang_interpret_push(child, NULL, RLM_MODULE_NOOP,
					      UNLANG_NEXT_STOP, UNLANG_TOP_FRAME);
			unlang_interpret_push_function(child, NULL, unlang_parallel_child_done,
						       &state->children[i]);
			unlang_interpret_push(child,
					      state->children[i].instruction, RLM_MODULE_FAIL,
					      UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);

			/*
			 *	It is often useful to create detached
			 *	children in parallel.
			 */
			if (state->g->detach) {
				state->children[i].state = CHILD_DONE;
				state->children[i].instruction = NULL;

				rad_assert(request->backlog != NULL);

				/*
				 *	Detach the child, and insert
				 *	it into the backlog.
				 */
				if (unlang_detach(child, &result) == UNLANG_ACTION_CALCULATE_RESULT) {
					talloc_free(child);
					done = CHILD_DONE;
					state->result = RLM_MODULE_FAIL;
					break;
				}

				if (fr_heap_insert(child->backlog, child) < 0) {
					RPERROR("Failed inserting child into backlog");
					talloc_free(child);
					done = CHILD_DONE;
					state->result = RLM_MODULE_FAIL;
					break;
				}

				continue;
			}

			state->children[i].child = child;
			state->children[i].state = CHILD_RUNNABLE;

			/* FALL-THROUGH */

			/*
			 *	Run this entry.
			 */
		case CHILD_RUNNABLE:
		runnable:
			RDEBUG2("parallel - running entry %d/%d", i + 1, state->num_children);

			/*
			 *	Note that we do NOT call child->async-process()
			 *
			 *	Doing that will end up calling
			 *	unlang_parallel_child_done(), and all
			 *	kinds of things happen..
			 */
			result = unlang_interpret_run(state->children[i].child);
			if (result == RLM_MODULE_YIELD) {
				state->children[i].state = CHILD_YIELDED;
				done = CHILD_YIELDED;
				continue;
			}

			RDEBUG3("parallel child %d returns %s", i + 1,
				fr_table_str_by_value(mod_rcode_table, result, "<invalid>"));

			rad_assert(result < NUM_ELEMENTS(state->children[i].instruction->actions));

			/*
			 *	Remember this before we delete the
			 *	reference to 'instruction'.
			 */
			priority = state->children[i].instruction->actions[result];

			/*
			 *	Clean up the state entry.
			 */
			state->children[i].state = CHILD_DONE;
			TALLOC_FREE(state->children[i].child);
			state->children[i].instruction = NULL;

			/*
			 *	return is "stop processing the
			 *	parallel section".
			 */
			if (priority == MOD_ACTION_RETURN) {
				RDEBUG2("child %d/%d says 'return' - skipping the remaining children",
				        i + 1, state->num_children);

				/*
				 *	Fall through to processing the
				 *	priorities and return codes.
				 */
				i = state->num_children;
				priority = 0;
				done = CHILD_DONE;
			}

			/*
			 *	Reject is just reject.
			 */
			if (priority == MOD_ACTION_REJECT) {
				priority = 0;
				result = RLM_MODULE_REJECT;
			}

			/*
			 *	Do priority over-ride.
			 */
			if (priority > state->priority) {
				unlang_stack_t *stack = request->stack;

				state->result = result;
				state->priority = priority;

				RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
					stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, result, "<invalid>"),
					priority);
			}

			/*
			 *	Another child has yielded, so we
			 *	remember the yield instead of the fact
			 *	that we're done.
			 */
			if (done == CHILD_YIELDED) continue;

			rad_assert(done == CHILD_DONE);
			break;

			/*
			 *	Not ready to run.
			 */
		case CHILD_YIELDED:
			if (state->children[i].child->runnable_id >= 0) {
				(void) fr_heap_extract(state->children[i].child->backlog,
						       state->children[i].child);
				goto runnable;
			}

			RDEBUG3("parallel child %d is already YIELDED", i + 1);
			rad_assert(state->children[i].child != NULL);
			rad_assert(state->children[i].instruction != NULL);
			done = CHILD_YIELDED;
			continue;

		case CHILD_EXITED:
			RDEBUG3("parallel child %d has already EXITED", i + 1);
			state->children[i].state = CHILD_DONE;
			state->children[i].child = NULL;		// someone else freed this somewhere
			state->children[i].instruction = NULL;
			/* FALL-THROUGH */

			/*
			 *	Don't need to call this any more.
			 */
		case CHILD_DONE:
			RDEBUG3("parallel child %d is already DONE", i + 1);
			rad_assert(state->children[i].child == NULL);
			rad_assert(state->children[i].instruction == NULL);
			continue;

		}
	}

	/*
	 *	Yield if necessary.
	 */
	if (done == CHILD_YIELDED) {
		return RLM_MODULE_YIELD;
	}

	rad_assert(done == CHILD_DONE);

	/*
	 *	Clean up all of the child requests, because once we
	 *	return, no one can access their data any more.
	 */
	for (i = 0; i < state->num_children; i++) {
		switch (state->children[i].state) {
		case CHILD_RUNNABLE:
			rad_assert(state->children[i].child->backlog == NULL);
			rad_assert(state->children[i].child->runnable_id < 0);

			/*
			 *	Un-detached children are never in the
			 *	runnable queue.
			 */
			/* FALL-THROUGH */

		case CHILD_YIELDED:
			REQUEST_VERIFY(state->children[i].child);
			rad_assert(state->children[i].child->runnable_id < 0);

			/*
			 *	Signal the child that it's going to be
			 *	stopped.  This tells any child modules
			 *	to clean up timers, etc.
			 */
			unlang_interpret_signal(state->children[i].child, FR_SIGNAL_CANCEL);
			TALLOC_FREE(state->children[i].child);
			/* FALL-THROUGH */

		default:
			state->children[i].state = CHILD_DONE;
			state->children[i].child = NULL;
			state->children[i].instruction = NULL;
			break;
		}
	}

	/*
	 *	Return the final result.  The caller will take care of
	 *	free'ing "state".
	 */
	return state->result;
}


/** Send a signal from parent request to all of it's children
 *
 */
static void unlang_parallel_signal(UNUSED REQUEST *request, void *rctx, fr_state_signal_t action)
{
	int			i;
	unlang_parallel_t	*state = talloc_get_type_abort(rctx, unlang_parallel_t);

	/*
	 *	Signal all of the children, if they exist.
	 */
	for (i = 0; i < state->num_children; i++) {
		switch (state->children[i].state) {
		case CHILD_INIT:
		case CHILD_EXITED:
		case CHILD_DONE:
			break;

		case CHILD_RUNNABLE:
		case CHILD_YIELDED:
			rad_assert(state->children[i].child != NULL);
			unlang_interpret_signal(state->children[i].child, action);
			break;
		}
	}
}


static unlang_action_t unlang_parallel_resume(REQUEST *request, rlm_rcode_t *presult, void *rctx)
{
	unlang_parallel_t	*state = talloc_get_type_abort(rctx, unlang_parallel_t);
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];

#ifndef NDEBUG
	unlang_resume_t		*mr;
#endif

	/*
	 *	Continue running the child.
	 */
	*presult = unlang_parallel_run(request, state);
	if (*presult != RLM_MODULE_YIELD) {
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		frame->instruction->type = UNLANG_TYPE_PARALLEL; /* for debug purposes */
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

#ifndef NDEBUG
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	mr = unlang_generic_to_resume(frame->instruction);
	(void) talloc_get_type_abort(mr, unlang_resume_t);

	rad_assert(mr->resume == NULL);
	rad_assert(mr->rctx == state);
#endif

	/*
	 *	If the child yields, our current frame is still an
	 *	unlang_resume_t.
	 */
	return UNLANG_ACTION_YIELD;
}

static unlang_action_t unlang_parallel(REQUEST *request, rlm_rcode_t *presult)
{
	int			i;
	rlm_rcode_t		rcode;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;
	unlang_parallel_t	*state;
	unlang_resume_t		*mr;

	g = unlang_generic_to_group(instruction);

	if (!g->num_children) {
		*presult = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Allocate an array for the children.
	 */
	frame->state = state = talloc_zero_size(request, sizeof(unlang_parallel_t) + sizeof(state->children[0]) * g->num_children);
	if (!state) {
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	};

	(void) talloc_set_type(state, unlang_parallel_t);
	state->result = RLM_MODULE_FAIL;
	state->priority = -1;				/* as-yet unset */
	state->g = g;
	state->num_children = g->num_children;

	/*
	 *	Initialize all of the children.
	 */
	for (i = 0, instruction = g->children; instruction != NULL; i++, instruction = instruction->next) {
		state->children[i].state = CHILD_INIT;
		state->children[i].instruction = instruction;
	}

	/*
	 *	Run the various children.  On the off chance they're
	 *	all done, free things, and return.
	 */
	rcode = unlang_parallel_run(request, state);
	if (rcode != RLM_MODULE_YIELD) {
		*presult = rcode;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Create the "resume" stack frame, and have it replace our stack frame.
	 */
	mr = unlang_interpret_resume_alloc(request, NULL, NULL, state);
	if (!mr) {
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	*presult = RLM_MODULE_YIELD;
	return UNLANG_ACTION_YIELD;
}

void unlang_parallel_init(void)
{
	unlang_register(UNLANG_TYPE_PARALLEL,
			   &(unlang_op_t){
				.name = "parallel",
				.func = unlang_parallel,
				.signal = unlang_parallel_signal,
				.resume = unlang_parallel_resume,
				.debug_braces = true
			   });
}
