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
 * @file unlang/interpret.c
 * @brief Execute compiled unlang structures using an iterative interpret.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/unlang/xlat.h>

#include "interpret_priv.h"
#include "module_priv.h"
#include "parallel_priv.h"
#include "unlang_priv.h"

/** The default interpreter instance for this thread
 */
static _Thread_local unlang_interpret_t *intp_thread_default;

static fr_table_num_ordered_t const unlang_action_table[] = {
	{ L("unwind"), 			UNLANG_ACTION_UNWIND },
	{ L("calculate-result"),	UNLANG_ACTION_CALCULATE_RESULT },
	{ L("next"),			UNLANG_ACTION_EXECUTE_NEXT },
	{ L("pushed-child"),		UNLANG_ACTION_PUSHED_CHILD },
	{ L("stop"),			UNLANG_ACTION_STOP_PROCESSING },
	{ L("yield"),			UNLANG_ACTION_YIELD }
};
static size_t unlang_action_table_len = NUM_ELEMENTS(unlang_action_table);

static fr_table_num_ordered_t const unlang_frame_action_table[] = {
	{ L("pop"), 			UNLANG_FRAME_ACTION_POP		},
	{ L("next"),			UNLANG_FRAME_ACTION_NEXT	},
	{ L("yield"),			UNLANG_FRAME_ACTION_YIELD	}
};
static size_t unlang_frame_action_table_len = NUM_ELEMENTS(unlang_frame_action_table);

#ifndef NDEBUG
static void instruction_dump(request_t *request, unlang_t const *instruction)
{
	RINDENT();
	if (!instruction) {
		RDEBUG2("instruction    <none>");
		REXDENT();
		return;
	}

	RDEBUG2("type           %s", unlang_ops[instruction->type].name);
	RDEBUG2("name           %s", instruction->name);
	RDEBUG2("debug_name     %s", instruction->debug_name);
	REXDENT();
}

static void frame_dump(request_t *request, unlang_stack_frame_t *frame)
{
	unlang_op_t	*op = NULL;

	if (frame->instruction) op = &unlang_ops[frame->instruction->type];

	instruction_dump(request, frame->instruction);

	RINDENT();
	if (frame->state) RDEBUG2("state          %s (%p)", talloc_get_name(frame->state), frame->state);
	if (frame->next) {
		RDEBUG2("next           %s", frame->next->debug_name);
	} else {
		RDEBUG2("next           <none>");
	}
	RDEBUG2("result         %s", fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"));
	RDEBUG2("priority       %d", frame->priority);
	RDEBUG2("top_frame      %s", is_top_frame(frame) ? "yes" : "no");
	RDEBUG2("repeat         %s", is_repeatable(frame) ? "yes" : "no");
	RDEBUG2("break_point    %s", is_break_point(frame) ? "yes" : "no");
	RDEBUG2("return_point   %s", is_return_point(frame) ? "yes" : "no");
	RDEBUG2("resumable      %s", is_yielded(frame) ? "yes" : "no");

	/*
	 *	Call the custom frame dump function
	 */
	if (op && op->dump) op->dump(request, frame);

	REXDENT();
}

static void stack_dump(request_t *request)
{
	int i;
	unlang_stack_t *stack = request->stack;

	RDEBUG2("----- Begin stack debug [depth %i, unwind %i] -----", stack->depth, stack->unwind);
	for (i = stack->depth; i >= 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];

		RDEBUG2("[%d] Frame contents", i);
		frame_dump(request, frame);
	}

	RDEBUG2("----- End stack debug [depth %i, unwind %i] -------", stack->depth, stack->unwind);
}
#define DUMP_STACK if (DEBUG_ENABLED5) stack_dump(request)
#else
#define DUMP_STACK
#endif

/** Push a new frame onto the stack
 *
 * @param[in] request		to push the frame onto.
 * @param[in] instruction	One or more unlang_t nodes describing the operations to execute.
 * @param[in] default_rcode	The default result.
 * @param[in] do_next_sibling	Whether to only execute the first node in the #unlang_t program
 *				or to execute subsequent nodes.
 * @param[in] top_frame		Return out of the unlang interpret when popping this frame.
 *				Hands execution back to whatever called the interpret.
 * @return
 *	- 0 on success.
 *	- -1 on call stack too deep.
 */
int unlang_interpret_push(request_t *request, unlang_t const *instruction,
			  rlm_rcode_t default_rcode, bool do_next_sibling, bool top_frame)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame;

	fr_assert(instruction || top_frame);

#ifndef NDEBUG
	if (DEBUG_ENABLED5) RDEBUG3("unlang_interpret_push called with instruction type \"%s\" - args %s %s",
				    instruction ? instruction->debug_name : "<none>",
				    do_next_sibling ? "UNLANG_NEXT_SIBLING" : "UNLANG_NEXT_STOP",
				    top_frame ? "UNLANG_TOP_FRAME" : "UNLANG_SUB_FRAME");
#endif

	/*
	 *	This is not a cancellation point.
	 *
	 *	If we cancel here bad things happen inside the interpret.
	 */
	if (stack->depth >= (UNLANG_STACK_MAX - 1)) {
		RERROR("Call stack is too deep");
		return - 1;
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	frame = &stack->frame[stack->depth];
	memset(frame, 0, sizeof(*frame));

	frame->instruction = instruction;

	if (do_next_sibling) {
		fr_assert(instruction != NULL);
		frame->next = instruction->next;
	}
	/* else frame->next MUST be NULL */

	frame->uflags = UNWIND_FLAG_NONE;
	if (top_frame) top_frame_set(frame);

	frame->result = default_rcode;
	frame->priority = -1;

	if (!instruction) return 0;

	frame_state_init(stack, frame);

	return 0;
}

static void instruction_timeout_handler(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx);

/** Update the current result after each instruction, and after popping each stack frame
 *
 * @param[in] request		The current request.
 * @param[in] frame		The curren stack frame.
 * @param[in,out] result	The current section result.
 * @param[in,out] priority	The current section priority.
 * @return
 *	- UNLANG_FRAME_ACTION_NEXT	evaluate more instructions.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline CC_HINT(always_inline)
unlang_frame_action_t result_calculate(request_t *request, unlang_stack_frame_t *frame,
				       rlm_rcode_t *result, int *priority)
{
	unlang_t const	*instruction = frame->instruction;
	unlang_stack_t	*stack = request->stack;

	RDEBUG4("** [%i] %s - have (%s %d) module returned (%s %d)",
		stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority,
		fr_table_str_by_value(mod_rcode_table, *result, "<invalid>"),
		*priority);

	/*
	 *	Don't set action or priority if we don't have one.
	 */
	if (*result == RLM_MODULE_NOT_SET) return UNLANG_FRAME_ACTION_NEXT;

	/*
	 *	The child's action says return.  Do so.
	 */
	if (instruction->actions.actions[*result] == MOD_ACTION_RETURN) {
		if (*priority < 0) *priority = 0;

		RDEBUG4("** [%i] %s - action says to return with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, *result, "<invalid>"),
			*priority);
		frame->result = *result;
		frame->priority = *priority;
		return UNLANG_FRAME_ACTION_POP;
	}

	/*
	 *	If "reject", break out of the loop and return
	 *	reject.
	 */
	if (instruction->actions.actions[*result] == MOD_ACTION_REJECT) {
		if (*priority < 0) *priority = 0;

		RDEBUG4("** [%i] %s - action says to return with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, RLM_MODULE_REJECT, "<invalid>"),
			*priority);
		frame->result = RLM_MODULE_REJECT;
		frame->priority = *priority;
		return UNLANG_FRAME_ACTION_POP;
	}

	/*
	 *	The instruction says it should be retried from the beginning.
	 */
	if (instruction->actions.actions[*result] == MOD_ACTION_RETRY) {
		unlang_retry_t *retry = frame->retry;

		RDEBUG4("** [%i] %s - action says to retry with",
			stack->depth, __FUNCTION__);

		if (*priority < 0) *priority = 0;

		/*
		 *	If this is the first time doing the retry,
		 *	then allocate the structure and set the timer.
		 */
		if (!retry) {
			frame->retry = retry = talloc_zero(stack, unlang_retry_t);
			if (!frame->retry) goto fail;

			retry->request = request;
			retry->depth = stack->depth;
			retry->state = FR_RETRY_CONTINUE;
			retry->count = 1;

			/*
			 *	Set a timer which automatically fires
			 *	if there's a timeout.  And parent it
			 *	from the retry structure, so that the
			 *	timer is automatically freed when the
			 *	frame is cleaned up.
			 */
			if (fr_time_delta_ispos(instruction->actions.retry.mrd)) {
				retry->timeout = fr_time_add(fr_time(), instruction->actions.retry.mrd);

				if (fr_event_timer_at(retry, unlang_interpret_event_list(request), &retry->ev, retry->timeout,
						      instruction_timeout_handler, request) < 0) {
					RPEDEBUG("Failed inserting event");
					goto fail;
				}
			}

		} else {
			/*
			 *	We've been told to stop doing retries,
			 *	probably from a timeout.
			 */
			if (retry->state != FR_RETRY_CONTINUE) goto fail;

			/*
			 *	Clamp it at the maximum count.
			 */
			if (instruction->actions.retry.mrc > 0) {
				retry->count++;

				if (retry->count >= instruction->actions.retry.mrc) {
					retry->state = FR_RETRY_MRC;

					REDEBUG("Retries hit max_rtx_count (%d) - returning 'fail'", instruction->actions.retry.mrc);

				fail:
					*result = RLM_MODULE_FAIL;
					goto finalize;
				}
			}
		}

		RINDENT();
		if (instruction->actions.retry.mrc) {
			RDEBUG("... retrying (%d/%d)", retry->count, instruction->actions.retry.mrc);
		} else {
			RDEBUG("... retrying");
		}
		REXDENT();

		talloc_free(frame->state);
		frame_state_init(stack, frame);
		return UNLANG_FRAME_ACTION_RETRY;
	}

finalize:
	/*
	 *	The array holds a default priority for this return
	 *	code.  Grab it in preference to any unset priority.
	 */
	if (*priority < 0) {
		*priority = instruction->actions.actions[*result];

		RDEBUG4("** [%i] %s - setting priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, *result, "<invalid>"),
			*priority);
	}

	/*
	 *	We're higher than any previous priority, remember this
	 *	return code and priority.
	 */
	if (*priority > frame->priority) {
		frame->result = *result;
		frame->priority = *priority;

		RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, *result, "<invalid>"),
			*priority);
	}

	/*
	 *	Not allowed in frame uflags...
	 */
	fr_assert(!(frame->uflags & UNWIND_FLAG_NO_CLEAR));

	/*
	 *	If we are unwinding the stack due to a break / return,
	 *	then handle it now.
	 */
	if (stack->unwind) {
		/*
		 *	Continue unwinding...
		 */
		if (!(stack->unwind & frame->uflags) || (stack->unwind & UNWIND_FLAG_NO_CLEAR)) {
			RDEBUG4("** [%i] %s - unwinding current frame with (%s %d) - flags - stack (%i), frame (%i)",
				stack->depth, __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
				frame->priority, stack->unwind, frame->uflags);

			return UNLANG_FRAME_ACTION_POP;
		}

		/*
		 *	If we've been told to unwind, and we've hit
		 *	the frame we should be unwinding to,
		 *	and the "NO_CLEAR" flag hasn't been set, then
		 *	clear the unwind field so we stop unwinding.
		 */
		stack->unwind = UNWIND_FLAG_NONE;

		RDEBUG4("** [%i] %s - unwind stop (%s %d) - flags - stack unwind (%i), frame uflags (%i)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
			frame->priority, stack->unwind, frame->uflags);
	}

	return frame->next ? UNLANG_FRAME_ACTION_NEXT : UNLANG_FRAME_ACTION_POP;
}

/** Evaluates all the unlang nodes in a section
 *
 * @param[in] request		The current request.
 * @param[in] frame		The curren stack frame.
 * @param[in,out] result	The current section result.
 * @param[in,out] priority	The current section priority.
 * @return
 *	- UNLANG_FRAME_ACTION_NEXT	evaluate more instructions in the current stack frame
 *					which may not be the same frame as when this function
 *					was called.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline CC_HINT(always_inline)
unlang_frame_action_t frame_eval(request_t *request, unlang_stack_frame_t *frame, rlm_rcode_t *result, int *priority)
{
	unlang_stack_t	*stack = request->stack;

	/*
	 *	Loop over all the instructions in this list.
	 */
	while (frame->instruction) {
		unlang_t const		*instruction = frame->instruction;
		unlang_action_t		ua = UNLANG_ACTION_UNWIND;
		unlang_frame_action_t	fa;

		DUMP_STACK;

		fr_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */

		REQUEST_VERIFY(request);

		/*
		 *	We're running this frame, so it can't possibly be yielded.
		 */
		if (is_yielded(frame)) {
			RDEBUG("%s - Resuming execution", instruction->debug_name);
			yielded_clear(frame);
		}

		/*
		 *	unlang_interpret_signal() takes care of
		 *	marking the requests as STOP on a CANCEL
		 *	signal.
		 */
		if (request->master_state == REQUEST_STOP_PROCESSING) {
		do_stop:
			frame->result = RLM_MODULE_FAIL;
			frame->priority = MOD_PRIORITY_MAX;

			RDEBUG4("** [%i] %s - STOP current subsection with (%s %d)",
				stack->depth, __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
				frame->priority);

			unwind_all(stack);
			return UNLANG_FRAME_ACTION_POP;
		}

		if (!is_repeatable(frame) && (unlang_ops[instruction->type].debug_braces)) {
			RDEBUG2("%s {", instruction->debug_name);
			RINDENT();
		}

		/*
		 *	Execute an operation
		 */
		RDEBUG4("** [%i] %s >> %s", stack->depth, __FUNCTION__,
			unlang_ops[instruction->type].name);

		fr_assert(frame->process != NULL);

		/*
		 *	Clear the repeatable flag so this frame
		 *	won't get executed again unless it specifically
		 *	requests it.
		 *
		 *	The flag may still be set again during the
		 *	process function to indicate that the frame
		 *	should be evaluated again.
		 */
		repeatable_clear(frame);
		ua = frame->process(result, request, frame);

		RDEBUG4("** [%i] %s << %s (%d)", stack->depth, __FUNCTION__,
			fr_table_str_by_value(unlang_action_table, ua, "<INVALID>"), *priority);

		fr_assert(*priority >= -1);
		fr_assert(*priority <= MOD_PRIORITY_MAX);

		switch (ua) {
		/*
		 *	The request is now defunct, and we should not
		 *	continue processing it.
		 */
		case UNLANG_ACTION_STOP_PROCESSING:
			goto do_stop;

		/*
		 *	The operation resulted in additional frames
		 *	being pushed onto the stack, execution should
		 *	now continue at the deepest frame.
		 */
		case UNLANG_ACTION_PUSHED_CHILD:
			fr_assert(&stack->frame[stack->depth] > frame);
			*result = frame->result;
			return UNLANG_FRAME_ACTION_NEXT;

		/*
		 *	We're in a looping construct and need to stop
		 *	execution of the current section.
		 */
		case UNLANG_ACTION_UNWIND:
			if (*priority < 0) *priority = 0;
			frame->result = *result;
			frame->priority = *priority;
			frame->next = NULL;
			fr_assert(stack->unwind != UNWIND_FLAG_NONE);
			return UNLANG_FRAME_ACTION_POP;

		/*
		 *	Yield control back to the scheduler, or whatever
		 *	called the interpreter.
		 */
		case UNLANG_ACTION_YIELD:
			yielded_set(frame);
			RDEBUG4("** [%i] %s - yielding with current (%s %d)", stack->depth, __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
				frame->priority);
			DUMP_STACK;
			return UNLANG_FRAME_ACTION_YIELD;

		/*
		 *	This action is intended to be returned by library
		 *	functions.  It reduces the boilerplate.
		 */
		case UNLANG_ACTION_FAIL:
			*result = RLM_MODULE_FAIL;
			FALL_THROUGH;

		/*
		 *	Instruction finished execution,
		 *	check to see what we need to do next, and update
		 *	the section rcode and priority.
		 */
		case UNLANG_ACTION_CALCULATE_RESULT:
			if (unlang_ops[instruction->type].debug_braces) {
				REXDENT();

				/*
				 *	If we're at debug level 1, don't emit the closing
				 *	brace as the opening brace wasn't emitted.
				 */
				if (RDEBUG_ENABLED && !RDEBUG_ENABLED2) {
					RDEBUG("# %s (%s)", instruction->debug_name,
					       fr_table_str_by_value(mod_rcode_table, *result, "<invalid>"));
				} else {
					RDEBUG2("} # %s (%s)", instruction->debug_name,
						fr_table_str_by_value(mod_rcode_table, *result, "<invalid>"));
				}
			}

			/*
			 *	RLM_MODULE_NOT_SET means the instruction
			 *	doesn't want to modify the result.
			 */
			if (*result != RLM_MODULE_NOT_SET) *priority = instruction->actions.actions[*result];

			fa = result_calculate(request, frame, result, priority);
			switch (fa) {
			case UNLANG_FRAME_ACTION_POP:
				return UNLANG_FRAME_ACTION_POP;

			case UNLANG_FRAME_ACTION_RETRY:
				if (unlang_ops[instruction->type].debug_braces) {
					REXDENT();
					RDEBUG2("} # retrying the same section");
				}
				continue; /* with the current frame */

			default:
				break;
			}

			FALL_THROUGH;

		/*
		 *	Execute the next instruction in this frame
		 */
		case UNLANG_ACTION_EXECUTE_NEXT:
			if ((ua == UNLANG_ACTION_EXECUTE_NEXT) && unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("}");
			}
			break;
		} /* switch over return code from the interpret function */

		frame_next(stack, frame);
	}

	RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
		stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority);

	return UNLANG_FRAME_ACTION_POP;
}

/** Run the interpreter for a current request
 *
 * @param[in] request		to run.  If this is an internal request
 *				the request may be freed by the interpreter.
 * @return The final request rcode.
 */
CC_HINT(hot) rlm_rcode_t unlang_interpret(request_t *request)
{
	unlang_frame_action_t	fa = UNLANG_FRAME_ACTION_NEXT;
	rlm_rcode_t		rcode;

	/*
	 *	We don't have a return code yet.
	 */
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp = stack->intp;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];	/* Quiet static analysis */

	stack->priority = -1;	/* Reset */

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("###### unlang_interpret is starting");
	DUMP_STACK;
#endif

	fr_assert(!unlang_request_is_scheduled(request)); /* if we're running it, it can't be scheduled */
	fr_assert_msg(intp, "request has no interpreter associated");

	RDEBUG4("** [%i] %s - interpret entered", stack->depth, __FUNCTION__);
	intp->funcs.resume(request, intp->uctx);

	for (;;) {
		RDEBUG4("** [%i] %s - frame action %s", stack->depth, __FUNCTION__,
			fr_table_str_by_value(unlang_frame_action_table, fa, "<INVALID>"));
		switch (fa) {
		case UNLANG_FRAME_ACTION_NEXT:	/* Evaluate the current frame */
			fr_assert(stack->depth > 0);
			fr_assert(stack->depth < UNLANG_STACK_MAX);

			frame = &stack->frame[stack->depth];
			fa = frame_eval(request, frame, &stack->result, &stack->priority);

			/*
			 *	We were executing a frame, frame_eval()
			 *	indicated we should pop it, but we're now at
			 *	a top_frame, so we need to break out of the loop
			 *	and calculate the final result for this substack.
			 *
			 *	Note that we only stop on a top frame.
			 *	If there's a return point such as in a
			 *	policy, then the "return" causes a
			 *	"pop" until the return point.  BUT we
			 *	then continue execution with the next
			 *	instruction.  And we don't return all
			 *	of the way up the stack.
			 */
			if ((fa == UNLANG_FRAME_ACTION_POP) && is_top_frame(frame)) break;	/* stop */
			continue;

		case UNLANG_FRAME_ACTION_POP:		/* Pop this frame and check the one beneath it */
			/*
			 *	The result / priority is returned from the sub-section,
			 *	and made into our current result / priority, as
			 *	if we had performed a module call.
			 */
			stack->result = frame->result;
			stack->priority = frame->priority;

			/*
			 *	Head on back up the stack
			 */
			frame_pop(stack);
			frame = &stack->frame[stack->depth];
			DUMP_STACK;

			/*
			 *	Resume a "foreach" loop, or a "load-balance" section
			 *	or anything else that needs to be checked on the way
			 *	back on up the stack.
			 */
			if (is_repeatable(frame)) {
				fa = UNLANG_FRAME_ACTION_NEXT;
				continue;
			}

			/*
			 *	Close out the section we entered earlier
			 */
			if (unlang_ops[frame->instruction->type].debug_braces) {
				REXDENT();

				/*
				 *	If we're at debug level 1, don't emit the closing
				 *	brace as the opening brace wasn't emitted.
				 */
				if (RDEBUG_ENABLED && !RDEBUG_ENABLED2) {
					RDEBUG("# %s (%s)", frame->instruction->debug_name,
					       fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"));
				} else {
					RDEBUG2("} # %s (%s)", frame->instruction->debug_name,
						fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"));
				}
			}

			/*
			 *	If we're done, merge the last stack->result / priority in.
			 */
			if (is_top_frame(frame)) break;	/* stop */

			fa = result_calculate(request, frame, &stack->result, &stack->priority);

			/*
			 *	If we're continuing after popping a frame
			 *	then we advance the instruction else we
			 *	end up executing the same code over and over...
			 */
			if (fa == UNLANG_FRAME_ACTION_NEXT) {
				RDEBUG4("** [%i] %s - continuing after subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"),
					stack->priority);
				frame_next(stack, frame);

			/*
			 *	Else if we're really done with this frame
			 *	print some helpful debug...
			 */
			} else {
				RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
			}
			continue;

		case UNLANG_FRAME_ACTION_YIELD:
			RDEBUG4("** [%i] %s - interpret yielding", stack->depth, __FUNCTION__);
			intp->funcs.yield(request, intp->uctx);
			return stack->result;

		case UNLANG_FRAME_ACTION_RETRY:	/* retry the current frame */
			fa = UNLANG_FRAME_ACTION_NEXT;
			continue;
		}
		break;
	}

	/*
	 *	Nothing in this section, use the top frame stack->result.
	 */
	if ((stack->priority < 0) || (stack->result == RLM_MODULE_NOT_SET)) {
		RDEBUG4("** [%i] %s - empty section, using stack result (%s %d)", stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"), stack->priority);
		stack->result = frame->result;
		stack->priority = frame->priority;
	}

	if (stack->priority > frame->priority) {
		frame->result = stack->result;
		frame->priority = stack->priority;

		RDEBUG4("** [%i] %s - over-riding stack->result from higher priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"),
			stack->priority);
	}

	/*
	 *	We're at the top frame, return the result from the
	 *	stack, and get rid of the top frame.
	 */
	RDEBUG4("** [%i] %s - interpret exiting, returning %s", stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"));

	stack->result = frame->result;

	stack->depth--;
	DUMP_STACK;

	/*
	 *	Record this now as the done functions may free
	 *	the request.
	 */
	rcode = stack->result;

	/*
	 *	This usually means the request is complete in its
	 *	entirety.
	 */
	if (stack->depth == 0) unlang_interpret_request_done(request);

	return rcode;
}

static unlang_group_t empty_group = {
	.self = {
		.type = UNLANG_TYPE_GROUP,
		.debug_name = "empty-group",
		.actions = {
			.actions = {
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN,
				MOD_ACTION_RETURN
			},
			.retry = RETRY_INIT,
		},
	},
};


/** Push a configuration section onto the request stack for later interpretation.
 *
 */
int unlang_interpret_push_section(request_t *request, CONF_SECTION *cs, rlm_rcode_t default_rcode, bool top_frame)
{
	unlang_t	*instruction = NULL;

	/*
	 *	Interpretable unlang instructions are stored as CONF_DATA
	 *	associated with sections.
	 */
	if (cs) {
		instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
		if (!instruction) {
			REDEBUG("Failed to find pre-compiled unlang for section %s %s { ... }",
				cf_section_name1(cs), cf_section_name2(cs));
			return -1;
		}
	}

	return unlang_interpret_push_instruction(request, instruction, default_rcode, top_frame);
}

/** Push an instruction onto the request stack for later interpretation.
 *
 */
int unlang_interpret_push_instruction(request_t *request, void *instruction, rlm_rcode_t default_rcode, bool top_frame)
{
	unlang_stack_t	*stack = request->stack;

	if (!instruction) {
		instruction = unlang_group_to_generic(&empty_group);
	}

	/*
	 *	Push the default action, and the instruction which has
	 *	no action.
	 */
	if (unlang_interpret_push(request,
				  instruction, default_rcode, UNLANG_NEXT_SIBLING, top_frame) < 0) {
		return -1;
	}

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

	DUMP_STACK;

	return 0;
}

/** Allocate a new unlang stack
 *
 * @param[in] ctx	to allocate stack in.
 * @return
 *	- A new stack on success.
 *	- NULL on OOM.
 */
void *unlang_interpret_stack_alloc(TALLOC_CTX *ctx)
{
	unlang_stack_t *stack;

	/*
	 *	If we have talloc_pooled_object allocate the
	 *	stack as a combined chunk/pool, with memory
	 *	to hold at mutable data for at least a quarter
	 *	of the maximum number of stack frames.
	 *
	 *	Having a dedicated pool for mutable stack data
	 *	means we don't have memory fragmentations issues
	 *	as we would if request were used as the pool.
	 *
	 *	This number is pretty arbitrary, but it seems
	 *	like too low level to make into a tuneable.
	 */
	stack = talloc_zero_pooled_object(ctx, unlang_stack_t, UNLANG_STACK_MAX, 128);	/* 128 bytes per state */
	stack->result = RLM_MODULE_NOT_SET;

	return stack;
}

/** Indicate to the caller of the interpreter that this request is complete
 *
 */
void unlang_interpret_request_done(request_t *request)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp;

	if (!fr_cond_assert(stack != NULL)) return;

	intp = stack->intp;

	switch (request->type) {
	case REQUEST_TYPE_EXTERNAL:
		intp->funcs.done_external(request, stack->result, intp->uctx);
		break;

	case REQUEST_TYPE_INTERNAL:
		intp->funcs.done_internal(request, stack->result, intp->uctx);
		break;

	case REQUEST_TYPE_DETACHED:
		intp->funcs.done_detached(request, stack->result, intp->uctx);
		break;
	}
}

static inline CC_HINT(always_inline)
void unlang_interpret_request_stop(request_t *request)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp;

	if (!fr_cond_assert(stack != NULL)) return;

	intp = stack->intp;
	intp->funcs.stop(request, intp->uctx);
}

static inline CC_HINT(always_inline)
void unlang_interpret_request_detach(request_t *request)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp;

	if (!fr_cond_assert(stack != NULL)) return;

	intp = stack->intp;
	intp->funcs.detach(request, intp->uctx);
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #unlang_module_signal_t callback defined, the action is ignored.
 *
 * The signaling stops at the "limit" frame.  This is so that keywords
 * such as "timeout" and "limit" can signal frames *lower* than theirs
 * to stop, but then continue with their own work.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 * @param[in] limit		the frame at which to stop signaling.
 */
static inline CC_HINT(always_inline) void frame_signal(request_t *request, fr_state_signal_t action, int limit)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	int			i, depth = stack->depth;

	(void)talloc_get_type_abort(request, request_t);	/* Check the request hasn't already been freed */

	fr_assert(stack->depth > 0);

	/*
	 *	Destructive signal where we clean each of the
	 *	stack frames up in turn.
	 *
	 *	We do this to avoid possible free ordering
	 *	issues where memory allocated by modules higher
	 *	in the stack is used by modules lower in the
	 *	stack.
	 */
	if (action == FR_SIGNAL_CANCEL) {
		for (i = depth; i > limit; i--) {
			frame = &stack->frame[i];
			if (frame->signal) frame->signal(request, frame, action);
			frame_cleanup(frame);
		}
		stack->depth = i;
		return;
	}

	/*
	 *	Walk back up the stack, calling signal handlers
	 *	to cancel any pending operations and free/release
	 *	any resources.
	 *
	 *	There may be multiple resumption points in the
	 *	stack, as modules can push xlats and function
	 *	calls.
	 */
	for (i = depth; i > limit; i--) {
		frame = &stack->frame[i];
		if (frame->signal) frame->signal(request, frame, action);
	}
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #unlang_module_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 */
void unlang_interpret_signal(request_t *request, fr_state_signal_t action)
{
	unlang_stack_t		*stack = request->stack;

	switch (action) {
	case FR_SIGNAL_DETACH:
		/*
		 *	Ensure the request is able to be detached
		 *      else don't signal.
		 */
		if (!fr_cond_assert(request_is_detachable(request))) return;
		break;

	default:
		break;
	}

	/*
	 *	Requests that haven't been run through the interpreter
	 *	yet should have a stack depth of zero, so we don't
	 *	need to do anything.
	 */
	if (stack && (stack->depth > 0)) frame_signal(request, action, 0);

	switch (action) {
	case FR_SIGNAL_CANCEL:
		unlang_interpret_request_stop(request);		/* Stop gets the request in a consistent state */
		unlang_interpret_request_done(request);		/* Done signals the request is complete */
		break;

	case FR_SIGNAL_DETACH:
		unlang_interpret_request_detach(request);	/* Tell our caller that the request is being detached */
		if (request_detach(request) < 0) RPEDEBUG("Failed detaching request");
		break;

	default:
		break;
	}
}

static void instruction_timeout_handler(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
{
	unlang_retry_t			*retry = talloc_get_type_abort(ctx, unlang_retry_t);
	request_t			*request = talloc_get_type_abort(retry->request, request_t);

	RDEBUG("retry timeout reached, signalling interpreter to cancel.");

	/*
	 *	Signal all lower frames to exit.
	 */
	frame_signal(request, FR_SIGNAL_CANCEL, retry->depth);

	retry->state = FR_RETRY_MRD;
	unlang_interpret_mark_runnable(request);
}

/** Return the depth of the request's stack
 *
 */
int unlang_interpret_stack_depth(request_t *request)
{
	unlang_stack_t	*stack = request->stack;

	return stack->depth;
}

/** Get the current rcode for the frame
 *
 * This can be useful for getting the result of unlang_function_t pushed
 * onto the stack for evaluation.
 *
 * @param[in] request	The current request.
 * @return the current rcode for the frame.
 */
rlm_rcode_t unlang_interpret_stack_result(request_t *request)
{
	unlang_stack_t		*stack = request->stack;

	return stack->result;
}

/** Overwrite the current stack rcode
 *
 * @param[in] request	The current request.
 * @param[in] rcode	to set.
 */
void unlang_interpret_stack_result_set(request_t *request, rlm_rcode_t rcode)
{
	unlang_stack_t		*stack = request->stack;

	stack->result = rcode;
}

/** Return whether a request is currently scheduled
 *
 */
bool unlang_request_is_scheduled(request_t const *request)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp = stack->intp;

	return intp->funcs.scheduled(request, intp->uctx);
}

/** Return whether a request has been cancelled
 */
bool unlang_request_is_cancelled(request_t const *request)
{
	return (request->master_state == REQUEST_STOP_PROCESSING);
}

/** Check if a request as resumable.
 *
 * @param[in] request		The current request.
 * @return
 *	- true if the request is resumable (i.e. has yeilded)
 *	- false if the request is not resumable (i.e. has not yielded)
 */
bool unlang_interpret_is_resumable(request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	return is_yielded(frame);
}

/** Mark a request as resumable.
 *
 * It's not called "unlang_interpret", because it doesn't actually
 * resume the request, it just schedules it for resumption.
 *
 * @note that this schedules the request for resumption.  It does not immediately
 *	start running the request.
 *
 * @param[in] request		The current request.
 */
void unlang_interpret_mark_runnable(request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_interpret_t		*intp = stack->intp;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	bool 				scheduled = unlang_request_is_scheduled(request);

	/*
	 *	The request hasn't yielded, OR it's already been
	 *	marked as runnable.  Don't do anything.
	 *
	 *	The IO code, or children have no idea where they're
	 *	being called from.  They just ask to mark the parent
	 *	resumable when they're done.  So we have to check here
	 *	if this request is resumable.
	 *
	 *	If the parent called the child directly, then the
	 *	parent hasn't yielded, so it isn't resumable.  When
	 *	the child is done, the parent will automatically
	 *	continue running.  We therefore don't need to insert
	 *	the parent into the backlog.
	 *
	 *	Multiple child request may also mark a parent request
	 *	runnable, before the parent request starts running.
	 */
	if (!is_yielded(frame) || scheduled) {
		RDEBUG3("Not marking runnable due to%s%s",
			!is_yielded(frame) ?
			" it not being yielded " : "", scheduled ? " it already being scheduled" : "");
		return;
	}

	RDEBUG3("Interpreter - Request marked as runnable");

	intp->funcs.mark_runnable(request, intp->uctx);
}

/** Get a talloc_ctx which is valid only for this frame
 *
 * @param[in] request		The current request.
 * @return
 *	- a TALLOC_CTX which is valid only for this stack frame
 */
TALLOC_CTX *unlang_interpret_frame_talloc_ctx(request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	switch (frame->instruction->type) {
	default:
		break;

	case UNLANG_TYPE_MODULE:
	case UNLANG_TYPE_XLAT:
		return (TALLOC_CTX *) frame->state;
	}

	/*
	 *	Ensure that the memory is always cleaned up when the
	 *	request exits.  And make sure that this function is safe to call from anywhere.
	 */
	return (TALLOC_CTX *)request;
}

static xlat_arg_parser_t const unlang_interpret_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Get information about the interpreter state
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unlang_interpret_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					   UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					   fr_value_box_list_t *in)
{
	unlang_stack_t		*stack = request->stack;
	int			depth = stack->depth;
	unlang_stack_frame_t	*frame;
	unlang_t const		*instruction;
	fr_value_box_t		*arg = fr_dlist_head(in);
	char const		*fmt = arg->vb_strvalue;
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc_null(ctx));
	/*
	 *	Find the correct stack frame.
	 */
	while (*fmt == '.') {
		if (depth <= 1) {
			if (fr_value_box_bstrndup(ctx, vb, NULL, "<underflow>", 11, false) < 0) {
			error:
				talloc_free(vb);
				return XLAT_ACTION_FAIL;
			};
			goto finish;
		}

		fmt++;
		depth--;
	}

	/*
	 *	Get the current instruction.
	 */
	frame = &stack->frame[depth];
	instruction = frame->instruction;

	/*
	 *	Nothing there...
	 */
	if (!instruction) {
		return XLAT_ACTION_DONE;
	}

	/*
	 *	Name of the instruction.
	 */
	if (strcmp(fmt, "name") == 0) {
		if (fr_value_box_bstrndup(ctx, vb, NULL, instruction->name,
					  strlen(instruction->name), false) < 0) goto error;
		goto finish;
	}

	/*
	 *	Unlang type.
	 */
	if (strcmp(fmt, "type") == 0) {
		if (fr_value_box_bstrndup(ctx, vb, NULL, unlang_ops[instruction->type].name,
					  strlen(unlang_ops[instruction->type].name), false) < 0) goto error;
		goto finish;
	}

	/*
	 *	How deep the current stack is.
	 */
	if (strcmp(fmt, "depth") == 0) {
		fr_value_box_int32(vb, NULL, depth, false);
		goto finish;
	}

	/*
	 *	Line number of the current section.
	 */
	if (strcmp(fmt, "line") == 0) {
		unlang_group_t const *g;

		if (!unlang_ops[instruction->type].debug_braces) {
			if (fr_value_box_bstrndup(ctx, vb, NULL, "???", 3, false) < 0) goto error;
			goto finish;
		}

		g = (unlang_group_t const *) instruction;
		fr_assert(g->cs != NULL);

		fr_value_box_int32(vb, NULL, cf_lineno(g->cs), false);
		goto finish;
	}

	/*
	 *	Filename of the current section.
	 */
	if (strcmp(fmt, "filename") == 0) {
		unlang_group_t const *g;

		if (!unlang_ops[instruction->type].debug_braces) {
			if (fr_value_box_bstrndup(ctx, vb, NULL, "???", 3, false) < 0) goto error;
			goto finish;
		}

		g = (unlang_group_t const *) instruction;
		fr_assert(g->cs != NULL);

		if (fr_value_box_bstrndup(ctx, vb, NULL, cf_filename(g->cs),
					  strlen(cf_filename(g->cs)), false) < 0) goto error;
		goto finish;
	}

finish:
	if (vb->type != FR_TYPE_NULL) fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

/** Initialize a unlang compiler / interpret.
 *
 * @param[in] ctx	to bind lifetime of the interpret to.
 *			Shouldn't be any free order issues here as
 *			the interpret itself has no state.
 *			But event loop should be stopped before
 *      		freeing the interpret.
 * @param[in] el	for any timer or I/O events.
 * @param[in] funcs	Callbacks to used to communicate request
 *			state to our owner.
 * @param[in] uctx	Data to pass to callbacks.
 */
unlang_interpret_t *unlang_interpret_init(TALLOC_CTX *ctx,
					  fr_event_list_t *el, unlang_request_func_t *funcs, void *uctx)
{
	unlang_interpret_t *intp;

	fr_assert(funcs->init_internal);

	fr_assert(funcs->done_internal);
	fr_assert(funcs->done_detached);
	fr_assert(funcs->done_external);

	fr_assert(funcs->detach);
	fr_assert(funcs->stop);
	fr_assert(funcs->yield);
	fr_assert(funcs->resume);
	fr_assert(funcs->mark_runnable);
	fr_assert(funcs->scheduled);

	MEM(intp = talloc(ctx, unlang_interpret_t));
	*intp = (unlang_interpret_t){
		.el = el,
		.funcs = *funcs,
		.uctx = uctx
	};

 	return intp;
}

/** Discard the bottom most frame on the request's stack
 *
 * This is used for cleaning up after errors. i.e. the caller
 * uses a push function, and experiences an error and needs to
 * remove the frame that was just pushed.
 */
void unlang_interpet_frame_discard(request_t *request)
{
	frame_pop(request->stack);
}

/** Set a specific interpreter for a request
 *
 */
void unlang_interpret_set(request_t *request, unlang_interpret_t *intp)
{
	unlang_stack_t	*stack = request->stack;
	stack->intp = intp;
}

/** Get the interpreter set for a request
 *
 */
unlang_interpret_t *unlang_interpret_get(request_t *request)
{
	unlang_stack_t	*stack = request->stack;

	return stack->intp;
}

/** Get the event list for the current interpreter
 *
 */
fr_event_list_t *unlang_interpret_event_list(request_t *request)
{
	unlang_stack_t	*stack = request->stack;

	if (!stack->intp) return NULL;

	return stack->intp->el;
}

/** Set the default interpreter for this thread
 *
 */
void unlang_interpret_set_thread_default(unlang_interpret_t *intp)
{
	if (intp) (void)talloc_get_type_abort(intp, unlang_interpret_t);

	intp_thread_default = intp;
}

/** Get the default interpreter for this thread
 *
 * This allows detached requests to be executed asynchronously
 */
unlang_interpret_t *unlang_interpret_get_thread_default(void)
{
	if (!intp_thread_default) return NULL;

	return talloc_get_type_abort(intp_thread_default, unlang_interpret_t);
}

void unlang_interpret_init_global(void)
{
	xlat_t	*xlat;
	xlat = xlat_register(NULL, "interpreter", unlang_interpret_xlat, false);
	xlat_func_args(xlat, unlang_interpret_xlat_args);
}
