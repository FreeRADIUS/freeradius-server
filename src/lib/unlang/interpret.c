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
 * @brief Execute compiled unlang structures using an iterative interpreter.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/xlat.h>

#include "unlang_priv.h"
#include "parallel_priv.h"
#include "module_priv.h"

static fr_table_num_ordered_t const unlang_action_table[] = {
	{ "unwind", 		UNLANG_ACTION_UNWIND },
	{ "calculate-result",	UNLANG_ACTION_CALCULATE_RESULT },
	{ "next",		UNLANG_ACTION_EXECUTE_NEXT },
	{ "pushed-child",	UNLANG_ACTION_PUSHED_CHILD },
	{ "stop",		UNLANG_ACTION_STOP_PROCESSING },
	{ "yield",		UNLANG_ACTION_YIELD }
};
static size_t unlang_action_table_len = NUM_ELEMENTS(unlang_action_table);

static fr_table_num_ordered_t const unlang_frame_action_table[] = {
	{ "pop", 		UNLANG_FRAME_ACTION_POP		},
	{ "next",		UNLANG_FRAME_ACTION_NEXT	},
	{ "yield",		UNLANG_FRAME_ACTION_YIELD	}
};
static size_t unlang_frame_action_table_len = NUM_ELEMENTS(unlang_frame_action_table);

#ifndef NDEBUG
static void instruction_dump(REQUEST *request, unlang_t *instruction)
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

static void frame_dump(REQUEST *request, unlang_stack_frame_t *frame)
{
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
	REXDENT();
}

static void stack_dump(REQUEST *request)
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

/** Different operations the interpreter can execute
 */
unlang_op_t unlang_ops[UNLANG_TYPE_MAX];


static inline void frame_state_init(unlang_stack_t *stack, unlang_stack_frame_t *frame)
{
	unlang_t	*instruction = frame->instruction;
	unlang_op_t	*op;

	op = &unlang_ops[instruction->type];

	frame->interpret = op->interpret;
	frame->signal = op->signal;

	/*
	 *	The frame needs to track state.  Do so here.
	 */
	if (op->frame_state_size) {
		char const *name = op->frame_state_name ? op->frame_state_name : __location__;

#ifdef HAVE_TALLOC_ZERO_POOLED_OBJECT
		if (op->frame_state_pool_size) {
			MEM(frame->state = _talloc_zero_pooled_object(stack,
								      op->frame_state_size, name,
								      op->frame_state_pool_objects,
								      op->frame_state_pool_size));
		}
#endif
		else {
			MEM(frame->state = _talloc_zero(stack, op->frame_state_size, name));
		}
	}
}

/** Push a new frame onto the stack
 *
 * @param[in] request		to push the frame onto.
 * @param[in] instruction	One or more unlang_t nodes describing the operations to execute.
 * @param[in] default_rcode	The default result.
 * @param[in] do_next_sibling	Whether to only execute the first node in the #unlang_t program
 *				or to execute subsequent nodes.
 * @param[in] top_frame		Return out of the unlang interpreter when popping this frame.
 *				Hands execution back to whatever called the interpreter.
 */
void unlang_interpret_push(REQUEST *request, unlang_t *instruction,
			   rlm_rcode_t default_rcode, bool do_next_sibling, bool top_frame)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame;

	rad_assert(instruction || top_frame);

#ifndef NDEBUG
	if (DEBUG_ENABLED5) RDEBUG3("unlang_interpret_push called with instruction %s - args %s %s",
				    instruction ? instruction->debug_name : "<none>",
				    do_next_sibling ? "UNLANG_NEXT_SIBLING" : "UNLANG_NEXT_STOP",
				    top_frame ? "UNLANG_TOP_FRAME" : "UNLANG_SUB_FRAME");
#endif

	if (stack->depth >= (UNLANG_STACK_MAX - 1)) {
		RERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(EXIT_FAILURE);
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	frame = &stack->frame[stack->depth];
	memset(frame, 0, sizeof(*frame));

	frame->instruction = instruction;

	if (do_next_sibling) {
		rad_assert(instruction != NULL);
		frame->next = instruction->next;
	}
	/* else frame->next MUST be NULL */

	frame->uflags = UNWIND_FLAG_NONE;
	if (top_frame) top_frame_set(frame);

	frame->result = default_rcode;
	frame->priority = -1;

	if (!instruction) return;

	frame_state_init(stack, frame);
}

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
static inline unlang_frame_action_t result_calculate(REQUEST *request, unlang_stack_frame_t *frame,
						     rlm_rcode_t *result, int *priority)
{
	unlang_t	*instruction = frame->instruction;
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
	if (*result == RLM_MODULE_UNKNOWN) return UNLANG_FRAME_ACTION_NEXT;

	/*
	 *	The child's action says return.  Do so.
	 */
	if (instruction->actions[*result] == MOD_ACTION_RETURN) {
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
	if (instruction->actions[*result] == MOD_ACTION_REJECT) {
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
	 *	The array holds a default priority for this return
	 *	code.  Grab it in preference to any unset priority.
	 */
	if (*priority < 0) {
		*priority = instruction->actions[*result];

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
	rad_assert(!(frame->uflags & UNWIND_FLAG_NO_CLEAR));

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

		RDEBUG4("** [%i] %s - unwind stop (%s %d) - flags - stack (%i), frame (%i)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
			frame->priority, stack->unwind, frame->uflags);
	}

	return frame->next ? UNLANG_FRAME_ACTION_NEXT : UNLANG_FRAME_ACTION_POP;
}

/** Cleanup any lingering frame state
 *
 */
static inline void frame_cleanup(unlang_stack_frame_t *frame)
{
	/*
	 *	Don't clear top_frame flag, bad things happen...
	 */
	repeatable_clear(frame);
	break_point_clear(frame);
	return_point_clear(frame);
	yielded_clear(frame);
	if (frame->state) TALLOC_FREE(frame->state);
}

/** Advance to the next sibling instruction
 *
 */
static inline void frame_next(unlang_stack_t *stack, unlang_stack_frame_t *frame)
{
	frame_cleanup(frame);
	frame->instruction = frame->next;

	if (!frame->instruction) return;

	frame->next = frame->instruction->next;

	frame_state_init(stack, frame);
}

/** Pop a stack frame, removing any associated dynamically allocated state
 *
 * @param[in] stack	frame to pop.
 */
static inline void frame_pop(unlang_stack_t *stack)
{
	unlang_stack_frame_t *frame;

	rad_assert(stack->depth > 1);

	frame = &stack->frame[stack->depth];

	frame_cleanup(frame);

	frame = &stack->frame[--stack->depth];

	/*
	 *	The child was break / return, AND the current frame is
	 *	a break / return point.  Stop unwinding the stack.
	 *
	 *	NOTE: This is the frame further UP the stack, not the
	 *	one we just popped.  So we *MUST* clear repeat,
	 *	otherwise the interpreter will just keep repeating
	 *	this frame instead of continuing to unwind the stack.
	 *
	 *	An alternative way of doing this would be to rearrange
	 *	the code so repeat unwinding had precedence, but it's
	 *	probably more robust to have the interpreter not be
	 *	dependent on flag evaluation order.
	 */
	if (stack->unwind && is_repeatable(frame)) repeatable_clear(frame);
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
static inline unlang_frame_action_t frame_eval(REQUEST *request, unlang_stack_frame_t *frame,
					       rlm_rcode_t *result, int *priority)
{
	unlang_stack_t	*stack = request->stack;

	/*
	 *	Loop over all the instructions in this list.
	 */
	while (frame->instruction) {
		unlang_t		*instruction = frame->instruction;
		unlang_action_t		action = UNLANG_ACTION_UNWIND;

		DUMP_STACK;

		rad_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */

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
			frame->priority = 9999;

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

		rad_assert(frame->interpret != NULL);
		action = frame->interpret(request, result);

		RDEBUG4("** [%i] %s << %s (%d)", stack->depth, __FUNCTION__,
			fr_table_str_by_value(unlang_action_table, action, "<INVALID>"), *priority);

		rad_assert(*priority >= -1);
		rad_assert(*priority <= MOD_PRIORITY_MAX);

		switch (action) {
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
			rad_assert(&stack->frame[stack->depth] > frame);
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
			rad_assert(stack->unwind != UNWIND_FLAG_NONE);
			return UNLANG_FRAME_ACTION_POP;

		/*
		 *	Yield control back to the scheduler, or whatever
		 *	called the interpreter.
		 */
		case UNLANG_ACTION_YIELD:
			*result = RLM_MODULE_YIELD;	/* Fixup rcode */
		yield:
			/*
			 *	Detach is magic.  The parent "subrequest" function
			 *	takes care of bumping the instruction
			 *	pointer...
			 */
			switch (frame->instruction->type) {
				/*
				 *	For sanity, we ensure that
				 *	only known keywords can yield.
				 */
			case UNLANG_TYPE_MODULE:
			case UNLANG_TYPE_PARALLEL:
			case UNLANG_TYPE_SUBREQUEST:
			case UNLANG_TYPE_XLAT:
			case UNLANG_TYPE_CALL:
			case UNLANG_TYPE_DETACH:
				repeatable_set(frame);
				yielded_set(frame);
				RDEBUG4("** [%i] %s - yielding with current (%s %d)", stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
				DUMP_STACK;
				return UNLANG_FRAME_ACTION_YIELD;

			default:
				rad_assert(0);
				return UNLANG_FRAME_ACTION_YIELD;
			}

		/*
		 *	Instruction finished execution,
		 *	check to see what we need to do next, and update
		 *	the section rcode and priority.
		 */
		case UNLANG_ACTION_CALCULATE_RESULT:
			/*
			 *	If a module returns yield, then do
			 *	yield.  Only keywords will return
			 *	UNLANG_ACTION_YIELD.
			 */
			if (*result == RLM_MODULE_YIELD) goto yield;

			rad_assert(*result != RLM_MODULE_UNKNOWN);

			repeatable_clear(frame);

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

			*priority = instruction->actions[*result];

			if (result_calculate(request, frame, result, priority) == UNLANG_FRAME_ACTION_POP) {
				return UNLANG_FRAME_ACTION_POP;
			}
			/* FALL-THROUGH */

		/*
		 *	Execute the next instruction in this frame
		 */
		case UNLANG_ACTION_EXECUTE_NEXT:
			if ((action == UNLANG_ACTION_EXECUTE_NEXT) && unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("}");
			}
			break;
		} /* switch over return code from the interpreter function */

		frame_next(stack, frame);
	}

	RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
		stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority);

	return UNLANG_FRAME_ACTION_POP;
}

/*
 *	Interpret the various types of blocks.
 */
rlm_rcode_t unlang_interpret(REQUEST *request)
{
	int			priority;
	unlang_frame_action_t	fa = UNLANG_FRAME_ACTION_NEXT;

	/*
	 *	We don't have a return code yet.
	 */
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];	/* Quiet static analysis */

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("###### unlang_interpret is starting");
	DUMP_STACK;
#endif

	rad_assert(!is_scheduled(request)); /* if we're running it, it can't be scheduled */

	RDEBUG4("** [%i] %s - interpreter entered", stack->depth, __FUNCTION__);

	for (;;) {
		RDEBUG4("** [%i] %s - frame action %s", stack->depth, __FUNCTION__,
			fr_table_str_by_value(unlang_frame_action_table, fa, "<INVALID>"));
		switch (fa) {
		case UNLANG_FRAME_ACTION_NEXT:	/* Evaluate the current frame */
			priority = -1;

			rad_assert(stack->depth > 0);
			rad_assert(stack->depth < UNLANG_STACK_MAX);

			frame = &stack->frame[stack->depth];
			fa = frame_eval(request, frame, &stack->result, &priority);

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
			priority = frame->priority;

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
			 *	If we're done, merge the last stack->result / priority in.
			 */
			if (is_top_frame(frame)) break;	/* stop */

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

			fa = result_calculate(request, frame, &stack->result, &priority);

			/*
			 *	If we're continuing after popping a frame
			 *	then we advance the instruction else we
			 *	end up executing the same code over and over...
			 */
			if (fa == UNLANG_FRAME_ACTION_NEXT) {
				RDEBUG4("** [%i] %s - continuing after subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"),
					priority);
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
			rad_assert(stack->result == RLM_MODULE_YIELD);
			RDEBUG4("** [%i] %s - interpreter yielding", stack->depth, __FUNCTION__);
			return stack->result;
		}
		break;
	}

	/*
	 *	Nothing in this section, use the top frame stack->result.
	 */
	if ((priority < 0) || (stack->result == RLM_MODULE_UNKNOWN)) {
			RDEBUG4("** [%i] %s - empty section, using stack result (%s %d)", stack->depth, __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"), priority);
		stack->result = frame->result;
		priority = frame->priority;
	}

	if (priority > frame->priority) {
		frame->result = stack->result;
		frame->priority = priority;

		RDEBUG4("** [%i] %s - over-riding stack->result from higher priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, stack->result, "<invalid>"),
			priority);
	}

	/*
	 *	We're at the top frame, return the result from the
	 *	stack, and get rid of the top frame.
	 */
	RDEBUG4("** [%i] %s - interpreter exiting, returning %s", stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->result, "<invalid>"));
	stack->result = frame->result;
	stack->depth--;
	DUMP_STACK;

	return stack->result;
}

/** Push a configuration section onto the request stack for later interpretation.
 *
 */
void unlang_interpret_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t default_rcode, bool top_frame)
{
	unlang_t	*instruction = NULL;
	unlang_stack_t	*stack = request->stack;

	static unlang_group_t empty_group = {
		.self = {
			.type = UNLANG_TYPE_GROUP,
			.debug_name = "empty-group",
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
		},
	};

	/*
	 *	Interpretable unlang instructions are stored as CONF_DATA
	 *	associated with sections.
	 */
	if (cs) {
		instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
		if (!instruction) {
			REDEBUG("Failed to find pre-compiled unlang for section %s %s { ... }",
				cf_section_name1(cs), cf_section_name2(cs));
		}
	}

	if (!instruction) instruction = unlang_group_to_generic(&empty_group);

	/*
	 *	Push the default action, and the instruction which has
	 *	no action.
	 */
	if (top_frame) unlang_interpret_push(request, NULL, default_rcode, UNLANG_NEXT_STOP, UNLANG_TOP_FRAME);
	if (instruction) unlang_interpret_push(request,
					       instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME);

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

	DUMP_STACK;
}

/** Call a module, iteratively, with a local stack, rather than recursively
 *
 * What did Paul Graham say about Lisp...?
 */
rlm_rcode_t unlang_interpret_section(REQUEST *request, CONF_SECTION *subcs, rlm_rcode_t default_rcode)
{
	/*
	 *	This pushes a new frame onto the stack, which is the
	 *	start of a new unlang section...
	 */
	unlang_interpret_push_section(request, subcs, default_rcode, UNLANG_TOP_FRAME);

	return unlang_interpret(request);
}

/** Execute an unlang section synchronously
 *
 * Create a temporary event loop and swap it out for the one in the request.
 * Execute unlang operations until we receive a non-yield return code then return.
 *
 * @note The use cases for this are very limited.  If you need to use it, chances
 *	are what you're doing could be done better using one of the thread
 *	event loops.
 *
 * @param[in] request	The current request.
 * @param[in] cs	Section with compiled unlang associated with it.
 * @param[in] action	The default return code to use.
 * @return One of the RLM_MODULE_* macros.
 */
rlm_rcode_t unlang_interpret_synchronous(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	fr_event_list_t *el, *old_el;
	fr_heap_t	*backlog, *old_backlog;
	rlm_rcode_t	rcode;
	char const	*caller;
	REQUEST		*sub_request = NULL;
	bool		wait_for_events;
	int		iterations = 0;

	/*
	 *	Don't talloc from the request
	 *	as we'll almost certainly leave holes in the memory pool.
	 */
	el = fr_event_list_alloc(NULL, NULL, NULL);
	if (!el) {
		RPERROR("Failed creating temporary event loop");
		rad_assert(0);		/* Cause debug builds to die */
		return RLM_MODULE_FAIL;
	}

	MEM(backlog = fr_heap_talloc_create(el, fr_pointer_cmp, REQUEST, runnable_id));
	old_el = request->el;
	old_backlog = request->backlog;
	caller = request->module;

	request->el = el;
	request->backlog = backlog;

	rcode = unlang_interpret_section(request, cs, action);
	wait_for_events = (rcode == RLM_MODULE_YIELD);

	while (true) {
		rlm_rcode_t sub_rcode;
		int num_events;

		/*
		 *	Wait for a timer / IO event.  If there's a
		 *	failure, all kinds of bad things happen.  Oh
		 *	well.
		 */
		DEBUG4("Corralling events (%s wait)", wait_for_events ? "will" : "will not");
		num_events = fr_event_corral(el, fr_time(), wait_for_events);
		if (num_events < 0) {
			RPERROR("Failed retrieving events");
			rcode = RLM_MODULE_FAIL;
			break;
		}

		/*
		 *	We were NOT waiting, AND there are no more
		 *	events to run, AND there are no more requests
		 *	to run.  We can exit the loop.
		 */
		if (!wait_for_events && (num_events == 0) &&
		    (fr_heap_num_elements(backlog) == 0)) {
			break;
		}

		/*
		 *	This function ends up pushing a
		 *	runnable request into the backlog, OR
		 *	setting new timers.
		 */
		if (num_events > 0) {
			DEBUG4("Servicing events");
			fr_event_service(el);
		}

		/*
		 *	If there are no runnable requests, then go
		 *	back to check the timers again.  Note that we
		 *	only wait if there are timer events left to
		 *	service.
		 *
		 *	If there WAS a timer event, but servicing that
		 *	timer event did not result in a runnable
		 *	request, THEN we're guaranteed that there is
		 *	still a timer event left.
		 */
		sub_request = fr_heap_pop(backlog);
		if (!sub_request) {
			wait_for_events = (num_events > 0);
			continue;
		}

		/*
		 *	Continue interpretation until there's nothing
		 *	in the backlog.  If this request YIELDs, then
		 *	do another loop around.
		 */
		RDEBUG4(">>> interpreter (iteration %i)", ++iterations);
		sub_rcode = unlang_interpret(sub_request);
		RDEBUG4("<<< interpreter (iteration %i) - %s", iterations,
			fr_table_str_by_value(mod_rcode_table, sub_rcode, "<INVALID>"));
		if (sub_rcode == RLM_MODULE_YIELD) {
			wait_for_events = true;
			continue;
		}

		/*
		 *	This request is done.  Clean up, and do a
		 *	non-blocking check for more events in the next
		 *	loop.
		 */
		wait_for_events = false;
		if (sub_request == request) {
			rcode = sub_rcode;
		} else {
			RDEBUG4("Cleaning up subrequest");
			talloc_free(sub_request);
		}
	}

	talloc_free(el);
	request->el = old_el;
	request->backlog = old_backlog;
	request->module = caller;

	return rcode;
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
	stack->result = RLM_MODULE_UNKNOWN;

	return stack;
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_module_signal_t callback defined, the action is ignored.
 *
 * The signaling stops at the "limit" frame.  This is so that keywords
 * such as "timeout" and "limit" can signal frames *lower* than theirs
 * to stop, but then continue with their own work.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 * @param[in] limit		the frame at which to stop signaling.
 */
static void frame_signal(REQUEST *request, fr_state_signal_t action, int limit)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	int			i, depth = stack->depth;

	(void)talloc_get_type_abort(request, REQUEST);	/* Check the request hasn't already been freed */

	rad_assert(stack->depth > 0);

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
		stack->depth = i;			/* We could also pass in the frame to the signal function */
		frame = &stack->frame[stack->depth];

		if (is_top_frame(frame)) continue;		/* Skip top frames as they have no instruction */

		/*
		 *	Be gracious in errors.
		 */
		if (!is_yielded(frame)) continue;

		if (!frame->signal) continue;

		frame->signal(request, action);
	}
	stack->depth = depth;				/* Reset */
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
void unlang_interpret_signal(REQUEST *request, fr_state_signal_t action)
{
	/*
	 *	If we're stopping, then mark the request as stopped.
	 *	Then, call the frame signal handler.  The keyword will
	 *	then take care of calling us for any children, which
	 *	will then be marked as STOP_PROCESSING.
	 */
	if (action == FR_SIGNAL_CANCEL) {
		request->master_state = REQUEST_STOP_PROCESSING;
	}

	frame_signal(request, action, 0);
}

/** Return the depth of the request's stack
 *
 */
int unlang_interpret_stack_depth(REQUEST *request)
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
rlm_rcode_t unlang_interpret_stack_result(REQUEST *request)
{

	unlang_stack_t		*stack = request->stack;

	return stack->result;
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
void unlang_interpret_resumable(REQUEST *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	/*
	 *	Child requests aren't runnable, only parent requests
	 *	are.
	 */
	while (request->parent) {
		rad_assert(!is_scheduled(request));
		request->runnable_id = -2; /* hack for now, see unlang_parallel_process() */
		request = request->parent;
	}

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
	if (!is_yielded(frame) || is_scheduled(request)) {
		RDEBUG3("Not marking resumable due to %d %d",
			is_yielded(frame), is_scheduled(request));
		return;
	}

	if (!is_scheduled(request)) {
		RDEBUG3("marking as resumable");
	}

	rad_assert(request->backlog != NULL);

	fr_heap_insert(request->backlog, request);
}


/** Get information about the interpreter state
 *
 */
static ssize_t unlang_interpret_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				     REQUEST *request, char const *fmt)
{
	unlang_stack_t		*stack = request->stack;
	int			depth = stack->depth;
	unlang_stack_frame_t	*frame;
	unlang_t		*instruction;

	fr_skip_whitespace(fmt);

	/*
	 *	Find the correct stack frame.
	 */
	while (*fmt == '.') {
		if (depth <= 1) {
			return snprintf(*out, outlen, "<underflow>");
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
		**out = '\0';
		return 0;
	}

	/*
	 *	Name of the instruction.
	 */
	if (strcmp(fmt, "name") == 0) {
		return snprintf(*out, outlen, "%s", instruction->name);
	}

	/*
	 *	Unlang type.
	 */
	if (strcmp(fmt, "type") == 0) {
		return snprintf(*out, outlen, "%s", unlang_ops[instruction->type].name);
	}

	/*
	 *	How deep the current stack is.
	 */
	if (strcmp(fmt, "depth") == 0) {
		return snprintf(*out, outlen, "%d", depth);
	}

	/*
	 *	Line number of the current section.
	 */
	if (strcmp(fmt, "line") == 0) {
		unlang_group_t *g;

		if (!unlang_ops[instruction->type].debug_braces) {
			return snprintf(*out, outlen, "???");
		}

		g = unlang_generic_to_group(instruction);
		rad_assert(g->cs != NULL);

		return snprintf(*out, outlen, "%d", cf_lineno(g->cs));
	}

	/*
	 *	Filename of the current section.
	 */
	if (strcmp(fmt, "filename") == 0) {
		unlang_group_t *g;

		if (!unlang_ops[instruction->type].debug_braces) {
			return snprintf(*out, outlen, "???");
		}

		g = unlang_generic_to_group(instruction);
		rad_assert(g->cs != NULL);

		return snprintf(*out, outlen, "%s", cf_filename(g->cs));
	}

	**out = '\0';
	return 0;
}

void unlang_interpret_init(void)
{
	(void) xlat_register(NULL, "interpreter", unlang_interpret_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
}
