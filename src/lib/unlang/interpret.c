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
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/xlat.h>
#include <freeradius-devel/io/listen.h>

#include "unlang_priv.h"

static FR_NAME_NUMBER unlang_action_table[] = {
	{ "calculate-result",	UNLANG_ACTION_CALCULATE_RESULT },
	{ "continue",		UNLANG_ACTION_CONTINUE },
	{ "pushed-child",	UNLANG_ACTION_PUSHED_CHILD },
	{ "break", 		UNLANG_ACTION_BREAK },
	{ "yield",		UNLANG_ACTION_YIELD },
	{ "stop",		UNLANG_ACTION_STOP_PROCESSING },
	{ NULL, -1 }
};

#ifndef NDEBUG
static void unlang_dump_instruction(REQUEST *request, unlang_t *instruction)
{
	RINDENT();
	if (!instruction) {
		RDEBUG("instruction = NULL");
		REXDENT();
		return;
	}
	RDEBUG("type           %s", unlang_ops[instruction->type].name);
	RDEBUG("name           %s", instruction->name);
	RDEBUG("debug_name     %s", instruction->debug_name);
	REXDENT();
}

static void unlang_dump_frame(REQUEST *request, unlang_stack_frame_t *frame)
{
	unlang_dump_instruction(request, frame->instruction);

	RINDENT();
	if (frame->next) {
		RDEBUG("next           %s", frame->next->debug_name);
	} else {
		RDEBUG("next           <none>");
	}
	RDEBUG("top_frame      %s", frame->top_frame ? "yes" : "no");
	RDEBUG("result         %s", fr_int2str(mod_rcode_table, frame->result, "<invalid>"));
	RDEBUG("priority       %d", frame->priority);
	RDEBUG("unwind         %d", frame->unwind);
	RDEBUG("repeat         %s", frame->repeat ? "yes" : "no");
	REXDENT();
}


static void unlang_dump_stack(REQUEST *request)
{
	int i;
	unlang_stack_t *stack = request->stack;

	RDEBUG("----- Begin stack debug [depth %i] -----", stack->depth);
	for (i = stack->depth; i >= 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];

		RDEBUG("[%d] Frame contents", i);
		unlang_dump_frame(request, frame);
	}

	RDEBUG("----- End stack debug [depth %i] -------", stack->depth);
}
#define DUMP_STACK if (DEBUG_ENABLED5) unlang_dump_stack(request)
#else
#define DUMP_STACK
#endif

/** Different operations the interpreter can execute
 */
unlang_op_t unlang_ops[UNLANG_TYPE_MAX];

/** Allocates and initializes an unlang_resume_t
 *
 * @param[in] request		The current request.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] signal		call on unlang_action().
 * @param[in] rctx		to pass to the callbacks.
 * @return
 *	unlang_resume_t on success
 *	NULL on error
 */
unlang_resume_t *unlang_resume_alloc(REQUEST *request, void *callback, void *signal, void *rctx)
{
	unlang_resume_t 		*mr;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	mr = talloc_zero(request, unlang_resume_t);
	if (!mr) return NULL;

	/*
	 *	Remember the parent.
	 */
	mr->parent = frame->instruction;

	/*
	 *	Initialize parent ptr, next ptr, name, debug_name,
	 *	type, actions, etc.
	 */
	memcpy(&mr->self, frame->instruction, sizeof(mr->self));

	/*
	 *	But note that we're of type RESUME
	 */
	mr->self.type = UNLANG_TYPE_RESUME;

	/*
	 *	Fill in the signal handlers and resumption ctx
	 */
	mr->callback = (void *)callback;
	mr->signal = (void *)signal;
	mr->rctx = rctx;

	/*
	 *	Replaces the current stack frame with a RESUME frame.
	 */
	frame->instruction = unlang_resume_to_generic(mr);
	frame->repeat = true;

	return mr;
}

/** Push a new frame onto the stack
 *
 * @param[in] stack		to push the frame onto.
 * @param[in] program		One or more unlang_t nodes describing the operations to execute.
 * @param[in] result		The default result.
 * @param[in] do_next_sibling	Whether to only execute the first node in the #unlang_t program
 *				or to execute subsequent nodes.
 * @param[in] top_frame		Return out of the unlang interpreter when popping this frame.
 *				Hands execution back to whatever called the interpreter.
 */
void unlang_push(unlang_stack_t *stack, unlang_t *program, rlm_rcode_t result, bool do_next_sibling, bool top_frame)
{
	unlang_stack_frame_t *frame;

	rad_assert(program || top_frame);

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("unlang_push called with instruction %s - args %s %s",
				  program ? program->debug_name : "<none>",
				  do_next_sibling ? "UNLANG_NEXT_CONTINUE" : "UNLANG_NEXT_STOP",
				  top_frame ? "UNLANG_TOP_FRAME" : "UNLANG_SUB_FRAME");
#endif

	if (stack->depth >= (UNLANG_STACK_MAX - 1)) {
		ERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(EXIT_FAILURE);
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	frame = &stack->frame[stack->depth];

	if (do_next_sibling) {
		rad_assert(program != NULL);
		frame->next = program->next;
	} else {
		frame->next = NULL;
	}

	frame->top_frame = top_frame;
	frame->instruction = program;
	frame->result = result;
	frame->priority = -1;
	frame->unwind = UNLANG_TYPE_NULL;
	frame->repeat = false;
	frame->state = NULL;
}

/** Pop a stack frame, removing any associated dynamically allocated state
 *
 * @param[in] stack	frame to pop.
 */
static inline void unlang_pop(unlang_stack_t *stack)
{
	unlang_stack_frame_t *frame, *next;

	rad_assert(stack->depth > 1);

	frame = &stack->frame[stack->depth];
	if (frame->state) talloc_free(frame->state);

	frame = &stack->frame[--stack->depth];
	next = frame + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) frame->unwind = next->unwind;
}

/** Update the current result after each instruction, and after popping each stack frame
 *
 * @param[in] request		The current request.
 * @param[in] frame		The curren stack frame.
 * @param[in,out] result	The current section result.
 * @param[in,out] priority	The current section priority.
 * @return
 *	- UNLANG_FRAME_ACTION_CONTINUE	evaluate more instructions.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline unlang_frame_action_t unlang_calculate_result(REQUEST *request, unlang_stack_frame_t *frame,
							    rlm_rcode_t *result, int *priority)
{
	unlang_t	*instruction = frame->instruction;
	unlang_stack_t	*stack = request->stack;

	RDEBUG4("** [%i] %s - have (%s %d) module returned (%s %d)",
		stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority,
		fr_int2str(mod_rcode_table, *result, "<invalid>"),
		*priority);

	/*
	 *	Don't set action or priority if we don't have one.
	 */
	if (*result == RLM_MODULE_UNKNOWN) return UNLANG_FRAME_ACTION_CONTINUE;

	/*
	 *	The child's action says return.  Do so.
	 */
	if (instruction->actions[*result] == MOD_ACTION_RETURN) {
		if (*priority < 0) *priority = 0;

		RDEBUG4("** [%i] %s - action says to return with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, *result, "<invalid>"),
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
			fr_int2str(mod_rcode_table, RLM_MODULE_REJECT, "<invalid>"),
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
			fr_int2str(mod_rcode_table, *result, "<invalid>"),
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
			fr_int2str(mod_rcode_table, *result, "<invalid>"),
			*priority);
	}

	/*
	 *	If we've been told to stop processing
	 *	it, do so.
	 */
	if (frame->unwind != 0) {
		RDEBUG4("** [%i] %s - unwinding current frame with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
			frame->priority);
		return UNLANG_FRAME_ACTION_POP;
	}

	return frame->next ? UNLANG_FRAME_ACTION_CONTINUE : UNLANG_FRAME_ACTION_POP;
}

/** Evaluates all the unlang nodes in a section
 *
 * @param[in] request		The current request.
 * @param[in] frame		The curren stack frame.
 * @param[in,out] result	The current section result.
 * @param[in,out] priority	The current section priority.
 * @return
 *	- UNLANG_FRAME_ACTION_CONTINUE	evaluate more instructions in the current stack frame
 *					which may not be the same frame as when this function
 *					was called.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline unlang_frame_action_t unlang_frame_eval(REQUEST *request, unlang_stack_frame_t *frame,
						      rlm_rcode_t *result, int *priority)
{
	unlang_stack_t	*stack = request->stack;

	/*
	 *	Loop over all the instructions in this list.
	 */
	while (frame->instruction) {
		REQUEST			*parent;
		unlang_t		*instruction = frame->instruction;
		unlang_action_t		action = UNLANG_ACTION_BREAK;

		DUMP_STACK;

		rad_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */

		REQUEST_VERIFY(request);

		/*
		 *	We may be multiple layers deep in create{} or
		 *	parallel{}.  Only the top-level request is
		 *	tracked && marked "stop processing".
		 */
		parent = request;
		while (parent->parent) parent = parent->parent;

		/*
		 *	We've been asked to stop.  Do so.
		 */
		if (parent->master_state == REQUEST_STOP_PROCESSING) {
		do_stop:
			frame->result = RLM_MODULE_FAIL;
			frame->priority = 9999;
			frame->unwind = UNLANG_TYPE_RETURN;
			break;
		}

		if (!frame->repeat && (unlang_ops[instruction->type].debug_braces)) {
			RDEBUG2("%s {", instruction->debug_name);
			RINDENT();
		}

		/*
		 *	Execute an operation
		 */
		RDEBUG4("** [%i] %s >> %s", stack->depth, __FUNCTION__,
			unlang_ops[instruction->type].name);

		action = unlang_ops[instruction->type].func(request, result, priority);

		RDEBUG4("** [%i] %s << %s (%d)", stack->depth, __FUNCTION__,
			fr_int2str(unlang_action_table, action, "<INVALID>"), *priority);

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
			return UNLANG_FRAME_ACTION_CONTINUE;

		/*
		 *	We're in a looping construct and need to stop
		 *	execution of the current section.
		 */
		case UNLANG_ACTION_BREAK:
			if (*priority < 0) *priority = 0;
			frame->result = *result;
			frame->priority = *priority;
			frame->next = NULL;
			return UNLANG_FRAME_ACTION_POP;

		/*
		 *	Yield control back to the scheduler, or whatever
		 *	called the interpreter.
		 */
		case UNLANG_ACTION_YIELD:
			*result = RLM_MODULE_YIELD;	/* Fixup rcode */
		yield:
			/*
			 *	Detach is magic.  The parent "create" function
			 *	takes care of bumping the instruction
			 *	pointer...
			 */
			switch (frame->instruction->type) {
			case UNLANG_TYPE_DETACH:
				RDEBUG4("** [%i] %s - detaching child with current (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
				DUMP_STACK;

				return UNLANG_FRAME_ACTION_YIELD;

			case UNLANG_TYPE_RESUME:
				frame->repeat = true;
				RDEBUG4("** [%i] %s - yielding with current (%s %d)", stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
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
			/* Temporary fixup - ops should return the correct code */
			if (*result == RLM_MODULE_YIELD) goto yield;

			frame->repeat = false;

			if (unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("} # %s (%s)", instruction->debug_name,
					fr_int2str(mod_rcode_table, *result, "<invalid>"));
			}

			if (unlang_calculate_result(request, frame, result, priority) == UNLANG_FRAME_ACTION_POP) {
				return UNLANG_FRAME_ACTION_POP;
			}
			/* FALL-THROUGH */

		/*
		 *	Execute the next instruction in this frame
		 */
		case UNLANG_ACTION_CONTINUE:
			if ((action == UNLANG_ACTION_CONTINUE) && unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("}");
			}
			break;
		} /* switch over return code from the interpreter function */

		frame->instruction = frame->next;
		if (frame->instruction) frame->next = frame->instruction->next;
	}

	RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
		stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority);

	return UNLANG_FRAME_ACTION_POP;
}

/*
 *	Interpret the various types of blocks.
 */
rlm_rcode_t unlang_run(REQUEST *request)
{
	int			priority;
	unlang_frame_action_t	fa = UNLANG_FRAME_ACTION_CONTINUE;

	/*
	 *	We don't have a return code yet.
	 */
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];	/* Quiet static analysis */

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("###### unlang_run is starting");
	DUMP_STACK;
#endif

	rad_assert(request->runnable_id < 0);

	RDEBUG4("** [%i] %s - interpreter entered", stack->depth, __FUNCTION__);

	for (;;) {
		switch (fa) {
		case UNLANG_FRAME_ACTION_CONTINUE:	/* Evaluate the current frame */
			priority = -1;

			rad_assert(stack->depth > 0);
			rad_assert(stack->depth < UNLANG_STACK_MAX);

			frame = &stack->frame[stack->depth];
			fa = unlang_frame_eval(request, frame, &stack->result, &priority);

			/*
			 *	We were executing a frame, unlang_frame_eval()
			 *	indicated we should pop it, but we're now at
			 *	a top_frame, so we need to break out of the loop
			 *	and calculate the final result for this substack.
			 */
			if ((fa == UNLANG_FRAME_ACTION_POP) && frame->top_frame) break;	/* return */
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
			unlang_pop(stack);
			frame = &stack->frame[stack->depth];
			DUMP_STACK;

			/*
			 *	Resume a "foreach" loop, or a "load-balance" section
			 *	or anything else that needs to be checked on the way
			 *	back on up the stack.
			 */
			if (frame->repeat) {
				fa = UNLANG_FRAME_ACTION_CONTINUE;
				continue;
			}

			/*
			 *	If we're done, merge the last stack->result / priority in.
			 */
			if (frame->top_frame) break;	/* return */

			/*
			 *	Close out the section we entered earlier
			 */
			if (unlang_ops[frame->instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("} # %s (%s)", frame->instruction->debug_name,
					fr_int2str(mod_rcode_table, stack->result, "<invalid>"));
			}

			fa = unlang_calculate_result(request, frame, &stack->result, &priority);
			/*
			 *	If we're continuing after popping a frame
			 *	then we advance the instruction else we
			 *	end up executing the same code over and over...
			 */
			if (fa == UNLANG_FRAME_ACTION_CONTINUE) {
				RDEBUG4("** [%i] %s - continuing after subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, stack->result, "<invalid>"),
					priority);
				frame->instruction = frame->next;
				if (frame->instruction) frame->next = frame->instruction->next;
			/*
			 *	Else if we're really done with this frame
			 *	print some helpful debug...
			 */
			} else {
				RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
			}
			continue;

		case UNLANG_FRAME_ACTION_YIELD:
			rad_assert(stack->result == RLM_MODULE_YIELD);
			return stack->result;
		}
		break;
	}

	/*
	 *	Nothing in this section, use the top frame stack->result.
	 */
	if ((priority < 0) || (stack->result == RLM_MODULE_UNKNOWN)) {
		stack->result = frame->result;
		priority = frame->priority;
	}

	if (priority > frame->priority) {
		frame->result = stack->result;
		frame->priority = priority;

		RDEBUG4("** [%i] %s - over-riding stack->result from higher priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, stack->result, "<invalid>"),
			priority);
	}

	/*
	 *	We're at the top frame, return the result from the
	 *	stack, and get rid of the top frame.
	 */
	RDEBUG4("** [%i] %s - interpreter exiting, returning %s", stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"));
	stack->result = frame->result;
	stack->depth--;
	DUMP_STACK;

	return stack->result;
}

static unlang_group_t empty_group = {
	.self = {
		.type = UNLANG_TYPE_GROUP,
		.debug_name = "empty-group",
		.actions = { MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN,
			     MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN,
			     MOD_ACTION_RETURN
		},
	},
	.group_type = UNLANG_GROUP_TYPE_SIMPLE,
};

/** Return whether a section has unlang data associated with it
 *
 * @param[in] cs	to check.
 * @return
 *	- true if it has data.
 *	- false if it doesn't have data.
 */
bool unlang_section(CONF_SECTION *cs)
{
	unlang_t	*instruction = NULL;

	instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
	if (instruction) return true;

	return false;
}

/** Push a configuration section onto the request stack for later interpretation.
 *
 */
void unlang_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action, bool top_frame)
{
	unlang_t	*instruction = NULL;
	unlang_stack_t	*stack = request->stack;

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
	if (top_frame) unlang_push(stack, NULL, action, UNLANG_NEXT_STOP, UNLANG_TOP_FRAME);
	if (instruction) unlang_push(stack, instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

	DUMP_STACK;
}

/** Continue interpreting after a previous push or yield.
 *
 */
rlm_rcode_t unlang_interpret_continue(REQUEST *request)
{
	return unlang_run(request);
}

/** Call a module, iteratively, with a local stack, rather than recursively
 *
 * What did Paul Graham say about Lisp...?
 */
rlm_rcode_t unlang_interpret(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	/*
	 *	This pushes a new frame onto the stack, which is the
	 *	start of a new unlang section...
	 */
	unlang_push_section(request, cs, action, UNLANG_TOP_FRAME);

	return unlang_run(request);
}

static int _unlang_request_ptr_cmp(void const *a, void const *b)
{
	return (a > b) - (a < b);
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

	MEM(backlog = fr_heap_talloc_create(el, _unlang_request_ptr_cmp, REQUEST, runnable_id));
	old_el = request->el;
	old_backlog = request->backlog;
	caller = request->module;

	request->el = el;
	request->backlog = backlog;

	rcode = unlang_interpret(request, cs, action);
	while (rcode == RLM_MODULE_YIELD) {
		REQUEST *sub_request = NULL;

		if (fr_event_corral(el, true) < 0) {			/* Wait for a timer/IO event */
			RPERROR("Failed retrieving events");
			rcode = RLM_MODULE_FAIL;
			break;
		}

		fr_event_service(el);

		while ((sub_request = fr_heap_pop(backlog))) {
			rlm_rcode_t srcode;

			srcode = unlang_interpret_continue(sub_request);
			if (sub_request == request) {
				rcode = srcode;
				break;
			}
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
void *unlang_stack_alloc(TALLOC_CTX *ctx)
{
	unlang_stack_t *stack;

#ifdef HAVE_TALLOC_POOLED_OBJECT
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
	stack = talloc_pooled_object(ctx, unlang_stack_t, UNLANG_STACK_MAX / 4, sizeof(unlang_frame_state_t));
#else
	stack = talloc_zero(ctx, unlang_stack_t);
#endif

	stack->result = RLM_MODULE_UNKNOWN;

	return stack;
}

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct unlang_event_t {
	REQUEST				*request;			//!< Request this event pertains to.
	int				fd;				//!< File descriptor to wait on.
	fr_unlang_module_timeout_t	timeout;			//!< Function to call on timeout.
	fr_unlang_module_fd_event_t	fd_read;			//!< Function to call when FD is readable.
	fr_unlang_module_fd_event_t	fd_write;			//!< Function to call when FD is writable.
	fr_unlang_module_fd_event_t	fd_error;			//!< Function to call when FD has errored.
	void const			*inst;				//!< Module instance to pass to callbacks.
	void				*thread;			//!< Thread specific module instance.
	void const			*ctx;				//!< ctx data to pass to callbacks.
	fr_event_timer_t const		*ev;				//!< Event in this worker's event heap.
} unlang_event_t;

/** Frees an unlang event, removing it from the request's event loop
 *
 * @param[in] ev	The event to free.
 *
 * @return 0
 */
static int _unlang_event_free(unlang_event_t *ev)
{
	if (ev->ev) {
		(void) fr_event_timer_delete(ev->request->el, &(ev->ev));
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
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 *
 */
static void unlang_event_timeout_handler(UNUSED fr_event_list_t *el, struct timeval *now, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->timeout(ev->request, mutable_inst, ev->thread, mutable_ctx, now);
	talloc_free(ev);
}

/** Call the callback registered for a read I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_read_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_read(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Call the callback registered for a write I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_write_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_write(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Call the callback registered for an I/O error event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_error_handler(UNUSED fr_event_list_t *el, int fd,
					  UNUSED int flags, UNUSED int fd_errno, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_error(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Set a timeout for the request.
 *
 * Used when a module needs wait for an event.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * param[in] request		the current request.
 * param[in] callback		to call.
 * param[in] ctx		for the callback.
 * param[in] timeout		when to call the timeout (i.e. now + timeout).
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_module_timeout_add(REQUEST *request, fr_unlang_module_timeout_t callback,
				    void const *ctx, struct timeval *when)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_event_t			*ev;
	unlang_module_t		*sp;
	unlang_frame_state_module_t	*ms = talloc_get_type_abort(frame->state,
								    unlang_frame_state_module_t);

	rad_assert(stack->depth > 0);
	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE) ||
		   (frame->instruction->type == UNLANG_TYPE_RESUME));
	sp = unlang_generic_to_module(frame->instruction);

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout = callback;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = ms->thread;
	ev->ctx = ctx;

	if (fr_event_timer_insert(request, request->el, &ev->ev,
				  when, unlang_event_timeout_handler, ev) < 0) {
		RPEDEBUG("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	(void) request_data_talloc_add(request, ctx, -1, unlang_event_t, ev, true, false, false);

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
int unlang_event_timeout_delete(REQUEST *request, void const *ctx)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, -1);
	if (!ev) return -1;
	talloc_free(ev);

	return 0;
}

/** Set a callback for the request.
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
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
int unlang_event_fd_add(REQUEST *request,
			fr_unlang_module_fd_event_t read,
			fr_unlang_module_fd_event_t write,
			fr_unlang_module_fd_event_t error,
			void const *ctx, int fd)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_event_t			*ev;
	unlang_module_t		*sp;
	unlang_frame_state_module_t	*ms = talloc_get_type_abort(frame->state,
								    unlang_frame_state_module_t);

	rad_assert(stack->depth > 0);

	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE) ||
		   (frame->instruction->type == UNLANG_TYPE_RESUME));
	sp = unlang_generic_to_module(frame->instruction);

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_read = read;
	ev->fd_write = write;
	ev->fd_error = error;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = ms->thread;
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

	(void) request_data_talloc_add(request, ctx, fd, unlang_event_t, ev, true, false, false);
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
int unlang_event_fd_delete(REQUEST *request, void const *ctx, int fd)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, fd);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
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
static void unlang_signal_frames(REQUEST *request, fr_state_signal_t action, int limit)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	unlang_resume_t		*mr;
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

		if (frame->top_frame) continue;		/* Skip top frames */

		/*
		 *	Be gracious in errors.
		 */
		if (frame->instruction->type != UNLANG_TYPE_RESUME) continue;

		mr = unlang_generic_to_resume(frame->instruction);

		/*
		 *	No signal handler for this frame type
		 */
		if (!unlang_ops[mr->parent->type].signal) continue;

		unlang_ops[mr->parent->type].signal(request, mr->rctx, action);
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
void unlang_signal(REQUEST *request, fr_state_signal_t action)
{
	unlang_signal_frames(request, action, 0);
}

int unlang_stack_depth(REQUEST *request)
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
rlm_rcode_t unlang_stack_result(REQUEST *request)
{

	unlang_stack_t		*stack = request->stack;

	return stack->result;
}

/*
 *	Temporary until the correct behaviour for unlang_resumable
 *	can be determined.
 */

/** Parallel children have states
 *
 */
typedef enum unlang_parallel_child_state_t {
	CHILD_INIT = 0,				//!< needs initialization
	CHILD_RUNNABLE,
	CHILD_YIELDED,
	CHILD_DONE
} unlang_parallel_child_state_t;

/** Each parallel child has a state, and an associated request
 *
 */
typedef struct unlang_parallel_child_t {
	unlang_parallel_child_state_t	state;		//!< state of the child
	REQUEST				*child; 	//!< child request
	unlang_t			*instruction;	//!< broken out of g->children
} unlang_parallel_child_t;

typedef struct unlang_parallel_t {
	rlm_rcode_t		result;
	int			priority;

	int			num_children;

	unlang_group_t		*g;

	unlang_parallel_child_t children[];
} unlang_parallel_t;

/** Mark a request as resumable.
 *
 * It's not called "unlang_resume", because it doesn't actually
 * resume the request, it just schedules it for resumption.
 *
 * @note that this schedules the request for resumption.  It does not immediately
 *	start running the request.
 *
 * @param[in] request		The current request.
 */
void unlang_resumable(REQUEST *request)
{
	REQUEST				*parent = request->parent;
	unlang_stack_t			*stack;
	unlang_stack_frame_t		*frame;

	while (parent) {
		int i;
		unlang_resume_t		*mr;
		unlang_parallel_t	*state;
#ifndef NDEBUG
		bool			found = false;
#endif

		/*
		 *	Child requests CANNOT be runnable.  Only the
		 *	parent request can be runnable.  When it runs
		 *	(eventually), the interpreter will walk back
		 *	down the stack, resuming anything that needs resuming.
		 */
		rad_assert(request->backlog == NULL);
		rad_assert(request->runnable_id < 0);

#ifndef NDEBUG
		/*
		 *	Look at the current stack.
		 */
		stack = request->stack;
		frame = &stack->frame[stack->depth];

		/*
		 *	The current request MUST have been yielded in
		 *	order for someone to mark it resumable.
		 */
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);
#endif

		/*
		 *	Now look at the parents stack.  It also must
		 *	have been yielded in order for someone to mark
		 *	the child as resumable.
		 */
		stack = parent->stack;
		frame = &stack->frame[stack->depth];
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		mr = unlang_generic_to_resume(frame->instruction);
		(void) talloc_get_type_abort(mr, unlang_resume_t);

		if (mr->parent->type != UNLANG_TYPE_PARALLEL) goto next;

		state = mr->rctx;

		/*
		 *	Find the child and mark it resumable
		 */
		for (i = 0; i < state->num_children; i++) {
			if (state->children[i].state != CHILD_YIELDED) continue;
			if (state->children[i].child != request) continue;

			state->children[i].state = CHILD_RUNNABLE;
#ifndef NDEBUG
			found = true;
#endif
			break;
		}

		/*
		 *	We MUST have found the child here.
		 */
		rad_assert(found == true);

	next:
		request = parent;
		parent = parent->parent;
	}


#ifndef NDEBUG
	/*
	 *	The current request MUST have been yielded in
	 *	order for someone to mark it resumable.
	 */
	stack = request->stack;
	frame = &stack->frame[stack->depth];
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);
#endif

	rad_assert(request->backlog != NULL);

	/*
	 *	Multiple child request may mark a request runnable,
	 *	before it is enabled for running.
	 */
	if (request->runnable_id < 0) fr_heap_insert(request->backlog, request);
}

/** Callback for handling resumption frames
 *
 * Resumption frames are added to track when a module, or other construct
 * has yielded control back to the interpreter.
 *
 * This function is called when the request has been marked as resumable
 * and a resumption frame was previously placed on the stack, i.e. when
 * the work that caused the request to be yielded initially has completed.
 *
 * @param[in] request	to be resumed.
 * @param[out] presult	the rcode returned by the resume function.
 * @param[out] priority associated with the rcode.
 */
static unlang_action_t unlang_resume(REQUEST *request, rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_resume_t			*mr = unlang_generic_to_resume(instruction);
	unlang_action_t			action;

	RDEBUG3("Resuming in %s", mr->self.debug_name);

	if (!unlang_ops[mr->parent->type].resume) {
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Run the resume callback associated with
	 *	the original frame which was used to
	 *	create this resumption frame.
	 */
	action = unlang_ops[mr->parent->type].resume(request, presult, mr->rctx);

	/*
	 *	Leave mr alone, it will be freed when the request is done.
	 */

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked", mr->self.debug_name);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	if (*presult != RLM_MODULE_YIELD) {
		rad_assert(*presult >= RLM_MODULE_REJECT);
		rad_assert(*presult < RLM_MODULE_NUMCODES);
		*priority = instruction->actions[*presult];
	}

	return action;
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
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] cancel		to call on unlang_action().
 * @param[in] rctx	to pass to the callbacks.
 * @return
 *	- RLM_MODULE_YIELD on success.
 *	- RLM_MODULE_FAIL (or asserts) if the current frame is not a module call or
 *	  resume frame.
 */
rlm_rcode_t unlang_module_yield(REQUEST *request, fr_unlang_module_resume_t callback,
				fr_unlang_module_signal_t cancel, void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_resume_t			*mr;

	rad_assert(stack->depth > 0);

	REQUEST_VERIFY(request);	/* Check the yielded request is sane */

	switch (frame->instruction->type) {
	case UNLANG_TYPE_MODULE:
		mr = unlang_resume_alloc(request, (void *)callback, (void *)cancel, rctx);
		if (!fr_cond_assert(mr)) {
			return RLM_MODULE_FAIL;
		}
		return RLM_MODULE_YIELD;

	case UNLANG_TYPE_RESUME:
		mr = talloc_get_type_abort(frame->instruction, unlang_resume_t);
		rad_assert(mr->parent->type == UNLANG_TYPE_MODULE);

		/*
		 *	Re-use the current RESUME frame, but over-ride
		 *	the callbacks and context.
		 */
		mr->callback = (void *)callback;
		mr->signal = (void *)signal;
		mr->rctx = rctx;

		return RLM_MODULE_YIELD;

	default:
		rad_assert(0);
		return RLM_MODULE_FAIL;
	}
}

/** Get information about the interpreter state
 *
 */
static ssize_t xlat_interpreter(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	unlang_stack_t		*stack = request->stack;
	int			depth = stack->depth;
	unlang_stack_frame_t	*frame;
	unlang_t		*instruction;

	while (isspace((int) *fmt)) fmt++;

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

/** Register an operation with the interpreter
 *
 * The main purpose of this registration API is to avoid intermixing the xlat,
 * condition, map APIs with the interpreter, i.e. the callbacks needed for that
 * functionality can be in their own source files, and we don't need to include
 * supporting types and function declarations in the interpreter.
 *
 * Later, this could potentially be used to register custom operations for modules.
 *
 * The reason why there's a function instead of accessing the unlang_op array
 * directly, is because 'type' really needs to go away, as needing to add ops to
 * the unlang_type_t enum breaks the pluggable module model. If there's no
 * explicit/consistent type values we need to enumerate the operations ourselves.
 *
 * @param[in] type		Operation identifier.  Used to map compiled unlang code
 *				to operations.
 * @param[in] op		unlang_op to register.
 */
void unlang_op_register(int type, unlang_op_t *op)
{
	rad_assert(type < UNLANG_TYPE_MAX);	/* Unlang max isn't a valid type */

	memcpy(&unlang_ops[type], op, sizeof(unlang_ops[type]));
}

/** Initialize the unlang compiler / interpreter.
 *
 *  For now, just register the magic xlat function.
 */
int unlang_init(void)
{
	(void) xlat_register(NULL, "interpreter", xlat_interpreter, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	unlang_op_register(UNLANG_TYPE_RESUME, &(unlang_op_t){ .name = "resume", .func = unlang_resume });

	/* Register operations for the default keywords */
	if (unlang_op_init() < 0) return -1;

	return 0;
}

void unlang_free(void)
{
	unlang_op_free();
}
