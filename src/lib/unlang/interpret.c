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

#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/timer.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/mod_action.h>

#include "interpret_priv.h"
#include "unlang_priv.h"
#include "module_priv.h"


/** The default interpreter instance for this thread
 */
static _Thread_local unlang_interpret_t *intp_thread_default;

static fr_table_num_ordered_t const unlang_action_table[] = {
	{ L("fail"),			UNLANG_ACTION_FAIL },
	{ L("calculate-result"),	UNLANG_ACTION_CALCULATE_RESULT },
	{ L("next"),			UNLANG_ACTION_EXECUTE_NEXT },
	{ L("pushed-child"),		UNLANG_ACTION_PUSHED_CHILD },
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
#include <freeradius-devel/unlang/module_priv.h>

typedef enum {
	P_RESULT_LOCATION_UNKNOWN = 0,
	P_RESULT_LOCATION_FRAME,
	P_RESULT_LOCATION_SCRATCH,
	P_RESULT_LOCATION_STATE,
	P_RESULT_LOCATION_MODULE_RCTX,
	P_RESULT_LOCATION_FUNCTION_RCTX
} p_result_location_t;

/** Try and figure out where p_result points to
 *
 * If it's somewhere other than these three locations, it's probably wrong.
 */
static int find_p_result_location(p_result_location_t *location, void **chunk, request_t *request, void *ptr)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame;
	unsigned int		i;

	for (i = 0; i <= (unsigned int)stack->depth; i++) {
		frame = &stack->frame[i];
		if (frame->state && (ptr >= (void *)frame->state) &&
		    (ptr < ((void *)((uint8_t *)frame->state + talloc_get_size(frame->state))))) {
			*location = P_RESULT_LOCATION_STATE;
			*chunk = frame->state;
			return i;
		}

		if (ptr == &frame->section_result) {
			*location = P_RESULT_LOCATION_FRAME;
			*chunk = NULL;
			return i;
		}

		if (ptr == &frame->scratch_result) {
			*location = P_RESULT_LOCATION_SCRATCH;
			*chunk = NULL;
			return i;
		}

		if (!frame->instruction) continue;

		switch (frame->instruction->type) {
		case UNLANG_TYPE_MODULE:
		{
			unlang_frame_state_module_t *mod_state = talloc_get_type_abort(frame->state, unlang_frame_state_module_t);

			if (!mod_state->rctx) continue;

			if ((ptr >= (void *)mod_state->rctx) &&
			    (ptr < ((void *)((uint8_t *)mod_state->rctx + talloc_get_size(mod_state->rctx))))) {
				*location = P_RESULT_LOCATION_MODULE_RCTX;
				*chunk = mod_state->rctx;
				return i;
			}

			/*
			 *	We don't know where the child frame is, so we can't
			 *	determine where the p_result is.
			 */
		}
			continue;

		default:
			break;
		}
	}

	*location = P_RESULT_LOCATION_UNKNOWN;
	*chunk = NULL;
	return -1;
}

static fr_table_num_ordered_t const p_result_location_table[] = {
	{ L("frame"),		P_RESULT_LOCATION_FRAME },
	{ L("module_rctx"),	P_RESULT_LOCATION_MODULE_RCTX },
	{ L("scratch"),		P_RESULT_LOCATION_SCRATCH },
	{ L("state"),		P_RESULT_LOCATION_STATE },
	{ L("unknown"),		P_RESULT_LOCATION_UNKNOWN }
};
static size_t p_result_location_table_len = NUM_ELEMENTS(p_result_location_table);

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

static void CC_HINT(nonnull) actions_dump(request_t *request, unlang_t const *instruction)
{
	int i;

	RDEBUG2("actions");
	RINDENT();
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		RDEBUG2("%s: %s",
			fr_table_str_by_value(mod_rcode_table, i, "<invalid>"),
			mod_action_name[instruction->actions.actions[i]]);
	}
	REXDENT();
}

static void frame_dump(request_t *request, unlang_stack_frame_t *frame, bool with_actions)
{
	unlang_op_t	*op = NULL;

	if (frame->instruction) {
		op = &unlang_ops[frame->instruction->type];
		instruction_dump(request, frame->instruction);
	}

	RINDENT();
	if (frame->state) RDEBUG2("state          %s (%p)", talloc_get_name(frame->state), frame->state);
	if (frame->next) {
		RDEBUG2("next           %s", frame->next->debug_name);
	} else {
		RDEBUG2("next           <none>");
	}

	fr_assert(MOD_ACTION_VALID(frame->p_result->priority));

	if (is_private_result(frame)) {
		int location;
		p_result_location_t type;
		void *chunk;

		RDEBUG2("p_rcode        %s", fr_table_str_by_value(mod_rcode_table, frame->p_result->rcode, "<invalid>"));
		RDEBUG2("p_priority     %s", mod_action_name[frame->p_result->priority]);

		location = find_p_result_location(&type, &chunk, request, frame->p_result);
		RDEBUG2("p_location     %s [%i] %p (%s)", fr_table_str_by_value(p_result_location_table, type, "<invalid>"),
			location, frame->p_result, chunk ? talloc_get_name(chunk) : "<none>"
			);
	} else {
		RDEBUG2("sec_rcode      %s", fr_table_str_by_value(mod_rcode_table, frame->section_result.rcode, "<invalid>"));
		RDEBUG2("sec_priority   %s", mod_action_name[frame->section_result.priority]);
	}
	RDEBUG2("scr_rcode      %s", fr_table_str_by_value(mod_rcode_table, frame->scratch_result.rcode, "<invalid>"));
	RDEBUG2("scr_priority   %s", mod_action_name[frame->scratch_result.priority]);
	RDEBUG2("top_frame      %s", is_top_frame(frame) ? "yes" : "no");
	RDEBUG2("repeat         %s", is_repeatable(frame) ? "yes" : "no");
	RDEBUG2("yielded        %s", is_yielded(frame) ? "yes" : "no");
	RDEBUG2("unwind         %s", is_unwinding(frame) ? "yes" : "no");

	if (frame->instruction) {
		RDEBUG2("control        %s%s%s",
			is_break_point(frame) ? "b" : "-",
			is_return_point(frame) ? "r" : "-",
			is_continue_point(frame) ? "c" : "-"
			);
		if (with_actions) actions_dump(request, frame->instruction);
	}

	/*
	 *	Call the custom frame dump function
	 */
	if (op && op->dump) op->dump(request, frame);
	REXDENT();
}

static void stack_dump_body(request_t *request, bool with_actions)
{
	int i;
	unlang_stack_t *stack = request->stack;

	RDEBUG2("----- Begin stack debug [depth %i] -----",
		stack->depth);
	for (i = stack->depth; i >= 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];
		RDEBUG2("[%d] Frame contents", i);
		frame_dump(request, frame, with_actions);
	}
	RDEBUG2("----- End stack debug [depth %i] -------", stack->depth);
}

void stack_dump(request_t *request)
{
	stack_dump_body(request, false);
}

void stack_dump_with_actions(request_t *request)
{
	stack_dump_body(request, true);
}
#define DUMP_STACK if (DEBUG_ENABLED5) stack_dump(request)
#else
#define DUMP_STACK
#endif

/** Push a new frame onto the stack
 *
 * @param[in] p_result		Where to write the result of evaluating the section.
 *				If NULL, results will be written to frame->section_result and will
 *				be automatically merged with the next highest frame when this one
 *				is popped.
 * @param[in] request		to push the frame onto.
 * @param[in] instruction	One or more unlang_t nodes describing the operations to execute.
 * @param[in] conf		Configuration for the frame.  If NULL, the following values areused:
 *				- default result = UNLANG_RESULT_NOT_SET
 *				- top_frame = UNLANG_SUB_FRAME
 *				- no_rcode = false
 * @param[in] do_next_sibling	Whether to only execute the first node in the #unlang_t program
 *				or to execute subsequent nodes.
 * @return
 *	- 0 on success.
 *	- -1 on call stack too deep.
 */
int unlang_interpret_push(unlang_result_t *p_result, request_t *request,
			  unlang_t const *instruction, unlang_frame_conf_t const *conf, bool do_next_sibling)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame;

	static unlang_frame_conf_t default_conf = {
		.default_result = UNLANG_RESULT_NOT_SET,
		.top_frame = UNLANG_SUB_FRAME
	};

	if (!conf) conf = &default_conf;

	fr_assert(instruction);

#ifndef NDEBUG
	if (DEBUG_ENABLED5) RDEBUG3("unlang_interpret_push called with instruction type \"%s\" - args %s %s",
				    instruction ? instruction->debug_name : "<none>",
				    do_next_sibling ? "UNLANG_NEXT_SIBLING" : "UNLANG_NEXT_STOP",
				    conf->top_frame ? "UNLANG_TOP_FRAME" : "UNLANG_SUB_FRAME");
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

	if (do_next_sibling && instruction->list) {
		fr_assert(instruction != NULL);
		frame->next = unlang_list_next(instruction->list, instruction);
	}
	/* else frame->next MUST be NULL */

	frame->flag = UNLANG_FRAME_FLAG_NONE;
	if (conf->top_frame) top_frame_set(frame);

	frame->p_result = p_result ? p_result : &frame->section_result;
	*frame->p_result = conf->default_result;

	frame->indent = request->log.indent;

	if (!instruction) return 0;

	frame_state_init(stack, frame);

	return 0;
}

typedef struct {
	fr_dict_t const	*old_dict;     	//!< the previous dictionary for the request
	request_t	*request;	//!< the request
} unlang_variable_ref_t;

static int _local_variables_free(unlang_variable_ref_t *ref)
{
	fr_pair_t *vp, *prev;

	/*
	 *	Local variables are appended to the end of the list.  So we remove them by walking backwards
	 *	from the end of the list.
	 */
	vp = fr_pair_list_tail(&ref->request->local_pairs);
	while (vp) {
		prev = fr_pair_list_prev(&ref->request->local_pairs, vp);
		if (vp->da->dict != ref->request->local_dict) {
			break;
		}

		(void) fr_pair_delete(&ref->request->local_pairs, vp);
		vp = prev;
	}

	ref->request->local_dict = ref->old_dict;

	return 0;
}

/** Push the children of the current frame onto a new frame onto the stack
 *
 * @param[out] p_result		set to RLM_MOULDE_FAIL if pushing the children fails
 * @param[in] request		to push the frame onto.
 * @param[in] default_rcode	The default result.
 * @param[in] do_next_sibling	Whether to only execute the first node in the #unlang_t program
 *				or to execute subsequent nodes.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_EXECUTE_NEXT do nothing, but just go to the next sibling instruction
 *	- UNLANG_ACTION_FAIL, fatal error, usually stack overflow.
 */
unlang_action_t unlang_interpret_push_children(unlang_result_t *p_result, request_t *request,
					       rlm_rcode_t default_rcode, bool do_next_sibling)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];	/* Quiet static analysis */
	unlang_group_t		*g;
	unlang_variable_ref_t	*ref;

	fr_assert(has_debug_braces(frame));

	g = unlang_generic_to_group(frame->instruction);

	/*
	 *	The compiler catches most of these, EXCEPT for the
	 *	top-level 'recv Access-Request' etc.  Which can exist,
	 *	and can be empty.
	 */
	if (unlang_list_empty(&g->children)) {
		RDEBUG2("... ignoring empty subsection ...");
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	if (unlang_interpret_push(p_result, request, unlang_list_head(&g->children),
				  FRAME_CONF(default_rcode, UNLANG_SUB_FRAME), do_next_sibling) < 0) {
		RETURN_UNLANG_ACTION_FATAL;
	}

	if (!g->variables) return UNLANG_ACTION_PUSHED_CHILD;

	/*
	 *	Note that we do NOT create the variables, This way we don't have to worry about any
	 *	uninitialized values.  If the admin tries to use the variable without initializing it, they
	 *	will get a "no such attribute" error.
	 */
	if (!frame->state) {
		MEM(ref = talloc(stack, unlang_variable_ref_t));
		frame->state = ref;
	} else {
		MEM(ref = talloc(frame->state, unlang_variable_ref_t));
	}

	/*
	 *	Set the destructor to clean up local variables.
	 */
	ref->request = request;
	ref->old_dict = request->local_dict;
	request->local_dict = g->variables->dict;
	talloc_set_destructor(ref, _local_variables_free);

	return UNLANG_ACTION_PUSHED_CHILD;
}

static void instruction_retry_handler(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *ctx);

/** Update the current result after each instruction, and after popping each stack frame
 *
 * @note Sets stack->scratch to be the the result of the frame being popped.
 *
 * @param[in] request			The current request.
 * @param[in] frame			The current stack frame.
 * @param[in] result			from the previous action.
 * @return
 *	- UNLANG_FRAME_ACTION_NEXT	evaluate more instructions.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline CC_HINT(always_inline)
unlang_frame_action_t result_calculate(request_t *request, unlang_stack_frame_t *frame, unlang_result_t *result)
{
	unlang_t const	*instruction = frame->instruction;
	unlang_stack_t	*stack = request->stack;
	unlang_result_t *frame_result = frame->p_result;

	if (is_unwinding(frame)) {
		RDEBUG4("** [%i] %s - unwinding frame", stack->depth, __FUNCTION__);
		return UNLANG_FRAME_ACTION_POP;
	}

	/*
	 *	Don't calculate a new return code for the frame, just skip
	 *	to the next instruction.
	 */
	if (result->rcode == RLM_MODULE_NOT_SET) {
		RDEBUG4("** [%i] %s - skipping frame, no result set",
			stack->depth, __FUNCTION__);
		return UNLANG_FRAME_ACTION_NEXT;
	}

	fr_assert(MOD_ACTION_VALID(frame_result->priority));
	fr_assert(MOD_ACTION_VALID(result->priority));

	RDEBUG4("** [%i] %s - have (%s %s) frame or module returned (%s %s)",
		stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame_result->rcode, "<invalid>"),
		mod_action_name[frame_result->priority],
		fr_table_str_by_value(mod_rcode_table, result->rcode, "<invalid>"),
		mod_action_name[result->priority]);

	/*
	 *	Update request->rcode if the instruction says we should
	 *	We don't care about priorities for this.
	 *
	 *	This is the field that's evaluated in unlang conditions
	 *	like `if (ok)`.
	 */
	if (is_rcode_set(frame) && (request->rcode != result->rcode)) {
		RDEBUG3("Setting request->rcode to '%s'",
			fr_table_str_by_value(rcode_table, result->rcode, "<INVALID>"));
		request->rcode = result->rcode;
	}

	/*
	*	The array holds a default priority for this return
	*	code.  Grab it in preference to any unset priority.
	*/
	if (result->priority == MOD_ACTION_NOT_SET) {
		result->priority = instruction->actions.actions[result->rcode];

		fr_assert(MOD_ACTION_VALID(result->priority));

		RDEBUG4("** [%i] %s - using default instruction priority for %s, %s",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, result->rcode, "<invalid>"),
			mod_action_name[result->priority]);
	}

	/*
	 *	Deal with special priorities which indicate we need
	 *	to do something in addition to modifying the frame's
	 *	rcode.
	 */
	switch (result->priority) {
	/*
	 *	The child's prioriy value indicates we
	 *	should return from this frame.
	 */
	case MOD_ACTION_RETURN:
		RDEBUG4("** [%i] %s - action says to return with (%s %s)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, result->rcode, "<invalid>"),
			mod_action_name[result->priority]);

		*frame_result = UNLANG_RESULT_RCODE(result->rcode);
		return UNLANG_FRAME_ACTION_POP;

	/*
	 *	Reject means we should return, but
	 *	with a reject rcode.  This allows the
	 *	user to change normally positive rcodes
	 *	into negative ones.
	 *
	 *	They could also just check the rcode
	 *	after the module returns...
	 */
	case MOD_ACTION_REJECT:
		RDEBUG4("** [%i] %s - action says to return with (%s %s)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, RLM_MODULE_REJECT, "<invalid>"),
			mod_action_name[result->priority]);

		*frame_result = UNLANG_RESULT_RCODE(RLM_MODULE_REJECT);
		return UNLANG_FRAME_ACTION_POP;

	case MOD_ACTION_RETRY:
	{
		unlang_retry_t *retry = frame->retry;

		RDEBUG4("** [%i] %s - action says to retry with",
			stack->depth, __FUNCTION__);

		/*
		 *	If this is the first time doing the retry,
		 *	then allocate the structure and set the timer.
		 */
		if (!retry) {
			MEM(frame->retry = retry = talloc_zero(stack, unlang_retry_t));

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
				if (fr_timer_in(retry, unlang_interpret_event_list(request)->tl, &retry->ev, instruction->actions.retry.mrd,
						false, instruction_retry_handler, request) < 0) {
					RPEDEBUG("Failed inserting retry event");
					*frame_result = UNLANG_RESULT_RCODE(RLM_MODULE_FAIL);
					goto finalize;
				}
			}

		} else {
			/*
			 *	We've been told to stop doing retries,
			 *	probably from a timeout.
			 */
			if (retry->state != FR_RETRY_CONTINUE) goto timeout;

			/*
			 *	Clamp it at the maximum count.
			 */
			if (instruction->actions.retry.mrc > 0) {
				retry->count++;

				if (retry->count >= instruction->actions.retry.mrc) {
					retry->state = FR_RETRY_MRC;

					REDEBUG("Retries hit max_rtx_count (%u) - returning 'timeout'", instruction->actions.retry.mrc);

				timeout:
					*frame_result = UNLANG_RESULT_RCODE(RLM_MODULE_TIMEOUT);
					goto finalize;
				}
			}
		}

		RINDENT();
		if (instruction->actions.retry.mrc) {
			RDEBUG("... retrying (%u/%u)", retry->count, instruction->actions.retry.mrc);
		} else {
			RDEBUG("... retrying");
		}
		REXDENT();

		talloc_free(frame->state);
		unlang_frame_perf_cleanup(frame);
		frame_state_init(stack, frame);	/* Don't change p_result */
		return UNLANG_FRAME_ACTION_RETRY;
	default:
		break;
	}
	}

finalize:
	/*
	 *	We're higher or equal to previous priority, remember this
	 *	return code and priority.
	 */
	if (result->priority >= frame_result->priority) {
		fr_assert(MOD_ACTION_VALID(result->priority));
		fr_assert(MOD_ACTION_VALID(frame_result->priority));

		RDEBUG4("** [%i] %s - overwriting existing result (%s %s) with higher priority (%s %s)",
			stack->depth, __FUNCTION__,
			fr_table_str_by_value(mod_rcode_table, frame_result->rcode, "<invalid>"),
			mod_action_name[frame_result->priority],
			fr_table_str_by_value(mod_rcode_table, result->rcode, "<invalid>"),
			mod_action_name[result->priority]);
		*frame->p_result = *result;
	}

	/*
	 *	Determine if we should continue processing siblings
	 *	or pop the frame ending the section.
	 */
	return frame->next ? UNLANG_FRAME_ACTION_NEXT : UNLANG_FRAME_ACTION_POP;
}

/** Function called to merge inter-stack-frame results
 *
 * This function is called whenever a frame is popped from the stack.
 *
 * 'result' is the result from the frame being popped, and 'frame' is the next highest frame in the stack.
 *
 * The logic here is very similar to result_eval(), with two important differences:
 * - The priority of the lower frame is ignored, and the default priority of the higher frame is used.
 *   Unless the higher frame's priority is MOD_ACTION_NOT_SET, in which case the lower frame's priority is used.
 */
static inline CC_HINT(always_inline)
unlang_frame_action_t result_pop(request_t *request, unlang_stack_frame_t *frame, unlang_result_t *result)
{
	unlang_stack_t	*stack = request->stack;
	unlang_result_t our_result = *result;

	fr_assert(MOD_ACTION_VALID(result->priority));

	/*
	 *	When a stack frame is being popped, the priority of the
	 *	source (lower) frame is ignored, and the default priority
	 *	of the destination (higher) frame is used.
	 *
	 *	We could (easily) add support for preserving the priority
	 *	from the lower frame, if the priority of the higher frame
	 *	was MOD_ACTION_NOT_SET, but there are no concrete use
	 *	cases for this yet.
	 */
	if (result->rcode != RLM_MODULE_NOT_SET) {
		fr_assert(MOD_ACTION_VALID(frame->instruction->actions.actions[result->rcode]));
		our_result.priority = frame->instruction->actions.actions[result->rcode];
	}

	RDEBUG4("** [%i] %s - using instruction priority for higher frame (%s, %s)",
		stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, our_result.rcode, "<invalid>"),
		mod_action_name[our_result.priority]);

	return result_calculate(request, frame, &our_result);
}

static inline CC_HINT(always_inline) void instruction_done_debug(request_t *request, unlang_stack_frame_t *frame, unlang_t const *instruction)
{
	if (has_debug_braces(instruction)) {
		REXDENT();

		/*
		 *	If we're at debug level 1, don't emit the closing
		 *	brace as the opening brace wasn't emitted.
		 *
		 *	Not a typo, we don't want to print the scratch_result
		 *	here, aka the ones the section actually returned,
		 *	vs the section result, which may have just been left
		 *	at defaults.
		 */
		if (RDEBUG_ENABLED && !RDEBUG_ENABLED2) {
			RDEBUG("# %s %s%s%s", frame->instruction->debug_name,
				frame->p_result == &frame->section_result ? "(" : "))",
				fr_table_str_by_value(mod_rcode_table, frame->p_result->rcode, "<invalid>"),
				frame->p_result == &frame->section_result ? "(" : "))");
		} else {
			RDEBUG2("} # %s %s%s%s", frame->instruction->debug_name,
				frame->p_result == &frame->section_result ? "(" : "((",
				fr_table_str_by_value(mod_rcode_table, frame->p_result->rcode, "<invalid>"),
				frame->p_result == &frame->section_result ? ")" : "))");
		}
	}
}

/** Evaluates all the unlang nodes in a section
 *
 * This function interprets a list of unlang instructions at a given level using the same
 * stack frame, and pushes additional frames onto the stack as needed.
 *
 * This function can be seen as moving horizontally.
 *
 * @param[in] request			The current request.
 * @param[in] frame			The current stack frame.
 * @return
 *	- UNLANG_FRAME_ACTION_NEXT	evaluate more instructions in the current stack frame
 *					which may not be the same frame as when this function
 *					was called.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline CC_HINT(always_inline)
unlang_frame_action_t frame_eval(request_t *request, unlang_stack_frame_t *frame)
{
	unlang_stack_t	*stack = request->stack;
	unlang_result_t *scratch = &frame->scratch_result;

	/*
	 *	Loop over all the instructions in this list.
	 */
	while (frame->instruction) {
		unlang_t const		*instruction = frame->instruction;
		unlang_action_t		ua;
		unlang_frame_action_t	fa;

		DUMP_STACK;

		fr_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */
		fr_assert(unlang_ops[instruction->type].interpret != NULL);
		fr_assert(frame->process != NULL);

		REQUEST_VERIFY(request);

		/*
		 *	We're running this frame, so it can't possibly be yielded.
		 */
		if (is_yielded(frame)) {
			RDEBUG("%s - Resuming execution", instruction->debug_name);
			yielded_clear(frame);
		}

#ifndef NDEBUG
		/*
		 *	Failure testing!
		 */
		if (request->ins_max) {
			request->ins_count++;

			if (request->ins_count >= request->ins_max) {
				RERROR("Failing request due to maximum instruction count %" PRIu64, request->ins_max);

				unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
			}
		}
#endif

		/*
		 *	We're not re-entering this frame, this is the first
		 *	time we're evaluating this instruction, so we should
		 *	print debug braces and indent.
		 */
		if (!is_repeatable(frame)) {
			if (has_debug_braces(frame)) {
				RDEBUG2("%s {", instruction->debug_name);
				RINDENT();
			}
		/*
		 *	Clear the repeatable flag so this frame
		 *	won't get executed again unless it specifically
		 *	requests it.
		 *
		 *	The flag may still be set again during the
		 *	process function to indicate that the frame
		 *	should be evaluated again.
		 */
		} else {
			repeatable_clear(frame);
		}

		/*
		 *	Execute an operation
		 */
		RDEBUG4("** [%i] %s >> %s", stack->depth, __FUNCTION__,
			unlang_ops[instruction->type].name);

		unlang_frame_perf_resume(frame);

		/*
		 *	catch plays games with the frame so we skip
		 *	to the next catch section at a given depth,
		 *	it's not safe to access frame->instruction
		 *	after this point, and the cached instruction
		 *	should be used instead.
		 */
		ua = frame->process(&frame->scratch_result, request, frame);

		fr_assert(MOD_ACTION_VALID(scratch->priority));

		RDEBUG4("** [%i] %s << %s (%s %s)", stack->depth, __FUNCTION__,
			fr_table_str_by_value(unlang_action_table, ua, "<INVALID>"),
			fr_table_str_by_value(mod_rcode_table, scratch->rcode, "<INVALID>"),
			mod_action_name[scratch->priority]);

		/*
		 *	If the frame is cancelled we ignore the
		 *	return code of the process function and
		 *	pop the frame.  We'll keep popping
		 *	frames until we hit a non-cancelled frame
		 *	or the top frame.
		 */
		if (is_unwinding(frame)) goto calculate_result;

		switch (ua) {
		/*
		 *	The operation resulted in additional frames
		 *	being pushed onto the stack, execution should
		 *	now continue at the deepest frame.
		 */
		case UNLANG_ACTION_PUSHED_CHILD:
			fr_assert_msg(&stack->frame[stack->depth] > frame,
				      "Instruction %s returned UNLANG_ACTION_PUSHED_CHILD, "
				      "but stack depth was not increased",
				      instruction->name);
			unlang_frame_perf_yield(frame);
			return UNLANG_FRAME_ACTION_NEXT;

		/*
		 *	Yield control back to the scheduler, or whatever
		 *	called the interpreter.
		 */
		case UNLANG_ACTION_YIELD:
			fr_assert_msg(&stack->frame[stack->depth] == frame,
				      "Instruction %s returned UNLANG_ACTION_YIELD, but pushed additional "
				      "frames for evaluation.  Instruction should return UNLANG_ACTION_PUSHED_CHILD "
				      "instead", instruction->name);
			unlang_frame_perf_yield(frame);
			yielded_set(frame);
			RDEBUG4("** [%i] %s - yielding with current (%s %s)", stack->depth, __FUNCTION__,
				fr_table_str_by_value(mod_rcode_table, scratch->rcode, "<invalid>"),
				mod_action_name[scratch->priority]);
			return UNLANG_FRAME_ACTION_YIELD;

		/*
		 *	This action is intended to be returned by library
		 *	functions.  It reduces boilerplate.
		 */
		case UNLANG_ACTION_FAIL:
			/*
			 *	Let unlang_calculate figure out if this is the final result
			 */
			frame->scratch_result = UNLANG_RESULT_RCODE(RLM_MODULE_FAIL);
			FALL_THROUGH;

		/*
		 *	Instruction finished execution,
		 *	check to see what we need to do next, and update
		 *	the section rcode and priority.
		 */
		case UNLANG_ACTION_CALCULATE_RESULT:
		calculate_result:
			/*
			 *	Merge in the scratch result _before_ printing
			 *	out the rcode for the frame, so get what we'll
			 *	actually return.
			 */
			fa = result_calculate(request, frame, &frame->scratch_result);

			instruction_done_debug(request, frame, instruction);

			switch (fa) {
			case UNLANG_FRAME_ACTION_POP:
				goto pop;

			case UNLANG_FRAME_ACTION_RETRY:
				if (has_debug_braces(instruction)) {
					REXDENT();
					RDEBUG2("} # retrying the same section");
				}
				continue; /* with the current instruction */

			default:
				break;
			}
			break;

		/*
		 *	Execute the next instruction in this frame
		 */
		case UNLANG_ACTION_EXECUTE_NEXT:
			if (has_debug_braces(instruction)) {
				REXDENT();
				RDEBUG2("}");
			}
			break;
		} /* switch over return code from the interpret function */

		frame_next(stack, frame);
	}

pop:
	fr_assert(MOD_ACTION_VALID(frame->p_result->priority));

	RDEBUG4("** [%i] %s - done current subsection with (%s %s), %s",
		stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->p_result->rcode, "<invalid>"),
		mod_action_name[frame->p_result->priority],
		frame->p_result == &(frame->section_result) ? "will set higher frame rcode" : "will NOT set higher frame rcode (p_result)");

	return UNLANG_FRAME_ACTION_POP;
}

/** Run the interpreter for a current request
 *
 * This function runs the interpreter for a request.  It deals with popping
 * stack frames, and calaculating the final result for the frame.
 *
 * @param[in] request		to run.  If this is an internal request
 *				the request may be freed by the interpreter.
 * @param[in] running		Is the interpreter already running.
 * @return The final request rcode.
 */
CC_HINT(hot) rlm_rcode_t unlang_interpret(request_t *request, bool running)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp = stack->intp;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];

	/*
	 *	This is needed to ensure that if a frame is marked
	 *	for unwinding whilst the request is yielded, we
	 *	unwind the cancelled frame correctly, instead of
	 *	continuing.
	 */
	unlang_frame_action_t	fa = is_unwinding(frame) ? UNLANG_FRAME_ACTION_POP : UNLANG_FRAME_ACTION_NEXT;

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("###### unlang_interpret is starting");
	DUMP_STACK;
#endif

	fr_assert(!unlang_request_is_scheduled(request)); /* if we're running it, it can't be scheduled */
	fr_assert_msg(intp, "request has no interpreter associated");

	RDEBUG4("** [%i] %s - interpret entered", stack->depth, __FUNCTION__);
	if (!running) intp->funcs.resume(request, intp->uctx);

	for (;;) {
		fr_assert(stack->depth > 0);
		fr_assert(stack->depth < UNLANG_STACK_MAX);

		RDEBUG4("** [%i] %s - frame action %s", stack->depth, __FUNCTION__,
			fr_table_str_by_value(unlang_frame_action_table, fa, "<INVALID>"));
		switch (fa) {
		next:
			RDEBUG4("** [%i] %s - frame action next", stack->depth, __FUNCTION__);
			FALL_THROUGH;

		case UNLANG_FRAME_ACTION_NEXT:	/* Evaluate the current frame */
			frame = &stack->frame[stack->depth];
			fa = frame_eval(request, frame);
			if (fa != UNLANG_FRAME_ACTION_POP) continue;

			RDEBUG4("** [%i] %s - frame action %s", stack->depth, __FUNCTION__,
				fr_table_str_by_value(unlang_frame_action_table, fa, "<INVALID>"));
			FALL_THROUGH;

		case UNLANG_FRAME_ACTION_POP:				/* Pop this frame and check the one beneath it */
		{
			bool top_frame = is_top_frame(frame);
			bool private_result = is_private_result(frame);

			unlang_result_t section_result = frame->section_result; /* record the result of the frame before we pop it*/

			DUMP_STACK;

			/*
			 *	Triggers can run modules which pop, and then the stack is empty.
			 */
			if (unlikely(stack->depth == 0)) {
				break;
			}

			/*
			 *	Head on back up the stack
			 */
			frame_pop(request, stack);
			RDEBUG4("** [%i] %s - frame popped", stack->depth + 1, __FUNCTION__);

			/*
			 *	Update the stack frame
			 */
			frame = &stack->frame[stack->depth];
			DUMP_STACK;

			/*
			 *	Transition back to the C stack
			 *
			 *	We still need to merge in the previous frame's result,
			 *	but we don't care about the action, as we're returning.
			 */
			if (top_frame) {
				if (!private_result) result_calculate(request, frame, &section_result);
				break;	/* stop */
			}

			/*
			 *	Don't process the section result for a frame if
			 *	the result is being consumed by a module.
			 */
			if (private_result) {
				fa = is_unwinding(frame) ? UNLANG_FRAME_ACTION_POP : UNLANG_FRAME_ACTION_NEXT;
			/*
			 *	Merge lower frame into higher frame.
			 *
			 *	this _MUST_ be done, even on resume, because the
			 *	section result needs to be updated for the frame
			 *	being resumed, in case it cares about the rcode
			 *	like transaction sections.
			 */
			} else {
				fa = result_pop(request, frame, &section_result);
			}

			/*
			 *	Resume a "foreach" loop, or a "load-balance" section
			 *	or anything else that needs to be checked on the way
			 *	back on up the stack.  Here we just resume evaluating
			 *	the frame, we don't advance the instruction.
			 */
			if (!is_unwinding(frame) && is_repeatable(frame)) goto next;

			/*
			 *	Close out the section we entered earlier
			 */
			instruction_done_debug(request, frame, frame->instruction);

			fr_assert(MOD_ACTION_VALID(frame->section_result.priority));

			/*
			 *	If we're continuing after popping a frame
			 *	then we advance the instruction else we
			 *	end up executing the same code over and over...
			 */
			switch (fa) {
			case UNLANG_FRAME_ACTION_NEXT:
				DEBUG4("** [%i] %s - continuing after subsection with (%s %s)",
					stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, frame->section_result.rcode, "<invalid>"),
				        mod_action_name[frame->section_result.priority]);
				frame_next(stack, frame);
				goto next;

			/*
			 *	Else if we're really done with this frame
			 *	print some helpful debug...
			 */
			default:
				RDEBUG4("** [%i] %s - done current subsection with (%s %s)",
					stack->depth, __FUNCTION__,
					fr_table_str_by_value(mod_rcode_table, frame->section_result.rcode, "<invalid>"),
					mod_action_name[frame->section_result.priority]);
				continue;
			}

		}

		case UNLANG_FRAME_ACTION_YIELD:
			/* Cannot yield from a nested call to unlang_interpret */
			fr_assert(!running);

			RDEBUG4("** [%i] %s - interpret yielding", stack->depth, __FUNCTION__);
			intp->funcs.yield(request, intp->uctx);
			return RLM_MODULE_NOT_SET;

		case UNLANG_FRAME_ACTION_RETRY:	/* retry the current frame */
			goto next;
		}
		break;
	}

	fr_assert(stack->depth >= 0);

	/*
	 *	We're at the top frame, return the result from the
	 *	stack, and get rid of the top frame.
	 */
	RDEBUG4("** [%i] %s - interpret exiting, returning (%s)", stack->depth, __FUNCTION__,
		fr_table_str_by_value(mod_rcode_table, frame->section_result.rcode, "<invalid>"));

	DUMP_STACK;

	{
		rlm_rcode_t		rcode;
		/*
		 *	Record this now as the done functions may free
		 *	the request.
		 *
		 *	Note: We use p_result here, as that's where the
		 *	result of evaluating the frame was written.
		 *	We don't use the section_result, as that may have
		 * 	been left as its default value which may be 0
		 *	(reject).
		 */
		rcode = frame->p_result->rcode;

		/*
		 *	This usually means the request is complete in its
		 *	entirety.
		 */
		if ((stack->depth == 0) && !running) unlang_interpret_request_done(request);

		return rcode;
	}
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
int unlang_interpret_push_section(unlang_result_t *p_result, request_t *request, CONF_SECTION *cs, unlang_frame_conf_t const *conf)
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

	return unlang_interpret_push_instruction(p_result, request, instruction, conf);
}

/** Push an instruction onto the request stack for later interpretation.
 *
 */
int unlang_interpret_push_instruction(unlang_result_t *p_result, request_t *request, void *instruction, unlang_frame_conf_t const *conf)
{
	unlang_stack_t	*stack = request->stack;

	if (!instruction) {
		instruction = unlang_group_to_generic(&empty_group);
	}

	/*
	 *	Push the default action, and the instruction which has
	 *	no action.
	 */
	if (unlang_interpret_push(p_result, request, instruction, conf, UNLANG_NEXT_SIBLING) < 0) {
		return -1;
	}

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

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
	/*
	 *	Should never be evaluated, is just here to reduce
	 *	branches, so we don't need to check for frame->instruction.
	 */
	static unlang_t unlang_instruction = {
		.debug_name = "top",
		.actions = DEFAULT_MOD_ACTIONS,
	};

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
	MEM(stack = talloc_zero_pooled_object(ctx, unlang_stack_t, UNLANG_STACK_MAX, 128));	/* 128 bytes per state */
	stack->frame[0].p_result = &stack->frame[0].section_result;
	stack->frame[0].scratch_result = UNLANG_RESULT_NOT_SET;
	stack->frame[0].section_result = UNLANG_RESULT_NOT_SET;
	stack->frame[0].instruction = &unlang_instruction;	/* The top frame has no instruction, so we use a dummy one */

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

	request->master_state = REQUEST_DONE;
	switch (request->type) {
	case REQUEST_TYPE_EXTERNAL:
		intp->funcs.done_external(request, frame_current(request)->section_result.rcode, intp->uctx);
		break;

	case REQUEST_TYPE_INTERNAL:
		intp->funcs.done_internal(request, frame_current(request)->section_result.rcode, intp->uctx);
		break;

	case REQUEST_TYPE_DETACHED:
		intp->funcs.done_detached(request, frame_current(request)->section_result.rcode, intp->uctx);	/* Callback will usually free the request */
		break;
	}
}

/** Tell the interpreter to detach the request
 *
 * This function should not be called directly use unlang_interpret_signal(request, FR_SIGNAL_DETACH) instead.
 * This will ensure all frames on the request's stack receive the detach signal.
 */
static inline CC_HINT(always_inline)
void unlang_interpret_request_detach(request_t *request)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp;

	if (!fr_cond_assert(stack != NULL)) return;

	if (!request_is_detachable(request)) return;

	intp = stack->intp;

	intp->funcs.detach(request, intp->uctx);
}

void unlang_interpret_request_prioritise(request_t *request, uint32_t priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_interpret_t	*intp;

	if (!fr_cond_assert(stack != NULL)) return;

	intp = stack->intp;

	request->priority = priority;

	if (intp->funcs.prioritise) intp->funcs.prioritise(request, intp->uctx);
}

/** Cancel any pending retry
 *
 * @param[in] request		The current request.
 */
void unlang_interpret_request_cancel_retry(request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	TALLOC_FREE(frame->retry);
}


/** Delivers a frame to one or more frames in the stack
 *
 * This is typically called via an "async" action, i.e. an action outside
 * of the normal processing of the request.
 *
 * For FR_SIGNAL_CANCEL all frames are marked up for cancellation, but the
 * cancellation is handled by the interpret.
 *
 * Other signal types are delivered immediately, inrrespecitve of whether
 * the request is currently being processed or not.
 *
 * Signaling stops at the "limit" frame.  This is so that keywords
 * such as "timeout" and "limit" can signal frames *lower* than theirs
 * to stop, but then continue with their own work.
 *
 * @note It's better (clearer) to use one of the unwind_* functions
 *	unless the entire request is being cancelled.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 * @param[in] limit		the frame at which to stop signaling.
 */
void unlang_stack_signal(request_t *request, fr_signal_t action, int limit)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	int			i, depth = stack->depth;

	(void)talloc_get_type_abort(request, request_t);	/* Check the request hasn't already been freed */

	fr_assert(stack->depth >= 1);

	/*
	 *	Does not complete the unwinding here, just marks
	 *	up the frames for unwinding.  The request must
	 *	be marked as runnable to complete the cancellation.
	 */
	if (action == FR_SIGNAL_CANCEL) unwind_to_depth(stack, limit);

	/*
	 *	Walk back up the stack, calling signal handlers
	 *	to cancel any pending operations and free/release
	 *	any resources.
	 *
	 *	There may be multiple resumption points in the
	 *	stack, as modules can push xlats and function
	 *	calls.
	 *
	 *	Note: Slightly confusingly, a cancellation signal
	 *	can still be delivered to a frame that is not
	 *	cancellable, but the frame won't be automatically
	 *	unwound.
	 */
	for (i = depth; i >= limit; i--) {
		frame = &stack->frame[i];
		if (frame->signal) {
			frame->signal(request, frame, action);

			/*
			 *	Once the cancellation function has been
			 *	called, the frame is no longer in a state
			 *	where it can accept further signals.
			 */
			if (action == FR_SIGNAL_CANCEL) frame->signal = NULL;

			/*
			 *	If the frame is cancelled, we don't do any retries.
			 */
			TALLOC_FREE(frame->retry);
		}
	}
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * @note This does NOT immediately stop the request, it just deliveres
 *	 signals, and in the case of a cancel, marks up frames for unwinding
 *	 and adds it to the runnable queue if it's yielded.
 *
 * @note This function should be safe to call anywhere.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 */
void unlang_interpret_signal(request_t *request, fr_signal_t action)
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
	if (!stack || stack->depth == 0) return;

	unlang_stack_signal(request, action, 1);

	switch (action) {
	case FR_SIGNAL_CANCEL:
	{
		unlang_stack_frame_t *frame = &stack->frame[stack->depth];
		/*
		 *	Let anything that cares, know that the
		 *	request was forcefully stopped.
		 */
		request->master_state = REQUEST_STOP_PROCESSING;

		/*
		 *	Give cancelled requests the highest priority
		 *	to get them to release resources ASAP.
		 */
		unlang_interpret_request_prioritise(request, UINT32_MAX);

		/*
		 *	If the request is yielded, mark it as runnable
		 *
		 *	If the request was _not_ cancelled, it means
		 *	it's not cancellable, and we need to let the
		 *	request progress normally.
		 *
		 *	A concrete example of this, is the parent of
		 *	subrequests, which must not continue until
		 *	the subrequest is done.
		 */
		if (stack && is_yielded(frame) && is_unwinding(frame) && !unlang_request_is_scheduled(request)) {
			unlang_interpret_mark_runnable(request);
		}
	}
		break;

	case FR_SIGNAL_DETACH:
		/*
		 *	Cleanup any cross-request pointers, and mark the
		 *	request as detached.  When the request completes it
		 *	should by automatically freed.
		 */
		unlang_interpret_request_detach(request);
		break;

	default:
		break;
	}
}

static void instruction_retry_handler(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *ctx)
{
	unlang_retry_t			*retry = talloc_get_type_abort(ctx, unlang_retry_t);
	request_t			*request = talloc_get_type_abort(retry->request, request_t);

	RDEBUG("retry timeout reached, signalling interpreter to cancel.");

	/*
	 *	Signal all lower frames to exit.
	 */
	unlang_stack_signal(request, FR_SIGNAL_CANCEL, retry->depth);

	retry->state = FR_RETRY_MRD;
	unlang_interpret_mark_runnable(request);
}

static void instruction_timeout_handler(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *ctx)
{
	request_t			*request = talloc_get_type_abort(ctx, request_t);

	RDEBUG("Maximum timeout reached, signalling interpreter to stop the request.");

	/*
	 *	Stop the entire request.
	 */
	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
}


/** Set a timeout for a request.
 *
 *  The timeout is associated with the current stack frame.
 *
 */
int unlang_interpret_set_timeout(request_t *request, fr_time_delta_t timeout)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_retry_t			*retry;
	TALLOC_CTX			*frame_ctx;

	fr_assert(!frame->retry);
	fr_assert(fr_time_delta_ispos(timeout));

	frame_ctx = frame->state;
	if (!frame_ctx) frame_ctx = stack;

	frame->retry = retry = talloc_zero(frame_ctx, unlang_retry_t);
	if (!frame->retry) return -1;

	retry->request = request;
	retry->depth = stack->depth;
	retry->state = FR_RETRY_CONTINUE;
	retry->count = 1;

	return fr_timer_in(retry, unlang_interpret_event_list(request)->tl, &retry->ev, timeout,
			   false, instruction_timeout_handler, request);
}


/** Return the depth of the request's stack
 *
 */
int unlang_interpret_stack_depth(request_t *request)
{
	unlang_stack_t	*stack = request->stack;

	return stack->depth;
}

/** Get the last instruction result OR the last frame that was popped
 *
 * @param[in] request	The current request.
 * @return the current rcode for the frame.
 */
rlm_rcode_t unlang_interpret_rcode(request_t *request)
{
	return frame_current(request)->p_result->rcode;
}

/** Get the last instruction priority OR the last frame that was popped
 *
 * @param[in] request	The current request.
 * @return the current rcode for the frame.
 */
unlang_mod_action_t unlang_interpret_priority(request_t *request)
{
	return frame_current(request)->p_result->priority;
}

/** Get the last instruction result OR the last frame that was popped
 *
 * @param[in] request	The current request.
 * @return the current result for the frame.
 */
unlang_result_t *unlang_interpret_result(request_t *request)
{
	return frame_current(request)->p_result;
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

/** Return whether a request has been marked done
 */
bool unlang_request_is_done(request_t const *request)
{
	return (request->master_state == REQUEST_DONE);
}

/** Check if a request as resumable.
 *
 * @param[in] request		The current request.
 * @return
 *	- true if the request is resumable (i.e. has yielded)
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
		RDEBUG3("Not marking request %s as runnable due to%s%s",
			request->name,
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

	if (frame->state) return (TALLOC_CTX *)frame->state;

	/*
	 *	If the frame doesn't ordinarily have a
	 *	state, assume the caller knows what it's
	 *	doing and allocate one.
	 */
	return (TALLOC_CTX *)(frame->state = talloc_new(request));
}

static xlat_arg_parser_t const unlang_cancel_xlat_args[] = {
	{ .required = false, .single = true, .type = FR_TYPE_TIME_DELTA },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t unlang_cancel_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *args);

/** Signal the request to stop executing
 *
 * The request can't be running at this point because we're in the event
 * loop.  This means the request is always in a consistent state when
 * the timeout event fires, even if that's state is waiting on I/O.
 */
static void unlang_cancel_event(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	request_t *request = talloc_get_type_abort(uctx, request_t);

	RDEBUG2("Request canceled by dynamic timeout");
	/*
	 *	Cleans up the memory allocated to hold
	 *	the pointer, not the event itself.
	 */
	talloc_free(request_data_get(request, (void *)unlang_cancel_xlat, 0));

	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
}

/** Allows a request to dynamically alter its own lifetime
 *
 * %cancel(<timeout>)
 *
 * If timeout is 0, then the request is immediately cancelled.
 */
static xlat_action_t unlang_cancel_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*timeout;
	fr_event_list_t		*el = unlang_interpret_event_list(request);
	fr_timer_t  		**ev_p, **ev_p_og;
	fr_value_box_t		*vb;
	fr_time_t		when = fr_time_from_sec(0); /* Invalid clang complaints if we don't set this */

	XLAT_ARGS(args, &timeout);

	/*
	 *	No timeout means cancel immediately, so yield allowing
	 *	the interpreter to run the event we added to cancel
	 *	the request.
	 *
	 *	We call unlang_xlat_yield to keep the interpreter happy
	 *	as it expects to see a resume function set.
	 */
	if (!timeout || fr_time_delta_eq(timeout->vb_time_delta, fr_time_delta_from_sec(0))) {
		unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	First see if we already have a timeout event
	 *	that was previously added by this xlat.
	 */
	ev_p = ev_p_og = request_data_get(request, (void *)unlang_cancel_xlat, 0);
	if (ev_p) {
		if (*ev_p) when = fr_timer_when(*ev_p);	/* *ev_p should never be NULL, really... */
	} else {
		/*
		 *	Must not be parented from the request
		 *	as this is freed by request data.
		 */
		MEM(ev_p = talloc_zero(NULL, fr_timer_t *));
	}

	if (unlikely(fr_timer_in(ev_p, el->tl, ev_p,
		      timeout ? timeout->vb_time_delta : fr_time_delta_from_sec(0),
	      false, unlang_cancel_event, request) < 0)) {
		RPERROR("Failed inserting cancellation event");
		talloc_free(ev_p);
		return XLAT_ACTION_FAIL;
	}
	if (unlikely(request_data_add(request, (void *)unlang_cancel_xlat, 0,
				      UNCONST(fr_timer_t **, ev_p), true, true, false) < 0)) {
		RPERROR("Failed associating cancellation event with request");
		talloc_free(ev_p);
		return XLAT_ACTION_FAIL;
	}

	if (ev_p_og) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));

		/*
		 *	Return how long before the previous
		 *	cancel event would have fired.
		 *
		 *	This can be useful for doing stacked
		 *	cancellations in policy.
		 */
		vb->vb_time_delta = fr_time_sub(when, unlang_interpret_event_list(request)->tl->time());
		fr_dcursor_insert(out, vb);
	}

	/*
	 *	No value if this is the first cleanup event
	 */
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const unlang_interpret_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Get information about the interpreter state
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unlang_interpret_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	unlang_stack_t		*stack = request->stack;
	int			depth = stack->depth;
	unlang_stack_frame_t	*frame;
	unlang_t const		*instruction;
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	char const		*fmt = arg->vb_strvalue;
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc_null(ctx));

	/*
	 *	Find the correct stack frame.
	 */
	while (*fmt == '.') {
		if (depth <= 1) {
			if (fr_value_box_bstrndup(vb, vb, NULL, "<underflow>", 11, false) < 0) {
			error:
				talloc_free(vb);
				return XLAT_ACTION_FAIL;
			}
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
		talloc_free(vb);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	How deep the current stack is.
	 */
	if (strcmp(fmt, "depth") == 0) {
		fr_value_box_int32(vb, NULL, depth, false);
		goto finish;
	}

	/*
	 *	The current module
	 */
	if (strcmp(fmt, "module") == 0) {
		if (fr_value_box_strdup(vb, vb, NULL, request->module, false) < 0) goto error;

		goto finish;
	}

	/*
	 *	Name of the instruction.
	 */
	if (strcmp(fmt, "name") == 0) {
		if (fr_value_box_bstrndup(vb, vb, NULL, instruction->name,
					  strlen(instruction->name), false) < 0) goto error;
		goto finish;
	}

	/*
	 *	The request processing stage.
	 */
	if (strcmp(fmt, "processing_stage") == 0) {
		if (fr_value_box_strdup(vb, vb, NULL, request->component, false) < 0) goto error;

		goto finish;
	}

	/*
	 *	The current return code.
	 */
	if (strcmp(fmt, "rcode") == 0) {
		if (fr_value_box_strdup(vb, vb, NULL, fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"), false) < 0) goto error;

		goto finish;
	}

	/*
	 *	The virtual server handling the request
	 */
	if (strcmp(fmt, "server") == 0) {
		if (!unlang_call_current(request)) goto finish;

		if (fr_value_box_strdup(vb, vb, NULL, cf_section_name2(unlang_call_current(request)), false) < 0) goto error;

		goto finish;
	}

	/*
	 *	Unlang instruction type.
	 */
	if (strcmp(fmt, "type") == 0) {
		if (fr_value_box_bstrndup(vb, vb, NULL, unlang_ops[instruction->type].name,
					  strlen(unlang_ops[instruction->type].name), false) < 0) goto error;

		goto finish;
	}

	/*
	 *	All of the remaining things need a CONF_ITEM.
	 */
	if (!instruction->ci) {
		if (fr_value_box_bstrndup(vb, vb, NULL, "<INVALID>", 3, false) < 0) goto error;

		goto finish;
	}

	/*
	 *	Line number of the current section.
	 */
	if (strcmp(fmt, "line") == 0) {
		fr_value_box_int32(vb, NULL, cf_lineno(instruction->ci), false);

		goto finish;
	}

	/*
	 *	Filename of the current section.
	 */
	if (strcmp(fmt, "filename") == 0) {
		if (fr_value_box_strdup(vb, vb, NULL, cf_filename(instruction->ci), false) < 0) goto error;

		goto finish;
	}

finish:
	if (vb->type != FR_TYPE_NULL) {
		fr_dcursor_append(out, vb);
	} else {
		talloc_free(vb);
	}

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
	frame_pop(request, request->stack);
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

int unlang_interpret_init_global(TALLOC_CTX *ctx)
{
	xlat_t	*xlat;
	/*
	 *  Should be void, but someone decided not to register multiple xlats
	 *  breaking the convention we use everywhere else in the server...
	 */
	if (unlikely((xlat = xlat_func_register(ctx, "interpreter", unlang_interpret_xlat, FR_TYPE_VOID)) == NULL)) return -1;
	xlat_func_args_set(xlat, unlang_interpret_xlat_args);

	if (unlikely((xlat = xlat_func_register(ctx, "cancel", unlang_cancel_xlat, FR_TYPE_VOID)) == NULL)) return -1;
	xlat_func_args_set(xlat, unlang_cancel_xlat_args);

	return 0;
}
