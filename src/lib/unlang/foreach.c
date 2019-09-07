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
 * @file unlang/foreach.c
 * @brief Unlang "foreach" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "return_priv.h"

static char const * const xlat_foreach_names[] = {"Foreach-Variable-0",
						  "Foreach-Variable-1",
						  "Foreach-Variable-2",
						  "Foreach-Variable-3",
						  "Foreach-Variable-4",
						  "Foreach-Variable-5",
						  "Foreach-Variable-6",
						  "Foreach-Variable-7",
						  "Foreach-Variable-8",
						  "Foreach-Variable-9"};

static int xlat_foreach_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };	/* up to 10 for foreach */

/** State of a foreach loop
 *
 */
typedef struct {
	REQUEST			*request;			//!< The current request.
	fr_cursor_t		cursor;				//!< Used to track our place in the list
								///< we're iterating over.
	VALUE_PAIR 		*vps;				//!< List containing the attribute(s) we're
								///< iterating over.
	VALUE_PAIR		*variable;			//!< Attribute we update the value of.
	int			depth;				//!< Level of nesting of this foreach loop.
#ifndef NDEBUG
	int			indent;				//!< for catching indentation issues
#endif
} unlang_frame_state_foreach_t;

static ssize_t unlang_foreach_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				   void const *mod_inst, UNUSED void const *xlat_inst,
				   REQUEST *request, UNUSED char const *fmt);

#define FOREACH_REQUEST_DATA (void *)unlang_foreach_xlat

/** Ensure request data is pulled out of the request if the frame is popped
 *
 */
static int _free_unlang_frame_state_foreach(unlang_frame_state_foreach_t *state)
{
	request_data_get(state->request, FOREACH_REQUEST_DATA, state->depth);

	return 0;
}

static unlang_action_t unlang_foreach(REQUEST *request,
				      rlm_rcode_t *presult, int *priority)
{
	VALUE_PAIR			*vp;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_foreach_t	*foreach = NULL;
	unlang_group_t			*g;

	g = unlang_generic_to_group(instruction);

	if (!is_repeatable(frame)) {
		int i, foreach_depth = 0;
		VALUE_PAIR *vps;

		/*
		 *	Ensure any breaks terminate here...
		 */
		break_point_set(frame);

		if (stack->depth >= UNLANG_STACK_MAX) {
			ERROR("Internal sanity check failed: module stack is too deep");
			fr_exit(EXIT_FAILURE);
		}

		/*
		 *	Figure out foreach depth by walking back up the stack
		 */
		if (stack->depth > 0) for (i = (stack->depth - 1); i >= 0; i--) {
			unlang_t *our_instruction;
			our_instruction = stack->frame[i].instruction;
			if (!our_instruction || (our_instruction->type != UNLANG_TYPE_FOREACH)) continue;
			foreach_depth++;
		}

		if (foreach_depth >= (int)NUM_ELEMENTS(xlat_foreach_names)) {
			REDEBUG("foreach Nesting too deep!");
			*presult = RLM_MODULE_FAIL;
			*priority = 0;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		MEM(frame->state = foreach = talloc_zero(stack, unlang_frame_state_foreach_t));

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set we're
		 *	iterating over.
		 */
		if (tmpl_copy_vps(frame->state, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			*presult = RLM_MODULE_NOOP;
			*priority = instruction->actions[RLM_MODULE_NOOP];
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		rad_assert(vps != NULL);

		foreach->request = request;
		foreach->depth = foreach_depth;
		foreach->vps = vps;
		fr_cursor_talloc_init(&foreach->cursor, &foreach->vps, VALUE_PAIR);
#ifndef NDEBUG
		foreach->indent = request->log.unlang_indent;
#endif
		talloc_set_destructor(foreach, _free_unlang_frame_state_foreach);

		vp = fr_cursor_head(&foreach->cursor);
	} else {
		foreach = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);

		vp = fr_cursor_next(&foreach->cursor);

		/*
		 *	We've been asked to unwind to the
		 *	enclosing "foreach".  We're here, so
		 *	we can stop unwinding.
		 */
		if (stack->unwind == UNLANG_TYPE_BREAK) {
			stack->unwind = UNLANG_TYPE_NULL;
			vp = NULL;
		}

		/*
		 *	Unwind all the way.
		 */
		if (stack->unwind == UNLANG_TYPE_RETURN) {
			vp = NULL;
		}

		if (!vp) {
			/*
			 *	Free the copied vps and the request data
			 *	If we don't remove the request data, something could call
			 *	the xlat outside of a foreach loop and trigger a segv.
			 */
			fr_pair_list_free(&foreach->vps);
			request_data_get(request, FOREACH_REQUEST_DATA, foreach->depth);

			*presult = frame->result;
			if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];
#ifndef NDEBUG
			rad_assert(foreach->indent == request->log.unlang_indent);
#endif
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	RDEBUG2("# looping with: Foreach-Variable-%d = %pV", foreach->depth, &vp->data);
#endif

	rad_assert(vp);

	/*
	 *	Add the vp to the request, so that
	 *	xlat.c, xlat_foreach() can find it.
	 */
	foreach->variable = vp;
	request_data_add(request, FOREACH_REQUEST_DATA, foreach->depth, &foreach->variable,
			 false, false, false);

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_interpret_push(request, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME);
	repeatable_set(frame);

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_break(REQUEST *request, rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;

	RDEBUG2("%s", unlang_ops[instruction->type].name);

	stack->unwind = instruction->type;

	*presult = frame->result;
	*priority = frame->priority;

	return UNLANG_ACTION_BREAK;
}

/** Implements the Foreach-Variable-X
 *
 */
static ssize_t unlang_foreach_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				   void const *mod_inst, UNUSED void const *xlat_inst,
				   REQUEST *request, UNUSED char const *fmt)
{
	VALUE_PAIR	**pvp;

	pvp = (VALUE_PAIR **) request_data_reference(request, FOREACH_REQUEST_DATA, *(int const *) mod_inst);
	if (!pvp || !*pvp) return 0;

	*out = fr_pair_value_asprint(ctx, *pvp, '\0');
	return 	talloc_array_length(*out) - 1;
}

void unlang_foreach_init(void)
{
	size_t	i;

	for (i = 0; i < NUM_ELEMENTS(xlat_foreach_names); i++) {
		xlat_register(&xlat_foreach_inst[i], xlat_foreach_names[i], unlang_foreach_xlat, NULL, NULL, 0, 0, true);
		xlat_internal(xlat_foreach_names[i]);
	}

	unlang_register(UNLANG_TYPE_FOREACH,
			   &(unlang_op_t){
				.name = "foreach",
				.func = unlang_foreach,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_BREAK,
			   &(unlang_op_t){
				.name = "break",
				.func = unlang_break,
			   });
}

void unlang_foreach_free(void)
{
	size_t	i;

	for (i = 0; i < NUM_ELEMENTS(xlat_foreach_names); i++) {
		xlat_unregister(xlat_foreach_names[i]);
	}
}
