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

#include <freeradius-devel/server/request_data.h>

#include "foreach_priv.h"
#include "return_priv.h"
#include "xlat_priv.h"

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
	request_t		*request;			//!< The current request.
	fr_dcursor_t		cursor;				//!< Used to track our place in the list
								///< we're iterating over.
	fr_pair_list_t 		vps;				//!< List containing the attribute(s) we're
								///< iterating over.
	int			depth;				//!< Level of nesting of this foreach loop.
#ifndef NDEBUG
	int			indent;				//!< for catching indentation issues
#endif
} unlang_frame_state_foreach_t;

static xlat_action_t unlang_foreach_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 xlat_ctx_t const *xctx,
					 request_t *request, UNUSED fr_value_box_list_t *in);

#define FOREACH_REQUEST_DATA (void *)unlang_foreach_xlat

/** Ensure request data is pulled out of the request if the frame is popped
 *
 */
static int _free_unlang_frame_state_foreach(unlang_frame_state_foreach_t *state)
{
	request_data_get(state->request, FOREACH_REQUEST_DATA, state->depth);

	return 0;
}

static unlang_action_t unlang_foreach_next(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	fr_pair_t			*vp;

	if (is_stack_unwinding_to_break(request->stack)) return UNLANG_ACTION_CALCULATE_RESULT;

	vp = fr_dcursor_next(&state->cursor);
	if (!vp) {
		*p_result = frame->result;
#ifndef NDEBUG
		fr_assert(state->indent == request->log.unlang_indent);
#endif
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

#ifndef NDEBUG
	RDEBUG2("# looping with: Foreach-Variable-%d = %pV", state->depth, &vp->data);
#endif

	/*
	 *	Push the child, and yield for a later return.
	 */
	if (unlang_interpret_push(request, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	repeatable_set(frame);

	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_foreach(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_stack_t			*stack = request->stack;
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_foreach_t		*gext = unlang_group_to_foreach(g);
	unlang_frame_state_foreach_t	*state;

	int				i, depth = 0;
	fr_pair_list_t			vps;

	fr_pair_list_init(&vps);

	/*
	 *	Ensure any breaks terminate here...
	 */
	break_point_set(frame);

	/*
	 *	Figure out foreach depth by walking back up the stack
	 */
	if (stack->depth > 0) for (i = (stack->depth - 1); i >= 0; i--) {
			unlang_t const *our_instruction;
			our_instruction = stack->frame[i].instruction;
			if (!our_instruction || (our_instruction->type != UNLANG_TYPE_FOREACH)) continue;
			depth++;
		}

	if (depth >= (int)NUM_ELEMENTS(xlat_foreach_names)) {
		REDEBUG("foreach Nesting too deep!");
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	MEM(frame->state = state = talloc_zero(request->stack, unlang_frame_state_foreach_t));
	fr_pair_list_init(&state->vps);

	/*
	 *	Copy the VPs from the original request, this ensures deterministic
	 *	behaviour if someone decides to add or remove VPs in the set we're
	 *	iterating over.
	 */
	if (tmpl_copy_pairs(frame->state, &vps, request, gext->vpt) < 0) {	/* nothing to loop over */
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_assert(!fr_pair_list_empty(&vps));

	state->request = request;
	state->depth = depth;
	fr_pair_list_append(&state->vps, &vps);
	fr_pair_dcursor_init(&state->cursor, &state->vps);
#ifndef NDEBUG
	state->indent = request->log.unlang_indent;
#endif

	/*
	 *	Add a (hopefully) faster lookup to get the state.
	 */
	request_data_add(request, FOREACH_REQUEST_DATA, state->depth, state, false, false, false);

	talloc_set_destructor(state, _free_unlang_frame_state_foreach);

	frame->process = unlang_foreach_next;

	/*
	 *	Push the child, and go process it.
	 */
	if (unlang_interpret_push(request, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	repeatable_set(frame);

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_break(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	*p_result = frame->result;

	/*
	 *	Stop at the next break point, or if we hit
	 *	the a top frame.
	 */
	return unwind_to_break(request->stack);
}

/** Implements the Foreach-Variable-X
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unlang_foreach_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 xlat_ctx_t const *xctx,
					 request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_pair_t			*vp;
	int const			*inst = xctx->inst;
	fr_value_box_t			*vb;
	unlang_frame_state_foreach_t	*state;

	state = request_data_reference(request, FOREACH_REQUEST_DATA, *inst);
	if (!state) return XLAT_ACTION_FAIL;

	vp = fr_dcursor_current(&state->cursor);
	fr_assert(vp != NULL);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_copy(ctx, vb, &vp->data);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

void unlang_foreach_init(void)
{
	size_t	i;

	for (i = 0; i < NUM_ELEMENTS(xlat_foreach_names); i++) {
		xlat_t *x;

		x = xlat_register(NULL, xlat_foreach_names[i],
				  unlang_foreach_xlat, XLAT_FLAG_NEEDS_ASYNC);
		fr_assert(x);
		x->uctx = &xlat_foreach_inst[i];
		xlat_internal(x);
	}

	unlang_register(UNLANG_TYPE_FOREACH,
			   &(unlang_op_t){
				.name = "foreach",
				.interpret = unlang_foreach,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_BREAK,
			   &(unlang_op_t){
				.name = "break",
				.interpret = unlang_break,
			   });
}

void unlang_foreach_free(void)
{
	size_t	i;

	for (i = 0; i < NUM_ELEMENTS(xlat_foreach_names); i++) {
		xlat_unregister(xlat_foreach_names[i]);
	}
}
