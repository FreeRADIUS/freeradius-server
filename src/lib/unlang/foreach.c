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

#define unlang_break unlang_return

/** State of a foreach loop
 *
 */
typedef struct {
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

	if (!frame->repeat) {
		int i, foreach_depth = -1;
		VALUE_PAIR *vps;

		if (stack->depth >= UNLANG_STACK_MAX) {
			ERROR("Internal sanity check failed: module stack is too deep");
			fr_exit(EXIT_FAILURE);
		}

		/*
		 *	Figure out how deep we are in nesting by looking at request_data
		 *	stored previously.
		 *
		 *	FIXME: figure this out by walking up the modcall stack instead.
		 */
		for (i = 0; i < 8; i++) {
			if (!request_data_reference(request, (void *)xlat_fmt_get_vp, i)) {
				foreach_depth = i;
				break;
			}
		}

		if (foreach_depth < 0) {
			REDEBUG("foreach Nesting too deep!");
			*presult = RLM_MODULE_FAIL;
			*priority = 0;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set we're
		 *	iterating over.
		 */
		if (tmpl_copy_vps(stack, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			*presult = RLM_MODULE_NOOP;
			*priority = instruction->actions[RLM_MODULE_NOOP];
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		MEM(frame->state = foreach = talloc_zero(stack, unlang_frame_state_foreach_t));

		rad_assert(vps != NULL);

		foreach->depth = foreach_depth;
		foreach->vps = vps;
		fr_cursor_talloc_init(&foreach->cursor, &foreach->vps, VALUE_PAIR);
#ifndef NDEBUG
		foreach->indent = request->log.unlang_indent;
#endif

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
			request_data_get(request, (void *)xlat_fmt_get_vp, foreach->depth);

			*presult = frame->result;
			if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];
#ifndef NDEBUG
			rad_assert(foreach->indent == request->log.unlang_indent);
#endif
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	RDEBUG2("");
	RDEBUG2("# looping with: Foreach-Variable-%d = %pV", foreach->depth, &vp->data);
#endif

	rad_assert(vp);

	/*
	 *	Add the vp to the request, so that
	 *	xlat.c, xlat_foreach() can find it.
	 */
	foreach->variable = vp;
	request_data_add(request, (void *)xlat_fmt_get_vp, foreach->depth, &foreach->variable,
			 false, false, false);

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_interpret_push(request, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME);
	frame->repeat = true;

	return UNLANG_ACTION_PUSHED_CHILD;
}

void unlang_foreach_init(void)
{
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
