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
 * @file unlang/load_balance.c
 * @brief Implementation of the unlang "load-balance" keyword.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/rand.h>
#include "unlang_priv.h"
#include "module_priv.h"

#define unlang_redundant_load_balance unlang_load_balance

static unlang_action_t unlang_load_balance_next(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_redundant_t	*redundant;
	unlang_group_t			*g;

	g = unlang_generic_to_group(instruction);

	redundant = talloc_get_type_abort(frame->state, unlang_frame_state_redundant_t);

#ifdef __clang_analyzer__
	if (!redundant->found) {
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
#endif
	/*
	 *	Set up the first round versus subsequent ones.
	 */
	if (!redundant->child) {
		redundant->child = redundant->found;

	} else {
		/*
		 *	child is NULL on the first pass.  But if it's
		 *	back to the found one, then we're done.
		 */
		if (redundant->child == redundant->found) {
			/* DON'T change presult, as it is taken from the child */
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		RDEBUG4("%s resuming", frame->instruction->debug_name);

		/*
		 *	We are in a resumed frame.  The module we
		 *	chose failed, so we have to go through the
		 *	process again.
		 */

		fr_assert(instruction->type != UNLANG_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	If the current child says "return", then do
		 *	so.
		 */
		if (redundant->child->actions[*presult] == MOD_ACTION_RETURN) {
			/* DON'T change presult, as it is taken from the child */
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_interpret_push(request, redundant->child, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);

	/*
	 *	Now that we've pushed this child, make the next call
	 *	use the next child, wrapping around to the beginning.
	 *
	 *	@todo - track the one we chose, and if it fails, do
	 *	the load-balancing again, except this time skipping
	 *	the failed module.  AND, keep track of multiple failed
	 *	modules in the unlang_frame_state_redundant_t
	 *	structure.
	 */
	redundant->child = redundant->child->next;
	if (!redundant->child) redundant->child = g->children;

	repeatable_set(frame);

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_load_balance(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_redundant_t	*redundant;
	unlang_group_t			*g;

	uint32_t count = 0;

	g = unlang_generic_to_group(instruction);
	if (!g->num_children) {
		*presult = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	RDEBUG4("%s setting up", frame->instruction->debug_name);

	redundant = talloc_get_type_abort(frame->state, unlang_frame_state_redundant_t);

	if (g->vpt) {
		uint32_t hash, start;
		ssize_t slen;
		char const *p = NULL;
		char buffer[1024];

		/*
		 *	Integer data types let the admin
		 *	select which frame is being used.
		 */
		if (tmpl_is_attr(g->vpt) &&
		    ((tmpl_da(g->vpt)->type == FR_TYPE_UINT8) ||
		     (tmpl_da(g->vpt)->type == FR_TYPE_UINT16) ||
		     (tmpl_da(g->vpt)->type == FR_TYPE_UINT32) ||
		     (tmpl_da(g->vpt)->type == FR_TYPE_UINT64))) {
			VALUE_PAIR *vp;

			slen = tmpl_find_vp(&vp, request, g->vpt);
			if (slen < 0) {
				REDEBUG("Failed finding attribute %s", g->vpt->name);
				goto randomly_choose;
			}

			switch (tmpl_da(g->vpt)->type) {
			case FR_TYPE_UINT8:
				start = ((uint32_t) vp->vp_uint8) % g->num_children;
				break;

			case FR_TYPE_UINT16:
				start = ((uint32_t) vp->vp_uint16) % g->num_children;
				break;

			case FR_TYPE_UINT32:
				start = vp->vp_uint32 % g->num_children;
				break;

			case FR_TYPE_UINT64:
				start = (uint32_t) (vp->vp_uint64 % ((uint64_t) g->num_children));
				break;

			default:
				goto randomly_choose;
			}

		} else {
			slen = tmpl_expand(&p, buffer, sizeof(buffer), request, g->vpt, NULL, NULL);
			if (slen < 0) {
				REDEBUG("Failed expanding template");
				goto randomly_choose;
			}

			hash = fr_hash(p, slen);

			start = hash % g->num_children;;
		}

		RDEBUG3("load-balance starting at child %d", (int) start);

		count = 0;
		for (redundant->child = redundant->found = g->children;
		     redundant->child != NULL;
		     redundant->child = redundant->child->next) {
			count++;
			if (count == start) {
				redundant->found = redundant->child;
				break;
			}
		}

	} else {
	randomly_choose:
		count = 0;

		/*
		 *	Choose a child at random.
		 *
		 *	@todo - leverage the "power of 2", as per
		 *      lib/io/network.c.  This is good enough for
		 *      most purposes.  However, in order to do this,
		 *      we need to track active callers across
		 *      *either* multiple modules in one thread, *or*
		 *      across multiple threads.
		 *
		 *	We don't have thread-specific instance data
		 *	for this load-balance section.  So for now,
		 *	just pick a random child.
		 */
		for (redundant->child = redundant->found = g->children;
		     redundant->child != NULL;
		     redundant->child = redundant->child->next) {
			count++;

			if ((count * (fr_rand() & 0xffffff)) < (uint32_t) 0x1000000) {
				redundant->found = redundant->child;
			}
		}
	}

	/*
	 *	Plain "load-balance".  Just do one child.
	 */
	if (instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
		unlang_interpret_push(request, redundant->found,
				      frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	"redundant" and "redundant-load-balance" starts at
	 *	"found", but we need to indicate that we're at the
	 *	first child.
	 */
	redundant->child = NULL;

	frame->interpret = unlang_load_balance_next;
	return unlang_load_balance_next(request, presult);
}

void unlang_load_balance_init(void)
{
	unlang_register(UNLANG_TYPE_LOAD_BALANCE,
			   &(unlang_op_t){
				.name = "load-balance group",
				.interpret = unlang_load_balance,
				.debug_braces = true,
			        .frame_state_size = sizeof(unlang_frame_state_redundant_t),
				.frame_state_name = "unlang_frame_state_redundant_t",
			   });

	unlang_register(UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,
			   &(unlang_op_t){
				.name = "redundant-load-balance group",
				.interpret = unlang_redundant_load_balance,
				.debug_braces = true,
			        .frame_state_size = sizeof(unlang_frame_state_redundant_t),
				.frame_state_name = "unlang_frame_state_redundant_t",
			   });
}
