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
#include "unlang_priv.h"
#include "module_priv.h"

#define unlang_redundant_load_balance unlang_load_balance

static unlang_action_t unlang_load_balance(REQUEST *request,
					   rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_redundant_t	*redundant;
	unlang_group_t			*g;

	uint32_t count = 0;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	/*
	 *	No frame?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!is_repeatable(frame)) {
		RDEBUG4("%s setting up", frame->instruction->debug_name);

		frame->state = redundant = talloc_zero(stack, unlang_frame_state_redundant_t);

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
			    ((g->vpt->tmpl_da->type == FR_TYPE_UINT8) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT16) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT32) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT64))) {
				VALUE_PAIR *vp;

				slen = tmpl_find_vp(&vp, request, g->vpt);
				if (slen < 0) {
					REDEBUG("Failed finding attribute %s", g->vpt->name);
					goto randomly_choose;
				}

				switch (g->vpt->tmpl_da->type) {
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
			int num;
			uint64_t lowest_active_callers;

		randomly_choose:
			lowest_active_callers = ~(uint64_t ) 0;

			/*
			 *	Choose a child at random.
			 */
			for (redundant->child = redundant->found = g->children, num = 0;
			     redundant->child != NULL;
			     redundant->child = redundant->child->next, num++) {
				uint64_t active_callers;
				unlang_t *child = redundant->child;

				if (child->type != UNLANG_TYPE_MODULE) {
					active_callers = unlang_interpret_active_callers(child);
					RDEBUG3("load-balance child %d sub-section has %" PRIu64 " active", num, active_callers);

				} else {
					module_thread_instance_t *thread;
					unlang_module_t *sp;

					sp = unlang_generic_to_module(child);
					rad_assert(sp != NULL);

					thread = module_thread(sp->module_instance);
					rad_assert(thread != NULL);

					active_callers = thread->active_callers;
					RDEBUG3("load-balance child %d sub-module has %" PRIu64 " active", num, active_callers);
				}


				/*
				 *	Reset the found, and the count
				 *	of children with this level of
				 *	activity.
				 */
				if (active_callers < lowest_active_callers) {
					RDEBUG3("load-balance choosing child %d as active %" PRIu64 " < %" PRIu64 "",
						num, active_callers, lowest_active_callers);

					count = 1;
					lowest_active_callers = active_callers;
					redundant->found = redundant->child;
					continue;
				}

				/*
				 *	Skip callers who are busier
				 *	than the one we found.
				 */
				if (active_callers > lowest_active_callers) {
					RDEBUG3("load-balance skipping child %d, as active %" PRIu64 " > %" PRIu64 "",
						num, active_callers, lowest_active_callers);
					continue;
				}

				count++;
				RDEBUG3("load-balance found %d children with %" PRIu64 " active", count, active_callers);

				if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
					RDEBUG3("load-balance choosing random child %d", num);
					redundant->found = redundant->child;
				}
			}
		}

		if (instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
			unlang_interpret_push(request, redundant->found,
					      frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		/*
		 *	redundant-load-balance starts at this one.
		 */
		redundant->child = redundant->found;

	} else {
		RDEBUG4("%s resuming", frame->instruction->debug_name);
		redundant = talloc_get_type_abort(frame->state, unlang_frame_state_redundant_t);

		/*
		 *	We are in a resumed frame.  The module we
		 *	chose failed, so we have to go through the
		 *	process again.
		 */

		rad_assert(instruction->type != UNLANG_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (redundant->child->actions[*presult] == MOD_ACTION_RETURN) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	@todo - track the one we chose, and if it
		 *	fails, do the load-balancing again, except
		 *	this time skipping the failed module.  AND,
		 *	keep track of multiple failed modules.
		 *	Probably in the unlang_resume_t, via a
		 *	uint64_t and bit mask for simplicity.
		 */

		redundant->child = redundant->child->next;
		if (!redundant->child) redundant->child = g->children;

		if (redundant->child == redundant->found) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_interpret_push(request, redundant->child, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	repeatable_set(frame);

	return UNLANG_ACTION_PUSHED_CHILD;
}

void unlang_load_balance_init(void)
{
	unlang_register(UNLANG_TYPE_LOAD_BALANCE,
			   &(unlang_op_t){
				.name = "load-balance group",
				.func = unlang_load_balance,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,
			   &(unlang_op_t){
				.name = "redundant-load-balance group",
				.func = unlang_redundant_load_balance,
				.debug_braces = true
			   });
}
