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
 * @file unlang/switch.c
 * @brief Unlang "switch" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/cond.h>

#include "group_priv.h"
#include "switch_priv.h"
#include "unlang_priv.h"

static unlang_action_t unlang_switch(request_t *request, UNUSED rlm_rcode_t *presult)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_t		*this, *found, *null_case;

	unlang_group_t		*switch_g;
	unlang_switch_t	*switch_gext;

	fr_cond_t		cond;
	map_t		map;
	tmpl_t			vpt;

	switch_g = unlang_generic_to_group(instruction);
	switch_gext = unlang_group_to_switch(switch_g);

	memset(&cond, 0, sizeof(cond));
	memset(&map, 0, sizeof(map));
	memset(&vpt, 0, sizeof(vpt));

	cond.type = COND_TYPE_MAP;
	cond.data.map = &map;

	map.op = T_OP_CMP_EQ;
	map.ci = cf_section_to_item(switch_g->cs);

	fr_assert(switch_gext->vpt != NULL);

	null_case = found = NULL;

	/*
	 *	The attribute doesn't exist.  We can skip
	 *	directly to the default 'case' statement.
	 */
	if (tmpl_is_attr(switch_gext->vpt) && (tmpl_find_vp(NULL, request, switch_gext->vpt) < 0)) {
	find_null_case:
		for (this = switch_g->children; this; this = this->next) {
			unlang_group_t		*case_g;
			unlang_case_t	*case_gext;

			fr_assert(this->type == UNLANG_TYPE_CASE);

			case_g = unlang_generic_to_group(this);
			case_gext = unlang_group_to_case(case_g);
			if (case_gext->vpt) continue;

			found = this;
			break;
		}

		goto do_null_case;
	}

	/*
	 *	Expand the template if necessary, so that it
	 *	is evaluated once instead of for each 'case'
	 *	statement.
	 */
	if (tmpl_is_xlat(switch_gext->vpt) ||
	    tmpl_is_xlat_unresolved(switch_gext->vpt) ||
	    tmpl_is_exec(switch_gext->vpt)) {
		char *p;
		ssize_t len;

		len = tmpl_aexpand(request, &p, request, switch_gext->vpt, NULL, NULL);
		if (len < 0) goto find_null_case;

		tmpl_init_shallow(&vpt, TMPL_TYPE_DATA, T_SINGLE_QUOTED_STRING, p, len);
		fr_value_box_bstrndup_shallow(&vpt.data.literal, NULL, p, len, false);
	}

	/*
	 *	Find either the exact matching name, or the
	 *	"case {...}" statement.
	 */
	for (this = switch_g->children; this; this = this->next) {
		unlang_group_t		*case_g;
		unlang_case_t	*case_gext;

		fr_assert(this->type == UNLANG_TYPE_CASE);

		case_g = unlang_generic_to_group(this);
		case_gext = unlang_group_to_case(case_g);

		/*
		 *	Remember the default case
		 */
		if (!case_gext->vpt) {
			if (!null_case) null_case = this;
			continue;
		}

		/*
		 *	If we're switching over an attribute
		 *	AND we haven't pre-parsed the data for
		 *	the case statement, then cast the data
		 *	to the type of the attribute.
		 */
		if (tmpl_is_attr(switch_gext->vpt) && !tmpl_is_data(case_gext->vpt)) {
			map.rhs = switch_gext->vpt;
			map.lhs = case_gext->vpt;
			cond.cast = tmpl_da(switch_gext->vpt);

			/*
			 *	Remove unnecessary casting.
			 */
			if (tmpl_is_attr(case_gext->vpt) &&
			    (tmpl_da(switch_gext->vpt)->type == tmpl_da(case_gext->vpt)->type)) {
				cond.cast = NULL;
			}

		/*
		 *	Use the pre-expanded string.
		 */
		} else if (tmpl_is_xlat(switch_gext->vpt) ||
			   tmpl_is_xlat_unresolved(switch_gext->vpt) ||
			   tmpl_is_exec(switch_gext->vpt)) {
			map.rhs = case_gext->vpt;
			map.lhs = &vpt;
			cond.cast = NULL;

		/*
		 *	Else evaluate the 'switch' statement.
		 */
		} else {
			map.rhs = case_gext->vpt;
			map.lhs = switch_gext->vpt;
			cond.cast = NULL;
		}

		if (cond_eval_map(request, 0, &cond) == 1) {
			found = this;
			break;
		}
	}

	if (!found) found = null_case;

do_null_case:
	if (vpt.type == TMPL_TYPE_DATA) fr_value_box_clear_value(&vpt.data.literal);

	/*
	 *	Nothing found.  Just continue, and ignore the "switch"
	 *	statement.
	 */
	if (!found) return UNLANG_ACTION_EXECUTE_NEXT;

	if (unlang_interpret_push(request, found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME) < 0) {
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_case(request_t *request, rlm_rcode_t *presult)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	g = unlang_generic_to_group(instruction);

	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_group(request, presult);
}

void unlang_switch_init(void)
{
	unlang_register(UNLANG_TYPE_SWITCH,
			   &(unlang_op_t){
				.name = "switch",
				.interpret = unlang_switch,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_CASE,
			   &(unlang_op_t){
				.name = "case",
				.interpret = unlang_case,
				.debug_braces = true
			   });
}
