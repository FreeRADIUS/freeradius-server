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

#include "unlang_priv.h"
#include "group_priv.h"

static unlang_action_t unlang_switch(REQUEST *request, UNUSED rlm_rcode_t *presult)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_t		*this, *found, *null_case;
	unlang_group_t		*g, *h;
	fr_cond_t		cond;
	fr_value_box_t		data;
	vp_map_t		map;
	vp_tmpl_t		vpt;

	g = unlang_generic_to_group(instruction);

	memset(&cond, 0, sizeof(cond));
	memset(&map, 0, sizeof(map));

	cond.type = COND_TYPE_MAP;
	cond.data.map = &map;

	map.op = T_OP_CMP_EQ;
	map.ci = cf_section_to_item(g->cs);

	rad_assert(g->vpt != NULL);

	null_case = found = NULL;
	data.datum.ptr = NULL;

	/*
	 *	The attribute doesn't exist.  We can skip
	 *	directly to the default 'case' statement.
	 */
	if (tmpl_is_attr(g->vpt) && (tmpl_find_vp(NULL, request, g->vpt) < 0)) {
	find_null_case:
		for (this = g->children; this; this = this->next) {
			rad_assert(this->type == UNLANG_TYPE_CASE);

			h = unlang_generic_to_group(this);
			if (h->vpt) continue;

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
	if (tmpl_is_xlat_struct(g->vpt) ||
	    tmpl_is_xlat(g->vpt) ||
	    tmpl_is_exec(g->vpt)) {
		char *p;
		ssize_t len;

		len = tmpl_aexpand(request, &p, request, g->vpt, NULL, NULL);
		if (len < 0) goto find_null_case;
		data.vb_strvalue = p;
		tmpl_init(&vpt, TMPL_TYPE_UNPARSED, data.vb_strvalue, len, T_SINGLE_QUOTED_STRING);
	}

	/*
	 *	Find either the exact matching name, or the
	 *	"case {...}" statement.
	 */
	for (this = g->children; this; this = this->next) {
		rad_assert(this->type == UNLANG_TYPE_CASE);

		h = unlang_generic_to_group(this);

		/*
		 *	Remember the default case
		 */
		if (!h->vpt) {
			if (!null_case) null_case = this;
			continue;
		}

		/*
		 *	If we're switching over an attribute
		 *	AND we haven't pre-parsed the data for
		 *	the case statement, then cast the data
		 *	to the type of the attribute.
		 */
		if (tmpl_is_attr(g->vpt) &&
		    !tmpl_is_data(h->vpt)) {
			map.rhs = g->vpt;
			map.lhs = h->vpt;
			cond.cast = g->vpt->tmpl_da;

			/*
			 *	Remove unnecessary casting.
			 */
			if (tmpl_is_attr(h->vpt) &&
			    (g->vpt->tmpl_da->type == h->vpt->tmpl_da->type)) {
				cond.cast = NULL;
			}

			/*
			 *	Use the pre-expanded string.
			 */
		} else if (tmpl_is_xlat_struct(g->vpt) ||
			   tmpl_is_xlat(g->vpt) ||
			   tmpl_is_exec(g->vpt)) {
			map.rhs = h->vpt;
			map.lhs = &vpt;
			cond.cast = NULL;

			/*
			 *	Else evaluate the 'switch' statement.
			 */
		} else {
			map.rhs = h->vpt;
			map.lhs = g->vpt;
			cond.cast = NULL;
		}

		if (cond_eval_map(request, RLM_MODULE_UNKNOWN, 0,
					&cond) == 1) {
			found = this;
			break;
		}
	}

	if (!found) found = null_case;

do_null_case:
	talloc_free(data.datum.ptr);

	/*
	 *	Nothing found.  Just continue, and ignore the "switch"
	 *	statement.
	 */
	if (!found) return UNLANG_ACTION_EXECUTE_NEXT;

	unlang_interpret_push(request, found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_case(REQUEST *request, rlm_rcode_t *presult)
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
