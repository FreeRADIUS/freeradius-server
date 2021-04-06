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

#include "group_priv.h"
#include "switch_priv.h"
#include "unlang_priv.h"

static unlang_action_t unlang_switch(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t		*this, *found, *null_case;

	unlang_group_t		*switch_g;
	unlang_switch_t		*switch_gext;

	tmpl_t			vpt;
	fr_value_box_t const	*box = NULL;

	fr_pair_t		*vp;

	switch_g = unlang_generic_to_group(frame->instruction);
	switch_gext = unlang_group_to_switch(switch_g);

	null_case = found = NULL;

	/*
	 *	The attribute doesn't exist.  We can skip
	 *	directly to the default 'case' statement.
	 */
	if (tmpl_is_attr(switch_gext->vpt)) {
		if (tmpl_find_vp(&vp, request, switch_gext->vpt) < 0) {
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
		} else {
			box = &vp->data;
		}

		/*
		 *	Expand the template if necessary, so that it
		 *	is evaluated once instead of for each 'case'
		 *	statement.
		 */
	} else if (tmpl_is_xlat(switch_gext->vpt) ||
	     tmpl_is_xlat_unresolved(switch_gext->vpt) ||
	     tmpl_is_exec(switch_gext->vpt)) {
		char *p;
		ssize_t len;

		len = tmpl_aexpand(request, &p, request, switch_gext->vpt, NULL, NULL);
		if (len < 0) goto find_null_case;

		tmpl_init_shallow(&vpt, TMPL_TYPE_DATA, T_SINGLE_QUOTED_STRING, p, len);
		fr_value_box_bstrndup_shallow(&vpt.data.literal, NULL, p, len, false);
		box = tmpl_value(&vpt);
	}

	/*
	 *	Find either the exact matching name, or the
	 *	"case {...}" statement.
	 */
	for (this = switch_g->children; this; this = this->next) {
		unlang_group_t	*case_g;
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
		 *	We have two values, just compare them.
		 */
		if (fr_value_box_cmp(box, &case_gext->vpt->data.literal) == 0) {
			found = this;
			break;
		}
	}

	if (!found) found = null_case;

do_null_case:
	if (box == tmpl_value(&vpt)) fr_value_box_clear_value(&vpt.data.literal);

	/*
	 *	Nothing found.  Just continue, and ignore the "switch"
	 *	statement.
	 */
	if (!found) return UNLANG_ACTION_EXECUTE_NEXT;

	if (unlang_interpret_push(request, found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_case(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t		*g = unlang_generic_to_group(frame->instruction);

	if (!g->children) {
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_group(p_result, request, frame);
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
