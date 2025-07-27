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
 * @file unlang/try.c
 * @brief Unlang "try" keyword evaluation.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "try_priv.h"

static unlang_action_t skip_to_catch(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	rlm_rcode_t		rcode = unlang_interpret_rcode(request);
	unlang_try_t const     	*gext = unlang_generic_to_try(frame->instruction);

	fr_assert(frame->instruction->type == UNLANG_TYPE_TRY);

	/*
	 *	Push the one "catch" section that we want to run.  Once it's done, it will pop, return to us,
	 *	and we will continue with the next sibling.
	 */
	if (gext->catch[rcode]) {
		if (unlang_interpret_push(NULL, request, gext->catch[rcode],
					  FRAME_CONF(RLM_MODULE_NOT_SET, UNLANG_SUB_FRAME), false) < 0) {
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		return UNLANG_ACTION_PUSHED_CHILD;
	}

	RDEBUG3("No catch section for %s",
		fr_table_str_by_value(mod_rcode_table, rcode, "<invalid>"));

	/*
	 *	Go to the next sibling, which MUST NOT be a "catch".
	 */
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_try(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	/*
	 *	When this frame finishes, jump ahead to the appropriate "catch".
	 *
	 *	All of the magic is done in the compile phase.
	 */
	frame_repeat(frame, skip_to_catch);

	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}

static unlang_t *unlang_compile_try(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION	*cs = cf_item_to_section(ci);
	unlang_group_t	*g;
	unlang_t	*c;
	CONF_SECTION	*parent_cs, *next;

	/*
	 *	The transaction is empty, ignore it.
	 */
	if (!cf_item_next(cs, NULL)) {
		cf_log_err(cs, "'try' sections cannot be empty");
	print_url:
		cf_log_err(ci, DOC_KEYWORD_REF(try));
		return NULL;
	}

	if (cf_section_name2(cs) != NULL) {
		cf_log_err(cs, "Unexpected argument to 'try' section");
		goto print_url;
	}

	parent_cs = cf_item_to_section(cf_parent(cs));
	next = cf_section_next(parent_cs, cs);

	if (!next ||
	    (strcmp(cf_section_name1(next), "catch") != 0)) {
		cf_log_err(cs, "'try' sections must be followed by a 'catch'");
		goto print_url;
	}

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_TRY);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);
	c->debug_name = c->name = cf_section_name1(cs);

	return unlang_compile_children(g, unlang_ctx);
}


void unlang_try_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "try",
			.type = UNLANG_TYPE_TRY,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET,

			.compile = unlang_compile_try,
			.interpret = unlang_try,

			.unlang_size = sizeof(unlang_try_t),
			.unlang_name = "unlang_try_t",
		});
}
