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
 * @file unlang/catch.c
 * @brief Unlang "catch" keyword evaluation.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/rcode.h>
#include "unlang_priv.h"
#include "catch_priv.h"

static unlang_action_t catch_skip_to_next(UNUSED unlang_result_t *p_result, UNUSED request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t		*unlang;

	fr_assert(frame->instruction->type == UNLANG_TYPE_CATCH);

	for (unlang = frame->instruction->next;
	     unlang != NULL;
	     unlang = unlang->next) {
		if (unlang->type == UNLANG_TYPE_CATCH) continue;

		break;
	}

	return frame_set_next(frame, unlang);
}

static unlang_action_t unlang_catch(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
#ifndef NDEBUG
	unlang_catch_t const *c = unlang_generic_to_catch(frame->instruction);

	fr_assert(!c->catching[p_result->rcode]);
#endif

	/*
	 *	Skip over any "catch" statementa after this one.
	 */
	frame_repeat(frame, catch_skip_to_next);

	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}


/** Skip ahead to a particular "catch" instruction.
 *
 */
unlang_action_t unlang_interpret_skip_to_catch(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t		*unlang;
	rlm_rcode_t		rcode = unlang_interpret_rcode(request);

	fr_assert(frame->instruction->type == UNLANG_TYPE_TRY);

	/*
	 *	'try' at the end of a block without 'catch' should have been caught by the compiler.
	 */
	fr_assert(frame->instruction->next);

	for (unlang = frame->instruction->next;
	     unlang != NULL;
	     unlang = unlang->next) {
		unlang_catch_t const *c;

		if (unlang->type != UNLANG_TYPE_CATCH) {
		not_caught:
			RDEBUG3("No catch section for %s",
				fr_table_str_by_value(mod_rcode_table, rcode, "<invalid>"));
			return frame_set_next(frame, unlang);
		}

		if (rcode >= RLM_MODULE_NUMCODES) continue;

		c = unlang_generic_to_catch(unlang);
		if (c->catching[rcode]) break;
	}
	if (!unlang) goto not_caught;

	return frame_set_next(frame, unlang);
}

static int catch_argv(CONF_SECTION *cs, unlang_catch_t *ca, char const *name)
{
	int rcode;

	rcode = fr_table_value_by_str(mod_rcode_table, name, -1);
	if (rcode < 0) {
		cf_log_err(cs, "Unknown rcode '%s'.", name);
		return -1;
	}

	if (ca->catching[rcode]) {
		cf_log_err(cs, "Duplicate rcode '%s'.", name);
		return -1;
	}

	ca->catching[rcode] = true;

	return 0;
}

static unlang_t *unlang_compile_catch(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION *cs = cf_item_to_section(ci);
	unlang_group_t *g;
	unlang_t *c;
	unlang_catch_t *ca;
	CONF_ITEM *prev;
	char const *name;

	prev = cf_item_prev(cf_parent(ci), ci);
	while (prev && cf_item_is_data(prev)) prev = cf_item_prev(cf_parent(ci), prev);

	if (!prev || !cf_item_is_section(prev)) {
	fail:
		cf_log_err(cs, "Found 'catch' section with no previous 'try'");
		cf_log_err(ci, DOC_KEYWORD_REF(catch));
		return NULL;
	}

	name = cf_section_name1(cf_item_to_section(prev));
	fr_assert(name != NULL);

	if ((strcmp(name, "try") != 0) && (strcmp(name, "catch") != 0)) {
		/*
		 *	The previous thing has to be a section.  And it has to
		 *	be either a "try" or a "catch".
		 */
		goto fail;
	}

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_CATCH);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	/*
	 *	Want to log what we caught
	 */
	c->debug_name = c->name = talloc_typed_asprintf(c, "%s %s", cf_section_name1(cs), cf_section_name2(cs));

	ca = unlang_group_to_catch(g);
	if (!cf_section_name2(cs)) {
		/*
		 *	No arg2: catch errors
		 */
		ca->catching[RLM_MODULE_REJECT] = true;
		ca->catching[RLM_MODULE_FAIL] = true;
		ca->catching[RLM_MODULE_INVALID] = true;
		ca->catching[RLM_MODULE_DISALLOW] = true;

	} else {
		int i;

		name = cf_section_name2(cs);

		if (catch_argv(cs, ca, name) < 0) {
			talloc_free(c);
			return NULL;
		}

		for (i = 0; (name = cf_section_argv(cs, i)) != NULL; i++) {
			if (catch_argv(cs, ca, name) < 0) {
				talloc_free(c);
				return NULL;
			}
		}
	}

	/*
	 *	@todo - Else parse and limit the things we catch
	 */
	return unlang_compile_children(g, unlang_ctx);
}

void unlang_catch_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "catch",
			.type = UNLANG_TYPE_CATCH,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_catch,
			.interpret = unlang_catch,

			.unlang_size = sizeof(unlang_catch_t),
			.unlang_name = "unlang_catch_t",
		});
}
