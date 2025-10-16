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
#include "try_priv.h"

static unlang_action_t unlang_catch(UNUSED unlang_result_t *p_result, request_t *request, UNUSED unlang_stack_frame_t *frame)
{
	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}


/*
 *	Sanity checks have already been done by compile_try().
 */
static void catch_argv(unlang_try_t *gext, char const *name, unlang_t *c)
{
	rlm_rcode_t rcode;

	rcode = fr_table_value_by_str(mod_rcode_table, name, RLM_MODULE_NOT_SET);
	fr_assert(rcode != RLM_MODULE_NOT_SET);
	fr_assert(!gext->catch[rcode]);

	gext->catch[rcode] = c;
}

static unlang_t *unlang_compile_catch(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION	*cs = cf_item_to_section(ci);
	unlang_group_t	*g;
	unlang_t	*c;
	unlang_try_t	*gext;
	char const	*name2;

	g = unlang_generic_to_group(parent);
	fr_assert(g != NULL);

	/*
	 *	"catch" is NOT inserted into the normal child list.
	 *	It's an exception, and is run only if the "try" says
	 *	to run it.
	 */
	c = unlang_list_tail(&g->children);
	if (!c || c->type != UNLANG_TYPE_TRY) {
		cf_log_err(cs, "Found 'catch' section with no previous 'try'");
		cf_log_err(ci, DOC_KEYWORD_REF(catch));
		return NULL;
	}

	gext = talloc_get_type_abort(c, unlang_try_t);
	fr_assert(gext != NULL);

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_CATCH);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	name2 = cf_section_name2(cs);

	/*
	 *	catch { ... } has to be the last one, and will catch _all_ rcodes that weren't mentioned
	 *	before.
	 */
	if (!cf_section_name2(cs)) {
		int i;

		c->debug_name = c->name = "catch";

		for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
			if (gext->catch[i]) continue;

			gext->catch[i] = c;
		}

	} else {
		int i;

		c->debug_name = c->name = talloc_typed_asprintf(c, "%s %s", cf_section_name1(cs), name2);

		catch_argv(gext, name2, c);

		for (i = 0; (name2 = cf_section_argv(cs, i)) != NULL; i++) {
			catch_argv(gext, name2, c);
		}
	}

	/*
	 *	Compile our children.
	 */
	if (!unlang_compile_children(g, unlang_ctx)) {
		return NULL;
	}

	/*
	 *	The "catch" section isn't in the parent list.  It's just associated with "try".
	 */
	(void) talloc_steal(gext, c);
	c->parent = &gext->group.self;
	c->list = NULL;

	/*
	 *	Don't insert it unto the normal list of children.
	 */
	return UNLANG_IGNORE;
}

void unlang_catch_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "catch",
			.type = UNLANG_TYPE_CATCH,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_catch,
			.interpret = unlang_catch,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",
		});
}
