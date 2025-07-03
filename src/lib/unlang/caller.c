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
 * @file unlang/caller.c
 * @brief Unlang "caller" keyword evaluation.  Used for setting allowed parent protocols
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/state.h>

#include "caller_priv.h"
#include "group_priv.h"

static unlang_action_t unlang_caller(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_caller_t			*gext = unlang_group_to_caller(g);

	fr_assert(g->num_children > 0); /* otherwise the compilation is broken */

	/*
	 *	No parent, or the dictionaries don't match.  Ignore it.
	 */
	if (!request->parent || (request->parent->proto_dict != gext->dict)) {
		RDEBUG2("...");
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	/*
	 *	The dictionary matches.  Go recurse into its' children.
	 */
	return unlang_group(p_result, request, frame);
}


static unlang_t *unlang_compile_caller(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION			*cs = cf_item_to_section(ci);
	unlang_t			*c;

	unlang_group_t			*g;
	unlang_caller_t			*gext;

	fr_token_t			type;
	char const     			*name;
	fr_dict_t const			*dict;
	unlang_compile_ctx_t		unlang_ctx2;
	tmpl_rules_t			parent_rules, t_rules;

	fr_dict_autoload_talloc_t	*dict_ref = NULL;

	name = cf_section_name2(cs);
	if (!name) {
		cf_log_err(cs, "You MUST specify a protocol name for 'caller <protocol> { ... }'");
	print_url:
		cf_log_err(ci, DOC_KEYWORD_REF(caller));
		return NULL;
	}

	type = cf_section_name2_quote(cs);
	if (type != T_BARE_WORD) {
		cf_log_err(cs, "The argument to 'caller' cannot be a quoted string or a dynamic value");
		goto print_url;
	}

	dict = fr_dict_by_protocol_name(name);
	if (!dict) {
		dict_ref = fr_dict_autoload_talloc(NULL, &dict, name);
		if (!dict_ref) {
			cf_log_perr(cs, "Unknown protocol '%s'", name);
			goto print_url;
		}
	}

	/*
	 *	Create a new parent context with the new dictionary.
	 */
	memcpy(&parent_rules, unlang_ctx->rules, sizeof(parent_rules));
	memcpy(&t_rules, unlang_ctx->rules, sizeof(t_rules));
	parent_rules.attr.dict_def = dict;
	t_rules.parent = &parent_rules;

	/*
	 *	We don't want to modify the context we were passed, so
	 *	we just clone it
	 */
	memcpy(&unlang_ctx2, unlang_ctx, sizeof(unlang_ctx2));
	unlang_ctx2.rules = &t_rules;
	unlang_ctx2.section_name1 = "caller";
	unlang_ctx2.section_name2 = name;

	c = unlang_compile_section(parent, &unlang_ctx2, cs, UNLANG_TYPE_CALLER);
	if (!c) {
		talloc_free(dict_ref);
		return NULL;
	}

	/*
	 *	Set the virtual server name, which tells unlang_call()
	 *	which virtual server to call.
	 */
	g = unlang_generic_to_group(c);
	gext = unlang_group_to_caller(g);
	gext->dict = dict;

	if (dict_ref) {
		/*
		 *	Parent the dictionary reference correctly now that we
		 *	have the section with the dependency.  This should
		 *	be fast as dict_ref has no siblings.
		 */
		talloc_steal(gext, dict_ref);
	}

	if (!g->num_children) {
		talloc_free(c);
		return UNLANG_IGNORE;
	}

	return c;
}

void unlang_caller_init(void)
{
	unlang_register(UNLANG_TYPE_CALLER,
			   &(unlang_op_t){
				.name = "caller",
				.type = UNLANG_TYPE_CALLER,
				.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

				.compile = unlang_compile_caller,
				.interpret = unlang_caller,

				.unlang_size = sizeof(unlang_caller_t),
				.unlang_name = "unlang_caller_t",
			   });
}
