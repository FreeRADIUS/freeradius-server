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
 * @file unlang/condition.c
 * @brief Unlang "condition" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "condition_priv.h"
#include "group_priv.h"

typedef struct {
	fr_value_box_list_t	out;				//!< Head of the result of a nested
								///< expansion.
	unlang_result_t		result;				//!< Store the result of unlang expressions.
} unlang_frame_state_cond_t;

static unlang_action_t unlang_if_resume(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_cond_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_cond_t);
	fr_value_box_t			*box = fr_value_box_list_head(&state->out);
	bool				value;
	unlang_t const			*unlang;

	/*
	 *	Something in the conditional evaluation failed.
	 */
	if (state->result.rcode == RLM_MODULE_FAIL) {
		unlang_group_t *g = unlang_generic_to_group(frame->instruction);
		unlang_cond_t  *gext = unlang_group_to_cond(g);

		RDEBUG2("... failed to evaluate condition ...");

		if (!gext->has_else) RETURN_UNLANG_FAIL;
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	if (!box) {
		value = false;

	} else if (fr_value_box_list_next(&state->out, box) != NULL) {
		value = true;

	} else {
		value = fr_value_box_is_truthy(box);
	}

	if (!value) {
		RDEBUG2("...");
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	/*
	 *	Tell the main interpreter to skip over the else /
	 *	elsif blocks, as this "if" condition was taken.
	 */
	for (unlang = frame->next;
	     unlang != NULL;
	     unlang = unlang_list_next(unlang->list, unlang)) {
		if ((unlang->type == UNLANG_TYPE_ELSE) ||
		    (unlang->type == UNLANG_TYPE_ELSIF)) {
			continue;
		}

		break;
	}

	/*
	 *	Do NOT call frame_set_next(), as that will clean up the current frame.
	 */
	frame->next = unlang;

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	return unlang_group(p_result, request, frame);
}

static unlang_action_t unlang_if(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_cond_t			*gext = unlang_group_to_cond(g);
	unlang_frame_state_cond_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_cond_t);

	fr_assert(gext->head != NULL);

	/*
	 *	If we always run this condition, then don't bother pushing anything onto the stack.
	 *
	 *	We still run this condition, even for "false" values, due to things like
	 *
	 *		if (0) { ... } elsif ....
	 */
	if (gext->is_truthy) {
		return unlang_group(p_result, request, frame);
	}

	frame_repeat(frame, unlang_if_resume);

	fr_value_box_list_init(&state->out);

	if (unlang_xlat_push(state, &state->result, &state->out,
			     request, gext->head, UNLANG_SUB_FRAME) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}


static const fr_sbuff_term_t if_terminals = FR_SBUFF_TERMS(
	L(""),
	L("{"),
);

static unlang_t *compile_if_subsection(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs, unlang_type_t type)
{
	unlang_t		*c;

	unlang_group_t		*g;
	unlang_cond_t		*gext;
	CONF_ITEM		*ci;

	xlat_exp_head_t		*head = NULL;
	bool			is_truthy = false, value = false;
	xlat_res_rules_t	xr_rules = {
		.tr_rules = &(tmpl_res_rules_t) {
			.dict_def = unlang_ctx->rules->attr.dict_def,
		},
	};

	if (!cf_section_name2(cs)) {
		cf_log_err(cs, "'%s' without condition", unlang_ops[type].name);
		return NULL;
	}

	/*
	 *	Migration support.
	 */
	{
		char const *name2 = cf_section_name2(cs);
		ssize_t slen;

		tmpl_rules_t t_rules = (tmpl_rules_t) {
			.parent = unlang_ctx->rules->parent,
			.attr = {
				.dict_def = xr_rules.tr_rules->dict_def,
				.list_def = request_attr_request,
				.ci = cf_section_to_item(cs),
				.allow_unresolved = false,
				.allow_unknown = false,
				.allow_wildcard = true,
			},
			.literals_safe_for = unlang_ctx->rules->literals_safe_for,
		};

		fr_sbuff_parse_rules_t p_rules = { };

		p_rules.terminals = &if_terminals;

		slen = xlat_tokenize_condition(cs, &head, &FR_SBUFF_IN_STR(name2), &p_rules, &t_rules);
		if (slen == 0) {
			cf_canonicalize_error(cs, slen, "Empty conditions are invalid", name2);
			return NULL;
		}

		if (slen < 0) {
			slen++;	/* fr_slen_t vs ssize_t */
			cf_canonicalize_error(cs, slen, "Failed parsing condition", name2);
			return NULL;
		}

		/*
		 *	Resolve the xlat first.
		 */
		if (xlat_resolve(head, &xr_rules) < 0) {
			cf_log_err(cs, "Failed resolving condition - %s", fr_strerror());
			return NULL;
		}

		fr_assert(!xlat_needs_resolving(head));

		is_truthy = xlat_is_truthy(head, &value);

		/*
		 *	If the condition is always false, we don't compile the
		 *	children.
		 */
		if (is_truthy && !value) {
			cf_log_debug_prefix(cs, "Skipping contents of '%s' as it is always 'false'",
					    unlang_ops[type].name);

			/*
			 *	Free the children, which frees any xlats,
			 *	conditions, etc. which were defined, but are
			 *	now entirely unused.
			 *
			 *	However, we still need to cache the conditions, as they will be accessed at run-time.
			 */
			c = unlang_compile_empty(parent, unlang_ctx, cs, type);
			cf_section_free_children(cs);
		} else {
			c = unlang_compile_section(parent, unlang_ctx, cs, type);
		}
	}

	if (!c) return NULL;
	fr_assert(c != UNLANG_IGNORE);

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_cond(g);

	gext->head = head;
	gext->is_truthy = is_truthy;
	gext->value = value;

	ci = cf_section_to_item(cs);
	while ((ci = cf_item_next(parent->ci, ci)) != NULL) {
		if (cf_item_is_data(ci)) continue;

		break;
	}

	/*
	 *	If there's an 'if' without an 'else', then remember that.
	 */
	if (ci && cf_item_is_section(ci)) {
		char const *name;

		name = cf_section_name1(cf_item_to_section(ci));
		fr_assert(name != NULL);

		gext->has_else = (strcmp(name, "else") == 0) || (strcmp(name, "elsif") == 0);
	}

	return c;
}

static unlang_t *unlang_compile_if(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	return compile_if_subsection(parent, unlang_ctx, cf_item_to_section(ci), UNLANG_TYPE_IF);
}

static unlang_t *unlang_compile_elsif(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	return compile_if_subsection(parent, unlang_ctx, cf_item_to_section(ci), UNLANG_TYPE_ELSIF);
}

static unlang_t *unlang_compile_else(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION *cs = cf_item_to_section(ci);

	if (cf_section_name2(cs)) {
		cf_log_err(cs, "'else' cannot have a condition");
		return NULL;
	}

	return unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_ELSE);
}


void unlang_condition_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "if",
			.type = UNLANG_TYPE_IF,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_if,
			.interpret = unlang_if,

			.unlang_size = sizeof(unlang_cond_t),
			.unlang_name = "unlang_cond_t",
			.pool_headers = 1 + 1 + (TMPL_POOL_DEF_HEADERS * 2),
			.pool_len = sizeof(map_t) + (TMPL_POOL_DEF_LEN * 2),

			.frame_state_size = sizeof(unlang_frame_state_cond_t),
			.frame_state_type = "unlang_frame_state_cond_t",
		});

	unlang_register(&(unlang_op_t){
			.name = "else",
			.type = UNLANG_TYPE_ELSE,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_else,
			.interpret = unlang_group,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t"	
		});

	unlang_register(&(unlang_op_t){
			.name = "elsif",
			.type = UNLANG_TYPE_ELSIF,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_elsif,
			.interpret = unlang_if,

			.unlang_size = sizeof(unlang_cond_t),
			.unlang_name = "unlang_cond_t",
			.pool_headers = 1 + 1 + (TMPL_POOL_DEF_HEADERS * 2),
			.pool_len = sizeof(map_t) + (TMPL_POOL_DEF_LEN * 2),

			.frame_state_size = sizeof(unlang_frame_state_cond_t),
			.frame_state_type = "unlang_frame_state_cond_t",
		});
}
