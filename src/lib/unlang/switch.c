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

#include <freeradius-devel/server/rcode.h>
#include "group_priv.h"
#include "switch_priv.h"
#include "xlat_priv.h"

static unlang_action_t unlang_switch(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t		*found;

	unlang_group_t		*switch_g;
	unlang_switch_t		*switch_gext;

	fr_value_box_t const	*box = NULL;

	fr_pair_t		*vp;

	/*
	 *	Mock up an unlang_cast_t.  Note that these on-stack
	 *	buffers are the reason why case_cmp(), case_hash(),
	 *	and case_to_key() use direct casts, and not the
	 *	"generic to x" functions.
	 */
	tmpl_t			case_vpt = (tmpl_t) {
					.type = TMPL_TYPE_DATA,
				};
	unlang_case_t		my_case = (unlang_case_t) {
					.group = (unlang_group_t) {
						.self = (unlang_t) {
							.type = UNLANG_TYPE_CASE,
						},
					},
					.vpt = &case_vpt,
				};

	switch_g = unlang_generic_to_group(frame->instruction);
	switch_gext = unlang_group_to_switch(switch_g);

	found = NULL;

	/*
	 *	The attribute doesn't exist.  We can skip
	 *	directly to the default 'case' statement.
	 */
	if (tmpl_is_attr(switch_gext->vpt)) {
		if (tmpl_find_vp(&vp, request, switch_gext->vpt) < 0) {
			found = switch_gext->default_case;
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
		   tmpl_is_exec(switch_gext->vpt)) {
		ssize_t slen;

		slen = tmpl_aexpand_type(unlang_interpret_frame_talloc_ctx(request), &box, FR_TYPE_VALUE_BOX,
					 request, switch_gext->vpt);
		if (slen < 0) {
			RDEBUG("Switch failed expanding %s - %s", switch_gext->vpt->name, fr_strerror());
			goto find_null_case;
		}
	} else if (!fr_cond_assert_msg(0, "Invalid tmpl type %s", tmpl_type_to_str(switch_gext->vpt->type))) {
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	case_gext->vpt.data.literal is an in-line box, so we
	 *	have to make a shallow copy of its contents.
	 *
	 *	Note: We do not pass a ctx here as we don't want to
	 *	create a reference.
	 */
	fr_value_box_copy_shallow(NULL, &case_vpt.data.literal, box);
	found = fr_htrie_find(switch_gext->ht, &my_case);
	if (!found) {
	find_null_case:
		found = switch_gext->default_case;
	}

do_null_case:
	/*
	 *	Nothing found.  Just continue, and ignore the "switch"
	 *	statement.
	 */
	if (!found) {
		if (box) {
			RWDEBUG("Failed to find 'case' target for value %pV", box);
		} else {
			RWDEBUG("Failed to find 'default' target when expansion of %s returning no value",
				switch_gext->vpt->name);
		}
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	if (unlang_interpret_push(NULL, request, found, FRAME_CONF(RLM_MODULE_NOT_SET, UNLANG_SUB_FRAME), UNLANG_NEXT_STOP) < 0) {
		RETURN_UNLANG_ACTION_FATAL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_case(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t		*g = unlang_generic_to_group(frame->instruction);

	if (unlang_list_empty(&g->children)) RETURN_UNLANG_NOOP;

	return unlang_group(p_result, request, frame);
}


static unlang_t *unlang_compile_case(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION		*cs = cf_item_to_section(ci);
	int			i;
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*case_g;
	unlang_case_t		*case_gext;
	tmpl_t			*vpt = NULL;
	tmpl_rules_t		t_rules;

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	RULES_VERIFY(&t_rules);

	if (!parent || (parent->type != UNLANG_TYPE_SWITCH)) {
		cf_log_err(cs, "\"case\" statements may only appear within a \"switch\" section");
		cf_log_err(ci, DOC_KEYWORD_REF(case));
		return NULL;
	}

	/*
	 *	case THING means "match THING"
	 *	case       means "match anything"
	 */
	name2 = cf_section_name2(cs);
	if (name2) {
		ssize_t			slen;
		fr_token_t		quote;
		unlang_group_t		*switch_g;
		unlang_switch_t		*switch_gext;

		switch_g = unlang_generic_to_group(parent);
		switch_gext = unlang_group_to_switch(switch_g);

		fr_assert(switch_gext->vpt != NULL);

		/*
		 *	We need to cast case values to match
		 *	what we're switching over, otherwise
		 *	integers of different widths won't
		 *	match.
		 */
		t_rules.cast = tmpl_expanded_type(switch_gext->vpt);

		/*
		 *	Need to pass the attribute from switch
		 *	to tmpl rules so we can convert the
		 *	case string to an integer value.
		 */
		if (tmpl_is_attr(switch_gext->vpt)) {
			fr_dict_attr_t const *da = tmpl_attr_tail_da(switch_gext->vpt);
			if (da->flags.has_value) t_rules.enumv = da;
		}

		quote = cf_section_name2_quote(cs);

		slen = tmpl_afrom_substr(cs, &vpt,
					 &FR_SBUFF_IN_STR(name2),
					 quote,
					 NULL,
					 &t_rules);
		if (!vpt) {
			cf_canonicalize_error(cs, slen, "Failed parsing argument to 'case'", name2);
			return NULL;
		}

		/*
		 *	Bare word strings are attribute references
		 */
		if (tmpl_is_attr(vpt) || tmpl_is_attr_unresolved(vpt)) {
		fail_attr:
			cf_log_err(cs, "arguments to 'case' statements MUST NOT be attribute references.");
			goto fail;
		}

		if (!tmpl_is_data(vpt) || tmpl_is_data_unresolved(vpt)) {
			cf_log_err(cs, "arguments to 'case' statements MUST be static data.");
		fail:
			talloc_free(vpt);
			return NULL;
		}

		/*
		 *	References to unresolved attributes are forbidden.  They are no longer "bare word
		 *	strings".
		 */
		if ((quote == T_BARE_WORD) && (tmpl_value_type(vpt) == FR_TYPE_STRING)) {
			goto fail_attr;
		}

	} /* else it's a default 'case' statement */

	/*
	 *	If we were asked to match something, then we MUST
	 *	match it, even if the section is empty.  Otherwise we
	 *	will silently skip the match, and then fall through to
	 *	the "default" statement.
	 */
	c = unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_CASE);
	if (!c) {
		talloc_free(vpt);
		return NULL;
	}

	case_g = unlang_generic_to_group(c);
	case_gext = unlang_group_to_case(case_g);
	case_gext->vpt = talloc_steal(case_gext, vpt);

	/*
	 *	Set all of it's codes to return, so that
	 *	when we pick a 'case' statement, we don't
	 *	fall through to processing the next one.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) c->actions.actions[i] = MOD_ACTION_RETURN;

	return c;
}

static int8_t case_cmp(void const *one, void const *two)
{
	unlang_case_t const *a = (unlang_case_t const *) one; /* may not be talloc'd! See switch.c */
	unlang_case_t const *b = (unlang_case_t const *) two; /* may not be talloc'd! */

	return fr_value_box_cmp(tmpl_value(a->vpt), tmpl_value(b->vpt));
}

static uint32_t case_hash(void const *data)
{
	unlang_case_t const *a = (unlang_case_t const *) data; /* may not be talloc'd! */

	return fr_value_box_hash(tmpl_value(a->vpt));
}

static int case_to_key(uint8_t **out, size_t *outlen, void const *data)
{
	unlang_case_t const *a = (unlang_case_t const *) data; /* may not be talloc'd! */

	return fr_value_box_to_key(out, outlen, tmpl_value(a->vpt));
}

static unlang_t *unlang_compile_switch(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION		*cs = cf_item_to_section(ci);
	CONF_ITEM		*subci;
	fr_token_t		token;
	char const		*name1, *name2;
	char const		*type_name;

	unlang_group_t		*g;
	unlang_switch_t		*gext;

	unlang_t		*c;
	ssize_t			slen;

	tmpl_rules_t		t_rules;

	fr_type_t		type;
	fr_htrie_type_t		htype;

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	RULES_VERIFY(&t_rules);

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs, "You must specify a variable to switch over for 'switch'");
	print_url:
		cf_log_err(ci, DOC_KEYWORD_REF(switch));
		return NULL;
	}

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_SWITCH);
	if (!g) return NULL;

	gext = unlang_group_to_switch(g);

	/*
	 *	Create the template.  All attributes and xlats are
	 *	defined by now.
	 *
	 *	The 'case' statements need g->vpt filled out to ensure
	 *	that the data types match.
	 */
	token = cf_section_name2_quote(cs);

	if ((token == T_BARE_WORD) && (name2[0] != '%')) {
		slen = tmpl_afrom_attr_substr(gext, NULL, &gext->vpt,
					      &FR_SBUFF_IN_STR(name2),
					      NULL,
					      &t_rules);
	} else {
		slen = tmpl_afrom_substr(gext, &gext->vpt,
					 &FR_SBUFF_IN_STR(name2),
					 token,
					 NULL,
					 &t_rules);
	}
	if (!gext->vpt) {
		cf_canonicalize_error(cs, slen, "Failed parsing argument to 'switch'", name2);
		talloc_free(g);
		return NULL;
	}

	c = unlang_group_to_generic(g);
	c->name = "switch";
	c->debug_name = talloc_typed_asprintf(c, "switch %s", name2);

	/*
	 *	Fixup the template before compiling the children.
	 *	This is so that compile_case() can do attribute type
	 *	checks / casts against us.
	 */
	if (!pass2_fixup_tmpl(g, &gext->vpt, cf_section_to_item(cs), unlang_ctx->rules->attr.dict_def)) {
		talloc_free(g);
		return NULL;
	}

	if (tmpl_is_list(gext->vpt)) {
		cf_log_err(cs, "Cannot use list for 'switch' statement");
	error:
		talloc_free(g);
		goto print_url;
	}

	if (tmpl_contains_regex(gext->vpt)) {
		cf_log_err(cs, "Cannot use regular expression for 'switch' statement");
		goto error;
	}

	if (tmpl_is_data(gext->vpt)) {
		cf_log_err(cs, "Cannot use constant data for 'switch' statement");
		goto error;
	}

	if (tmpl_is_xlat(gext->vpt)) {
		xlat_exp_head_t *xlat = tmpl_xlat(gext->vpt);

		if (xlat->flags.constant || xlat->flags.pure) {
			cf_log_err(cs, "Cannot use constant data for 'switch' statement");
			goto error;
		}
	}


	if (tmpl_needs_resolving(gext->vpt)) {
		cf_log_err(cs, "Cannot resolve key for 'switch' statement");
		goto error;
	}

	type_name = cf_section_argv(cs, 0); /* AFTER name1, name2 */
	if (type_name) {
		type = fr_table_value_by_str(fr_type_table, type_name, FR_TYPE_NULL);

		/*
		 *	Should have been caught in cf_file.c, process_switch()
		 */
		fr_assert(type != FR_TYPE_NULL);
		fr_assert(fr_type_is_leaf(type));

	do_cast:
		if (tmpl_cast_set(gext->vpt, type) < 0) {
			cf_log_perr(cs, "Failed setting cast type");
			goto error;
		}

	} else {
		/*
		 *	Get the return type of the tmpl.  If we don't know,
		 *	mash it all to string.
		 */
		type = tmpl_data_type(gext->vpt);
		if ((type == FR_TYPE_NULL) || (type == FR_TYPE_VOID)) {
			type = FR_TYPE_STRING;
			goto do_cast;
		}
	}

	htype = fr_htrie_hint(type);
	if (htype == FR_HTRIE_INVALID) {
		cf_log_err(cs, "Invalid data type '%s' used for 'switch' statement",
			    fr_type_to_str(type));
		goto error;
	}

	gext->ht = fr_htrie_alloc(gext, htype,
				  (fr_hash_t) case_hash,
				  (fr_cmp_t) case_cmp,
				  (fr_trie_key_t) case_to_key,
				  NULL);
	if (!gext->ht) {
		cf_log_err(cs, "Failed initializing internal data structures");
		talloc_free(g);
		return NULL;
	}

	/*
	 *	Walk through the children of the switch section,
	 *	ensuring that they're all 'case' statements, and then compiling them.
	 */
	for (subci = cf_item_next(cs, NULL);
	     subci != NULL;
	     subci = cf_item_next(cs, subci)) {
		CONF_SECTION *subcs;
		unlang_t *single;
		unlang_case_t	*case_gext;

		if (!cf_item_is_section(subci)) {
			if (!cf_item_is_pair(subci)) continue;

			cf_log_err(subci, "\"switch\" sections can only have \"case\" subsections");
			goto error;
		}

		subcs = cf_item_to_section(subci);	/* can't return NULL */
		name1 = cf_section_name1(subcs);

		if (strcmp(name1, "case") != 0) {
			/*
			 *	We finally support "default" sections for "switch".
			 */
			if (strcmp(name1, "default") == 0) {
				if (cf_section_name2(subcs) != 0) {
					cf_log_err(subci, "\"default\" sections cannot have a match argument");
					goto error;
				}
				goto handle_default;
			}

			cf_log_err(subci, "\"switch\" sections can only have \"case\" subsections");
			goto error;
		}

		name2 = cf_section_name2(subcs);
		if (!name2) {
		handle_default:
			if (gext->default_case) {
				cf_log_err(subci, "Cannot have two 'default' case statements");
				goto error;
			}
		}

		/*
		 *	Compile the subsection.
		 */
		single = unlang_compile_case(c, unlang_ctx, subci);
		if (!single) goto error;

		fr_assert(single->type == UNLANG_TYPE_CASE);

		/*
		 *	Remember the "default" section, and insert the
		 *	non-default "case" into the htrie.
		 */
		case_gext = unlang_group_to_case(unlang_generic_to_group(single));
		if (!case_gext->vpt) {
			gext->default_case = single;

		} else if (!fr_htrie_insert(gext->ht, single)) {
			single = fr_htrie_find(gext->ht, single);

			/*
			 *	@todo - look up the key and get the previous one?
			 */
			cf_log_err(subci, "Failed inserting 'case' statement.  Is there a duplicate?");

			if (single) cf_log_err(unlang_generic_to_group(single)->cs, "Duplicate may be here.");

			goto error;
		}

		unlang_list_insert_tail(&g->children, single);
	}

	return c;
}

void unlang_switch_init(void)
{
	unlang_register(&(unlang_op_t) {
			.name = "switch",
			.type = UNLANG_TYPE_SWITCH,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_switch,
			.interpret = unlang_switch,

			.unlang_size = sizeof(unlang_switch_t),
			.unlang_name = "unlang_switch_t",

			.pool_headers = TMPL_POOL_DEF_HEADERS,
			.pool_len = TMPL_POOL_DEF_LEN
		});


	unlang_register(&(unlang_op_t){
			.name = "case",
			.type = UNLANG_TYPE_CASE,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_BREAK_POINT,

			.compile = unlang_compile_case,
			.interpret = unlang_case,

			.unlang_size = sizeof(unlang_case_t),
			.unlang_name = "unlang_case_t",
		});
}
