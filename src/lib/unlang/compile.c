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
 * @file unlang/compile.c
 * @brief Functions to convert configuration sections into unlang structures.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <freeradius-devel/server/virtual_servers.h>

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module_rlm.h>


#include <freeradius-devel/unlang/xlat_priv.h>

#include "call_priv.h"
#include "caller_priv.h"
#include "condition_priv.h"
#include "foreach_priv.h"
#include "load_balance_priv.h"
#include "map_priv.h"
#include "module_priv.h"
#include "parallel_priv.h"
#include "subrequest_priv.h"
#include "switch_priv.h"
#include "edit_priv.h"
#include "timeout_priv.h"
#include "limit_priv.h"
#include "transaction_priv.h"
#include "try_priv.h"
#include "mod_action.h"

static unsigned int unlang_number = 1;

/*
 *	For simplicity, this is just array[unlang_number].  Once we
 *	call unlang_thread_instantiate(), the "unlang_number" above MUST
 *	NOT change.
 */
static _Thread_local unlang_thread_t *unlang_thread_array;

/*
 *	Until we know how many instructions there are, we can't
 *	allocate an array.  So we have to put the instructions into an
 *	RB tree.
 */
static fr_rb_tree_t *unlang_instruction_tree = NULL;

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
fr_table_num_sorted_t const mod_rcode_table[] = {
	{ L("..."),        	RLM_MODULE_NOT_SET	},
	{ L("disallow"),   	RLM_MODULE_DISALLOW	},
	{ L("fail"),       	RLM_MODULE_FAIL		},
	{ L("handled"),    	RLM_MODULE_HANDLED	},
	{ L("invalid"),    	RLM_MODULE_INVALID	},
	{ L("noop"),       	RLM_MODULE_NOOP		},
	{ L("notfound"),   	RLM_MODULE_NOTFOUND	},
	{ L("ok"),	   	RLM_MODULE_OK		},
	{ L("reject"),     	RLM_MODULE_REJECT	},
	{ L("timeout"),	   	RLM_MODULE_TIMEOUT	},
	{ L("updated"),    	RLM_MODULE_UPDATED	}
};
size_t mod_rcode_table_len = NUM_ELEMENTS(mod_rcode_table);

#define UPDATE_CTX2 unlang_compile_ctx_copy(&unlang_ctx2, unlang_ctx)


static char const unlang_spaces[] = "                                                                                                                                                                                                                                                                ";

bool pass2_fixup_tmpl(UNUSED TALLOC_CTX *ctx, tmpl_t **vpt_p, CONF_ITEM const *ci, fr_dict_t const *dict)
{
	tmpl_t *vpt = *vpt_p;

	TMPL_VERIFY(vpt);

	/*
	 *	We may now know the correct dictionary
	 *	where we didn't before...
	 */
	if (!vpt->rules.attr.dict_def) tmpl_set_dict_def(vpt, dict);

	/*
	 *	Fixup any other tmpl types
	 */
	if (tmpl_resolve(vpt, &(tmpl_res_rules_t){ .dict_def = dict, .force_dict_def = (dict != NULL)}) < 0) {
		cf_log_perr(ci, NULL);
		return false;
	}

	return true;
}

/** Fixup ONE map (recursively)
 *
 *  This function resolves most things.  Most notable it CAN leave the
 *  RHS unresolved, for use in `map` sections.
 */
bool pass2_fixup_map(map_t *map, tmpl_rules_t const *rules, fr_dict_attr_t const *parent)
{
	RULES_VERIFY(rules);

	if (tmpl_is_data_unresolved(map->lhs)) {
		if (!pass2_fixup_tmpl(map, &map->lhs, map->ci, rules->attr.dict_def)) {
			return false;
		}
	}

	/*
	 *	Enforce parent-child relationships in nested maps.
	 */
	if (parent) {
		if ((map->op != T_OP_EQ) && (!map->parent || (map->parent->op != T_OP_SUB_EQ))) {
			cf_log_err(map->ci, "Invalid operator \"%s\" in nested map section.  "
				   "Only '=' is allowed",
				   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
			return false;
		}
	}

	if (map->rhs) {
		if (tmpl_is_data_unresolved(map->rhs)) {
			fr_assert(!tmpl_is_regex_xlat_unresolved(map->rhs));

			if (!pass2_fixup_tmpl(map, &map->rhs, map->ci, rules->attr.dict_def)) {
				return false;
			}
		}
	}

	/*
	 *	Sanity check sublists.
	 */
	if (!map_list_empty(&map->child)) {
		fr_dict_attr_t const *da;
		map_t *child;

		if (!tmpl_is_attr(map->lhs)) {
			cf_log_err(map->ci, "Sublists can only be assigned to a known attribute");
			return false;
		}

		da = tmpl_attr_tail_da(map->lhs);

		/*
		 *	Resolve all children.
		 */
		for (child = map_list_next(&map->child, NULL);
		     child != NULL;
		     child = map_list_next(&map->child, child)) {
			if (!pass2_fixup_map(child, rules, da)) {
				return false;
			}
		}
	}

	return true;
}

/*
 *	Do all kinds of fixups and checks for update sections.
 */
bool pass2_fixup_update(unlang_group_t *g, tmpl_rules_t const *rules)
{
	unlang_map_t	*gext = unlang_group_to_map(g);
	map_t		*map = NULL;

	RULES_VERIFY(rules);

	while ((map = map_list_next(&gext->map, map))) {
		/*
		 *	Mostly fixup the map, but maybe leave the RHS
		 *	unresolved.
		 */
		if (!pass2_fixup_map(map, rules, NULL)) return false;

		/*
		 *	Check allowed operators, and ensure that the
		 *	RHS is resolved.
		 */
		if (cf_item_is_pair(map->ci) && (unlang_fixup_update(map, NULL) < 0)) return false;
	}

	return true;
}

/*
 *	Compile the RHS of map sections to xlat_exp_t
 */
bool pass2_fixup_map_rhs(unlang_group_t *g, tmpl_rules_t const *rules)
{
	unlang_map_t	*gext = unlang_group_to_map(g);
	map_t		*map = NULL;

	RULES_VERIFY(rules);

	/*
	 *	Do most fixups on the maps.  Leaving the RHS as
	 *	unresolved, so that the `map` function can interpret
	 *	the RHS as a reference to a json string, SQL column
	 *	name, etc.
	 */
	while ((map = map_list_next(&gext->map, map))) {
		if (!pass2_fixup_map(map, rules, NULL)) return false;
	}

	/*
	 *	Map sections don't need a VPT.
	 */
	if (!gext->vpt) return true;

	if (map_list_num_elements(&gext->map) == 0) return true;

	return pass2_fixup_tmpl(map_list_head(&gext->map)->ci, &gext->vpt,
				cf_section_to_item(g->cs), rules->attr.dict_def);
}

static void unlang_dump(unlang_t *c, int depth)
{
	unlang_group_t *g;
	map_t *map;
	char buffer[1024];

	switch (c->type) {
	case UNLANG_TYPE_NULL:
	case UNLANG_TYPE_CHILD_REQUEST:
	case UNLANG_TYPE_MAX:
		fr_assert(0);
		break;

	case UNLANG_TYPE_FUNCTION:
		DEBUG("%.*s%s", depth, unlang_spaces, c->debug_name);
		break;

	case UNLANG_TYPE_MODULE:
	{
		unlang_module_t *m = unlang_generic_to_module(c);

		DEBUG("%.*s%s", depth, unlang_spaces, m->mmc.mi->name);
	}
	break;

	case UNLANG_TYPE_MAP:
	{
		unlang_map_t *gext;

		DEBUG("%.*s%s {", depth, unlang_spaces, c->debug_name);

		g = unlang_generic_to_group(c);
		gext = unlang_group_to_map(g);
		map = NULL;
		while ((map = map_list_next(&gext->map, map))) {
			map_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map);
			DEBUG("%.*s%s", depth + 1, unlang_spaces, buffer);
		}

		DEBUG("%.*s}", depth, unlang_spaces);
	}
	break;

	case UNLANG_TYPE_EDIT:
	{
		unlang_edit_t *edit;

		edit = unlang_generic_to_edit(c);
		map = NULL;
		while ((map = map_list_next(&edit->maps, map))) {
			if (!map->rhs) continue; /* @todo - fixme */

			map_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map);
			DEBUG("%.*s%s", depth + 1, unlang_spaces, buffer);
		}

		DEBUG("%.*s}", depth, unlang_spaces);
	}
	break;

	case UNLANG_TYPE_CALL:
	case UNLANG_TYPE_CALLER:
	case UNLANG_TYPE_CASE:
	case UNLANG_TYPE_FOREACH:
	case UNLANG_TYPE_FINALLY:
	case UNLANG_TYPE_ELSE:
	case UNLANG_TYPE_ELSIF:
	case UNLANG_TYPE_GROUP:
	case UNLANG_TYPE_IF:
	case UNLANG_TYPE_LOAD_BALANCE:
	case UNLANG_TYPE_PARALLEL:
	case UNLANG_TYPE_POLICY:
	case UNLANG_TYPE_REDUNDANT:
	case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
	case UNLANG_TYPE_SUBREQUEST:
	case UNLANG_TYPE_SWITCH:
	case UNLANG_TYPE_TIMEOUT:
	case UNLANG_TYPE_LIMIT:
	case UNLANG_TYPE_TRANSACTION:
	case UNLANG_TYPE_TRY:
	case UNLANG_TYPE_CATCH: /* @todo - print out things we catch, too */
		g = unlang_generic_to_group(c);

		DEBUG("%.*s%s {", depth, unlang_spaces, c->debug_name);
		unlang_list_foreach(&g->children, child) {
			unlang_dump(child, depth + 1);
		}
		DEBUG("%.*s}", depth, unlang_spaces);
		break;

	case UNLANG_TYPE_BREAK:
	case UNLANG_TYPE_CONTINUE:
	case UNLANG_TYPE_DETACH:
	case UNLANG_TYPE_RETURN:
	case UNLANG_TYPE_TMPL:
	case UNLANG_TYPE_XLAT:
		DEBUG("%.*s%s", depth, unlang_spaces, c->debug_name);
		break;
	}
}


/** Validate and fixup a map that's part of an update section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return
 *	- 0 if valid.
 *	- -1 not valid.
 */
int unlang_fixup_update(map_t *map, void *ctx)
{
	CONF_PAIR *cp = cf_item_to_pair(map->ci);

	if (!ctx) {
		/*
		 *	Fixup RHS attribute references to change NUM_UNSPEC to NUM_ALL.
		 *
		 *	RHS may be NULL for T_OP_CMP_FALSE.
		 */
		if (map->rhs) {
			switch (map->rhs->type) {
			case TMPL_TYPE_ATTR:
				if (!tmpl_is_list(map->rhs)) tmpl_attr_rewrite_leaf_num(map->rhs, NUM_ALL);
				break;

			default:
				break;
			}
		}
	}

	/*
	 *	Lots of sanity checks for insane people...
	 */

	/*
	 *	Depending on the attribute type, some operators are disallowed.
	 */
	if (tmpl_is_attr(map->lhs)) {
		/*
		 *	What exactly where you expecting to happen here?
		 */
		if (tmpl_attr_tail_da_is_leaf(map->lhs) &&
		    map->rhs && tmpl_is_list(map->rhs)) {
			cf_log_err(map->ci, "Can't copy list into an attribute");
			return -1;
		}

		if (!fr_assignment_op[map->op] && !fr_comparison_op[map->op] && !fr_binary_op[map->op]) {
			cf_log_err(map->ci, "Invalid operator \"%s\" in update section.  "
				   "Only assignment or filter operators are allowed",
				   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
			return -1;
		}

		if (fr_comparison_op[map->op] && (map->op != T_OP_CMP_FALSE)) {
			cf_log_warn(cp, "Please use the 'filter' keyword for attribute filtering");
		}
	}

	/*
	 *	If the map has a unary operator there's no further
	 *	processing we need to, as RHS is unused.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	if (unlikely(!map->rhs)) {
		cf_log_err(map->ci, "Missing rhs");
		return -1;
	}

	if (!tmpl_is_data_unresolved(map->rhs)) return 0;

	/*
	 *	If LHS is an attribute, and RHS is a literal, we can
	 *	preparse the information into a TMPL_TYPE_DATA.
	 *
	 *	Unless it's a unary operator in which case we
	 *	ignore map->rhs.
	 */
	if (tmpl_is_attr(map->lhs) && tmpl_is_data_unresolved(map->rhs)) {
		fr_type_t type = tmpl_attr_tail_da(map->lhs)->type;

		/*
		 *	@todo - allow passing octets to
		 *	FR_TYPE_STRUCT, which can then decode them as
		 *	data?  That would be rather powerful.
		 */
		if (fr_type_is_structural(type)) type = FR_TYPE_STRING;

		/*
		 *	It's a literal string, just copy it.
		 *	Don't escape anything.
		 */
		if (tmpl_cast_in_place(map->rhs, type, tmpl_attr_tail_da(map->lhs)) < 0) {
			cf_log_perr(map->ci, "Cannot convert RHS value (%s) to LHS attribute type (%s)",
				    fr_type_to_str(FR_TYPE_STRING),
				    fr_type_to_str(tmpl_attr_tail_da(map->lhs)->type));
			return -1;
		}

		return 0;
	} /* else we can't precompile the data */

	if (!tmpl_is_xlat(map->lhs)) {
		fr_assert(0);
		cf_log_err(map->ci, "Cannot determine what update action to perform");
		return -1;
	}

	return 0;
}


unlang_group_t *unlang_group_allocate(unlang_t *parent, CONF_SECTION *cs, unlang_type_t type)
{
	unlang_group_t	*g;
	unlang_t	*c;
	TALLOC_CTX	*ctx;
	unlang_op_t const *op = &unlang_ops[type];

	ctx = parent;
	if (!ctx) ctx = cs;

	fr_assert(op->unlang_size > 0);

	/*
	 *	All the groups have a common header
	 */
	g = (unlang_group_t *)_talloc_zero_pooled_object(ctx, op->unlang_size, op->unlang_name,
							 op->pool_headers, op->pool_len);
	if (!g) return NULL;

	g->cs = cs;

	c = unlang_group_to_generic(g);
	c->ci = CF_TO_ITEM(cs);

	unlang_group_type_init(c, parent, type);

	return g;
}

/**  Update a compiled unlang_t with the default actions.
 *
 *  Don't over-ride any actions which have been set.
 */
static void compile_set_default_actions(unlang_t *c, unlang_compile_ctx_t *unlang_ctx)
{
	int i;

	/*
	 *	Note that we do NOT copy over the default retries, as
	 *	that would result in every subsection doing it's own
	 *	retries.  That is not what we want.  Instead, we want
	 *	the retries to apply only to the _current_ section.
	 */

	/*
	 *	Set the default actions if they haven't already been
	 *	set.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		if (!c->actions.actions[i]) {
			c->actions.actions[i] = unlang_ctx->actions.actions[i];
		}
	}
}

#define T(_x) [T_OP_ ## _x] = true

static const bool edit_list_sub_op[T_TOKEN_LAST] = {
	T(NE),
	T(GE),
	T(GT),
	T(LE),
	T(LT),
	T(CMP_EQ),
};

/** Validate and fixup a map that's part of an edit section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return 0 if valid else -1.
 *
 *  @todo - this is only called for CONF_PAIR maps, not for
 *  CONF_SECTION.  So when we parse nested maps, there's no validation
 *  done of the CONF_SECTION.  In order to fix this, we need to have
 *  map_afrom_cs() call the validation function for the CONF_SECTION
 *  *before* recursing.
 */
static int unlang_fixup_edit(map_t *map, void *ctx)
{
	CONF_PAIR *cp = cf_item_to_pair(map->ci);
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent = NULL;
	map_t		*parent_map = ctx;

	fr_assert(parent_map);
#ifdef STATIC_ANALYZER
	if (!parent_map) return -1;
#endif

	fr_assert(tmpl_is_attr(parent_map->lhs));

	if (parent_map && (parent_map->op == T_OP_SUB_EQ)) {
		if (!edit_list_sub_op[map->op]) {
			cf_log_err(cp, "Invalid operator '%s' for right-hand side list.  It must be a comparison operator", fr_tokens[map->op]);
			return -1;
		}

	} else if (map->op != T_OP_EQ) {
		cf_log_err(cp, "Invalid operator '%s' for right-hand side list.  It must be '='", fr_tokens[map->op]);
		return -1;
	}

	/*
	 *	map_afrom_cs() will build its tree recursively, and call us for each child map.
	 */
	if (map->parent && (map->parent != parent_map)) parent_map = map->parent;

	parent = tmpl_attr_tail_da(parent_map->lhs);

	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
		da = tmpl_attr_tail_da(map->lhs);
		if (!da->flags.internal && parent && (parent->type != FR_TYPE_GROUP) &&
		    (da->parent != parent)) {
			/* FIXME - Broken check, doesn't work for key attributes */
			cf_log_err(cp, "Invalid location for %s - it is not a child of %s",
				   da->name, parent->name);
			return -1;
		}
		break;

	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_XLAT:
		break;

	default:
		cf_log_err(map->ci, "Left side of map must be an attribute "
		           "or an xlat (that expands to an attribute), not a %s",
		           tmpl_type_to_str(map->lhs->type));
		return -1;
	}

	fr_assert(map->rhs);

	switch (map->rhs->type) {
	case TMPL_TYPE_DATA_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
		break;

	default:
		cf_log_err(map->ci, "Right side of map must be an attribute, literal, xlat or exec, got type %s",
		           tmpl_type_to_str(map->rhs->type));
		return -1;
	}

	return 0;
}

/** Compile one edit section.
 */
static unlang_t *compile_edit_section(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs)
{
	unlang_edit_t		*edit;
	unlang_t		*c, *out = UNLANG_IGNORE;
	map_t			*map;
	char const		*name;
	fr_token_t		op;
	ssize_t			slen;
	fr_dict_attr_t const	*parent_da;
	int			num;

	tmpl_rules_t		t_rules;

	name = cf_section_name2(cs);
	if (name) {
		cf_log_err(cs, "Unexpected name2 '%s' for editing list %s ", name, cf_section_name1(cs));
		return NULL;
	}

	op = cf_section_name2_quote(cs);
	if ((op == T_INVALID) || !fr_list_assignment_op[op]) {
		cf_log_err(cs, "Invalid operator '%s' for editing list %s.", fr_tokens[op], cf_section_name1(cs));
		return NULL;
	}

	if ((op == T_OP_CMP_TRUE) || (op == T_OP_CMP_FALSE)) {
		cf_log_err(cs, "Invalid operator \"%s\".",
			   fr_table_str_by_value(fr_tokens_table, op, "<INVALID>"));
		return NULL;
	}

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	RULES_VERIFY(&t_rules);

	edit = talloc_zero(parent, unlang_edit_t);
	if (!edit) return NULL;

	c = out = unlang_edit_to_generic(edit);
	unlang_type_init(c, parent, UNLANG_TYPE_EDIT);
	c->name = cf_section_name1(cs);
	c->debug_name = c->name;
	c->ci = CF_TO_ITEM(cs);

	map_list_init(&edit->maps);

	/*
	 *	Allocate the map and initialize it.
	 */
	MEM(map = talloc_zero(edit, map_t));
	map->op = op;
	map->ci = cf_section_to_item(cs);
	map_list_init(&map->child);

	name = cf_section_name1(cs);

	slen = tmpl_afrom_attr_str(map, NULL, &map->lhs, name, &t_rules);
	if (slen <= 0) {
		cf_log_err(cs, "Failed parsing list reference %s - %s", name, fr_strerror());
	fail:
		talloc_free(edit);
		return NULL;
	}

	/*
	 *	Can't assign to [*] or [#]
	 */
	num = tmpl_attr_tail_num(map->lhs);
	if ((num == NUM_ALL) || (num == NUM_COUNT)) {
		cf_log_err(cs, "Invalid array reference in %s", name);
		goto fail;
	}

	/*
	 *	If the DA isn't structural, then it can't have children.
	 */
	parent_da = tmpl_attr_tail_da(map->lhs);
	if (fr_type_is_structural(parent_da->type)) {
		map_t *child;

		/*
		 *	Reset the namespace to be this attribute.  The tmpl tokenizer will take care of
		 *	figuring out if this is a group, TLV, dictionary switch, etc.
		 */
		t_rules.attr.namespace = parent_da;

		if (map_afrom_cs_edit(map, &map->child, cs, &t_rules, &t_rules, unlang_fixup_edit, map, 256) < 0) {
			goto fail;
		}

		/*
		 *	As a set of fixups... we can't do array references in -=
		 */
		if (map->op == T_OP_SUB_EQ) {
			for (child = map_list_head(&map->child); child != NULL; child = map_list_next(&map->child, child)) {
				if (!tmpl_is_attr(child->lhs)) continue;

				if (tmpl_attr_tail_num(child->lhs) != NUM_UNSPEC) {
					cf_log_err(child->ci, "Cannot use array references and values when deleting from a list");
					goto fail;
				}

				/*
				 *	The edit code doesn't do this correctly, so we just forbid it.
				 */
				if ((tmpl_attr_num_elements(child->lhs) - tmpl_attr_num_elements(map->lhs)) > 1) {
					cf_log_err(child->ci, "List deletion must operate directly on the final child");
					goto fail;
				}

				/*
				 *	We don't do list comparisons either.
				 */
				if (fr_type_is_structural(tmpl_attr_tail_da(child->lhs)->type)) {
					cf_log_err(child->ci, "List deletion cannot operate on lists");
					goto fail;
				}
			}
		}
	} else {
		/*
		 *	foo := { a, b, c }
		 */
		if (map_list_afrom_cs(map, &map->child, cs, &t_rules, NULL, NULL, 256) < 0) {
			goto fail;
		}

		if ((map->op != T_OP_SET) && !map_list_num_elements(&map->child)) {
			cf_log_err(cs, "Cannot use operator '%s' for assigning empty list to '%s' data type.",
				   fr_tokens[map->op], fr_type_to_str(parent_da->type));
			goto fail;
		}
	}
	/*
	 *	Do basic sanity checks and resolving.
	 */
	if (!pass2_fixup_map(map, unlang_ctx->rules, NULL)) goto fail;

	/*
	 *	Check operators, and ensure that the RHS has been
	 *	resolved.
	 */
//	if (unlang_fixup_update(map, NULL) < 0) goto fail;

	map_list_insert_tail(&edit->maps, map);

	return out;
}

/** Compile one edit pair
 *
 */
static unlang_t *compile_edit_pair(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_PAIR *cp)
{
	unlang_edit_t		*edit;
	unlang_t		*c = NULL, *out = UNLANG_IGNORE;
	map_t			*map;
	int			num;

	tmpl_rules_t		t_rules;
	fr_token_t		op;

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	fr_assert(t_rules.attr.ci == cf_pair_to_item(cp));
	RULES_VERIFY(&t_rules);

	edit = talloc_zero(parent, unlang_edit_t);
	if (!edit) return NULL;

	c = out = unlang_edit_to_generic(edit);
	unlang_type_init(c, parent, UNLANG_TYPE_EDIT);
	c->name = cf_pair_attr(cp);
	c->debug_name = c->name;
	c->ci = CF_TO_ITEM(cp);

	map_list_init(&edit->maps);

	op = cf_pair_operator(cp);
	if ((op == T_OP_CMP_TRUE) || (op == T_OP_CMP_FALSE)) {
		cf_log_err(cp, "Invalid operator \"%s\".",
			   fr_table_str_by_value(fr_tokens_table, op, "<INVALID>"));
	fail:
		talloc_free(edit);
		return NULL;
	}

	/*
	 *	Convert this particular map.
	 */
	if (map_afrom_cp(edit, &map, map_list_tail(&edit->maps), cp, &t_rules, NULL, true) < 0) {
		goto fail;
	}

	/*
	 *	@todo - we still want to do fixups on the RHS?
	 */
	if (tmpl_is_attr(map->lhs)) {
		/*
		 *	Can't assign to [*] or [#]
		 */
		num = tmpl_attr_tail_num(map->lhs);
		if ((num == NUM_ALL) || (num == NUM_COUNT)) {
			cf_log_err(cp, "Invalid array reference in %s", map->lhs->name);
			goto fail;
		}

		if ((map->op == T_OP_SUB_EQ) && fr_type_is_structural(tmpl_attr_tail_da(map->lhs)->type) &&
		    tmpl_is_attr(map->rhs) && tmpl_attr_tail_da(map->rhs)->flags.local) {
			cf_log_err(cp, "Cannot delete local variable %s", map->rhs->name);
			goto fail;
		}
	}

	/*
	 *	Do basic sanity checks and resolving.
	 */
	if (!pass2_fixup_map(map, unlang_ctx->rules, NULL)) goto fail;

	/*
	 *	Check operators, and ensure that the RHS has been
	 *	resolved.
	 */
	if (unlang_fixup_update(map, c) < 0) goto fail;

	map_list_insert_tail(&edit->maps, map);

	return out;
}

#define debug_braces(_type)	(unlang_ops[_type].flag & UNLANG_OP_FLAG_DEBUG_BRACES)

/** Compile a variable definition.
 *
 *  Definitions which are adjacent to one another are automatically merged
 *  into one larger variable definition.
 */
static int compile_variable(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_PAIR *cp, tmpl_rules_t *t_rules)
{
	unlang_variable_t *var;
	fr_type_t	type;
	char const	*attr, *value;
	unlang_group_t	*group;

	fr_assert(debug_braces(parent->type));

	/*
	 *	Enforce locations for local variables.
	 */
	switch (parent->type) {
	case UNLANG_TYPE_CASE:
	case UNLANG_TYPE_ELSE:
	case UNLANG_TYPE_ELSIF:
	case UNLANG_TYPE_FOREACH:
	case UNLANG_TYPE_GROUP:
	case UNLANG_TYPE_IF:
	case UNLANG_TYPE_TIMEOUT:
	case UNLANG_TYPE_LIMIT:
	case UNLANG_TYPE_POLICY:
	case UNLANG_TYPE_REDUNDANT:
	case UNLANG_TYPE_SUBREQUEST:
	case UNLANG_TYPE_LOAD_BALANCE:
	case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
		break;

	default:
		cf_log_err(cp, "Local variables cannot be used here");
		return -1;
	}

	/*
	 *	The variables exist in the parent block.
	 */
	group = unlang_generic_to_group(parent);
	if (group->variables) {
		var = group->variables;

	} else {
		group->variables = var = talloc_zero(parent, unlang_variable_t);
		if (!var) return -1;

		var->dict = fr_dict_protocol_alloc(unlang_ctx->rules->attr.dict_def);
		if (!var->dict) {
			talloc_free(var);
			return -1;
		}
		var->root = fr_dict_root(var->dict);

		var->max_attr = 1;

		/*
		 *	Initialize the new rules, and point them to the parent rules.
		 *
		 *	Then replace the parse rules with our rules, and our dictionary.
		 */
		*t_rules = *unlang_ctx->rules;
		t_rules->parent = unlang_ctx->rules;

		t_rules->attr.dict_def = var->dict;
		t_rules->attr.namespace = NULL;

		unlang_ctx->rules = t_rules;
	}

	attr = cf_pair_attr(cp);	/* data type */
	value = cf_pair_value(cp);	/* variable name */

	type = fr_table_value_by_str(fr_type_table, attr, FR_TYPE_NULL);
	if (type == FR_TYPE_NULL) {
invalid_type:
		cf_log_err(cp, "Invalid data type '%s'", attr);
		return -1;
	}

	/*
	 *	Leaf and group are OK.  TLV, Vendor, Struct, VSA, etc. are not.
	 */
	if (!(fr_type_is_leaf(type) || (type == FR_TYPE_GROUP))) goto invalid_type;

	return unlang_define_local_variable(cf_pair_to_item(cp), var, t_rules, type, value, NULL);
}

/*
 *	Compile action && rcode for later use.
 */
static int compile_action_pair(unlang_mod_actions_t *actions, CONF_PAIR *cp)
{
	int action;
	char const *attr, *value;

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) return 0;

	if (!strcasecmp(value, "return"))
		action = MOD_ACTION_RETURN;

	else if (!strcasecmp(value, "break"))
		action = MOD_ACTION_RETURN;

	else if (!strcasecmp(value, "reject"))
		action = MOD_ACTION_REJECT;

	else if (!strcasecmp(value, "retry"))
		action = MOD_ACTION_RETRY;

	else if (strspn(value, "0123456789") == strlen(value)) {
		if (strlen(value) > 2) {
		invalid_action:
			cf_log_err(cp, "Priorities MUST be between 1 and 64.");
			return 0;
		}

		action = MOD_PRIORITY(atoi(value));

		if (!MOD_ACTION_VALID_SET(action)) goto invalid_action;

	} else {
		cf_log_err(cp, "Unknown action '%s'.\n",
			   value);
		return 0;
	}

	if (strcasecmp(attr, "default") != 0) {
		int rcode;

		rcode = fr_table_value_by_str(mod_rcode_table, attr, -1);
		if (rcode < 0) {
			cf_log_err(cp,
				   "Unknown module rcode '%s'.",
				   attr);
			return 0;
		}
		actions->actions[rcode] = action;

	} else {		/* set all unset values to the default */
		int i;

		for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
			if (!actions->actions[i]) actions->actions[i] = action;
		}
	}

	return 1;
}

static bool compile_retry_section(unlang_mod_actions_t *actions, CONF_ITEM *ci)
{
	CONF_ITEM *csi;
	CONF_SECTION *cs;

	cs = cf_item_to_section(ci);
	for (csi=cf_item_next(cs, NULL);
	     csi != NULL;
	     csi=cf_item_next(cs, csi)) {
		CONF_PAIR *cp;
		char const *name, *value;

		if (cf_item_is_section(csi)) {
			cf_log_err(csi, "Invalid subsection in 'retry' configuration.");
			return false;
		}

		if (!cf_item_is_pair(csi)) continue;

		cp = cf_item_to_pair(csi);
		name = cf_pair_attr(cp);
		value = cf_pair_value(cp);

		if (!value) {
			cf_log_err(csi, "Retry configuration must specify a value");
			return false;
		}

#define CLAMP(_name, _field, _limit) do { \
			if (!fr_time_delta_ispos(actions->retry._field)) { \
				cf_log_err(csi, "Invalid value for '" STRINGIFY(_name) " = %s' - value must be positive", \
					   value); \
				return false; \
			} \
			if (fr_time_delta_cmp(actions->retry._field, fr_time_delta_from_sec(_limit)) > 0) { \
				cf_log_err(csi, "Invalid value for '" STRINGIFY(_name) " = %s' - value must be less than " STRINGIFY(_limit) "s", \
					   value); \
				return false; \
		        } \
	} while (0)

		/*
		 *	We don't use conf_parser_t here for various
		 *	magical reasons.
		 */
		if (strcmp(name, "initial_rtx_time") == 0) {
			if (fr_time_delta_from_str(&actions->retry.irt, value, strlen(value), FR_TIME_RES_SEC) < 0) {
			error:
				cf_log_err(csi, "Failed parsing '%s = %s' - %s",
					   name, value, fr_strerror());
				return false;
			}
			CLAMP(initial_rtx_time, irt, 2);

		} else if (strcmp(name, "max_rtx_time") == 0) {
			if (fr_time_delta_from_str(&actions->retry.mrt, value, strlen(value), FR_TIME_RES_SEC) < 0) goto error;

			CLAMP(max_rtx_time, mrt, 10);

		} else if (strcmp(name, "max_rtx_count") == 0) {
			unsigned long v = strtoul(value, 0, 0);

			if (v > 10) {
				cf_log_err(csi, "Invalid value for 'max_rtx_count = %s' - value must be between 0 and 10",
					   value);
				return false;
			}

			actions->retry.mrc = v;

		} else if (strcmp(name, "max_rtx_duration") == 0) {
			if (fr_time_delta_from_str(&actions->retry.mrd, value, strlen(value), FR_TIME_RES_SEC) < 0) goto error;

			CLAMP(max_rtx_duration, mrd, 20);

		} else {
			cf_log_err(csi, "Invalid item '%s' in 'retry' configuration.", name);
			return false;
		}
	}

	return true;
}

bool unlang_compile_actions(unlang_mod_actions_t *actions, CONF_SECTION *action_cs, bool module_retry)
{
	int i;
	bool disallow_retry_action = false;
	CONF_ITEM *csi;
	CONF_SECTION *cs;

	/*
	 *	Over-ride the default return codes of the module.
	 */
	cs = cf_item_to_section(cf_section_to_item(action_cs));
	for (csi=cf_item_next(cs, NULL);
	     csi != NULL;
	     csi=cf_item_next(cs, csi)) {
		char const *name;
		CONF_PAIR *cp;

		if (cf_item_is_section(csi)) {
			CONF_SECTION *subcs = cf_item_to_section(csi);

			name = cf_section_name1(subcs);

			/*
			 *	Look for a "retry" section.
			 */
			if (name && (strcmp(name, "retry") == 0) && !cf_section_name2(subcs)) {
				if (!compile_retry_section(actions, csi)) return false;
				continue;
			}

			cf_log_err(csi, "Invalid subsection.  Expected 'action = value'");
			return false;
		}

		if (!cf_item_is_pair(csi)) continue;

		cp = cf_item_to_pair(csi);

		/*
		 *	Allow 'retry = path.to.retry.config'
		 */
		name = cf_pair_attr(cp);
		if (strcmp(name, "retry") == 0) {
			CONF_ITEM *subci;
			char const *value = cf_pair_value(cp);

			if (!value) {
				cf_log_err(csi, "Missing reference string");
				return false;
			}

			subci = cf_reference_item(cs, cf_root(cf_section_to_item(action_cs)), value);
			if (!subci) {
				cf_log_perr(csi, "Failed finding reference '%s'", value);
				return false;
			}

			if (!compile_retry_section(actions, subci)) return false;
			continue;
		}

		if (!compile_action_pair(actions, cp)) {
			return false;
		}
	}

	if (module_retry) {
		if (!fr_time_delta_ispos(actions->retry.irt)) {
			cf_log_err(action_cs, "initial_rtx_time MUST be non-zero for modules which support retries.");
			return false;
		}
	} else {
		if (fr_time_delta_ispos(actions->retry.irt)) {
			cf_log_err(action_cs, "initial_rtx_time MUST be zero, as only max_rtx_count and max_rtx_duration are used.");
			return false;
		}

		if (!actions->retry.mrc && !fr_time_delta_ispos(actions->retry.mrd)) {
			disallow_retry_action = true;
		}
	}

	/*
	 *	Sanity check that "fail = retry", we actually have a
	 *	retry section.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		if (actions->actions[i] != MOD_ACTION_RETRY) continue;

		if (module_retry) {
			cf_log_err(action_cs, "Cannot use a '%s = retry' action for a module which has its own retries",
				   fr_table_str_by_value(mod_rcode_table, i, "<INVALID>"));
			return false;
		}

		if (disallow_retry_action) {
			cf_log_err(action_cs, "max_rtx_count and max_rtx_duration cannot both be zero when using '%s = retry'",
				   fr_table_str_by_value(mod_rcode_table, i, "<INVALID>"));
			return false;
		}

		if (!fr_time_delta_ispos(actions->retry.irt) &&
		    !actions->retry.mrc &&
		    !fr_time_delta_ispos(actions->retry.mrd)) {
			cf_log_err(action_cs, "Cannot use a '%s = retry' action without a 'retry { ... }' section.",
				   fr_table_str_by_value(mod_rcode_table, i, "<INVALID>"));
			return false;
		}
	}

	return true;
}

unlang_t *unlang_compile_empty(unlang_t *parent, UNUSED unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs, unlang_type_t type)
{
	unlang_group_t *g;
	unlang_t *c;

	/*
	 *	If we're compiling an empty section, then the
	 *	*interpreter* type is GROUP, even if the *debug names*
	 *	are something else.
	 */
	g = unlang_group_allocate(parent, cs, type);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);
	if (!cs) {
		c->name = unlang_ops[type].name;
		c->debug_name = c->name;

	} else {
		char const *name2;

		name2 = cf_section_name2(cs);
		if (!name2) {
			c->name = cf_section_name1(cs);
			c->debug_name = c->name;
		} else {
			c->name = name2;
			c->debug_name = talloc_typed_asprintf(c, "%s %s", cf_section_name1(cs), name2);
		}
	}

	return c;
}


static unlang_t *compile_item(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM *ci);

/*
 *	compile 'actions { ... }' inside of another group.
 */
static bool compile_action_subsection(unlang_t *c, CONF_SECTION *cs, CONF_SECTION *subcs)
{
	CONF_ITEM *ci, *next;

	ci = cf_section_to_item(subcs);

	next = cf_item_next(cs, ci);
	if (next && (cf_item_is_pair(next) || cf_item_is_section(next))) {
		cf_log_err(ci, "'actions' MUST be the last block in a section");
		return false;
	}

	if (cf_section_name2(subcs) != NULL) {
		cf_log_err(ci, "Invalid name for 'actions' section");
		return false;
	}

	/*
	 *	Over-riding the actions can be done in certain limited
	 *	situations.  In other situations (e.g. "redundant",
	 *	"load-balance"), it doesn't make sense.
	 *
	 *	Note that this limitation also applies to "retry"
	 *	timers.  We can do retries of a "group".  We cannot do
	 *	retries of "load-balance", as the "load-balance"
	 *	section already takes care of redundancy.
	 *
	 *	We may need to loosen that limitation in the future.
	 */
	switch (c->type) {
	case UNLANG_TYPE_CASE:
	case UNLANG_TYPE_CATCH:
	case UNLANG_TYPE_IF:
	case UNLANG_TYPE_ELSE:
	case UNLANG_TYPE_ELSIF:
	case UNLANG_TYPE_FOREACH:
	case UNLANG_TYPE_GROUP:
	case UNLANG_TYPE_LIMIT:
	case UNLANG_TYPE_SWITCH:
	case UNLANG_TYPE_TIMEOUT:
	case UNLANG_TYPE_TRANSACTION:
		break;

	default:
		cf_log_err(ci, "'actions' MUST NOT be in a '%s' block", unlang_ops[c->type].name);
		return false;
	}

	return unlang_compile_actions(&c->actions, subcs, false);
}


unlang_t *unlang_compile_children(unlang_group_t *g, unlang_compile_ctx_t *unlang_ctx_in)
{
	CONF_ITEM	*ci = NULL;
	unlang_t	*c, *single;
	bool		was_if = false;
	char const	*skip_else = NULL;
	unlang_compile_ctx_t *unlang_ctx;
	unlang_compile_ctx_t unlang_ctx2;
	tmpl_rules_t	t_rules, t2_rules; /* yes, it does */

	c = unlang_group_to_generic(g);

	/*
	 *	Create our own compilation context which can be edited
	 *	by a variable definition.
	 */
	unlang_compile_ctx_copy(&unlang_ctx2, unlang_ctx_in);
	t2_rules = *(unlang_ctx_in->rules);

	unlang_ctx = &unlang_ctx2;
	unlang_ctx2.rules = &t2_rules;

	t_rules = *unlang_ctx_in->rules;

	/*
	 *	Loop over the children of this group.
	 */
	while ((ci = cf_item_next(g->cs, ci))) {
		if (cf_item_is_data(ci)) continue;

		t_rules.attr.ci = ci;
		t2_rules.attr.ci = ci;

		/*
		 *	Sections are keywords, or references to
		 *	modules with updated return codes.
		 */
		if (cf_item_is_section(ci)) {
			char const *name = NULL;
			CONF_SECTION *subcs = cf_item_to_section(ci);

			/*
			 *	Skip precompiled blocks.  This is
			 *	mainly for policies.
			 */
			if (cf_data_find(subcs, unlang_group_t, NULL)) continue;

			/*
			 *	"actions" apply to the current group.
			 *	It's not a subgroup.
			 */
			name = cf_section_name1(subcs);

			/*
			 *	In-line attribute editing.  Nothing else in the parse has list assignments, so this must be it.
			 */
			if (fr_list_assignment_op[cf_section_name2_quote(subcs)]) {
				single = compile_edit_section(c, unlang_ctx, subcs);
				if (!single) {
				fail:
					talloc_free(c);
					return NULL;
				}

				goto add_child;
			}

			if (strcmp(name, "actions") == 0) {
				if (!compile_action_subsection(c, g->cs, subcs)) goto fail;
				continue;
			}

			/*
			 *	Special checks for "else" and "elsif".
			 */
			if ((strcmp(name, "else") == 0) || (strcmp(name, "elsif") == 0)) {
				/*
				 *	We ran into one without a preceding "if" or "elsif".
				 *	That's not allowed.
				 */
				if (!was_if) {
					cf_log_err(ci, "Invalid location for '%s'.  There is no preceding "
						   "'if' or 'elsif' statement", name);
					goto fail;
				}

				/*
				 *	There was a previous "if" or "elsif" which was always taken.
				 *	So we skip this "elsif" or "else".
				 */
				if (skip_else) {
					void *ptr;

					/*
					 *	And manually free this.
					 */
					ptr = cf_data_remove(subcs, xlat_exp_head_t, NULL);
					talloc_free(ptr);

					cf_section_free_children(subcs);

					cf_log_debug_prefix(ci, "Skipping contents of '%s' due to previous "
							    "'%s' being always being taken.",
							    name, skip_else);
					continue;
				}
			}

			/*
			 *	Otherwise it's a real keyword.
			 */
			single = compile_item(c, unlang_ctx, ci);
			if (!single) {
				cf_log_err(ci, "Failed to parse \"%s\" subsection", cf_section_name1(subcs));
				goto fail;
			}

			goto add_child;

		} else if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_item_to_pair(ci);

			/*
			 *	Variable definition.
			 */
			if (cf_pair_operator(cp) == T_OP_CMP_TRUE) {
				if (compile_variable(c, unlang_ctx, cp, &t_rules) < 0) goto fail;

				single = UNLANG_IGNORE;
				goto add_child;
			}

			if (!cf_pair_value(cp)) {
				single = compile_item(c, unlang_ctx, ci);
				if (!single) {
					cf_log_err(ci, "Invalid keyword \"%s\".", cf_pair_attr(cp));
					goto fail;
				}

				goto add_child;
			}

			/*
			 *	What remains MUST be an edit pair.  At this point, the state of the compiler
			 *	tells us what it is, and we don't really care if there's a leading '&'.
			 */
			single = compile_edit_pair(c, unlang_ctx, cp);
			if (!single) goto fail;

			goto add_child;
		} else {
			cf_log_err(ci, "Asked to compile unknown conf type");
			goto fail;
		}

	add_child:
		if (single == UNLANG_IGNORE) continue;

		/*
		 *	Do optimizations for "if" and "elsif"
		 *	conditions.
		 */
		switch (single->type) {
		case UNLANG_TYPE_ELSIF:
		case UNLANG_TYPE_IF:
			was_if = true;

			{
				unlang_group_t	*f;
				unlang_cond_t	*gext;

				/*
				 *	Skip else, and/or omit things which will never be run.
				 */
				f = unlang_generic_to_group(single);
				gext = unlang_group_to_cond(f);

				if (gext->is_truthy) {
					if (gext->value) {
						skip_else = single->debug_name;
					} else {
						/*
						 *	The condition never
						 *	matches, so we can
						 *	avoid putting it into
						 *	the unlang tree.
						 */
						talloc_free(single);
						continue;
					}
				}
			}
			break;

		default:
			was_if = false;
			skip_else = NULL;
			break;
		}

		/*
		 *	unlang_group_t is grown by adding a unlang_t to the end
		 */
		fr_assert(g == talloc_parent(single));
		fr_assert(single->parent == unlang_group_to_generic(g));
		unlang_list_insert_tail(&g->children, single);
		single->list = &g->children;

		/*
		 *	If it's not possible to execute statement
		 *	after the current one, then just stop
		 *	processing the children.
		 */
		if (g->self.closed) {
			cf_log_warn(ci, "Skipping remaining instructions due to '%s'",
				    single->name);
			break;
		}
	}

	return c;
}


/*
 *	Generic "compile a section with more unlang inside of it".
 */
unlang_t *unlang_compile_section(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs, unlang_type_t type)
{
	unlang_group_t	*g;
	unlang_t	*c;
	char const	*name1, *name2;

	fr_assert(unlang_ctx->rules != NULL);
	fr_assert(unlang_ctx->rules->attr.list_def);

	/*
	 *	We always create a group, even if the section is empty.
	 */
	g = unlang_group_allocate(parent, cs, type);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	/*
	 *	Remember the name for printing, etc.
	 */
	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);
	c->name = name1;

	/*
	 *	Make sure to tell the user that we're running a
	 *	policy, and not anything else.
	 */
	if (type == UNLANG_TYPE_POLICY) {
		MEM(c->debug_name = talloc_typed_asprintf(c, "policy %s", name1));

	} else if (!name2) {
		c->debug_name = c->name;

	} else {
		MEM(c->debug_name = talloc_typed_asprintf(c, "%s %s", name1, name2));
	}

	return unlang_compile_children(g, unlang_ctx);
}


static unlang_t *compile_tmpl(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM *ci)
{
	CONF_PAIR	*cp = cf_item_to_pair(ci);
	unlang_t	*c;
	unlang_tmpl_t	*ut;
	ssize_t		slen;
	char const	*p = cf_pair_attr(cp);
	tmpl_t		*vpt;

	MEM(ut = talloc_zero(parent, unlang_tmpl_t));
	c = unlang_tmpl_to_generic(ut);
	unlang_type_init(c, parent, UNLANG_TYPE_TMPL);
	c->name = p;
	c->debug_name = c->name;
	c->ci = CF_TO_ITEM(cp);

	RULES_VERIFY(unlang_ctx->rules);
	slen = tmpl_afrom_substr(ut, &vpt,
				 &FR_SBUFF_IN(p, talloc_array_length(p) - 1),
				 cf_pair_attr_quote(cp),
				 NULL,
				 unlang_ctx->rules);
	if (!vpt) {
		cf_canonicalize_error(cp, slen, "Failed parsing expansion", p);
		talloc_free(ut);
		return NULL;
	}
	ut->tmpl = vpt;	/* const issues */

	return c;
}

/*
 *	redundant, load-balance and parallel have limits on what can
 *	go in them.
 */
bool unlang_compile_limit_subsection(CONF_SECTION *cs, char const *name)
{
	CONF_ITEM *ci;

	for (ci=cf_item_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_next(cs, ci)) {
		/*
		 *	If we're a redundant, etc. group, then the
		 *	intention is to call modules, rather than
		 *	processing logic.  These checks aren't
		 *	*strictly* necessary, but they keep the users
		 *	from doing crazy things.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *subcs = cf_item_to_section(ci);
			char const *name1 = cf_section_name1(subcs);

			/*
			 *	Allow almost anything except "else"
			 *	statements.  The normal processing
			 *	falls through from "if" to "else", and
			 *	we can't do that for redundant and
			 *	load-balance sections.
			 */
			if ((strcmp(name1, "else") == 0) ||
			    (strcmp(name1, "elsif") == 0)) {
				cf_log_err(ci, "%s sections cannot contain a \"%s\" statement",
				       name, name1);
				return false;
			}
			continue;
		}

		if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_item_to_pair(ci);

			if (cf_pair_operator(cp) == T_OP_CMP_TRUE) continue;

			if (cf_pair_value(cp) != NULL) {
				cf_log_err(cp, "Unknown keyword '%s', or invalid location", cf_pair_attr(cp));
				return false;
			}
		}
	}

	return true;
}


static unlang_t *compile_function(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM *ci,
				  CONF_SECTION *subcs,
				  bool policy)
{
	unlang_compile_ctx_t		unlang_ctx2;
	unlang_t			*c;

	UPDATE_CTX2;

	/*
	 *	module.c takes care of ensuring that this is:
	 *
	 *	group foo { ...
	 *	load-balance foo { ...
	 *	redundant foo { ...
	 *	redundant-load-balance foo { ...
	 *
	 *	We can just recurse to compile the section as
	 *	if it was found here.
	 */
	if (cf_section_name2(subcs)) {
		if (policy) {
			cf_log_err(subcs, "Unexpected second name in policy");
			return NULL;
		}

		c = compile_item(parent, &unlang_ctx2, cf_section_to_item(subcs));

	} else {
		/*
		 *	We have:
		 *
		 *	foo { ...
		 *
		 *	So we compile it like it was:
		 *
		 *	group foo { ...
		 */
		c = unlang_compile_section(parent, &unlang_ctx2, subcs,
				    policy ? UNLANG_TYPE_POLICY : UNLANG_TYPE_GROUP);
	}
	if (!c) return NULL;
	fr_assert(c != UNLANG_IGNORE);

	/*
	 *	Return the compiled thing if we can.
	 */
	if (!cf_item_is_section(ci)) return c;

	/*
	 *	Else we have a reference to a policy, and that reference
	 *	over-rides the return codes for the policy!
	 */
	if (!unlang_compile_actions(&c->actions, cf_item_to_section(ci), false)) {
		talloc_free(c);
		return NULL;
	}

	return c;
}

/** Load a named module from the virtual module list, or from the "policy" subsection.
 *
 * If it's "foo.method", look for "foo", and return "method" as the method
 * we wish to use, instead of the input component.
 *
 * @param[in] ci		Configuration item to check
 * @param[in] real_name		Complete name string e.g. foo.authorize.
 * @param[in] virtual_name	Virtual module name e.g. foo.
 * @param[in] method_name	Method override (may be NULL) or the method
 *				name e.g. authorize.
 * @param[in] unlang_ctx	Unlang context this call is being compiled in.
 * @param[out] policy		whether or not this thing was a policy
 * @return the CONF_SECTION specifying the virtual module.
 */
static CONF_SECTION *virtual_module_find_cs(CONF_ITEM *ci, UNUSED char const *real_name, char const *virtual_name,
					    char const *method_name, unlang_compile_ctx_t *unlang_ctx, bool *policy)
{
	CONF_SECTION *cs, *subcs, *conf_root;
	CONF_ITEM *loop;
	char buffer[256];

	*policy = false;
	conf_root = cf_root(ci);

	/*
	 *	Look for "foo" as a virtual server.  If we find it,
	 *	AND there's no method name, we've found the right
	 *	thing.
	 *
	 *	Found "foo".  Load it as "foo", or "foo.method".
	 *
	 *	Return it to the caller, with the updated method.
	 */
	subcs = module_rlm_virtual_by_name(virtual_name);
	if (subcs) goto check_for_loop;

	/*
	 *	Look for it in "policy".
	 *
	 *	If there's no policy section, we can't do anything else.
	 */
	cs = cf_section_find(conf_root, "policy", NULL);
	if (!cs) return NULL;

	*policy = true;

	/*
	 *	"foo.authorize" means "load policy 'foo.authorize' or 'foo'"
	 *	as method "authorize".
	 *
	 *	And bail out if there's no policy "foo.authorize" or "foo".
	 */
	if (method_name) {
		snprintf(buffer, sizeof(buffer), "%s.%s", virtual_name, method_name);
		subcs = cf_section_find(cs, buffer, NULL);
		if (!subcs) subcs = cf_section_find(cs, virtual_name, NULL);
		if (!subcs) return NULL;

		goto check_for_loop;
	}

	/*
	 *	"foo" means "look for foo.name1.name2" first, to allow
	 *	method overrides.  If that's not found, look for
	 *	"foo.name1" and if that's not found just look for
	 *	a policy "foo".
	 */
	if (unlang_ctx->section_name2) {
		snprintf(buffer, sizeof(buffer), "%s.%s.%s", virtual_name, unlang_ctx->section_name1, unlang_ctx->section_name2);
		subcs = cf_section_find(cs, buffer, NULL);
	} else {
		subcs = NULL;
	}

	if (!subcs) {
		snprintf(buffer, sizeof(buffer), "%s.%s", virtual_name, unlang_ctx->section_name1);
		subcs = cf_section_find(cs, buffer, NULL);
	}

	if (!subcs) subcs = cf_section_find(cs, virtual_name, NULL);
	if (!subcs) return NULL;

check_for_loop:
	/*
	 *	Check that we're not creating a loop.  We may
	 *	be compiling an "sql" module reference inside
	 *	of an "sql" policy.  If so, we allow the
	 *	second "sql" to refer to the module.
	 */
	for (loop = cf_parent(ci);
	     loop && subcs;
	     loop = cf_parent(loop)) {
		if (loop == cf_section_to_item(subcs)) {
			return NULL;
		}
	}

	return subcs;
}

static unlang_t *compile_module(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM *ci, char const *name)
{
	unlang_t	*c;
	unlang_module_t *m;
	fr_slen_t	slen;

	MEM(m = talloc_zero(parent, unlang_module_t));
	slen = module_rlm_by_name_and_method(m, &m->mmc,
					     unlang_ctx->vs,
					     &(section_name_t){ .name1 = unlang_ctx->section_name1, .name2 = unlang_ctx->section_name2 },
					     &FR_SBUFF_IN_STR(name),
					     unlang_ctx->rules);
	if (slen < 0) {
		cf_log_perr(ci, "Failed compiling module call");
		talloc_free(m);
		return NULL;
	}

	/*
	 *	We parsed a string, but we were told to ignore it.  Don't do anything.
	 */
	if (!m->mmc.rlm) return UNLANG_IGNORE;

	if (m->mmc.rlm->common.dict &&
	    !fr_dict_compatible(*m->mmc.rlm->common.dict, unlang_ctx->rules->attr.dict_def)) {
		cf_log_err(ci, "The '%s' module can only be used within a '%s' namespace.",
			   m->mmc.rlm->common.name, fr_dict_root(*m->mmc.rlm->common.dict)->name);
		cf_log_err(ci, "Please use the 'subrequest' keyword to change namespaces");
		cf_log_err(ci, DOC_KEYWORD_REF(subrequest));
		talloc_free(m);
		return NULL;
	}

	c = unlang_module_to_generic(m);
	unlang_type_init(c, parent, UNLANG_TYPE_MODULE);
	c->name = talloc_typed_strdup(c, name);
	c->debug_name = c->name;
	c->ci = ci;

	/*
	 *	Set the default actions for this module.
	 */
	c->actions = m->mmc.mi->actions;

	/*
	 *	Parse the method environment for this module / method
	 */
	if (m->mmc.mmb.method_env) {
		call_env_method_t const *method_env = m->mmc.mmb.method_env;

		fr_assert_msg(method_env->inst_size, "Method environment for module %s, method %s %s declared, "
			      "but no inst_size set",
			      m->mmc.mi->name, unlang_ctx->section_name1, unlang_ctx->section_name2);

		if (!unlang_ctx->rules) {
			cf_log_err(ci, "Failed compiling %s - no rules",  m->mmc.mi->name);
			goto error;
		}
		m->call_env = call_env_alloc(m, m->self.name, method_env,
					     unlang_ctx->rules, m->mmc.mi->conf,
					     &(call_env_ctx_t){
						.type = CALL_ENV_CTX_TYPE_MODULE,
						.mi = m->mmc.mi,
						.asked = &m->mmc.asked
					     });
		if (!m->call_env) {
		error:
			talloc_free(m);
			return NULL;
		}
	}

	/*
	 *	If a module reference is a section, then the section
	 *	should contain action over-rides.  We add those here.
	 */
	if (cf_item_is_section(ci) &&
	    !unlang_compile_actions(&c->actions, cf_item_to_section(ci),
				    (m->mmc.mi->exported->flags & MODULE_TYPE_RETRY) != 0)) goto error;

	return c;
}

extern int dict_attr_acopy_children(fr_dict_t *dict, fr_dict_attr_t *dst, fr_dict_attr_t const *src);

static inline CC_HINT(always_inline) unlang_op_t const *name_to_op(char const *name)
{
	unlang_op_t const *op;

	op = fr_hash_table_find(unlang_op_table, &(unlang_op_t) { .name = name });
	if (op) return op;

	return NULL;
}

int unlang_define_local_variable(CONF_ITEM *ci, unlang_variable_t *var, tmpl_rules_t *t_rules, fr_type_t type, char const *name,
				 fr_dict_attr_t const *ref)
{
	fr_dict_attr_t const *da;
	fr_slen_t len;
	unlang_op_t const *op;

	fr_dict_attr_flags_t flags = {
		.internal = true,
		.local = true,
	};

	/*
	 *	No overlap with list names.
	 */
	if (fr_table_value_by_str(tmpl_request_ref_table, name, REQUEST_UNKNOWN) != REQUEST_UNKNOWN) {
	fail_list:
		cf_log_err(ci, "Local variable '%s' cannot be a list reference.", name);
		return -1;
	}

	len = strlen(name);
	if (tmpl_attr_list_from_substr(&da, &FR_SBUFF_IN(name, len)) == len) goto fail_list;

	/*
	 *	No keyword section names.
	 */
	op = name_to_op(name);
	if (op) {
		cf_log_err(ci, "Local variable '%s' cannot be an unlang keyword.", name);
		return -1;
	}

	/*
	 *	No protocol names.
	 */
	if (fr_dict_by_protocol_name(name) != NULL) {
		cf_log_err(ci, "Local variable '%s' cannot be an existing protocol name.", name);
		return -1;
	}

	/*
	 *	No overlap with attributes in the current dictionary.  The lookup in var->root will also check
	 *	the current dictionary, so the check here is really only for better error messages.
	 */
	if (t_rules && t_rules->parent && t_rules->parent->attr.dict_def) {
		da = fr_dict_attr_by_name(NULL, fr_dict_root(t_rules->parent->attr.dict_def), name);
		if (da) {
			cf_log_err(ci, "Local variable '%s' duplicates a dictionary attribute.", name);
			return -1;
		}
	}

	/*
	 *	No data types.
	 */
	if (fr_table_value_by_str(fr_type_table, name, FR_TYPE_NULL) != FR_TYPE_NULL) {
		cf_log_err(ci, "Invalid variable name '%s'.", name);
		return -1;
	}

	/*
	 *	No dups of local variables.
	 */
	da = fr_dict_attr_by_name(NULL, var->root, name);
	if (da) {
		cf_log_err(ci, "Duplicate variable name '%s'.", name);
		return -1;
	}

	if (fr_dict_attr_add(var->dict, var->root, name, var->max_attr, type, &flags) < 0) {
	fail:
		cf_log_err(ci, "Failed adding variable '%s' - %s", name, fr_strerror());
		return -1;
	}
	da = fr_dict_attr_by_name(NULL, var->root, name);
	fr_assert(da != NULL);

	/*
	 *	Copy the children over.
	 */
	if (fr_type_is_structural(type) && (type != FR_TYPE_GROUP)) {
		fr_fatal_assert(ref != NULL);

		if (fr_dict_attr_acopy_local(da, ref) < 0) goto fail;
	}

	var->max_attr++;

	return 0;
}

/*
 *	Compile one unlang instruction
 */
static unlang_t *compile_item(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM *ci)
{
	char const		*name, *p;
	CONF_SECTION		*cs, *subcs, *modules;
	unlang_compile_ctx_t	unlang_ctx2;
	bool			policy;
	unlang_t		*c;
	unlang_op_t const	*op;

	if (cf_item_is_section(ci)) {
		cs = cf_item_to_section(ci);
		name = cf_section_name1(cs);
		op = name_to_op(name);

		if (op) {
			/*
			 *	Forbid pair keywords as section names,
			 *	e.g. "break { ... }"
			 */
			if ((op->flag & UNLANG_OP_FLAG_SINGLE_WORD) != 0) {
				cf_log_err(ci, "Syntax error after keyword '%s' - unexpected '{'", name);
				return NULL;
			}

			c = op->compile(parent, unlang_ctx, ci);
			goto allocate_number;
		}

		/* else it's something like sql { fail = 1 ...} */
		goto check_for_module;

	} else if (cf_item_is_pair(ci)) {

		/*
		 *	Else it's a module reference such as "sql", OR
		 *	one of the few bare keywords that we allow.
		 */
		CONF_PAIR *cp = cf_item_to_pair(ci);

		/*
		 *	We cannot have assignments or actions here.
		 */
		if (cf_pair_value(cp) != NULL) {
			cf_log_err(ci, "Invalid assignment");
			return NULL;
		}

		name = cf_pair_attr(cp);
		op = name_to_op(name);

		if (op) {
			/*
			 *	Forbid section keywords as pair names, e.g. "switch = foo"
			 */
			if ((op->flag & UNLANG_OP_FLAG_SINGLE_WORD) == 0) {
				cf_log_err(ci, "Syntax error after keyword '%s' - missing '{'", name);
				return NULL;
			}

			c = op->compile(parent, unlang_ctx, ci);
			goto allocate_number;
		}

		/*
		 *	In-place expansions.
		 *
		 *	@todo - allow only function calls, not %{...}
		 *
		 *	@todo don't create a tmpl.  Instead, create an
		 *	xlat.  This functionality is needed for the in-place language functions via
		 *
		 *	language {{{
		 *		...
		 *	}}}
		 */
		if (name[0] == '%') {
			c = compile_tmpl(parent, unlang_ctx, cf_pair_to_item(cp));
			goto allocate_number;
		}

		goto check_for_module;

	} else {
		cf_log_err(ci, "Asked to compile unknown configuration item");
		return NULL;	/* who knows what it is... */
	}

check_for_module:
	/*
	 *	We now have a name.  It can be one of two forms.  A
	 *	bare module name, or a section named for the module,
	 *	with over-rides for the return codes.
	 *
	 *	The name can refer to a real module, in the "modules"
	 *	section.  In that case, the name will be either the
	 *	first or second name of the sub-section of "modules".
	 *
	 *	Or, the name can refer to a policy, in the "policy"
	 *	section.  In that case, the name will be first of the
	 *	sub-section of "policy".
	 *
	 *	Or, the name can refer to a "module.method", in which
	 *	case we're calling a different method than normal for
	 *	this section.
	 *
	 *	Or, the name can refer to a virtual module, in the
	 *	"modules" section.  In that case, the name will be
	 *	name2 of the CONF_SECTION.
	 *
	 *	We try these in sequence, from the bottom up.  This is
	 *	so that virtual modules and things in "policy" can
	 *	over-ride calls to real modules.
	 */


	/*
	 *	Try:
	 *
	 *	policy { ... name { .. } .. }
	 *	policy { ... name.method { .. } .. }
	 */
	p = strrchr(name, '.');
	if (!p) {
		subcs = virtual_module_find_cs(ci, name, name, NULL, unlang_ctx, &policy);
	} else {
		char buffer[256];

		strlcpy(buffer, name, sizeof(buffer));
		buffer[p - name] = '\0';

		subcs = virtual_module_find_cs(ci, name,
					       buffer, buffer + (p - name) + 1, unlang_ctx, &policy);
	}

	/*
	 *	We've found the thing which defines this "function".
	 *	It MUST be a sub-section.
	 *
	 *	i.e. it refers to a a subsection in "policy".
	 */
	if (subcs) {
		c = compile_function(parent, unlang_ctx, ci, subcs, policy);
		goto allocate_number;
	}

	/*
	 *	Not a function.  It must be a real module.
	 */
	modules = cf_section_find(cf_root(ci), "modules", NULL);
	if (!modules) {
		cf_log_err(ci, "Failed compiling \"%s\" as a module or policy as no modules are enabled", name);
		cf_log_err(ci, "Please verify that modules { ... }  section is present in the server configuration");
		return NULL;
	}

	/*
	 *	Set the child compilation context BEFORE parsing the
	 *	module name and method.  The lookup function will take
	 *	care of returning the appropriate component, name1,
	 *	name2, etc.
	 */
	UPDATE_CTX2;
	c = compile_module(parent, &unlang_ctx2, ci, name);

allocate_number:
	if (!c) return NULL;
	if (c == UNLANG_IGNORE) return UNLANG_IGNORE;

	c->number = unlang_number++;
	compile_set_default_actions(c, unlang_ctx);

	/*
	 *	Only insert the per-thread allocation && instantiation if it's used.
	 */
	op = &unlang_ops[c->type];
	if (!op->thread_inst_size) return c;

	if (!fr_rb_insert(unlang_instruction_tree, c)) {
		cf_log_err(ci, "Instruction \"%s\" number %u has conflict with previous one.",
			   c->debug_name, c->number);
		talloc_free(c);
		return NULL;
	}

	return c;
}

/** Compile an unlang section for a virtual server
 *
 * @param[in] vs		Virtual server to compile section for.
 * @param[in] cs		containing the unlang calls to compile.
 * @param[in] actions		Actions to use for the unlang section.
 * @param[in] rules		Rules to use for the unlang section.
 * @param[out] instruction	Pointer to store the compiled unlang section.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int unlang_compile(virtual_server_t const *vs,
		   CONF_SECTION *cs, unlang_mod_actions_t const *actions, tmpl_rules_t const *rules, void **instruction)
{
	unlang_t			*c;
	tmpl_rules_t			my_rules;
	char const			*name1, *name2;
	CONF_DATA const			*cd;

	/*
	 *	Don't compile it twice, and don't print out debug
	 *	messages twice.
	 */
	cd = cf_data_find(cs, unlang_group_t, NULL);
	if (cd) {
		if (instruction) *instruction = cf_data_value(cd);
		return 1;
	}

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	if (!name2) name2 = "";

	cf_log_debug(cs, "Compiling policies in - %s %s {...}", name1, name2);

	/*
	 *	Ensure that all compile functions get valid rules.
	 */
	if (!rules) {
		memset(&my_rules, 0, sizeof(my_rules));
		rules = &my_rules;
	}

	c = unlang_compile_section(NULL,
			    &(unlang_compile_ctx_t){
				.vs = vs,
				.section_name1 = cf_section_name1(cs),
				.section_name2 = cf_section_name2(cs),
				.actions = *actions,
				.rules = rules
			    },
			    cs, UNLANG_TYPE_GROUP);
	if (!c) return -1;

	fr_assert(c != UNLANG_IGNORE);

	if (DEBUG_ENABLED4) unlang_dump(c, 2);

	/*
	 *	Associate the unlang with the configuration section,
	 *	and free the unlang code when the configuration
	 *	section is freed.
	 */
	cf_data_add(cs, c, NULL, true);
	cf_item_mark_parsed(cs);
	if (instruction) *instruction = c;

	return 0;
}


/** Check if name is an unlang keyword
 *
 * @param[in] name	to check.
 * @return
 *	- true if it is a keyword.
 *	- false if it's not a keyword.
 */
bool unlang_compile_is_keyword(const char *name)
{
	if (!name || !*name) return false;

	return (name_to_op(name) != 0);
}

/*
 *	These are really unlang_foo_t, but that's fine...
 */
static int8_t instruction_cmp(void const *one, void const *two)
{
	unlang_t const *a = one;
	unlang_t const *b = two;

	return CMP(a->number, b->number);
}


void unlang_compile_init(TALLOC_CTX *ctx)
{
	unlang_instruction_tree = fr_rb_alloc(ctx, instruction_cmp, NULL);
}


/** Create thread-specific data structures for unlang
 *
 */
int unlang_thread_instantiate(TALLOC_CTX *ctx)
{
	fr_rb_iter_inorder_t	iter;
	unlang_t		*instruction;

	if (unlang_thread_array) {
		fr_strerror_const("already initialized");
		return -1;
	}

	MEM(unlang_thread_array = talloc_zero_array(ctx, unlang_thread_t, unlang_number + 1));
//	talloc_set_destructor(unlang_thread_array, _unlang_thread_array_free);

	/*
	 *	Instantiate each instruction with thread-specific data.
	 */
	for (instruction = fr_rb_iter_init_inorder(unlang_instruction_tree, &iter);
	     instruction;
	     instruction = fr_rb_iter_next_inorder(unlang_instruction_tree, &iter)) {
		unlang_op_t *op;

		unlang_thread_array[instruction->number].instruction = instruction;

		op = &unlang_ops[instruction->type];

		fr_assert(op->thread_inst_size);

		/*
		 *	Allocate any thread-specific instance data.
		 */
		MEM(unlang_thread_array[instruction->number].thread_inst = talloc_zero_array(unlang_thread_array, uint8_t, op->thread_inst_size));
		talloc_set_name_const(unlang_thread_array[instruction->number].thread_inst, op->thread_inst_type);

		if (op->thread_instantiate && (op->thread_instantiate(instruction, unlang_thread_array[instruction->number].thread_inst) < 0)) {
			return -1;
		}
	}

	return 0;
}

/** Get the thread-instance data for an instruction.
 *
 * @param[in] instruction	the instruction to use
 * @return			a pointer to thread-local data
 */
void *unlang_thread_instance(unlang_t const *instruction)
{
	if (!instruction->number || !unlang_thread_array) return NULL;

	fr_assert(instruction->number <= unlang_number);

	return unlang_thread_array[instruction->number].thread_inst;
}

#ifdef WITH_PERF
void unlang_frame_perf_init(unlang_stack_frame_t *frame)
{
	unlang_thread_t *t;
	fr_time_t now;
	unlang_t const *instruction = frame->instruction;

	if (!instruction->number || !unlang_thread_array) return;

	fr_assert(instruction->number <= unlang_number);

	t = &unlang_thread_array[instruction->number];

	t->use_count++;
	t->yielded++;			// everything starts off as yielded
	now = fr_time();

	fr_time_tracking_start(NULL, &frame->tracking, now);
	fr_time_tracking_yield(&frame->tracking, fr_time());
}

void unlang_frame_perf_yield(unlang_stack_frame_t *frame)
{
	unlang_t const *instruction = frame->instruction;
	unlang_thread_t *t;

	if (!instruction->number || !unlang_thread_array) return;

	t = &unlang_thread_array[instruction->number];
	t->yielded++;
	t->running--;

	fr_time_tracking_yield(&frame->tracking, fr_time());
}

void unlang_frame_perf_resume(unlang_stack_frame_t *frame)
{
	unlang_t const *instruction = frame->instruction;
	unlang_thread_t *t;

	if (!instruction->number || !unlang_thread_array) return;

	if (frame->tracking.state != FR_TIME_TRACKING_YIELDED) return;

	t = &unlang_thread_array[instruction->number];
	t->running++;
	t->yielded--;

	fr_time_tracking_resume(&frame->tracking, fr_time());
}

void unlang_frame_perf_cleanup(unlang_stack_frame_t *frame)
{
	unlang_t const *instruction = frame->instruction;
	unlang_thread_t *t;

	if (!instruction || !instruction->number || !unlang_thread_array) return;

	fr_assert(instruction->number <= unlang_number);

	t = &unlang_thread_array[instruction->number];

	if (frame->tracking.state == FR_TIME_TRACKING_YIELDED) {
		t->yielded--;
		fr_time_tracking_resume(&frame->tracking, fr_time());
	} else {
		t->running--;
	}

	fr_time_tracking_end(NULL, &frame->tracking, fr_time());
	t->tracking.running_total = fr_time_delta_add(t->tracking.running_total, frame->tracking.running_total);
	t->tracking.waiting_total = fr_time_delta_add(t->tracking.waiting_total, frame->tracking.waiting_total);
}


static void unlang_perf_dump(fr_log_t *log, unlang_t const *instruction, int depth)
{
	unlang_group_t const *g;
	unlang_thread_t *t;
	char const *file;
	int line;

	if (!instruction || !instruction->number) return;

	/*
	 *	These are generally pushed onto the stack, and therefore ignored.
	 */
	if (instruction->type == UNLANG_TYPE_TMPL) return;

	/*
	 *	Everything else is an unlang_group_t;
	 */
	g = unlang_generic_to_group(instruction);

	if (!g->cs) return;

	file = cf_filename(g->cs);
	line = cf_lineno(g->cs);

	if (depth) {
		fr_log(log, L_DBG, file, line, "%.*s", depth, unlang_spaces);
	}

	if (debug_braces(instruction->type)) {
		fr_log(log, L_DBG, file, line, "%s { #", instruction->debug_name);
	} else {
		fr_log(log, L_DBG, file, line, "%s #", instruction->debug_name);
	}

	t = &unlang_thread_array[instruction->number];

	fr_log(log, L_DBG, file, line, "count=%" PRIu64 " cpu_time=%" PRId64 " yielded_time=%" PRId64 ,
	       t->use_count, fr_time_delta_unwrap(t->tracking.running_total), fr_time_delta_unwrap(t->tracking.waiting_total));

	if (!unlang_list_empty(&g->children)) {
		unlang_list_foreach(&g->children, child) {
			unlang_perf_dump(log, child, depth + 1);
		}
	}

	if (debug_braces(instruction->type)) {
		if (depth) {
			fr_log(log, L_DBG, file, line, "%.*s", depth, unlang_spaces);
		}

		fr_log(log, L_DBG, file, line, "}");
	}
}

void unlang_perf_virtual_server(fr_log_t *log, char const *name)
{

	virtual_server_t const	*vs = virtual_server_find(name);
	CONF_SECTION		*cs;
	CONF_ITEM		*ci;
	char const		*file;
	int			line;

	if (!vs) return;

	cs = virtual_server_cs(vs);

	file = cf_filename(cs);
	line = cf_lineno(cs);

	fr_log(log, L_DBG, file, line, " server %s {\n", name);

	/*
	 *	Loop over the children of the virtual server, checking for unlang_t;
	 */
	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		char const *name1, *name2;
		unlang_t *instruction;
		CONF_SECTION *subcs;

		if (!cf_item_is_section(ci)) continue;

		instruction = (unlang_t *)cf_data_value(cf_data_find(ci, unlang_group_t, NULL));
		if (!instruction) continue;

		subcs = cf_item_to_section(ci);
		name1 = cf_section_name1(subcs);
		name2 = cf_section_name2(subcs);
		file = cf_filename(ci);
		line = cf_lineno(ci);

		if (!name2) {
			fr_log(log, L_DBG, file, line, " %s {\n", name1);
		} else {
			fr_log(log, L_DBG, file, line, " %s %s {\n", name1, name2);
		}

		unlang_perf_dump(log, instruction, 2);

		fr_log(log, L_DBG, file, line, " }\n");
	}

	fr_log(log, L_DBG, file, line, "}\n");
}
#endif
