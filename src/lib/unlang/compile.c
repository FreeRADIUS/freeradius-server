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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/unlang/base.h>

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

#include "unlang_priv.h"

#define UNLANG_IGNORE ((unlang_t *) -1)

/*
 *	When we switch to a new unlang ctx, we use the new component
 *	name and number, but we use the CURRENT actions.
 */
#define UPDATE_CTX2  \
	unlang_ctx2.component = component; \
	unlang_ctx2.actions = unlang_ctx->actions; \
	unlang_ctx2.section_name1 = unlang_ctx->section_name1; \
	unlang_ctx2.section_name2 = unlang_ctx->section_name2; \
	unlang_ctx2.rules = unlang_ctx->rules

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
fr_table_num_sorted_t const mod_rcode_table[] = {
	{ L("..."),        RLM_MODULE_UNKNOWN	},
	{ L("disallow"),   RLM_MODULE_DISALLOW	},
	{ L("fail"),       RLM_MODULE_FAIL	},
	{ L("handled"),    RLM_MODULE_HANDLED	},
	{ L("invalid"),    RLM_MODULE_INVALID	},
	{ L("noop"),       RLM_MODULE_NOOP	},
	{ L("notfound"),   RLM_MODULE_NOTFOUND	},
	{ L("ok"),	   RLM_MODULE_OK	},
	{ L("reject"),     RLM_MODULE_REJECT	},
	{ L("updated"),    RLM_MODULE_UPDATED	},
	{ L("yield"),      RLM_MODULE_YIELD	}
};
size_t mod_rcode_table_len = NUM_ELEMENTS(mod_rcode_table);


/* Some short names for debugging output */
static char const * const comp2str[] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"post-auth"
};

typedef int const unlang_action_table_t[RLM_MODULE_NUMCODES];

typedef struct {
	rlm_components_t	component;
	char const		*section_name1;
	char const		*section_name2;
	unlang_action_table_t	*actions;
	tmpl_rules_t const	*rules;
} unlang_compile_t;

static unlang_t *compile_empty(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs, unlang_ext_t const *ext);

static char const unlang_spaces[] = "                                                                                                                                                                                                                                                                ";


static const int
default_actions[MOD_COUNT][RLM_MODULE_NUMCODES] =
{
	/* authenticate */
	{
		MOD_ACTION_RETURN,	/* reject   */
		MOD_ACTION_RETURN,	/* fail     */
		4,			/* ok       */
		MOD_ACTION_RETURN,	/* handled  */
		MOD_ACTION_RETURN,	/* invalid  */
		MOD_ACTION_RETURN,	/* disallow */
		1,			/* notfound */
		2,			/* noop     */
		3			/* updated  */
	},
	/* authorize */
	{
		MOD_ACTION_RETURN,	/* reject   */
		MOD_ACTION_RETURN,	/* fail     */
		3,			/* ok       */
		MOD_ACTION_RETURN,	/* handled  */
		MOD_ACTION_RETURN,	/* invalid  */
		MOD_ACTION_RETURN,	/* disallow */
		1,			/* notfound */
		2,			/* noop     */
		4			/* updated  */
	},
	/* preacct */
	{
		MOD_ACTION_RETURN,	/* reject   */
		MOD_ACTION_RETURN,	/* fail     */
		2,			/* ok       */
		MOD_ACTION_RETURN,	/* handled  */
		MOD_ACTION_RETURN,	/* invalid  */
		MOD_ACTION_RETURN,	/* disallow */
		MOD_ACTION_RETURN,	/* notfound */
		1,			/* noop     */
		3			/* updated  */
	},
	/* accounting */
	{
		MOD_ACTION_RETURN,	/* reject   */
		MOD_ACTION_RETURN,	/* fail     */
		2,			/* ok       */
		MOD_ACTION_RETURN,	/* handled  */
		MOD_ACTION_RETURN,	/* invalid  */
		MOD_ACTION_RETURN,	/* disallow */
		MOD_ACTION_RETURN,	/* notfound */
		1,			/* noop     */
		3			/* updated  */
	},
	/* post-auth */
	{
		MOD_ACTION_RETURN,	/* reject   */
		MOD_ACTION_RETURN,	/* fail     */
		3,			/* ok       */
		MOD_ACTION_RETURN,	/* handled  */
		MOD_ACTION_RETURN,	/* invalid  */
		MOD_ACTION_RETURN,	/* disallow */
		1,			/* notfound */
		2,			/* noop     */
		4			/* updated  */
	}
};

static bool pass2_fixup_tmpl(TALLOC_CTX *ctx, CONF_ITEM const *ci, tmpl_t **vpt_p)
{
	tmpl_t *vpt = *vpt_p;

	TMPL_VERIFY(vpt);

	/*
	 *	Convert virtual &Attr-Foo to "%{Attr-Foo}"
	 */
	if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
		if (tmpl_attr_to_xlat(ctx, vpt_p) < 0) {
			return false;
		}

		/*
		 *	The VPT has been rewritten, so use the new one.
		 */
		vpt = *vpt_p;
	} /* it's now xlat, so we need to resolve it. */

	/*
	 *	Fixup any other tmpl types
	 */
	if (tmpl_resolve(vpt) < 0) {
		cf_log_perr(ci, NULL);
		return false;
	}

	return true;
}

static bool pass2_fixup_map(fr_cond_t *c)
{
	tmpl_t		*vpt;
	map_t	*map;

	map = c->data.map;	/* shorter */

	/*
	 *	Auth-Type := foo
	 *
	 *	Where "foo" is dynamically defined.
	 */
	if (c->pass2_fixup == PASS2_FIXUP_TYPE) {
		if (!fr_dict_enum_by_name(tmpl_da(map->lhs), map->rhs->name, -1)) {
			cf_log_err(map->ci, "Invalid reference to non-existent %s %s { ... }",
				   tmpl_da(map->lhs)->name,
				   map->rhs->name);
			return false;
		}

		/*
		 *	These guys can't have a paircmp fixup applied.
		 */
		c->pass2_fixup = PASS2_FIXUP_NONE;
		return true;
	}

	if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
		fr_dict_attr_t const *cast = c->cast;

		/*
		 *	Resolve the attribute references first
		 */
		if (tmpl_is_attr_unresolved(map->lhs)) {
			if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) return false;
			if (!cast) cast = tmpl_da(map->lhs);
		}

		if (tmpl_is_attr_unresolved(map->rhs)) {
			if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) return false;
			if (!cast) cast = tmpl_da(map->rhs);
		}

		/*
		 *	Then fixup the other side if it was unresolved
		 */
		if (tmpl_is_unresolved(map->lhs)) {
			switch (cast->type) {
			case FR_TYPE_IPV4_ADDR:
				if (strchr(c->data.map->lhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
										   FR_CAST_BASE + FR_TYPE_IPV4_PREFIX);
				}
				break;

			case FR_TYPE_IPV6_ADDR:
				if (strchr(c->data.map->lhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
						    				   FR_CAST_BASE + FR_TYPE_IPV6_PREFIX);
				}
				break;

			default:
				break;
			}

			if (tmpl_cast_in_place(c->data.map->lhs, cast->type, cast) < 0) {
				cf_log_err(map->ci, "Failed to parse data type %s from string: %pV",
					   fr_table_str_by_value(fr_value_box_type_table, cast->type, "<UNKNOWN>"),
					   fr_box_strvalue_len(map->lhs->name, map->lhs->len));

				return false;
			}
		} else if (tmpl_is_unresolved(map->rhs)) {
			switch (cast->type) {
			case FR_TYPE_IPV4_ADDR:
				if (strchr(c->data.map->rhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
										   FR_CAST_BASE + FR_TYPE_IPV4_PREFIX);
				}
				break;

			case FR_TYPE_IPV6_ADDR:
				if (strchr(c->data.map->rhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
						    				   FR_CAST_BASE + FR_TYPE_IPV6_PREFIX);
				}
				break;

			default:
				break;
			}

			if (tmpl_cast_in_place(c->data.map->rhs, cast->type, cast) < 0) {
				cf_log_err(map->ci, "Failed to parse data type %s from string: %pV",
					   fr_table_str_by_value(fr_value_box_type_table, cast->type, "<UNKNOWN>"),
					   fr_box_strvalue_len(map->rhs->name, map->rhs->len));
				return false;
			}
		}

		c->pass2_fixup = PASS2_FIXUP_NONE;
	}

	/*
	 *	Just in case someone adds a new fixup later.
	 */
	fr_assert((c->pass2_fixup == PASS2_FIXUP_NONE) ||
		   (c->pass2_fixup == PASS2_PAIRCOMPARE));

	/*
	 *	Precompile xlat's
	 */
	if (tmpl_is_xlat_unresolved(map->lhs)) {
		/*
		 *	Compile the LHS to an attribute reference only
		 *	if the RHS is a literal.
		 *
		 *	@todo v3.1: allow anything anywhere.
		 */
		if (!tmpl_is_unresolved(map->rhs)) {
			if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) {
				return false;
			}
		} else {
			if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) {
				return false;
			}

			/*
			 *	Attribute compared to a literal gets
			 *	the literal cast to the data type of
			 *	the attribute.
			 *
			 *	The code in parser.c did this for
			 *
			 *		&Attr == data
			 *
			 *	But now we've just converted "%{Attr}"
			 *	to &Attr, so we've got to do it again.
			 */
			if (tmpl_is_attr(map->lhs)) {
				if ((map->rhs->len > 0) ||
				    (map->op != T_OP_CMP_EQ) ||
				    (tmpl_da(map->lhs)->type == FR_TYPE_STRING) ||
				    (tmpl_da(map->lhs)->type == FR_TYPE_OCTETS)) {

					if (tmpl_cast_in_place(map->rhs, tmpl_da(map->lhs)->type, tmpl_da(map->lhs)) < 0) {
						cf_log_err(map->ci, "Failed to parse data type %s from string: %pV",
							   fr_table_str_by_value(fr_value_box_type_table, tmpl_da(map->lhs)->type, "<UNKNOWN>"),
							   fr_box_strvalue_len(map->rhs->name, map->rhs->len));
						return false;
					} /* else the cast was successful */

				} else {	/* RHS is empty, it's just a check for empty / non-empty string */
					vpt = talloc_steal(c, map->lhs);
					map->lhs = NULL;
					talloc_free(c->data.map);

					/*
					 *	"%{Foo}" == '' ---> !Foo
					 *	"%{Foo}" != '' ---> Foo
					 */
					c->type = COND_TYPE_EXISTS;
					c->data.vpt = vpt;
					c->negate = !c->negate;

					WARN("%s[%d]: Please change (\"%%{%s}\" %s '') to %c&%s",
					     cf_filename(cf_item_to_section(c->ci)),
					     cf_lineno(cf_item_to_section(c->ci)),
					     vpt->name, c->negate ? "==" : "!=",
					     c->negate ? '!' : ' ', vpt->name);

					/*
					 *	No more RHS, so we can't do more optimizations
					 */
					return true;
				}
			}
		}
	}

	if (tmpl_is_xlat_unresolved(map->rhs)) {
		/*
		 *	Convert the RHS to an attribute reference only
		 *	if the LHS is an attribute reference, AND is
		 *	of the same type as the RHS.
		 *
		 *	We can fix this when the code in evaluate.c
		 *	can handle strings on the LHS, and attributes
		 *	on the RHS.  For now, the code in parser.c
		 *	forbids this.
		 */
		if (tmpl_is_attr(map->lhs)) {
			if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) return false;
		} else {
			if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) return false;
		}
	}

	if (tmpl_is_exec_unresolved(map->lhs)) {
		if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) {
			return false;
		}
	}

	if (tmpl_is_exec_unresolved(map->rhs)) {
		if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) {
			return false;
		}
	}

	/*
	 *	Convert bare refs to %{Foreach-Variable-N}
	 */
	if (tmpl_is_unresolved(map->lhs) &&
	    (strncmp(map->lhs->name, "Foreach-Variable-", 17) == 0)) {
		char *fmt;
		ssize_t slen;

		fmt = talloc_typed_asprintf(map->lhs, "%%{%s}", map->lhs->name);
		slen = tmpl_afrom_substr(map, &vpt, &FR_SBUFF_IN(fmt, talloc_array_length(fmt) - 1),
					 T_DOUBLE_QUOTED_STRING,
					 NULL,
					 &(tmpl_rules_t){
					 	.allow_unknown = true
					 });
		if (slen < 0) {
			char *spaces, *text;

			fr_canonicalize_error(map->ci, &spaces, &text, slen, fr_strerror());

			cf_log_err(map->ci, "Failed converting %s to xlat", map->lhs->name);
			cf_log_err(map->ci, "%s", fmt);
			cf_log_err(map->ci, "%s^ %s", spaces, text);

			talloc_free(spaces);
			talloc_free(text);
			talloc_free(fmt);

			return false;
		}
		talloc_free(map->lhs);
		map->lhs = vpt;
	}

#ifdef HAVE_REGEX
	if (tmpl_is_regex_xlat_unresolved(map->rhs)) {
		if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) {
			return false;
		}
	}
	fr_assert(!tmpl_is_regex_xlat_unresolved(map->lhs));
#endif

	/*
	 *	Convert &Packet-Type to "%{Packet-Type}", because
	 *	these attributes don't really exist.  The code to
	 *	find an attribute reference doesn't work, but the
	 *	xlat code does.
	 */
	vpt = c->data.map->lhs;
	if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
		if (tmpl_attr_to_xlat(c, &vpt) < 0) return false;
	}

	/*
	 *	@todo v3.1: do the same thing for the RHS...
	 */

	/*
	 *	Only attributes can have a paircmp registered, and
	 *	they can only be with the current request_t, and only
	 *	with the request pairs.
	 */
	if (!tmpl_is_attr(map->lhs) ||
	    (tmpl_request(map->lhs) != REQUEST_CURRENT) ||
	    (tmpl_list(map->lhs) != PAIR_LIST_REQUEST)) {
		return true;
	}

	if (!paircmp_find(tmpl_da(map->lhs))) return true;

	if (tmpl_is_regex_xlat_unresolved(map->rhs)) {
		cf_log_err(map->ci, "Cannot compare virtual attribute %s via a regex", map->lhs->name);
		return false;
	}

	if (c->cast) {
		cf_log_err(map->ci, "Cannot cast virtual attribute %s to %s", map->lhs->name,
			   fr_table_str_by_value(fr_value_box_type_table, c->cast->type, "<INVALID>"));
		return false;
	}

	if (map->op != T_OP_CMP_EQ) {
		cf_log_err(map->ci, "Must use '==' for comparisons with virtual attribute %s", map->lhs->name);
		return false;
	}

	/*
	 *	Mark it as requiring a paircmp() call, instead of
	 *	fr_pair_cmp().
	 */
	c->pass2_fixup = PASS2_PAIRCOMPARE;

	return true;
}

static bool pass2_cond_callback(fr_cond_t *c, UNUSED void *uctx)
{
	switch (c->type) {
	/*
	 *	These don't get optimized.
	 */
	case COND_TYPE_TRUE:
	case COND_TYPE_FALSE:
	case COND_TYPE_RCODE:
		return true;

	/*
	 *	Call children.
	 */
	case COND_TYPE_CHILD:
		return pass2_cond_callback(c->data.child, uctx);

	/*
	 *	Fix up the template.
	 */
	case COND_TYPE_EXISTS:
		fr_assert(!tmpl_is_regex_xlat_unresolved(c->data.vpt));
		return pass2_fixup_tmpl(c, c->ci, &c->data.vpt);

	/*
	 *	Fixup the map
	 */
	case COND_TYPE_MAP:
		return pass2_fixup_map(c);

	/*
	 *	Nothing else has pass2 fixups
	 */
	default:
		fr_assert(0);
		return false;
	}
}

static bool pass2_fixup_update_map(map_t *map, tmpl_rules_t const *rules, fr_dict_attr_t const *parent)
{
	if (tmpl_is_xlat_unresolved(map->lhs)) {
		fr_assert(tmpl_xlat(map->lhs) == NULL);

		/*
		 *	FIXME: compile to attribute && handle
		 *	the conversion in map_to_vp().
		 */
		if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) {
			return false;
		}
	}

	if (tmpl_is_exec(map->lhs)) {
		if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) {
			return false;
		}
	}

	/*
	 *	Deal with undefined attributes now.
	 */
	if (tmpl_is_attr_unresolved(map->lhs)) {
		if (!pass2_fixup_tmpl(map, map->ci, &map->lhs)) return false;
	}

	/*
	 *	Enforce parent-child relationships in nested maps.
	 */
	if (parent) {
		if (map->op != T_OP_EQ) {
			cf_log_err(map->ci, "Invalid operator \"%s\" in nested map section.  "
				   "Only '=' is allowed",
				   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
			return false;
		}
	}

	if (map->rhs) {
		if (tmpl_is_xlat_unresolved(map->rhs)) {
			fr_assert(tmpl_xlat(map->rhs) == NULL);

			/*
			 *	FIXME: compile to attribute && handle
			 *	the conversion in map_to_vp().
			 */
			if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) {
				return false;
			}
		}

		fr_assert(!tmpl_is_regex_xlat_unresolved(map->rhs));

		if (tmpl_is_attr_unresolved(map->rhs)) {
			if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) return false;
		}

		if (tmpl_is_exec(map->rhs)) {
			if (!pass2_fixup_tmpl(map, map->ci, &map->rhs)) {
				return false;
			}
		}
	}

	/*
	 *	Sanity check sublists.
	 */
	if (map->child) {
		if (!tmpl_is_attr(map->lhs)) {
			cf_log_err(map->ci, "Sublists can only be assigned to a known attribute");
			return false;
		}

		if ((tmpl_da(map->lhs)->type != FR_TYPE_GROUP) &&
		    (tmpl_da(map->lhs)->type != FR_TYPE_TLV)) {
			cf_log_err(map->ci, "Sublists can only be assigned to attributes of type 'group' or 'tlv'");
			return false;
		}

		return pass2_fixup_update_map(map->child, rules, tmpl_da(map->lhs));
	}

	return true;
}

/*
 *	Compile the RHS of update sections to xlat_exp_t
 */
static bool pass2_fixup_update(unlang_group_t *g, tmpl_rules_t const *rules)
{
	unlang_map_t	*gext = unlang_group_to_map(g);
	map_t		*map;

	for (map = gext->map; map != NULL; map = map->next) {
		if (!pass2_fixup_update_map(map, rules, NULL)) return false;
	}

	return true;
}

/*
 *	Compile the RHS of map sections to xlat_exp_t
 */
static bool pass2_fixup_map_rhs(unlang_group_t *g, tmpl_rules_t const *rules)
{
	unlang_map_t	*gext = unlang_group_to_map(g);

	/*
	 *	Compile the map
	 */
	if (!pass2_fixup_update(g, rules)) return false;

	/*
	 *	Map sections don't need a VPT.
	 */
	if (!gext->vpt) return true;

	return pass2_fixup_tmpl(gext->map->ci, cf_section_to_item(g->cs), &gext->vpt);
}

static void unlang_dump(unlang_t *instruction, int depth)
{
	unlang_t *c;
	unlang_group_t *g;
	map_t *map;
	char buffer[1024];

	for (c = instruction; c != NULL; c = c->next) {
		switch (c->type) {
		case UNLANG_TYPE_NULL:
		case UNLANG_TYPE_MAX:
			fr_assert(0);
			break;

		case UNLANG_TYPE_FUNCTION:
			DEBUG("%.*s%s", depth, unlang_spaces, c->debug_name);
			break;

		case UNLANG_TYPE_MODULE:
		{
			unlang_module_t *single = unlang_generic_to_module(c);

			DEBUG("%.*s%s", depth, unlang_spaces, single->instance->name);
		}
			break;

		case UNLANG_TYPE_MAP:
		case UNLANG_TYPE_UPDATE:
		{
			unlang_map_t *gext;

			DEBUG("%.*s%s {", depth, unlang_spaces, c->debug_name);

			g = unlang_generic_to_group(c);
			gext = unlang_group_to_map(g);
			for (map = gext->map; map != NULL; map = map->next) {
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
		case UNLANG_TYPE_ELSE:
		case UNLANG_TYPE_ELSIF:
		case UNLANG_TYPE_FILTER:
		case UNLANG_TYPE_GROUP:
		case UNLANG_TYPE_IF:
		case UNLANG_TYPE_LOAD_BALANCE:
		case UNLANG_TYPE_PARALLEL:
		case UNLANG_TYPE_POLICY:
		case UNLANG_TYPE_SUBREQUEST:
		case UNLANG_TYPE_SWITCH:
		case UNLANG_TYPE_REDUNDANT:
		case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
			g = unlang_generic_to_group(c);
			DEBUG("%.*s%s {", depth, unlang_spaces, c->debug_name);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, unlang_spaces);
			break;

		case UNLANG_TYPE_BREAK:
		case UNLANG_TYPE_DETACH:
		case UNLANG_TYPE_RETURN:
		case UNLANG_TYPE_TMPL:
		case UNLANG_TYPE_XLAT:
			DEBUG("%.*s%s", depth, unlang_spaces, c->debug_name);
			break;
		}
	}
}

/** Validate and fixup a map that's part of an map section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return 0 if valid else -1.
 */
static int unlang_fixup_map(map_t *map, UNUSED void *ctx)
{
	CONF_PAIR *cp = cf_item_to_pair(map->ci);

	/*
	 *	Anal-retentive checks.
	 */
	if (DEBUG_ENABLED3) {
		if (tmpl_is_attr(map->lhs) && (map->lhs->name[0] != '&')) {
			cf_log_warn(cp, "Please change attribute reference to '&%s %s ...'",
				    map->lhs->name, fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		}

		if (tmpl_is_attr(map->rhs) && (map->rhs->name[0] != '&')) {
			cf_log_warn(cp, "Please change attribute reference to '... %s &%s'",
				    fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"), map->rhs->name);
		}
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_XLAT:
		break;

	default:
		cf_log_err(map->ci, "Left side of map must be an attribute "
		           "or an xlat (that expands to an attribute), not a %s",
		           fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
		return -1;
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
		break;

	default:
		cf_log_err(map->ci, "Right side of map must be an attribute, literal, xlat or exec");
		return -1;
	}

	if (!fr_assignment_op[map->op] && !fr_equality_op[map->op]) {
		cf_log_err(map->ci, "Invalid operator \"%s\" in map section.  "
			   "Only assignment or filter operators are allowed",
			   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		return -1;
	}

	return 0;
}


/** Validate and fixup a map that's part of an update section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return
 *	- 0 if valid.
 *	- -1 not valid.
 */
int unlang_fixup_update(map_t *map, UNUSED void *ctx)
{
	CONF_PAIR *cp = cf_item_to_pair(map->ci);

	/*
	 *	Anal-retentive checks.
	 */
	if (DEBUG_ENABLED3) {
		if (tmpl_is_attr(map->lhs) && (map->lhs->name[0] != '&')) {
			cf_log_warn(cp, "Please change attribute reference to '&%s %s ...'",
				    map->lhs->name, fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		}

		if (tmpl_is_attr(map->rhs) && (map->rhs->name[0] != '&')) {
			cf_log_warn(cp, "Please change attribute reference to '... %s &%s'",
				    fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"), map->rhs->name);
		}
	}

	/*
	 *	Fixup LHS attribute references to change NUM_ANY to NUM_ALL.
	 */
	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		tmpl_attr_rewrite_leaf_num(map->lhs, NUM_ANY, NUM_ALL);
		break;

	default:
		break;
	}

	/*
	 *	Fixup RHS attribute references to change NUM_ANY to NUM_ALL.
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		tmpl_attr_rewrite_leaf_num(map->rhs, NUM_ANY, NUM_ALL);
		break;

	default:
		break;
	}

	/*
	 *	Values used by unary operators should be literal ANY
	 *
	 *	We then free the template and alloc a NULL one instead.
	 */
	if (map->op == T_OP_CMP_FALSE) {
		if (!tmpl_is_unresolved(map->rhs) || (strcmp(map->rhs->name, "ANY") != 0)) {
			WARN("%s[%d] Wildcard deletion MUST use '!* ANY'",
			     cf_filename(cp), cf_lineno(cp));
		}

		TALLOC_FREE(map->rhs);

		map->rhs = tmpl_alloc(map, TMPL_TYPE_NULL, T_INVALID, NULL, 0);
	}

	/*
	 *	Lots of sanity checks for insane people...
	 */

	/*
	 *	What exactly where you expecting to happen here?
	 */
	if (tmpl_is_attr(map->lhs) &&
	    tmpl_is_list(map->rhs)) {
		cf_log_err(map->ci, "Can't copy list into an attribute");
		return -1;
	}

	/*
	 *	Depending on the attribute type, some operators are disallowed.
	 */
	if (tmpl_is_attr(map->lhs)) {
		if (!fr_assignment_op[map->op] && !fr_equality_op[map->op]) {
			cf_log_err(map->ci, "Invalid operator \"%s\" in update section.  "
				   "Only assignment or filter operators are allowed",
				   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
			return -1;
		}

		if (fr_equality_op[map->op]) {
			cf_log_warn(cp, "Please use the 'filter' keyword for attribute filtering");
		}
	}

	if (tmpl_is_list(map->lhs)) {
		/*
		 *	Can't copy an xlat expansion or literal into a list,
		 *	we don't know what type of attribute we'd need
		 *	to create.
		 *
		 *	The only exception is where were using a unary
		 *	operator like !*.
		 */
		if (map->op != T_OP_CMP_FALSE) switch (map->rhs->type) {
		case TMPL_TYPE_XLAT_UNRESOLVED:
		case TMPL_TYPE_UNRESOLVED:
			cf_log_err(map->ci, "Can't copy value into list (we don't know which attribute to create)");
			return -1;

		default:
			break;
		}

		/*
		 *	Only += and :=, and !* operators are supported
		 *	for lists.
		 */
		switch (map->op) {
		case T_OP_CMP_FALSE:
			break;

		case T_OP_ADD:
			if (!tmpl_is_list(map->rhs) &&
			    !tmpl_is_exec(map->rhs)) {
				cf_log_err(map->ci, "Invalid source for list assignment '%s += ...'", map->lhs->name);
				return -1;
			}
			break;

		case T_OP_SET:
			if (tmpl_is_exec(map->rhs)) {
				WARN("%s[%d]: Please change ':=' to '=' for list assignment",
				     cf_filename(cp), cf_lineno(cp));
			}

			if (!tmpl_is_list(map->rhs)) {
				cf_log_err(map->ci, "Invalid source for list assignment '%s := ...'", map->lhs->name);
				return -1;
			}
			break;

		case T_OP_EQ:
			if (!tmpl_is_exec(map->rhs)) {
				cf_log_err(map->ci, "Invalid source for list assignment '%s = ...'", map->lhs->name);
				return -1;
			}
			break;

		default:
			cf_log_err(map->ci, "Operator \"%s\" not allowed for list assignment",
				   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
			return -1;
		}
	}

	/*
	 *	If the map has a unary operator there's no further
	 *	processing we need to, as RHS is unused.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	If LHS is an attribute, and RHS is a literal, we can
	 *	preparse the information into a TMPL_TYPE_DATA.
	 *
	 *	Unless it's a unary operator in which case we
	 *	ignore map->rhs.
	 */
	if (tmpl_is_attr(map->lhs) && tmpl_is_unresolved(map->rhs)) {
		/*
		 *	It's a literal string, just copy it.
		 *	Don't escape anything.
		 */
		if (tmpl_cast_in_place(map->rhs, tmpl_da(map->lhs)->type, tmpl_da(map->lhs)) < 0) {
			cf_log_perr(map->ci, "Cannot convert RHS value (%s) to LHS attribute type (%s)",
				    fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_STRING, "<INVALID>"),
				    fr_table_str_by_value(fr_value_box_type_table, tmpl_da(map->lhs)->type, "<INVALID>"));
			return -1;
		}

		/*
		 *	Fixup LHS da if it doesn't match the type
		 *	of the RHS.
		 */
		if (tmpl_da(map->lhs)->type != tmpl_value_type(map->rhs)) {
			if (tmpl_attr_abstract_to_concrete(map->lhs, tmpl_value_type(map->rhs)) < 0) return -1;
		}
	} /* else we can't precompile the data */

	return 0;
}


/** Validate and fixup a map that's part of a filter section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return
 *	- 0 if valid.
 *	- -1 not valid.
 */
static int unlang_fixup_filter(map_t *map, UNUSED void *ctx)
{
	CONF_PAIR *cp = cf_item_to_pair(map->ci);

	/*
	 *	Anal-retentive checks.
	 */
	if (DEBUG_ENABLED3) {
		if (tmpl_is_attr(map->lhs) && (map->lhs->name[0] != '&')) {
			cf_log_warn(cp, "Please change attribute reference to '&%s %s ...'",
				    map->lhs->name, fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		}

		if (tmpl_is_attr(map->rhs) && (map->rhs->name[0] != '&')) {
			cf_log_warn(cp, "Please change attribute reference to '... %s &%s'",
				    fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"), map->rhs->name);
		}
	}

	/*
	 *	We only allow attributes on the LHS.
	 */
	if (map->lhs->type != TMPL_TYPE_ATTR) {
		cf_log_err(cp, "Filter sections can only operate on attributes");
		return -1;
	}

	if (map->rhs->type == TMPL_TYPE_LIST) {
		cf_log_err(map->ci, "Cannot filter an attribute using a list.");
		return -1;
	}

	/*
	 *	Fixup LHS attribute references to change NUM_ANY to NUM_ALL.
	 */
	if (tmpl_is_attr(map->lhs)) tmpl_attr_rewrite_leaf_num(map->lhs, NUM_ANY, NUM_ALL);

	/*
	 *	Fixup RHS attribute references to change NUM_ANY to NUM_ALL.
	 */
	if (tmpl_is_attr(map->rhs)) tmpl_attr_rewrite_leaf_num(map->rhs, NUM_ANY, NUM_ALL);

	/*
	 *	Values used by unary operators should be literal ANY
	 *
	 *	We then free the template and alloc a NULL one instead.
	 */
	if (map->op == T_OP_CMP_FALSE) {
		if (!tmpl_is_unresolved(map->rhs) || (strcmp(map->rhs->name, "ANY") != 0)) {
			WARN("%s[%d] Wildcard deletion MUST use '!* ANY'",
			     cf_filename(cp), cf_lineno(cp));
		}

		TALLOC_FREE(map->rhs);

		map->rhs = tmpl_alloc(map, TMPL_TYPE_NULL, T_INVALID, NULL, 0);
	}

	/*
	 *	Lots of sanity checks for insane people...
	 */

	/*
	 *	Filtering only allows for filtering operators.
	 */
	if (tmpl_is_attr(map->lhs) && !fr_equality_op[map->op]) {
		cf_log_err(map->ci, "Invalid operator \"%s\" in update section.  "
			   "Only assignment or filter operators are allowed",
			   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		return -1;
	}

	/*
	 *	If the map has a unary operator there's no further
	 *	processing we need to, as RHS is unused.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	If LHS is an attribute, and RHS is a literal, we can
	 *	preparse the information into a TMPL_TYPE_DATA.
	 *
	 *	Unless it's a unary operator in which case we
	 *	ignore map->rhs.
	 */
	if (tmpl_is_attr(map->lhs) && tmpl_is_unresolved(map->rhs)) {
		/*
		 *	It's a literal string, just copy it.
		 *	Don't escape anything.
		 */
		if (tmpl_cast_in_place(map->rhs, tmpl_da(map->lhs)->type, tmpl_da(map->lhs)) < 0) {
			cf_log_perr(map->ci, "Cannot convert RHS value (%s) to LHS attribute type (%s)",
				    fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_STRING, "<INVALID>"),
				    fr_table_str_by_value(fr_value_box_type_table, tmpl_da(map->lhs)->type, "<INVALID>"));
			return -1;
		}

		/*
		 *	Fixup LHS da if it doesn't match the type
		 *	of the RHS.
		 */
		if (tmpl_da(map->lhs)->type != tmpl_value_type(map->rhs)) {
			if (tmpl_attr_abstract_to_concrete(map->lhs, tmpl_value_type(map->rhs)) < 0) return -1;
		}
	} /* else we can't precompile the data */

	return 0;
}

static unlang_group_t *group_allocate(unlang_t *parent, CONF_SECTION *cs, unlang_ext_t const *ext)
{
	unlang_group_t	*g;
	unlang_t	*c;
	TALLOC_CTX	*ctx;

	ctx = parent;
	if (!ctx) ctx = cs;

	/*
	 *	All the groups have a common header
	 */
	g = (unlang_group_t *)_talloc_zero_pooled_object(ctx, ext->len, ext->type_name,
							 ext->pool_headers, ext->pool_len);
	if (!g) return NULL;

	g->children = NULL;
	g->tail = &g->children;
	g->cs = cs;

	c = unlang_group_to_generic(g);
	c->parent = parent;
	c->type = ext->type;

	return g;
}

static void compile_action_defaults(unlang_t *c, unlang_compile_t *unlang_ctx)
{
	int i;

	/*
	 *	Children of "redundant" and "redundant-load-balance"
	 *	have RETURN for all actions except fail.  But THEIR children are normal.
	 */
	if (c->parent &&
	    ((c->parent->type == UNLANG_TYPE_REDUNDANT) || (c->parent->type == UNLANG_TYPE_REDUNDANT_LOAD_BALANCE))) {
		for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
			if (i == RLM_MODULE_FAIL) {
				if (!c->actions[i]) {
					c->actions[i] = 1;
				}

				continue;
			}

			if (!c->actions[i]) {
				c->actions[i] = MOD_ACTION_RETURN;
			}
		}

		return;
	}

	/*
	 *	Set the default actions, if they haven't already been
	 *	set.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		if (!c->actions[i]) {
			c->actions[i] = unlang_ctx->actions[0][i];
		}
	}
}

static int compile_map_name(unlang_group_t *g)
{
	unlang_map_t	*gext = unlang_group_to_map(g);

	/*
	 *	If the section has arguments beyond
	 *	name1 and name2, they form input
	 *	arguments into the map.
	 */
	if (gext->vpt) {
		char	quote;
		size_t	quoted_len;
		char	*quoted_str;

		switch (cf_section_argv_quote(g->cs, 0)) {
		case T_DOUBLE_QUOTED_STRING:
			quote = '"';
			break;

		case T_SINGLE_QUOTED_STRING:
			quote = '\'';
			break;

		case T_BACK_QUOTED_STRING:
			quote = '`';
			break;

		default:
			quote = '\0';
			break;
		}

		quoted_len = fr_snprint_len(gext->vpt->name, gext->vpt->len, quote);
		quoted_str = talloc_array(g, char, quoted_len);
		fr_snprint(quoted_str, quoted_len, gext->vpt->name, gext->vpt->len, quote);

		g->self.name = talloc_typed_asprintf(g, "map %s %s", cf_section_name2(g->cs), quoted_str);
		g->self.debug_name = g->self.name;
		talloc_free(quoted_str);

		return 0;
	}

	g->self.name = talloc_typed_asprintf(g, "map %s", cf_section_name2(g->cs));
	g->self.debug_name = g->self.name;

	return 0;
}

static unlang_t *compile_map(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	int			rcode;

	unlang_group_t		*g;
	unlang_map_t	*gext;

	unlang_t		*c;
	CONF_SECTION		*modules;
	ssize_t			slen;
	char const		*tmpl_str;

	map_t		*head;
	tmpl_t			*vpt = NULL;

	map_proc_t		*proc;
	map_proc_inst_t		*proc_inst;

	char const		*name2 = cf_section_name2(cs);

	tmpl_rules_t		parse_rules;

	static unlang_ext_t const map_ext = {
		.type = UNLANG_TYPE_MAP,
		.len = sizeof(unlang_map_t),
		.type_name = "unlang_map_t"
	};

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	modules = cf_section_find(cf_root(cs), "modules", NULL);
	if (!modules) {
		cf_log_err(cs, "'map' sections require a 'modules' section");
		return NULL;
	}

	proc = map_proc_find(name2);
	if (!proc) {
		cf_log_err(cs, "Failed to find map processor '%s'", name2);
		return NULL;
	}

	g = group_allocate(parent, cs, &map_ext);
	if (!g) return NULL;

	gext = unlang_group_to_map(g);

	/*
	 *	If there's a third string, it's the map src.
	 *
	 *	Convert it into a template.
	 */
	tmpl_str = cf_section_argv(cs, 0); /* AFTER name1, name2 */
	if (tmpl_str) {
		fr_token_t type;

		type = cf_section_argv_quote(cs, 0);

		/*
		 *	Try to parse the template.
		 */
		slen = tmpl_afrom_substr(gext, &vpt,
					 &FR_SBUFF_IN(tmpl_str, talloc_array_length(tmpl_str) - 1),
					 type,
					 NULL,
					 &parse_rules);
		if (slen < 0) {
			cf_log_perr(cs, "Failed parsing map");
		error:
			talloc_free(g);
			return NULL;
		}

		/*
		 *	Limit the allowed template types.
		 */
		switch (vpt->type) {
		case TMPL_TYPE_UNRESOLVED:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_ATTR_UNRESOLVED:
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_XLAT_UNRESOLVED:
		case TMPL_TYPE_EXEC:
		case TMPL_TYPE_EXEC_UNRESOLVED:
		case TMPL_TYPE_DATA:
			break;

		default:
			talloc_free(vpt);
			cf_log_err(cs, "Invalid third argument for map");
			return NULL;
		}
	}

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = map_afrom_cs(gext, &head, cs, &parse_rules, &parse_rules, unlang_fixup_map, NULL, 256);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err(cs, "'map' sections cannot be empty");
		goto error;
	}


	/*
	 *	Call the map's instantiation function to validate
	 *	the map and perform any caching required.
	 */
	proc_inst = map_proc_instantiate(gext, proc, cs, vpt, head);
	if (!proc_inst) {
		cf_log_err(cs, "Failed instantiating map function '%s'", name2);
		goto error;
	}
	c = unlang_group_to_generic(g);

	gext->map = head;
	gext->vpt = vpt;
	gext->proc_inst = proc_inst;

	compile_map_name(g);

	/*
	 *	Cache the module in the unlang_group_t struct.
	 *
	 *	Ensure that the module has a "map" entry in its module
	 *	header?  Or ensure that the map is registered in the
	 *	"boostrap" phase, so that it's always available here.
	 */
	if (!pass2_fixup_map_rhs(g, unlang_ctx->rules)) goto error;

	compile_action_defaults(c, unlang_ctx);

	return c;
}

static unlang_t *compile_update(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	int			rcode;

	unlang_group_t		*g;
	unlang_map_t	*gext;

	unlang_t		*c;
	char const		*name2 = cf_section_name2(cs);

	map_t		*head;

	tmpl_rules_t		parse_rules;

	static unlang_ext_t const update_ext = {
		.type = UNLANG_TYPE_UPDATE,
		.len = sizeof(unlang_map_t),
		.type_name = "unlang_map_t"
	};

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	g = group_allocate(parent, cs, &update_ext);
	if (!g) return NULL;

	gext = unlang_group_to_map(g);

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = map_afrom_cs(gext, &head, cs, &parse_rules, &parse_rules, unlang_fixup_update, NULL, 128);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err(cs, "'update' sections cannot be empty");
	error:
		talloc_free(g);
		return NULL;
	}

	c = unlang_group_to_generic(g);
	if (name2) {
		c->name = name2;
		c->debug_name = talloc_typed_asprintf(c, "update %s", name2);
	} else {
		c->name = "update";
		c->debug_name = c->name;
	}

	gext->map = head;

	if (!pass2_fixup_update(g, unlang_ctx->rules)) goto error;

	compile_action_defaults(c, unlang_ctx);

	return c;
}

static unlang_t *compile_filter(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	int			rcode;

	unlang_group_t		*g;
	unlang_map_t	*gext;

	unlang_t		*c;
	char const		*name2 = cf_section_name2(cs);

	map_t		*head;

	tmpl_rules_t		parse_rules;

	static unlang_ext_t const filter_ext = {
		.type = UNLANG_TYPE_FILTER,
		.len = sizeof(unlang_map_t),
		.type_name = "unlang_map_t"
	};

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	g = group_allocate(parent, cs, &filter_ext);
	if (!g) return NULL;

	gext = unlang_group_to_map(g);

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = map_afrom_cs(gext, &head, cs, &parse_rules, &parse_rules, unlang_fixup_filter, NULL, 128);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err(cs, "'filter' sections cannot be empty");
		return NULL;
	}

	c = unlang_group_to_generic(g);

	if (name2) {
		c->name = name2;
		c->debug_name = talloc_typed_asprintf(c, "filter %s", name2);
	} else {
		c->name = "filter";
		c->debug_name = c->name;
	}

	gext->map = head;

	/*
	 *	The fixups here occur whether or not it's UPDATE or FILTER
	 */
	if (!pass2_fixup_update(g, unlang_ctx->rules)) {
		talloc_free(g);
		return NULL;
	}

	compile_action_defaults(c, unlang_ctx);

	return c;
}

/*
 *	Compile action && rcode for later use.
 */
static int compile_action_pair(unlang_t *c, CONF_PAIR *cp)
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

	else if (strspn(value, "0123456789")==strlen(value)) {
		action = atoi(value);

		if (!action || (action > MOD_PRIORITY_MAX)) {
			cf_log_err(cp, "Priorities MUST be between 1 and 64.");
			return 0;
		}

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
		c->actions[rcode] = action;

	} else {		/* set all unset values to the default */
		int i;

		for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
			if (!c->actions[i]) c->actions[i] = action;
		}
	}

	return 1;
}

static bool compile_action_section(unlang_t *c, CONF_ITEM *ci)
{
	CONF_ITEM *csi;
	CONF_SECTION *cs;

	if (!cf_item_is_section(ci)) return c;

	/*
	 *	Over-ride the default return codes of the module.
	 */
	cs = cf_item_to_section(ci);
	for (csi=cf_item_next(cs, NULL);
	     csi != NULL;
	     csi=cf_item_next(cs, csi)) {

		if (cf_item_is_section(csi)) {
			cf_log_err(csi, "Invalid subsection.  Expected 'action = value'");
			return false;
		}

		if (!cf_item_is_pair(csi)) continue;

		if (!compile_action_pair(c, cf_item_to_pair(csi))) {
			return false;
		}
	}

	return true;
}

static unlang_t *compile_empty(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs, unlang_ext_t const *ext)
{
	unlang_group_t *g;
	unlang_t *c;

	/*
	 *	If we're compiling an empty section, then the
	 *	*intepreter* type is GROUP, even if the *debug names*
	 *	are something else.
	 */
	g = group_allocate(parent, cs, ext);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);
	if (!cs) {
		c->name = unlang_ops[ext->type].name;
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

	compile_action_defaults(c, unlang_ctx);
	return c;
}


static unlang_t *compile_item(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM *ci);

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
	 *	Over-riding actions makes no sense in some situations.
	 *	They just don't make sense for many group types.
	 */
	if (!((c->type == UNLANG_TYPE_CASE) || (c->type == UNLANG_TYPE_IF) || (c->type == UNLANG_TYPE_ELSIF) ||
	      (c->type == UNLANG_TYPE_GROUP) || (c->type == UNLANG_TYPE_ELSE))) {
		cf_log_err(ci, "'actions' MUST NOT be in a '%s' block", unlang_ops[c->type].name);
		return false;
	}

	return compile_action_section(c, ci);
}


static unlang_t *compile_children(unlang_group_t *g, unlang_compile_t *unlang_ctx)
{
	CONF_ITEM	*ci = NULL;
	unlang_t	*c, *single;
	bool		was_if = false;
	char const	*skip_else = NULL;

	c = unlang_group_to_generic(g);

	/*
	 *	Loop over the children of this group.
	 */
	while ((ci = cf_item_next(g->cs, ci))) {
		if (cf_item_is_data(ci)) continue;

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
			if (strcmp(name, "actions") == 0) {
				if (!compile_action_subsection(c, g->cs, subcs)) {
					talloc_free(c);
					return NULL;
				}

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
					talloc_free(c);
					return NULL;
				}

				/*
				 *	There was a previous "if" or "elsif" which was always taken.
				 *	So we skip this "elsif" or "else".
				 */
				if (skip_else) {
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
				talloc_free(c);
				return NULL;
			}

			goto add_child;
		}

		if (cf_item_is_pair(ci)) {
			char const *attr;
			CONF_PAIR *cp = cf_item_to_pair(ci);

			attr = cf_pair_attr(cp);

			/*
			 *	Bare "foo = bar" is disallowed.
			 */
			if (cf_pair_value(cp) != NULL) {
				cf_log_err(cp, "Unknown keyword '%s', or invalid location", attr);
				talloc_free(c);
				return NULL;
			}

			/*
			 *	Compile the item as a module
			 *	reference, or as "break / return /
			 *	etc."
			 */
			single = compile_item(c, unlang_ctx, ci);
			if (!single) {
				cf_log_err(ci, "Invalid keyword \"%s\".", attr);
				talloc_free(c);
				return NULL;
			}

			goto add_child;
		} /* was CONF_PAIR */

		cf_log_err(ci, "Internal sanity check failed in unlang compile.");
		talloc_free(c);
		return NULL;

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
				unlang_group_t		*f;
				unlang_cond_t	*gext;

				f = unlang_generic_to_group(single);
				gext = unlang_group_to_cond(f);

				switch (gext->cond->type) {
				case COND_TYPE_TRUE:
					skip_else = single->debug_name;
					break;

				case COND_TYPE_FALSE:
					/*
					 *	The condition never
					 *	matches, so we can
					 *	avoid putting it into
					 *	the unlang tree.
					 */
					talloc_free(single);
					continue;

				default:
					break;
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
		fr_assert(!single->next);

		*g->tail = single;
		g->tail = &single->next;
		g->num_children++;

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

	/*
	 *	Set the default actions, if they haven't already been
	 *	set by an "actions" section above.
	 */
	compile_action_defaults(c, unlang_ctx);

	return c;
}


/*
 *	Generic "compile a section with more unlang inside of it".
 */
static unlang_t *compile_section(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				 unlang_ext_t const *ext)
{
	unlang_group_t	*g;
	unlang_t	*c;
	char const	*name1, *name2;

	/*
	 *	We always create a group, even if the section is empty.
	 */
	g = group_allocate(parent, cs, ext);
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
	if (ext->type == UNLANG_TYPE_POLICY) {
		MEM(c->debug_name = talloc_typed_asprintf(c, "policy %s", name1));

	} else if (!name2) {
		c->debug_name = c->name;

	} else {
		MEM(c->debug_name = talloc_typed_asprintf(c, "%s %s", name1, name2));
	}

	return compile_children(g, unlang_ctx);
}


static unlang_t *compile_group(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	static unlang_ext_t const group = {
		.type = UNLANG_TYPE_GROUP,
		.len = sizeof(unlang_group_t),
		.type_name = "unlang_group_t",
	};

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	return compile_section(parent, unlang_ctx, cs, &group);
}

static unlang_t *compile_case(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs);

static unlang_t *compile_switch(UNUSED unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	CONF_ITEM		*ci;
	fr_token_t		type;
	char const		*name1, *name2;
	bool			had_seen_default = false;

	unlang_group_t		*g;
	unlang_switch_t	*gext;

	unlang_t		*c;
	ssize_t			slen;

	tmpl_rules_t		parse_rules;

	static unlang_ext_t const switch_ext = {
		.type = UNLANG_TYPE_SWITCH,
		.len = sizeof(unlang_switch_t),
		.type_name = "unlang_switch_t",
		.pool_headers = TMPL_POOL_DEF_HEADERS,
		.pool_len = TMPL_POOL_DEF_LEN
	};

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs, "You must specify a variable to switch over for 'switch'");
		return NULL;
	}

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	g = group_allocate(parent, cs, &switch_ext);
	if (!g) return NULL;

	gext = unlang_group_to_switch(g);

	/*
	 *	Create the template.  All attributes and xlats are
	 *	defined by now.
	 *
	 *	The 'case' statements need g->vpt filled out to ensure
	 *	that the data types match.
	 */
	type = cf_section_name2_quote(cs);
	slen = tmpl_afrom_substr(gext, &gext->vpt,
				 &FR_SBUFF_IN(name2, strlen(name2)),
				 type,
				 NULL,
				 &parse_rules);
	if (slen < 0) {
		char *spaces, *text;

		fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

		cf_log_err(cs, "Syntax error");
		cf_log_err(cs, "%s", name2);
		cf_log_err(cs, "%s^ %s", spaces, text);

		talloc_free(g);
		talloc_free(spaces);
		talloc_free(text);

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
	if (!pass2_fixup_tmpl(g, cf_section_to_item(cs), &gext->vpt)) {
		talloc_free(g);
		return NULL;
	}

	/*
	 *	Walk through the children of the switch section,
	 *	ensuring that they're all 'case' statements, and then compiling them.
	 */
	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		CONF_SECTION *subcs;
		unlang_t *single;

		if (!cf_item_is_section(ci)) {
			if (!cf_item_is_pair(ci)) continue;

			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(g);
			return NULL;
		}

		subcs = cf_item_to_section(ci);	/* can't return NULL */
		name1 = cf_section_name1(subcs);

		if (strcmp(name1, "case") != 0) {
			/*
			 *	We finally support "default" sections for "switch".
			 */
			if (strcmp(name1, "default") == 0) {
				if (cf_section_name2(subcs) != 0) {
					cf_log_err(ci, "\"default\" sections cannot have a match argument");
					talloc_free(g);
					return NULL;
				}
				goto handle_default;
			}

			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(g);
			return NULL;
		}

		name2 = cf_section_name2(subcs);
		if (!name2) {
		handle_default:
			if (had_seen_default) {
				cf_log_err(ci, "Cannot have two 'default' case statements");
				talloc_free(g);
				return NULL;
			}

			had_seen_default = true;
		}

		/*
		 *	Compile the subsection.
		 */
		single = compile_case(c, unlang_ctx, subcs);
		if (!single) {
			talloc_free(g);
			return NULL;
		}

		*g->tail = single;
		g->tail = &single->next;
		g->num_children++;
	}

	compile_action_defaults(c, unlang_ctx);

	return c;
}

static unlang_t *compile_case(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	int			i;
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*case_g;
	unlang_case_t	*case_gext;
	tmpl_t			*vpt = NULL;
	tmpl_rules_t		parse_rules;

	static unlang_ext_t const case_ext = {
		.type = UNLANG_TYPE_CASE,
		.len = sizeof(unlang_case_t),
		.type_name = "unlang_case_t",
	};

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	if (!parent || (parent->type != UNLANG_TYPE_SWITCH)) {
		cf_log_err(cs, "\"case\" statements may only appear within a \"switch\" section");
		return NULL;
	}

	/*
	 *	case THING means "match THING"
	 *	case       means "match anything"
	 */
	name2 = cf_section_name2(cs);
	if (name2) {
		ssize_t			slen;
		fr_token_t		type;
		unlang_group_t		*switch_g;
		unlang_switch_t	*switch_gext;

		type = cf_section_name2_quote(cs);

		slen = tmpl_afrom_substr(cs, &vpt,
					 &FR_SBUFF_IN(name2, strlen(name2)),
					 type,
					 NULL,
					 &parse_rules);
		if (slen < 0) {
			char *spaces, *text;

			fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

			cf_log_err(cs, "Syntax error");
			cf_log_err(cs, "%s", name2);
			cf_log_err(cs, "%s^ %s", spaces, text);

			talloc_free(spaces);
			talloc_free(text);

			return NULL;
		}

		if (tmpl_is_attr_unresolved(vpt)) {
			if (!pass2_fixup_tmpl(parent, cf_section_to_item(cs), &vpt)) {
				talloc_free(vpt);
				return NULL;
			}
		}

		switch_g = unlang_generic_to_group(parent);
		switch_gext = unlang_group_to_switch(switch_g);
		fr_assert(switch_gext->vpt != NULL);

		/*
		 *	Do type-specific checks on the case statement
		 */

		/*
		 *	We're switching over an attribute.  Check that the
		 *	values match.
		 */
		if (tmpl_is_unresolved(vpt) &&
		    tmpl_is_attr(switch_gext->vpt)) {
			fr_assert(tmpl_da(switch_gext->vpt) != NULL);

			if (tmpl_cast_in_place(vpt, tmpl_da(switch_gext->vpt)->type, tmpl_da(switch_gext->vpt)) < 0) {
				cf_log_perr(cs, "Invalid argument for case statement");
				talloc_free(vpt);
				return NULL;
			}
		}

		/*
		 *	Compile and sanity check xlat
		 *	expansions.
		 */
		if (tmpl_is_xlat_unresolved(vpt)) {
			/*
			 *	Don't expand xlat's into an
			 *	attribute of a different type.
			 */
			if (!pass2_fixup_tmpl(parent, cf_section_to_item(cs), &vpt)) {
				talloc_free(vpt);
				return NULL;
			}
		}

		if (tmpl_is_exec(vpt)) {
			if (!pass2_fixup_tmpl(parent, cf_section_to_item(cs), &vpt)) {
				talloc_free(vpt);
				return NULL;
			}
		}
	} /* else it's a default 'case' statement */

	/*
	 *	If we were asked to match something, then we MUST
	 *	match it, even if the section is empty.  Otherwise we
	 *	will silently skip the match, and then fall through to
	 *	the "default" statement.
	 */
	c = compile_section(parent, unlang_ctx, cs, &case_ext);
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
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) c->actions[i] = MOD_ACTION_RETURN;

	return c;
}

static unlang_t *compile_foreach(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	fr_token_t		type;
	char const		*name2;
	unlang_t		*c;

	unlang_group_t		*g;
	unlang_foreach_t	*gext;

	ssize_t			slen;
	tmpl_t			*vpt;

	tmpl_rules_t		parse_rules;

	static unlang_ext_t const foreach_ext = {
		.type = UNLANG_TYPE_FOREACH,
		.len = sizeof(unlang_foreach_t),
		.type_name = "unlang_foreach_t",
		.pool_headers = TMPL_POOL_DEF_HEADERS,
		.pool_len = TMPL_POOL_DEF_LEN
	};

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs,
			   "You must specify an attribute to loop over in 'foreach'");
		return NULL;
	}

	/*
	 *	Create the template.  If we fail, AND it's a bare word
	 *	with &Foo-Bar, it MAY be an attribute defined by a
	 *	module.  Allow it for now.  The pass2 checks below
	 *	will fix it up.
	 */
	type = cf_section_name2_quote(cs);
	slen = tmpl_afrom_substr(cs, &vpt,
				 &FR_SBUFF_IN(name2, strlen(name2)),
				 type,
				 NULL,
				 &parse_rules);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

		cf_log_err(cs, "Syntax error");
		cf_log_err(cs, "%s", name2);
		cf_log_err(cs, "%s^ %s", spaces, text);

		talloc_free(spaces);
		talloc_free(text);

		return NULL;
	}

	if (!cf_item_next(cs, NULL)) {
		talloc_free(vpt);
		return UNLANG_IGNORE;
	}

	/*
	 *	If we don't have a negative return code, we must have a vpt
	 *	(mostly to quiet coverity).
	 */
	fr_assert(vpt);

	if (!tmpl_is_attr(vpt) && !tmpl_is_list(vpt)) {
		cf_log_err(cs, "MUST use attribute or list reference (not %s) in 'foreach'",
			   fr_table_str_by_value(tmpl_type_table, vpt->type, "???"));
		talloc_free(vpt);
		return NULL;
	}

	if ((tmpl_num(vpt) != NUM_ALL) && (tmpl_num(vpt) != NUM_ANY)) {
		cf_log_err(cs, "MUST NOT use instance selectors in 'foreach'");
		talloc_free(vpt);
		return NULL;
	}

	/*
	 *	Fix up the template to iterate over all instances of
	 *	the attribute. In a perfect consistent world, users would do
	 *	foreach &attr[*], but that's taking the consistency thing a bit far.
	 */
	tmpl_attr_rewrite_leaf_num(vpt, NUM_ANY, NUM_ALL);

	c = compile_section(parent, unlang_ctx, cs, &foreach_ext);
	if (!c) {
		talloc_free(vpt);
		return NULL;
	}

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_foreach(g);
	gext->vpt = vpt;

	return c;
}

static unlang_t *compile_break(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *foreach;

	static unlang_ext_t const break_ext = {
		.type = UNLANG_TYPE_BREAK,
		.len = sizeof(unlang_group_t),
		.type_name = "unlang_group_t",
	};

	for (foreach = parent; foreach != NULL; foreach = foreach->parent) {
		/*
		 *	A "break" inside of a "policy" is an error.
		 *	We CANNOT allow "break" inside of a policy to
		 *	affect a "foreach" loop outside of that
		 *	policy.
		 */
		if (foreach->type == UNLANG_TYPE_POLICY) goto fail;

		if (foreach->type == UNLANG_TYPE_FOREACH) break;
	}

	if (!foreach) {
	fail:
		cf_log_err(ci, "'break' can only be used in a 'foreach' section");
		return NULL;
	}

	parent->closed = true;

	return compile_empty(parent, unlang_ctx, NULL, &break_ext);
}

static unlang_t *compile_detach(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *subrequest;

	static unlang_ext_t const detach_ext = {
		.type = UNLANG_TYPE_DETACH,
		.len = sizeof(unlang_group_t),
		.type_name = "unlang_group_t",
	};

	for (subrequest = parent;
	     subrequest != NULL;
	     subrequest = subrequest->parent) {
		if (subrequest->type == UNLANG_TYPE_SUBREQUEST) break;
	}

	if (!subrequest) {
		cf_log_err(ci, "'detach' can only be used inside of a 'subrequest' section.");
		return NULL;
	}

	/*
	 *	This really overloads the functionality of
	 *	cf_item_next().
	 */
	if ((parent == subrequest) && !cf_item_next(ci, ci)) {
		cf_log_err(ci, "'detach' cannot be used as the last entry in a section, as there is nothing more to do");
		return NULL;
	}

	return compile_empty(parent, unlang_ctx, NULL, &detach_ext);
}

static unlang_t *compile_return(unlang_t *parent, unlang_compile_t *unlang_ctx, UNUSED CONF_ITEM *ci)
{
	static unlang_ext_t const return_ext = {
		.type = UNLANG_TYPE_RETURN,
		.len = sizeof(unlang_group_t),
		.type_name = "unlang_group_t",
	};

	/*
	 *	These types are all parallel, and therefore can have a "return" in them.
	 */
	switch (parent->type) {
	case UNLANG_TYPE_LOAD_BALANCE:
	case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
	case UNLANG_TYPE_PARALLEL:
		break;

	default:
		parent->closed = true;
		break;
	}

	return compile_empty(parent, unlang_ctx, NULL, &return_ext);
}

static unlang_t *compile_tmpl(unlang_t *parent,
			      unlang_compile_t *unlang_ctx, CONF_PAIR *cp)
{
	unlang_t	*c;
	unlang_tmpl_t	*ut;
	ssize_t		slen;
	char const	*p = cf_pair_attr(cp);
	tmpl_t		*vpt;

	ut = talloc_zero(parent, unlang_tmpl_t);

	c = unlang_tmpl_to_generic(ut);
	c->parent = parent;
	c->next = NULL;
	c->name = p;
	c->debug_name = c->name;
	c->type = UNLANG_TYPE_TMPL;

	slen = tmpl_afrom_substr(ut, &vpt,
				 &FR_SBUFF_IN(p, talloc_array_length(p) - 1),
				 cf_pair_attr_quote(cp),
				 NULL,
				 unlang_ctx->rules);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(cp, &spaces, &text, slen, fr_strerror());

		cf_log_err(cp, "Syntax error");
		cf_log_err(cp, "%s", p);
		cf_log_err(cp, "%s^ %s", spaces, text);

		talloc_free(ut);
		talloc_free(spaces);
		talloc_free(text);

		return NULL;
	}
	ut->tmpl = vpt;	/* const issues */

	compile_action_defaults(c, unlang_ctx);
	return c;
}

static unlang_t *compile_if_subsection(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				       unlang_ext_t const *ext)
{
	unlang_t		*c;

	unlang_group_t		*g;
	unlang_cond_t	*gext;

	fr_cond_t		*cond;

	if (!cf_section_name2(cs)) {
		cf_log_err(cs, "'%s' without condition", unlang_ops[ext->type].name);
		return NULL;
	}

	cond = cf_data_value(cf_data_find(cs, fr_cond_t, NULL));
	fr_assert(cond != NULL);

	if (cond->type == COND_TYPE_FALSE) {
		cf_log_debug_prefix(cs, "Skipping contents of '%s' as it is always 'false'",
				    unlang_ops[ext->type].name);
		c = compile_empty(parent, unlang_ctx, cs, ext);
	} else {
		/*
		 *	The condition may refer to attributes, xlats, or
		 *	Auth-Types which didn't exist when it was first
		 *	parsed.  Now that they are all defined, we need to fix
		 *	them up.
		 */
		if (!fr_cond_walk(cond, pass2_cond_callback, unlang_ctx)) return NULL;
		c = compile_section(parent, unlang_ctx, cs, ext);
	}
	if (!c) return NULL;
	fr_assert(c != UNLANG_IGNORE);

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_cond(g);
	gext->cond = cond;

	return c;
}

static unlang_t *compile_if(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	static unlang_ext_t const if_ext = {
		.type = UNLANG_TYPE_IF,
		.len = sizeof(unlang_cond_t),
		.type_name = "unlang_cond_t",
		.pool_headers = 1 + 1 + (TMPL_POOL_DEF_HEADERS * 2),
		.pool_len = sizeof(fr_cond_t) + sizeof(map_t) + (TMPL_POOL_DEF_LEN * 2)
	};

	return compile_if_subsection(parent, unlang_ctx, cs, &if_ext);
}

static unlang_t *compile_elsif(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	static unlang_ext_t const elsif_ext = {
		.type = UNLANG_TYPE_ELSIF,
		.len = sizeof(unlang_cond_t),
		.type_name = "unlang_cond_t",
		.pool_headers = 1 + 1 + (TMPL_POOL_DEF_HEADERS * 2),
		.pool_len = sizeof(fr_cond_t) + sizeof(map_t) + (TMPL_POOL_DEF_LEN * 2)
	};

	return compile_if_subsection(parent, unlang_ctx, cs, &elsif_ext);
}

static unlang_t *compile_else(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	static unlang_ext_t const else_ext = {
		.type = UNLANG_TYPE_ELSE,
		.len = sizeof(unlang_group_t),
		.type_name = "unlang_group_t"
	};

	if (cf_section_name2(cs)) {
		cf_log_err(cs, "'else' cannot have a condition");
		return NULL;
	}

	return compile_section(parent, unlang_ctx, cs, &else_ext);
}

/*
 *	redundant, load-balance and parallel have limits on what can
 *	go in them.
 */
static int validate_limited_subsection(CONF_SECTION *cs, char const *name)
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
				return 0;
			}
			continue;
		}

		if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_item_to_pair(ci);
			if (cf_pair_value(cp) != NULL) {
				cf_log_err(cp, "Unknown keyword '%s', or invalid location", cf_pair_attr(cp));
				return 0;
			}
		}
	}

	return 1;
}


static unlang_t *compile_redundant(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	char const			*name2;
	unlang_t			*c;

	static unlang_ext_t const	redundant_ext = {
						.type = UNLANG_TYPE_REDUNDANT,
						.len = sizeof(unlang_group_t),
						.type_name = "unlang_group_t"
					};

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	if (!validate_limited_subsection(cs, cf_section_name1(cs))) {
		return NULL;
	}

	c = compile_section(parent, unlang_ctx, cs, &redundant_ext);
	if (!c) return NULL;

	/*
	 *	"redundant" is just "group" with different default actions.
	 *
	 *	Named redundant sections are only allowed in the
	 *	"instantiate" section.
	 */
	name2 = cf_section_name2(cs);

	/*
	 *	But only outside of the "instantiate" section.
	 *	For backwards compatibility.
	 */
	if (name2 &&
	    (strcmp(cf_section_name1(cf_item_to_section(cf_parent(cs))), "instantiate") != 0)) {
		cf_log_err(cs, "'redundant' sections cannot have a name");
		return NULL;
	}

	return c;
}

static unlang_t *compile_load_balance_subsection(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
						 unlang_ext_t const *ext)
{
	char const			*name2;
	unlang_t			*c;
	unlang_group_t			*g;
	unlang_load_balance_t	*gext;

	tmpl_rules_t			parse_rules;

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	/*
	 *	No children?  Die!
	 */
	if (!cf_item_next(cs, NULL)) {
		cf_log_err(cs, "%s sections cannot be empty", unlang_ops[ext->type].name);
		return NULL;
	}

	if (!validate_limited_subsection(cs, cf_section_name1(cs))) return NULL;

	c = compile_section(parent, unlang_ctx, cs, ext);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);

	/*
	 *	Allow for keyed load-balance / redundant-load-balance sections.
	 */
	name2 = cf_section_name2(cs);

	/*
	 *	Inside of the "instantiate" section, the name is a name, not a key.
	 */
	if (name2) {
		if (strcmp(cf_section_name1(cf_item_to_section(cf_parent(cs))), "instantiate") == 0) name2 = NULL;
	}

	if (name2) {
		fr_token_t type;
		ssize_t slen;

		/*
		 *	Create the template.  All attributes and xlats are
		 *	defined by now.
		 */
		type = cf_section_name2_quote(cs);
		gext = unlang_group_to_load_balance(g);
		slen = tmpl_afrom_substr(gext, &gext->vpt,
					 &FR_SBUFF_IN(name2, strlen(name2)),
					 type,
					 NULL,
					 &parse_rules);
		if (slen < 0) {
			char *spaces, *text;

			fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

			cf_log_err(cs, "Syntax error");
			cf_log_err(cs, "%s", name2);
			cf_log_err(cs, "%s^ %s", spaces, text);

			talloc_free(g);
			talloc_free(spaces);
			talloc_free(text);

			return NULL;
		}

		fr_assert(gext->vpt != NULL);

		/*
		 *	Fixup the templates
		 */
		if (!pass2_fixup_tmpl(g, cf_section_to_item(cs), &gext->vpt)) {
			talloc_free(g);
			return NULL;
		}

		switch (gext->vpt->type) {
		default:
			cf_log_err(cs, "Invalid type in '%s': data will not result in a load-balance key", name2);
			talloc_free(g);
			return NULL;

			/*
			 *	Allow only these ones.
			 */
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_EXEC:
			break;
		}
	}

	return c;
}

static unlang_t *compile_load_balance(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	static unlang_ext_t const load_balance_ext = {
		.type = UNLANG_TYPE_LOAD_BALANCE,
		.len = sizeof(unlang_load_balance_t),
		.type_name = "unlang_load_balance_t"
	};

	return compile_load_balance_subsection(parent, unlang_ctx, cs, &load_balance_ext);
}


static unlang_t *compile_redundant_load_balance(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	static unlang_ext_t const redundant_load_balance_ext = {
		.type = UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,
		.len = sizeof(unlang_load_balance_t),
		.type_name = "unlang_load_balance_t"
	};

	return compile_load_balance_subsection(parent, unlang_ctx, cs, &redundant_load_balance_ext);
}

static unlang_t *compile_parallel(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	unlang_t			*c;
	char const			*name2;

	unlang_group_t			*g;
	unlang_parallel_t		*gext;

	bool				clone = true;
	bool				detach = false;

	static unlang_ext_t const 	parallel_ext = {
						.type = UNLANG_TYPE_PARALLEL,
						.len = sizeof(unlang_parallel_t),
						.type_name = "unlang_parallel_t"
					};

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	/*
	 *	Parallel sections can create empty children, if the
	 *	admin demands it.  Otherwise, the principle of least
	 *	surprise is to copy the whole request, reply, and
	 *	config items.
	 */
	name2 = cf_section_name2(cs);
	if (name2) {
		if (strcmp(name2, "empty") == 0) {
			clone = false;

		} else if (strcmp(name2, "detach") == 0) {
			detach = true;

		} else {
			cf_log_err(cs, "Invalid argument '%s'", name2);
			return NULL;
		}

	}

	/*
	 *	We can do "if" in parallel with other "if", but we
	 *	cannot do "else" in parallel with "if".
	 */
	if (!validate_limited_subsection(cs, cf_section_name1(cs))) {
		return NULL;
	}

	c = compile_section(parent, unlang_ctx, cs, &parallel_ext);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_parallel(g);
	gext->clone = clone;
	gext->detach = detach;

	return c;
}

static unlang_t *compile_subrequest(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	char const			*name2;

	unlang_t			*c;

	unlang_group_t			*g;
	unlang_subrequest_t	*gext;

	unlang_compile_t		unlang_ctx2;

	tmpl_rules_t			parse_rules;

	fr_dict_t const			*dict;
	fr_dict_attr_t const		*da = NULL;
	fr_dict_enum_t const		*type_enum = NULL;

	char const			*packet_name = NULL;
	char				*p, *namespace = NULL;

	tmpl_t				*vpt = NULL, *src_vpt = NULL, *dst_vpt = NULL;

	static unlang_ext_t const 	subrequest_ext = {
						.type = UNLANG_TYPE_SUBREQUEST,
						.len = sizeof(unlang_subrequest_t),
						.type_name = "unlang_subrequest_t",
						.pool_headers = (TMPL_POOL_DEF_HEADERS * 3),
						.pool_len = (TMPL_POOL_DEF_LEN * 3)
					};

	/*
	 *	subrequest { ... }
	 *
	 *	Create a subrequest which is of the same dictionary
	 *	and packet type as the current request.
	 *
	 *	We assume that the Packet-Type attribute exists.
	 */
	name2 = cf_section_name2(cs);
	if (!name2) {
		dict = unlang_ctx->rules->dict_def;
		packet_name = name2 = unlang_ctx->section_name2;
		goto get_packet_type;
	}

	if (cf_section_name2_quote(cs) != T_BARE_WORD) {
		cf_log_err(cs, "The arguments to 'subrequest' must be a name or an attribute reference");
		return NULL;
	}

	if (name2[0] == '&') {
		size_t slen;

		slen = tmpl_afrom_attr_substr(parent, NULL, &vpt,
					      &FR_SBUFF_IN(name2, talloc_array_length(name2) - 1),
					      NULL, unlang_ctx->rules);
		if (slen <= 0) {
			cf_log_perr(cs, "Invalid argument to 'subrequest', failed parsing packet-type");
			return NULL;
		}

		/*
		 *	Anything resembling an integer or string is
		 *	OK.  Nothing else makes sense.
		 */
		switch (tmpl_da(vpt)->type) {
		case FR_TYPE_INTEGER_EXCEPT_BOOL:
		case FR_TYPE_STRING:
			break;

		default:
			cf_log_err(cs, "Invalid data type for attribute %s.  "
				   "Must be an integer type or string", name2 + 1);
			talloc_free(vpt);
			return NULL;
		}

		dict = unlang_ctx->rules->dict_def;
		packet_name = NULL;
		goto get_packet_type;
	}

	/*
	 *	subrequest foo { ... }
	 *
	 *	Change packet types without changing dictionaries.
	 */
	p = strchr(name2, '.');
	if (!p) {
		dict = unlang_ctx->rules->dict_def;
		packet_name = name2;

	} else {
		/*
		 *	subrequest foo.bar { ... }
		 *
		 *	Change to dictionary "foo", packet type "bar".
		 */
		MEM(namespace = talloc_strdup(parent, name2)); /* get a modifiable copy */

		p = namespace + (p - name2);
		*(p++) = '\0';
		packet_name = p;

		dict = fr_dict_by_protocol_name(namespace);
		if (!dict) {
			cf_log_err(cs, "Unknown namespace '%s'", namespace);
			talloc_free(namespace);
			return NULL;
		}
	}

	/*
	 *	Use dict name instead of "namespace", because "namespace" can be omitted.
	 */
get_packet_type:
	da = fr_dict_attr_by_name(NULL, fr_dict_root(dict), "Packet-Type");
	if (!da) {
		cf_log_err(cs, "No such attribute 'Packet-Type' in namespace '%s'", fr_dict_root(dict)->name);
		talloc_free(vpt);
		talloc_free(namespace);
		return NULL;
	}

	if (packet_name) {
		type_enum = fr_dict_enum_by_name(da, packet_name, -1);
		if (!type_enum) {
			cf_log_err(cs, "No such value '%s' for attribute 'Packet-Type' in namespace '%s'",
				   packet_name, fr_dict_root(dict)->name);
			talloc_free(vpt);
			talloc_free(namespace);
			return NULL;
		}
	}
	talloc_free(namespace);		/* no longer needed */

	/*
	 *	Source and destination arguments
	 */
	{
		char const	*dst, *src;
		ssize_t		slen;

		src = cf_section_argv(cs, 0);
		if (src) {
			slen = tmpl_afrom_substr(parent, &src_vpt,
						 &FR_SBUFF_IN(src, talloc_array_length(src) - 1),
						 cf_section_argv_quote(cs, 0), NULL, unlang_ctx->rules);
			if (slen <= 0) {
				cf_log_perr(cs, "Invalid argument to 'subrequest', failed parsing src");
			error:
				talloc_free(vpt);
				return NULL;
			}

			if (!tmpl_contains_attr(src_vpt)) {
				cf_log_err(cs, "Invalid argument to 'subrequest' src must be an attr or list, got %s",
					   fr_table_str_by_value(tmpl_type_table, src_vpt->type, "<INVALID>"));
				talloc_free(src_vpt);
				goto error;
			}

			dst = cf_section_argv(cs, 1);
			if (dst) {
				slen = tmpl_afrom_substr(parent, &dst_vpt,
							 &FR_SBUFF_IN(dst, talloc_array_length(dst) - 1),
							 cf_section_argv_quote(cs, 1), NULL, unlang_ctx->rules);
				if (slen <= 0) {
					cf_log_perr(cs, "Invalid argument to 'subrequest', failed parsing dst");
					goto error;
				}

				if (!tmpl_contains_attr(dst_vpt)) {
					cf_log_err(cs, "Invalid argument to 'subrequest' dst must be an "
						   "attr or list, got %s",
						   fr_table_str_by_value(tmpl_type_table, src_vpt->type, "<INVALID>"));
					talloc_free(src_vpt);
					talloc_free(dst_vpt);
					goto error;
				}
			}
		}
	}

	if (!cf_item_next(cs, NULL)) {
		talloc_free(vpt);
		talloc_free(src_vpt);
		talloc_free(dst_vpt);
		return UNLANG_IGNORE;
	}

	parse_rules = *unlang_ctx->rules;
	parse_rules.parent = unlang_ctx->rules;
	parse_rules.dict_def = dict;
	parse_rules.allow_foreign = true;

	unlang_ctx2.actions = unlang_ctx->actions;

	/*
	 *	Update the new compilation context.
	 */
	unlang_ctx2.section_name1 = "subrequest";
	unlang_ctx2.section_name2 = name2;
	unlang_ctx2.rules = &parse_rules;
	unlang_ctx2.component = unlang_ctx->component;

	/*
	 *	Compile the subsection with a *different* default dictionary.
	 */
	c = compile_section(parent, &unlang_ctx2, cs, &subrequest_ext);
	if (!c) return NULL;

	/*
	 *	Set the dictionary and packet information, which tells
	 *	unlang_subrequest() how to process the request.
	 */
	g = unlang_generic_to_group(c);
	gext = unlang_group_to_subrequest(g);

	if (vpt) gext->vpt = talloc_steal(gext, vpt);
	gext->dict = dict;
	gext->attr_packet_type = da;
	gext->type_enum = type_enum;
	gext->src = src_vpt;
	gext->dst = dst_vpt;

	return c;
}


static unlang_t *compile_call(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	unlang_t			*c;

	unlang_group_t			*g;
	unlang_call_t		*gext;

	fr_token_t			type;
	char const     			*server;
	CONF_SECTION			*server_cs;
	fr_dict_t const			*dict;
	fr_dict_attr_t const		*attr_packet_type;

	static unlang_ext_t const 	call_ext = {
						.type = UNLANG_TYPE_CALL,
						.len = sizeof(unlang_call_t),
						.type_name = "unlang_call_t",
					};

	server = cf_section_name2(cs);
	if (!server) {
		cf_log_err(cs, "You MUST specify a server name for 'call <server> { ... }'");
		return NULL;
	}

	type = cf_section_name2_quote(cs);
	if (type != T_BARE_WORD) {
		cf_log_err(cs, "The arguments to 'call' cannot be a quoted string or a dynamic value");
		return NULL;
	}

	server_cs = virtual_server_find(server);
	if (!server_cs) {
		cf_log_err(cs, "Unknown virtual server '%s'", server);
		return NULL;
	}

	/*
	 *	The dictionaries are not compatible, forbid it.
	 */
	dict = virtual_server_namespace(server);
	if (dict && (dict != fr_dict_internal()) && fr_dict_internal() &&
	    unlang_ctx->rules->dict_def && (unlang_ctx->rules->dict_def != dict)) {
		cf_log_err(cs, "Cannot call namespace '%s' from namespaces '%s' - they have incompatible protocols",
			   fr_dict_root(dict)->name, fr_dict_root(unlang_ctx->rules->dict_def)->name);
		return NULL;
	}

	attr_packet_type = fr_dict_attr_by_name(NULL, fr_dict_root(dict), "Packet-Type");
	if (!attr_packet_type) {
		cf_log_err(cs, "Cannot call namespace '%s' - it has no Packet-Type attribute",
			   fr_dict_root(dict)->name);
		return NULL;
	}

	c = compile_section(parent, unlang_ctx, cs, &call_ext);
	if (!c) return NULL;

	/*
	 *	Set the virtual server name, which tells unlang_call()
	 *	which virtual server to call.
	 */
	g = unlang_generic_to_group(c);
	gext = unlang_group_to_call(g);
	gext->server_cs = server_cs;
	gext->attr_packet_type = attr_packet_type;

	return c;
}


static unlang_t *compile_caller(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs)
{
	unlang_t			*c;

	unlang_group_t			*g;
	unlang_caller_t		*gext;

	fr_token_t			type;
	char const     			*name;
	fr_dict_t const			*dict;
	unlang_compile_t		unlang_ctx2;
	tmpl_rules_t			parent_rules, parse_rules;

	static unlang_ext_t const 	caller_ext = {
						.type = UNLANG_TYPE_CALLER,
						.len = sizeof(unlang_caller_t),
						.type_name = "unlang_caller_t",
					};

	name = cf_section_name2(cs);
	if (!name) {
		cf_log_err(cs, "You MUST specify a protocol name for 'caller <protocol> { ... }'");
		return NULL;
	}

	type = cf_section_name2_quote(cs);
	if (type != T_BARE_WORD) {
		cf_log_err(cs, "The argument to 'caller' cannot be a quoted string or a dynamic value");
		return NULL;
	}

	dict = fr_dict_by_protocol_name(name);
	if (!dict) {
		cf_log_err(cs, "Unknown protocol '%s'", name);
		return NULL;
	}

	/*
	 *	Create a new parent context with the new dictionary.
	 */
	memcpy(&parent_rules, unlang_ctx->rules, sizeof(parent_rules));
	memcpy(&parse_rules, unlang_ctx->rules, sizeof(parse_rules));
	parent_rules.dict_def = dict;
	parse_rules.parent = &parent_rules;

	/*
	 *	We don't want to modify the context we were passed, so
	 *	we just clone it
	 */
	memcpy(&unlang_ctx2, unlang_ctx, sizeof(unlang_ctx2));
	unlang_ctx2.rules = &parse_rules;
	unlang_ctx2.section_name1 = "caller";
	unlang_ctx2.section_name2 = name;

	c = compile_section(parent, &unlang_ctx2, cs, &caller_ext);
	if (!c) return NULL;

	/*
	 *	Set the virtual server name, which tells unlang_call()
	 *	which virtual server to call.
	 */
	g = unlang_generic_to_group(c);
	gext = unlang_group_to_caller(g);
	gext->dict = dict;

	if (!g->num_children) {
		talloc_free(c);
		return UNLANG_IGNORE;
	}

	return c;
}

static unlang_t *compile_function(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM *ci,
				  CONF_SECTION *subcs, rlm_components_t component,
				  bool policy)
{
	unlang_compile_t		unlang_ctx2;
	unlang_t			*c;

	static unlang_ext_t const 	policy_ext = {
						.type = UNLANG_TYPE_POLICY,
						.len = sizeof(unlang_group_t),
						.type_name = "unlang_group_t",
					};

	static unlang_ext_t const 	group_ext = {
						.type = UNLANG_TYPE_GROUP,
						.len = sizeof(unlang_group_t),
						.type_name = "unlang_group_t",
					};

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
		UPDATE_CTX2;

		if (policy) {
			cf_log_err(subcs, "Unexpected second name in policy");
			return NULL;
		}

		c = compile_item(parent, &unlang_ctx2, cf_section_to_item(subcs));

	} else {
		UPDATE_CTX2;

		/*
		 *	We have:
		 *
		 *	foo { ...
		 *
		 *	So we compile it like it was:
		 *
		 *	group foo { ...
		 */
		c = compile_section(parent, &unlang_ctx2, subcs,
				    policy ? &policy_ext : &group_ext);
	}
	if (!c) return NULL;
	fr_assert(c != UNLANG_IGNORE);

	/*
	 *	Return the compiled thing if we can.
	 */
	if (cf_item_is_pair(ci)) return c;

	/*
	 *	Else we have a reference to a policy, and that reference
	 *	over-rides the return codes for the policy!
	 */
	if (!compile_action_section(c, ci)) {
		talloc_free(c);
		return NULL;
	}

	return c;
}

/** Load a named module from "instantiate" or "policy".
 *
 * If it's "foo.method", look for "foo", and return "method" as the method
 * we wish to use, instead of the input component.
 *
 * @param[in] ci		Configuration item to check
 * @param[out] pcomponent	Where to write the method we found, if any.
 *				If no method is specified will be set to MOD_COUNT.
 * @param[in] real_name		Complete name string e.g. foo.authorize.
 * @param[in] virtual_name	Virtual module name e.g. foo.
 * @param[in] method_name	Method override (may be NULL) or the method
 *				name e.g. authorize.
 * @param[out] policy		whether or not this thing was a policy
 * @return the CONF_SECTION specifying the virtual module.
 */
static CONF_SECTION *virtual_module_find_cs(CONF_ITEM *ci, rlm_components_t *pcomponent,
					    char const *real_name, char const *virtual_name, char const *method_name,
					    bool *policy)
{
	CONF_SECTION *cs, *subcs, *conf_root;
	CONF_ITEM *loop;
	rlm_components_t method = *pcomponent;
	char buffer[256];

	*policy = false;
	conf_root = cf_root(ci);

	/*
	 *	Turn the method name into a method enum.
	 */
	if (method_name) {
		rlm_components_t i;

		for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
			if (strcmp(comp2str[i], method_name) == 0) break;
		}

		if (i != MOD_COUNT) {
			method = i;
		} else {
			method_name = NULL;
			virtual_name = real_name;
		}
	}

	/*
	 *	Look for "foo" in the "instantiate" section.  If we
	 *	find it, AND there's no method name, we've found the
	 *	right thing.
	 *
	 *	Return it to the caller, with the updated method.
	 */
	cs = cf_section_find(conf_root, "instantiate", NULL);
	if (cs) {
		/*
		 *	Found "foo".  Load it as "foo", or "foo.method".
		 */
		subcs = cf_section_find(cs, CF_IDENT_ANY, virtual_name);
		if (subcs) {
			*pcomponent = method;
			goto check_for_loop;
		}
	}

	/*
	 *	Look for it in "policy".
	 *
	 *	If there's no policy section, we can't do anything else.
	 */
	cs = cf_section_find(conf_root, "policy", NULL);
	if (!cs) return NULL;

	*policy = true;

	/*
	 *	"foo.authorize" means "load policy "foo" as method "authorize".
	 *
	 *	And bail out if there's no policy "foo".
	 */
	if (method_name) {
		subcs = cf_section_find(cs, virtual_name, NULL);
		if (!subcs) return NULL;

		*pcomponent = method;
		goto check_for_loop;
	}

	/*
	 *	"foo" means "look for foo.component" first, to allow
	 *	method overrides.  If that's not found, just look for
	 *	a policy "foo".
	 */
	snprintf(buffer, sizeof(buffer), "%s.%s", virtual_name, comp2str[method]);
	subcs = cf_section_find(cs, buffer, NULL);
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


static unlang_t *compile_module(unlang_t *parent, unlang_compile_t *unlang_ctx,
				CONF_ITEM *ci, module_instance_t *inst, module_method_t method,
				char const *realname)
{
	unlang_t *c;
	unlang_module_t *single;

	/*
	 *	Can't use "chap" in "dhcp".
	 */
	if (inst->module->dict && *inst->module->dict && unlang_ctx->rules && unlang_ctx->rules->dict_def &&
	    (unlang_ctx->rules->dict_def != fr_dict_internal()) &&
	    (*(inst->module->dict) != unlang_ctx->rules->dict_def)) {
		cf_log_err(ci, "The \"%s\" module can only used with 'namespace = %s'.  It cannot be used with 'namespace = %s'.",
			   inst->module->name,
			   fr_dict_root(*inst->module->dict)->name,
			   fr_dict_root(unlang_ctx->rules->dict_def)->name);
		return NULL;
	}

	/*
	 *	Check if the module in question has the necessary
	 *	component.
	 */
	if (!method) {
		if (unlang_ctx->section_name1 && unlang_ctx->section_name2) {
			cf_log_err(ci, "The \"%s\" module does not have a '%s %s' method.",
				   inst->module->name,
				   unlang_ctx->section_name1, unlang_ctx->section_name2);
		} else {
			cf_log_err(ci, "The \"%s\" module does not have a '%s' method.",
				   inst->module->name,
				   unlang_ctx->section_name1);
		}

		return NULL;
	}

	MEM(single = talloc_zero(parent, unlang_module_t));
	single->instance = inst;
	single->method = method;

	c = unlang_module_to_generic(single);
	c->parent = parent;
	c->next = NULL;

	c->name = talloc_typed_strdup(c, realname);
	c->debug_name = c->name;
	c->type = UNLANG_TYPE_MODULE;

	/*
	 *	Set the default actions, and then try to compile an action subsection.
	 */
	compile_action_defaults(c, unlang_ctx);
	if (!compile_action_section(c, ci)) {
		talloc_free(c);
		return NULL;
	}

	return c;
}

typedef unlang_t *(*unlang_op_compile_t)(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM *ci);

static fr_table_ptr_sorted_t unlang_section_keywords[] = {
	{ L("call"),		(void *) compile_call },
	{ L("caller"),		(void *) compile_caller },
	{ L("case"),		(void *) compile_case },
	{ L("else"),		(void *) compile_else },
	{ L("elsif"),		(void *) compile_elsif },
	{ L("filter"),		(void *) compile_filter },
	{ L("foreach"),		(void *) compile_foreach },
	{ L("group"),		(void *) compile_group },
	{ L("if"),		(void *) compile_if },
	{ L("load-balance"),	(void *) compile_load_balance },
	{ L("map"),		(void *) compile_map },
	{ L("parallel"),	(void *) compile_parallel },
	{ L("redundant"), 	(void *) compile_redundant },
	{ L("redundant-load-balance"), (void *) compile_redundant_load_balance },
	{ L("subrequest"),	(void *) compile_subrequest },
	{ L("switch"),		(void *) compile_switch },
	{ L("update"),		(void *) compile_update },
};
static int unlang_section_keywords_len = NUM_ELEMENTS(unlang_section_keywords);

static fr_table_ptr_sorted_t unlang_pair_keywords[] = {
	{ L("break"),		(void *) compile_break },
	{ L("detach"),		(void *) compile_detach },
	{ L("return"), 		(void *) compile_return },
};
static int unlang_pair_keywords_len = NUM_ELEMENTS(unlang_pair_keywords);


/*
 *	Compile one entry of a module call.
 */
static unlang_t *compile_item(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM *ci)
{
	char const		*name, *p;
	module_instance_t	*inst;
	CONF_SECTION		*cs, *subcs, *modules;
	char const		*realname;
	rlm_components_t	component = unlang_ctx->component;
	unlang_compile_t	unlang_ctx2;
	module_method_t		method;
	bool			policy;
	unlang_op_compile_t	compile;

	if (cf_item_is_section(ci)) {
		cs = cf_item_to_section(ci);
		name = cf_section_name1(cs);

		compile = (unlang_op_compile_t) fr_table_value_by_str(unlang_section_keywords, name, NULL);
		if (compile) return compile(parent, unlang_ctx, ci);

		/*
		 *	Forbid pair keywords as section names, e.g. "break { ... }"
		 */
		if (fr_table_value_by_str(unlang_pair_keywords, name, NULL) != NULL) {
			cf_log_err(ci, "Syntax error after keyword '%s' - unexpected '{'", name);
			return NULL;
		}

		/* else it's something like sql { fail = 1 ...} */
		goto check_for_module;

	}

	if (cf_item_is_pair(ci)) {
		/*
		 *	Else it's a module reference such as "sql", OR
		 *	one of the few bare keywords that we allow.
		 */
		CONF_PAIR *cp = cf_item_to_pair(ci);

		name = cf_pair_attr(cp);

		/*
		 *	We cannot have assignments or actions here.
		 */
		if (cf_pair_value(cp) != NULL) {
			cf_log_err(ci, "Entry is not a reference to a module");
			return NULL;
		}

		/*
		 *	In-place xlat's via %{...}.
		 *
		 *	This should really be removed from the server.
		 */
		if (((name[0] == '%') && (name[1] == '{')) ||
		    (cf_pair_attr_quote(cp) == T_BACK_QUOTED_STRING)) {
			return compile_tmpl(parent, unlang_ctx, cp);
		}

		compile = fr_table_value_by_str(unlang_pair_keywords, name, NULL);
		if (compile) return compile(parent, unlang_ctx, ci);

		/*
		 *	Forbid section keywords as pair names, e.g. bare "update"
		 */
		if (fr_table_value_by_str(unlang_section_keywords, name, NULL) != NULL) {
			cf_log_err(ci, "Syntax error after keyword '%s' - expected '{'", name);
			return NULL;
		}

		goto check_for_module;
	}

	cf_log_err(ci, "Internal sanity check failed in compile_item()");
	return NULL;	/* who knows what it is... */

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
	 *	"instantiate" section.  In that case, the name will be
	 *	the first of the sub-section of "instantiate".
	 *
	 *	We try these in sequence, from the bottom up.  This is
	 *	so that things in "instantiate" and "policy" can
	 *	over-ride calls to real modules.
	 */


	/*
	 *	Try:
	 *
	 *	instantiate { ... name { ...} ... }
	 *	policy { ... name { .. } .. }
	 *	policy { ... name.method { .. } .. }
	 *
	 *	The only difference between things in "instantiate"
	 *	and "policy" is that "instantiate" will cause modules
	 *	to be instantiated in a particular order.
	 */
	p = strrchr(name, '.');
	if (!p) {
		subcs = virtual_module_find_cs(ci, &component, name, name, NULL, &policy);
	} else {
		char buffer[256];

		strlcpy(buffer, name, sizeof(buffer));
		buffer[p - name] = '\0';

		subcs = virtual_module_find_cs(ci, &component, name,
					       buffer, buffer + (p - name) + 1, &policy);
	}

	/*
	 *	We've found the thing which defines this "function".
	 *	It MUST be a sub-section.
	 *
	 *	i.e. it refers to a a subsection in "policy", or to a
	 *	named redundant / load-balance subsection defined in
	 *	"instantiate".
	 */
	if (subcs) return compile_function(parent, unlang_ctx, ci, subcs, component, policy);

	/*
	 *	Not a function.  It must be a real module.
	 */
	modules = cf_section_find(cf_root(ci), "modules", NULL);
	if (!modules) goto fail;

	realname = name;

	/*
	 *	Try to load the optional module.
	 */
	if (realname[0] == '-') realname++;

	/*
	 *	Set the child compilation context BEFORE parsing the
	 *	module name and method.  The lookup function will take
	 *	care of returning the appropriate component, name1,
	 *	name2, etc.
	 */
	UPDATE_CTX2;
	inst = module_by_name_and_method(&method, &unlang_ctx2.component,
					 &unlang_ctx2.section_name1, &unlang_ctx2.section_name2,
					 realname);
	if (inst) {
		return compile_module(parent, &unlang_ctx2, ci, inst, method, realname);
	}

	/*
	 *	We were asked to MAYBE load it and it
	 *	doesn't exist.  Return a soft error.
	 */
	if (realname != name) {
		cf_log_warn(ci, "Ignoring \"%s\" as the \"%s\" module is not enabled.", name, realname);
		return UNLANG_IGNORE;
	}

	/*
	 *	Can't de-reference it to anything.  Ugh.
	 */
fail:
	cf_log_err(ci, "Failed to find \"%s\" as a module or policy.", name);
	cf_log_err(ci, "Please verify that the configuration exists in mods-enabled/%s.", name);
	return NULL;
}

int unlang_compile(CONF_SECTION *cs, rlm_components_t component, tmpl_rules_t const *rules, void **instruction)
{
	unlang_t			*c;
	tmpl_rules_t			my_rules;
	char const			*name1, *name2;
	CONF_DATA const			*cd;
	static unlang_ext_t const 	group_ext = {
						.type = UNLANG_TYPE_GROUP,
						.len = sizeof(unlang_group_t),
						.type_name = "unlang_group_t",
					};
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

	c = compile_section(NULL,
			    &(unlang_compile_t){
				.component = component,
				.section_name1 = cf_section_name1(cs),
				.section_name2 = cf_section_name2(cs),
				.actions = &default_actions[component],
				.rules = rules
			    },
			    cs, &group_ext);
	if (!c) return -1;

	if (DEBUG_ENABLED4) unlang_dump(c, 2);

	/*
	 *	Associate the unlang with the configuration section,
	 *	and free the unlang code when the configuration
	 *	section is freed.
	 */
	cf_data_add(cs, c, NULL, true);
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

	if (fr_table_value_by_str(unlang_section_keywords, name, NULL) != NULL) return true;

	return (fr_table_value_by_str(unlang_pair_keywords, name, NULL) != NULL);
}
