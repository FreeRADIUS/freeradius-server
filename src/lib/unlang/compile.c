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
#include "unlang_priv.h"
#include "module_priv.h"

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
fr_table_num_sorted_t const mod_rcode_table[] = {
	{ "...",        RLM_MODULE_UNKNOWN      },
	{ "fail",       RLM_MODULE_FAIL		},
	{ "handled",    RLM_MODULE_HANDLED      },
	{ "invalid",    RLM_MODULE_INVALID      },
	{ "noop",       RLM_MODULE_NOOP		},
	{ "notfound",   RLM_MODULE_NOTFOUND     },
	{ "ok",	 	RLM_MODULE_OK		},
	{ "reject",     RLM_MODULE_REJECT       },
	{ "updated",    RLM_MODULE_UPDATED      },
	{ "userlock",   RLM_MODULE_USERLOCK     },
	{ "yield",      RLM_MODULE_YIELD	}
};
size_t mod_rcode_table_len = NUM_ELEMENTS(mod_rcode_table);


/* Some short names for debugging output */
char const * const comp2str[] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"pre-proxy",
	"post-proxy",
	"post-auth"
#ifdef WITH_COA
	,
	"recv-coa",
	"send-coa"
#endif
};

typedef int const unlang_action_table_t[UNLANG_GROUP_TYPE_MAX][RLM_MODULE_NUMCODES];

typedef struct {
	rlm_components_t	component;
	char const		*section_name1;
	char const		*section_name2;
	unlang_action_table_t	*actions;
	vp_tmpl_rules_t const	*rules;
} unlang_compile_t;

static char const modcall_spaces[] = "                                                                                                                                                                                                                                                                ";


#if 0
static char const *action2str(int action)
{
	static char buf[32];
	if(action==MOD_ACTION_RETURN)
		return "return";
	if(action==MOD_ACTION_REJECT)
		return "reject";
	snprintf(buf, sizeof buf, "%d", action);
	return buf;
}

/* If you suspect a bug in the parser, you'll want to use these dump
 * functions. dump_tree should reproduce a whole tree exactly as it was found
 * in radiusd.conf, but in long form (all actions explicitly defined) */
static void dump_mc(unlang_t *c, int indent)
{
	int i;

	if(c->type==UNLANG_TYPE_MODULE) {
		unlang_module_t *single = unlang_generic_to_module(c);
		DEBUG("%.*s%s {", indent, "\t\t\t\t\t\t\t\t\t\t\t",
			single->module_instance->name);
	} else if ((c->type > UNLANG_TYPE_MODULE) && (c->type <= UNLANG_TYPE_POLICY)) {
		unlang_group_t *g = unlang_generic_to_group(c);
		unlang_t *p;
		DEBUG("%.*s%s {", indent, "\t\t\t\t\t\t\t\t\t\t\t",
		      unlang_ops[c->type].name);
		for(p = g->children;p;p = p->next)
			dump_mc(p, indent+1);
	} /* else ignore it for now */

	for(i = 0; i<RLM_MODULE_NUMCODES; ++i) {
		DEBUG("%.*s%s = %s", indent+1, "\t\t\t\t\t\t\t\t\t\t\t",
		      fr_table_str_by_value(mod_rcode_table, i, "<invalid>"),
		      action2str(c->actions[i]));
	}

	DEBUG("%.*s}", indent, "\t\t\t\t\t\t\t\t\t\t\t");
}

static void dump_tree(unlang_t *c, char const *name)
{
	DEBUG("[%s]", name);
	dump_mc(c, 0);
}
#else
#define dump_tree(a, b)
#endif

/* These are the default actions. For each section , the group{} block
 * behaves like the code from the old module_*() function. redundant{}
 * are based on my guesses of what they will be used for. --Pac. */
static const int
defaultactions[MOD_COUNT][UNLANG_GROUP_TYPE_MAX][RLM_MODULE_NUMCODES] =
{
	/* authenticate */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			4,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			3			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* authorize */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* preacct */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			2,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			1,			/* noop     */
			3			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* accounting */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			2,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			1,			/* noop     */
			3			/* updated  */
		},
		/* redundant */
		{
			1,			/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			1,			/* invalid  */
			1,			/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		}
	},
	/* pre-proxy */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* post-proxy */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* post-auth */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	}
#ifdef WITH_COA
	,
	/* recv-coa */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* send-coa */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	}
#endif
};

#ifdef WITH_UNLANG
static bool pass2_fixup_xlat(CONF_ITEM const *ci, vp_tmpl_t **pvpt, bool convert,
			       fr_dict_attr_t const *da, vp_tmpl_rules_t const *rules)
{
	ssize_t slen;
	char *fmt;
	xlat_exp_t *head;
	vp_tmpl_t *vpt;

	vpt = *pvpt;

	rad_assert(tmpl_is_xlat(vpt));

	fmt = talloc_typed_strdup(vpt, vpt->name);
	slen = xlat_tokenize(vpt, &head, fmt, rules);

	if (slen < 0) {
		char *spaces, *text;

		fr_canonicalize_error(vpt, &spaces, &text, slen, vpt->name);

		cf_log_err(ci, "Failed parsing expansion string:");
		cf_log_err(ci, "%s", text);
		cf_log_err(ci, "%s^ %s", spaces, fr_strerror());

		talloc_free(spaces);
		talloc_free(text);
		return false;
	}

	/*
	 *	Convert %{Attribute-Name} to &Attribute-Name
	 */
	if (convert) {
		vp_tmpl_t *attr;

		attr = xlat_to_tmpl_attr(talloc_parent(vpt), head);
		if (attr) {
			/*
			 *	If it's a virtual attribute, leave it
			 *	alone.
			 */
			if (attr->tmpl_da->flags.virtual) {
				talloc_free(attr);
				return true;
			}

			/*
			 *	If the attribute is of incompatible
			 *	type, leave it alone.
			 */
			if (da && (da->type != attr->tmpl_da->type)) {
				talloc_free(attr);
				return true;
			}

			if (cf_item_is_pair(ci)) {
				CONF_PAIR *cp = cf_item_to_pair(ci);

				WARN("%s[%d]: Please change \"%%{%s}\" to &%s",
				       cf_filename(cp), cf_lineno(cp),
				       attr->name, attr->name);
			} else {
				CONF_SECTION *cs = cf_item_to_section(ci);

				WARN("%s[%d]: Please change \"%%{%s}\" to &%s",
				       cf_filename(cs), cf_lineno(cs),
				       attr->name, attr->name);
			}
			TALLOC_FREE(*pvpt);
			*pvpt = attr;
			return true;
		}
	}

	/*
	 *	Re-write it to be a pre-parsed XLAT structure.
	 */
	vpt->type = TMPL_TYPE_XLAT_STRUCT;
	vpt->tmpl_xlat = head;

	return true;
}


#ifdef HAVE_REGEX
static bool pass2_fixup_regex(CONF_ITEM const *ci, vp_tmpl_t *vpt, vp_tmpl_rules_t const *rules)
{
	ssize_t slen;
	regex_t *preg;

	rad_assert(tmpl_is_regex(vpt));

	/*
	 *	It's a dynamic expansion.  We can't expand the string,
	 *	but we can pre-parse it as an xlat struct.  In that
	 *	case, we convert it to a pre-compiled XLAT.
	 *
	 *	This is a little more complicated than it needs to be
	 *	because cond_eval_map() keys off of the src
	 *	template type, instead of the operators.  And, the
	 *	pass2_fixup_xlat() function expects to get passed an
	 *	XLAT instead of a REGEX.
	 */
	if (strchr(vpt->name, '%')) {
		vpt->type = TMPL_TYPE_XLAT;
		return pass2_fixup_xlat(ci, &vpt, false, NULL, rules);
	}

	slen = regex_compile(vpt, &preg, vpt->name, vpt->len, &vpt->tmpl_regex_flags, true, false);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(vpt, &spaces, &text, slen, vpt->name);

		cf_log_err(ci, "Invalid regular expression:");
		cf_log_err(ci, "%s", text);
		cf_log_err(ci, "%s^ %s", spaces, fr_strerror());

		talloc_free(spaces);
		talloc_free(text);

		return false;
	}

	vpt->type = TMPL_TYPE_REGEX_STRUCT;
	vpt->tmpl_preg = preg;

	return true;
}
#endif

static bool pass2_fixup_undefined(CONF_ITEM const *ci, vp_tmpl_t *vpt, vp_tmpl_rules_t const *rules)
{
	fr_dict_attr_t const *da;

	rad_assert(tmpl_is_attr_undefined(vpt));

	if (fr_dict_attr_by_qualified_name(&da, rules->dict_def, vpt->tmpl_unknown_name, true) != FR_DICT_ATTR_OK) {
		ssize_t slen;
		fr_dict_attr_t *unknown_da;

		/*
		 *	Can't find it under it's regular name.  Try an unknown attribute.
		 */
		slen = fr_dict_unknown_afrom_oid_str(vpt, &unknown_da, fr_dict_root(rules->dict_def),
						     vpt->tmpl_unknown_name);
		if ((slen <= 0) || (vpt->tmpl_unknown_name[slen] != '\0')) {
			cf_log_perr(ci, "Failed resolving undefined attribute");
			return false;
		}

#ifdef __clang_analyzer__
		/*
		 *	This can't happen, but clang analyzer
		 *	can't deal with the call depth.
		 */
		if (!unknown_da) return false;
#endif

		vpt->tmpl_da = vpt->tmpl_unknown = unknown_da;
		vpt->type = TMPL_TYPE_ATTR;
		return true;
	}

#ifdef __clang_analyzer__
	/*
	 *	This can't happen, but clang analyzer
	 *	can't deal with the call depth.
	 */
	if (!da) return false;
#endif

	vpt->tmpl_da = da;
	vpt->type = TMPL_TYPE_ATTR;
	return true;
}


static bool pass2_fixup_tmpl(CONF_ITEM const *ci, vp_tmpl_t **pvpt, vp_tmpl_rules_t const *rules, bool convert)
{
	vp_tmpl_t *vpt = *pvpt;

	if (tmpl_is_xlat(vpt)) {
		return pass2_fixup_xlat(ci, pvpt, convert, NULL, rules);
	}

	/*
	 *	The existence check might have been &Foo-Bar,
	 *	where Foo-Bar is defined by a module.
	 */
	if (tmpl_is_attr_undefined(vpt)) {
		return pass2_fixup_undefined(ci, vpt, rules);
	}

	/*
	 *	Convert virtual &Attr-Foo to "%{Attr-Foo}"
	 */
	if (tmpl_is_attr(vpt) && vpt->tmpl_da->flags.virtual) {
		vpt->tmpl_xlat = xlat_from_tmpl_attr(vpt, vpt);
		vpt->type = TMPL_TYPE_XLAT_STRUCT;
	}

	return true;
}

static bool pass2_fixup_map(fr_cond_t *c, vp_tmpl_rules_t const *rules)
{
	vp_tmpl_t		*vpt;
	vp_map_t		*map;

	map = c->data.map;	/* shorter */

	/*
	 *	Auth-Type := foo
	 *
	 *	Where "foo" is dynamically defined.
	 */
	if (c->pass2_fixup == PASS2_FIXUP_TYPE) {
		if (!fr_dict_enum_by_alias(map->lhs->tmpl_da, map->rhs->name, -1)) {
			cf_log_err(map->ci, "Invalid reference to non-existent %s %s { ... }",
				   map->lhs->tmpl_da->name,
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
		if (tmpl_is_attr_undefined(map->lhs)) {
			if (!pass2_fixup_undefined(map->ci, map->lhs, rules)) return false;
			if (!cast) cast = map->lhs->tmpl_da;
		}

		if (tmpl_is_attr_undefined(map->rhs)) {
			if (!pass2_fixup_undefined(map->ci, map->rhs, rules)) return false;
			if (!cast) cast = map->rhs->tmpl_da;
		}

		/*
		 *	Then fixup the other side if it was unparsed
		 */
		if (tmpl_is_unparsed(map->lhs)) {
			switch (cast->type) {
			case FR_TYPE_IPV4_ADDR:
				if (strchr(c->data.map->lhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal),
										   FR_CAST_BASE + FR_TYPE_IPV4_PREFIX);
				}
				break;

			case FR_TYPE_IPV6_ADDR:
				if (strchr(c->data.map->lhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal),
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
		} else if (tmpl_is_unparsed(map->rhs)) {
			switch (cast->type) {
			case FR_TYPE_IPV4_ADDR:
				if (strchr(c->data.map->rhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal),
										   FR_CAST_BASE + FR_TYPE_IPV4_PREFIX);
				}
				break;

			case FR_TYPE_IPV6_ADDR:
				if (strchr(c->data.map->rhs->name, '/') != NULL) {
					c->cast = cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal),
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
	rad_assert((c->pass2_fixup == PASS2_FIXUP_NONE) ||
		   (c->pass2_fixup == PASS2_PAIRCOMPARE));

	/*
	 *	Precompile xlat's
	 */
	if (tmpl_is_xlat(map->lhs)) {
		/*
		 *	Compile the LHS to an attribute reference only
		 *	if the RHS is a literal.
		 *
		 *	@todo v3.1: allow anything anywhere.
		 */
		if (!tmpl_is_unparsed(map->rhs)) {
			if (!pass2_fixup_xlat(map->ci, &map->lhs, false, NULL, rules)) {
				return false;
			}
		} else {
			if (!pass2_fixup_xlat(map->ci, &map->lhs, true, NULL, rules)) {
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
				    (map->lhs->tmpl_da->type == FR_TYPE_STRING) ||
				    (map->lhs->tmpl_da->type == FR_TYPE_OCTETS)) {

					if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) {
						cf_log_err(map->ci, "Failed to parse data type %s from string: %pV",
							   fr_table_str_by_value(fr_value_box_type_table, map->lhs->tmpl_da->type, "<UNKNOWN>"),
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

	if (tmpl_is_xlat(map->rhs)) {
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
			fr_dict_attr_t const *da = c->cast;

			if (!c->cast) da = map->lhs->tmpl_da;

			if (!pass2_fixup_xlat(map->ci, &map->rhs, true, da, rules)) {
				return false;
			}

		} else {
			if (!pass2_fixup_xlat(map->ci, &map->rhs, false, NULL, rules)) {
				return false;
			}
		}
	}

	/*
	 *	Convert bare refs to %{Foreach-Variable-N}
	 */
	if (tmpl_is_unparsed(map->lhs) &&
	    (strncmp(map->lhs->name, "Foreach-Variable-", 17) == 0)) {
		char *fmt;
		ssize_t slen;

		fmt = talloc_typed_asprintf(map->lhs, "%%{%s}", map->lhs->name);
		slen = tmpl_afrom_str(map, &vpt, fmt, talloc_array_length(fmt) - 1, T_DOUBLE_QUOTED_STRING,
				      &(vp_tmpl_rules_t){ .allow_unknown = true }, true);
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
	if (tmpl_is_regex(map->rhs)) {
		if (!pass2_fixup_regex(map->ci, map->rhs, rules)) {
			return false;
		}
	}
	rad_assert(!tmpl_is_regex(map->lhs));
#endif

	/*
	 *	Convert &Packet-Type to "%{Packet-Type}", because
	 *	these attributes don't really exist.  The code to
	 *	find an attribute reference doesn't work, but the
	 *	xlat code does.
	 */
	vpt = c->data.map->lhs;
	if (tmpl_is_attr(vpt) && vpt->tmpl_da->flags.virtual) {
		if (!c->cast) c->cast = vpt->tmpl_da;
		vpt->tmpl_xlat = xlat_from_tmpl_attr(vpt, vpt);
		vpt->type = TMPL_TYPE_XLAT_STRUCT;
	}

	/*
	 *	@todo v3.1: do the same thing for the RHS...
	 */

	/*
	 *	Only attributes can have a paircmp registered, and
	 *	they can only be with the current REQUEST, and only
	 *	with the request pairs.
	 */
	if (!tmpl_is_attr(map->lhs) ||
	    (map->lhs->tmpl_request != REQUEST_CURRENT) ||
	    (map->lhs->tmpl_list != PAIR_LIST_REQUEST)) {
		return true;
	}

	if (!paircmp_find(map->lhs->tmpl_da)) return true;

	if (tmpl_is_regex(map->rhs)) {
		cf_log_err(map->ci, "Cannot compare virtual attribute %s via a regex", map->lhs->name);
		return false;
	}

	if (c->cast) {
		cf_log_err(map->ci, "Cannot cast virtual attribute %s", map->lhs->name);
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

static bool pass2_cond_callback(fr_cond_t *c, void *uctx)
{
	unlang_compile_t	*unlang_ctx = uctx;

	switch (c->type) {
	/*
	 *	These don't get optimized.
	 */
	case COND_TYPE_TRUE:
	case COND_TYPE_FALSE:
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
		rad_assert(!tmpl_is_regex(c->data.vpt));
		return pass2_fixup_tmpl(c->ci, &c->data.vpt, unlang_ctx->rules, true);

	/*
	 *	Fixup the map
	 */
	case COND_TYPE_MAP:
		return pass2_fixup_map(c, unlang_ctx->rules);

	/*
	 *	Nothing else has pass2 fixups
	 */
	default:
		rad_assert(0);
		return false;
	}
}

static bool pass2_fixup_update_map(vp_map_t *map, vp_tmpl_rules_t const *rules)
{
	if (tmpl_is_xlat(map->lhs)) {
		rad_assert(map->lhs->tmpl_xlat == NULL);

		/*
		 *	FIXME: compile to attribute && handle
		 *	the conversion in map_to_vp().
		 */
		if (!pass2_fixup_xlat(map->ci, &map->lhs, false, NULL, rules)) {
			return false;
		}
	}

	/*
	 *	Deal with undefined attributes now.
	 */
	if (tmpl_is_attr_undefined(map->lhs)) {
		if (!pass2_fixup_undefined(map->ci, map->lhs, rules)) return false;
	}

	if (map->rhs) {
		if (tmpl_is_xlat(map->rhs)) {
			rad_assert(map->rhs->tmpl_xlat == NULL);

			/*
			 *	FIXME: compile to attribute && handle
			 *	the conversion in map_to_vp().
			 */
			if (!pass2_fixup_xlat(map->ci, &map->rhs, false, NULL, rules)) {
				return false;
			}
		}

		rad_assert(!tmpl_is_regex(map->rhs));

		if (tmpl_is_attr_undefined(map->rhs)) {
			if (!pass2_fixup_undefined(map->ci, map->rhs, rules)) return false;
		}
	}

	if (map->child) return pass2_fixup_update_map(map->child, rules);

	return true;
}

/*
 *	Compile the RHS of update sections to xlat_exp_t
 */
static bool pass2_fixup_update(unlang_group_t *g, vp_tmpl_rules_t const *rules)
{
	vp_map_t *map;

	for (map = g->map; map != NULL; map = map->next) {
		if (!pass2_fixup_update_map(map, rules)) return false;
	}

	return true;
}

/*
 *	Compile the RHS of map sections to xlat_exp_t
 */
static bool pass2_fixup_map_rhs(unlang_group_t *g, vp_tmpl_rules_t const *rules)
{
	/*
	 *	Compile the map
	 */
	if (!pass2_fixup_update(g, rules)) return false;

	/*
	 *	Map sections don't need a VPT.
	 */
	if (!g->vpt) return true;

	return pass2_fixup_tmpl(g->map->ci, &g->vpt, rules, false);
}
#endif

static void unlang_dump(unlang_t *mc, int depth)
{
	unlang_t *inst;
	unlang_group_t *g;
	vp_map_t *map;
	char buffer[1024];

	for (inst = mc; inst != NULL; inst = inst->next) {
		switch (inst->type) {
		default:
			break;

		case UNLANG_TYPE_MODULE:
		{
			unlang_module_t *single = unlang_generic_to_module(inst);

			DEBUG("%.*s%s", depth, modcall_spaces, single->module_instance->name);
		}
			break;

#ifdef WITH_UNLANG
		case UNLANG_TYPE_MAP:
			g = unlang_generic_to_group(inst); /* FIXMAP: print option 3, too */
			DEBUG("%.*s%s %s {", depth, modcall_spaces, unlang_ops[inst->type].name,
			      cf_section_name2(g->cs));
			goto print_map;

		case UNLANG_TYPE_UPDATE:
			g = unlang_generic_to_group(inst);
			DEBUG("%.*s%s {", depth, modcall_spaces, unlang_ops[inst->type].name);

		print_map:
			for (map = g->map; map != NULL; map = map->next) {
				map_snprint(buffer, sizeof(buffer), map);
				DEBUG("%.*s%s", depth + 1, modcall_spaces, buffer);
			}

			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case UNLANG_TYPE_ELSE:
			g = unlang_generic_to_group(inst);
			DEBUG("%.*s%s {", depth, modcall_spaces, unlang_ops[inst->type].name);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case UNLANG_TYPE_IF:
		case UNLANG_TYPE_ELSIF:
			g = unlang_generic_to_group(inst);
			cond_snprint(buffer, sizeof(buffer), g->cond);
			DEBUG("%.*s%s (%s) {", depth, modcall_spaces, unlang_ops[inst->type].name, buffer);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case UNLANG_TYPE_SWITCH:
		case UNLANG_TYPE_CASE:
			g = unlang_generic_to_group(inst);
			tmpl_snprint(buffer, sizeof(buffer), g->vpt);
			DEBUG("%.*s%s %s {", depth, modcall_spaces, unlang_ops[inst->type].name, buffer);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case UNLANG_TYPE_POLICY:
		case UNLANG_TYPE_FOREACH:
			g = unlang_generic_to_group(inst);
			DEBUG("%.*s%s %s {", depth, modcall_spaces, unlang_ops[inst->type].name, inst->name);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case UNLANG_TYPE_BREAK:
			DEBUG("%.*sbreak", depth, modcall_spaces);
			break;

#endif
		case UNLANG_TYPE_GROUP:
			g = unlang_generic_to_group(inst);
			DEBUG("%.*s%s {", depth, modcall_spaces, unlang_ops[inst->type].name);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case UNLANG_TYPE_LOAD_BALANCE:
		case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
			g = unlang_generic_to_group(inst);
			DEBUG("%.*s%s {", depth, modcall_spaces, unlang_ops[inst->type].name);
			unlang_dump(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;
		}
	}
}

#ifdef WITH_UNLANG
/** Validate and fixup a map that's part of an map section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return 0 if valid else -1.
 */
static int modcall_fixup_map(vp_map_t *map, UNUSED void *ctx)
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
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
		break;

	default:
		cf_log_err(map->ci, "Left side of map must be an attribute "
		           "or an xlat (that expands to an attribute), not a %s",
		           fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
		return -1;
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_UNPARSED:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
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
int unlang_fixup_update(vp_map_t *map, UNUSED void *ctx)
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
		if (map->lhs->tmpl_num == NUM_ANY) map->lhs->tmpl_num = NUM_ALL;
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
		if (map->rhs->tmpl_num == NUM_ANY) map->rhs->tmpl_num = NUM_ALL;
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
		if (!tmpl_is_unparsed(map->rhs) || (strcmp(map->rhs->name, "ANY") != 0)) {
			WARN("%s[%d] Wildcard deletion MUST use '!* ANY'",
			     cf_filename(cp), cf_lineno(cp));
		}

		TALLOC_FREE(map->rhs);

		map->rhs = tmpl_alloc(map, TMPL_TYPE_NULL, NULL, 0, T_INVALID);
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
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_UNPARSED:
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
	if (tmpl_is_attr(map->lhs) && tmpl_is_unparsed(map->rhs)) {
		/*
		 *	It's a literal string, just copy it.
		 *	Don't escape anything.
		 */
		if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) {
			cf_log_perr(map->ci, "Cannot convert RHS value (%s) to LHS attribute type (%s)",
				    fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_STRING, "<INVALID>"),
				    fr_table_str_by_value(fr_value_box_type_table, map->lhs->tmpl_da->type, "<INVALID>"));
			return -1;
		}

		/*
		 *	Fixup LHS da if it doesn't match the type
		 *	of the RHS.
		 */
		if (map->lhs->tmpl_da->type != map->rhs->tmpl_value_type) {
			fr_dict_attr_t const *da;

			da = fr_dict_attr_by_type(map->lhs->tmpl_da, map->rhs->tmpl_value_type);
			if (!da) {
				fr_strerror_printf("Cannot find %s variant of attribute \"%s\"",
						   fr_table_str_by_value(fr_value_box_type_table, map->rhs->tmpl_value_type,
						   "<INVALID>"), map->lhs->tmpl_da->name);
				return -1;
			}
			map->lhs->tmpl_da = da;
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
static int unlang_fixup_filter(vp_map_t *map, UNUSED void *ctx)
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
	if (map->lhs->tmpl_num == NUM_ANY) map->lhs->tmpl_num = NUM_ALL;

	/*
	 *	Fixup RHS attribute references to change NUM_ANY to NUM_ALL.
	 */
	if ((map->rhs->type == TMPL_TYPE_ATTR) &&
	    (map->rhs->tmpl_num == NUM_ANY)) {
		map->rhs->tmpl_num = NUM_ALL;
	}

	/*
	 *	Values used by unary operators should be literal ANY
	 *
	 *	We then free the template and alloc a NULL one instead.
	 */
	if (map->op == T_OP_CMP_FALSE) {
		if (!tmpl_is_unparsed(map->rhs) || (strcmp(map->rhs->name, "ANY") != 0)) {
			WARN("%s[%d] Wildcard deletion MUST use '!* ANY'",
			     cf_filename(cp), cf_lineno(cp));
		}

		TALLOC_FREE(map->rhs);

		map->rhs = tmpl_alloc(map, TMPL_TYPE_NULL, NULL, 0, T_INVALID);
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
	if (tmpl_is_attr(map->lhs) && tmpl_is_unparsed(map->rhs)) {
		/*
		 *	It's a literal string, just copy it.
		 *	Don't escape anything.
		 */
		if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) {
			cf_log_perr(map->ci, "Cannot convert RHS value (%s) to LHS attribute type (%s)",
				    fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_STRING, "<INVALID>"),
				    fr_table_str_by_value(fr_value_box_type_table, map->lhs->tmpl_da->type, "<INVALID>"));
			return -1;
		}

		/*
		 *	Fixup LHS da if it doesn't match the type
		 *	of the RHS.
		 */
		if (map->lhs->tmpl_da->type != map->rhs->tmpl_value_type) {
			fr_dict_attr_t const *da;

			da = fr_dict_attr_by_type(map->lhs->tmpl_da, map->rhs->tmpl_value_type);
			if (!da) {
				fr_strerror_printf("Cannot find %s variant of attribute \"%s\"",
						   fr_table_str_by_value(fr_value_box_type_table, map->rhs->tmpl_value_type,
						   "<INVALID>"), map->lhs->tmpl_da->name);
				return -1;
			}
			map->lhs->tmpl_da = da;
		}
	} /* else we can't precompile the data */

	return 0;
}


static unlang_group_t *group_allocate(unlang_t *parent, CONF_SECTION *cs,
				      unlang_group_type_t group_type, unlang_type_t mod_type)
{
	unlang_group_t *g;
	unlang_t *c;
	TALLOC_CTX *ctx;

	ctx = parent;
	if (!ctx) ctx = cs;

	g = talloc_zero(ctx, unlang_group_t);
	if (!g) return NULL;

	g->group_type = group_type;
	g->children = NULL;
	g->cs = cs;

	c = unlang_group_to_generic(g);
	c->parent = parent;
	c->type = mod_type;
	c->next = NULL;
	memset(c->actions, 0, sizeof(c->actions));

	return g;
}


static unlang_t *compile_action_defaults(unlang_t *c, unlang_compile_t *unlang_ctx, unlang_group_type_t parentgroup_type)
{
	int i;

	/*
	 *	Set the default actions, if they haven't already been
	 *	set.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		if (!c->actions[i]) {
			c->actions[i] = unlang_ctx->actions[0][parentgroup_type][i];
		}
	}

	/*
	 *	FIXME: If there are no children, return NULL?
	 */
	return c;
}

static int compile_map_name(unlang_group_t *g)
{
	/*
	 *	If the section has arguments beyond
	 *	name1 and name2, they form input
	 *	arguments into the map.
	 */
	if (cf_section_argv(g->cs, 0)) {
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

		quoted_len = fr_snprint_len(g->vpt->name, g->vpt->len, quote);
		quoted_str = talloc_array(g, char, quoted_len);
		fr_snprint(quoted_str, quoted_len, g->vpt->name, g->vpt->len, quote);

		g->self.name = talloc_typed_asprintf(g, "map %s %s", cf_section_name2(g->cs), quoted_str);
		g->self.debug_name = g->self.name;
		talloc_free(quoted_str);

		return 0;
	}

	g->self.name = talloc_typed_asprintf(g, "map %s", cf_section_name2(g->cs));
	g->self.debug_name = g->self.name;

	return 0;
}

static unlang_t *compile_map(unlang_t *parent, unlang_compile_t *unlang_ctx,
			     CONF_SECTION *cs, UNUSED unlang_group_type_t group_type,
			     unlang_group_type_t parentgroup_type, UNUSED unlang_type_t mod_type)
{
	int			rcode;
	unlang_group_t		*g;
	unlang_t		*c;
	CONF_SECTION		*modules;
	ssize_t			slen;
	char const		*tmpl_str;

	vp_map_t		*head;
	vp_tmpl_t		*vpt = NULL;

	map_proc_t		*proc;
	map_proc_inst_t		*proc_inst;

	char const		*name2 = cf_section_name2(cs);

	vp_tmpl_rules_t		parse_rules;

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

	/*
	 *	If there's a third string, it's the map src.
	 *
	 *	Convert it into a template.
	 */
	tmpl_str = cf_section_argv(cs, 0); /* AFTER name1, name2 */
	if (tmpl_str) {
		FR_TOKEN type;

		type = cf_section_argv_quote(cs, 0);

		/*
		 *	Try to parse the template.
		 */
		slen = tmpl_afrom_str(cs, &vpt, tmpl_str, talloc_array_length(tmpl_str) - 1, type,
				      &parse_rules, true);
		if (slen < 0) {
			cf_log_perr(cs, "Failed parsing map");
			return NULL;
		}

		/*
		 *	Limit the allowed template types.
		 */
		switch (vpt->type) {
		case TMPL_TYPE_UNPARSED:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_ATTR_UNDEFINED:
		case TMPL_TYPE_EXEC:
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
	rcode = map_afrom_cs(cs, &head, cs, &parse_rules, &parse_rules, modcall_fixup_map, NULL, 256);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err(cs, "'map' sections cannot be empty");
		return NULL;
	}

	g = group_allocate(parent, cs, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_MAP);
	if (!g) return NULL;

	/*
	 *	Call the map's instantiation function to validate
	 *	the map and perform any caching required.
	 */
	proc_inst = map_proc_instantiate(g, proc, cs, vpt, head);
	if (!proc_inst) {
		talloc_free(g);
		cf_log_err(cs, "Failed instantiating map function '%s'", name2);
		return NULL;
	}
	c = unlang_group_to_generic(g);

	(void) compile_action_defaults(c, unlang_ctx, parentgroup_type);

	g->map = talloc_steal(g, head);
	if (vpt) g->vpt = talloc_steal(g, vpt);
	g->proc_inst = proc_inst;

	compile_map_name(g);

	/*
	 *	Cache the module in the unlang_group_t struct.
	 *
	 *	Ensure that the module has a "map" entry in its module
	 *	header?  Or ensure that the map is registered in the
	 *	"boostrap" phase, so that it's always available here.
	 */
	if (!pass2_fixup_map_rhs(g, unlang_ctx->rules)) {
		talloc_free(g);
		return NULL;
	}

	return c;

}

static unlang_t *compile_update(unlang_t *parent, unlang_compile_t *unlang_ctx,
				CONF_SECTION *cs, unlang_group_type_t group_type,
				UNUSED unlang_group_type_t parentgroup_type, UNUSED unlang_type_t mod_type)
{
	int			rcode;
	unlang_group_t		*g;
	unlang_t		*c;
	char const		*name2 = cf_section_name2(cs);

	vp_map_t		*head;

	vp_tmpl_rules_t		parse_rules;

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = map_afrom_cs(cs, &head, cs, &parse_rules, &parse_rules, unlang_fixup_update, NULL, 128);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err(cs, "'update' sections cannot be empty");
		return NULL;
	}

	g = group_allocate(parent, cs, group_type, UNLANG_TYPE_UPDATE);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	if (name2) {
		c->name = name2;
		c->debug_name = talloc_typed_asprintf(c, "update %s", name2);
	} else {
		c->name = unlang_ops[c->type].name;
		c->debug_name = unlang_ops[c->type].name;
	}

	(void) compile_action_defaults(c, unlang_ctx, UNLANG_GROUP_TYPE_SIMPLE);

	g->map = talloc_steal(g, head);

#ifdef WITH_CONF_WRITE
//	cf_data_add(cs, CF_DATA_TYPE_UNLANG, "update", g->map, NULL); /* for output normalization */
#endif

	if (!pass2_fixup_update(g, unlang_ctx->rules)) {
		talloc_free(g);
		return NULL;
	}

	return c;
}

static unlang_t *compile_filter(unlang_t *parent, unlang_compile_t *unlang_ctx,
				CONF_SECTION *cs, unlang_group_type_t group_type,
				UNUSED unlang_group_type_t parentgroup_type, UNUSED unlang_type_t mod_type)
{
	int			rcode;
	unlang_group_t		*g;
	unlang_t		*c;
	char const		*name2 = cf_section_name2(cs);

	vp_map_t		*head;

	vp_tmpl_rules_t		parse_rules;

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = map_afrom_cs(cs, &head, cs, &parse_rules, &parse_rules, unlang_fixup_filter, NULL, 128);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err(cs, "'update' sections cannot be empty");
		return NULL;
	}

	g = group_allocate(parent, cs, group_type, UNLANG_TYPE_FILTER);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	if (name2) {
		c->name = name2;
		c->debug_name = talloc_typed_asprintf(c, "filter %s", name2);
	} else {
		c->name = unlang_ops[c->type].name;
		c->debug_name = unlang_ops[c->type].name;
	}

	(void) compile_action_defaults(c, unlang_ctx, UNLANG_GROUP_TYPE_SIMPLE);

	g->map = talloc_steal(g, head);

#ifdef WITH_CONF_WRITE
//	cf_data_add(cs, CF_DATA_TYPE_FILTER, "filter", g->map, NULL); /* for output normalization */
#endif

	/*
	 *	The fixups here occur whether or not it's UPDATE or FILTER
	 */
	if (!pass2_fixup_update(g, unlang_ctx->rules)) {
		talloc_free(g);
		return NULL;
	}

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

static unlang_t *compile_empty(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				  unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type,
				  fr_cond_type_t cond_type)
{
	unlang_group_t *g;
	unlang_t *c;

	g = group_allocate(parent, cs, group_type, mod_type);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);
	if (!cs) {
		c->name = unlang_ops[c->type].name;
		c->debug_name = c->name;

	} else {
		char const *name2;

		name2 = cf_section_name2(cs);
		if (!name2) {
			c->name = cf_section_name1(cs);
			c->debug_name = c->name;
		} else {
			c->name = name2;
			c->debug_name = talloc_typed_asprintf(c, "%s %s", unlang_ops[c->type].name, name2);
		}
	}

	if (cond_type != COND_TYPE_INVALID) {
		g->cond = talloc_zero(g, fr_cond_t);
		g->cond->type = cond_type;
	}

	return compile_action_defaults(c, unlang_ctx, parentgroup_type);
}


static unlang_t *compile_item(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM *ci,
			      unlang_group_type_t parent_group_type, char const **modname);


/* unlang_group_ts are grown by adding a unlang_t to the end */
static bool add_child(unlang_group_t *g, unlang_t *c, CONF_ITEM *ci)
{
	if (!c) return true;

	/*
	 *	Check if the section is closed.  But the compiler
	 *	closes the section BEFORE adding the child, so we have
	 *	to double-check for the child here.
	 */
	if (g->self.closed && (g->self.closed != ci)) {
		cf_log_err(ci, "Cannot add more items to section due to previous 'break' or 'return' at %s:%d",
			cf_filename(g->self.closed), cf_lineno(g->self.closed));
		return false;
	}

	(void) talloc_steal(g, c);

	if (!g->children) {
		g->children = g->tail = c;
	} else {
		rad_assert(g->tail->next == NULL);
		g->tail->next = c;
		g->tail = c;
	}

	g->num_children++;
	c->parent = unlang_group_to_generic(g);

	return true;
}

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


static unlang_t *compile_children(unlang_group_t *g, unlang_t *parent, unlang_compile_t *unlang_ctx,
				  unlang_group_type_t group_type, unlang_group_type_t parentgroup_type)
{
	CONF_ITEM *ci = NULL;
	unlang_t *c;

	c = unlang_group_to_generic(g);

	/*
	 *	Loop over the children of this group.
	 */
	while ((ci = cf_item_next(g->cs, ci))) {
		if (cf_item_is_data(ci)) continue;

		/*
		 *	Sections are references to other groups, or
		 *	to modules with updated return codes.
		 */
		if (cf_item_is_section(ci)) {
			char const *name1 = NULL;
			unlang_t *single;
			CONF_SECTION *subcs = cf_item_to_section(ci);

			/*
			 *	Skip precompiled blocks.
			 */
			if (cf_data_find(subcs, unlang_group_t, NULL)) continue;

			/*
			 *	"actions" apply to the current group.
			 *	It's not a subgroup.
			 */
			name1 = cf_section_name1(subcs);
			if (strcmp(name1, "actions") == 0) {
				if (cf_item_next(g->cs, ci) != NULL) {
					cf_log_err(subcs, "'actions' MUST be the last thing in a subsection");
					talloc_free(c);
					return NULL;
				}

				if (!compile_action_subsection(c, g->cs, subcs)) {
					talloc_free(c);
					return NULL;
				}

				continue;
			}

			/*
			 *	Otherwise it's a real keyword.
			 */
			single = compile_item(c, unlang_ctx, ci, group_type, &name1);
			if (!single) {
				cf_log_err(ci, "Failed to parse \"%s\" subsection", cf_section_name1(subcs));
				talloc_free(c);
				return NULL;
			}
			if (!add_child(g, single, ci)) {
				talloc_free(c);
				return NULL;
			}

		} else if (cf_item_is_pair(ci)) {
			char const *attr, *value;
			CONF_PAIR *cp = cf_item_to_pair(ci);

			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);

			/*
			 *	A CONF_PAIR is either a module
			 *	instance with no actions
			 *	specified ...
			 */
			if (!value) {
				unlang_t *single;
				char const *name = NULL;

				single = compile_item(c, unlang_ctx, ci, group_type, &name);
				if (!single) {
					/*
					 *	Skip optional modules, which start with '-'
					 */
					name = cf_pair_attr(cp);
					if (name[0] == '-') {
						cf_log_warn(cp, "Ignoring \"%s\" as it is commented out",
							    name + 1);
						continue;
					}

					cf_log_err(ci,
						   "Invalid keyword \"%s\".",
						   attr);
					talloc_free(c);
					return NULL;
				}
				if (!add_child(g, single, ci)) {
					talloc_free(c);
					return NULL;
				}

			} else if (!parent || (parent->type != UNLANG_TYPE_MODULE)) {
				cf_log_err(cp, "Invalid location for action over-ride");
				talloc_free(c);
				return NULL;

			} else {
				if (!compile_action_pair(c, cp)) {
					talloc_free(c);
					return NULL;
				}
			}
		} else {
			rad_assert(0);
		}
	}

	return compile_action_defaults(c, unlang_ctx, parentgroup_type);
}


/*
 *	Generic "compile a section with more unlang inside of it".
 */
static unlang_t *compile_group(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
			       unlang_group_type_t group_type,
			       unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	unlang_group_t *g;
	unlang_t *c;

	g = group_allocate(parent, cs, group_type, mod_type);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	/*
	 *	Remember the name for printing, etc.
	 *
	 *	FIXME: We may also want to put the names into a
	 *	rbtree, so that groups can reference each other...
	 */
	c->name = talloc_typed_strdup(c, unlang_ops[c->type].name);
	c->debug_name = talloc_typed_strdup(c, c->name);

	return compile_children(g, parent, unlang_ctx, group_type, parentgroup_type);
}

static unlang_t *compile_switch(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				unlang_group_type_t group_type,
				unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	CONF_ITEM *ci;
	FR_TOKEN type;
	char const *name2;
	bool had_seen_default = false;
	unlang_t *c;
	unlang_group_t *g;
	ssize_t slen;

	vp_tmpl_rules_t	parse_rules;

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

	g = group_allocate(parent, cs, group_type, mod_type);
	if (!g) return NULL;

	/*
	 *	Create the template.  All attributes and xlats are
	 *	defined by now.
	 */
	type = cf_section_name2_quote(cs);
	slen = tmpl_afrom_str(g, &g->vpt, name2, strlen(name2), type, &parse_rules, true);
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

	/*
	 *	Walk through the children of the switch section,
	 *	ensuring that they're all 'case' statements
	 */
	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		CONF_SECTION *subcs;
		char const *name1;

		if (!cf_item_is_section(ci)) {
			if (!cf_item_is_pair(ci)) continue;

			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(g);
			return NULL;
		}

		subcs = cf_item_to_section(ci);	/* can't return NULL */
		name1 = cf_section_name1(subcs);

		if (strcmp(name1, "case") != 0) {
			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(g);
			return NULL;
		}

		name2 = cf_section_name2(subcs);
		if (!name2) {
			if (!had_seen_default) {
				had_seen_default = true;
				continue;
			}

			cf_log_err(ci, "Cannot have two 'default' case statements");
			talloc_free(g);
			return NULL;
		}
	}

	c = unlang_group_to_generic(g);
	c->name = unlang_ops[c->type].name;
	c->debug_name = talloc_typed_asprintf(c, "%s %s", unlang_ops[c->type].name, cf_section_name2(cs));

	/*
	 *	Fixup the template before compiling the children.
	 *	This is so that compile_case() can do attribute type
	 *	checks / casts against us.
	 */
	if (!pass2_fixup_tmpl(cf_section_to_item(g->cs), &g->vpt, unlang_ctx->rules, true)) {
		talloc_free(g);
		return NULL;
	}

	return compile_children(g, parent, unlang_ctx, group_type, parentgroup_type);
}

static unlang_t *compile_case(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				 unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	int			i;
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*g;
	vp_tmpl_t		*vpt = NULL;
	vp_tmpl_rules_t		parse_rules;

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
		ssize_t slen;
		FR_TOKEN type;
		unlang_group_t *f;

		type = cf_section_name2_quote(cs);

		slen = tmpl_afrom_str(cs, &vpt, name2, strlen(name2), type, &parse_rules, true);
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

		if (tmpl_is_attr_undefined(vpt)) {
			if (!pass2_fixup_undefined(cf_section_to_item(cs), vpt, unlang_ctx->rules)) {
				talloc_free(vpt);
				return NULL;
			}
		}

		f = unlang_generic_to_group(parent);
		rad_assert(f->vpt != NULL);

		/*
		 *	Do type-specific checks on the case statement
		 */

		/*
		 *	We're switching over an
		 *	attribute.  Check that the
		 *	values match.
		 */
		if (tmpl_is_unparsed(vpt) &&
		    tmpl_is_attr(f->vpt)) {
			rad_assert(f->vpt->tmpl_da != NULL);

			if (tmpl_cast_in_place(vpt, f->vpt->tmpl_da->type, f->vpt->tmpl_da) < 0) {
				cf_log_err(cs, "Invalid argument for case statement: %s",
					      fr_strerror());
				talloc_free(vpt);
				return NULL;
			}
		}

		/*
		 *	Compile and sanity check xlat
		 *	expansions.
		 */
		if (tmpl_is_xlat(vpt)) {
			fr_dict_attr_t const *da = NULL;

			if (tmpl_is_attr(f->vpt)) da = f->vpt->tmpl_da;

			/*
			 *	Don't expand xlat's into an
			 *	attribute of a different type.
			 */
			if (!pass2_fixup_xlat(cf_section_to_item(cs), &vpt, true, da, unlang_ctx->rules)) {
				talloc_free(vpt);
				return NULL;
			}
		}
	} /* else it's a default 'case' statement */

	c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
	if (!c) {
		talloc_free(vpt);
		return NULL;
	}

	/*
	 *	The interpretor expects this to be NULL for the
	 *	default case.  compile_group sets it to name2,
	 *	unless name2 is NULL, in which case it sets it to name1.
	 */
	c->name = name2;
	if (!name2) {
		c->debug_name = unlang_ops[c->type].name;
	} else {
		c->debug_name = talloc_typed_asprintf(c, "%s %s", unlang_ops[c->type].name, name2);
	}

	g = unlang_generic_to_group(c);
	g->vpt = talloc_steal(g, vpt);

	/*
	 *	Set all of it's codes to return, so that
	 *	when we pick a 'case' statement, we don't
	 *	fall through to processing the next one.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		c->actions[i] = MOD_ACTION_RETURN;
	}

	return c;
}

static unlang_t *compile_foreach(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				    unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	FR_TOKEN		type;
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*g;
	ssize_t			slen;
	vp_tmpl_t		*vpt;

	vp_tmpl_rules_t		parse_rules;

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
	slen = tmpl_afrom_str(cs, &vpt, name2, strlen(name2), type, &parse_rules, true);
	if ((slen < 0) && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
		char *spaces, *text;

		fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

		cf_log_err(cs, "Syntax error");
		cf_log_err(cs, "%s", name2);
		cf_log_err(cs, "%s^ %s", spaces, text);

		talloc_free(spaces);
		talloc_free(text);

		return NULL;
	}

	/*
	 *	If we don't have a negative return code, we must have a vpt
	 *	(mostly to quiet coverity).
	 */
	rad_assert(vpt);

	if (!tmpl_is_attr(vpt) && !tmpl_is_list(vpt)) {
		cf_log_err(cs, "MUST use attribute or list reference (not %s) in 'foreach'",
			   fr_table_str_by_value(tmpl_type_table, vpt->type, "???"));
		talloc_free(vpt);
		return NULL;
	}

	if ((vpt->tmpl_num != NUM_ALL) && (vpt->tmpl_num != NUM_ANY)) {
		cf_log_err(cs, "MUST NOT use instance selectors in 'foreach'");
		talloc_free(vpt);
		return NULL;
	}

	/*
	 *	Fix up the template to iterate over all instances of
	 *	the attribute. In a perfect consistent world, users would do
	 *	foreach &attr[*], but that's taking the consistency thing a bit far.
	 */
	vpt->tmpl_num = NUM_ALL;

	c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
	if (!c) {
		talloc_free(vpt);
		return NULL;
	}

	c->name = unlang_ops[c->type].name;
	c->debug_name = talloc_typed_asprintf(c, "%s %s", unlang_ops[c->type].name, name2);

	g = unlang_generic_to_group(c);
	g->vpt = vpt;

	return c;
}


static unlang_t *compile_break(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *foreach;
	unlang_t *c;

	for (foreach = parent; foreach != NULL; foreach = foreach->parent) {
		if (foreach->type == UNLANG_TYPE_FOREACH) break;
	}

	if (!foreach) {
		cf_log_err(ci, "'break' can only be used in a 'foreach' section");
		return NULL;
	}

	c = compile_empty(parent, unlang_ctx, NULL, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_GROUP_TYPE_SIMPLE,
			  UNLANG_TYPE_BREAK, COND_TYPE_INVALID);
	if (!c) return NULL;

	parent->closed = ci;
	return c;
}

static unlang_t *compile_detach(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *subrequest;

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

	return compile_empty(parent, unlang_ctx, NULL, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_GROUP_TYPE_SIMPLE,
			     UNLANG_TYPE_DETACH, COND_TYPE_INVALID);
}
#endif

static unlang_t *compile_xlat_inline(unlang_t *parent,
				     unlang_compile_t *unlang_ctx, CONF_PAIR const *cp)
{
	unlang_t *c;
	unlang_xlat_inline_t *mx;

	mx = talloc_zero(parent, unlang_xlat_inline_t);

	c = unlang_xlat_inline_to_generic(mx);
	c->parent = parent;
	c->next = NULL;
	c->name = "expand";
	c->debug_name = c->name;
	c->type = UNLANG_TYPE_XLAT_INLINE;

	(void) compile_action_defaults(c, unlang_ctx, UNLANG_GROUP_TYPE_SIMPLE);

	mx->xlat_name = talloc_typed_strdup(mx, cf_pair_attr(cp));
	if (mx->xlat_name[0] == '%') {
		ssize_t		slen;

		slen = xlat_tokenize(mx, &mx->exp, mx->xlat_name, unlang_ctx->rules);
		if (slen < 0) {
			cf_log_err(cp, "%s", fr_strerror());
			talloc_free(mx);
			return NULL;
		}
	} else {
		char *p;
		mx->exec = true;

		memmove(mx->xlat_name, mx->xlat_name + 1, strlen(mx->xlat_name)); /* including trailing NUL */
		p = strrchr(mx->xlat_name, '`');
		if (p) *p = '\0';
	}

	return c;
}

static unlang_t *compile_if(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
			       unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	unlang_t *c;
	unlang_group_t *g;
	fr_cond_t *cond;

	if (!cf_section_name2(cs)) {
		cf_log_err(cs, "'%s' without condition", unlang_ops[mod_type].name);
		return NULL;
	}

	cond = cf_data_value(cf_data_find(cs, fr_cond_t, NULL));
	rad_assert(cond != NULL);

	if (cond->type == COND_TYPE_FALSE) {
		cf_log_debug_prefix(cs, "Skipping contents of '%s' as it is always 'false'",
				    unlang_ops[mod_type].name);
		return compile_empty(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type, COND_TYPE_FALSE);
	}

	/*
	 *	The condition may refer to attributes, xlats, or
	 *	Auth-Types which didn't exist when it was first
	 *	parsed.  Now that they are all defined, we need to fix
	 *	them up.
	 */
	if (!fr_cond_walk(cond, pass2_cond_callback, unlang_ctx)) return NULL;

	c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
	if (!c) return NULL;

	c->name = unlang_ops[c->type].name;
	c->debug_name = talloc_typed_asprintf(c, "%s %s", unlang_ops[c->type].name, cf_section_name2(cs));

	g = unlang_generic_to_group(c);
	g->cond = cond;

	return c;
}

static int previous_if(CONF_SECTION *cs, unlang_t *parent, unlang_type_t mod_type)
{
	unlang_group_t *p, *f;

	p = unlang_generic_to_group(parent);
	if (!p->tail) goto else_fail;

	f = unlang_generic_to_group(p->tail);
	if ((f->self.type != UNLANG_TYPE_IF) && (f->self.type != UNLANG_TYPE_ELSIF)) {
	else_fail:
		cf_log_err(cs, "Invalid location for '%s'.  There is no preceding 'if' or 'elsif' statement",
			      unlang_ops[mod_type].name);
		return -1;
	}

	if (f->cond->type == COND_TYPE_TRUE) {
		cf_log_debug_prefix(cs, "Skipping contents of '%s' as previous '%s' is always 'true'",
				    unlang_ops[mod_type].name,
				    unlang_ops[f->self.type].name);
		return 0;
	}

	return 1;
}

static unlang_t *compile_elsif(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				  unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	int rcode;

	/*
	 *	This is always a syntax error.
	 */
	if (!cf_section_name2(cs)) {
		cf_log_err(cs, "'%s' without condition", unlang_ops[mod_type].name);
		return NULL;
	}

	rcode = previous_if(cs, parent, mod_type);
	if (rcode < 0) return NULL;

	if (rcode == 0) return compile_empty(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type, COND_TYPE_TRUE);

	return compile_if(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
}

static unlang_t *compile_else(unlang_t *parent,
			       unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
			       unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	int rcode;
	unlang_t *c;

	if (cf_section_name2(cs)) {
		cf_log_err(cs, "'%s' cannot have a condition", unlang_ops[mod_type].name);
		return NULL;
	}

	rcode = previous_if(cs, parent, mod_type);
	if (rcode < 0) return NULL;

	if (rcode == 0) {
		c = compile_empty(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type, COND_TYPE_TRUE);
	} else {
		c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
	}

	if (!c) return c;

	c->name = unlang_ops[c->type].name;
	c->debug_name = c->name;

	return c;
}

/*
 *	redundant, etc. can refer to modules or groups, but not much else.
 */
static int all_children_are_modules(CONF_SECTION *cs, char const *name)
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
			 *	@todo - put this into a list somewhere
			 */
			if ((strcmp(name1, "if") == 0) ||
			    (strcmp(name1, "else") == 0) ||
			    (strcmp(name1, "elsif") == 0) ||
			    (strcmp(name1, "update") == 0) ||
			    (strcmp(name1, "filter") == 0) ||
			    (strcmp(name1, "switch") == 0) ||
			    (strcmp(name1, "case") == 0)) {
				cf_log_err(ci, "%s sections cannot contain a \"%s\" statement",
				       name, name1);
				return 0;
			}
			continue;
		}

		if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_item_to_pair(ci);
			if (cf_pair_value(cp) != NULL) {
				cf_log_err(ci,
					   "Entry with no value is invalid");
				return 0;
			}
		}
	}

	return 1;
}


static unlang_t *compile_redundant(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				      unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	char const *name2;
	unlang_t *c;

	/*
	 *	No children?  Die!
	 */
	if (!cf_item_next(cs, NULL)) {
		cf_log_err(cs, "%s sections cannot be empty", unlang_ops[mod_type].name);
		return NULL;
	}

	if (!all_children_are_modules(cs, cf_section_name1(cs))) {
		return NULL;
	}

	c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
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
		cf_log_err(cs, "%s sections cannot have a name", unlang_ops[mod_type].name);
		return NULL;
	}

	c->debug_name = c->name;
	c->name = unlang_ops[c->type].name;

	return c;
}

static unlang_t *compile_load_balance(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				      unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	char const	*name2;
	unlang_t	*c;
	unlang_group_t	*g;

	vp_tmpl_rules_t	parse_rules;

	/*
	 *	We allow unknown attributes here.
	 */
	parse_rules = *(unlang_ctx->rules);
	parse_rules.allow_unknown = true;

	/*
	 *	No children?  Die!
	 */
	if (!cf_item_next(cs, NULL)) {
		cf_log_err(cs, "%s sections cannot be empty", unlang_ops[mod_type].name);
		return NULL;
	}

	if (!all_children_are_modules(cs, cf_section_name1(cs))) {
		return NULL;
	}

	c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
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
		FR_TOKEN type;
		ssize_t slen;

		/*
		 *	Create the template.  All attributes and xlats are
		 *	defined by now.
		 */
		type = cf_section_name2_quote(cs);
		slen = tmpl_afrom_str(g, &g->vpt, name2, strlen(name2), type, &parse_rules, true);
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

		c->debug_name = talloc_typed_asprintf(c, "%s %s", unlang_ops[c->type].name, name2);
		rad_assert(g->vpt != NULL);

		/*
		 *	Fixup the templates
		 */
		if (!pass2_fixup_tmpl(cf_section_to_item(g->cs), &g->vpt, unlang_ctx->rules, true)) {
			talloc_free(g);
			return NULL;
		}

		switch (g->vpt->type) {
		default:
			cf_log_err(cs, "Invalid type in '%s': data will not result in a load-balance key", name2);
			talloc_free(g);
			return NULL;

			/*
			 *	Allow only these ones.
			 */
		case TMPL_TYPE_XLAT_STRUCT:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_EXEC:
			break;
		}

	} else {
		c->debug_name = c->name;
	}

	c->name = unlang_ops[c->type].name;

	return c;
}

static unlang_t *compile_parallel(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				      unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	unlang_t *c;
	char const *name2;
	unlang_group_t *g;
	bool clone = true;
	bool detach = false;

	/*
	 *	No children?  Die!
	 */
	if (!cf_item_next(cs, NULL)) {
		cf_log_err(cs, "%s sections cannot be empty", unlang_ops[mod_type].name);
		return NULL;
	}

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

	c = compile_group(parent, unlang_ctx, cs, group_type, parentgroup_type, mod_type);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);
	g->clone = clone;
	g->detach = detach;

	c->name = c->debug_name = unlang_ops[c->type].name;

	return c;
}


static unlang_t *compile_subrequest(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
				    unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type)
{
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*g;
	unlang_compile_t	unlang_ctx2;
	vp_tmpl_rules_t		parse_rules;
	fr_dict_t const		*dict;
	fr_dict_attr_t const	*da;
	fr_dict_enum_t const	*type_enum;
	char const		*namespace, *packet_name, *component_name, *p;
	char			buffer[64];
	char			buffer2[64];
	char			buffer3[64];

	g = group_allocate(parent, cs, group_type, mod_type);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);
	c->name = unlang_ops[c->type].name;
	c->debug_name = c->name;

	/*
	 *	subrequests can specify the dictionary if they want to.
	 */
	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs, "Invalid syntax: expected <namespace>.<packet>");
		return NULL;
	}

	p = strchr(name2, '.');
	if (!p) {
		dict = unlang_ctx->rules->dict_def;
		namespace = fr_dict_root(dict)->name;
		packet_name = name2;

	} else {
		if ((size_t) (p - name2) >= sizeof(buffer)) {
			cf_log_err(cs, "Unknown namespace '%.*s'", (int) (p - name2), name2);
			return NULL;
		}

		memcpy(buffer, name2, p - name2);
		buffer[p - name2] = '\0';

		dict = fr_dict_by_protocol_name(buffer);
		if (!dict) {
			cf_log_err(cs, "Unknown namespace '%.*s'", (int) (p - name2), name2);
			return NULL;
		}

		namespace = buffer;
		p++;
		packet_name = p;	// need to quiet a stupid compiler
	}

	da = fr_dict_attr_by_name(dict, "Packet-Type");
	if (!da) {
		cf_log_err(cs, "No such attribute 'Packet-Type' in namespace '%s'", namespace);
		return NULL;
	}

	/*
	 *	Get the packet name.
	 */
	if (p) {
		packet_name = p;
		p = strchr(packet_name, '.');
		if (p) {
			if ((size_t) (p - packet_name) >= sizeof(buffer2)) {
				cf_log_err(cs, "No such value '%.*s' for attribute 'Packet-Type' in namespace '%s'",
					   (int) (p - packet_name), packet_name, namespace);
				return NULL;
			}

			memcpy(buffer2, packet_name, p - packet_name);
			buffer[p - packet_name] = '\0';
			packet_name = buffer2;
			p++;
		}
	}

	type_enum = fr_dict_enum_by_alias(da, packet_name, -1);
	if (!type_enum) {
		cf_log_err(cs, "No such value '%s' for attribute 'Packet-Type' in namespace '%s'",
			   packet_name, namespace);
		return NULL;
	}

	unlang_ctx2.component = unlang_ctx->component;

	/*
	 *	Figure out the component name we're supposed to call.
	 *	Which isn't necessarily the same as the one from the
	 *	parent request.
	 */
	if (p) {
		component_name = p;
		p = strchr(component_name, '.');
		if (p) {
			rlm_components_t i;

			if ((size_t) (p - component_name) >= sizeof(buffer3)) {
			unknown_component:
				cf_log_err(cs, "No such component '%.*s",
					   (int) (p - component_name), component_name);
				return NULL;
			}

			memcpy(buffer3, component_name, p - component_name);
			buffer[p - component_name] = '\0';
			component_name = buffer3;

			for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
				if (strcmp(comp2str[i], component_name) == 0) {
				break;
				}
			}

			if (i == MOD_COUNT) goto unknown_component;

			unlang_ctx2.component = i;
		}
	}

	parse_rules = *unlang_ctx->rules;
	parse_rules.dict_def = dict;

	unlang_ctx2.actions = unlang_ctx->actions;

	/*
	 *	@todo - for named methods, we really need to determine
	 *	what methods we're calling here.
	 */
	unlang_ctx2.section_name1 = "subrequest";
	unlang_ctx2.section_name2 = name2;
	unlang_ctx2.rules = &parse_rules;

	/*
	 *	Compile the children of this subrequest in the context
	 *	of the dictionary && namespace that was given by the
	 *	subrequest.
	 */
	c = compile_children(g, parent, &unlang_ctx2, group_type, parentgroup_type);
	if (!c) return NULL;

	g->dict = dict;
	g->attr_packet_type = da;
	g->type_enum = type_enum;

	return c;
}


static unlang_t *compile_call(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
			      unlang_group_type_t group_type, unlang_group_type_t parentgroup_type,
			      unlang_type_t mod_type)
{
	unlang_group_t		*g;
	unlang_t		*c;
	FR_TOKEN		type;
	char const     		*server;
	CONF_SECTION		*server_cs;
	fr_dict_t const		*dict;

	server = cf_section_name2(cs);
	if (!server) {
		cf_log_err(cs, "You MUST specify a server name for 'call <server> { ... }'");
		return NULL;
	}

	type = cf_section_name2_quote(cs);
	if (type != T_BARE_WORD) {
		cf_log_err(cs, "The arguments to 'call' cannot by a quoted string or a dynamic value");
		return NULL;
	}

	g = group_allocate(parent, cs, group_type, mod_type);
	if (!g) return NULL;

	server_cs = virtual_server_find(server);
	if (!server_cs) {
		cf_log_err(cs, "Unknown virtual server '%s'", server);
		talloc_free(g);
		return NULL;
	}

	/*
	 *	The dictionaries are not compatible, forbid it.
	 */
	dict = virtual_server_namespace(server);
	if (dict && (dict != fr_dict_internal) && fr_dict_internal &&
	    unlang_ctx->rules->dict_def && (unlang_ctx->rules->dict_def != dict)) {
		cf_log_err(cs, "Cannot call namespace '%s' from namespaces '%s'",
			   fr_dict_root(dict)->name, fr_dict_root(unlang_ctx->rules->dict_def)->name);
		talloc_free(g);
		return NULL;
	}

	g->server_cs = server_cs;

	c = unlang_group_to_generic(g);
	c->name = unlang_ops[c->type].name;
	c->debug_name = talloc_typed_asprintf(c, "%s %s", c->name, server);

	return compile_children(g, parent, unlang_ctx, group_type, parentgroup_type);
}


/** Load a named module from "instantiate" or "policy".
 *
 * If it's "foo.method", look for "foo", and return "method" as the method
 * we wish to use, instead of the input component.
 *
 * @param[in] conf_root		Configuration root.
 * @param[out] pcomponent	Where to write the method we found, if any.
 *				If no method is specified will be set to MOD_COUNT.
 * @param[in] real_name		Complete name string e.g. foo.authorize.
 * @param[in] virtual_name	Virtual module name e.g. foo.
 * @param[in] method_name	Method override (may be NULL) or the method
 *				name e.g. authorize.
 * @return the CONF_SECTION specifying the virtual module.
 */
static CONF_SECTION *virtual_module_find_cs(CONF_SECTION *conf_root, rlm_components_t *pcomponent,
					    char const *real_name, char const *virtual_name, char const *method_name)
{
	CONF_SECTION *cs, *subcs;
	rlm_components_t method = *pcomponent;
	char buffer[256];

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
			return subcs;
		}
	}

	/*
	 *	Look for it in "policy".
	 *
	 *	If there's no policy section, we can't do anything else.
	 */
	cs = cf_section_find(conf_root, "policy", NULL);
	if (!cs) return NULL;

	/*
	 *	"foo.authorize" means "load policy "foo" as method "authorize".
	 *
	 *	And bail out if there's no policy "foo".
	 */
	if (method_name) {
		subcs = cf_section_find(cs, virtual_name, NULL);
		if (subcs) *pcomponent = method;

		return subcs;
	}

	/*
	 *	"foo" means "look for foo.component" first, to allow
	 *	method overrides.  If that's not found, just look for
	 *	a policy "foo".
	 *
	 */
	snprintf(buffer, sizeof(buffer), "%s.%s", virtual_name, comp2str[method]);
	subcs = cf_section_find(cs, buffer, NULL);
	if (subcs) return subcs;

	return cf_section_find(cs, virtual_name, NULL);
}


static unlang_t *compile_module(unlang_t *parent, unlang_compile_t *unlang_ctx,
				CONF_ITEM *ci, module_instance_t *inst, module_method_t method,
				unlang_group_type_t parentgroup_type, char const *realname)
{
	unlang_t *c;
	unlang_module_t *single;

	/*
	 *	Can't use "chap" in "dhcp".
	 */
	if (inst->module->dict && *inst->module->dict && unlang_ctx->rules && unlang_ctx->rules->dict_def &&
	    (unlang_ctx->rules->dict_def != fr_dict_internal) &&
	    (*inst->module->dict != unlang_ctx->rules->dict_def)) {
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

	single = talloc_zero(parent, unlang_module_t);
	single->module_instance = inst;
	single->method = method;

	c = unlang_module_to_generic(single);
	c->parent = parent;
	c->next = NULL;

	(void) compile_action_defaults(c, unlang_ctx, parentgroup_type);

	c->name = realname;
	c->debug_name = realname;
	c->type = UNLANG_TYPE_MODULE;

	if (!compile_action_section(c, ci)) {
		talloc_free(c);
		return NULL;
	}

	return c;
}

typedef unlang_t *(*modcall_compile_function_t)(unlang_t *parent, unlang_compile_t *unlang_ctx, CONF_SECTION *cs,
					 unlang_group_type_t group_type, unlang_group_type_t parentgroup_type, unlang_type_t mod_type);
typedef struct {
	char const			*name;
	modcall_compile_function_t	compile;
	unlang_group_type_t	        group_type;
	unlang_type_t			mod_type;
	bool				require_children;
} modcall_compile_t;

#define ALLOW_EMPTY_GROUP	(false)
#define REQUIRE_CHILDREN	(true)

static modcall_compile_t compile_table[] = {
	{ "group",		compile_group, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_GROUP, REQUIRE_CHILDREN },
	{ "redundant",		compile_redundant, UNLANG_GROUP_TYPE_REDUNDANT, UNLANG_TYPE_GROUP, REQUIRE_CHILDREN },
	{ "load-balance",	compile_load_balance, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_LOAD_BALANCE, REQUIRE_CHILDREN },
	{ "redundant-load-balance", compile_load_balance, UNLANG_GROUP_TYPE_REDUNDANT, UNLANG_TYPE_REDUNDANT_LOAD_BALANCE, REQUIRE_CHILDREN },

	{ "case",		compile_case, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_CASE, ALLOW_EMPTY_GROUP },
	{ "foreach",		compile_foreach, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_FOREACH, REQUIRE_CHILDREN },
	{ "if",			compile_if, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_IF, ALLOW_EMPTY_GROUP },
	{ "elsif",		compile_elsif, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_ELSIF, ALLOW_EMPTY_GROUP },
	{ "else",		compile_else, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_ELSE, REQUIRE_CHILDREN },
	{ "filter",		compile_filter, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_FILTER, REQUIRE_CHILDREN },
	{ "update",		compile_update, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_UPDATE, REQUIRE_CHILDREN },
	{ "map",		compile_map, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_MAP, REQUIRE_CHILDREN },
	{ "switch",		compile_switch, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_SWITCH, REQUIRE_CHILDREN },
	{ "parallel",		compile_parallel, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_PARALLEL, REQUIRE_CHILDREN },
	{ "subrequest",		compile_subrequest, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_SUBREQUEST, REQUIRE_CHILDREN },
	{ "call",		compile_call, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_CALL, ALLOW_EMPTY_GROUP },

	{ NULL, NULL, 0, UNLANG_TYPE_NULL }
};


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

/*
 *	Compile one entry of a module call.
 */
static unlang_t *compile_item(unlang_t *parent,
			      unlang_compile_t *unlang_ctx, CONF_ITEM *ci,
			      unlang_group_type_t parent_group_type, char const **modname)
{
	char const		*modrefname, *p;
	unlang_t		*c;
	module_instance_t	*inst;
	CONF_SECTION		*cs, *subcs, *modules;
	CONF_ITEM		*loop;
	char const		*realname;
	rlm_components_t	component = unlang_ctx->component;
	unlang_compile_t	unlang_ctx2;
	module_method_t		method;

	if (cf_item_is_section(ci)) {
		int i;
		char const *name2;

		cs = cf_item_to_section(ci);
		modrefname = cf_section_name1(cs);
		name2 = cf_section_name2(cs);

		for (i = 0; compile_table[i].name != NULL; i++) {
			if (strcmp(modrefname, compile_table[i].name) == 0) {
				if (name2) {
					*modname = name2;
				} else {
					*modname = "";
				}

				/*
				 *	Some blocks can be empty.  The rest need
				 *	to have contents.
				 */
				if (!cf_item_next(cs, NULL) &&
				    (compile_table[i].require_children == true)) {
					cf_log_err(ci, "'%s' sections cannot be empty", modrefname);
					return NULL;
				}

				return compile_table[i].compile(parent, unlang_ctx, cs,
								compile_table[i].group_type, parent_group_type,
								compile_table[i].mod_type);
			}
		}

		/*
		 *	Allow for named subsections, to change processing method types.
		 */
		if (name2 && (virtual_server_section_component(&component, modrefname, name2) == 0)) {
			UPDATE_CTX2;

			c = compile_group(parent, &unlang_ctx2, cs, UNLANG_GROUP_TYPE_SIMPLE, parent_group_type, UNLANG_TYPE_GROUP);
			if (!c) return NULL;

			c->name = modrefname;
			c->debug_name = talloc_typed_asprintf(c, "%s %s", modrefname, name2);
			return c;
		}

#ifdef WITH_UNLANG
		if (strcmp(modrefname, "break") == 0) {
			cf_log_err(ci, "Invalid use of 'break'");
			return NULL;

		} else if (strcmp(modrefname, "detach") == 0) {
			cf_log_err(ci, "Invalid use of 'detach'");
			return NULL;

		} else if (strcmp(modrefname, "return") == 0) {
			cf_log_err(ci, "Invalid use of 'return'");
			return NULL;

		} /* else it's something like sql { fail = 1 ...} */
#endif

	} else if (!cf_item_is_pair(ci)) { /* CONF_DATA or some such */
		return NULL;

		/*
		 *	Else it's a module reference, with updated return
		 *	codes.
		 */
	} else {
		CONF_PAIR *cp = cf_item_to_pair(ci);
		modrefname = cf_pair_attr(cp);

		/*
		 *	Actions (ok = 1), etc. are orthogonal to just
		 *	about everything else.
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
		if (((modrefname[0] == '%') && (modrefname[1] == '{')) ||
		    (modrefname[0] == '`')) {
			return compile_xlat_inline(parent, unlang_ctx, cp);
		}
	}

#ifdef WITH_UNLANG
	/*
	 *	These can't be over-ridden.
	 */
	if (strcmp(modrefname, "break") == 0) {
		return compile_break(parent, unlang_ctx, ci);
	}

	if (strcmp(modrefname, "detach") == 0) {
		return compile_detach(parent, unlang_ctx, ci);
	}

	if (strcmp(modrefname, "return") == 0) {
		c = compile_empty(parent, unlang_ctx, NULL, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_RETURN, COND_TYPE_INVALID);
		if (!c) return NULL;

		/*
		 *	These types are all parallel, and therefore can have a "return" in them.
		 */
		switch (parent->type) {
		case UNLANG_TYPE_LOAD_BALANCE:
		case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
		case UNLANG_TYPE_PARALLEL:
			break;

		default:
			parent->closed = ci;
			break;
		}

		return c;
	}
#endif

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
	subcs = NULL;
	p = strrchr(modrefname, '.');
	if (!p) {
		subcs = virtual_module_find_cs(cf_root(ci), &component, modrefname, modrefname, NULL);
	} else {
		char buffer[256];

		strlcpy(buffer, modrefname, sizeof(buffer));
		buffer[p - modrefname] = '\0';

		subcs = virtual_module_find_cs(cf_root(ci), &component, modrefname,
					       buffer, buffer + (p - modrefname) + 1);
	}

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
			subcs = NULL;
		}
	}

	/*
	 *	We've found the relevant entry.  It MUST be a
	 *	sub-section.
	 *
	 *	However, it can be a "redundant" block, or just
	 */
	if (subcs) {
		/*
		 *	module.c takes care of ensuring that this is:
		 *
		 *	group foo { ...
		 *	load-balance foo { ...
		 *	redundant foo { ...
		 *	redundant-load-balance foo { ...
		 *
		 *	We can just recurs to compile the section as
		 *	if it was found here.
		 */
		if (cf_section_name2(subcs)) {
			UPDATE_CTX2;

			c = compile_item(parent, &unlang_ctx2, cf_section_to_item(subcs), parent_group_type, modname);
			if (!c) return NULL;

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
			c = compile_group(parent, &unlang_ctx2, subcs, UNLANG_GROUP_TYPE_SIMPLE, parent_group_type, UNLANG_TYPE_GROUP);
			if (!c) return NULL;

			c->name = cf_section_name1(subcs);
			c->debug_name = c->name;
		}

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

	/*
	 *	Not a virtual module.  It must be a real module.
	 */
	modules = cf_section_find(cf_root(ci), "modules", NULL);
	if (!modules) goto fail;

	inst = NULL;
	realname = modrefname;

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
		*modname = inst->module->name;
		return compile_module(parent, &unlang_ctx2, ci, inst, method, parent_group_type, realname);
	}

	/*
	 *	We were asked to MAYBE load it and it
	 *	doesn't exist.  Return a soft error.
	 */
	if (realname != modrefname) {
		*modname = modrefname;
		return NULL;
	}

	/*
	 *	Can't de-reference it to anything.  Ugh.
	 */
fail:
	*modname = NULL;
	cf_log_err(ci, "Failed to find \"%s\" as a module or policy.", modrefname);
	cf_log_err(ci, "Please verify that the configuration exists in mods-enabled/%s.", modrefname);
	return NULL;
}

/** Set an unlang group name from a section
 *
 * This is to improve debug readability
 *
 * @param[in] group	to set name for.
 * @param[in] cs	to derive name from.
 */
static inline void unlang_group_name_from_cs(unlang_group_t *group, CONF_SECTION *cs)
{
	char const *name1, *name2;

	/*
	 *	Clear out existing name values
	 */
	talloc_const_free(group->self.name);
	talloc_const_free(group->self.debug_name);

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);
	group->self.name = name1;

	if (!name2) {
		MEM(group->self.debug_name = talloc_typed_strdup(group, name1));
	} else {
		MEM(group->self.debug_name = talloc_typed_asprintf(group, "%s %s", name1, name2));
	}
}

int unlang_compile(CONF_SECTION *cs, rlm_components_t component, vp_tmpl_rules_t const *rules)
{
	unlang_t		*c;
	vp_tmpl_rules_t		my_rules;

	/*
	 *	Don't compile it twice, and don't print out debug
	 *	messages twice.
	 */
	if (cf_data_find(cs, unlang_group_t, NULL) != NULL) return 1;

	/*
	 *	Ensure that all compile functions get valid rules.
	 */
	if (!rules) {
		memset(&my_rules, 0, sizeof(my_rules));
		rules = &my_rules;
	}

	c = compile_group(NULL,
			  &(unlang_compile_t){
			  	.component = component,
			  	.section_name1 = cf_section_name1(cs),
			  	.section_name2 = cf_section_name2(cs),
			  	.actions = &defaultactions[component],
				.rules = rules
			  },
			  cs, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_GROUP_TYPE_SIMPLE, UNLANG_TYPE_GROUP);
	if (!c) return -1;

	unlang_group_name_from_cs(unlang_generic_to_group(c), cs);


	if (DEBUG_ENABLED4) unlang_dump(c, 2);

	/*
	 *	Associate the unlang with the configuration section.
	 */
	cf_data_add(cs, c, NULL, false);

	dump_tree(c, c->debug_name);
	return 0;
}

/** Compile a named subsection
 *
 * @param[in] cs		the subsection to compile
 * @param[in] component 	The default method to call when compiling module calls.
 * @param[in] rules		For resolving attribute references.
 * @return
 *	- <0 on error
 *	- 0 on section was not found
 *	- 1 on successfully compiled
 *
 */
int unlang_compile_subsection(CONF_SECTION *cs, rlm_components_t component,
			      vp_tmpl_rules_t const *rules)
{
	char const *name1, *name2;

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	if (!name2) name2 = "";

	cf_log_debug(cs, "Compiling policies in - %s %s {...}", name1, name2);

	if (unlang_compile(cs, component, rules) < 0) {
		cf_log_err(cs, "Failed compiling '%s %s { ... }' section", name1, name2);
		return -1;
	}

	return 1;
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
	int i;

	if (!name || !*name) return false;

	for (i = 1; compile_table[i].name != NULL; i++) {
		if (strcmp(name, compile_table[i].name) == 0) return true;
	}

	if (strcmp(name, "break") == 0) return true;
	if (strcmp(name, "detach") == 0) return true;
	if (strcmp(name, "return") == 0) return true;

	return false;
}
