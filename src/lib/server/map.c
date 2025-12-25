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

/*
 * $Id$
 *
 * @brief map / template functions
 * @file src/lib/server/map.c
 *
 * @ingroup AVP
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/exec_legacy.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/tmpl_dcursor.h>

#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>


static fr_table_num_sorted_t const cond_quote_table[] = {
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},	/* Don't re-order, backslash throws off ordering */
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("/"),	T_SOLIDUS_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
static size_t cond_quote_table_len = NUM_ELEMENTS(cond_quote_table);


#ifdef DEBUG_MAP
static void map_dump(request_t *request, map_t const *map)
{
	RDEBUG2(">>> MAP TYPES LHS: %s, RHS: %s",
	        tmpl_type_to_str(map->lhs->type),
	        tmpl_type_to_str(map->rhs->type));

	if (map->rhs) {
		RDEBUG2(">>> MAP NAMES %s %s", map->lhs->name, map->rhs->name);
	}
}
#endif

static inline map_t *map_alloc(TALLOC_CTX *ctx, map_t *parent)
{
	map_t *map;

	if (parent) {
		map = talloc_zero(parent, map_t);
	} else {
		map = talloc_zero(ctx, map_t);
	}
	map->parent = parent;

	map_list_init(&map->child);
	return map;
}

/** Convert CONFIG_PAIR (which may contain refs) to map_t.
 *
 * Treats the left operand as an attribute reference
 * @verbatim<request>.<list>.<attribute>@endverbatim
 *
 * Treatment of left operand depends on quotation, barewords are treated as
 * attribute references, double quoted values are treated as expandable strings,
 * single quoted values are treated as literal strings.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx		for talloc.
 * @param[in] out		Where to write the pointer to the new #map_t.
 * @param[in] parent		the parent map
 * @param[in] cp		to convert to map.
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] input_rhs_rules	rules for parsing RHS attribute references.
 * @param[in] edit		treat the map as an edit
 * @return
 *	- #map_t if successful.
 *	- NULL on error.
 */
int map_afrom_cp(TALLOC_CTX *ctx, map_t **out, map_t *parent, CONF_PAIR *cp,
		 tmpl_rules_t const *lhs_rules, tmpl_rules_t const *input_rhs_rules, bool edit)
{
	map_t		*map;
	char const	*attr, *value, *marker_subject;
	char		*unescaped_value = NULL;
	fr_sbuff_parse_rules_t const *p_rules;
	ssize_t		slen;
	fr_token_t	quote;
	fr_dict_attr_t const *da;
	tmpl_rules_t	my_rhs_rules = {};
	tmpl_rules_t const *rhs_rules = input_rhs_rules;
	TALLOC_CTX	*child_ctx = NULL;

	*out = NULL;

	if (!cp) return -1;

	MEM(map = map_alloc(ctx, parent));
	map->op = cf_pair_operator(cp);
	map->ci = cf_pair_to_item(cp);

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err(cp, "Missing attribute value");
		goto error;
	}

	/*
	 *	Allow for the RHS rules to be taken from the LHS rules.
	 */
	if (!rhs_rules) rhs_rules = lhs_rules;

	MEM(child_ctx = talloc(map, uint8_t));

	/*
	 *	LHS may be an expansion (that expands to an attribute reference)
	 *	or an attribute reference. Quoting determines which it is.
	 */
	quote = cf_pair_attr_quote(cp);
	switch (quote) {
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
		slen = tmpl_afrom_substr(ctx, &map->lhs,
					 &FR_SBUFF_IN(attr, talloc_array_length(attr) - 1),
					 quote,
					 value_parse_rules_unquoted[quote],	/* We're not searching for quotes */
					 lhs_rules);
		if (slen <= 0) {
			char *spaces, *text;

			marker_subject = attr;
		marker:
			fr_canonicalize_error(ctx, &spaces, &text, slen, marker_subject);
			cf_log_err(cp, "%s", text);
			cf_log_perr(cp, "%s^", spaces);

			talloc_free(spaces);
			talloc_free(text);
			goto error;
		}
		break;

	default:
		slen = tmpl_afrom_attr_str(ctx, NULL, &map->lhs, attr, lhs_rules);
		if (slen <= 0) {
			cf_log_err(cp, "Failed parsing attribute reference %s - %s", attr, fr_strerror());
			marker_subject = attr;
			goto marker;
		}

		if (tmpl_attr_tail_is_unknown(map->lhs) && tmpl_attr_unknown_add(map->lhs) < 0) {
			cf_log_perr(cp, "Failed creating attribute %s", map->lhs->name);
			goto error;
		}

		fr_assert(tmpl_is_attr(map->lhs));

		/*
		 *	The caller wants the RHS attributes to be
		 *	parsed in the context of the LHS, but only if
		 *	the LHS attribute was a group / structural attribute.
		 */
		if (!input_rhs_rules) {
			tmpl_rules_child_init(child_ctx, &my_rhs_rules, lhs_rules, map->lhs);
		} else {
			my_rhs_rules = *input_rhs_rules;
		}
		rhs_rules = &my_rhs_rules;

		if (edit) {
			if ((map->op != T_OP_RSHIFT_EQ) && (map->op != T_OP_LSHIFT_EQ)) {
				my_rhs_rules.enumv = tmpl_attr_tail_da(map->lhs);
			}
		} else {
			/*
			 *	If we parsed an attribute on the LHS, and the RHS looks like an enumerated
			 *	value, then set the enumv.
			 */
			if (!rhs_rules->enumv && tmpl_is_attr(map->lhs) &&
			    (value[0] == ':') && value[1] == ':') {
				my_rhs_rules.enumv = tmpl_attr_tail_da(map->lhs);
			}
		}
		break;
	}

	/*
	 *	RHS might be an attribute reference.
	 */
	quote = cf_pair_value_quote(cp);
	p_rules = value_parse_rules_unquoted[quote]; /* We're not searching for quotes */
	if (quote == T_DOUBLE_QUOTED_STRING || quote == T_BACK_QUOTED_STRING) {
		slen = fr_sbuff_out_aunescape_until(child_ctx, &unescaped_value,
				&FR_SBUFF_IN(value, talloc_array_length(value) - 1), SIZE_MAX, p_rules->terminals, p_rules->escapes);
		if (slen < 0) {
			marker_subject = value;
			goto marker;
		}
		value = unescaped_value;
		p_rules = NULL;

	} else if (edit && (quote == T_HASH)) {
		fr_slen_t slent;
		xlat_exp_head_t *head;

		/*
		 *	Not a bare word, it's marked up as a complex expression.
		 *
		 *	See cf_file.c, parse_input() and the use of T_HASH when doing alloc_pair,
		 *	in order to see what magic is going on here.
		 */
		slen = talloc_array_length(value) - 1;

		MEM(map->rhs = tmpl_alloc(map, TMPL_TYPE_XLAT, T_BARE_WORD, value, slen));

		/*
		 *	Tokenize the expression.
		 */
		slent = xlat_tokenize_expression(map->rhs, &head, &FR_SBUFF_IN(value, slen), p_rules, rhs_rules);
		if (slent <= 0) {
			slen = slent + 1;
			marker_subject = value;
			goto marker;
		}

		tmpl_set_xlat(map->rhs, head);
		goto verify;

	} else if ((map->op == T_OP_CMP_TRUE) || (map->op == T_OP_CMP_FALSE)) {
		/*
		 *	These operators require a hard-coded string on the RHS.
		 */
		if (strcmp(value, "ANY") != 0) {
			fr_strerror_printf("Invalid value for %s", fr_tokens[map->op]);
			goto error;
		}

		(void) tmpl_afrom_value_box(map, &map->rhs, fr_box_strvalue("ANY"), false);
		goto verify;

	} else {
		slen = talloc_array_length(value) - 1;
	}

	/*
	 *	If we're assigning to a structural attribute, AND the
	 *	RHS side is a string, THEN don't parse the RHS as a
	 *	"group".  The edit code will take the string, create
	 *	pairs, and work on that.
	 */
	if (edit && (rhs_rules == &my_rhs_rules) && my_rhs_rules.enumv && fr_type_is_structural(my_rhs_rules.enumv->type) &&
	    ((quote == T_DOUBLE_QUOTED_STRING) || (quote == T_BACK_QUOTED_STRING) || (quote == T_SINGLE_QUOTED_STRING))) {
		my_rhs_rules.enumv = NULL;
	}

	slen = tmpl_afrom_substr(map, &map->rhs,
				 &FR_SBUFF_IN(value, slen),
				 quote,
				 p_rules,
				 rhs_rules);
	if (slen < 0) {
		marker_subject = value;
		goto marker;
	}

	if (!map->rhs) {
		cf_log_perr(cp, "Failed parsing RHS");
		goto error;
	}

	if (tmpl_is_attr(map->rhs) && (tmpl_attr_unknown_add(map->rhs) < 0)) {
		cf_log_perr(cp, "Failed creating attribute %s", map->rhs->name);
		goto error;
	}

	/*
	 *	We cannot assign a count to an attribute.  That must
	 *	be done in an xlat.
	 */
	if (tmpl_is_attr(map->rhs) &&
	    (tmpl_attr_tail_num(map->rhs) == NUM_COUNT)) {
		cf_log_err(cp, "Cannot assign from a count");
		goto error;
	}

	/*
	 *	If we can resolve the RHS in the context of the LHS,
	 *	and are allowed to do so, then do that now.
	 *
	 *	The "map" keyword uses the RHS not as the value which
	 *	is assigned to the LHS.  Instead, it is a pointer to
	 *	the value.  As such, we cannot immediately resolve the
	 *	RHS in the context of the LHS.
	 *
	 *	The edit code allows string assignments to lists, and
	 *	will interpret the string as a sequence of edit
	 *	operations.  So we skip casting strings to lists.
	 *
	 *	@todo - that could arguably be done immediately here,
	 *	and the RHS could be parsed and created as a child
	 *	map.  That would allow for more compile-time sanity
	 *	checks.
	 */
	if (tmpl_is_attr(map->lhs) && tmpl_is_data(map->rhs) &&
	    (!input_rhs_rules || !input_rhs_rules->attr.disallow_rhs_resolve) &&
	    fr_type_is_leaf(tmpl_attr_tail_da(map->lhs)->type)) {
		fr_type_t cast_type;

		if ((map->op != T_OP_RSHIFT_EQ) && (map->op != T_OP_LSHIFT_EQ)) {
			da = tmpl_attr_tail_da(map->lhs);
			cast_type = da->type;
		} else {
			da = NULL;
			cast_type = FR_TYPE_UINT32;
		}

		if (tmpl_cast_in_place(map->rhs, cast_type, da) < 0) {
			cf_log_err(cp, "Invalid assignment - %s", fr_strerror());
			goto error;
		}
	}

verify:
	MAP_VERIFY(map);
	TALLOC_FREE(child_ctx);

	*out = map;

	return 0;

error:
	TALLOC_FREE(child_ctx);
	talloc_free(map);
	return -1;
}

fr_table_num_sorted_t const map_assignment_op_table[] = {
	{ L("!*"),	T_OP_CMP_FALSE		},
	{ L("!="),	T_OP_NE			},
	{ L("!~"),	T_OP_REG_NE		},
	{ L("+="),	T_OP_ADD_EQ		},
	{ L("-="),	T_OP_SUB_EQ		},
	{ L(":="),	T_OP_SET		},
	{ L("<"),	T_OP_LT			},
	{ L("<="),	T_OP_LE			},
	{ L("="),	T_OP_EQ			},
	{ L("=*"),	T_OP_CMP_TRUE		},
	{ L("=="),	T_OP_CMP_EQ		},
	{ L("=~"),	T_OP_REG_EQ		},
	{ L(">"),	T_OP_GT			},
	{ L(">="),	T_OP_GE			}
};
size_t map_assignment_op_table_len = NUM_ELEMENTS(map_assignment_op_table);

fr_sbuff_parse_rules_t const map_parse_rules_bareword_quoted = {
	.escapes = &(fr_sbuff_unescape_rules_t){
		.chr = '\\',
		/*
		 *	Allow barewords to contain whitespace
		 *	if they're escaped.
		 */
		.subs = {
			['\t'] = '\t',
			['\n'] = '\n',
			[' '] = ' '
		},
		.do_hex = false,
		.do_oct = false
	},

	/*
	 *	We want to stop on _any_ terminal character, even if
	 *	the token itself isn't valid here.  Doing so means
	 *	that we don't have the parser accept things like:
	 *
	 *		User-Name,,,,=bob===
	 */
	.terminals = &FR_SBUFF_TERMS(
		L("\t"),
		L("\n"),
		L(" "),
		L("!*"),
		L("!="),
		L("!~"),
		L("+="),
		L(","),
		L("-="),
		L(":="),
		L("<"),
		L("<="),
		L("=*"),
		L("=="),
		L("=~"),
		L(">"),
		L(">="),
	)
};

fr_sbuff_parse_rules_t const *map_parse_rules_quoted[T_TOKEN_LAST] = {
	[T_BARE_WORD]			= &map_parse_rules_bareword_quoted,
	[T_DOUBLE_QUOTED_STRING]	= &value_parse_rules_double_quoted,
	[T_SINGLE_QUOTED_STRING]	= &value_parse_rules_single_quoted,
	[T_SOLIDUS_QUOTED_STRING]	= &value_parse_rules_solidus_quoted,
	[T_BACK_QUOTED_STRING]		= &value_parse_rules_backtick_quoted
};

/** Parse sbuff into (which may contain refs) to map_t.
 *
 * This function uses the legacy operator meanings.  The maps created here
 * should only be used with radius_legacy_map_cmp() and
 * radius_legacy_map_apply()
 *
 * The left operand MUST be an attribute reference
 * @verbatim<request>.<list>.<attribute>@endverbatim
 *
 *  The op_table should be #cond_cmp_op_table for check items, and
 *  #map_assignment_op_table for reply items.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx		for talloc.
 * @param[in] out		Where to write the pointer to the new #map_t.
 * @param[in,out] parent_p	the parent map, updated for relative maps
 * @param[in] in		the data to parse for creating the map.
 * @param[in] op_table		for lhs OP rhs
 * @param[in] op_table_len	length of op_table
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @param[in] p_rules		a list of terminals which will stop string
 *				parsing.
 * @return
 *	- >0 on success.
 *	- <=0 on error.
 */
ssize_t map_afrom_substr(TALLOC_CTX *ctx, map_t **out, map_t **parent_p, fr_sbuff_t *in,
			 fr_table_num_sorted_t const *op_table, size_t op_table_len,
			 tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
			 fr_sbuff_parse_rules_t const *p_rules)
{
	ssize_t				slen;
	fr_token_t			token;
	map_t				*map;
	fr_sbuff_t			our_in = FR_SBUFF(in);
	fr_sbuff_marker_t		m_lhs, m_rhs, m_op;
	fr_sbuff_term_t const		*tt = p_rules ? p_rules->terminals : NULL;
	map_t				*parent;
	fr_dict_attr_t const		*enumv;
	tmpl_rules_t			our_rhs_rules;

	if (parent_p) {
		parent = *parent_p;
	} else {
		parent = NULL;
	}

	*out = NULL;
	MEM(map = map_alloc(ctx, NULL));

	(void)fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, tt);

	fr_sbuff_marker(&m_lhs, &our_in);
	fr_sbuff_out_by_longest_prefix(&slen, &token, cond_quote_table, &our_in, T_BARE_WORD);
	switch (token) {
	default:
		fr_strerror_const("Expected attribute reference, not string");
		goto error;

	case T_BARE_WORD:
	{
		tmpl_rules_t our_lhs_rules;

		our_lhs_rules = *lhs_rules;

		/*
		 *	Bare words on the LHS are always attributes.
		 *
		 *	It doesn't make sense to allow "5 = 4".  Or, "5 = NAS-Port".
		 *
		 *	The conditions do allow "5 == NAS-Port", but
		 *	they use a different parser for that.
		 */

		/*
		 *	Absolute references are from the root.
		 */
		if (!fr_sbuff_next_if_char(&our_in, '.')) {
			parent = NULL;

		lhs_root:
			slen = tmpl_afrom_attr_substr(map, NULL, &map->lhs, &our_in,
						      &map_parse_rules_bareword_quoted, &our_lhs_rules);
			break;
		}

		/*
		 *	Allow for ".foo" to refer to the current
		 *	parents list.  Allow for "..foo" to refer to
		 *	the grandparent list.
		 */

		/*
		 *	Relative references must have a parent.
		 */
		if (!parent) {
			fr_strerror_const("Unexpected location for relative attribute - no parent attribute exists");
			goto error;
		}

		/*
		 *	Multiple '.' means "go to our parents parent".
		 */
		while (fr_sbuff_next_if_char(&our_in, '.')) {
			if (!parent) {
				fr_strerror_const("Too many '.' in relative reference");
				goto error;
			}
			parent = parent->parent;
		}

		if (!parent) goto lhs_root;

		/*
		 *	Start looking in the correct parent, not in whatever we were handed.
		 */
		fr_assert(tmpl_is_attr(parent->lhs));
		our_lhs_rules.attr.namespace = tmpl_attr_tail_da(parent->lhs);

		slen = tmpl_afrom_attr_substr(map, NULL, &map->lhs, &our_in,
					      &map_parse_rules_bareword_quoted, &our_lhs_rules);
		break;
	}
	}

	if (!map->lhs) {
	error:
		slen = 0;

	error_adj:
		talloc_free(map);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}
	fr_assert(tmpl_is_attr(map->lhs));

	(void)fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, tt);
	fr_sbuff_marker(&m_op, &our_in);

	/*
	 *	Parse operator.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &map->op, op_table, &our_in, T_INVALID);
	if (map->op == T_INVALID) {
		fr_strerror_const("Invalid operator");
		goto error_adj;
	}

	/*
	 *	Validate operators for check items.
	 *
	 *	We can have comparison operators for reply items, as the rlm_attr_filter module
	 *	uses that.
	 *
	 *	However, we can't do comparisons on structural entries, except for existence checks.
	 */
	if (!parent_p && tmpl_attr_tail_da_is_structural(map->lhs)) {
		if (fr_comparison_op[map->op] && (map->op != T_OP_CMP_TRUE) && (map->op != T_OP_CMP_FALSE)) {
			fr_sbuff_set(&our_in, &m_op);
			fr_strerror_const("Comparison operators cannot be used inside of structural data types");
			goto error;
		}
	}

	(void)fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, tt);

	/*
	 *	Copy LHS code above, except parsing in RHS, with some
	 *	minor modifications.
	 */
	fr_sbuff_marker(&m_rhs, &our_in);

	/*
	 *	If the LHS is a structural attribute, then (for now),
	 *	the RHS can only be {}.  This limitation should only
	 *	be temporary, as we should really recurse to create
	 *	child maps.  And then the child maps should not have
	 *	'.' as prefixes, and should require that the LHS can
	 *	only be an attribute, etc.  Not trivial, so we'll just
	 *	skip all that for now.
	 */
	switch (tmpl_attr_tail_da(map->lhs)->type) {
		case FR_TYPE_STRUCTURAL:
			if ((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)) {
				fr_sbuff_set(&our_in, &m_op);
				fr_assert(0);
				fr_strerror_const("Regular expressions cannot be used for structural attributes");
				goto error;
			}

			/*
			 *	To match Vendor-Specific =* ANY
			 *
			 *	Which is a damned hack.
			 */
			if ((map->op == T_OP_CMP_TRUE) || (map->op == T_OP_CMP_FALSE)) goto parse_rhs;

			if (fr_comparison_op[map->op]) {
				fr_sbuff_set(&our_in, &m_op);
				fr_strerror_const("Comparison operators cannot be used for structural attributes");
				goto error;
			}

			/*
			 *	radius_legacy_map_cmp() and radius_legacy_map_apply() both support structural
			 *	attributes with RHS strings.  And this function is only called from
			 *	users_file.c.  The consumers of the users file only call the radius legacy map
			 *	functions.
			 */
			if (!fr_sbuff_next_if_char(&our_in, '{')) {
				goto parse_rhs;
			}

			fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, tt);

			/*
			 *	Peek at the next character.  If it's '}', stop.
			 */
			if (!fr_sbuff_next_if_char(&our_in, '}')) {
				fr_sbuff_set(&our_in, &m_rhs);
				fr_strerror_const("Unexpected text before '}'");
				goto error;
			}

			/*
			 *	@todo - call ourselves recursively, with a special flag saying '.' is no
			 *	longer necessary.  And that we need to stop on '}'
			 */

			/*
			 *	Create an empty RHS.
			 */
			MEM(map->rhs = tmpl_alloc(map, TMPL_TYPE_DATA, T_SINGLE_QUOTED_STRING, "", 0));
			(void) fr_value_box_strdup(map->rhs, tmpl_value(map->rhs), NULL, "", false);
			goto check_for_child;

		default:
			break;
	}

parse_rhs:
	/*
	 *	These operators require a hard-coded string on the
	 *	RHS.  And we don't care about enums.
	 */
	if ((map->op == T_OP_CMP_TRUE) || (map->op == T_OP_CMP_FALSE)) {
		if (fr_sbuff_adv_past_str_literal(&our_in, "ANY") <= 0) {
			fr_strerror_printf("Invalid value for %s", fr_tokens[map->op]);
			goto error;
		}

		(void) tmpl_afrom_value_box(map, &map->rhs, fr_box_strvalue("ANY"), false);

		goto check_for_child;
	}

	enumv = tmpl_attr_tail_da(map->lhs);

	/*
	 *	LHS is a structural type.  The RHS is either empty (create empty LHS), or it's a string
	 *	containing a list of attributes to create.
	 */
	if (fr_type_is_leaf(enumv->type)) {
		our_rhs_rules = *rhs_rules;
		our_rhs_rules.enumv = enumv;
		rhs_rules = &our_rhs_rules;
	}

	fr_sbuff_out_by_longest_prefix(&slen, &token, cond_quote_table, &our_in, T_BARE_WORD);
	switch (token) {
	case T_SOLIDUS_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
		slen = tmpl_afrom_substr(map, &map->rhs, &our_in, token,
					 value_parse_rules_quoted[token], rhs_rules);
		break;

	default:
		if (rhs_rules->attr.bare_word_enum && rhs_rules->enumv) {
			fr_value_box_t *vb;

			MEM(vb = fr_value_box_alloc(map, rhs_rules->enumv->type, rhs_rules->enumv));

			if (!p_rules) p_rules = &value_parse_rules_bareword_quoted;

			/*
			 *	It MUST be the given data type, and it MAY be an enum name.
			 */
			slen = fr_value_box_from_substr(map, vb, rhs_rules->enumv->type, rhs_rules->enumv,
							&our_in, p_rules);
			if (slen < 0) goto error;

			if (tmpl_afrom_value_box(map, &map->rhs, vb, true) < 0) {
				goto error;
			}

		} else {
			if (!p_rules) p_rules = &value_parse_rules_bareword_quoted;

			/*
			 *	Use the RHS termination rules ONLY for bare
			 *	words.  For quoted strings we already know how
			 *	to terminate the input string.
			 */
			slen = tmpl_afrom_substr(map, &map->rhs, &our_in, token, p_rules, rhs_rules);
		}
		break;
	}
	if (!map->rhs) goto error_adj;

	/*
	 *	Check for, and skip, the trailing quote if we had a leading quote.
	 */
	if (token != T_BARE_WORD) {
		if (!fr_sbuff_next_if_char(&our_in, fr_token_quote[token])) {
			fr_strerror_const("Unexpected end of quoted string");
			goto error;
		}

		/*
		 *	The tmpl code does NOT return tmpl_type_data
		 *	for string data without xlat.  Instead, it
		 *	creates TMPL_TYPE_DATA_UNRESOLVED.
		 */
		if (tmpl_resolve(map->rhs, NULL) < 0) {
			fr_sbuff_set(&our_in, &m_rhs);	/* Marker points to RHS */
			goto error;
		}
	} else if (tmpl_is_attr(map->lhs) && (tmpl_is_data_unresolved(map->rhs) || tmpl_is_data(map->rhs))) {
		/*
		 *	If the operator is "true" or "false", just
		 *	cast the RHS to string, as no one will care
		 *	about it.
		 */
		if ((map->op != T_OP_CMP_TRUE) && (map->op != T_OP_CMP_FALSE)) {
			fr_dict_attr_t const *da = tmpl_attr_tail_da(map->lhs);

			if (tmpl_cast_in_place(map->rhs, da->type, da) < 0) {
				fr_sbuff_set(&our_in, &m_rhs);	/* Marker points to RHS */
				goto error;
			}
		} else {
			if (tmpl_cast_in_place(map->rhs, FR_TYPE_STRING, NULL) < 0) {
				fr_sbuff_set(&our_in, &m_rhs);	/* Marker points to RHS */
				goto error;
			}
		}
	}

	if (tmpl_contains_regex(map->lhs)) {
		fr_sbuff_set(&our_in, &m_lhs);
		fr_strerror_const("Unexpected regular expression");
		goto error;
	}

	if ((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)) {
		if (!tmpl_contains_regex(map->rhs)) {
			fr_sbuff_set(&our_in, &m_rhs);
			fr_strerror_const("Expected regular expression after regex operator");
			goto error;
		}
	} else {
		if (tmpl_contains_regex(map->rhs)) {
			fr_sbuff_set(&our_in, &m_rhs);
			fr_strerror_const("Unexpected regular expression");
			goto error;
		}
	}

check_for_child:
	/*
	 *	Add this map to to the parents list.  Note that the caller
	 *	will have to check for this, but checking if map->parent
	 *	exists.
	 */
	if (parent) {
		(void) talloc_steal(parent, map);
		map->parent = parent;
		map_list_insert_tail(&parent->child, map);
	}

	if (parent_p) {
		if (!tmpl_needs_resolving(map->lhs) && tmpl_attr_tail_da_is_structural(map->lhs)) {
			*parent_p = map;
		} else {
			*parent_p = parent;
		}
	}

	/*
	 *	Xlat expansions are cast to strings for structural data types.
	 */
	if (!tmpl_needs_resolving(map->lhs) && tmpl_attr_tail_da_is_structural(map->lhs) && (tmpl_is_xlat(map->rhs))) {
		tmpl_cast_set(map->rhs, FR_TYPE_STRING);
	}

	MAP_VERIFY(map);
	*out = map;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

static int _map_afrom_cs(TALLOC_CTX *ctx, map_list_t *out, map_t *parent, CONF_SECTION *cs,
			 tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
			 map_validate_t validate, void *uctx,
			 unsigned int max, bool update, bool edit)
{
	CONF_ITEM 	*ci;
	CONF_PAIR 	*cp;

	unsigned int 	total = 0;
	map_t		*map;
	TALLOC_CTX	*parent_ctx;

	tmpl_rules_t	our_lhs_rules = *lhs_rules;	/* Mutable copy of the destination */
	TALLOC_CTX	*tmp_ctx = NULL;		/* Temporary context for request lists */
	tmpl_rules_t	child_rhs_rules = *rhs_rules;
	tmpl_rules_t const  *our_rhs_rules;

	/*
	 *	The first map has ctx as the parent context.
	 *	The rest have the previous map as the parent context.
	 */
	parent_ctx = ctx;

	ci = cf_section_to_item(cs);

	/*
	 *	Check the "update" section for destination lists.
	 */
	if (update) {
		char const *name2 = cf_section_name2(cs);

		if (name2) {
			fr_dict_attr_t const *list_def = NULL;
			fr_sbuff_t sbuff = FR_SBUFF_IN(name2, strlen(name2));

			/*
			 *	There's a name, but it's not one we recognize.  Or, it's one we recognize but
			 *	there are things after it, we forbid it.
			 *
			 *	This code is ONLY used for "update" sections in modules.  None of those
			 *	examples use a destination list.  If we allow any destination list (including
			 *	parent, outer, etc.) then we allow the possibility of changing protocols,
			 *	which is bad.
			 *
			 *	This limitation also means that the module "update" lists can't automatically
			 *	edit other structural attributes, such as "reply.foo".  But that seems a small
			 *	price to pay.
			 *
			 *	The admin can still specify outer / parent / etc. on the individual entries in
			 *	an "update" section, but we'll let that go for now.
			 *
			 *	@todo - We should arguably forbid parent/outer list references in an "update"
			 *	section.
			 */
			if ((tmpl_attr_list_from_substr(&list_def, &sbuff) <= 0) ||
			    !fr_sbuff_eof(&sbuff)) {
				cf_log_err(ci, "Invalid destination list specifier for 'update' - must be one of 'request', 'reply', 'control', or 'state'");
				return -1;
			}

			our_lhs_rules.attr.list_def = list_def;
		}
	}

	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		tmpl_rules_t	child_lhs_rules = our_lhs_rules;

		/*
		 *	Disallow list references on the LHS of child lists for edit sections.
		 */
		if (edit) child_lhs_rules.attr.list_presence = TMPL_ATTR_LIST_FORBID;

		if (total++ == max) {
			cf_log_err(ci, "Map size exceeded");
		error:
			/*
			 *	Free in reverse as successive entries have their
			 *	prececessors as talloc parent contexts
			 */
			talloc_free(tmp_ctx);
			map_list_talloc_reverse_free(out);
			return -1;
		}

		/*
		 *	If we have a subsection, AND the name2 is an
		 *	assignment operator, THEN we allow sub-maps.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION	*subcs;
			fr_token_t	token;
			ssize_t		slen;
			map_list_t	child_list;

			map_list_init(&child_list);
			subcs = cf_item_to_section(ci);
			token = cf_section_name2_quote(subcs);

			if (token == T_INVALID) {
				cf_log_err(ci, "Section '%s { ... }' is missing the '=' operator", cf_section_name1(subcs));
				goto error;
			}

			if (!fr_assignment_op[token]) {
				cf_log_err(ci, "Invalid operator '%s'", fr_tokens[token]);
				goto error;
			}

			MEM(map = map_alloc(parent_ctx, parent));
			map->op = token;
			map->ci = ci;

			/*
			 *	The LHS MUST be an attribute name.
			 *	map_afrom_cp() allows for dynamic
			 *	names, but for simplicity we forbid
			 *	them for now.  Once the functionality
			 *	is tested and used, we can allow that.
			 */
			slen = tmpl_afrom_attr_str(ctx, NULL, &map->lhs, cf_section_name1(subcs), &our_lhs_rules);
			if (slen <= 0) {
				cf_log_err(ci, "Failed parsing attribute reference for list %s - %s",
					   cf_section_name1(subcs), fr_strerror());
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			/*
			 *	The LHS MUST be an attribute reference
			 *	for now.
			 */
			if (!tmpl_is_attr(map->lhs)) {
				cf_log_err(ci, "Left side of group '%s' is NOT an attribute reference",
					   map->lhs->name);
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			if (tmpl_attr_tail_da(map->lhs)->flags.is_unknown) {
				cf_log_err(ci, "Unknown attribute '%s'", map->lhs->name);
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			/*
			 *	The leaf reference of the outer section
			 *	is used as the parsing context of the
			 *	inner section.
			 */
			child_lhs_rules.attr.namespace = tmpl_attr_tail_da(map->lhs);

			/*
			 *	Groups MAY change dictionaries.  If so, then swap the dictionary and the parent.
			 */
			if (child_lhs_rules.attr.namespace->type == FR_TYPE_GROUP) {
				fr_dict_attr_t const *ref;
				fr_dict_t const *dict, *internal;

				ref = fr_dict_attr_ref(child_lhs_rules.attr.namespace);
				dict = fr_dict_by_da(ref);
				internal = fr_dict_internal();

				if (dict != internal) {
					if (dict != child_lhs_rules.attr.dict_def) {
						child_lhs_rules.attr.dict_def = dict;
						child_lhs_rules.attr.namespace = ref;
					}
				} else {
					/*
					 *	We're internal: don't use it, and instead rely on dict_def.
					 */
					child_lhs_rules.attr.namespace = NULL;
				}
			}

			if (fr_type_is_structural(tmpl_attr_tail_da(map->lhs)->type)) {
				/*
				 *	This prints out any relevant error
				 *	messages.  We MAY want to print out
				 *	additional ones, but that might get
				 *	complex and confusing.
				 *
				 *	We call out internal _map_afrom_cs()
				 *	function, in order to pass in the
				 *	correct parent map.
				 */
				if (_map_afrom_cs(map, &child_list, map, cf_item_to_section(ci),
						  &child_lhs_rules, rhs_rules, validate, uctx, max, false, edit) < 0) {
				fail:
					map_list_talloc_free(&child_list);
					talloc_free(map);
					goto error;
				}
				map_list_move(&map->child, &child_list);
			} else {
				fr_assert(fr_type_is_leaf(tmpl_attr_tail_da(map->lhs)->type));

				/*
				 *	foo := { a, b, c }
				 *
				 *	@todo - maybe lhs_rules?  But definitely not child_lhs_rules.
				 *
				 *	@todo - this code is taken from compile_edit_section(), we might want
				 *	to just move that code here, for fewer special cases.
				 */
				if (map_list_afrom_cs(map, &child_list, cf_item_to_section(ci), rhs_rules, NULL, NULL, max) < 0) {
					goto fail;
				}

				if ((map->op != T_OP_SET) && !map_list_num_elements(&child_list)) {
					cf_log_err(cs, "Cannot use operator '%s' for assigning empty list to '%s' data type.",
						   fr_tokens[map->op], fr_type_to_str(tmpl_attr_tail_da(map->lhs)->type));
					goto fail;
				}

				map_list_move(&map->child, &child_list);
			}

			MAP_VERIFY(map);
			goto next;
		}

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"attribute = value\" format");
			goto error;
		}

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		/*
		 *	Over-ride RHS rules for
		 *
		 *	reply += {
		 *		User-Name = User-Name
		 *	}
		 *
		 *	Which looks stupid.  Instead we require
		 *
		 *	reply += {
		 *		User-Name = request.User-Name
		 *	}
		 *
		 *	On the other hand, any xlats on the RHS don't use the full path.  :( And we still need
		 *	to allow relative attribute references via ".foo", when updating structures.
		 */
		our_rhs_rules = rhs_rules;
		if (edit && (rhs_rules->attr.list_def != child_lhs_rules.attr.list_def)) {
			char const *value = cf_pair_value(cp);

			if (value && (*value == '&')) {
				child_rhs_rules.attr.list_presence = TMPL_ATTR_LIST_REQUIRE;
				our_rhs_rules = &child_rhs_rules;
			}
		}

		if (map_afrom_cp(parent_ctx, &map, parent, cp, &child_lhs_rules, our_rhs_rules, edit) < 0) {
			cf_log_err(ci, "Failed creating map from '%s = %s'",
				   cf_pair_attr(cp), cf_pair_value(cp));
			goto error;
		}

		MAP_VERIFY(map);

		/*
		 *	Check the types in the map are valid
		 */
		if (validate && (validate(map, uctx) < 0)) goto error;

	next:
		parent_ctx = map;
		map_list_insert_tail(out, map);
	}

	talloc_free(tmp_ctx);
	return 0;

}

/** Convert a config section into an attribute map.
 *
 *  For "update" sections, Uses 'name2' of section to set default request and lists.
 *
 * @param[in] ctx		for talloc.
 * @param[out] out		Where to store the allocated map.
 * @param[in] cs		the update section
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @param[in] validate		map using this callback (may be NULL).
 * @param[in] uctx		to pass to callback.
 * @param[in] max		number of mappings to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_afrom_cs(TALLOC_CTX *ctx, map_list_t *out, CONF_SECTION *cs,
		 tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
		 map_validate_t validate, void *uctx,
		 unsigned int max)
{
	bool update;
	char const *name2;
	map_t *parent = NULL;

	name2 = cf_section_name1(cs);
	update = (name2 && (strcmp(name2, "update") == 0));

	if (ctx) parent = talloc_get_type(ctx, map_t);

	return _map_afrom_cs(ctx, out, parent, cs, lhs_rules, rhs_rules, validate, uctx, max, update, false);
}

/** Convert a config section into an attribute map for editing
 *
 * @param[in] ctx		for talloc.
 * @param[out] out		Where to store the allocated map.
 * @param[in] cs		the update section
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @param[in] validate		map using this callback (may be NULL).
 * @param[in] uctx		to pass to callback.
 * @param[in] max		number of mappings to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_afrom_cs_edit(TALLOC_CTX *ctx, map_list_t *out, CONF_SECTION *cs,
		      tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
		      map_validate_t validate, void *uctx,
		      unsigned int max)
{
	map_t *parent = NULL;

	if (ctx) parent = talloc_get_type(ctx, map_t);

	return _map_afrom_cs(ctx, out, parent, cs, lhs_rules, rhs_rules, validate, uctx, max, false, true);
}

/** Convert CONFIG_PAIR (which may contain refs) to map_t.
 *
 * Treats the CONFIG_PAIR name as a value.
 *
 * Treatment of left operand depends on quotation, barewords are treated as
 * attribute , double quoted values are treated as expandable strings,
 * single quoted values are treated as literal strings.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx		for talloc.
 * @param[in] out		Where to write the pointer to the new #map_t.
 * @param[in] parent		the parent map
 * @param[in] cp		to convert to map.
 * @param[in] t_rules		rules for parsing name
 * @return
 *	- #map_t if successful.
 *	- NULL on error.
 */
static int map_value_afrom_cp(TALLOC_CTX *ctx, map_t **out, map_t *parent, CONF_PAIR *cp,
			      tmpl_rules_t const *t_rules)
{
	map_t		*map;
	char const	*attr, *marker_subject;
	ssize_t		slen;
	fr_token_t	type;

	*out = NULL;

	if (!cp) return -1;

	MEM(map = map_alloc(ctx, parent));
	map->op = T_OP_EQ;	/* @todo - should probably be T_INVALID */
	map->ci = cf_pair_to_item(cp);

	attr = cf_pair_attr(cp);

	/*
	 *	LHS may be an expansion (that expands to an attribute reference)
	 *	or an attribute reference. Quoting determines which it is.
	 */
	type = cf_pair_attr_quote(cp);
	switch (type) {
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
		slen = tmpl_afrom_substr(ctx, &map->lhs,
					 &FR_SBUFF_IN(attr, talloc_array_length(attr) - 1),
					 type,
					 value_parse_rules_unquoted[type],	/* We're not searching for quotes */
					 t_rules);
		if (slen <= 0) {
			char *spaces, *text;

		marker:
			marker_subject = attr;
			fr_canonicalize_error(ctx, &spaces, &text, slen, marker_subject);
			cf_log_err(cp, "%s", text);
			cf_log_perr(cp, "%s^", spaces);

			talloc_free(spaces);
			talloc_free(text);
			goto error;
		}
		break;

	case T_SOLIDUS_QUOTED_STRING:
		fr_strerror_const("Invalid location for regular expression");
		slen = 0;
		goto marker;

	default:
		/*
		 *	Let the tmpl code determine if it's an attribute reference or else is a raw value.
		 */
		slen = tmpl_afrom_substr(ctx, &map->lhs, &FR_SBUFF_IN(attr, talloc_array_length(attr) - 1), T_BARE_WORD, NULL, t_rules);
		if (slen <= 0) goto marker;

		if (tmpl_is_attr(map->lhs) && (tmpl_attr_unknown_add(map->lhs) < 0)) {
			fr_strerror_printf("Failed defining attribute %s", map->lhs->name);
			goto error;
		}
		break;
	}

	MAP_VERIFY(map);

	*out = map;

	return 0;

error:
	talloc_free(map);
	return -1;
}

/*
 *	Where the RHS are all values.
 */
static int _map_list_afrom_cs(TALLOC_CTX *ctx, map_list_t *out, map_t *parent, CONF_SECTION *cs,
			     tmpl_rules_t const *t_rules,
			     map_validate_t validate, void *uctx,
			     unsigned int max)
{
	CONF_ITEM 	*ci;
	CONF_PAIR 	*cp;

	unsigned int 	total = 0;
	map_t		*map;
	TALLOC_CTX	*parent_ctx;

	/*
	 *	The first map has ctx as the parent context.
	 *	The rest have the previous map as the parent context.
	 */
	parent_ctx = ctx;

	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		if (total++ == max) {
			cf_log_err(ci, "Map size exceeded");
		error:
			/*
			 *	Free in reverse as successive entries have their
			 *	prececessors as talloc parent contexts
			 */
			map_list_talloc_reverse_free(out);
			return -1;
		}

		if (cf_item_is_section(ci)) {
			cf_log_err(ci, "Cannot create sub-lists");
			goto error;
		}

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		if (map_value_afrom_cp(parent_ctx, &map, parent, cp, t_rules) < 0) {
			fr_assert(0);
			cf_log_err(ci, "Failed creating map from '%s'", cf_pair_attr(cp));
			goto error;
		}

		MAP_VERIFY(map);

		/*
		 *	Check the types in the map are valid
		 */
		if (validate && (validate(map, uctx) < 0)) goto error;

		parent_ctx = map;
		map_list_insert_tail(out, map);
	}

	return 0;

}

/** Convert a config section into a list of { a, b, c, d, ... }
 *
 * @param[in] ctx		for talloc.
 * @param[out] out		Where to store the allocated map.
 * @param[in] cs		the update section
 * @param[in] t_rules		rules for parsing the data.
 * @param[in] validate		map using this callback (may be NULL).
 * @param[in] uctx		to pass to callback.
 * @param[in] max		number of mappings to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_list_afrom_cs(TALLOC_CTX *ctx, map_list_t *out, CONF_SECTION *cs,
		      tmpl_rules_t const *t_rules,
		      map_validate_t validate, void *uctx,
		      unsigned int max)
{
	map_t *parent = NULL;

	if (ctx) parent = talloc_get_type(ctx, map_t);

	return _map_list_afrom_cs(ctx, out, parent, cs, t_rules, validate, uctx, max);
}

/** Convert a value box to a map
 *
 * This is mainly used in IO modules, where another function is used to convert
 * between the foreign value type and internal values, and the destination
 * attribute is provided as a string.
 *
 * @param[in] ctx		for talloc
 * @param[out] out		Where to store the head of the map.
 * @param[in] lhs		of the operation
 * @param[in] lhs_quote		type of the LHS string
 * @param[in] lhs_rules		rules that control parsing of the LHS string.
 * @param[in] op		the operation to perform
 * @param[in] rhs		of the operation
 * @param[in] steal_rhs_buffs	Whether we attempt to save allocs by stealing the buffers
 *				from the rhs #fr_value_box_t.
 * @return
 *	- #map_t if successful.
 *	- NULL on error.
 */
int map_afrom_value_box(TALLOC_CTX *ctx, map_t **out,
			char const *lhs, fr_token_t lhs_quote, tmpl_rules_t const *lhs_rules,
			fr_token_t op,
			fr_value_box_t *rhs, bool steal_rhs_buffs)
{
	ssize_t slen;
	map_t *map;

	map = map_alloc(ctx, NULL);

	slen = tmpl_afrom_substr(map, &map->lhs,
				 &FR_SBUFF_IN_STR(lhs),
				 lhs_quote,
				 NULL,
				 lhs_rules);
	if (slen < 0) {
	error:
		talloc_free(map);
		return -1;
	}

	map->op = op;

	if (tmpl_afrom_value_box(map, &map->rhs, rhs, steal_rhs_buffs) < 0) goto error;

	MAP_VERIFY(map);
	*out = map;

	return 0;
}

/** Convert a value pair string to valuepair map
 *
 * Takes a valuepair string with list and request qualifiers and converts it into a
 * #map_t.
 *
 * Attribute string is in the format (where @verbatim <qu> @endverbatim is a quotation char ['"]):
 @verbatim
   [<list>.][<qu>]<attribute>[<qu>] <op> [<qu>]<value>[<qu>]
 @endverbatim
 *
 * @param[in] ctx		where to allocate the map.
 * @param[out] out		Where to write the new map.
 * @param[in] vp_str		string to parse.
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
int map_afrom_attr_str(TALLOC_CTX *ctx, map_t **out, char const *vp_str,
		       tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules)
{
	fr_sbuff_t sbuff = FR_SBUFF_IN(vp_str, strlen(vp_str));

	if (map_afrom_substr(ctx, out, NULL, &sbuff, map_assignment_op_table, map_assignment_op_table_len,
			    lhs_rules, rhs_rules, NULL) < 0) {
		return -1;
	}

	if (!fr_cond_assert(*out != NULL)) return -1;

	if (!tmpl_is_attr((*out)->lhs)) {
		TALLOC_FREE(*out);
		fr_strerror_const("Left operand must be an attribute");
		return -1;
	}

	return 0;
}

/** Convert a fr_pair_t into a map
 *
 * @param[in] ctx		where to allocate the map.
 * @param[out] out		Where to write the new map (must be freed with talloc_free()).
 * @param[in] vp		to convert.
 * @param[in] rules		to insert attributes into.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_afrom_vp(TALLOC_CTX *ctx, map_t **out, fr_pair_t *vp, tmpl_rules_t const *rules)
{
	char buffer[256];
	fr_sbuff_t buffer_sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	map_t *map;

	map = map_alloc(ctx, NULL);
	if (!map) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}

	/*
	 *	Allocate the LHS
	 */
	map->lhs = tmpl_alloc(map, TMPL_TYPE_ATTR, T_BARE_WORD, NULL, 0);
	if (!map->lhs) goto oom;

	tmpl_attr_set_leaf_da(map->lhs, vp->da);

	tmpl_attr_set_request_ref(map->lhs, rules->attr.request_def);
	tmpl_attr_set_list(map->lhs, rules->attr.list_def);

	tmpl_print(&buffer_sbuff, map->lhs, NULL);
	tmpl_set_name(map->lhs, T_BARE_WORD, fr_sbuff_start(&buffer_sbuff), -1);

	/*
	 *	Allocate the RHS
	 */
	map->rhs = tmpl_alloc(map, TMPL_TYPE_DATA, T_BARE_WORD, NULL, -1);
	if (!map->lhs) goto oom;

	switch (vp->vp_type) {
	case FR_TYPE_QUOTED:
		tmpl_set_name_printf(map->rhs, T_DOUBLE_QUOTED_STRING, "%pV", &vp->data);
		break;

	default:
		tmpl_set_name_printf(map->rhs, T_BARE_WORD, "%pV", &vp->data);
		break;
	}

	if (unlikely(fr_value_box_copy(map->rhs, tmpl_value(map->rhs), &vp->data) < 0)) {
		talloc_free(map);
		return -1;
	}

	*out = map;

	return 0;
}

/** Process map which has exec as a src
 *
 * Evaluate maps which specify exec as a src. This may be used by various sorts of update sections, and so
 * has been broken out into it's own function.
 *
 * @param[in,out] ctx to allocate new #fr_pair_t (s) in.
 * @param[out] out Where to write the #fr_pair_t (s).
 * @param[in] request structure (used only for talloc).
 * @param[in] map the map. The LHS (dst) must be #TMPL_TYPE_ATTR.
 *	The RHS (src) must be #TMPL_TYPE_EXEC.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int map_exec_to_vp(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, map_t const *map)
{
	int result;
	fr_pair_t *vp;
	fr_pair_list_t *input_pairs = NULL;
	char answer[1024];

	fr_pair_list_free(out);

	MAP_VERIFY(map);

	fr_assert(map->rhs);		/* Quite clang scan */
	fr_assert(tmpl_is_exec(map->rhs));
	fr_assert(tmpl_is_attr(map->lhs));

	if (fr_type_is_structural(tmpl_attr_tail_da(map->lhs)->type)) {
		REDEBUG("Cannot assign `exec` output to structural attribute %s", map->lhs->name);
		return -1;
	}

	/*
	 *	We always put the request pairs into the environment
	 */
	input_pairs = tmpl_list_head(request, request_attr_request);

	/*
	 *	Automagically switch output type depending on our destination
	 *	@todo - If dst is a list, then we create attributes from the output of the program
	 *	if dst is an attribute, then we create an attribute of that type and then
	 *	call fr_pair_value_from_str on the output of the script.
	 */
	result = radius_exec_program_legacy(answer, sizeof(answer),
				     request, map->rhs->name, input_pairs ? input_pairs : NULL,
				     true, true, fr_time_delta_from_sec(EXEC_TIMEOUT));
	if (result != 0) {
		REDEBUG("Exec failed with code (%i)", result);
		return -1;
	}

	/*
	 *	@todo - we completely ignore the operator here :( Arguably the caller should be calling ONLY
	 *	the legacy pair move functions with the results of this function.
	 */
	MEM(vp = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));
	vp->op = map->op;
	if (fr_pair_value_from_str(vp, answer, strlen(answer), &fr_value_unescape_single, false) < 0) {
		RPEDEBUG("Failed parsing exec output");
		talloc_free(&vp);
		return -2;
	}
	fr_pair_append(out, vp);

	return 0;
}

/** Convert a map to a #fr_pair_t
 *
 * @param[in,out] ctx to allocate #fr_pair_t (s) in.
 * @param[out] out Where to write the #fr_pair_t (s), which may be NULL if not found
 * @param[in] request The current request.
 * @param[in] map the map. The LHS (dst) has to be #TMPL_TYPE_ATTR.
 * @param[in] uctx unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_to_vp(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, map_t const *map, UNUSED void *uctx)
{
	int		rcode = 0;
	fr_pair_t	*n = NULL;
	fr_pair_list_t	found;
	request_t	*context = request;
	ssize_t		slen;
	char		*str;

	fr_pair_list_init(&found);
	fr_pair_list_free(out);

	MAP_VERIFY(map);
	if (!fr_cond_assert(map->lhs != NULL)) return -1;

	fr_assert(tmpl_is_attr(map->lhs));

	/*
	 *	If there's no RHS, then it MUST be an attribute, and
	 *	it MUST be structural.  And it MAY have children.
	 */
	if (!map->rhs) {
		map_t *child;

		if (!tmpl_is_attr(map->lhs)) return -1;

		switch (tmpl_attr_tail_da(map->lhs)->type) {
		case FR_TYPE_STRUCTURAL:
			break;

		default:
			return -1;
		}

		/*
		 *	Create the parent attribute, and
		 *	recurse to generate the children into
		 *	vp->vp_group
		 */
		MEM(n = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));
		n->op = map->op;

		for (child = map_list_next(&map->child, NULL);
		     child != NULL;
		     child = map_list_next(&map->child, child)) {
			fr_pair_list_t list;

			/*
			 *	map_to_vp() frees "out", so we need to
			 *	work around that by creating a
			 *	temporary list.
			 */
			fr_pair_list_init(&list);
			if (map_to_vp(n, &list, request, child, NULL) < 0) {
				talloc_free(n);
				return -1;
			}

			fr_pair_list_append(&n->vp_group, &list);
		}

		fr_pair_append(out, n);
		return 0;
	}

	/*
	 *	List to list found, this is a special case because we don't need
	 *	to allocate any attributes, just finding the current list, and change
	 *	the op.
	 */
	if ((tmpl_contains_attr(map->lhs) && tmpl_attr_tail_da_is_structural(map->lhs)) &&
	    (tmpl_contains_attr(map->rhs) && tmpl_attr_tail_da_is_structural(map->rhs))) {
		fr_pair_list_t *from = NULL;

		if (tmpl_request_ptr(&context, tmpl_request(map->rhs)) == 0) {
			from = tmpl_list_head(context, tmpl_list(map->rhs));
		}
		if (!from) return 0;

		if (fr_pair_list_copy(ctx, &found, from) < 0) return -1;

		/*
		 *	List to list copy is empty if the src list has no attributes.
		 */
		if (fr_pair_list_empty(&found)) return 0;

		fr_pair_list_foreach(&found, vp) {
			vp->op = T_OP_ADD_EQ;
		}

		fr_pair_list_append(out, &found);

		return 0;
	}

	/*
	 *	And parse the RHS
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_XLAT:
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(tmpl_attr_tail_da(map->lhs));	/* We need to know which attribute to create */
		fr_assert(tmpl_xlat(map->rhs) != NULL);

		MEM(n = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));

		/*
		 *	We do the debug printing because xlat_aeval_compiled
		 *	doesn't have access to the original string.  It's been
		 *	mangled during the parsing to an internal data structure
		 */
		RDEBUG2("EXPAND %s", map->rhs->name);
		RINDENT();

		str = NULL;
		slen = xlat_aeval_compiled(request, &str, request, tmpl_xlat(map->rhs), NULL, NULL);
		REXDENT();

		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		RDEBUG2("--> %s", str);

		rcode = fr_pair_value_from_str(n, str, strlen(str), NULL, false);
		talloc_free(str);
		if (rcode < 0) {
			goto error;
		}

		n->op = map->op;
		fr_pair_append(out, n);
		break;

	case TMPL_TYPE_DATA_UNRESOLVED:
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(tmpl_attr_tail_da(map->lhs));	/* We need to know which attribute to create */

		MEM(n = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));

		if (fr_pair_value_from_str(n, map->rhs->name, strlen(map->rhs->name), NULL, false) < 0) {
			rcode = 0;
			goto error;
		}
		n->op = map->op;
		fr_pair_append(out, n);
		break;

	case TMPL_TYPE_ATTR:
	{
		fr_pair_t *vp;
		fr_dcursor_t from;

		fr_assert(tmpl_is_attr(map->lhs) && tmpl_attr_tail_da(map->lhs));

		/*
		 * @todo should log error, and return -1 for v3.1 (causes update to fail)
		 */
		if (tmpl_copy_pairs(ctx, &found, request, map->rhs) < 0) return 0;

		vp = fr_pair_dcursor_init(&from, &found);

		/*
		 *  Src/Dst attributes don't match, convert src attributes
		 *  to match dst.
		 */
		if (tmpl_is_attr(map->lhs) && tmpl_attr_tail_da_is_leaf(map->lhs) &&
		    (tmpl_attr_tail_da(map->rhs)->type != tmpl_attr_tail_da(map->lhs)->type)) {
			for (; vp; vp = fr_dcursor_current(&from)) {
				MEM(n = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));

				if (fr_value_box_cast(n, &n->data,
						      tmpl_attr_tail_da(map->lhs)->type, tmpl_attr_tail_da(map->lhs), &vp->data) < 0) {
					RPEDEBUG("Attribute conversion failed");
					fr_pair_list_free(&found);
					talloc_free(n);
					return -1;
				}
				vp = fr_dcursor_remove(&from);	/* advances cursor */
				talloc_free(vp);

				fr_assert((n->vp_type != FR_TYPE_STRING) || (n->vp_strvalue != NULL));

				n->op = map->op;
				fr_pair_append(out, n);
			}

			return 0;
		}

		/*
		 *   Otherwise we just need to fixup the attribute types
		 *   and operators
		 */
		for (; vp; vp = fr_dcursor_next(&from)) {
			fr_pair_reinit_from_da(&found, vp, tmpl_attr_tail_da(map->lhs));
			vp->op = map->op;
		}
		fr_pair_list_append(out, &found);
	}
		break;

	case TMPL_TYPE_DATA:
		fr_assert(tmpl_attr_tail_da(map->lhs));
		fr_assert(tmpl_is_attr(map->lhs));

		MEM(n = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));

		if (tmpl_attr_tail_da(map->lhs)->type == tmpl_value_type(map->rhs)) {
			if (unlikely(fr_value_box_copy(n, &n->data, tmpl_value(map->rhs)) < 0)) {
				rcode = -1;
				talloc_free(n);
				goto error;
			}

		} else if (fr_value_box_cast(n, &n->data, n->vp_type, n->da, tmpl_value(map->rhs)) < 0) {
			RPEDEBUG("Implicit cast failed");
			rcode = -1;
			goto error;
		}
		n->op = map->op;
		fr_pair_append(out, n);

		MAP_VERIFY(map);
		break;

	/*
	 *	This essentially does the same as rlm_exec xlat, except it's non-configurable.
	 *	It's only really here as a convenience for people who expect the contents of
	 *	backticks to be executed in a shell.
	 *
	 *	exec string is xlat expanded and arguments are shell escaped.
	 */
	case TMPL_TYPE_EXEC:
		return map_exec_to_vp(ctx, out, request, map);

	default:
		fr_assert(0);	/* Should have been caught at parse time */

	error:
		talloc_free(n);
		return rcode;
	}

	return 0;
}

#define DEBUG_OVERWRITE(_old, _new) \
do {\
	if (RDEBUG_ENABLED3) {\
		char *our_old; \
		char *our_new; \
		fr_pair_aprint_value_quoted(request, &our_old, _old, T_DOUBLE_QUOTED_STRING); \
		fr_pair_aprint_value_quoted(request, &our_new, _new, T_DOUBLE_QUOTED_STRING); \
		RINDENT(); \
		RDEBUG3("--> overwriting %s with %s", our_old, our_new); \
		REXDENT(); \
		talloc_free(our_old); \
		talloc_free(our_new); \
	} \
} while (0)

/** Convert #map_t to #fr_pair_t (s) and add them to a #request_t.
 *
 * Takes a single #map_t, resolves request and list identifiers
 * to pointers in the current request, then attempts to retrieve module
 * specific value(s) using callback, and adds the resulting values to the
 * correct request/list.
 *
 * @param request The current request.
 * @param map specifying destination attribute and location and src identifier.
 * @param func to retrieve module specific values and convert them to
 *	#fr_pair_t.
 * @param ctx to be passed to func.
 * @return
 *	- -1 if the operation failed.
 *	- -2 in the source attribute wasn't valid.
 *	- 0 on success.
 */
int map_to_request(request_t *request, map_t const *map, radius_map_getvalue_t func, void *ctx)
{
	int			rcode = 0;
	fr_pair_t		*dst;
	fr_pair_list_t		*list, src_list;
	request_t		*context, *tmp_ctx = NULL;
	TALLOC_CTX		*parent;
	fr_dcursor_t		dst_list;

	bool			found = false;

	map_t			exp_map;
	tmpl_t			*exp_lhs;
	fr_dict_attr_t const	*list_ref;

	tmpl_dcursor_ctx_t	cc = {};

	fr_pair_list_init(&src_list);
	MAP_VERIFY(map);
	fr_assert(map->lhs != NULL);
	fr_assert(map->rhs != NULL);

	/*
	 *	This function is called only when creating attributes.  It cannot be called for conditions.
	 */
	if (fr_comparison_op[map->op]) {
		REDEBUG("Invalid operator in %s %s ...", map->lhs->name, fr_tokens[map->op]);
		return -1;
	}

	tmp_ctx = talloc_pool(request, 1024);

	/*
	 *	Preprocessing of the LHS of the map.
	 */
	switch (map->lhs->type) {
	/*
	 *	Already in the correct form.
	 */
	case TMPL_TYPE_ATTR:
		break;

	/*
	 *	Everything else gets expanded, then re-parsed as an attribute reference.
	 *
	 *	This allows the syntax like:
	 *	- "Attr-%{number}" := "value"
	 */
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
	{
		char *attr_str;
		ssize_t slen;

		slen = tmpl_aexpand(request, &attr_str, request, map->lhs, NULL, NULL);
		if (slen <= 0) {
			RPEDEBUG("Left side expansion failed");
			fr_assert(!attr_str);
			rcode = -1;
			goto finish;
		}

		slen = tmpl_afrom_attr_str(tmp_ctx, NULL, &exp_lhs, attr_str,
					   &(tmpl_rules_t){
					   	.attr = {
							.dict_def = request->local_dict,
							.list_def = request_attr_request,
				   		}
					   });
		if (slen <= 0) {
			RPEDEBUG("Left side expansion result \"%s\" is not an attribute reference", attr_str);
			talloc_free(attr_str);
			rcode = -1;
			goto finish;
		}
		fr_assert(tmpl_is_attr(exp_lhs));

		memcpy(&exp_map, map, sizeof(exp_map));
		exp_map.lhs = exp_lhs;
		map = &exp_map;
	}
		break;

	default:
		fr_assert(0);
		break;
	}


	/*
	 *	Sanity check inputs.  We can have a list or attribute
	 *	as a destination.
	 */
	if (!tmpl_is_attr(map->lhs)) {
		REDEBUG("Left side \"%.*s\" of map should be an attr or list but is an %s",
			(int)map->lhs->len, map->lhs->name,
			tmpl_type_to_str(map->lhs->type));
		rcode = -2;
		goto finish;
	}

	context = request;
	if (tmpl_request_ptr(&context, tmpl_request(map->lhs)) < 0) {
		RPEDEBUG("Mapping \"%.*s\" -> \"%.*s\" cannot be performed due to error in left side of map",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name);
		rcode = -2;
		goto finish;
	}

	list_ref = tmpl_list(map->lhs);
	list = tmpl_list_head(context, list_ref);
	if (!list) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" cannot be performed due to to invalid list qualifier \"%s\" in left side of map",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name,
			tmpl_list_name(list_ref, "<INVALID>"));
		rcode = -2;
		goto finish;
	}

	parent = tmpl_list_ctx(context, tmpl_list(map->lhs));
	fr_assert(parent);

	/*
	 *	The callback should either return -1 to signify operations error,
	 *	-2 when it can't find the attribute or list being referenced, or
	 *	0 to signify success. It may return "success", but still have no
	 *	VPs to work with.
	 */
	rcode = func(parent, &src_list, request, map, ctx);
	if (rcode < 0) {
		fr_assert(fr_pair_list_empty(&src_list));
		goto finish;
	}
	if (fr_pair_list_empty(&src_list)) {
		RDEBUG2("%.*s skipped: No values available", (int)map->lhs->len, map->lhs->name);
		goto finish;
	}

	/*
	 *	Print the VPs
	 */
#ifndef WITH_VERIFY_PTR
	if (RDEBUG_ENABLED)
#endif
	{
		fr_pair_list_foreach(&src_list, vp) {
			PAIR_VERIFY(vp);

			if (RDEBUG_ENABLED) map_debug_log(request, map, vp);
		}
	}

	/*
	 *	The destination is a list (which is a completely different set of operations)
	 */
	if (tmpl_is_list(map->lhs)) {
		switch (map->op) {
		case T_OP_CMP_FALSE:
			/* We don't need the src VPs (should just be 'ANY') */
			fr_assert(fr_pair_list_empty(&src_list));

			/* Clear the entire dst list */
			fr_pair_list_free(list);
			goto finish;

		case T_OP_SET:
			if (tmpl_is_list(map->rhs)) {
				fr_pair_list_free(list);
				fr_pair_list_append(list, &src_list);
				fr_pair_list_init(&src_list);
			} else {
				FALL_THROUGH;

		case T_OP_EQ:
				fr_assert(tmpl_is_exec(map->rhs));
				FALL_THROUGH;

		case T_OP_ADD_EQ:
			fr_pair_list_move_op(list, &src_list, T_OP_ADD_EQ);
			}
			goto update;

		case T_OP_PREPEND:
			fr_pair_list_move_op(list, &src_list, T_OP_PREPEND);
			goto update;

		default:
			fr_pair_list_free(&src_list);
			rcode = -1;
			goto finish;
		}
	}

	/*
	 *	Find the destination attribute.  We leave with either
	 *	the dst_list and vp pointing to the attribute or the VP
	 *	being NULL (no attribute at that index).
	 */
	dst = tmpl_dcursor_init(NULL, tmp_ctx, &cc, &dst_list, request, map->lhs);
	/*
	 *	The destination is an attribute
	 */
	switch (map->op) {
	default:
		break;
	/*
	 * 	!* - Remove all attributes which match dst in the specified list.
	 *	This doesn't use attributes returned by the func(), and immediately frees them.
	 */
	case T_OP_CMP_FALSE:
		/* We don't need the src VPs (should just be 'ANY') */
		fr_assert(fr_pair_list_empty(&src_list));
		if (!dst) goto finish;

		/*
		 *	Wildcard: delete all of the matching ones
		 */
		if (tmpl_attr_tail_num(map->lhs) == NUM_UNSPEC) {
			fr_pair_delete_by_child_num(list, tmpl_attr_tail_da(map->lhs)->parent, tmpl_attr_tail_da(map->lhs)->attr);
			dst = NULL;
		/*
		 *	We've found the Nth one.  Delete it, and only it.
		 */
		} else {
			dst = fr_dcursor_remove(&dst_list);
			talloc_free(dst);
		}

		/*
		 *	Check that the User-Name and User-Password
		 *	caches point to the correct attribute.
		 */
		goto update;

	/*
	 *	-= - Delete attributes in the dst list which match any of the
	 *	src_list attributes.
	 *
	 *	This operation has two modes:
	 *	- If tmpl_attr_tail_num(map->lhs) > 0, we check each of the src_list attributes against
	 *	  the dst attribute, to see if any of their values match.
	 *	- If tmpl_attr_tail_num(map->lhs) == NUM_UNSPEC, we compare all instances of the dst attribute
	 *	  against each of the src_list attributes.
	 */
	case T_OP_SUB_EQ:
		/* We didn't find any attributes earlier */
		if (!dst) {
			fr_pair_list_free(&src_list);
			goto finish;
		}

		/*
		 *	Instance specific[n] delete
		 */
		if (tmpl_attr_tail_num(map->lhs) != NUM_UNSPEC) {
			fr_pair_list_foreach(&src_list, vp) {
				vp->op = T_OP_CMP_EQ;
				rcode = paircmp_pairs(request, vp, dst);
				if (rcode == 0) {
					dst = fr_dcursor_remove(&dst_list);
					talloc_free(dst);
					found = true;
				}
			}
			rcode = 0;
			fr_pair_list_free(&src_list);
			if (!found) goto finish;
			goto update;
		}

		/*
		 *	All instances[*] delete
		 */
		for (dst = fr_dcursor_current(&dst_list);
		     dst;
		     dst = fr_dcursor_filter_next(&dst_list, fr_pair_matches_da, tmpl_attr_tail_da(map->lhs))) {
			fr_pair_list_foreach(&src_list, vp) {
				vp->op = T_OP_CMP_EQ;
				rcode = paircmp_pairs(request, vp, dst);
				if (rcode == 0) {
					dst = fr_dcursor_remove(&dst_list);
					talloc_free(dst);
					found = true;
				}
			}
		}
		rcode = 0;
		fr_pair_list_free(&src_list);
		if (!found) goto finish;
		goto update;
	}

	switch (map->op) {
	/*
	 *	= - Set only if not already set
	 */
	case T_OP_EQ:
	{
		tmpl_attr_extent_t 	*extent = NULL;
		fr_dlist_head_t		leaf;
		fr_dlist_head_t		interior;
		fr_pair_t 		*src_vp;

		if (dst) {
			RDEBUG3("Refusing to overwrite (use :=)");
			fr_pair_list_free(&src_list);
			goto finish;
		}

		fr_dlist_talloc_init(&leaf, tmpl_attr_extent_t, entry);
		fr_dlist_talloc_init(&interior, tmpl_attr_extent_t, entry);

		/*
		 *	Find out what we need to build and build it
		 */
		if ((tmpl_extents_find(tmp_ctx, &leaf, &interior, request, map->lhs) < 0) ||
		    (tmpl_extents_build_to_leaf_parent(&leaf, &interior, map->lhs) < 0)) {
			fr_dlist_talloc_free(&leaf);
			fr_dlist_talloc_free(&interior);
			rcode = -1;
		    	goto finish;
		}

		/*
		 *	Need to copy src to all dsts
		 */
		src_vp = fr_pair_list_head(&src_list);
		if (!src_vp) {
			fr_dlist_talloc_free(&leaf);
			rcode = -1;
			goto finish;
		}

		if (fr_dlist_num_elements(&leaf) > 1) {
			while ((extent = fr_dlist_tail(&leaf))) {
				fr_pair_append(extent->list, fr_pair_copy(extent->list_ctx, src_vp));
				fr_dlist_talloc_free_tail(&leaf);
			}
		} else {
			extent = fr_dlist_head(&leaf);
			fr_pair_append(extent->list, fr_pair_copy(extent->list_ctx, src_vp));
			fr_dlist_talloc_free_head(&leaf);
		}

		/* Free any we didn't insert */
		fr_pair_list_free(&src_list);
		fr_assert(fr_dlist_num_elements(&interior) == 0);
		fr_assert(fr_dlist_num_elements(&leaf) == 0);
	}
		break;

	/*
	 *	:= - Overwrite existing attribute with last src_list attribute
	 */
	case T_OP_SET:
	{
		tmpl_attr_extent_t 	*extent = NULL;
		fr_dlist_head_t		leaf;
		fr_dlist_head_t		interior;
		fr_pair_t 		*src_vp;

		src_vp = fr_pair_list_tail(&src_list);

		if (dst) {
			DEBUG_OVERWRITE(dst, src_vp);

			fr_pair_reinit_from_da(NULL, dst, src_vp->da);
			fr_pair_value_copy(dst, src_vp);

			goto op_set_done;
		}

		fr_dlist_talloc_init(&leaf, tmpl_attr_extent_t, entry);
		fr_dlist_talloc_init(&interior, tmpl_attr_extent_t, entry);

		/*
		 *	Find out what we need to build and build it
		 */
		if ((tmpl_extents_find(tmp_ctx, &leaf, &interior, request, map->lhs) < 0) ||
		    (tmpl_extents_build_to_leaf_parent(&leaf, &interior, map->lhs) < 0)) {
		    op_set_error:
			fr_dlist_talloc_free(&leaf);
			fr_dlist_talloc_free(&interior);
			rcode = -1;
		    	goto finish;
		}

		if (fr_dlist_num_elements(&leaf) > 1) {
			ERROR("Not yet supported");

			goto op_set_error;
		} else {
			extent = fr_dlist_head(&leaf);
			fr_pair_append(extent->list, fr_pair_copy(extent->list_ctx, src_vp));
		}

		fr_assert(fr_dlist_num_elements(&interior) == 0);
		fr_dlist_talloc_free(&leaf);

	op_set_done:
		/* Free any we didn't insert */
		fr_pair_list_free(&src_list);
	}
		break;

	/*
	 *	^= - Prepend src_list attributes to the destination
	 */
	case T_OP_PREPEND:
		fr_pair_list_prepend(list, &src_list);
		fr_pair_list_free(&src_list);
		break;

	/*
	 *	+= - Add all src_list attributes to the destination
	 */
	case T_OP_ADD_EQ:
	{
		tmpl_attr_extent_t 	*extent = NULL;
		fr_dlist_head_t		leaf;
		fr_dlist_head_t		interior;

		fr_dlist_talloc_init(&leaf, tmpl_attr_extent_t, entry);
		fr_dlist_talloc_init(&interior, tmpl_attr_extent_t, entry);

		/*
		 *	Find out what we need to build and build it
		 */
		if ((tmpl_extents_find(tmp_ctx, &leaf, &interior, request, map->lhs) < 0) ||
		    (tmpl_extents_build_to_leaf_parent(&leaf, &interior, map->lhs) < 0)) {
			fr_dlist_talloc_free(&leaf);
			fr_dlist_talloc_free(&interior);
			rcode = -1;
		    	goto finish;
		}

		if (fr_dlist_num_elements(&leaf) > 1) {
			while ((extent = fr_dlist_tail(&leaf))) {
				(void) fr_pair_list_copy(extent->list_ctx, extent->list, &src_list);
				fr_dlist_talloc_free_tail(&leaf);
			}
			/* Free all the src vps */
			fr_pair_list_free(&src_list);
		} else {
			extent = fr_dlist_head(&leaf);
			(void) fr_pair_list_copy(extent->list_ctx, extent->list, &src_list);
			fr_dlist_talloc_free_head(&leaf);
		}

		fr_pair_list_free(&src_list);
		fr_assert(fr_dlist_num_elements(&interior) == 0);
		fr_assert(fr_dlist_num_elements(&leaf) == 0);
	}
		break;

	/*
	 *	Filter operators
	 */
	case T_OP_NE:
	case T_OP_CMP_EQ:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
	{
		fr_pair_t *a;

		fr_pair_list_sort(&src_list, fr_pair_cmp_by_da);
		fr_pair_list_sort(list, fr_pair_cmp_by_da);

		fr_dcursor_head(&dst_list);

		fr_pair_list_foreach(&src_list, b) {
			for (a = fr_dcursor_current(&dst_list);
			     a;
			     a = fr_dcursor_next(&dst_list)) {
				int8_t cmp;

				cmp = fr_pair_cmp_by_da(a, b);	/* attribute and tag match */
				if (cmp > 0) break;
				else if (cmp < 0) continue;

				cmp = (fr_value_box_cmp_op(map->op, &a->data, &b->data) == 0);
				if (cmp != 0) {
					a = fr_dcursor_remove(&dst_list);
					talloc_free(a);
				}
			}
			if (!a) break;	/* end of the list */
		}
		fr_pair_list_free(&src_list);
	}
		break;

	default:
		fr_assert(0);	/* Should have been caught be the caller */
		rcode = -1;
		goto finish;
	}

update:
	fr_assert(fr_pair_list_empty(&src_list));

finish:
	tmpl_dcursor_clear(&cc);
	talloc_free(tmp_ctx);
	return rcode;
}

/** Print a map to a string
 *
 * @param[out] out	Buffer to write string to.
 * @param[in] map	to print.
 * @return
 *	- The number of bytes written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
ssize_t map_print(fr_sbuff_t *out, map_t const *map)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);

	MAP_VERIFY(map);

	/*
	 *	Print the lhs
	 */
	if (tmpl_rules_cast(map->lhs)) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "<%s>",
					   fr_type_to_str(tmpl_rules_cast(map->lhs)));
	}
	FR_SBUFF_RETURN(tmpl_print_quoted, &our_out, map->lhs);

	/*
	 *	Print separators and operator
	 */
	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ');
	FR_SBUFF_IN_STRCPY_RETURN(&our_out, fr_token_name(map->op));
	FR_SBUFF_IN_CHAR_RETURN(&our_out, ' ');

	/*
	 *	The RHS doesn't matter for many operators
	 */
	if ((map->op == T_OP_CMP_TRUE) || (map->op == T_OP_CMP_FALSE)) {
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, "ANY");
		FR_SBUFF_SET_RETURN(out, &our_out);
	}

	/*
	 *	If there's no child and no RHS then the
	 *	map was invalid.
	 */
	if (map_list_empty(&map->child) && !fr_cond_assert(map->rhs != NULL)) {
		fr_sbuff_terminate(out);
		return 0;
	}

	if (tmpl_rules_cast(map->rhs)) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "<%s>",
					   fr_type_to_str(tmpl_rules_cast(map->rhs)));
	}

	/*
	 *	Print the RHS.
	 */
	FR_SBUFF_RETURN(tmpl_print_quoted, &our_out, map->rhs);

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/*
 *	Debug print a map / VP
 */
void map_debug_log(request_t *request, map_t const *map, fr_pair_t const *vp)
{
	char *rhs = NULL, *value = NULL;
	char buffer[256];

	MAP_VERIFY(map);
	if (!fr_cond_assert(map->lhs != NULL)) return;
	if (!fr_cond_assert(map->rhs != NULL)) return;

	fr_assert(vp);

	switch (map->rhs->type) {
	/*
	 *	Just print the value being assigned
	 */
	default:
	case TMPL_TYPE_DATA_UNRESOLVED:
		fr_pair_aprint_value_quoted(request, &rhs, vp, map->rhs->quote);
		break;

	case TMPL_TYPE_XLAT:
		fr_pair_aprint_value_quoted(request, &rhs, vp, map->rhs->quote);
		break;

	case TMPL_TYPE_DATA:
		fr_pair_aprint_value_quoted(request, &rhs, vp, map->rhs->quote);
		break;

	case TMPL_TYPE_ATTR:
	{
		fr_token_t	quote;

		switch (vp->vp_type) {
		case FR_TYPE_QUOTED:
			quote = T_DOUBLE_QUOTED_STRING;
			break;
		default:
			quote = T_BARE_WORD;
			break;
		}

		/*
		 *	Not appropriate to use map->rhs->quote here, as that's the quoting
		 *	around the attr ref. The attribute value has no quoting, so we choose
		 *	the quoting based on the data type.
		 */
		fr_pair_aprint_value_quoted(request, &value, vp, quote);
		tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map->rhs, NULL);
		rhs = talloc_typed_asprintf(request, "%s -> %s", buffer, value);
	}
		break;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
		tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map->lhs, NULL);
		RDEBUG2("%s %s %s", buffer, fr_table_str_by_value(fr_tokens_table, vp ? vp->op : map->op, "<INVALID>"), rhs);
		break;

	default:
		break;
	}

	/*
	 *	Must be LIFO free order so we don't leak pool memory
	 */
	talloc_free(rhs);
	talloc_free(value);
}

/** Convert a fr_pair_t into a map
 *
 * @param[in] ctx		where to allocate the map.
 * @param[out] out		Where to write the new map (must be freed with talloc_free()).
 * @param[in,out] parent_p	the parent map, updated for relative maps
 * @param[in] request		the request
 * @param[in] lhs		of map
 * @param[in] op_str		operator for map
 * @param[in] rhs		of map
 * @param[in] lhs_rules		for parsing the LHS
 * @param[in] rhs_rules		for parsing the RHS
 * @param[in] bare_word_only	RHS is bare words, and nothing else.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_afrom_fields(TALLOC_CTX *ctx, map_t **out, map_t **parent_p, request_t *request,
		     char const *lhs, char const *op_str, char const *rhs,
		     tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules, bool bare_word_only)
{
	ssize_t		slen;
	fr_token_t	quote, op;
	map_t		*map;
	map_t		*parent = *parent_p;
	tmpl_rules_t	my_rules;

	op = fr_table_value_by_str(fr_tokens_table, op_str, T_INVALID);
	if (op == T_INVALID) {
		fr_strerror_printf("Invalid operator '%s'", op_str);
		return -1;
	}

	/*
	 *	Reply items can be expanded.  Check items cannot be,
	 *	unless the operator is a comparison operator.
	 */
	if (!bare_word_only) {
		if (!fr_assignment_op[op]) {
			fr_assert(0);
			fr_strerror_printf("Invalid operator '%s' for assignment in reply item", op_str);
			return -1;
		}

	} else if (!fr_assignment_op[op] && !fr_comparison_op[op]) {
		if (!fr_assignment_op[op]) {
			fr_strerror_printf("Invalid operator '%s' for check item", op_str);
			return -1;
		}
	}

	my_rules = *lhs_rules;
	lhs_rules = &my_rules;

	/*
	 *	We're only called from SQL.  If the default list is request, then we only use that for
	 *	comparisons.  We rewrite assignments to use the control list.
	 *
	 *	@todo - as we expand the use of this function, perhaps add another argument which controls
	 *	this flag.  But this function already has parameter overload :(
	 */
	if (fr_assignment_op[op] && (lhs_rules->attr.list_def == request_attr_request)) {
		my_rules.attr.list_def = request_attr_control;
	}

	/*
	 *	One '.' means "the current parent".
	 */
	if (*lhs == '.') {
		if (!parent) {
		no_parent:
			fr_strerror_const("Unexpected location for relative attribute - no parent attribute exists");
			return -1;
		}
		lhs++;

		/*
		 *	Multiple '.' means "go to our parents parent".
		 */
		while (*lhs == '.') {
			if (!parent) goto no_parent;

			parent = parent->parent;
			lhs++;
		}

		/*
		 *	Child elements can only be "=".
		 */
		if (parent) {
			if (fr_comparison_op[op]) {
				fr_strerror_const("Comparison operators cannot be used inside of structural data types");
				return -1;
			}

			if (op != T_OP_EQ) {
				fr_strerror_const("Invalid operator inside of structural data type - must be '='");
				return -1;
			}
		}
	}

	MEM(map = map_alloc(ctx, parent));
	map->op = op;

	/*
	 *	Start looking in the correct parent, not in whatever we were handed.
	 */
	if (parent) {
		fr_assert(tmpl_is_attr(parent->lhs));
		my_rules.attr.namespace = tmpl_attr_tail_da(parent->lhs);

		slen = tmpl_afrom_attr_substr(map, NULL, &map->lhs, &FR_SBUFF_IN_STR(lhs),
					      &map_parse_rules_bareword_quoted, lhs_rules);
	} else {
		/*
		 *	There's no '.', so this
		 *	attribute MUST come from the
		 *	root of the dictionary tree.
		 */
		parent = NULL;

		/*
		 *	Allocate the LHS, which must be an attribute.
		 *
		 *	@todo - track relative attributes, which begin with a '.'
		 */
		slen = tmpl_afrom_attr_str(ctx, NULL, &map->lhs, lhs, lhs_rules);
	}
	if (slen <= 0) {
	error:
		talloc_free(map);
		return -1;
	}

	if (tmpl_attr_tail_is_unknown(map->lhs) && tmpl_attr_unknown_add(map->lhs) < 0) {
		fr_strerror_printf("Failed creating attribute %s", map->lhs->name);
		goto error;
	}

	my_rules = *rhs_rules;
	my_rules.at_runtime = true;
	my_rules.xlat.runtime_el = unlang_interpret_event_list(request);
	my_rules.enumv = tmpl_attr_tail_da(map->lhs);

	/*
	 *	LHS is a structureal type.  The RHS is either empty (create empty LHS), or it's a string
	 *	containing a list of attributes to create.
	 */
	if (!fr_type_is_leaf(my_rules.enumv->type)) {
		my_rules.enumv = NULL;
	}

	/*
	 *	Try to figure out what we should do with the RHS.
	 */
	if ((map->op == T_OP_CMP_TRUE) || (map->op == T_OP_CMP_FALSE)) {
		/*
		 *	These operators require a hard-coded string on the RHS.
		 */
		if (strcmp(rhs, "ANY") != 0) {
			fr_strerror_printf("Invalid value %s for operator %s", rhs, fr_tokens[map->op]);
			goto error;
		}

		if (tmpl_afrom_value_box(map, &map->rhs, fr_box_strvalue("ANY"), false) < 0) goto error;

	} else if (bare_word_only) {
		fr_value_box_t *vb;

		/*
		 *	No value, or no enum, parse it as a bare-word string.
		 */
		if (!rhs[0] || !my_rules.enumv) goto do_bare_word;

		MEM(vb = fr_value_box_alloc(map, my_rules.enumv->type, my_rules.enumv));

		/*
		 *	It MUST be the given data type.
		 */
		slen = fr_value_box_from_str(map, vb, my_rules.enumv->type, my_rules.enumv,
					     rhs, strlen(rhs), NULL);
		if (slen <= 0) goto error;

		if (tmpl_afrom_value_box(map, &map->rhs, vb, true) < 0) {
			goto error;
		}

	} else if (rhs[0] == '"') {
		/*
		 *	We've been asked to expand the RHS.  Passwords like
		 *
		 *		"%{Calling-Station-ID}"
		 *
		 *	might not do what you want.
		 */
		quote = T_DOUBLE_QUOTED_STRING;
		goto parse_quoted;

	} else if (rhs[0] == '\'') {
		size_t len;

		quote = T_SINGLE_QUOTED_STRING;

	parse_quoted:
		len = strlen(rhs + 1);
		if (len == 1) {
			if (rhs[1] != rhs[0]) {
				fr_strerror_const("Invalid string on right side");
				return -1;
			}

			rhs = "";
			goto alloc_empty;
		}

		slen = tmpl_afrom_substr(map, &map->rhs, &FR_SBUFF_IN(rhs + 1, len - 1),
					 quote, value_parse_rules_quoted[quote], &my_rules);
		if (slen < 0) {
			REDEBUG3("Failed parsing right-hand side as quoted string.");
		fail_rhs:
			fr_strerror_printf("Failed parsing right-hand side: %s", fr_strerror());
			goto error;
		}

		if (slen == 0) {
			rhs = "";
			goto alloc_empty;
		}

		/*
		 *	Ignore any extra data after the string.
		 *
		 *	@todo - this should likely be a parse error: we didn't parse the entire string!
		 */

	} else if (rhs[0] == '&') {
		/*
		 *	No enums here.
		 */
		fr_assert(my_rules.attr.list_def == request_attr_request);

	parse_as_attr:
		my_rules.enumv = NULL;

		slen = tmpl_afrom_attr_str(map, NULL, &map->rhs, rhs, &my_rules);
		if (slen <= 0) {
			REDEBUG3("Failed parsing right-hand side as attribute.");
			goto fail_rhs;
		}

	} else if (!rhs[0] || !my_rules.enumv || (my_rules.enumv->type == FR_TYPE_STRING)) {
	do_bare_word:
		quote = T_BARE_WORD;

		if (tmpl_attr_tail_da_is_structural(map->lhs) && !*rhs) goto done;

	alloc_empty:
		MEM(map->rhs = tmpl_alloc(map, TMPL_TYPE_DATA, quote, rhs, strlen(rhs)));

		/*
		 *	Create it when we have
		 *
		 *		my-struct = ""
		 */
		(void) fr_value_box_strdup(map->rhs, tmpl_value(map->rhs), NULL, rhs, false);

	} else {
		/*
		 *	Parse it as the given data type.
		 */
		slen = tmpl_afrom_substr(map, &map->rhs, &FR_SBUFF_IN_STR(rhs),
					 T_BARE_WORD, value_parse_rules_unquoted[T_BARE_WORD], &my_rules);
		if (slen <= 0) {
			goto parse_as_attr;
		}

		/*
		 *	Xlat expansions are cast to strings for structural data types.
		 */
		if (tmpl_attr_tail_da_is_structural(map->lhs) && (tmpl_is_xlat(map->rhs))) {
			tmpl_cast_set(map->rhs, FR_TYPE_STRING);
		}
	}

	if (tmpl_needs_resolving(map->rhs)) {
		tmpl_res_rules_t tr_rules = (tmpl_res_rules_t) {
			.dict_def = lhs_rules->attr.dict_def,
			.enumv = tmpl_attr_tail_da(map->lhs)
		};

		fr_assert(tmpl_is_data_unresolved(map->rhs));

		if (tmpl_resolve(map->rhs, &tr_rules) < 0) {
			REDEBUG3("Failed resolving right-hand side.");
			goto fail_rhs;
		}
	}

	/*
	 *	@todo - check that the entire string was parsed.
	 */

done:
	/*
	 *	If the tail is a leaf, we don't change parent.
	 *	Otherwise the structural attribute is the new parent.
	 */
	if (tmpl_attr_tail_da_is_leaf(map->lhs)) {
		*parent_p = parent;
	} else {
		*parent_p = map;
	}

	MAP_VERIFY(map);

	if (parent) map_list_insert_tail(&parent->child, map);
	*out = map;

	return 0;
}
