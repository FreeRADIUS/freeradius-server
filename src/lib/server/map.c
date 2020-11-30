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
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/cond.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

#ifdef DEBUG_MAP
static void map_dump(request_t *request, map_t const *map)
{
	RDEBUG2(">>> MAP TYPES LHS: %s, RHS: %s",
	        fr_table_str_by_value(tmpl_type_table, map->lhs->type, "???"),
	        fr_table_str_by_value(tmpl_type_table, map->rhs->type, "???"));

	if (map->rhs) {
		RDEBUG2(">>> MAP NAMES %s %s", map->lhs->name, map->rhs->name);
	}
}
#endif

static inline map_t *map_alloc(TALLOC_CTX *ctx)
{
	return talloc_zero(ctx, map_t);
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
 * @param[in] cp		to convert to map.
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @return
 *	- #map_t if successful.
 *	- NULL on error.
 */
int map_afrom_cp(TALLOC_CTX *ctx, map_t **out, CONF_PAIR *cp,
		 tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules)
{
	map_t	*map;
	char const	*attr, *value, *marker_subject;
	ssize_t		slen;
	fr_token_t	type;

	*out = NULL;

	if (!cp) return -1;

	MEM(map = talloc_zero(ctx, map_t));
	map->op = cf_pair_operator(cp);
	map->ci = cf_pair_to_item(cp);

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err(cp, "Missing attribute value");
		goto error;
	}

	/*
	 *	LHS may be an expansion (that expands to an attribute reference)
	 *	or an attribute reference. Quoting determines which it is.
	 */
	type = cf_pair_attr_quote(cp);
	switch (type) {
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
		slen = tmpl_afrom_substr(ctx, &map->lhs,
					 &FR_SBUFF_IN(attr, talloc_array_length(attr) - 1),
					 type,
					 tmpl_parse_rules_unquoted[type],	/* We're not searching for quotes */
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
			cf_log_err(cp, "Failed parsing attribute reference");
			marker_subject = attr;
			goto marker;
		}

		if (tmpl_is_attr(map->lhs) && tmpl_attr_unknown_add(map->lhs) < 0) {
			cf_log_perr(cp, "Failed creating attribute %s", map->lhs->name);
			goto error;
		}
		break;
	}

	/*
	 *	RHS might be an attribute reference.
	 */
	type = cf_pair_value_quote(cp);

	slen = tmpl_afrom_substr(map, &map->rhs,
				 &FR_SBUFF_IN(value, strlen(value)),
				 type,
				 tmpl_parse_rules_unquoted[type],	/* We're not searching for quotes */
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
	    (tmpl_num(map->rhs) == NUM_COUNT)) {
		cf_log_err(cp, "Cannot assign from a count");
		goto error;
	}

	MAP_VERIFY(map);

	*out = map;

	return 0;

error:
	talloc_free(map);
	return -1;
}

fr_table_num_sorted_t const map_assignment_op_table[] = {
	{ L("!*"),	T_OP_CMP_FALSE		},
	{ L("!="),	T_OP_NE			},
	{ L("!~"),	T_OP_REG_NE		},
	{ L("+="),	T_OP_ADD		},
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
	[T_DOUBLE_QUOTED_STRING]	= &tmpl_parse_rules_double_quoted,
	[T_SINGLE_QUOTED_STRING]	= &tmpl_parse_rules_single_quoted,
	[T_SOLIDUS_QUOTED_STRING]	= &tmpl_parse_rules_solidus_quoted,
	[T_BACK_QUOTED_STRING]		= &tmpl_parse_rules_backtick_quoted
};

/** Parse sbuff into (which may contain refs) to map_t.
 *
 * Treats the left operand as an attribute reference
 * @verbatim<request>.<list>.<attribute>@endverbatim
 *
 * Treatment of left operand depends on quotation, barewords are treated as
 * attribute references, double quoted values are treated as expandable strings,
 * single quoted values are treated as literal strings.
 *
 *  The op_table should be #cond_cmp_op_table for check items, and
 *  #map_assignment_op_table for reply items.
 *
 * Return must be freed with talloc_free
 *
 * @param[in] ctx		for talloc.
 * @param[in] out		Where to write the pointer to the new #map_t.
 * @param[in] in		to convert to map.
 * @param[in] op_table		for lhs OP rhs
 * @param[in] op_table_len	length of op_table
 * @param[in] lhs_rules		rules for parsing LHS attribute references.
 * @param[in] rhs_rules		rules for parsing RHS attribute references.
 * @param[in] rhs_term		terminating rules for the RHS
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int map_afrom_sbuff(TALLOC_CTX *ctx, map_t **out, fr_sbuff_t *in,
		    fr_table_num_sorted_t const *op_table, size_t op_table_len,
		    tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
		    fr_sbuff_parse_rules_t const *rhs_term)
{
	ssize_t		slen;
	fr_token_t	token;
	map_t		*map;
	fr_sbuff_t	sbuff = FR_SBUFF_NO_ADVANCE(in);

	*out = NULL;
	MEM(map = talloc_zero(ctx, map_t));

	slen = fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX);
	if (slen < 0) return -1;

	fr_sbuff_out_by_longest_prefix(&slen, &token, cond_quote_table, &sbuff, T_BARE_WORD);
	switch (token) {
	case T_SOLIDUS_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
		slen = tmpl_afrom_substr(map, &map->lhs, &sbuff, token,
					 tmpl_parse_rules_quoted[token], lhs_rules);
		break;

	default:
		slen = tmpl_afrom_attr_substr(map, NULL, &map->lhs, &sbuff,
					      &map_parse_rules_bareword_quoted, lhs_rules);
		break;
	}

	if (slen < 0) {
	error:
		talloc_free(map);
		return -1;
	}

	/*
	 *	We didn't parse anything from the LHS, that's OK.  The
	 *	input must be empty.
	 */
	if (slen == 0) {
		talloc_free(map);
		*out = NULL;
		return 0;
	}

	/*
	 *	Check for, and skip, the trailing quote if we had a leading quote.
	 */
	if (token != T_BARE_WORD) {
		if (!fr_sbuff_is_char(&sbuff, fr_token_quote[token])) {
			fr_strerror_printf("Unexpected end of quoted string");
			return -1;
		}

		fr_sbuff_advance(&sbuff, 1);

		/*
		 *	The tmpl code does NOT return tmpl_type_data
		 *	for string data without xlat.  Instead, it
		 *	creates TMPL_TYPE_UNRESOLVED.
		 */
		if (tmpl_resolve(map->lhs) < 0) goto error;
	}

	slen = fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX);
	if (slen < 0) {
		fr_strerror_printf("Unexpected end of string after parsing left side");
		goto error;
	}

	/*
	 *	Parse operator.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &map->op, op_table, &sbuff, 0);
	if (slen <= 0) {
		fr_strerror_printf("Invalid operator");
		goto error;
	}

	slen = fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX);
	if (slen < 0) {
		fr_strerror_printf("Unexpected end of string after operator");
		goto error;
	}

	/*
	 *	Copy LHS code above, except parsing in RHS, with some
	 *	minor modifications.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &token, cond_quote_table, &sbuff, T_BARE_WORD);
	switch (token) {
	case T_SOLIDUS_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
		slen = tmpl_afrom_substr(map, &map->rhs, &sbuff, token,
					 tmpl_parse_rules_quoted[token], rhs_rules);
		break;

	default:
		if (!rhs_term) rhs_term = &tmpl_parse_rules_bareword_quoted;

		/*
		 *	Use the RHS termination rules ONLY for bare
		 *	words.  For quoted strings we already know how
		 *	to terminate the input string.
		 */
		slen = tmpl_afrom_substr(map, &map->rhs, &sbuff, token, rhs_term, rhs_rules);
		break;
	}
	if (slen < 0) goto error;

	if (slen == 0) {
		fr_strerror_printf("Unexpected end of input after operator");
		goto error;
	}
	fr_assert(map->rhs != NULL);

	/*
	 *	Check for, and skip, the trailing quote if we had a leading quote.
	 */
	if (token != T_BARE_WORD) {
		if (!fr_sbuff_is_char(&sbuff, fr_token_quote[token])) {
			fr_strerror_printf("Unexpected end of quoted string");
			return -1;
		}

		fr_sbuff_advance(&sbuff, 1);

		/*
		 *	The tmpl code does NOT return tmpl_type_data
		 *	for string data without xlat.  Instead, it
		 *	creates TMPL_TYPE_UNRESOLVED.
		 */
		if (tmpl_resolve(map->rhs) < 0) goto error;

	} else if (tmpl_is_attr(map->lhs) && (tmpl_is_unresolved(map->rhs) || tmpl_is_data(map->rhs))) {
		/*
		 *	If the operator is "true" or "false", just
		 *	cast the RHS to string, as no one will care
		 *	about it.
		 */
		if ((map->op != T_OP_CMP_TRUE) && (map->op != T_OP_CMP_FALSE)) {
			fr_dict_attr_t const *da = tmpl_da(map->lhs);

			if (tmpl_cast_in_place(map->rhs, da->type, da) < 0) goto error;
		} else {
			if (tmpl_cast_in_place(map->rhs, FR_TYPE_STRING, NULL) < 0) goto error;
		}
	}

	fr_sbuff_set(in, &sbuff);
	MAP_VERIFY(map);
	*out = map;

	return 0;
}


/** Convert an 'update' config section into an attribute map.
 *
 * Uses 'name2' of section to set default request and lists.
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
int map_afrom_cs(TALLOC_CTX *ctx, map_t **out, CONF_SECTION *cs,
		 tmpl_rules_t const *lhs_rules, tmpl_rules_t const *rhs_rules,
		 map_validate_t validate, void *uctx,
		 unsigned int max)
{
	char const	*cs_list, *p;

	CONF_ITEM 	*ci;
	CONF_PAIR 	*cp;

	unsigned int 	total = 0;
	map_t	**tail, *map;
	TALLOC_CTX	*parent;

	tmpl_rules_t	our_lhs_rules = *lhs_rules;	/* Mutable copy of the destination */

	*out = NULL;
	tail = out;

	/*
	 *	The first map has ctx as the parent.
	 *	The rest have the previous map as the parent.
	 */
	parent = ctx;

	ci = cf_section_to_item(cs);

	/*
	 *	Check the destination list for "update" sections.
	 */
	cs_list = p = cf_section_name2(cs);
	if (cs_list && (strcmp(cf_section_name1(cs), "update") == 0)) {
		p += radius_request_name(&our_lhs_rules.request_def, p, REQUEST_CURRENT);
		if (our_lhs_rules.request_def == REQUEST_UNKNOWN) {
			cf_log_err(ci, "Default request specified in mapping section is invalid");
			return -1;
		}

		our_lhs_rules.list_def = fr_table_value_by_str(pair_list_table, p, PAIR_LIST_UNKNOWN);
		if (our_lhs_rules.list_def == PAIR_LIST_UNKNOWN) {
			cf_log_err(ci, "Default list \"%s\" specified in mapping section is invalid", p);
			return -1;
		}
	}

	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		if (total++ == max) {
			cf_log_err(ci, "Map size exceeded");
		error:
			TALLOC_FREE(*out);
			return -1;
		}

		/*
		 *	If we have a subsection, AND the name2 is an
		 *	assignment operator, THEN we allow sub-maps.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *subcs;
			fr_token_t token;
			ssize_t slen;
			bool qualifiers = our_lhs_rules.disallow_qualifiers;

			subcs = cf_item_to_section(ci);
			token = cf_section_name2_quote(subcs);

			if (!fr_assignment_op[token]) {
				cf_log_err(ci, "Invalid operator '%s'", fr_tokens[token]);
				goto error;
			}

			MEM(map = map_alloc(parent));
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
				cf_log_err(ci, "Failed parsing attribute reference");
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

			if (tmpl_da(map->lhs)->flags.is_unknown) {
				cf_log_err(ci, "Unknown attribute '%s'", map->lhs->name);
				talloc_free(map);
				goto error; /* re-do "goto marker" stuff to print out spaces ? */
			}

			/*
			 *	Disallow list qualifiers for the child
			 *	templates.  The syntax requires that
			 *	the child attributes go into the
			 *	parent one.
			 */
			our_lhs_rules.disallow_qualifiers = true;

			/*
			 *	The leaf reference of the outer section
			 *	is used as the parsing context of the
			 *	inner section.
			 */
			our_lhs_rules.attr_parent = tmpl_da(map->lhs);
			our_lhs_rules.prefix = TMPL_ATTR_REF_PREFIX_NO;

			/*
			 *	This prints out any relevant error
			 *	messages.  We MAY want to print out
			 *	additional ones, but that might get
			 *	complex and confusing.
			 */
			if (map_afrom_cs(map, &map->child, cf_item_to_section(ci),
					 &our_lhs_rules, rhs_rules, validate, uctx, max) < 0) {
				talloc_free(map);
				goto error;
			}

			our_lhs_rules.disallow_qualifiers = qualifiers;
			MAP_VERIFY(map);
			goto next;
		}

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"attribute = value\" format");
			goto error;
		}

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		if (map_afrom_cp(parent, &map, cp, &our_lhs_rules, rhs_rules) < 0) {
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
		parent = *tail = map;
		tail = &(map->next);
	}

	return 0;

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

	map = talloc_zero(ctx, map_t);

	slen = tmpl_afrom_substr(map, &map->lhs,
				 &FR_SBUFF_IN(lhs, strlen(lhs)),
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

	if (map_afrom_sbuff(ctx, out, &sbuff, map_assignment_op_table, map_assignment_op_table_len,
			    lhs_rules, rhs_rules, NULL) < 0) {
		return -1;
	}

	if (!fr_cond_assert(*out != NULL)) return -1;

	if (!tmpl_is_attr((*out)->lhs)) {
		TALLOC_FREE(*out);
		fr_strerror_printf("Left operand must be an attribute");
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

	map_t *map;

	map = map_alloc(ctx);
	if (!map) {
	oom:
		fr_strerror_printf("Out of memory");
		return -1;
	}

	/*
	 *	Allocate the LHS
	 */
	map->lhs = tmpl_alloc(map, TMPL_TYPE_ATTR, T_BARE_WORD, NULL, 0);
	if (!map->lhs) goto oom;

	tmpl_attr_set_leaf_da(map->lhs, vp->da);
	tmpl_attr_set_leaf_num(map->lhs, NUM_ANY);

	tmpl_attr_set_request(map->lhs, rules->request_def);
	tmpl_attr_set_list(map->lhs, rules->list_def);

	tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map->lhs, TMPL_ATTR_REF_PREFIX_YES, NULL);
	tmpl_set_name(map->lhs, T_BARE_WORD, buffer, -1);

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

	fr_value_box_copy(map->rhs, tmpl_value(map->rhs), &vp->data);

	*out = map;

	return 0;
}

static void map_sort_split(map_t *source, map_t **front, map_t **back)
{
	map_t *fast;
	map_t *slow;

	/*
	 *	Stopping condition - no more elements left to split
	 */
	if (!source || !source->next) {
		*front = source;
		*back = NULL;

		return;
	}

	/*
	 *	Fast advances twice as fast as slow, so when it gets to the end,
	 *	slow will point to the middle of the linked list.
	 */
	slow = source;
	fast = source->next;

	while (fast) {
		fast = fast->next;
		if (fast) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*front = source;
	*back = slow->next;
	slow->next = NULL;
}

static map_t *map_sort_merge(map_t *a, map_t *b, fr_cmp_t cmp)
{
	map_t *result = NULL;

	if (!a) return b;
	if (!b) return a;

	/*
	 *	Compare things in the maps
	 */
	if (cmp(a, b) <= 0) {
		result = a;
		result->next = map_sort_merge(a->next, b, cmp);
	} else {
		result = b;
		result->next = map_sort_merge(a, b->next, cmp);
	}

	return result;
}

/** Sort a linked list of #map_t using merge sort
 *
 * @param[in,out] maps List of #map_t to sort.
 * @param[in] cmp to sort with
 */
void map_sort(map_t **maps, fr_cmp_t cmp)
{
	map_t *head = *maps;
	map_t *a;
	map_t *b;

	/*
	 *	If there's 0-1 elements it must already be sorted.
	 */
	if (!head || !head->next) {
		return;
	}

	map_sort_split(head, &a, &b);	/* Split into sublists */
	map_sort(&a, cmp);		/* Traverse left */
	map_sort(&b, cmp);		/* Traverse right */

	/*
	 *	merge the two sorted lists together
	 */
	*maps = map_sort_merge(a, b, cmp);
}

/** Process map which has exec as a src
 *
 * Evaluate maps which specify exec as a src. This may be used by various sorts of update sections, and so
 * has been broken out into it's own function.
 *
 * @param[in,out] ctx to allocate new #fr_pair_t (s) in.
 * @param[out] out Where to write the #fr_pair_t (s).
 * @param[in] request structure (used only for talloc).
 * @param[in] map the map. The LHS (dst) must be #TMPL_TYPE_ATTR or #TMPL_TYPE_LIST.
 *	The RHS (src) must be #TMPL_TYPE_EXEC.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int map_exec_to_vp(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request, map_t const *map)
{
	int result;
	char *expanded = NULL;
	char answer[1024];
	fr_pair_list_t *input_pairs = NULL;
	fr_pair_list_t output_pairs;

	fr_pair_list_init(&output_pairs);
	*out = NULL;

	MAP_VERIFY(map);

	fr_assert(map->rhs);		/* Quite clang scan */
	fr_assert(tmpl_is_exec(map->rhs));
	fr_assert(tmpl_is_attr(map->lhs) || tmpl_is_list(map->lhs));

	/*
	 *	We always put the request pairs into the environment
	 */
	input_pairs = radius_list(request, PAIR_LIST_REQUEST);

	/*
	 *	Automagically switch output type depending on our destination
	 *	If dst is a list, then we create attributes from the output of the program
	 *	if dst is an attribute, then we create an attribute of that type and then
	 *	call fr_pair_value_from_str on the output of the script.
	 */
	result = radius_exec_program(ctx, answer, sizeof(answer),
				     tmpl_is_list(map->lhs) ? &output_pairs : NULL,
				     request, map->rhs->name, input_pairs ? *input_pairs : NULL,
				     true, true, fr_time_delta_from_sec(EXEC_TIMEOUT));
	talloc_free(expanded);
	if (result != 0) {
		REDEBUG("Exec failed with code (%i)", result);
		talloc_free(output_pairs);
		return -1;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_LIST:
		if (!output_pairs) {
			REDEBUG("No valid attributes received from program");
			return -2;
		}
		*out = output_pairs;
		return 0;

	case TMPL_TYPE_ATTR:
	{
		fr_pair_t *vp;

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_da(map->lhs)));
		vp->op = map->op;
		if (fr_pair_value_from_str(vp, answer, -1, '"', false) < 0) {
			RPEDEBUG("Failed parsing exec output");
			fr_pair_list_free(&vp);
			return -2;
		}
		*out = vp;

		return 0;
	}

	default:
		fr_assert(0);
		return -1;
	}
}

/** Convert a map to a #fr_pair_t
 *
 * @param[in,out] ctx to allocate #fr_pair_t (s) in.
 * @param[out] out Where to write the #fr_pair_t (s), which may be NULL if not found
 * @param[in] request The current request.
 * @param[in] map the map. The LHS (dst) has to be #TMPL_TYPE_ATTR or #TMPL_TYPE_LIST.
 * @param[in] uctx unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_to_vp(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request, map_t const *map, UNUSED void *uctx)
{
	int		rcode = 0;
	fr_pair_t	*vp = NULL, *n;
	fr_pair_list_t	found;
	request_t	*context = request;
	fr_cursor_t	cursor;
	ssize_t		slen;
	char		*str;

	fr_pair_list_init(&found);
	*out = NULL;

	MAP_VERIFY(map);
	if (!fr_cond_assert(map->lhs != NULL)) return -1;
	if (!fr_cond_assert(map->rhs != NULL)) return -1;

	fr_assert(tmpl_is_list(map->lhs) || tmpl_is_attr(map->lhs));

	/*
	 *	Special case for !*, we don't need to parse RHS as this is a unary operator.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	List to list found, this is a special case because we don't need
	 *	to allocate any attributes, just finding the current list, and change
	 *	the op.
	 */
	if (tmpl_is_list(map->lhs) && tmpl_is_list(map->rhs)) {
		fr_pair_list_t *from = NULL;

		if (radius_request(&context, tmpl_request(map->rhs)) == 0) {
			from = radius_list(context, tmpl_list(map->rhs));
		}
		if (!from) return 0;

		if (fr_pair_list_copy(ctx, &found, from) < 0) return -1;

		/*
		 *	List to list copy is empty if the src list has no attributes.
		 */
		if (!found) return 0;

		for (vp = fr_cursor_init(&cursor, &found);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			vp->op = T_OP_ADD;
		}

		*out = found;

		return 0;
	}

	/*
	 *	And parse the RHS
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_XLAT:
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(tmpl_da(map->lhs));	/* We need to know which attribute to create */
		fr_assert(tmpl_xlat(map->rhs) != NULL);

		MEM(n = fr_pair_afrom_da(ctx, tmpl_da(map->lhs)));

		/*
		 *	We do the debug printing because xlat_aeval_compiled
		 *	doesn't have access to the original string.  It's been
		 *	mangled during the parsing to xlat_exp_t
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

		rcode = fr_pair_value_from_str(n, str, -1, '\0', false);
		talloc_free(str);
		if (rcode < 0) {
			fr_pair_list_free(&n);
			goto error;
		}
		n->op = map->op;
		*out = n;
		break;

	case TMPL_TYPE_UNRESOLVED:
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(tmpl_da(map->lhs));	/* We need to know which attribute to create */

		MEM(n = fr_pair_afrom_da(ctx, tmpl_da(map->lhs)));

		if (fr_pair_value_from_str(n, map->rhs->name, -1, '\0', false) < 0) {
			rcode = 0;
			talloc_free(n);
			goto error;
		}
		n->op = map->op;
		*out = n;
		break;

	case TMPL_TYPE_ATTR:
	{
		fr_cursor_t from;

		fr_assert((tmpl_is_attr(map->lhs) && tmpl_da(map->lhs)) ||
			   (tmpl_is_list(map->lhs) && !tmpl_da(map->lhs)));

		/*
		 * @todo should log error, and return -1 for v3.1 (causes update to fail)
		 */
		if (tmpl_copy_pairs(ctx, &found, request, map->rhs) < 0) return 0;

		vp = fr_cursor_init(&from, &found);

		/*
		 *  Src/Dst attributes don't match, convert src attributes
		 *  to match dst.
		 */
		if (tmpl_is_attr(map->lhs) &&
		    (tmpl_da(map->rhs)->type != tmpl_da(map->lhs)->type)) {
			fr_cursor_t to;

			(void) fr_cursor_init(&to, out);
			for (; vp; vp = fr_cursor_current(&from)) {
				MEM(n = fr_pair_afrom_da(ctx, tmpl_da(map->lhs)));

				if (fr_value_box_cast(n, &n->data,
						      tmpl_da(map->lhs)->type, tmpl_da(map->lhs), &vp->data) < 0) {
					RPEDEBUG("Attribute conversion failed");
					fr_pair_list_free(&found);
					talloc_free(n);
					return -1;
				}
				vp = fr_cursor_remove(&from);	/* advances cursor */
				talloc_free(vp);

				fr_assert((n->vp_type != FR_TYPE_STRING) || (n->vp_strvalue != NULL));

				n->op = map->op;
				fr_cursor_append(&to, n);
			}

			return 0;
		}

		/*
		 *   Otherwise we just need to fixup the attribute types
		 *   and operators
		 */
		for (; vp; vp = fr_cursor_next(&from)) {
			vp->da = tmpl_da(map->lhs);
			vp->op = map->op;
		}
		*out = found;
	}
		break;

	case TMPL_TYPE_DATA:
		fr_assert(tmpl_da(map->lhs));
		fr_assert(tmpl_is_attr(map->lhs));

		MEM(n = fr_pair_afrom_da(ctx, tmpl_da(map->lhs)));

		if (tmpl_da(map->lhs)->type == tmpl_value_type(map->rhs)) {
			if (fr_value_box_copy(n, &n->data, tmpl_value(map->rhs)) < 0) {
				rcode = -1;
				talloc_free(n);
				goto error;
			}
		} else {
			if (fr_value_box_cast(n, &n->data, n->vp_type, n->da, tmpl_value(map->rhs)) < 0) {
				RPEDEBUG("Implicit cast failed");
				rcode = -1;
				talloc_free(n);
				goto error;
			}
		}
		n->op = map->op;
		*out = n;

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
		fr_pair_list_free(&vp);
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
	fr_pair_t		*vp, *dst;
	fr_pair_list_t		*list, head;
	request_t		*context, *tmp_ctx = NULL;
	TALLOC_CTX		*parent;
	fr_cursor_t		dst_list, src_list;

	bool			found = false;

	map_t			exp_map;
	tmpl_t			*exp_lhs;
	request_ref_t		request_ref;
	pair_list_t		list_ref;

	tmpl_cursor_ctx_t	cc = {};

	fr_pair_list_init(&head);
	MAP_VERIFY(map);
	fr_assert(map->lhs != NULL);
	fr_assert(map->rhs != NULL);

	tmp_ctx = talloc_pool(request, 1024);
	fr_cursor_init(&src_list, &head);

	/*
	 *	Preprocessing of the LHS of the map.
	 */
	switch (map->lhs->type) {
	/*
	 *	Already in the correct form.
	 */
	case TMPL_TYPE_LIST:
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
					   	.dict_def = request->dict,
					   	.prefix = TMPL_ATTR_REF_PREFIX_NO
					   });
		if (slen <= 0) {
			RPEDEBUG("Left side expansion result \"%s\" is not an attribute reference", attr_str);
			talloc_free(attr_str);
			rcode = -1;
			goto finish;
		}
		fr_assert(tmpl_is_attr(exp_lhs) || tmpl_is_list(exp_lhs));

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
	if (!tmpl_is_list(map->lhs) &&
	    !tmpl_is_attr(map->lhs)) {
		REDEBUG("Left side \"%.*s\" of map should be an attr or list but is an %s",
			(int)map->lhs->len, map->lhs->name,
			fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
		rcode = -2;
		goto finish;
	}

	context = request;
	request_ref = tmpl_request(map->lhs);
	if (radius_request(&context, request_ref) < 0) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" cannot be performed due to invalid request reference \"%s\" in right side of map",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name,
			fr_table_str_by_value(request_ref_table, request_ref, "<INVALID>"));
		rcode = -2;
		goto finish;
	}

	list_ref = tmpl_list(map->lhs);
	list = radius_list(context, list_ref);
	if (!list) {
		REDEBUG("Mapping \"%.*s\" -> \"%.*s\" cannot be performed due to to invalid list qualifier \"%s\" in left side of map",
			(int)map->rhs->len, map->rhs->name, (int)map->lhs->len, map->lhs->name,
			fr_table_str_by_value(pair_list_table, list_ref, "<INVALID>"));
		rcode = -2;
		goto finish;
	}

	parent = radius_list_ctx(context, tmpl_list(map->lhs));
	fr_assert(parent);

	/*
	 *	The callback should either return -1 to signify operations error,
	 *	-2 when it can't find the attribute or list being referenced, or
	 *	0 to signify success. It may return "success", but still have no
	 *	VPs to work with.
	 */
	if (!tmpl_is_null(map->rhs)) {
		rcode = func(parent, &head, request, map, ctx);
		if (rcode < 0) {
			fr_assert(!head);
			goto finish;
		}
		if (!head) {
			RDEBUG2("%.*s skipped: No values available", (int)map->lhs->len, map->lhs->name);
			goto finish;
		}
	} else {
		if (RDEBUG_ENABLED) map_debug_log(request, map, NULL);
	}

	/*
	 *	Print the VPs
	 */
#ifndef WITH_VERIFY_PTR
	if (RDEBUG_ENABLED)
#endif
	{
		fr_cursor_t cursor;

		for (vp = fr_cursor_init(&cursor, &head);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			VP_VERIFY(vp);

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
			fr_assert(!head);

			/* Clear the entire dst list */
			fr_pair_list_free(list);
			goto finish;

		case T_OP_SET:
			if (tmpl_is_list(map->rhs)) {
				fr_pair_list_free(list);
				*list = head;
				fr_pair_list_init(&head);
			} else {
				FALL_THROUGH;

		case T_OP_EQ:
				fr_assert(tmpl_is_exec(map->rhs));
				FALL_THROUGH;

		case T_OP_ADD:
				fr_pair_list_move(list, &head);
				fr_pair_list_free(&head);
			}
			goto update;

		default:
			fr_pair_list_free(&head);
			rcode = -1;
			goto finish;
		}
	}

	/*
	 *	Find the destination attribute.  We leave with either
	 *	the dst_list and vp pointing to the attribute or the VP
	 *	being NULL (no attribute at that index).
	 */
	dst = tmpl_cursor_init(NULL, tmp_ctx, &cc, &dst_list, request, map->lhs);
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
		fr_assert(!head);
		if (!dst) goto finish;

		/*
		 *	Wildcard: delete all of the matching ones
		 */
		if (tmpl_num(map->lhs) == NUM_ANY) {
			fr_pair_delete_by_child_num(list, tmpl_da(map->lhs)->parent, tmpl_da(map->lhs)->attr);
			dst = NULL;
		/*
		 *	We've found the Nth one.  Delete it, and only it.
		 */
		} else {
			dst = fr_cursor_remove(&dst_list);
			fr_pair_list_free(&dst);
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
	 *	- If tmpl_num(map->lhs) > 0, we check each of the src_list attributes against
	 *	  the dst attribute, to see if any of their values match.
	 *	- If tmpl_num(map->lhs) == NUM_ANY, we compare all instances of the dst attribute
	 *	  against each of the src_list attributes.
	 */
	case T_OP_SUB:
		/* We didn't find any attributes earlier */
		if (!dst) {
			fr_pair_list_free(&head);
			goto finish;
		}

		/*
		 *	Instance specific[n] delete
		 */
		if (tmpl_num(map->lhs) != NUM_ANY) {
			for (vp = fr_cursor_head(&src_list);
			     vp;
			     vp = fr_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = paircmp_pairs(request, vp, dst);
				if (rcode == 0) {
					dst = fr_cursor_remove(&dst_list);
					fr_pair_list_free(&dst);
					found = true;
				}
			}
			rcode = 0;
			fr_pair_list_free(&head);
			if (!found) goto finish;
			goto update;
		}

		/*
		 *	All instances[*] delete
		 */
		for (dst = fr_cursor_current(&dst_list);
		     dst;
		     dst = fr_cursor_filter_next(&dst_list, fr_pair_matches_da, tmpl_da(map->lhs))) {
			for (vp = fr_cursor_head(&src_list);
			     vp;
			     vp = fr_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = paircmp_pairs(request, vp, dst);
				if (rcode == 0) {
					dst = fr_cursor_remove(&dst_list);
					fr_pair_list_free(&dst);
					found = true;
				}
			}
		}
		rcode = 0;
		fr_pair_list_free(&head);
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
			fr_pair_list_free(&head);
			goto finish;
		}

		fr_dlist_talloc_init(&leaf, tmpl_attr_extent_t, entry);
		fr_dlist_talloc_init(&interior, tmpl_attr_extent_t, entry);

		/*
		 *	Find out what we need to build and build it
		 */
		if ((tmpl_extents_find(tmp_ctx, &leaf, &interior, request, map->lhs) < 0) ||
		    (tmpl_extents_build_to_leaf(&leaf, &interior, map->lhs) < 0)) {
			fr_dlist_talloc_free(&leaf);
			fr_dlist_talloc_free(&interior);
			rcode = -1;
		    	goto finish;
		}

		/*
		 *	Need to copy src to all dsts
		 */
		src_vp = fr_cursor_head(&src_list);
		if (!src_vp) {
			fr_dlist_talloc_free(&leaf);
			rcode = -1;
			goto finish;
		}

		if (fr_dlist_num_elements(&leaf) > 1) {
			while ((extent = fr_dlist_tail(&leaf))) {
				fr_pair_add(extent->list, fr_pair_copy(extent->list_ctx, src_vp));
				fr_dlist_talloc_free_tail(&leaf);
			}
		} else {
			extent = fr_dlist_head(&leaf);
			fr_pair_add(extent->list, fr_pair_copy(extent->list_ctx, src_vp));
			fr_dlist_talloc_free_head(&leaf);
		}

		/* Free any we didn't insert */
		fr_pair_list_free(&head);
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

		fr_dlist_talloc_init(&leaf, tmpl_attr_extent_t, entry);
		fr_dlist_talloc_init(&interior, tmpl_attr_extent_t, entry);

		/*
		 *	Find out what we need to build and build it
		 */
		src_vp = fr_cursor_tail(&src_list);
		if ((tmpl_extents_find(tmp_ctx, &leaf, &interior, request, map->lhs) < 0) ||
		    (tmpl_extents_build_to_leaf(&leaf, &interior, map->lhs) < 0)) {
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
			if (dst) {
				DEBUG_OVERWRITE(dst, fr_cursor_current(&src_list));
				dst = fr_cursor_replace(&dst_list, fr_pair_copy(extent->list_ctx, src_vp));
				talloc_free(dst);
			} else {
				fr_pair_add(extent->list, fr_pair_copy(extent->list_ctx, src_vp));
			}
		}

		/* Free any we didn't insert */
		fr_pair_list_free(&head);
		fr_assert(fr_dlist_num_elements(&interior) == 0);
		fr_dlist_talloc_free(&leaf);
	}
		break;

	/*
	 *	+= - Add all src_list attributes to the destination
	 */
	case T_OP_ADD:
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
		    (tmpl_extents_build_to_leaf(&leaf, &interior, map->lhs) < 0)) {
			fr_dlist_talloc_free(&leaf);
			fr_dlist_talloc_free(&interior);
			rcode = -1;
		    	goto finish;
		}

		if (fr_dlist_num_elements(&leaf) > 1) {
			while ((extent = fr_dlist_tail(&leaf))) {
				fr_pair_list_copy(extent->list_ctx, extent->list, &head);
				fr_dlist_talloc_free_tail(&leaf);
			}
			/* Free all the src vps */
			fr_pair_list_free(&head);
		} else {
			extent = fr_dlist_head(&leaf);
			fr_pair_list_copy(extent->list_ctx, extent->list, &head);
			fr_dlist_talloc_free_head(&leaf);
		}

		fr_pair_list_free(&head);
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
		fr_pair_t *a, *b;

		fr_pair_list_sort(&head, fr_pair_cmp_by_da);
		fr_pair_list_sort(list, fr_pair_cmp_by_da);

		fr_cursor_head(&dst_list);

		for (b = fr_cursor_head(&src_list);
		     b;
		     b = fr_cursor_next(&src_list)) {
			for (a = fr_cursor_current(&dst_list);
			     a;
			     a = fr_cursor_next(&dst_list)) {
				int8_t cmp;

				cmp = fr_pair_cmp_by_da(a, b);	/* attribute and tag match */
				if (cmp > 0) break;
				else if (cmp < 0) continue;

				cmp = (fr_value_box_cmp_op(map->op, &a->data, &b->data) == 0);
				if (cmp != 0) {
					a = fr_cursor_remove(&dst_list);
					talloc_free(a);
				}
			}
			if (!a) break;	/* end of the list */
		}
		fr_pair_list_free(&head);
	}
		break;

	default:
		fr_assert(0);	/* Should have been caught be the caller */
		rcode = -1;
		goto finish;
	}

update:
	fr_assert(!head);

finish:
	tmpl_cursor_clear(&cc);
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
	fr_sbuff_t	our_out = FR_SBUFF_NO_ADVANCE(out);

	MAP_VERIFY(map);

	/*
	 *	Print the lhs
	 */
	FR_SBUFF_RETURN(tmpl_print_quoted, &our_out, map->lhs, TMPL_ATTR_REF_PREFIX_YES);

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
		return fr_sbuff_set(out, &our_out);
	}

	/*
	 *	If there's no child and no RHS then the
	 *	map was invalid.
	 */
	if (!map->child && !fr_cond_assert(map->rhs != NULL)) {
		fr_sbuff_terminate(out);
		return 0;
	}

	/*
	 *	Print the RHS.
	 */
	FR_SBUFF_RETURN(tmpl_print_quoted, &our_out, map->rhs, TMPL_ATTR_REF_PREFIX_YES);

	return fr_sbuff_set(out, &our_out);
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

	fr_assert(vp || tmpl_is_null(map->rhs));

	switch (map->rhs->type) {
	/*
	 *	Just print the value being assigned
	 */
	default:
	case TMPL_TYPE_UNRESOLVED:
		fr_pair_aprint_value_quoted(request, &rhs, vp, map->rhs->quote);
		break;

	case TMPL_TYPE_XLAT:
		fr_pair_aprint_value_quoted(request, &rhs, vp, map->rhs->quote);
		break;

	case TMPL_TYPE_DATA:
		fr_pair_aprint_value_quoted(request, &rhs, vp, map->rhs->quote);
		break;

	/*
	 *	For the lists, we can't use the original name, and have to
	 *	rebuild it using tmpl_print, for each attribute we're
	 *	copying.
	 */
	case TMPL_TYPE_LIST:
	{
		tmpl_t		*vpt;
		fr_token_t	quote;

		switch (vp->vp_type) {
		case FR_TYPE_QUOTED:
			quote = T_DOUBLE_QUOTED_STRING;
			break;
		default:
			quote = T_BARE_WORD;
			break;
		}

		vpt = tmpl_alloc(request, TMPL_TYPE_ATTR, quote, map->rhs->name, strlen(map->rhs->name));

		/*
		 *	Fudge a temporary tmpl that describes the attribute we're copying
		 *	this is a combination of the original list tmpl, and values from
		 *	the fr_pair_t.
		 */
		tmpl_attr_copy(vpt, map->rhs);
		tmpl_attr_set_leaf_da(vpt, vp->da);
		tmpl_attr_set_leaf_num(vpt, NUM_ANY);

		/*
		 *	Not appropriate to use map->rhs->quote here, as that's the quoting
		 *	around the list ref. The attribute value has no quoting, so we choose
		 *	the quoting based on the data type.
		 */
		fr_pair_aprint_value_quoted(request, &value, vp, quote);
		tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), vpt, TMPL_ATTR_REF_PREFIX_YES, NULL);
		rhs = talloc_typed_asprintf(request, "%s -> %s", buffer, value);

		talloc_free(vpt);
	}
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
		tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map->rhs, TMPL_ATTR_REF_PREFIX_YES, NULL);
		rhs = talloc_typed_asprintf(request, "%s -> %s", buffer, value);
	}
		break;

	case TMPL_TYPE_NULL:
		rhs = talloc_typed_strdup(request, "ANY");
		break;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_LIST:
		/*
		 *	The MAP may have said "list", but if there's a
		 *	VP, it has it's own name, which isn't in the
		 *	map name.
		 */
		if (vp) {
			tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map->lhs, TMPL_ATTR_REF_PREFIX_YES, NULL);	/* Fixme - bad escaping */
			RDEBUG2("%s%s %s %s", buffer, vp->da->name, fr_table_str_by_value(fr_tokens_table, vp->op, "<INVALID>"), rhs);
			break;
		}
		FALL_THROUGH;

	case TMPL_TYPE_ATTR:
		tmpl_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map->lhs, TMPL_ATTR_REF_PREFIX_YES, NULL);
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
