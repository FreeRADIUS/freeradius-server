/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Parse attribute value pairs from text
 *
 * @file src/lib/util/pair_tokenize.c
 *
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/value.h>

/** Operators that may appear between an attribute name and a value
 *
 * fr_table_num_sorted_t requires the entries in sorted order, so keep the entries sorted.
 */
fr_table_num_sorted_t const fr_pair_comparison_op_table[] = {
	{ L("!*"),	T_OP_CMP_FALSE		},
	{ L("!="),	T_OP_NE			},
	{ L("!~"),	T_OP_REG_NE		},
	{ L("+="),	T_OP_ADD_EQ		},
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
size_t fr_pair_comparison_op_table_len = NUM_ELEMENTS(fr_pair_comparison_op_table);

/** A bare word value ends at whitespace or at the comma before the next pair
 *
 */
static fr_sbuff_parse_rules_t const pair_value_bareword_rules = {
	.terminals = &FR_SBUFF_TERMS(
		L("\t"),
		L("\n"),
		L("\r"),
		L(" "),
		L(",")
	)
};

/** Parse `Attribute op value` and append the pair to pair_ctx->list
 *
 * The function looks the attribute name up under pair_ctx->parent, and the
 * attribute must be a direct child of pair_ctx->parent.
 *
 * @param[in,out] pair_ctx	the parsing context.
 * @param[in,out] in		to parse.  Advanced past the value on success.
 * @return
 *	- >0 the number of bytes parsed.
 *	- <0 the negative offset of the error.
 */
static fr_slen_t pair_afrom_substr(fr_pair_ctx_t *pair_ctx, fr_sbuff_t *in)
{
	fr_sbuff_t			our_in = FR_SBUFF(in);
	fr_sbuff_marker_t		name_m;
	fr_dict_attr_t const		*da;
	fr_token_t			op;
	size_t				op_len;
	char				quote;
	fr_sbuff_parse_rules_t const	*rules;
	fr_pair_t			*vp;
	fr_slen_t			slen;

	fr_sbuff_marker(&name_m, &our_in);
	if (fr_dict_attr_by_name_substr(NULL, &da, pair_ctx->parent, &our_in, NULL) < 0) FR_SBUFF_ERROR_RETURN(&our_in);

	if (da->parent != pair_ctx->parent) {
		fr_strerror_printf("Unexpected attribute %s is not a child of %s", da->name, pair_ctx->parent->name);
		FR_SBUFF_ERROR_RETURN(&name_m);
	}

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	fr_sbuff_out_by_longest_prefix(&op_len, &op, fr_pair_comparison_op_table, &our_in, T_INVALID);
	if (op == T_INVALID) {
		fr_strerror_const("Expected operator");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	if (fr_sbuff_next_if_char(&our_in, '"')) {
		quote = '"';
		rules = &value_parse_rules_double_quoted;
	} else if (fr_sbuff_next_if_char(&our_in, '\'')) {
		quote = '\'';
		rules = &value_parse_rules_single_quoted;
	} else if (fr_sbuff_is_char(&our_in, '`')) {
		fr_strerror_const("Invalid string quotation");
		FR_SBUFF_ERROR_RETURN(&our_in);
	} else {
		quote = '\0';
		rules = &pair_value_bareword_rules;
	}

	vp = fr_pair_afrom_da(pair_ctx->ctx, da);
	if (unlikely(!vp)) FR_SBUFF_ERROR_RETURN(&name_m);
	vp->op = op;

	slen = fr_value_box_from_substr(vp, &vp->data, da->type, da, &our_in, rules);
	if (slen < 0) {
	error:
		talloc_free(vp);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (quote && !fr_sbuff_next_if_char(&our_in, quote)) {
		fr_strerror_const("Unterminated string");
		goto error;
	}

	FR_PAIR_APPEND(pair_ctx->list, vp);

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Set a new parent from a dotted attribute reference
 *
 * The first component must be a direct child of pair_ctx->parent, and each
 * later component must be a direct child of the component before.  The last
 * component becomes the new pair_ctx->parent.  The function stops at the end
 * of the input or at a comma.  The comma remains in the buffer for the caller.
 *
 * @param[in,out] pair_ctx	the parsing context.
 * @param[in,out] in		to parse.  Advanced past the reference on success.
 * @return
 *	- >0 the number of bytes parsed.
 *	- <0 the negative offset of the error.
 *
 *  @todo - allow for child contexts, so that the parser can parse TLVs into vp->vp_children.
 *	    The change requires nested cursors, but not necessarily nested contexts.
 *	    One design is a `fr_dlist_t` of pair_ctx, where the parser always operates
 *	    on the last pair_ctx in the list.  When the context changes to the parent of
 *	    an attribute, pair_ctx also changes to a parent context.  The list resembles
 *	    the da stack, but with child cursors as well.
 *
 *	    The parser also needs to emulate the previous behavior of group attributes,
 *	    based on the parent and an increasing child_num.  When the parser reads a
 *	    series of "attr-foo = bar" pairs, the parser watches the parent context, and
 *	    creates a new parent VP when a child has a SMALLER attribute number than the
 *	    previous child.  Emulating the previous behavior keeps existing configurations
 *	    working.
 */
static fr_slen_t pair_ctx_set_from_substr(fr_pair_ctx_t *pair_ctx, fr_sbuff_t *in)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	name_m;
	fr_dict_attr_t const	*da;
	fr_dict_attr_t const	*parent = pair_ctx->parent;

	for (;;) {
		fr_sbuff_marker(&name_m, &our_in);
		if (fr_dict_attr_by_name_substr(NULL, &da, parent, &our_in, NULL) < 0) FR_SBUFF_ERROR_RETURN(&our_in);

		if (da->parent != parent) {
			fr_strerror_printf("Unexpected attribute %s is not a child of %s", da->name, parent->name);
			FR_SBUFF_ERROR_RETURN(&name_m);
		}
		parent = da;

		if (!fr_sbuff_extend(&our_in) || fr_sbuff_is_char(&our_in, ',')) break;

		if (!fr_sbuff_next_if_char(&our_in, '.')) {
			fr_strerror_const("Unexpected text after attribute");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
	}

	pair_ctx->parent = parent;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Parse one pair, or one context change, from a string
 *
 * The function stops at the end of the input or at a comma.  The comma remains
 * in the buffer for the caller.
 *
 * The syntax is:
 *
 *  - `Attribute = value`
 *	The function resets the context to the parent of Attribute, a top level
 *	attribute, then parses the attribute and the value.
 *
 *  - `Attribute`
 *	The function resets the context to Attribute, a top level structural
 *	attribute (a group, a TLV, or a struct).
 *
 *  - `Attribute.Child`
 *	The function resets the context to Child, where each component is a
 *	structural attribute and a direct child of the component before.
 *
 *  - `.Attribute = value`, `.Attribute` and `.Attribute.Child`
 *	As above, with the lookup starting at the current context.
 *
 *  - `..Attribute = value`, `..Attribute` and `..Attribute.Child`
 *	As above, with the lookup starting at the parent of the current
 *	context.  Each further '.' starts one level further up, and a
 *	reference of dots alone only moves the context up.
 *
 * @param[in,out] pair_ctx	the parsing context.
 * @param[in,out] in		to parse.  Advanced past what was parsed on success.
 * @return
 *	- >=0 the number of bytes parsed.
 *	- <0 the negative offset of the error.
 */
fr_slen_t fr_pair_ctx_afrom_substr(fr_pair_ctx_t *pair_ctx, fr_sbuff_t *in)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	name_m;
	fr_dict_attr_t const	*parent;
	fr_dict_attr_t const	*da;
	fr_slen_t		slen;

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
	if (!fr_sbuff_extend(&our_in)) FR_SBUFF_SET_RETURN(in, &our_in);

	/*
	 *	The reference has no leading '.', so the lookup
	 *	starts at the dictionary root.
	 */
	if (!fr_sbuff_is_char(&our_in, '.')) {
		parent = fr_dict_root(pair_ctx->parent->dict);
	/*
	 *	The first '.' starts the lookup at the current
	 *	context, and each further '.' walks one level up.
	 */
	} else {
		fr_sbuff_advance(&our_in, 1);
		parent = pair_ctx->parent;

		while (fr_sbuff_is_char(&our_in, '.')) {
			if (!parent->parent) {
				fr_strerror_const("No parent above the dictionary root");
				FR_SBUFF_ERROR_RETURN(&our_in);
			}
			parent = parent->parent;
			fr_sbuff_advance(&our_in, 1);
		}

		if (!fr_sbuff_extend(&our_in) || fr_sbuff_is_char(&our_in, ',')) {
			pair_ctx->parent = parent;
			FR_SBUFF_SET_RETURN(in, &our_in);
		}
	}

	fr_sbuff_marker(&name_m, &our_in);
	if (fr_dict_attr_by_name_substr(NULL, &da, parent, &our_in, NULL) < 0) FR_SBUFF_ERROR_RETURN(&our_in);

	switch (da->type) {
	/*
	 *	Structural types have no values, so a bare
	 *	structural attribute changes the context.
	 */
	case FR_TYPE_GROUP:
	case FR_TYPE_TLV:
	case FR_TYPE_STRUCT:
		pair_ctx->parent = da;

		if (!fr_sbuff_extend(&our_in) || fr_sbuff_is_char(&our_in, ',')) FR_SBUFF_SET_RETURN(in, &our_in);

		if (!fr_sbuff_next_if_char(&our_in, '.')) {
			fr_strerror_const("Unexpected text after attribute");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		slen = pair_ctx_set_from_substr(pair_ctx, &our_in);
		if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);
		break;

	/*
	 *	Leaf types have values, so the context becomes
	 *	the parent of the leaf, and pair_afrom_substr()
	 *	parses the leaf again from the start of the name.
	 */
	default:
		pair_ctx->parent = parent;
		fr_sbuff_set(&our_in, &name_m);

		slen = pair_afrom_substr(pair_ctx, &our_in);
		if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);
		break;
	}

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Reset a pair_ctx to the dictionary root
 *
 * Callers reset the context when the parsed text switches to a different
 * attribute list, for example from request.foo to reply.bar.
 *
 * The function will need to reset child contexts once pairs store children
 * in vp->vp_children.
 *
 * @param[in,out] pair_ctx	the parsing context.
 * @param[in] dict		whose root becomes the parent.
 */
void fr_pair_ctx_reset(fr_pair_ctx_t *pair_ctx, fr_dict_t const *dict)
{
	pair_ctx->parent = fr_dict_root(dict);
}
