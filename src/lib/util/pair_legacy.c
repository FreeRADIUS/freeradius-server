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

/** AVP manipulation and search API
 *
 * @file src/lib/util/pair_legacy.c
 *
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

static fr_sbuff_term_t const 	bareword_terminals =
				FR_SBUFF_TERMS(
					L("\t"),
					L("\n"),
					L(" "),
					L("!*"),
					L("!="),
					L("!~"),
					L("&&"),		/* Logical operator */
					L(")"),			/* Close condition/sub-condition */
					L("+="),
					L("-="),
					L(":="),
					L("<"),
					L("<="),
					L("=*"),
					L("=="),
					L("=~"),
					L(">"),
					L(">="),
					L("||"),		/* Logical operator */
				);

static fr_table_num_sorted_t const pair_assignment_op_table[] = {
	{ L("+="),	T_OP_ADD_EQ		},
	{ L(":="),	T_OP_EQ			},
	{ L("="),	T_OP_EQ			},
};
static ssize_t pair_assignment_op_table_len = NUM_ELEMENTS(pair_assignment_op_table);

static fr_table_num_sorted_t const pair_comparison_op_table[] = {
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
static size_t pair_comparison_op_table_len = NUM_ELEMENTS(pair_comparison_op_table);

/*
 *	Stop parsing bare words at whitespace, comma, or end of list.
 *
 *	Note that we don't allow escaping of bare words here, as that screws up parsing of raw attributes with
 *	0x... prefixes.
 */
static fr_sbuff_parse_rules_t const bareword_unquoted = {
	.terminals = &FR_SBUFF_TERMS(
		L(""),
		L("\t"),
		L("\n"),
		L("\r"),
		L(" "),
		L(","),
		L("}")
	)
};


static ssize_t fr_pair_value_from_substr(fr_pair_t *vp, fr_sbuff_t *in, UNUSED bool tainted)
{
	char quote;
	ssize_t slen;
	fr_sbuff_parse_rules_t const *rules;

	if (fr_sbuff_next_if_char(in, '"')) {
		rules = &value_parse_rules_double_quoted;
		quote = '"';

	} else if (fr_sbuff_next_if_char(in, '\'')) {
		rules = &value_parse_rules_single_quoted;
		quote = '\'';

		/*
		 *	We don't support backticks here.
		 */
	} else if (fr_sbuff_is_char(in, '\'')) {
		fr_strerror_const("Backticks are not supported here");
		return 0;

	} else {
		rules = &bareword_unquoted;
		quote = '\0';
	}

	slen = fr_value_box_from_substr(vp, &vp->data, vp->da->type, vp->da, in, rules);
	if (slen < 0) {
		fr_assert(slen >= -((ssize_t) 1 << 20));
		return slen - (quote != 0);
	}

	if (quote && !fr_sbuff_next_if_char(in, quote)) {
		fr_strerror_const("Unterminated string");
		return 0;
	}

	fr_assert(slen <= ((ssize_t) 1 << 20));

	return slen + ((quote != 0) << 1);
}

/**  Parse a #fr_pair_list_t from a substring
 *
 * @param[in] root	where we start parsing from
 * @param[in,out] relative where we left off, or where we should continue from
 * @param[in] in	input sbuff
 * @return
 *	- <0 on error
 *	- 0 on no input
 *	- >0 on how many bytes of input we read
 *
 */
fr_slen_t fr_pair_list_afrom_substr(fr_pair_parse_t const *root, fr_pair_parse_t *relative,
				    fr_sbuff_t *in)
{
	int			i, components;
	bool			raw;
	bool			was_relative = false;
	bool			append;
	bool			keep_going;
	fr_type_t		raw_type;
	fr_token_t		op;
	fr_slen_t		slen;
	fr_pair_t		*vp;
	fr_dict_attr_t const	*internal = NULL;
	fr_sbuff_marker_t	lhs_m, rhs_m;
	fr_sbuff_t		our_in = FR_SBUFF(in);

	if (unlikely(!root->ctx)) {
		fr_strerror_const("Missing ctx fr_pair_parse_t");
		return -1;
	}

	if (unlikely(!root->da)) {
		fr_strerror_const("Missing namespace attribute");
		return -1;
	}

	if (unlikely(!root->list)) {
		fr_strerror_const("Missing list");
		return -1;
	}

	if (fr_dict_internal()) internal = fr_dict_root(fr_dict_internal());
	if (internal == root->da) internal = NULL;

	if (fr_sbuff_remaining(&our_in) == 0) return 0;

redo:
	append = true;
	raw = false;
	raw_type = FR_TYPE_NULL;
	relative->last_char = 0;
	vp = NULL;

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	/*
	 *	Relative attributes start from the input list / parent.
	 *
	 *	Absolute attributes start from the root list / parent.
	 *
	 *	Once we decide where we are coming from, all subsequent operations are on the "relative"
	 *	structure.
	 */
	if (!fr_sbuff_next_if_char(&our_in, '.')) {
		*relative = *root;

		append = !was_relative;
		was_relative = false;

		/*
		 *	Be nice to people who expect to see '&' everywhere.
		 */
		(void) fr_sbuff_next_if_char(&our_in, '&');

		/*
		 *	Raw attributes can only be at our root.
		 *
		 *	"raw.foo" means that SOME component of the OID is raw.  But the starting bits might be known.
		 */
		if (fr_sbuff_is_str_literal(&our_in, "raw.")) {
			raw = true;
			fr_sbuff_advance(&our_in, 4);
		}
	} else if (!relative->ctx || !relative->da || !relative->list) {
		fr_strerror_const("The '.Attribute' syntax can only be used if the previous attribute is structural, and the line ends with ','");
		return -1;
	} else {
		was_relative = true;
	}

	/*
	 *	Set the LHS marker to be after any initial '.'
	 */
	fr_sbuff_marker(&lhs_m, &our_in);

	/*
	 *	Skip over the attribute name.  We need to get the operator _before_ creating the VPs.
	 */
	components = 0;
	do {
		if (fr_sbuff_adv_past_allowed(&our_in, SIZE_MAX, fr_dict_attr_allowed_chars, NULL) == 0) break;
		components++;
	} while (fr_sbuff_next_if_char(&our_in, '.'));

	/*
	 *	Couldn't find anything.
	 */
	if (!components) {
		fr_strerror_const("Empty input");
		return 0;
	}

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	/*
	 *	Look for the operator.
	 */
	if (relative->allow_compare) {
		fr_sbuff_out_by_longest_prefix(&slen, &op, pair_comparison_op_table, &our_in, T_INVALID);
	} else {
		fr_sbuff_out_by_longest_prefix(&slen, &op, pair_assignment_op_table, &our_in, T_INVALID);
	}
	if (op == T_INVALID) {
		fr_strerror_const("Expecting operator");
		return fr_sbuff_error(&our_in);
	}

	/*
	 *	Skip past whitespace, and set a marker at the RHS.  Then reset the input to the LHS attribute
	 *	name, so that we can go back and parse / create the attributes.
	 */
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	fr_sbuff_marker(&rhs_m, &our_in);

	/*
	 *	If the value of the attribute is 0x..., then we always force the raw type to be octets, even
	 *	if the attribute is named and known.  e.g. raw.Framed-IP-Address = 0x01
	 *
	 *	OR if the attribute is entirely unknown (and not a raw version of a known one), then we allow a
	 *	cast to set the data type.
	 */
	if (raw) {
		if (fr_sbuff_is_str_literal(&our_in, "0x")) {
			raw_type = FR_TYPE_OCTETS;

		} else if (fr_sbuff_next_if_char(&our_in, '(')) {
			fr_sbuff_marker_t m;

			fr_sbuff_marker(&m, &our_in);

			fr_sbuff_out_by_longest_prefix(&slen, &raw_type, fr_type_table, &our_in, FR_TYPE_NULL);
			if ((raw_type == FR_TYPE_NULL) || !fr_type_is_leaf(raw_type)) {
				fr_sbuff_set(&our_in, &rhs_m);
				fr_strerror_const("Invalid data type in cast");
				return fr_sbuff_error(&our_in);
			}

			if (!fr_sbuff_next_if_char(&our_in, ')')) {
				fr_strerror_const("Missing ')' in cast");
				return fr_sbuff_error(&our_in);
			}

			fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
			fr_sbuff_marker(&rhs_m, &our_in);

		} else if (fr_sbuff_is_char(&our_in, '{')) {
			raw_type = FR_TYPE_TLV;
		}
	}

	fr_sbuff_set(&our_in, &lhs_m);

	/*
	 *	Parse each OID component, creating pairs along the way.
	 */
	i = 1;
	do {
		fr_dict_attr_err_t	err;
		fr_dict_attr_t const	*da = NULL;
		fr_dict_attr_t const	*da_unknown = NULL;

		slen = fr_dict_oid_component(&err, &da, relative->da, &our_in, &bareword_terminals);
		if (err == FR_DICT_ATTR_NOTFOUND) {
			if (raw) {
				/*
				 *	We looked up raw.FOO, and FOO wasn't found.  The component must be a number.
				 */
				if (!fr_sbuff_is_digit(&our_in)) goto notfound;

				if (raw_type == FR_TYPE_NULL) {
					raw_type = FR_TYPE_OCTETS;

				} else if (raw_type == FR_TYPE_TLV) {
					/*
					 *	Reset the type based on the parent.
					 */
					if (relative->da->type == FR_TYPE_VSA) {
						raw_type = FR_TYPE_VENDOR;
					}
				}

				slen = fr_dict_attr_unknown_afrom_oid_substr(root->ctx, &da_unknown, relative->da, &our_in, raw_type);
				if (slen < 0) return fr_sbuff_error(&our_in) + slen;

				fr_assert(da_unknown);

				/*
				 *	Append from the root list, starting at the root depth.
				 */
				vp = fr_pair_afrom_da_depth_nested(root->ctx, root->list, da_unknown,
								   root->da->depth);
				fr_dict_attr_unknown_free(&da_unknown);

				if (!vp) return fr_sbuff_error(&our_in);

				PAIR_VERIFY(vp);

				/*
				 *	The above function MAY have jumped ahead a few levels.  Ensure
				 *	that the relative structure is set correctly for the parent,
				 *	but only if the parent changed.
				 */
				if (relative->da != vp->da->parent) {
					fr_pair_t *parent_vp;

					parent_vp = fr_pair_parent(vp);
					fr_assert(parent_vp);

					relative->ctx = parent_vp;
					relative->da = parent_vp->da;
					relative->list = &parent_vp->vp_group;
				}

				/*
				 *	Update the new relative information for the current VP, which
				 *	may be structural, or a key field.
				 */
				fr_assert(!fr_sbuff_is_char(&our_in, '.')); /* be sure the loop exits */
				goto update_relative;
			}

			if (internal) {
				slen = fr_dict_oid_component(&err, &da, internal, &our_in, &bareword_terminals);
			}

		} else if (raw && fr_type_is_structural(da->type) && (raw_type != FR_TYPE_OCTETS)) {
			/*
			 *	We were asked to do a "raw" thing, but we found a known attribute matching
			 *	that description.
			 *
			 *	@todo - this is only allowed because we can't distinguish between "raw.1" and
			 *	"raw.User-Name".
			 */
			raw = false;
			raw_type = FR_TYPE_NULL;
		}

		if (err != FR_DICT_ATTR_OK) {
		notfound:
			fr_sbuff_marker(&rhs_m, &our_in);
			fr_sbuff_adv_past_allowed(&our_in, SIZE_MAX, fr_dict_attr_allowed_chars, NULL);

			fr_strerror_printf("Unknown attribute \"%.*s\" for parent \"%s\"",
					   (int) fr_sbuff_diff(&our_in, &rhs_m), fr_sbuff_current(&rhs_m),
					   relative->da->name);
			return fr_sbuff_error(&our_in);
		}
		fr_assert(da != NULL);

#if 0
		/*
		 *	@todo - If we're at the root, then aliases can cause us to jump over intermediate
		 *	attributes.  In which case we have to create the intermediate attributes, too.
		 */
		if (relative->da) {
			if (relative->da->flags.is_root) {
				fr_assert(da->depth == 1);
			}
		}
#endif

		/*
		 *	Intermediate components are always found / created.  The final component is
		 *	always appended, no matter the operator.
		 */
		if (i < components) {
			if (append) {
				vp = fr_pair_find_last_by_da(relative->list, NULL, da);
				if (!vp) {
					if (fr_pair_append_by_da(relative->ctx, &vp, relative->list, da) < 0) {
						return fr_sbuff_error(&our_in);
					}
				}
			} else {
				vp = fr_pair_afrom_da(relative->ctx, da);
				if (!vp) return fr_sbuff_error(&our_in);

				fr_pair_append(relative->list, vp);
			}

			/*
			 *	We had a raw type and we're passing
			 *	raw octets to it.  We don't care if
			 *	its structural or anything else.  Just
			 *	create the raw attribute.
			 */
		} else if (raw_type != FR_TYPE_NULL) {
			/*
			 *	We have parsed the full OID tree, *and* found a known attribute.  e.g. raw.Vendor-Specific = ...
			 *
			 *	For some reason, we allow: raw.Vendor-Specific = { ... }
			 *
			 *	But this is what we really want: raw.Vendor-Specific = 0xabcdef
			 */
			fr_assert(!da_unknown);

			if ((raw_type != FR_TYPE_OCTETS) && (raw_type != da->type)) {
				fr_strerror_printf("Cannot create raw attribute %s which changes data type from %s to %s",
						   da->name, fr_type_to_str(da->type), fr_type_to_str(raw_type));
				return fr_sbuff_error(&our_in);
			}

			/*
			 *	If we're parsing raw octets, create a raw octets attribute.
			 *
			 *	Otherwise create one of type 'tlv', and then parse the children.
			 */
			if (raw_type == FR_TYPE_OCTETS) {
				da_unknown = fr_dict_attr_unknown_raw_afrom_da(root->ctx, da);
			} else {
				da_unknown = fr_dict_attr_unknown_afrom_da(root->ctx, da);
			}
			if (!da_unknown) return fr_sbuff_error(&our_in);

			if (fr_pair_append_by_da(relative->ctx, &vp, relative->list, da_unknown) < 0) {
				fr_dict_attr_unknown_free(&da_unknown);
				return fr_sbuff_error(&our_in);
			}

			fr_dict_attr_unknown_free(&da_unknown);

			/*
			 *	Just create the leaf attribute.
			 */
		} else if (da->parent->type == FR_TYPE_STRUCT) {
			fr_pair_t *tail = fr_pair_list_tail(relative->list);

			/*
			 *	If the structure member is _less_ than the last one, go create a new structure
			 *	in the grandparent.
			 */
			if (tail && (tail->da->attr >= da->attr) && !da->flags.array) {
				fr_pair_t *parent_vp, *grand_vp;

				parent_vp = fr_pair_list_parent(relative->list);
				if (!parent_vp) goto leaf;

				fr_assert(da->parent == parent_vp->da);

				grand_vp = fr_pair_parent(parent_vp);
				if (!grand_vp) goto leaf;

				/*
				 *	Create a new parent in the context of the grandparent.
				 */
				if (fr_pair_append_by_da(grand_vp, &vp, &grand_vp->vp_group, parent_vp->da) < 0) {
					return fr_sbuff_error(&our_in);
				}

				relative->ctx = vp;
				fr_assert(relative->da == vp->da);
				relative->list = &vp->vp_group;
			}

			goto leaf;
		} else {
		leaf:
			vp = fr_pair_afrom_da_depth_nested(relative->ctx, relative->list, da,
							   relative->da->depth);
			if (!vp) return fr_sbuff_error(&our_in);
		}

		fr_assert(vp != NULL);

	update_relative:
		/*
		 *	Reset the parsing to the new namespace if necessary.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_STRUCTURAL_EXCEPT_GROUP:
			relative->ctx = vp;
			relative->da = vp->da;
			relative->list = &vp->vp_group;
			break;

			/*
			 *	Groups reset the namespace to the da referenced by the group.
			 *
			 *	Internal groups get their namespace to the root namespace.
			 */
		case FR_TYPE_GROUP:
			relative->ctx = vp;
			relative->da = fr_dict_attr_ref(vp->da);
			if (relative->da == internal) {
				relative->da = fr_dict_root(root->da->dict);
			}
			fr_assert(relative->da != NULL);
			relative->list = &vp->vp_group;
			break;

		default:
			break;

		case FR_TYPE_INTERNAL:
			fr_strerror_printf("Cannot parse internal data type %s", fr_type_to_str(vp->vp_type));
			return fr_sbuff_error(&our_in);
		}

		i++;
	} while (fr_sbuff_next_if_char(&our_in, '.'));

	if (relative->allow_compare) {
		vp->op = op;
	} else {
		vp->op = T_OP_EQ;
	}

	/*
	 *	Reset the parser to the RHS so that we can parse the value.
	 */
	fr_sbuff_set(&our_in, &rhs_m);

	/*
	 *	The RHS is a list, go parse the nested attributes.
	 */
	if (fr_sbuff_next_if_char(&our_in, '{')) {
		fr_pair_parse_t child = (fr_pair_parse_t) {
			.allow_compare = root->allow_compare,
		};

		if (!fr_type_is_structural(vp->vp_type)) {
			fr_strerror_printf("Cannot assign list to leaf data type %s for attribute %s",
				fr_type_to_str(vp->vp_type), vp->da->name);
			return fr_sbuff_error(&our_in);
		}

		while (true) {
			fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

			if (fr_sbuff_is_char(&our_in, '}')) {
				break;
			}

			slen = fr_pair_list_afrom_substr(relative, &child, &our_in);
			if (!slen) break;

			if (slen < 0) return fr_sbuff_error(&our_in) + slen;
		}

		if (!fr_sbuff_next_if_char(&our_in, '}')) {
			fr_strerror_const("Failed to end list with '}'");
			return fr_sbuff_error(&our_in);
		}

		goto done;
	}

	if (fr_type_is_structural(vp->vp_type)) {
		fr_strerror_printf("Group list for %s MUST start with '{'", vp->da->name);
		return fr_sbuff_error(&our_in);
	}

	slen = fr_pair_value_from_substr(vp, &our_in, relative->tainted);
	if (slen <= 0) return fr_sbuff_error(&our_in) + slen;

done:
	PAIR_VERIFY(vp);

	keep_going = false;
	if (fr_sbuff_next_if_char(&our_in, ',')) {
		keep_going = true;
		relative->last_char = ',';
	}

	if (relative->allow_crlf) {
		size_t len;

		len = fr_sbuff_adv_past_allowed(&our_in, SIZE_MAX, sbuff_char_line_endings, NULL);
		if (len) {
			keep_going |= true;
			if (!relative->last_char) relative->last_char = '\n';
		}
	}

	keep_going &= ((fr_sbuff_remaining(&our_in) > 0) || (fr_sbuff_extend(&our_in) > 0));

	if (keep_going) goto redo;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Read valuepairs from the fp up to End-Of-File.
 *
 * @param[in] ctx		for talloc
 * @param[in] dict		to resolve attributes in.
 * @param[in,out] out		where the parsed fr_pair_ts will be appended.
 * @param[in] fp		to read valuepairs from.
 * @param[out] pfiledone	true if file parsing complete;
 * @return
 *	- 0 on success
 *	- -1 on error
 */
int fr_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_pair_list_t *out, FILE *fp, bool *pfiledone)
{
	fr_pair_list_t tmp_list;
	fr_pair_parse_t	root, relative;
	bool		found = false;
	char		buf[8192];

	/*
	 *	Read all of the attributes on the current line.
	 *
	 *	If we get nothing but an EOL, it's likely OK.
	 */
	fr_pair_list_init(&tmp_list);

	root = (fr_pair_parse_t) {
		.ctx = ctx,
		.da = fr_dict_root(dict),
		.list = &tmp_list,
		.allow_crlf = true,
		.allow_compare = true,
	};
	relative = (fr_pair_parse_t) { };

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP list.
		 */
		if ((buf[0] == '\n') || (buf[0] == '\r')) {
			if (found) {
				*pfiledone = false;
				break;
			}
			continue;
		}

		/*
		 *	Comments get ignored
		 */
		if (buf[0] == '#') continue;

		/*
		 *	Leave "relative" between calls, so that we can do:
		 *
		 *		foo = {}
		 *		.bar = baz
		 *
		 *	and get
		 *
		 *		foo = { bar = baz }
		 */
		if (fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN_STR(buf)) < 0) {
			*pfiledone = false;
			fr_pair_list_free(&tmp_list);
			return -1;
		}

		found = true;
	}

	fr_pair_list_append(out, &tmp_list);

	*pfiledone = true;
	return 0;
}


/** Move pairs from source list to destination list respecting operator
 *
 * @note This function does some additional magic that's probably not needed in most places. Consider using
 *	 radius_legacy_map_cmp() and radius_legacy_map_apply() instead.
 *
 * @note fr_pair_list_free should be called on the head of the source list to free
 *	 unmoved attributes (if they're no longer needed).
 *
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 * @param[in] op operator for list move.
 */
void fr_pair_list_move_op(fr_pair_list_t *to, fr_pair_list_t *from, fr_token_t op)
{
	fr_pair_t *vp, *next, *found;
	fr_pair_list_t head_append, head_prepend;

	if (!to || fr_pair_list_empty(from)) return;

	/*
	 *	We're editing the "to" list while we're adding new
	 *	attributes to it.  We don't want the new attributes to
	 *	be edited, so we create an intermediate list to hold
	 *	them during the editing process.
	 */
	fr_pair_list_init(&head_append);

	/*
	 *	Any attributes that are requested to be prepended
	 *	are added to a temporary list here
	 */
	fr_pair_list_init(&head_prepend);

	/*
	 *	We're looping over the "from" list, moving some
	 *	attributes out, but leaving others in place.
	 */
	for (vp = fr_pair_list_head(from); vp != NULL; vp = next) {
		PAIR_VERIFY(vp);
		next = fr_pair_list_next(from, vp);

		/*
		 *	We never move Fall-Through.
		 */
		if (fr_dict_attr_is_top_level(vp->da) && (vp->da->attr == FR_FALL_THROUGH) &&
		    (fr_dict_by_da(vp->da) == fr_dict_internal())) {
			continue;
		}

		/*
		 *	Unlike previous versions, we treat all other
		 *	attributes as normal.  i.e. there's no special
		 *	treatment for passwords or Hint.
		 */

		switch (vp->op) {
		/*
		 *	Anything else are operators which
		 *	shouldn't occur.  We ignore them, and
		 *	leave them in place.
		 */
		default:
			continue;

		/*
		 *	Add it to the "to" list, but only if
		 *	it doesn't already exist.
		 */
		case T_OP_EQ:
			found = fr_pair_find_by_da(to, NULL, vp->da);
			if (!found) goto do_add;
			continue;

		/*
		 *	Add it to the "to" list, and delete any attribute
		 *	of the same vendor/attr which already exists.
		 */
		case T_OP_SET:
			found = fr_pair_find_by_da(to, NULL, vp->da);
			if (!found) goto do_add;

			/*
			 *	Delete *all* matching attributes.
			 */
			fr_pair_delete_by_da(to, found->da);
			goto do_add;

		/*
		 *	Move it from the old list and add it
		 *	to the new list.
		 */
		case T_OP_ADD_EQ:
	do_add:
			fr_pair_remove(from, vp);
			fr_pair_append(&head_append, vp);
			continue;

		case T_OP_PREPEND:
			fr_pair_remove(from, vp);
			fr_pair_prepend(&head_prepend, vp);
			continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	If the op parameter was prepend, add the "new list
	 *	attributes first as those whose individual operator
	 *	is prepend should be prepended to the resulting list
	 */
	if (op == T_OP_PREPEND) fr_pair_list_prepend(to, &head_append);

	/*
	 *	If there are any items in the prepend list prepend
	 *	it to the "to" list
	 */
	fr_pair_list_prepend(to, &head_prepend);

	/*
	 *	If the op parameter was not prepend, take the "new"
	 *	list, and append it to the "to" list.
	 */
	if (op != T_OP_PREPEND) fr_pair_list_append(to, &head_append);

	fr_pair_list_free(from);
}
