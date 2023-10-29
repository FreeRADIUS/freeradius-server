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
#include "lib/util/dict.h"
RCSID("$Id$")

#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/misc.h>
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
	{ L("="),	T_OP_EQ			},
};
static ssize_t pair_assignment_op_table_len = NUM_ELEMENTS(pair_assignment_op_table);

static fr_table_num_sorted_t const pair_comparison_op_table[] = {
	{ L("!="),	T_OP_NE			},
	{ L("+="),	T_OP_ADD_EQ		},
	{ L(":="),	T_OP_SET		},
	{ L("<"),	T_OP_LT			},
	{ L("<="),	T_OP_LE			},
	{ L("="),	T_OP_EQ			},
	{ L("=="),	T_OP_CMP_EQ		},
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
		L("\t"),
		L("\n"),
		L(" "),
		L(","),
		L("}")
	)
};


static ssize_t fr_pair_value_from_substr(fr_pair_t *vp, fr_sbuff_t *in)
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

#if 0
		/*
		 *	We don't support backticks here.
		 */
	} else if (fr_sbuff_next_if_char(in, '\'')) {
		rules = &value_parse_rules_backtick_quoted;
		quote = '`';

#endif
	} else {
		rules = &bareword_unquoted;
		quote = '\0';
	}

	slen = fr_value_box_from_substr(vp, &vp->data, vp->da->type, vp->da, in, rules, false);
	if (slen < 0) return slen - (quote != 0);

	if (quote && !fr_sbuff_next_if_char(in, quote)) {
		fr_strerror_const("Unterminated string");
		return 0;
	}

	return slen + ((quote != 0) << 1);
}

fr_slen_t fr_pair_list_afrom_substr(fr_pair_parse_t const *root, fr_pair_parse_t *relative,
				    fr_sbuff_t *in)
{
	int			i, components;
	bool			raw, raw_octets;
	bool			was_relative = false;
	bool			append;
	fr_token_t		op;
	fr_slen_t		slen;
	fr_pair_t		*vp;
	fr_dict_attr_t const	*internal = NULL;
	fr_sbuff_marker_t	lhs_m, rhs_m;
	fr_sbuff_t		our_in = FR_SBUFF(in);

	if (!root->ctx || !root->da || !root->list) return 0;

	if (fr_dict_internal()) internal = fr_dict_root(fr_dict_internal());
	if (internal == root->da) internal = NULL;

redo:
	append = true;
	raw = raw_octets = false;

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
	 *	Peek ahead to see if the final element is defined to be structural, but the caller instead
	 *	wants to parse it as raw octets.
	 */
	if (raw) raw_octets = fr_sbuff_is_str_literal(&our_in, "0x");

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
				if (fr_sbuff_is_digit(&our_in)) {
					slen = fr_dict_unknown_afrom_oid_substr(NULL, &da_unknown, relative->da, &our_in);
					if (slen < 0) return fr_sbuff_error(&our_in) + slen;

					fr_assert(da_unknown);

					/*
					 *	Append from the root list, starting at the root depth.
					 */
					vp = fr_pair_afrom_da_depth_nested(root->ctx, root->list, da_unknown,
									   root->da->depth);
					fr_dict_unknown_free(&da_unknown);

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

				/*
				 *	@todo - it isn't found, return a descriptive error.
				 */
				fr_strerror_printf("Unknown child attribute for parent %s", relative->da->name);
				return fr_sbuff_error(&our_in);
			}

			if (internal) {
				slen = fr_dict_oid_component(&err, &da, internal, &our_in, &bareword_terminals);
			}
		}

		if (err != FR_DICT_ATTR_OK) {
			fr_strerror_printf("Unknown child attribute for parent %s", relative->da->name);
			return fr_sbuff_error(&our_in) + slen;
		}
		fr_assert(da != NULL);

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
		} else if (raw_octets) {
			if (!da_unknown) da_unknown = fr_dict_unknown_attr_afrom_da(NULL, da);
			if (!da_unknown) return fr_sbuff_error(&our_in);

			fr_assert(da_unknown->type == FR_TYPE_OCTETS);

			if (fr_pair_append_by_da(relative->ctx, &vp, relative->list, da_unknown) < 0) {
				fr_dict_unknown_free(&da_unknown);
				return fr_sbuff_error(&our_in);
			}
			fr_dict_unknown_free(&da_unknown);
			fr_assert(vp->vp_type == FR_TYPE_OCTETS);

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
			if (fr_pair_append_by_da(relative->ctx, &vp, relative->list, da) < 0) {
				return fr_sbuff_error(&our_in);
			}
		}

		fr_assert(vp != NULL);

	update_relative:
		/*
		 *	Reset the parsing to the new namespace if necessary.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_TLV:
		case FR_TYPE_STRUCT:
		case FR_TYPE_VSA:
		case FR_TYPE_VENDOR:
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
			relative->list = &vp->vp_group;
			break;

		default:
			/*
			 *	Key fields have children in their namespace, but the children go into the
			 *	parents context and list.
			 */
			if (fr_dict_attr_is_key_field(vp->da)) {
				fr_pair_t *parent_vp;

				parent_vp = fr_pair_parent(vp);
				fr_assert(parent_vp);

				relative->ctx = parent_vp;
				relative->da = vp->da;
				relative->list = &parent_vp->vp_group;
			}
			break;
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
			fr_strerror_const("Cannot assign list to leaf data type");
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

	slen = fr_pair_value_from_substr(vp, &our_in);
	if (slen <= 0) return fr_sbuff_error(&our_in) + slen;

done:
	PAIR_VERIFY(vp);

	if (fr_sbuff_next_if_char(&our_in, ',')) goto redo;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param[in] ctx	for talloc
 * @param[in] parent	parent DA to start referencing from
 * @param[in] parent_vp	vp where we place the result
 * @param[in] buffer	to read valuepairs from.
 * @param[in] end	end of the buffer
 * @param[in] list	where the parsed fr_pair_ts will be appended.
 * @param[in,out] token	The last token we parsed
 * @param[in] depth	the nesting depth for FR_TYPE_GROUP
 * @param[in,out] relative_vp for relative attributes
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
static ssize_t pair_parse_legacy(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, fr_pair_t *parent_vp, char const *buffer, char const *end,
				      fr_pair_list_t *list, fr_token_t *token, unsigned int depth, fr_pair_t **relative_vp)
{
	fr_pair_t		*vp = NULL;
	fr_pair_t		*my_relative_vp;
	char const		*p, *next, *op_p;
	fr_token_t		quote, last_token = T_INVALID;
	fr_dict_attr_t const	*internal = NULL;
	fr_pair_list_t		*my_list = list;
	TALLOC_CTX		*my_ctx;
	char			rhs[1024];

	if (fr_dict_internal()) internal = fr_dict_root(fr_dict_internal());
	if (!internal && !parent) return 0;
	if (internal == parent) internal = NULL;

	/*
	 *	Zero data, or empty line.
	 */
	if ((buffer == end) || (buffer[0] == 0)) {
		*token = T_EOL;
		return 0;
	}

#ifndef NDEBUG
	if (parent_vp) {
		fr_assert(ctx == parent_vp);
		fr_assert(list == &parent_vp->vp_group);
	}
#endif

	p = buffer;
	while (true) {
		bool is_raw = false;
		ssize_t slen;
		fr_token_t op;
		fr_dict_attr_t const *da, *my_parent;
		fr_dict_attr_t const *da_unknown = NULL;
		fr_dict_attr_err_t err;

		fr_skip_whitespace(p);

		/*
		 *	Stop at the end of the input, returning
		 *	whatever token was last read.
		 */
		if (!*p) break;

		if (*p == '#') {
			last_token = T_EOL;
			break;
		}

		/*
		 *	Stop at '}', too, if we're inside of a group.
		 */
		if ((depth > 0) && (*p == '}')) {
			last_token = T_RCBRACE;
			break;
		}

		/*
		 *	Relative attributes can only exist if there's a relative VP parent.
		 */
		if (*p == '.') {
			p++;

			if (!*relative_vp) {
				fr_strerror_const("The '.Attribute' syntax can only be used if the previous attribute is structural, and the line ends with ','");
				goto error;
			}

			my_parent = (*relative_vp)->da;
			my_list = &(*relative_vp)->vp_group;
			my_ctx = *relative_vp;
		} else {
			/*
			 *	Be nice to people who expect to see '&' everywhere.
			 */
			if (*p == '&') p++;

			/*
			 *	We can find an attribute from the parent, but if the path is fully specified,
			 *	then we reset any relative VP.  So that the _next_ line we parse cannot use
			 *	".foo = bar" to get a relative attribute which was used when parsing _this_
			 *	line.
			 */
			my_parent = parent;
			*relative_vp = NULL;
			my_list = list;
			my_ctx = ctx;

			/*
			 *	Raw attributes get a special parser.
			 */
			if (strncmp(p, "raw.", 4) == 0) {
				p += 4;
				is_raw = true;
			}
		}

		/*
		 *	Parse the name.
		 */
		slen = fr_dict_attr_by_oid_substr(&err, &da, my_parent, &FR_SBUFF_IN(p, (end - p)), &bareword_terminals);
		if (err == FR_DICT_ATTR_NOTFOUND) {
			if (is_raw) {
				/*
				 *	We have something like raw.KNOWN.26, let's go parse the unknown OID
				 *	portion, starting from where the parsing failed.
				 */
				if (((slen > 0) && (p[slen] == '.') && isdigit((int) p[slen + 1])) ||
				    ((slen == 0) && isdigit((int) *p))) {
					char const *q = p + slen + (slen > 0);

					slen = fr_dict_unknown_afrom_oid_substr(NULL, &da_unknown, da, &FR_SBUFF_IN(q, (end - q)));
					if (slen < 0) goto error;

					p = q;
					da = da_unknown;
					goto check_for_operator;
				}

				goto notfound;
			}

			/*
			 *	We have an internal dictionary, look up the attribute there.  Note that we
			 *	can't have raw internal attributes.
			 */
			if (internal) {
				slen = fr_dict_attr_by_oid_substr(&err, &da, internal,
								  &FR_SBUFF_IN(p, (end - p)), &bareword_terminals);
			}
		}
		if (err != FR_DICT_ATTR_OK) {
			if (slen < 0) slen = -slen;
			p += slen;

			/*
			 *	Regenerate the error message so that it's for the correct parent.
			 */
			if (err == FR_DICT_ATTR_NOTFOUND) {
				uint8_t const *q;

				if (!fr_dict_attr_allowed_chars[(unsigned char) *p]) {
					fr_strerror_printf("Invalid character '%c' in attribute name at %s", *p, p);
				} else {
				notfound:
					for (q = (uint8_t const *) p; q < (uint8_t const *) end && fr_dict_attr_allowed_chars[*q]; q++) {
						/* nothing */
					}
					fr_strerror_printf("Unknown attribute \"%.*s\" for parent \"%s\"", (int) (q - ((uint8_t const *) p)), p, my_parent->name);
				}
			}
		error:
			fr_dict_unknown_free(&da_unknown);
			*token = T_INVALID;
			return -(p - buffer);
		}

		/*
		 *	If we force it to be raw, then only do that if it's not already unknown.
		 */
		if (is_raw && !da_unknown) {
			da_unknown = fr_dict_unknown_afrom_da(ctx, da);
			if (!da_unknown) goto error;
			da = da_unknown;
		}

	check_for_operator:
#ifdef STATIC_ANALYZER
		if (!da) goto error;
#endif

		next = p + slen;

		rhs[0] = '\0';

		p = next;
		fr_skip_whitespace(p);
		op_p = p;

		/*
		 *	There must be an operator here.
		 */
		op = gettoken(&p, rhs, sizeof(rhs), false);
		if ((op  < T_EQSTART) || (op  > T_EQEND)) {
			fr_strerror_const("Expecting operator");
			goto error;
		}

		fr_skip_whitespace(p);

		if (parent_vp || (*relative_vp && ((*relative_vp)->da == da->parent)))  {
			vp = fr_pair_afrom_da(my_ctx, da);
			if (!vp) goto error;
			fr_pair_append(my_list, vp);

		} else if (*relative_vp) {

			if (op != T_OP_ADD_EQ) {
				fr_strerror_const("Relative attributes can only use '+=' for the operator");
				p = op_p;
				goto error;
			}

			vp = fr_pair_afrom_da_depth_nested(my_ctx, my_list, da, (*relative_vp)->da->depth);
			if (!vp) goto error;

		} else if (op != T_OP_ADD_EQ) {
			fr_assert(op != T_OP_PREPEND);

			vp = fr_pair_afrom_da_nested(my_ctx, my_list, da);
			if (!vp) goto error;

		} else {
			if (fr_pair_append_by_da_parent(my_ctx, &vp, my_list, da) < 0) goto error;
		}

		vp->op = op;

		/*
		 *	Peek ahead for structural elements which are raw.  If the caller wants to parse them
		 *	as a set of raw octets, then swap the data type to be octets.
		 */
		if (is_raw && (p[0] == '0') && (p[1] == 'x') && (da->type != FR_TYPE_OCTETS)) {
			fr_dict_unknown_free(&da_unknown);

			da_unknown = fr_dict_unknown_attr_afrom_da(vp, vp->da);
			if (!da_unknown) goto error;

			fr_assert(da_unknown->type == FR_TYPE_OCTETS);

			if (fr_pair_reinit_from_da(NULL, vp, da_unknown) < 0) goto error;

			da = vp->da;
			da_unknown = NULL;		/* already parented from vp */
		}

		/*
		 *	Allow grouping attributes.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_NON_LEAF:
			if ((op != T_OP_EQ) && (op != T_OP_CMP_EQ)) {
				fr_strerror_printf("Group list for %s MUST use '=' as the operator", da->name);
				goto error;
			}

			if (*p != '{') {
				fr_strerror_printf("Group list for %s MUST start with '{'", da->name);
				goto error;
			}
			p++;

			/*
			 *	Parse nested attributes, but the
			 *	attributes here are relative to each
			 *	other, and not to our parent relative VP.
			 */
			my_relative_vp = NULL;

			slen = pair_parse_legacy(vp, vp->da, vp, p, end, &vp->vp_group, &last_token, depth + 1, &my_relative_vp);
			if (slen <= 0) {
				goto error;
			}

			if (last_token != T_RCBRACE) {
			failed_group:
				fr_strerror_const("Failed to end group list with '}'");
				goto error;
			}

			p += slen;
			fr_skip_whitespace(p);
			if (*p != '}') goto failed_group;
			p++;

			/*
			 *	Cache which VP is now the one for
			 *	relative references.
			 */
			*relative_vp = vp;
			break;

		case FR_TYPE_LEAF:
			/*
			 *	Get the RHS thing.
			 */
			quote = gettoken(&p, rhs, sizeof(rhs), false);
			if (quote == T_EOL) {
				fr_strerror_const("Failed to get value");
				goto error;
			}

			switch (quote) {
			case T_DOUBLE_QUOTED_STRING:
			case T_SINGLE_QUOTED_STRING:
			case T_BACK_QUOTED_STRING:
			case T_BARE_WORD:
				break;

			default:
				fr_strerror_printf("Failed to find expected value on right hand side in %s", da->name);
				goto error;
			}

			fr_skip_whitespace(p);

			/*
			 *	Regular expressions get sanity checked by pair_make().
			 *
			 *	@todo - note that they will also be escaped,
			 *	so we may need to fix that later.
			 */
			if ((vp->op == T_OP_REG_EQ) || (vp->op == T_OP_REG_NE)) {
				if (fr_pair_value_bstrndup(vp, rhs, strlen(rhs), false) < 0) goto error;

			} else if ((vp->op == T_OP_CMP_TRUE) || (vp->op == T_OP_CMP_FALSE)) {
				/*
				 *	We don't care what the value is, so
				 *	ignore it.
				 */
				break;
			}

			if (fr_pair_value_from_str(vp, rhs, strlen(rhs),
						   fr_value_unescape_by_quote[quote], false) < 0) goto error;
			break;
		}

		/*
		 *	Free the unknown attribute, we don't need it any more.
		 */
		fr_dict_unknown_free(&da_unknown);

		fr_assert(vp != NULL);

		PAIR_VERIFY(vp);

		/*
		 *	Now look for EOL, hash, etc.
		 */
		if (!*p || (*p == '#') || (*p == '\n')) {
			last_token = T_EOL;
			break;
		}

		fr_skip_whitespace(p);

		/*
		 *	Stop at '}', too, if we're inside of a group.
		 */
		if ((depth > 0) && (*p == '}')) {
			last_token = T_RCBRACE;
			break;
		}

		if (*p != ',') {
			fr_strerror_printf("Expected ',', got '%c' at offset %zu", *p, p - buffer);
			goto error;
		}
		p++;
		last_token = T_COMMA;
	}

	/*
	 *	And return the last token which we read.
	 */
	*token = last_token;
	return p - buffer;
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param[in] ctx	for talloc
 * @param[in] parent	parent attribute for resolution
 * @param[in] buffer	to read valuepairs from.
 * @param[in] len	length of the buffer
 * @param[in] list	where the parsed fr_pair_ts will be appended.
 * @return the last token parsed, or #T_INVALID
 */
fr_token_t fr_pair_list_afrom_str(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, char const *buffer, size_t len, fr_pair_list_t *list)
{
	fr_token_t token;
	fr_pair_t    *relative_vp = NULL;
	fr_pair_list_t tmp_list;

	fr_pair_list_init(&tmp_list);

	if (pair_parse_legacy(ctx, parent, NULL, buffer, buffer + len, &tmp_list, &token, 0, &relative_vp) < 0) {
		fr_pair_list_free(&tmp_list);
		return T_INVALID;
	}

	fr_pair_list_append(list, &tmp_list);

	return token;
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
	fr_token_t	last_token = T_EOL;
	bool		found = false;
	fr_pair_list_t tmp_list;
	fr_pair_t	*relative_vp = NULL;
	char		buf[8192];

	/*
	 *	Read all of the attributes on the current line.
	 *
	 *	If we get nothing but an EOL, it's likely OK.
	 */
	fr_pair_list_init(&tmp_list);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP list.
		 */
		if (buf[0] == '\n') {
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
		 *	Call our internal function, instead of the public wrapper.
		 */
		if (pair_parse_legacy(ctx, fr_dict_root(dict), NULL, buf, buf + strlen(buf), &tmp_list, &last_token, 0, &relative_vp) < 0) {
			goto fail;
		}

		/*
		 *	@todo - rely on actually checking the syntax, and "OK" result, instead of guessing.
		 *
		 *	The main issue is that it's OK to read no
		 *	attributes on a particular line, but only if
		 *	it's comments.
		 */
		if (!fr_pair_list_num_elements(&tmp_list)) {
			/*
			 *	This is allowed for relative attributes.
			 */
			if (relative_vp) {
				if (last_token != T_COMMA) relative_vp = NULL;
				continue;
			}

			/*
			 *	Blank line by itself, with no relative
			 *	VP, and no output attributes means
			 *	that we stop reading the file.
			 */
			if (last_token == T_EOL) break;

		fail:
			/*
			 *	Didn't read anything, but the previous
			 *	line wasn't EOL.  The input file has a
			 *	format error.
			 */
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
 * @note This function does some additional magic that's probably not needed
 *	 in most places. Consider using radius_pairmove in server code.
 *
 * @note fr_pair_list_free should be called on the head of the source list to free
 *	 unmoved attributes (if they're no longer needed).
 *
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 * @param[in] op operator for list move.
 *
 * @see radius_pairmove
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
			 *	Delete *all* matching attribues.
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
