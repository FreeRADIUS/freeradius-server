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
 * @file src/lib/server/cond_tokenize.c
 * @brief Parse complex conditions
 *
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

static fr_table_num_sorted_t const allowed_return_codes[] = {
	{ L("fail"),		1 },
	{ L("handled"),		1 },
	{ L("invalid"),		1 },
	{ L("noop"),		1 },
	{ L("notfound"),	1 },
	{ L("ok"),		1 },
	{ L("reject"),		1 },
	{ L("updated"),		1 },
	{ L("disallow"),	1 }
};
static size_t allowed_return_codes_len = NUM_ELEMENTS(allowed_return_codes);

fr_table_num_sorted_t const cond_quote_table[] = {
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},	/* Don't re-order, backslash throws off ordering */
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("/"),	T_SOLIDUS_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
size_t cond_quote_table_len = NUM_ELEMENTS(cond_quote_table);

fr_table_num_sorted_t const cond_logical_op_table[] = {
	{ L("&&"),	COND_AND		},
	{ L("||"),	COND_OR			}
};
size_t cond_logical_op_table_len = NUM_ELEMENTS(cond_logical_op_table);

fr_table_num_sorted_t const cond_cmp_op_table[] = {
	{ L("!*"),	T_OP_CMP_FALSE		},
	{ L("!="),	T_OP_NE			},
	{ L("!~"),	T_OP_REG_NE		},
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
size_t cond_cmp_op_table_len = NUM_ELEMENTS(cond_cmp_op_table);

/*
 *	This file shouldn't use any functions from the server core.
 */
ssize_t cond_print(fr_sbuff_t *out, fr_cond_t const *in)
{
	fr_sbuff_t		our_out = FR_SBUFF_NO_ADVANCE(out);
	fr_cond_t const		*c = in;

	while (c) {
		if (c->negate) FR_SBUFF_IN_CHAR_RETURN(&our_out, '!');

		switch (c->type) {
		case COND_TYPE_EXISTS:
			fr_assert(c->data.vpt != NULL);
			if (c->cast) {
				FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "<%s>",
							   fr_table_str_by_value(fr_value_box_type_table,
										 c->cast->type, "??"));
			}
			FR_SBUFF_RETURN(tmpl_print_quoted, &our_out, c->data.vpt, TMPL_ATTR_REF_PREFIX_YES);
			break;

		case COND_TYPE_RCODE:
			fr_assert(c->data.rcode != RLM_MODULE_UNKNOWN);
			FR_SBUFF_IN_STRCPY_RETURN(&our_out, fr_table_str_by_value(rcode_table, c->data.rcode, ""));
			break;

		case COND_TYPE_MAP:
			if (c->cast) {
				FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "<%s>",
							   fr_table_str_by_value(fr_value_box_type_table,
										 c->cast->type, "??"));
			}
			FR_SBUFF_RETURN(map_print, &our_out, c->data.map);
			break;

		case COND_TYPE_CHILD:
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '(');
			FR_SBUFF_RETURN(cond_print, &our_out, c->data.child);
			FR_SBUFF_IN_CHAR_RETURN(&our_out, ')');
			break;

		case COND_TYPE_TRUE:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "true");
			break;

		case COND_TYPE_FALSE:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "false");
			break;

		default:
			break;
		}

		if (c->next_op == COND_NONE) {
			fr_assert(c->next == NULL);
			goto done;
		}

		switch (c->next_op) {
		case COND_AND:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, " && ");
			break;

		case COND_OR:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, " || ");
			break;

		default:
			fr_assert(0);
		}
		c = c->next;
	}

done:
	fr_sbuff_terminate(&our_out);
	return fr_sbuff_set(out, &our_out);
}


static bool cond_type_check(fr_cond_t *c, fr_type_t lhs_type)
{
	/*
	 *	SOME integer mismatch is OK.  If the LHS has a large type,
	 *	and the RHS has a small type, it's OK.
	 *
	 *	If the LHS has a small type, and the RHS has a large type,
	 *	then add a cast to the LHS.
	 */
	if (lhs_type == FR_TYPE_UINT64) {
		if ((tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT32) ||
		    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT16) ||
		    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT8)) {
			c->cast = NULL;
			return true;
		}
	}

	if (lhs_type == FR_TYPE_UINT32) {
		if ((tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT16) ||
		    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT8)) {
			c->cast = NULL;
			return true;
		}

		if (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT64) {
			c->cast = tmpl_da(c->data.map->rhs);
			return true;
		}
	}

	if (lhs_type == FR_TYPE_UINT16) {
		if (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT8) {
			c->cast = NULL;
			return true;
		}

		if ((tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT64) ||
		    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT32)) {
			c->cast = tmpl_da(c->data.map->rhs);
			return true;
		}
	}

	if (lhs_type == FR_TYPE_UINT8) {
		if ((tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT64) ||
		    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT32) ||
		    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_UINT16)) {
			c->cast = tmpl_da(c->data.map->rhs);
			return true;
		}
	}

	if ((lhs_type == FR_TYPE_IPV4_PREFIX) &&
	    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_IPV4_ADDR)) {
		return true;
	}

	if ((lhs_type == FR_TYPE_IPV6_PREFIX) &&
	    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_IPV6_ADDR)) {
		return true;
	}

	/*
	 *	Same checks as above, but with the types swapped, and
	 *	with explicit cast for the interpretor.
	 */
	if ((lhs_type == FR_TYPE_IPV4_ADDR) &&
	    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_IPV4_PREFIX)) {
		c->cast = tmpl_da(c->data.map->rhs);
		return true;
	}

	if ((lhs_type == FR_TYPE_IPV6_ADDR) &&
	    (tmpl_da(c->data.map->rhs)->type == FR_TYPE_IPV6_PREFIX)) {
		c->cast = tmpl_da(c->data.map->rhs);
		return true;
	}

	return false;
}


/*
 *	Less code means less bugs
 */
#define return_P(_x) *error = _x;goto return_p
#define return_0(_x) *error = _x;goto return_0
#define return_lhs(_x) *error = _x;goto return_lhs
#define return_rhs(_x) *error = _x;goto return_rhs
#define return_SLEN goto return_slen

static ssize_t cond_check_cast(fr_cond_t *c, char const *start,
			       char const *lhs, char const *rhs)
{
	if (tmpl_is_attr(c->data.map->rhs) &&
	    (c->cast->type != tmpl_da(c->data.map->rhs)->type)) {
		if (cond_type_check(c, c->cast->type)) {
			return 1;
		}

		fr_strerror_printf("Cannot compare types '%s' (cast) and '%s' (attr)",
				   fr_table_str_by_value(fr_value_box_type_table, c->cast->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, tmpl_da(c->data.map->rhs)->type, "<INVALID>"));
		return 0;
	}

#ifdef HAVE_REGEX
	if (tmpl_contains_regex(c->data.map->rhs)) {
		fr_strerror_printf("Cannot use cast with regex comparison");
		return -(rhs - start);
	}
#endif

	/*
	 *	The LHS is a literal which has been cast to a data type.
	 *	Cast it to the appropriate data type.
	 */
	if (tmpl_is_unresolved(c->data.map->lhs) &&
	    (tmpl_cast_in_place(c->data.map->lhs, c->cast->type, c->cast) < 0)) {
		fr_strerror_printf("Failed to parse field");
		return -(lhs - start);
	}

	/*
	 *	The RHS is a literal, and the LHS has been cast to a data
	 *	type.
	 */
	if ((tmpl_is_data(c->data.map->lhs)) &&
	    (tmpl_is_unresolved(c->data.map->rhs)) &&
	    (tmpl_cast_in_place(c->data.map->rhs, c->cast->type, c->cast) < 0)) {
		fr_strerror_printf("Failed to parse field");
		return -(rhs - start);
	}

	/*
	 *	We may be casting incompatible
	 *	types.  We check this based on
	 *	their size.
	 */
	if (tmpl_is_attr(c->data.map->lhs)) {
		/*
		 *      dst.min == src.min
		 *	dst.max == src.max
		 */
		if ((dict_attr_sizes[c->cast->type][0] == dict_attr_sizes[tmpl_da(c->data.map->lhs)->type][0]) &&
		    (dict_attr_sizes[c->cast->type][1] == dict_attr_sizes[tmpl_da(c->data.map->lhs)->type][1])) {
			goto cast_ok;
		}

		/*
		 *	Run-time parsing of strings.
		 *	Run-time copying of octets.
		 */
		if ((tmpl_da(c->data.map->lhs)->type == FR_TYPE_STRING) ||
		    (tmpl_da(c->data.map->lhs)->type == FR_TYPE_OCTETS)) {
			goto cast_ok;
		}

		/*
		 *	ifid to uint64 is OK
		 */
		if ((tmpl_da(c->data.map->lhs)->type == FR_TYPE_IFID) &&
		    (c->cast->type == FR_TYPE_UINT64)) {
			goto cast_ok;
		}

		/*
		 *	ipaddr to ipv4prefix is OK
		 */
		if ((tmpl_da(c->data.map->lhs)->type == FR_TYPE_IPV4_ADDR) &&
		    (c->cast->type == FR_TYPE_IPV4_PREFIX)) {
			goto cast_ok;
		}

		/*
		 *	ipv6addr to ipv6prefix is OK
		 */
		if ((tmpl_da(c->data.map->lhs)->type == FR_TYPE_IPV6_ADDR) &&
		    (c->cast->type == FR_TYPE_IPV6_PREFIX)) {
			goto cast_ok;
		}

		/*
		 *	uint64 to ethernet is OK.
		 */
		if ((tmpl_da(c->data.map->lhs)->type == FR_TYPE_UINT64) &&
		    (c->cast->type == FR_TYPE_ETHERNET)) {
			goto cast_ok;
		}

		/*
		 *	dst.max < src.min
		 *	dst.min > src.max
		 */
		if ((dict_attr_sizes[c->cast->type][1] < dict_attr_sizes[tmpl_da(c->data.map->lhs)->type][0]) ||
		    (dict_attr_sizes[c->cast->type][0] > dict_attr_sizes[tmpl_da(c->data.map->lhs)->type][1])) {
			fr_strerror_printf("Cannot cast to attribute of incompatible size");
			return 0;
		}
	}

cast_ok:
	/*
	 *	Casting to a redundant type means we don't need the cast.
	 *
	 *	Do this LAST, as the rest of the code above assumes c->cast
	 *	is not NULL.
	 */
	if (tmpl_is_attr(c->data.map->lhs) &&
	    (c->cast->type == tmpl_da(c->data.map->lhs)->type)) {
		c->cast = NULL;
	}

	return 1;
}

/*
 *	See if two attribute comparisons are OK.
 */
static ssize_t cond_check_attrs(fr_cond_t *c, fr_sbuff_marker_t *m_lhs, fr_sbuff_marker_t *m_rhs)
{
	tmpl_t		*attr, *data, *xlat, *unresolved, *xlat_unresolved, *exec, *vpt;
	tmpl_t		*lhs = c->data.map->lhs, *rhs = c->data.map->rhs;
	fr_token_t	op = c->data.map->op;

/** True if one operand is of _type_a and the other of _type_b
 */
#define TMPL_OF_TYPE_A_B(_type_a, _type_b) \
	((((tmpl_is_##_type_a(lhs) && (_type_a = lhs)) && (tmpl_is_##_type_b(rhs) && (_type_b = rhs)))) || \
	(((tmpl_is_##_type_a(rhs) && (_type_a = rhs)) && (tmpl_is_##_type_b(lhs) && (_type_b = lhs)))))

/** True if one operand is of _type_a and the other is not of _type_a
 *
 */
#define TMPL_OF_TYPE_A_NOT_A(_type_a, _out_b) \
	((((tmpl_is_##_type_a(lhs) && (_type_a = lhs)) && (!tmpl_is_##_type_a(rhs) && (_out_b = rhs)))) || \
	(((tmpl_is_##_type_a(rhs) && (_type_a = rhs)) && (!tmpl_is_##_type_a(lhs) && (_out_b = lhs)))))

/** True if both operands are of _type_a
 *
 */
#define TMPL_OF_TYPE_A_A(_type_a) \
	((tmpl_is_##_type_a(lhs)) && (tmpl_is_##_type_a(rhs)))

#define TMPL_RETURN(_vpt) return -((_vpt) == lhs ? fr_sbuff_used(m_lhs) : fr_sbuff_used(m_rhs))

	/*
	 *	Attribute comparison with a box
	 */
	if (TMPL_OF_TYPE_A_B(attr, data)) {
		fr_type_t		type = tmpl_da(attr)->type;

		/*
		 *	Most of the time the box type takes
		 *	precedence, except in the case of a few types
		 *	like IP prefixes.
		 */
		switch (tmpl_value_type(data)) {
		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_PREFIX:
			type = tmpl_value_type(data);
			break;

		default:
			break;
		}

		if (tmpl_cast_in_place(data, type, tmpl_da(attr)) < 0) {
			fr_strerror_printf_push("Failed casting data to match attribute");
			return -(data == lhs ? fr_sbuff_used(m_lhs) : fr_sbuff_used(m_rhs));
		}
	}

	/*
	 *	Two attributes?  They must be of the same type
	 */
	if (TMPL_OF_TYPE_A_A(attr) && (tmpl_da(lhs)->type != tmpl_da(rhs)->type)) {
		if (cond_type_check(c, tmpl_da(lhs)->type)) return 1;	/* Or be mungeable to the same type */

		fr_strerror_printf("Cannot compare attributes of type '%s' and '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, tmpl_da(lhs)->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, tmpl_da(rhs)->type, "<INVALID>"));
		return 0;
	}

	/*
	 *	The LHS has been cast to a data type, and the RHS is a
	 *	literal.  Cast the RHS to the type of the cast.
	 *
	 *	FIXME - We should revisit this when RHS casting is supported.
	 */
	if (c->cast && tmpl_is_unresolved(rhs) &&
	    (tmpl_cast_in_place(rhs, c->cast->type, c->cast) < 0)) {
	    	fr_strerror_printf("Failed to parse field");
		return -fr_sbuff_used(m_rhs);
	}

	/*
	 *	The LHS is an attribute, and the RHS is a literal.  Cast the
	 *	RHS to the data type of the LHS.
	 *
	 *	Note: There's a hack in here to always parse RHS as the
	 *	equivalent prefix type if the LHS is an IP address.
	 *
	 *	This allows Framed-IP-Address < 192.168.0.0./24
	 */
	unresolved = NULL;
	data = NULL;	/* gcc stupidity */
	if (TMPL_OF_TYPE_A_B(attr, unresolved) || TMPL_OF_TYPE_A_B(attr, data)) {
		fr_type_t type = tmpl_da(attr)->type;

		vpt = unresolved ? unresolved : data;

		/*
		 *	Invalid: User-Name == bob
		 *	Valid:   User-Name == "bob"
		 *
		 *	There's no real reason for
		 *	this, other than consistency.
		 */
		if ((unresolved || (data && tmpl_value_type(data) == FR_TYPE_STRING)) &&
		    (tmpl_da(attr)->type == FR_TYPE_STRING) &&
		    (op != T_OP_CMP_TRUE) &&
		    (op != T_OP_CMP_FALSE) &&
		    (vpt->quote == T_BARE_WORD)) {
			fr_strerror_printf("Comparison value must be a quoted string");
			TMPL_RETURN(vpt);
		}

		switch (tmpl_da(attr)->type) {
		case FR_TYPE_IPV4_ADDR:
			if (strchr(vpt->name, '/') != NULL) {
				type = FR_TYPE_IPV4_PREFIX;
				c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CAST_BASE + type);
			}
			break;

		case FR_TYPE_IPV6_ADDR:
			if (strchr(vpt->name, '/') != NULL) {
				type = FR_TYPE_IPV6_PREFIX;
				c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CAST_BASE + type);
			}
			break;

		default:
			break;
		}

		/*
		 *	Do not pass LHS as enumv if we're casting
		 *	as that means there's now a type mismatch between
		 *	attr and vpt, which means the enumerations
		 *	can never match.
		 */
		if (tmpl_cast_in_place(vpt, type,
				       c->cast ? NULL : tmpl_da(attr)) < 0) {
			fr_dict_attr_t const *da = tmpl_da(attr);

			switch (da->attr) {
			case FR_AUTH_TYPE:
				/*
				 *	The types for these attributes are dynamically allocated
				 *	by module.c, so we can't enforce strictness here.
				 */
				c->pass2_fixup = PASS2_FIXUP_TYPE;
				break;

			default:
				if (!attr->data.attribute.was_oid) {
					fr_strerror_printf("Failed to parse value for attribute");
					TMPL_RETURN(vpt);
				}
				/*
				 *	Convert the attr to a raw type and
				 *	try the cast again.
				 */
				tmpl_attr_to_raw(attr);
				if (tmpl_cast_in_place(vpt, tmpl_da(attr)->type,
						       c->cast ? NULL : tmpl_da(attr)) < 0) {
					fr_strerror_printf("Failed to parse value for attribute");
					TMPL_RETURN(vpt);
				}
				break;
			}
		}

		/*
		 *	Stupid WiMAX shit.
		 *	Cast the LHS to the
		 *	type of the RHS.
		 */
		if (tmpl_da(attr)->type == FR_TYPE_COMBO_IP_ADDR) {
			if (tmpl_attr_abstract_to_concrete(attr, tmpl_value_type(vpt)) < 0) {
				fr_strerror_printf("Cannot find type for attribute");
				TMPL_RETURN(attr);
			}
		}
	} /* attr to literal comparison */

	/*
	 *	If one side is unresolved, and the other is data,
	 *	we can use the data type to attempt a cast on the
	 *	unresolved side.
	 */
	if (TMPL_OF_TYPE_A_B(data, unresolved) &&
	    (tmpl_cast_in_place(unresolved, tmpl_value_type(data), NULL) < 0)) TMPL_RETURN(unresolved);

	/*
	 *	The RHS will turn into... something.  Allow for prefixes
	 *	there, too.
	 */
	if (TMPL_OF_TYPE_A_B(attr, xlat_unresolved) || TMPL_OF_TYPE_A_B(attr, xlat) || TMPL_OF_TYPE_A_B(attr, exec)) {
		if (tmpl_da(attr)->type == FR_TYPE_IPV4_ADDR) {
			c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
							    FR_CAST_BASE + FR_TYPE_IPV4_PREFIX);
		}

		if (tmpl_da(attr)->type == FR_TYPE_IPV6_ADDR) {
			c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()),
							    FR_CAST_BASE + FR_TYPE_IPV6_PREFIX);
		}
	}

	/*
	 *	If the LHS is a bare word, AND it looks like
	 *	an attribute, try to parse it as such.
	 *
	 *	This allows LDAP-Group and SQL-Group to work.
	 *
	 *	The real fix is to just read the config files,
	 *	and do no parsing until after all of the modules
	 *	are loaded.  But that has issues, too.
	 */
	if (tmpl_is_unresolved(lhs) && (lhs->quote == T_BARE_WORD)) {
		int hyphens = 0;
		bool may_be_attr = true;
		size_t i;
		ssize_t attr_slen;

		/*
		 *	Backwards compatibility: Allow Foo-Bar,
		 *	e.g. LDAP-Group and SQL-Group.
		 */
		for (i = 0; i < lhs->len; i++) {
			if (!fr_dict_attr_allowed_chars[(uint8_t) lhs->name[i]]) {
				may_be_attr = false;
				break;
			}

			if (lhs->name[i] == '-') {
				hyphens++;
			}
		}

		if (!hyphens || (hyphens > 3)) may_be_attr = false;

		if (may_be_attr) {
			attr_slen = tmpl_afrom_attr_str(c->data.map, NULL, &vpt, fr_sbuff_current(m_lhs),
							&(tmpl_rules_t){
								.allow_unknown = true,
								.allow_unresolved = true
							});
			if ((attr_slen > 0) && (vpt->len == lhs->len)) {
				talloc_free(lhs);
				c->pass2_fixup = PASS2_FIXUP_ATTR;
			}
		}
	}

	return 1;
}

static int cond_normalise(TALLOC_CTX *ctx, fr_token_t lhs_type, fr_cond_t **c_out)
{
	fr_cond_t *c = *c_out;

	/*
	 *	Normalize the condition before returning.
	 *
	 *	We collapse multiple levels of braces to one.  Then
	 *	convert maps to literals.  Then literals to true/false
	 *	statements.  Then true/false ||/&& followed by other
	 *	conditions to just conditions.
	 *
	 *	Order is important.  The more complex cases are
	 *	converted to simpler ones, from the most complex cases
	 *	to the simplest ones.
	 */

	/*
	 *	(FOO)     --> FOO
	 *	(FOO) ... --> FOO ...
	 */
	if ((c->type == COND_TYPE_CHILD) && !c->data.child->next) {
		fr_cond_t *child;

		child = talloc_steal(ctx, c->data.child);
		c->data.child = NULL;

		child->next = talloc_steal(child, c->next);
		c->next = NULL;

		child->next_op = c->next_op;

		/*
		 *	Set the negation properly
		 */
		if ((c->negate && !child->negate) ||
		    (!c->negate && child->negate)) {
			child->negate = true;
		} else {
			child->negate = false;
		}

		talloc_free(c);
		c = child;
	}

	/*
	 *	(FOO ...) --> FOO ...
	 *
	 *	But don't do !(FOO || BAR) --> !FOO || BAR
	 *	Because that's different.
	 */
	if ((c->type == COND_TYPE_CHILD) &&
	    !c->next && !c->negate) {
		fr_cond_t *child;

		child = talloc_steal(ctx, c->data.child);
		c->data.child = NULL;

		talloc_free(c);
		c = child;
	}

	/*
	 *	Convert maps to literals.  Convert one form of map to
	 *	a standardized form.  This doesn't make any
	 *	theoretical difference, but it does mean that the
	 *	run-time evaluation has fewer cases to check.
	 */
	if (c->type == COND_TYPE_MAP) do {
		/*
		 *	!FOO !~ BAR --> FOO =~ BAR
		 */
		if (c->negate && (c->data.map->op == T_OP_REG_NE)) {
			c->negate = false;
			c->data.map->op = T_OP_REG_EQ;
		}

		/*
		 *	FOO !~ BAR --> !FOO =~ BAR
		 */
		if (!c->negate && (c->data.map->op == T_OP_REG_NE)) {
			c->negate = true;
			c->data.map->op = T_OP_REG_EQ;
		}

		/*
		 *	!FOO != BAR --> FOO == BAR
		 */
		if (c->negate && (c->data.map->op == T_OP_NE)) {
			c->negate = false;
			c->data.map->op = T_OP_CMP_EQ;
		}

		/*
		 *	This next one catches "LDAP-Group != foo",
		 *	which doesn't work as-is, but this hack fixes
		 *	it.
		 *
		 *	FOO != BAR --> !FOO == BAR
		 */
		if (!c->negate && (c->data.map->op == T_OP_NE)) {
			c->negate = true;
			c->data.map->op = T_OP_CMP_EQ;
		}

		/*
		 *	FOO =* BAR --> FOO
		 *	FOO !* BAR --> !FOO
		 *
		 *	FOO may be a string, or a delayed attribute
		 *	reference.
		 */
		if ((c->data.map->op == T_OP_CMP_TRUE) ||
		    (c->data.map->op == T_OP_CMP_FALSE)) {
			tmpl_t *vpt;

			vpt = talloc_steal(c, c->data.map->lhs);
			c->data.map->lhs = NULL;

			/*
			 *	Invert the negation bit.
			 */
			if (c->data.map->op == T_OP_CMP_FALSE) {
				c->negate = !c->negate;
			}

			TALLOC_FREE(c->data.map);

			c->type = COND_TYPE_EXISTS;
			c->data.vpt = vpt;
			break;	/* it's no longer a map */
		}

		/*
		 *	Both are data (IP address, integer, etc.)
		 *
		 *	We can do the evaluation here, so that it
		 *	doesn't need to be done at run time
		 */
		if (tmpl_is_data(c->data.map->lhs) &&
		    tmpl_is_data(c->data.map->rhs)) {
			int rcode;

			rcode = cond_eval_map(NULL, 0, c);
			TALLOC_FREE(c->data.map);
			c->cast = NULL;
			if (rcode) {
				c->type = COND_TYPE_TRUE;
			} else {
				c->type = COND_TYPE_FALSE;
			}

			break;	/* it's no longer a map */
		}

		/*
		 *	Both are literal strings.  They're not parsed
		 *	as TMPL_TYPE_DATA because there's no cast to an
		 *	attribute.
		 *
		 *	We can do the evaluation here, so that it
		 *	doesn't need to be done at run time
		 */
		if (tmpl_is_unresolved(c->data.map->rhs) &&
		    tmpl_is_unresolved(c->data.map->lhs) &&
		    !c->pass2_fixup) {
			int rcode;

			fr_assert(c->cast == NULL);

			rcode = cond_eval_map(NULL, 0, c);
			if (rcode) {
				c->type = COND_TYPE_TRUE;
			} else {
				DEBUG4("OPTIMIZING (%s %s %s) --> FALSE",
				       c->data.map->lhs->name,
				       fr_table_str_by_value(fr_tokens_table, c->data.map->op, "??"),
				       c->data.map->rhs->name);
				c->type = COND_TYPE_FALSE;
			}

			/*
			 *	Free map after using it above.
			 */
			TALLOC_FREE(c->data.map);
			break;
		}

		/*
		 *	<ipaddr>"foo" CMP &Attribute-Name The cast may
		 *	not be necessary, and we can re-write it so
		 *	that the attribute reference is on the LHS.
		 */
		if (c->cast &&
		    tmpl_is_attr(c->data.map->rhs) &&
		    (c->cast->type == tmpl_da(c->data.map->rhs)->type) &&
		    !tmpl_is_attr(c->data.map->lhs)) {
			tmpl_t *tmp;

			tmp = c->data.map->rhs;
			c->data.map->rhs = c->data.map->lhs;
			c->data.map->lhs = tmp;

			c->cast = NULL;

			switch (c->data.map->op) {
			case T_OP_CMP_EQ:
				/* do nothing */
				break;

			case T_OP_LE:
				c->data.map->op = T_OP_GE;
				break;

			case T_OP_LT:
				c->data.map->op = T_OP_GT;
				break;

			case T_OP_GE:
				c->data.map->op = T_OP_LE;
				break;

			case T_OP_GT:
				c->data.map->op = T_OP_LT;
				break;

			default:
				fr_strerror_printf("Internal sanity check failed 1");
				return -1;
			}

			/*
			 *	This must have been parsed into TMPL_TYPE_DATA.
			 */
			fr_assert(!tmpl_is_unresolved(c->data.map->rhs));
		}

	} while (0);

	/*
	 *	Existence checks.  We short-circuit static strings,
	 *	too.
	 *
	 *	FIXME: the data types should be in the template, too.
	 *	So that we know where a literal came from.
	 *
	 *	"foo" is NOT the same as 'foo' or a bare foo.
	 */
	if (c->type == COND_TYPE_EXISTS) {
		switch (c->data.vpt->type) {
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_XLAT_UNRESOLVED:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_ATTR_UNRESOLVED:
		case TMPL_TYPE_LIST:
		case TMPL_TYPE_EXEC:
			break;

		/*
		 *	'true' and 'false' are special strings
		 *	which mean themselves.
		 *
		 *	For integers, 0 is false, all other
		 *	integers are true.
		 *
		 *	For strings, '' and "" are false.
		 *	'foo' and "foo" are true.
		 *
		 *	The str2tmpl function takes care of
		 *	marking "%{foo}" as TMPL_TYPE_XLAT_UNRESOLVED, so
		 *	the strings here are fixed at compile
		 *	time.
		 *
		 *	`exec` and "%{...}" are left alone.
		 *
		 *	Bare words must be module return
		 *	codes.
		 */
		case TMPL_TYPE_UNRESOLVED:
			if (!*c->data.vpt->name) {
				c->type = COND_TYPE_FALSE;
				TALLOC_FREE(c->data.vpt);

			} else if ((lhs_type == T_SINGLE_QUOTED_STRING) ||
				   (lhs_type == T_DOUBLE_QUOTED_STRING)) {
				c->type = COND_TYPE_TRUE;
				TALLOC_FREE(c->data.vpt);

			} else if (lhs_type == T_BARE_WORD) {
				int rcode;
				bool zeros = true;
				char const *q;

				for (q = c->data.vpt->name;
				     *q != '\0';
				     q++) {
					if (!isdigit((int) *q)) {
						break;
					}
					if (*q != '0') zeros = false;
				}

				/*
				 *	It's all digits, and therefore
				 *	'false' if zero, and 'true' otherwise.
				 */
				if (!*q) {
					if (zeros) {
						c->type = COND_TYPE_FALSE;
					} else {
						c->type = COND_TYPE_TRUE;
					}
					TALLOC_FREE(c->data.vpt);
					break;
				}

				/*
				 *	Allow &Foo-Bar where Foo-Bar is an attribute
				 *	defined by a module.
				 */
				if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
					break;
				}

				rcode = fr_table_value_by_str(allowed_return_codes, c->data.vpt->name, 0);
				if (!rcode) {
					fr_strerror_printf("Expected a module return code");
					return -1;
				}
			}

			/*
			 *	Else lhs_type==T_INVALID, and this
			 *	node was made by promoting a child
			 *	which had already been normalized.
			 */
			break;

		case TMPL_TYPE_DATA:
		{
			fr_value_box_t res;

			if (fr_value_box_cast(NULL, &res, FR_TYPE_BOOL, NULL, tmpl_value(c->data.vpt)) < 0) return -1;
			c->type = res.vb_bool ? COND_TYPE_TRUE : COND_TYPE_FALSE;
			TALLOC_FREE(c->data.vpt);
		}
			break;

		default:
			fr_assert_fail("Internal sanity check failed 2");
			return -1;
		}
	}

	/*
	 *	!TRUE -> FALSE
	 */
	if (c->type == COND_TYPE_TRUE) {
		if (c->negate) {
			c->negate = false;
			c->type = COND_TYPE_FALSE;
		}
	}

	/*
	 *	!FALSE -> TRUE
	 */
	if (c->type == COND_TYPE_FALSE) {
		if (c->negate) {
			c->negate = false;
			c->type = COND_TYPE_TRUE;
		}
	}

	/*
	 *	true && FOO --> FOO
	 */
	if ((c->type == COND_TYPE_TRUE) &&
	    (c->next_op == COND_AND)) {
		fr_cond_t *next;

		next = talloc_steal(ctx, c->next);
		c->next = NULL;

		talloc_free(c);
		c = next;
	}

	/*
	 *	false && FOO --> false
	 */
	if ((c->type == COND_TYPE_FALSE) &&
	    (c->next_op == COND_AND)) {

		talloc_free(c->next);
		c->next = NULL;
		c->next_op = COND_NONE;
	}

	/*
	 *	false || FOO --> FOO
	 */
	if ((c->type == COND_TYPE_FALSE) &&
	    (c->next_op == COND_OR)) {
		fr_cond_t *next;

		next = talloc_steal(ctx, c->next);
		c->next = NULL;

		talloc_free(c);
		c = next;
	}

	/*
	 *	true || FOO --> true
	 */
	if ((c->type == COND_TYPE_TRUE) &&
	    (c->next_op == COND_OR)) {

		talloc_free(c->next);
		c->next = NULL;
		c->next_op = COND_NONE;
	}

	*c_out = c;

	return 0;
}

static int cond_forbid_groups(tmpl_t *vpt, fr_sbuff_t *in, fr_sbuff_marker_t *m_lhs)
{
	if (tmpl_is_list(vpt)) {
		fr_strerror_printf("Cannot use list references in condition");
		fr_sbuff_set(in, m_lhs);
		return -1;
	}

	if (!tmpl_is_attr(vpt)) return 0;

	switch (tmpl_da(vpt)->type) {
	case FR_TYPE_VALUE:
		break;

	default:
		fr_strerror_printf("Nesting types such as groups or TLVs cannot "
				   "be used in condition comparisons");
		fr_sbuff_set(in, m_lhs);
		return -1;
	}

	return 0;
}

static ssize_t cond_tokenize_operand(TALLOC_CTX *ctx, tmpl_t **out,
				     fr_sbuff_marker_t *opd_start, fr_sbuff_t *in,
				     tmpl_rules_t const *rules)
{
	fr_sbuff_term_t const 		bareword_terminals =
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

	fr_sbuff_t			our_in = FR_SBUFF_NO_ADVANCE(in);
	fr_sbuff_marker_t		m;
	tmpl_t				*vpt;
	fr_token_t			type;
	fr_type_t			cast = FR_TYPE_INVALID;
	fr_sbuff_parse_rules_t		tmp_p_rules;
	fr_sbuff_parse_rules_t const	*p_rules;
	ssize_t				slen;

	*out = NULL;

	/*
	 *	Parse (optional) cast
	 */
	slen = tmpl_cast_from_substr(&cast, &our_in);
	if (slen < 0) return slen;

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);
	fr_sbuff_marker(&m, &our_in);

	/*
	 *	Check for quoting
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &type, cond_quote_table, &our_in, T_BARE_WORD);
	switch (type) {
	default:
	case T_BARE_WORD:
		tmp_p_rules = (fr_sbuff_parse_rules_t){		/* Stack allocated due to CL scope */
			.terminals = &bareword_terminals,
			.escapes = NULL
		};
		p_rules = &tmp_p_rules;
		break;

	case T_BACK_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
#ifdef HAVE_REGEX
	case T_SOLIDUS_QUOTED_STRING:
#endif
		p_rules = tmpl_parse_rules_quoted[type];
		break;
#ifndef HAVE_REGEX
	case T_SOLIDUS_QUOTED_STRING:
		fr_strerror_printf("Compiled without support for regexes");
		fr_sbuff_set(&our_in, &m);
		fr_sbuff_advance(&our_in, 1);
		goto error;
#endif
	}

	slen = tmpl_afrom_substr(ctx, &vpt, &our_in, type, p_rules, rules);
	if (!vpt) {
		fr_sbuff_advance(&our_in, slen * -1);

	error:
		talloc_free(vpt);
		return -(fr_sbuff_used_total(&our_in));
	}

	if ((type != T_BARE_WORD) && !fr_sbuff_next_if_char(&our_in, fr_token_quote[type])) { /* Quoting */
		fr_strerror_printf("Unterminated string");
		fr_sbuff_set(&our_in, &m);
		fr_sbuff_advance(&our_in, 1);
		goto error;
	}

#ifdef HAVE_REGEX
	/*
	 *	Parse the regex flags
	 *
	 *	The quote parsing we performed for the RHS
	 *	earlier means out buffer should be sitting
	 *	at the start of the flags.
	 */
	if (type == T_SOLIDUS_QUOTED_STRING) {
		if (!tmpl_contains_regex(vpt)) {
			fr_strerror_printf("Expected regex");
			fr_sbuff_set(&our_in, &m);
			goto error;
		}

		slen = tmpl_regex_flags_substr(vpt, &our_in, &bareword_terminals);
		if (slen < 0) {
			fr_sbuff_advance(&our_in, slen * -1);
			goto error;
		}

		/*
		 *	We've now got the expressions and
		 *	the flags.  Try to compile the
		 *	regex.
		 */
		if (tmpl_is_regex_uncompiled(vpt)) {
			slen = tmpl_regex_compile(vpt, true);
			if (slen <= 0) {
				fr_sbuff_set(&our_in, &m);	/* Reset to start of expression */
				fr_sbuff_advance(&our_in, slen * -1);
				goto error;
			}
		}
	}
#endif

	/*
	 *	Sanity check for nested types
	 */
	if (tmpl_is_attr(vpt) && (tmpl_attr_unknown_add(vpt) < 0)) {
		fr_strerror_printf("Failed defining attribute %s", tmpl_da(vpt)->name);
		fr_sbuff_set(&our_in, &m);
		goto error;
	}

	if (tmpl_cast_set(vpt, cast) < 0) {
		fr_sbuff_set(&our_in, &m);	/* Reset to start of cast */
		goto error;
	}

	*out = vpt;

	fr_sbuff_marker(opd_start, in);
	fr_sbuff_set(opd_start, &m);

	return fr_sbuff_set(in, &our_in);
}

/** Tokenize a conditional check
 *
 *  @param[in] ctx	talloc ctx
 *  @param[in] cs	our configuration section
 *  @param[out] out	pointer to the returned condition structure
 *  @param[in] in	the start of the string to process.  Should be "(..."
 *  @param[in] brace	look for a closing brace (how many deep we are)
 *  @param[in] t_rules	for attribute parsing
 *  @return
 *	- Length of the string skipped.
 *	- < 0 (the offset to the offending error) on error.
 */
static ssize_t cond_tokenize(TALLOC_CTX *ctx, fr_cond_t **out,
			     CONF_SECTION *cs, fr_sbuff_t *in, int brace,
			     tmpl_rules_t const *t_rules)
{
	fr_sbuff_t		our_in = FR_SBUFF_NO_ADVANCE(in);
	ssize_t			slen;
	fr_cond_t		*c;

	tmpl_t			*lhs = NULL;
	fr_token_t		op;
	fr_cond_op_t		cond_op;

	fr_sbuff_marker_t	m_lhs, m_lhs_cast, m_op, m_rhs, m_rhs_cast;
	tmpl_rules_t		our_t_rules;

	/*
	 *	We allow unknown and undefined attributes here
	 */
	our_t_rules = *t_rules;
	our_t_rules.allow_unknown = true;
	our_t_rules.allow_unresolved = true;

	MEM(c = talloc_zero(ctx, fr_cond_t));

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);
	if (!fr_sbuff_extend(&our_in)) {
		fr_strerror_printf("Empty condition is invalid");
	error:
		talloc_free(c);
		return -(fr_sbuff_used_total(&our_in));
	}

	/*
	 *	!COND
	 */
	if (fr_sbuff_next_if_char(&our_in, '!')) {
		c->negate = true;
		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);

		/*
		 *  Just for stupidity
		 */
		if (fr_sbuff_is_char(&our_in, '!')) {
			fr_strerror_printf("Double negation is invalid");
			goto error;
		}
	}

	/*
	 *	(COND)
	 */
	if (fr_sbuff_next_if_char(&our_in, '(')) {

		/*
		 *	We've already eaten one layer of
		 *	brackets.  Go recurse to get more.
		 */
		c->type = COND_TYPE_CHILD;
		c->ci = cf_section_to_item(cs);

		slen = cond_tokenize(c, &c->data.child, cs, &our_in, brace + 1, &our_t_rules);
		if (slen <= 0) {
			fr_sbuff_advance(&our_in, slen * -1);
			goto error;
		}

		if (!c->data.child) {
			fr_strerror_printf("Empty condition is invalid");
			goto error;
		}

		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);
		goto closing_brace;
	}

	/*
	 *	We didn't see anything special.  The condition must be one of
	 *
	 *	FOO
	 *	FOO OP BAR
	 */

	/*
	 *	Grab the LHS
	 */
	fr_sbuff_marker(&m_lhs_cast, &our_in);
	slen = cond_tokenize_operand(c, &lhs, &m_lhs, &our_in, &our_t_rules);
	if (!lhs) {
		fr_sbuff_advance(&our_in, slen * -1);
		goto error;
	}
	if (tmpl_is_attr_unresolved(lhs)) c->pass2_fixup = PASS2_FIXUP_ATTR;

	/*
	 *	Hack...
	 */
	if (lhs->cast != FR_TYPE_INVALID) {
		c->cast = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CAST_BASE + lhs->cast);
	}

	/*
	 *	We may (or not) have an operator
	 */
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);

	/*
	 *	What's found directly after the LHS token determines
	 *	what type of expression this is.
	 */

	/*
	 *	Closing curly brace - end of sub-expression
	 */
	if (fr_sbuff_is_char(&our_in, ')')) {
		if (fr_sbuff_used_total(&our_in) == 0) {
			fr_strerror_printf("Empty string is invalid");
			goto error;
		}

		/*
		 *	don't skip the brace.  We'll look for it later.
		 */
		goto unary;

	/*
	 *	FOO - Existence check
	 */
	} else if (!fr_sbuff_extend(&our_in)) {
		if (brace) {
			fr_strerror_printf("Missing closing brace");
			goto error;
		}

		goto unary;
	}

	/*
	 *	FOO && ... - Logical operator (existence check)
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &cond_op, cond_logical_op_table, &FR_SBUFF_NO_ADVANCE(&our_in), COND_NONE);
	if ((cond_op == COND_AND) || (cond_op == COND_OR)) {
	unary:
		if (c->cast) {
			fr_strerror_printf("Cannot do cast for existence check");
			fr_sbuff_set(&our_in, &m_lhs_cast);
			goto error;
		}

		if (tmpl_contains_regex(lhs)) {
			fr_strerror_printf("Unexpected regular expression");
			fr_sbuff_set(&our_in, &m_lhs);
			goto error;
		}

		/*
		 *	Check to see if this is an rcode operand.
		 *      These are common enough and specific enough
		 *	to conditions that we handle them in the
		 *	condition code specifically.
		 *
		 *	Unary barewords can only be rcodes, so
		 *	anything that's not a rcode an rcode
		 *	is an error.
		 */
		if (tmpl_is_unresolved(lhs) && (lhs->quote == T_BARE_WORD)) {
			rlm_rcode_t rcode;

			rcode = fr_table_value_by_str(rcode_table, lhs->data.unescaped, RLM_MODULE_UNKNOWN);
			if (rcode == RLM_MODULE_UNKNOWN) {
				fr_strerror_printf("Expected a module return code");
				fr_sbuff_set(&our_in, &m_lhs);
				goto error;
			}
			TALLOC_FREE(lhs);

			c->type = COND_TYPE_RCODE;
			c->ci = cf_section_to_item(cs);
			c->data.rcode = rcode;

			goto closing_brace;
		}

		c->type = COND_TYPE_EXISTS;
		c->ci = cf_section_to_item(cs);
		c->data.vpt = lhs;

		goto closing_brace;
	}

	/*
	 *	We now have LHS OP RHS.  So the LHS can't be a group,
	 *	list, or nested thing.
	 */
	if (cond_forbid_groups(lhs, &our_in, &m_lhs) < 0) goto error;

	/*
	 *	Check for any other operator
	 */
	fr_sbuff_marker(&m_op, &our_in);
	fr_sbuff_out_by_longest_prefix(&slen, &op, cond_cmp_op_table, &our_in, 0);
	if (slen == 0) {
		fr_strerror_printf("Invalid operator");
		goto error;
	}
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);

	{
		map_t 	*map;
		tmpl_t	*rhs;

		/*
		 *	The next thing should now be a comparison operator.
		 */
		c->type = COND_TYPE_MAP;
		c->ci = cf_section_to_item(cs);

		switch (op) {
#ifdef HAVE_REGEX
		case T_OP_REG_NE:
		case T_OP_REG_EQ:
			break;
#endif

		case T_OP_CMP_FALSE:
		case T_OP_CMP_TRUE:
			if (lhs->quote != T_BARE_WORD) {
				fr_strerror_printf("Cannot use %s on a string",
						   fr_table_str_by_value(cond_cmp_op_table, op, "<INVALID>"));
				fr_sbuff_set(&our_in, &m_op);
				goto error;
			}
			break;
		default:
			break;
		}

		if (!fr_sbuff_extend(&our_in)) {
			fr_strerror_printf("Expected text after operator");
			goto error;
		}

		MEM(c->data.map = map = talloc(c, map_t));

		/*
		 *	Grab the RHS
		 */
		fr_sbuff_marker(&m_rhs_cast, &our_in);
		slen = cond_tokenize_operand(c, &rhs, &m_rhs, &our_in, &our_t_rules);
		if (!rhs) {
			fr_sbuff_advance(&our_in, slen * -1);
			goto error;
		}
		if (tmpl_is_attr_unresolved(rhs)) c->pass2_fixup = PASS2_FIXUP_ATTR;

		/*
		 *	Groups can't be on the RHS of a comparison, either
		 */
		if (cond_forbid_groups(rhs, &our_in, &m_rhs) < 0) goto error;

		*map = (map_t) {
			.ci = cf_section_to_item(cs),
			.lhs = lhs,
			.op = op,
			.rhs = rhs
		};

		if (rhs->cast != FR_TYPE_INVALID) {
			fr_strerror_printf("Unexpected cast");
			fr_sbuff_set(&our_in, &m_rhs_cast);
			goto error;
		}

		if (((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) &&
		    (!tmpl_contains_regex(lhs) && !tmpl_contains_regex(rhs))) {
			fr_strerror_printf("Expected regular expression");
			fr_sbuff_set(&our_in, &m_rhs);
			goto error;
		}

		if (((op != T_OP_REG_EQ) && (op != T_OP_REG_NE)) &&
		    (tmpl_contains_regex(lhs) || tmpl_contains_regex(rhs))) {
		     	fr_strerror_printf("Unexpected regular expression");	/* Fixme should point to correct operand */
			fr_sbuff_set(&our_in, &m_rhs);
			goto error;
		}

		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);

		/*
		 *	Check cast type.  We can have the RHS
		 *	a string if the LHS has a cast.  But
		 *	if the RHS is an attr, it MUST be the
		 *	same type as the LHS.
		 */
		if (c->cast) {
			slen = cond_check_cast(c, fr_sbuff_start(&our_in), m_lhs.p, m_rhs.p);
			if (slen <= 0) {
				fr_sbuff_set(&our_in, our_in.start + (slen * -1));
				goto error;
			}
		} else {
			slen = cond_check_attrs(c, &m_lhs, &m_rhs);
			if (slen <= 0) {
				fr_sbuff_set(&our_in, our_in.start + (slen * -1));
				goto error;
			}
		}
	} /* parse OP RHS */

closing_brace:
	/*
	 *	...COND)
	 */
	if (fr_sbuff_is_char(&our_in, ')')) {
		if (!brace) {
			fr_strerror_printf("Unexpected closing brace");
			goto error;
		}
		fr_sbuff_advance(&our_in, 1);
		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);
		goto done;
	}

	/*
	 *	End of string is allowed, unless we're still looking
	 *	for closing braces.
	 */
	if (!fr_sbuff_extend(&our_in)) {
		if (brace) {
			fr_strerror_printf("Missing closing brace");
			goto error;
		}
		goto done;
	}

	/*
	 *	We've parsed all of the condition, stop.
	 */
	if (brace == 0) {
		if (fr_sbuff_is_space(&our_in)) goto done;

		/*
		 *	Open a section, it's OK to be done.
		 */
		if (fr_sbuff_is_char(&our_in, '{')) goto done;
	}

	/*
	 *	Allow ((a == b) && (b == c))
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &cond_op, cond_logical_op_table,
				       &our_in, COND_NONE);
	if (slen == 0) {
		fr_strerror_printf("Unexpected text after condition");
		goto error;
	}

	/*
	 *	Recurse to parse the next condition.
	 */
	c->next_op = cond_op;

	/*
	 *	May still be looking for a closing brace.
	 */
	slen = cond_tokenize(c, &c->next, cs, &our_in, brace, &our_t_rules);
	if (slen <= 0) {
		fr_sbuff_advance(&our_in, slen * -1);
		goto error;
	}

done:
	if (cond_normalise(ctx, lhs ? lhs->quote : T_INVALID, &c) < 0) {
		talloc_free(c);
		return 0;
	}

	*out = c;

	return fr_sbuff_set(in, &our_in);
}

/** Tokenize a conditional check
 *
 * @param[in] cs	current CONF_SECTION and talloc ctx
 * @param[out] head	the parsed condition structure
 * @param[in] dict	dictionary to resolve attributes in.
 * @param[in] in	the start of the string to process.
 * @return
 *	- Length of the string skipped.
 *	- < 0 (the offset to the offending error) on error.
 */
ssize_t fr_cond_tokenize(CONF_SECTION *cs, fr_cond_t **head, fr_dict_t const *dict, fr_sbuff_t *in)
{
	char buffer[8192];
	ssize_t diff, slen;

	if (!cf_expand_variables(cf_filename(cs), cf_lineno(cs), cf_item_to_section(cf_parent(cs)),
				 buffer, sizeof(buffer),
				 fr_sbuff_current(in), fr_sbuff_remaining(in), NULL)) {
		fr_strerror_printf("Failed expanding configuration variable");
		return 0;
	}

	diff = fr_sbuff_remaining(in) - strlen(buffer); /* Hack so that we appear to consume more of the string */
	slen = cond_tokenize(cs, head, cs, &FR_SBUFF_IN(buffer, strlen(buffer)), 0,
			     &(tmpl_rules_t){
			     		.dict_def = dict,
			     		.allow_unresolved = true,
			     		.allow_unknown = true,
			     		.allow_foreign = (dict == NULL)	/* Allow foreign attributes if we have no dict */
			     });
	if (slen < 0) return slen;

	return slen + diff;
}

/*
 *	Walk in order.
 */
bool fr_cond_walk(fr_cond_t *c, bool (*callback)(fr_cond_t *cond, void *uctx), void *uctx)
{
	while (c) {
		/*
		 *	Process this one, exit on error.
		 */
		if (!callback(c, uctx)) return false;

		switch (c->type) {
		case COND_TYPE_INVALID:
			return false;

		case COND_TYPE_RCODE:
		case COND_TYPE_EXISTS:
		case COND_TYPE_MAP:
		case COND_TYPE_TRUE:
		case COND_TYPE_FALSE:
			break;

		case COND_TYPE_CHILD:
			/*
			 *	Walk over the child.
			 */
			if (!fr_cond_walk(c->data.child, callback, uctx)) {
				return false;
			}
		}

		/*
		 *	No sibling, stop.
		 */
		if (c->next_op == COND_NONE) break;

		/*
		 *	process the next sibling
		 */
		c = c->next;
	}

	return true;
}
