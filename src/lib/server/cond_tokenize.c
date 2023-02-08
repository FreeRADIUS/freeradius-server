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
	{ L("&&"),	COND_TYPE_AND		},
	{ L("||"),	COND_TYPE_OR		}
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
	fr_sbuff_t		our_out = FR_SBUFF(out);
	fr_cond_t const		*c = in;

	while (c) {
		if (c->negate) FR_SBUFF_IN_CHAR_RETURN(&our_out, '!');

		switch (c->type) {
		case COND_TYPE_TMPL:
			fr_assert(c->data.vpt != NULL);
			FR_SBUFF_RETURN(tmpl_print_quoted, &our_out, c->data.vpt, TMPL_ATTR_REF_PREFIX_YES);
			break;

		case COND_TYPE_RCODE:
			fr_assert(c->data.rcode != RLM_MODULE_NOT_SET);
			FR_SBUFF_IN_STRCPY_RETURN(&our_out, fr_table_str_by_value(rcode_table, c->data.rcode, ""));
			break;

		case COND_TYPE_MAP:
			FR_SBUFF_RETURN(map_print, &our_out, c->data.map);
			break;

		case COND_TYPE_CHILD:
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '(');
			FR_SBUFF_RETURN(cond_print, &our_out, c->data.child);
			FR_SBUFF_IN_CHAR_RETURN(&our_out, ')');
			break;

		case COND_TYPE_AND:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, " && ");
			break;

		case COND_TYPE_OR:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, " || ");
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

		c = c->next;
	}

	fr_sbuff_terminate(&our_out);
	FR_SBUFF_SET_RETURN(out, &our_out);
}


static int cond_cast_tmpl(tmpl_t *vpt, fr_type_t type, tmpl_t *other)
{
	fr_dict_attr_t const *da;

	fr_assert(type != FR_TYPE_NULL);
	fr_assert(type < FR_TYPE_TLV);

	if (tmpl_is_attr(vpt)) {
		(void) tmpl_cast_set(vpt, type);
		return 0;

	} else if (!tmpl_is_data(vpt) && !tmpl_is_unresolved(vpt)) {
		/*
		 *	Nothing to do.
		 */
		return 0;

	} else if (tmpl_value_type(vpt) == type) {
#if 0
		/*
		 *	The parser will parse "256" as a 16-bit
		 *	integer.  If that's being compared to an 8-bit
		 *	type, then fr_type_promote() will promote that
		 *	8-bit integer to 16-bits.
		 *
		 *	However... if the 8-bit data type comes from
		 *	an attribute, then we know at compile time
		 *	that the value won't fit.  So we should issue
		 *	a compile-time error.
		 *
		 *	As a result, we call the cast below, even if
		 *	the type of the value matches the type we're
		 *	going to cast.
		 */
		if (tmpl_is_attr(other)) {
			// double check it?
		}
#endif

//		(void) tmpl_cast_set(vpt, FR_TYPE_NULL);
		return 0;
	}

	/*
	 *	Allow enumerated values like "PPP" for
	 *	Framed-Protocol, which is an integer data type.
	 */
	if (tmpl_is_attr(other)) {
		da = tmpl_attr_tail_da(other);
	} else {
		da = NULL;
	}

	fr_strerror_clear();

	if (tmpl_cast_in_place(vpt, type, da) < 0) {
		return -1;
	}

	/*
	 *	The result has to be data, AND of the correct type.
	 *	Which means we no longer need the cast.
	 */
	fr_assert(tmpl_is_data(vpt));
	fr_assert_msg(fr_type_is_null(tmpl_rules_cast(vpt)) || (tmpl_rules_cast(vpt) == tmpl_value_type(vpt)),
		      "Cast mismatch, target was %s, but output was %s",
		      fr_type_to_str(tmpl_rules_cast(vpt)),
		      fr_type_to_str(tmpl_value_type(vpt)));
	(void) tmpl_cast_set(vpt, FR_TYPE_NULL);
	return 0;
}


/** Promote the types in a FOO OP BAR comparison.
 *
 */
int fr_cond_promote_types(fr_cond_t *c, fr_sbuff_t *in, fr_sbuff_marker_t *m_lhs, fr_sbuff_marker_t *m_rhs, bool simple_parse)
{
	fr_type_t lhs_type, rhs_type;
	fr_type_t cast_type;

#ifdef HAVE_REGEX
	/*
	 *	Regular expressions have their own casting rules.
	 */
	if (tmpl_contains_regex(c->data.map->rhs)) {
		fr_assert((c->data.map->op == T_OP_REG_EQ) || (c->data.map->op == T_OP_REG_NE));
		fr_assert(fr_type_is_null(tmpl_rules_cast(c->data.map->rhs)));

		/*
		 *	Can't use casts with regular expressions, on
		 *	LHS or RHS.  Instead, the regular expression
		 *	returns a true/false match.
		 *
		 *	It's OK to have a redundant cast to string on
		 *	the LHS.  We also allow a cast to octets, in
		 *	which case we do a binary regex comparison.
		 *
		 *	@todo - ensure that the regex interpreter is
		 *	binary-safe!
		 */
		cast_type = tmpl_rules_cast(c->data.map->lhs);
		if (cast_type != FR_TYPE_NULL) {
			if ((cast_type != FR_TYPE_STRING) &&
			    (cast_type != FR_TYPE_OCTETS)) {
				fr_strerror_const("Casts cannot be used with regular expressions");
				if (in) fr_sbuff_set(in, m_lhs);
				return -1;
			}
		} else {
			cast_type = FR_TYPE_STRING;
		}

		/*
		 *	Ensure that the data is cast appropriately.
		 */
		if (tmpl_is_unresolved(c->data.map->lhs) || tmpl_is_data(c->data.map->lhs)) {
			if (tmpl_cast_in_place(c->data.map->lhs, FR_TYPE_STRING, NULL) < 0) {
				if (in) fr_sbuff_set(in, m_lhs);
				return -1;
			}

			(void) tmpl_cast_set(c->data.map->lhs, FR_TYPE_NULL);
		}

		/*
		 *	Force a cast to 'string', so the conditional
		 *	evaluator has less work to do.
		 */
		(void) tmpl_cast_set(c->data.map->lhs, cast_type);
		return 0;
	}
#endif

	/*
	 *	Rewrite the map so that the attribute being evaluated
	 *	is on the LHS.  This exchange makes cond_eval() easier
	 *	to implement, as it doesn't have to check both sides
	 *	for attributes.
	 */
	if (tmpl_is_attr(c->data.map->rhs) &&
	    !tmpl_contains_attr(c->data.map->lhs)) { /* also unresolved attributes! */
		tmpl_t *tmp;
		fr_sbuff_marker_t *m_tmp;

		tmp = c->data.map->rhs;
		c->data.map->rhs = c->data.map->lhs;
		c->data.map->lhs = tmp;

		m_tmp = m_rhs;
		m_rhs = m_lhs;
		m_lhs = m_tmp;

		switch (c->data.map->op) {
		case T_OP_CMP_EQ:
		case T_OP_NE:
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
			fr_strerror_printf("%s: Internal sanity check failed", __FUNCTION__);
			return -1;
		}
	}

	/*
	 *	Figure out the type of the LHS.
	 */
	if (tmpl_rules_cast(c->data.map->lhs) != FR_TYPE_NULL) {
		lhs_type = tmpl_rules_cast(c->data.map->lhs);
		/*
		 *	Two explicit casts MUST be the same, otherwise
		 *	it's an error.
		 *
		 *	We only do type promotion when at least one
		 *	data type is implicitly specified.
		 */
		if (tmpl_rules_cast(c->data.map->rhs) != FR_TYPE_NULL) {
			if (tmpl_rules_cast(c->data.map->rhs) != lhs_type) {
				fr_strerror_printf("Incompatible casts '%s' and '%s'",
						   fr_type_to_str(tmpl_rules_cast(c->data.map->rhs)),
						   fr_type_to_str(lhs_type));
				if (in) fr_sbuff_set(in, fr_sbuff_start(in));
				return -1;
			}

			return 0;
		}

	} else if (tmpl_is_data(c->data.map->lhs)) {
		/*
		 *	Choose the data type which was parsed.
		 */
		lhs_type = tmpl_value_type(c->data.map->lhs);

	} else if (tmpl_is_attr(c->data.map->lhs)) {
		/*
		 *	Choose the attribute type which was parsed.
		 */
		lhs_type = tmpl_attr_tail_da(c->data.map->lhs)->type;

	} else if (tmpl_is_exec(c->data.map->lhs)) {
		lhs_type = FR_TYPE_STRING;

	} else if (tmpl_is_xlat(c->data.map->lhs) && (c->data.map->lhs->quote != T_BARE_WORD)) {
		/*
		 *	bare xlats return a list of typed value-boxes.
		 *	We don't know those types until run-time.
		 */
		lhs_type = FR_TYPE_STRING;

	} else {
#ifdef HAVE_REGEX
		fr_assert(!tmpl_is_regex(c->data.map->lhs));
#endif

		lhs_type = FR_TYPE_NULL;
	}

	/*
	 *	Figure out the type of the RHS.
	 */
	if (tmpl_rules_cast(c->data.map->rhs) != FR_TYPE_NULL) {
		rhs_type = tmpl_rules_cast(c->data.map->rhs);

	} else if (tmpl_is_data(c->data.map->rhs)) {
		rhs_type = tmpl_value_type(c->data.map->rhs);

		/*
		 *	If we have ATTR op DATA, then ensure that the
		 *	data type we choose is the one from the
		 *	attribute, because that's what limits the
		 *	range of the RHS data.
		 */
		if (fr_type_is_numeric(lhs_type) && tmpl_is_attr(c->data.map->lhs)) rhs_type = lhs_type;

	} else if (tmpl_is_attr(c->data.map->rhs)) {
		rhs_type = tmpl_attr_tail_da(c->data.map->rhs)->type;

	} else if (tmpl_is_exec(c->data.map->rhs)) {
		rhs_type = FR_TYPE_STRING;

	} else if (tmpl_is_xlat(c->data.map->rhs) && (c->data.map->rhs->quote != T_BARE_WORD)) {
		/*
		 *	bare xlats return a list of typed value-boxes.
		 *	We don't know those types until run-time.
		 */
		rhs_type = FR_TYPE_STRING;

	} else {
		rhs_type = FR_TYPE_NULL;

		/*
		 *	Both sides are have unresolved issues.  Leave
		 *	them alone...
		 */
		if (fr_type_is_null(lhs_type)) {
			/*
			 *	If we still have unresolved data, then
			 *	ensure that they are converted to
			 *	strings.
			 */
			if ((c->pass2_fixup == PASS2_FIXUP_NONE) &&
			    tmpl_is_unresolved(c->data.map->lhs) && tmpl_is_unresolved(c->data.map->rhs)) {
				if (tmpl_cast_in_place(c->data.map->lhs, FR_TYPE_STRING, NULL) < 0) return -1;
				if (tmpl_cast_in_place(c->data.map->rhs, FR_TYPE_STRING, NULL) < 0) return -1;
			}

			return 0;
		}
	}

	/*
	 *	Both types are identical.  Ensure that LHS / RHS are
	 *	cast as appropriate.
	 */
	if (lhs_type == rhs_type) {
		cast_type = lhs_type;
		goto set_types;
	}

	/*
	 *	Only one side has a known data type.  Cast the other
	 *	side to it.
	 *
	 *	Note that we don't check the return code for
	 *	tmpl_cast_set().  If one side is an unresolved
	 *	attribute, then the cast will fail.  Which is fine,
	 *	because we will just check it again after the pass2
	 *	fixups.
	 */
	if (!fr_type_is_null(lhs_type) && fr_type_is_null(rhs_type)) {
		cast_type = lhs_type;
		goto set_types;
	}

	if (!fr_type_is_null(rhs_type) && fr_type_is_null(lhs_type)) {
		cast_type = rhs_type;
		goto set_types;
	}

	cast_type = fr_type_promote(lhs_type, rhs_type);
	if (!fr_cond_assert_msg(cast_type != FR_TYPE_NULL, "%s", fr_strerror())) return -1;

set_types:
	/*
	 *	If the caller is doing comparisons with prefixes, then
	 *	update the cast to an IP prefix.  But only if they're
	 *	not comparing IP addresses by value.  <sigh> We should
	 *	really have separate "set membership" operators.
	 */
	if (((cast_type == FR_TYPE_IPV4_ADDR) || (cast_type == FR_TYPE_IPV6_ADDR)) &&
	    (lhs_type != rhs_type)) {
		switch (c->data.map->op) {
		default:
			break;

		case T_OP_LT:
		case T_OP_LE:
		case T_OP_GT:
		case T_OP_GE:
			if (cast_type == FR_TYPE_IPV4_ADDR) {
				cast_type = FR_TYPE_IPV4_PREFIX;
			} else {
				cast_type = FR_TYPE_IPV6_PREFIX;
			}
			break;
		}
	}

	/*
	 *	Skip casting.
	 */
	if (simple_parse) return 0;

	/*
	 *	Cast both sides to the promoted type.
	 */
	if (cond_cast_tmpl(c->data.map->lhs, cast_type, c->data.map->rhs) < 0) {
		if (in) fr_sbuff_set(in, m_lhs);
		return -1;
	}

	if (cond_cast_tmpl(c->data.map->rhs, cast_type, c->data.map->lhs) < 0) {
		if (in) fr_sbuff_set(in, m_rhs);
		return -1;
	}

	return 0;
}

/** Normalise one level of a condition
 *
 *	This function is called after every individual condition is
 *	tokenized.  As a result, this function does not need to
 *	recurse.  Instead, it just looks at itself, and it's immediate
 *	children for optimizations
 */
static int cond_normalise(TALLOC_CTX *ctx, fr_token_t lhs_type, fr_cond_t **c_out)
{
	fr_cond_t *c = *c_out;
	fr_cond_t *next;

	/*
	 *	Normalize the condition before returning.
	 *
	 *	We convert maps to literals.  Then literals to
	 *	true/false statements.  Then true/false ||/&& followed
	 *	by other conditions to just conditions.
	 *
	 *	Order is important.  The more complex cases are
	 *	converted to simpler ones, from the most complex cases
	 *	to the simplest ones.
	 */

	/*
	 *	Do some limited normalizations here.
	 */
	if (c->type == COND_TYPE_CHILD) {
		fr_cond_t *child = c->data.child;

		/*
		 *	((FOO)) --> (FOO)
		 *	!(!(FOO)) --> FOO
		 */
		if (!c->next && !child->next) {
			if ((child->type == COND_TYPE_CHILD) ||
			    (child->type == COND_TYPE_TRUE) ||
			    (child->type == COND_TYPE_FALSE)) {
				(void) talloc_steal(ctx, child);
				child->parent = c->parent;
				child->negate = (c->negate != child->negate);

				talloc_free(c);
				c = child;
			}
		}

		/*
		 *	No further optimizations are possible, so we
		 *	just check for and/or short-circuit.
		 */
		 goto check_short_circuit;
	}

	/*
	 *	Normalise the equality checks.
	 *
	 *	This doesn't make a lot of difference, but it does
	 *	help fix !* and =*, which are horrible hacks.
	 */
	if (c->type == COND_TYPE_MAP) switch (c->data.map->op) {
		/*
		 *	!FOO !~ BAR --> FOO =~ BAR
		 *
		 *	FOO !~ BAR --> !FOO =~ BAR
		 */
		case T_OP_REG_NE:
			if (c->negate) {
				c->negate = false;
				c->data.map->op = T_OP_REG_EQ;
			} else {
				c->negate = true;
				c->data.map->op = T_OP_REG_EQ;
			}
			break;

		/*
		 *	!FOO != BAR --> FOO == BAR
		 *
		 *	This next one catches "LDAP-Group != foo",
		 *	which doesn't work as-is, but this hack fixes
		 *	it.
		 *
		 *	FOO != BAR --> !FOO == BAR
		 */
		case T_OP_NE:
			if (c->negate) {
				c->negate = false;
				c->data.map->op = T_OP_CMP_EQ;
			} else {
				c->negate = true;
				c->data.map->op = T_OP_CMP_EQ;
			}
			break;

		/*
		 *	Don't do any other re-writing.
		 */
		default:
			break;
	}

	/*
	 *	Do compile-time evaluation of literals.  That way it
	 *	does not need to be done at run-time.
	 */
	if (c->type == COND_TYPE_MAP) {
		/*
		 *	Both are data (IP address, integer, etc.)
		 *
		 *	We can do the evaluation here, so that it
		 *	doesn't need to be done at run time
		 */
		if (tmpl_is_data(c->data.map->lhs) &&
		    tmpl_is_data(c->data.map->rhs)) {
			bool rcode;

			fr_assert(c->next == NULL);

			rcode = cond_eval(NULL, RLM_MODULE_NOOP, c);
			TALLOC_FREE(c->data.map);

			if (rcode) {
				c->type = COND_TYPE_TRUE;
			} else {
				c->type = COND_TYPE_FALSE;
			}

			c->negate = false;
			goto check_true; /* it's no longer a map */
		}

		c->async_required = tmpl_async_required(c->data.map->lhs) || tmpl_async_required(c->data.map->rhs);
	}

	/*
	 *	Existence checks.  We short-circuit static strings,
	 *	too.
	 *
	 *	FIXME: the data types should be in the template, too.
	 *	So that we know where a literal came from.
	 *
	 *	"foo" is NOT the same as 'foo' or a bare foo.
	 */
	if (c->type == COND_TYPE_TMPL) {
		switch (c->data.vpt->type) {
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_XLAT_UNRESOLVED:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_ATTR_UNRESOLVED:
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
		check_bool:
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
					if (!isdigit((uint8_t) *q)) {
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
					fr_strerror_const("Expected a module return code");
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
			if (lhs_type != T_BARE_WORD) goto check_bool;

		{
			fr_value_box_t res;

			if (fr_value_box_cast(NULL, &res, FR_TYPE_BOOL, NULL, tmpl_value(c->data.vpt)) < 0) return -1;
			c->type = res.vb_bool ? COND_TYPE_TRUE : COND_TYPE_FALSE;
			TALLOC_FREE(c->data.vpt);
		}
			break;

		default:
			fr_assert_fail("%s: Internal sanity check failed", __FUNCTION__);
			return -1;
		}

		if (c->type == COND_TYPE_TMPL) {
			c->async_required = tmpl_async_required(c->data.vpt);
		}
	}

	/*
	 *	!TRUE -> FALSE
	 */
check_true:
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
	 *	We now do short-circuit evaluation of && and ||.
	 */

check_short_circuit:
	if (!c->next) goto done;

	/*
	 *	true && FOO --> FOO
	 */
	if ((c->type == COND_TYPE_TRUE) &&
	    (c->next->type == COND_TYPE_AND)) {
		goto hoist_grandchild;
	}

	/*
	 *	false && FOO --> false
	 */
	if ((c->type == COND_TYPE_FALSE) &&
	    (c->next->type == COND_TYPE_AND)) {
		goto drop_child;
	}

	/*
	 *	false || FOO --> FOO
	 */
	if ((c->type == COND_TYPE_FALSE) &&
	     (c->next->type == COND_TYPE_OR)) {
	hoist_grandchild:
		next = talloc_steal(ctx, c->next->next);
		talloc_free(c->next);
		talloc_free(c);
		c = next;
		goto done;	/* we've already called normalise for FOO */
	}

	/*
	 *	true || FOO --> true
	 */
	if ((c->type == COND_TYPE_TRUE) &&
	     (c->next->type == COND_TYPE_OR)) {

	drop_child:
		TALLOC_FREE(c->next);
		goto done;	/* we don't need to normalise a boolean */
	}

	/*
	 *	the short-circuit operators don't call normalise, so
	 *	we have to check for that, too.
	 */
	next = c->next;
	if (!next->next) goto done;

	/*
	 *	FOO && true --> FOO
	 */
	if ((next->type == COND_TYPE_AND) &&
	    (next->next->type == COND_TYPE_TRUE)) {
		goto drop_next_child;
	}

	/*
	 *	FOO && false --> false
	 */
	if ((next->type == COND_TYPE_AND) &&
	    (next->next->type == COND_TYPE_FALSE)) {
		goto hoist_next_grandchild;
	}

	/*
	 *	FOO || false --> FOO
	 */
	if ((next->type == COND_TYPE_OR) &&
	     (next->next->type == COND_TYPE_FALSE)) {
	drop_next_child:
		TALLOC_FREE(c->next);
		goto done;
	}

	/*
	 *	FOO || true --> true
	 */
	if ((next->type == COND_TYPE_OR) &&
	     (next->next->type == COND_TYPE_TRUE)) {
	hoist_next_grandchild:
		next = talloc_steal(ctx, next->next);
		talloc_free(c->next);
		c = next;
	}

done:
	*c_out = c;
	return 0;
}

static CC_HINT(nonnull) int cond_forbid_groups(tmpl_t *vpt, fr_sbuff_t *in, fr_sbuff_marker_t *m_lhs)
{
	if (!tmpl_is_attr(vpt) || tmpl_attr_tail_is_unresolved(vpt)) return 0;

	if (tmpl_is_list(vpt)) {
		fr_strerror_const("Cannot use list references in condition");
		fr_sbuff_set(in, m_lhs);
		return -1;
	}

	switch (tmpl_attr_tail_da(vpt)->type) {
	case FR_TYPE_LEAF:
		break;

	default:
		fr_strerror_const("Nesting types such as groups or TLVs cannot "
				  "be used in condition comparisons");
		fr_sbuff_set(in, m_lhs);
		return -1;
	}

	return 0;
}

static fr_slen_t cond_tokenize_operand(fr_cond_t *c, tmpl_t **out,
				       fr_sbuff_marker_t *opd_start, fr_sbuff_t *in,
				       tmpl_rules_t const *t_rules, bool simple_parse)
{
	fr_sbuff_term_t const 		bareword_terminals =
					FR_SBUFF_TERMS(
						L(""),			/* Hack for EOF */
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

	fr_sbuff_t			our_in = FR_SBUFF(in);
	fr_sbuff_marker_t		m;
	tmpl_t				*vpt;
	fr_token_t			type;
	fr_type_t			cast = FR_TYPE_NULL;
	fr_sbuff_parse_rules_t		tmp_p_rules;
	fr_sbuff_parse_rules_t const	*p_rules;
	fr_slen_t			slen;
	tmpl_rules_t			our_t_rules = *t_rules;

	*out = NULL;

	/*
	 *	Parse (optional) cast
	 */
	if (tmpl_cast_from_substr(&our_t_rules, &our_in) < 0) FR_SBUFF_ERROR_RETURN(&our_in);

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
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
		p_rules = value_parse_rules_quoted[type];
		break;
#ifndef HAVE_REGEX
	case T_SOLIDUS_QUOTED_STRING:
		fr_strerror_const("Compiled without support for regexes");
		fr_sbuff_set(&our_in, &m);
		fr_sbuff_advance(&our_in, 1);
		goto error;
#endif
	}

	slen = tmpl_afrom_substr(c, &vpt, &our_in, type, p_rules, &our_t_rules);
	if (slen < 0) {
	error:
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if ((type != T_BARE_WORD) && !fr_sbuff_next_if_char(&our_in, fr_token_quote[type])) { /* Quoting */
		fr_strerror_const("Unterminated string");
		fr_sbuff_set(&our_in, &m);
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
		if (cast != FR_TYPE_NULL) {
			fr_strerror_const("Casts cannot be used with regular expressions");
			fr_sbuff_set(&our_in, &m);
			goto error;
		}

		if (!tmpl_contains_regex(vpt)) {
			fr_strerror_const("Expected regex");
			fr_sbuff_set(&our_in, &m);
			goto error;
		}

		if (tmpl_regex_flags_substr(vpt, &our_in, &bareword_terminals) < 0) goto error;

		/*
		 *	We've now got the expressions and
		 *	the flags.  Try to compile the
		 *	regex.
		 */
		if (!simple_parse && tmpl_is_regex_uncompiled(vpt)) {
			if (tmpl_regex_compile(vpt, true) < 0) {
				fr_sbuff_set(&our_in, &m);	/* Reset to start of expression */
				goto error;
			}
		}
	}
#endif

	/*
	 *	Sanity check for nested types
	 */
	if (tmpl_is_attr(vpt) && (tmpl_attr_unknown_add(vpt) < 0)) {
		fr_strerror_printf("Failed defining attribute %s", tmpl_attr_tail_da(vpt)->name);
		fr_sbuff_set(&our_in, &m);
		goto error;
	}

	if (tmpl_is_unresolved(vpt) &&
	    ((type == T_BACK_QUOTED_STRING) || (type == T_SINGLE_QUOTED_STRING) || (type == T_DOUBLE_QUOTED_STRING))) {
		if (tmpl_cast_in_place(vpt, FR_TYPE_STRING, NULL) < 0) {
			fr_sbuff_set(&our_in, &m);
			goto error;
		}
	}

	if (tmpl_is_attr_unresolved(vpt)) c->pass2_fixup = PASS2_FIXUP_ATTR;

	*out = vpt;

	fr_sbuff_marker(opd_start, in);
	fr_sbuff_set(opd_start, &m);

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Tokenize a conditional check
 *
 *  @param[in] ctx	talloc ctx
 *  @param[out] out	pointer to the returned condition structure
 *  @param[in] cs	our configuration section
 *  @param[in] in	the start of the string to process.  Should be "(..."
 *  @param[in] brace	look for a closing brace (how many deep we are)
 *  @param[in] t_rules	for attribute parsing
 *  @param[in] simple_parse	temporary hack
 *  @return
 *	- Length of the string skipped.
 *	- < 0 (the offset to the offending error) on error.
 */
static fr_slen_t cond_tokenize(TALLOC_CTX *ctx, fr_cond_t **out,
			       CONF_SECTION *cs, fr_sbuff_t *in, int brace,
			       tmpl_rules_t const *t_rules, bool simple_parse)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	ssize_t			slen;
	fr_cond_t		*c;

	tmpl_t			*lhs = NULL;
	fr_token_t		op;
	fr_cond_type_t		cond_op;

	fr_sbuff_marker_t	m_lhs, m_lhs_cast, m_op, m_rhs, m_rhs_cast;

	MEM(c = talloc_zero(ctx, fr_cond_t));

	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
	if (!fr_sbuff_extend(&our_in)) {
		fr_strerror_const("Empty condition is invalid");
	error:
		talloc_free(c);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	!COND
	 */
	if (fr_sbuff_next_if_char(&our_in, '!')) {
		c->negate = true;
		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

		/*
		 *  Just for stupidity
		 */
		if (fr_sbuff_is_char(&our_in, '!')) {
			fr_strerror_const("Double negation is invalid");
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

		/*
		 *	Children are allocated from the parent.
		 */
		if (cond_tokenize(c, &c->data.child, cs, &our_in, brace + 1, t_rules, simple_parse) < 0) goto error;

		if (!c->data.child) {
			fr_strerror_const("Empty condition is invalid");
			goto error;
		}

		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
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

	/*
	 *	Check to see if this is an rcode operand.  These are
	 *      common enough and specific enough to conditions that
	 *      we handle them in the condition code specifically.
	 *
	 *	Unary barewords can only be rcodes, so anything that's
	 *	not a rcode an rcode is an error.
	 */
	{
		rlm_rcode_t rcode;
		size_t match_len;

		fr_sbuff_out_by_longest_prefix(&match_len, &rcode, rcode_table, &our_in, RLM_MODULE_NOT_SET);
		if (rcode != RLM_MODULE_NOT_SET) {
			c->type = COND_TYPE_RCODE;
			c->data.rcode = rcode;

			fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
			goto closing_brace;
		}
	}

	if (cond_tokenize_operand(c, &lhs, &m_lhs, &our_in, t_rules, simple_parse) < 0) goto error;

#ifdef HAVE_REGEX
	/*
	 *	LHS can't have regex.  We can't use regex as a unary
	 *	existence check.
	 */
	if (tmpl_contains_regex(lhs)) {
		fr_strerror_const("Unexpected regular expression");
		fr_sbuff_set(&our_in, &m_lhs);
		goto error;
	}
#endif

	/*
	 *	We may (or not) have an operator
	 */
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	/*
	 *	What's found directly after the LHS token determines
	 *	what type of expression this is.
	 */

	/*
	 *	Closing curly brace - end of sub-expression
	 */
	if (fr_sbuff_is_char(&our_in, ')')) {
		if (fr_sbuff_used_total(&our_in) == 0) {
			fr_strerror_const("Empty string is invalid");
			goto error;
		}

		/*
		 *	don't skip the brace.  We'll look for it later.
		 */
		goto unary;

	} else if (fr_sbuff_is_char(&our_in, '&') || fr_sbuff_is_char(&our_in, '|')) {
		/*
		 *	FOO && ...
		 *	FOO || ...
		 *
		 *	end of sub-expression.
		 */
		goto unary;

	} else if (!fr_sbuff_extend(&our_in)) {
		/*
		 *	FOO - Existence check at EOF
		 */
		if (brace) {
			fr_strerror_const("Missing closing brace");
			goto error;
		}

	unary:
		if (tmpl_rules_cast(lhs) != FR_TYPE_NULL) {
			fr_strerror_const("Cannot do cast for existence check");
			fr_sbuff_set(&our_in, &m_lhs_cast);
			goto error;
		}

		c->type = COND_TYPE_TMPL;
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
		fr_strerror_const("Invalid operator");
		goto error;
	}
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	{
		map_t 	*map;
		tmpl_t	*rhs;

		/*
		 *	The next thing should now be a comparison operator.
		 */
		c->type = COND_TYPE_MAP;

		switch (op) {
		case T_OP_CMP_FALSE:
		case T_OP_CMP_TRUE:
			fr_strerror_printf("Invalid operator %s",
					   fr_table_str_by_value(cond_cmp_op_table, op, "<INVALID>"));
			fr_sbuff_set(&our_in, &m_op);
			goto error;

		default:
			break;
		}

		if (!fr_sbuff_extend(&our_in)) {
			fr_strerror_const("Expected text after operator");
			goto error;
		}

		MEM(c->data.map = map = talloc_zero(c, map_t));

		/*
		 *	Grab the RHS
		 */
		fr_sbuff_marker(&m_rhs_cast, &our_in);
		if (cond_tokenize_operand(c, &rhs, &m_rhs, &our_in, t_rules, simple_parse) < 0) goto error;

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

#ifdef HAVE_REGEX
		/*
		 *	LHS can't have regex.  We can't use regex as a unary
		 *	existence check.
		 */
		if (tmpl_contains_regex(rhs) &&
		    !((op == T_OP_REG_EQ) || (op == T_OP_REG_NE))) {
			fr_strerror_const("Unexpected regular expression");
			fr_sbuff_set(&our_in, &m_rhs);
			goto error;
		}

		/*
		 *	=~ and !~ MUST have regular expression on the
		 *	RHS.
		 */
		if ((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) {
			if (!tmpl_contains_regex(rhs)) {
				fr_strerror_const("Expected regular expression");
				fr_sbuff_set(&our_in, &m_rhs);
				goto error;
			}
		}
#endif

		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

		/*
		 *	Promote the data types to the appropriate
		 *	values.
		 */
		if (fr_cond_promote_types(c, &our_in, &m_lhs, &m_rhs, simple_parse) < 0) {
			goto error;
		}
	} /* parse OP RHS */

closing_brace:

	/*
	 *	Recurse to parse the next condition.
	 */

	/*
	 *	...COND)
	 */
	if (fr_sbuff_is_char(&our_in, ')')) {
		if (!brace) {
			fr_strerror_const("Unexpected closing brace");
			goto error;
		}
		fr_sbuff_advance(&our_in, 1);
		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
		goto done;
	}

	/*
	 *	End of string is allowed, unless we're still looking
	 *	for closing braces.
	 */
	if (!fr_sbuff_extend(&our_in)) {
		if (brace) {
			fr_strerror_const("Missing closing brace");
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

	fr_sbuff_out_by_longest_prefix(&slen, &cond_op, cond_logical_op_table,
				       &our_in, COND_TYPE_INVALID);
	if (slen == 0) {
		/*
		 *	Peek ahead to give slightly better error messages.
		 */
		if (fr_sbuff_is_char(&our_in, '=')) {
			fr_strerror_const("Invalid location for operator");

		} else if (fr_sbuff_is_char(&our_in, '!')) {
			fr_strerror_const("Invalid location for negation");

		} else {
			fr_strerror_const("Expected closing brace or logical operator");
		}
		goto error;
	}

	/*
	 *	We have a short-circuit condition, create it.
	 */
	if (cond_op != COND_TYPE_INVALID) {
		fr_cond_t *child;

		/*
		 *	This node is talloc parented by the previous
		 *	condition.
		 */
		MEM(child = talloc_zero(c, fr_cond_t));
		child->type = cond_op;

		/*
		 *	siblings are allocated from their older
		 *	siblings.
		 */
		if (cond_tokenize(child, &child->next, cs, &our_in, brace, t_rules, simple_parse) < 0) goto error;
		c->next = child;
		goto done;
	}

	/*
	 *	May still be looking for a closing brace.
	 *
	 *	siblings are allocated from their older
	 *	siblings.
	 */
	if (cond_tokenize(c, &c->next, cs, &our_in, brace, t_rules, simple_parse) < 0) goto error;

done:
	if (cond_normalise(ctx, lhs ? lhs->quote : T_INVALID, &c) < 0) {
		talloc_free(c);
		fr_sbuff_set_to_start(&our_in);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	*out = c;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/*
 *	Normalisation will restructure the conditional tree, including
 *	removing and/or rearranging the parents.  So we reparent
 *	everything after the full normalization has run.
 */
static void cond_reparent(fr_cond_t *c, fr_cond_t *parent)
{
	while (c) {
		c->parent = parent;

		if (c->type == COND_TYPE_CHILD) cond_reparent(c->data.child, c);

		if (parent) parent->async_required |= c->async_required;

		c = c->next;
	}
}

/** Tokenize a conditional check
 *
 * @param[in] cs	current CONF_SECTION and talloc ctx
 * @param[out] head	the parsed condition structure
 * @param[in] rules	for parsing operands.
 * @param[in] in	the start of the string to process.
 * @param[in] simple_parse	temporary hack
 * @return
 *	- Length of the string skipped.
 *	- < 0 (the offset to the offending error) on error.
 */
ssize_t fr_cond_tokenize(CONF_SECTION *cs, fr_cond_t **head, tmpl_rules_t const *rules, fr_sbuff_t *in, bool simple_parse)
{
	ssize_t slen;
	fr_sbuff_t our_in = FR_SBUFF(in);

	*head = NULL;

	slen = cond_tokenize(cs, head, cs, &our_in, 0, rules, simple_parse);
	if (slen <= 0) return slen;

	/*
	 *	Now that everything has been normalized, reparent the children.
	 */
	if (*head) {
		fr_cond_t *c = *head;

		/*
		 *	(FOO) -> FOO
		 *	!(!(FOO)) -> FOO
		 */
		if ((c->type == COND_TYPE_CHILD) && !c->next) {
			if (!c->negate || !c->data.child->next) {
				fr_cond_t *child = c->data.child;
				(void) talloc_steal(cs, child);
				child->parent = c->parent;
				child->negate = (c->negate != child->negate);

				talloc_free(c);
				*head = child;
			}
		}

		cond_reparent(*head, NULL);
	}

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Initialise a cond iterator
 *
 * Will return the first leaf condition node.
 *
 * @param[out] iter	to initialise.
 * @param[in] head	the root of the condition structure.
 * @return The first leaf condition node.
 */
fr_cond_t *fr_cond_iter_init(fr_cond_iter_t *iter, fr_cond_t *head)
{
	fr_cond_t *c;

	for (c = head; c->type == COND_TYPE_CHILD; c = c->data.child);	/* Deepest condition */

	return iter->cond = c;
}

/** Get the next leaf condition node
 *
 * @param[in] iter	to iterate over.
 * @return The next leaf condition node.
 */
fr_cond_t *fr_cond_iter_next(fr_cond_iter_t *iter)
{
	fr_cond_t *c;

	/*
	 *	Walk up the tree, maybe...
	 */
	for (c = iter->cond; c; c = c->parent) {
		if (!c->next) continue; /* Done with this level */
		for (c = c->next; c->type == COND_TYPE_CHILD; c = c->data.child);	/* down we go... */
		break;
	}

	return iter->cond = c;
}

/** Update the condition with "is async required".
 *
 *  This is done only by the compiler, in pass2, after is has resolved
 *  all of the various TMPLs.  Note that we MUST walk over the entire
 *  condition, as tmpl_async_required() returns "true" for unresolved
 *  TMPLs.  Which means that if the TMPL is resolved to a synchronous
 *  one, then the flag will be set.  So we have to clear the flag, and
 *  then set it again ourselves.
 */
void fr_cond_async_update(fr_cond_t *c)
{
	while (c) {
		c->async_required = false;

		switch (c->type) {
		case COND_TYPE_INVALID:
		case COND_TYPE_RCODE:
		case COND_TYPE_AND:
		case COND_TYPE_OR:
		case COND_TYPE_TRUE:
		case COND_TYPE_FALSE:
			break;

		case COND_TYPE_TMPL:
			c->async_required = tmpl_async_required(c->data.vpt);
			break;

		case COND_TYPE_MAP:
			c->async_required = tmpl_async_required(c->data.map->lhs) || tmpl_async_required(c->data.map->rhs);
			break;

		case COND_TYPE_CHILD:
			c = c->data.child;
			continue;

		}

		/*
		 *	Mark up the parent, too.  If any of the
		 *	children are async, then the parent is async,
		 *	too.
		 */
		if (c->parent) c->parent->async_required |= c->async_required;

		/*
		 *	Go up if there's no sibling, or to the next
		 *	sibling if it exists.
		 */
		while (!c->next) {
			c = c->parent;
			if (!c) return;
		}
		c = c->next;
	}
}
