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
 * @file src/lib/server/cond_eval.c
 * @brief Evaluate complex conditions
 *
 * @copyright 2007 The FreeRADIUS server project
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/print.h>

#include <ctype.h>

#ifdef WITH_EVAL_DEBUG
#  define EVAL_DEBUG(fmt, ...) printf("EVAL: ");fr_fprintf(stdout, fmt, ## __VA_ARGS__);printf("\n");fflush(stdout)
#else
#  define EVAL_DEBUG(...)
#endif

/** Map keywords to #pair_list_t values
 */
static fr_table_num_sorted_t const cond_type_table[] = {
	{ L("child"),		COND_TYPE_CHILD		},
	{ L("tmpl"),		COND_TYPE_TMPL		},
	{ L("false"),		COND_TYPE_FALSE		},
	{ L("invalid"),		COND_TYPE_INVALID	},
	{ L("map"),		COND_TYPE_MAP		},
	{ L("true"),		COND_TYPE_TRUE		},
};
static size_t cond_type_table_len = NUM_ELEMENTS(cond_type_table);

static fr_table_num_sorted_t const cond_pass2_table[] = {
	{ L("none"),		PASS2_FIXUP_NONE	},
	{ L("attr"),		PASS2_FIXUP_ATTR	},
	{ L("type"),		PASS2_FIXUP_TYPE	},
	{ L("paircompre"),	PASS2_PAIRCOMPARE	},
};
static size_t cond_pass2_table_len = NUM_ELEMENTS(cond_pass2_table);


/** Debug function to dump a cond structure
 *
 */
void cond_debug(fr_cond_t const *cond)
{
	fr_cond_t const *c;

	for (c = cond; c; c =c->next) {
		INFO("cond %s (%p)", fr_table_str_by_value(cond_type_table, c->type, "<INVALID>"), cond);
		INFO("\tnegate : %s", c->negate ? "true" : "false");
		INFO("\tfixup  : %s", fr_table_str_by_value(cond_pass2_table, c->pass2_fixup, "<INVALID>"));

		switch (c->type) {
		case COND_TYPE_MAP:
			INFO("lhs (");
			tmpl_debug(c->data.map->lhs);
			INFO(")");
			INFO("rhs (");
			tmpl_debug(c->data.map->rhs);
			INFO(")");
			break;

		case COND_TYPE_RCODE:
			INFO("\trcode  : %s", fr_table_str_by_value(rcode_table, c->data.rcode, ""));
			break;

		case COND_TYPE_TMPL:
			tmpl_debug(c->data.vpt);
			break;

		case COND_TYPE_CHILD:
			INFO("child (");
			cond_debug(c->data.child);
			INFO(")");
			break;

		case COND_TYPE_AND:
			INFO("&& ");
			break;

		case COND_TYPE_OR:
			INFO("|| ");
			break;

		default:
			break;
		}
	}
}

/** Evaluate a template
 *
 * Converts a tmpl_t to a boolean value.
 *
 * @param[in] request the request_t
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] vpt the template to evaluate
 * @return
 *	- 0 for "no match" or failure
 *	- 1 for "match".
 */
int cond_eval_tmpl(request_t *request, UNUSED int depth, tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		if (tmpl_find_vp(NULL, request, vpt) == 0) {
			return true;
		}
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
	{
		char	*p;
		ssize_t	slen;

		slen = tmpl_aexpand(request, &p, request, vpt, NULL, NULL);
		if (slen < 0) {
			EVAL_DEBUG("FAIL %d", __LINE__);
			return false;
		}
		talloc_free(p);

		if (slen == 0) return false;
	}
		return true;

	/*
	 *	Can't have a bare ... (/foo/) ...
	 */
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
		fr_assert(0 == 1);
		FALL_THROUGH;

	/*
	 *	TMPL_TYPE_DATA is not allowed here, as it is
	 *	statically evaluated to true/false by cond_normalise()
	 */
	default:
		EVAL_DEBUG("FAIL %d", __LINE__);
		break;
	}

	return false;
}

#ifdef HAVE_REGEX
/** Perform a regular expressions comparison between two operands
 *
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
static int cond_do_regex(request_t *request, fr_value_box_t const *subject, regex_t *preg)
{
	uint32_t	subcaptures;
	int		ret;

	fr_regmatch_t	*regmatch;

	if (!fr_cond_assert(subject != NULL)) return -1;
	if (!fr_cond_assert(subject->type == FR_TYPE_STRING)) return -1;

	EVAL_DEBUG("CMP WITH REGEX");

	subcaptures = regex_subcapture_count(preg);
	if (!subcaptures) subcaptures = REQUEST_MAX_REGEX + 1;	/* +1 for %{0} (whole match) capture group */
	MEM(regmatch = regex_match_data_alloc(NULL, subcaptures));

	/*
	 *	Evaluate the expression
	 */
	ret = regex_exec(preg, subject->vb_strvalue, subject->vb_length, regmatch);
	switch (ret) {
	case 0:
		EVAL_DEBUG("CLEARING SUBCAPTURES");
		regex_sub_to_request(request, NULL, NULL);	/* clear out old entries */
		break;

	case 1:
		EVAL_DEBUG("SETTING SUBCAPTURES");
		regex_sub_to_request(request, &preg, &regmatch);
		break;

	case -1:
		EVAL_DEBUG("REGEX ERROR");
		RPEDEBUG("regex failed");
		break;

	default:
		break;
	}

	talloc_free(regmatch);	/* free if not consumed */

	return ret;
}
#endif

static size_t regex_escape(UNUSED request_t *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	char *p = out;

	while (*in && (outlen >= 2)) {
		switch (*in) {
		case '\\':
		case '.':
		case '*':
		case '+':
		case '?':
		case '|':
		case '^':
		case '$':
		case '[':	/* we don't list close braces */
		case '{':
		case '(':
			if (outlen < 3) goto done;

			*(p++) = '\\';
			outlen--;
			FALL_THROUGH;

		default:
			*(p++) = *(in++);
			outlen--;
			break;
		}
	}

done:
	*(p++) = '\0';
	return p - out;
}

/** Turn a raw #tmpl_t into #fr_value_data_t, mostly.
 *
 *  It does nothing for lists, attributes, and precompiled regexes.
 *
 *  For #TMPL_TYPE_DATA, it returns the raw data, which MUST NOT have
 *  a cast, and which MUST have the correct data type.
 *
 *  For everything else (exec, xlat, regex-xlat), it evaluates the
 *  tmpl, and returns a "realized" #fr_value_box_t.  That box can then
 *  be used for comparisons, with minimal extra processing.
 */
static int cond_realize_tmpl(request_t *request,
			     fr_value_box_t **out, fr_value_box_t **to_free,
			     tmpl_t *in, tmpl_t *other) /* both really should be 'const' */
{
	fr_value_box_t		*box;
	xlat_escape_legacy_t	escape = NULL;

	*out = *to_free = NULL;

	switch (in->type) {
	/*
	 *	These are handled elsewhere.
	 */
	case TMPL_TYPE_LIST:
#ifdef HAVE_REGEX
	case TMPL_TYPE_REGEX:
#endif
		return 0;

	case TMPL_TYPE_ATTR:
		/*
		 *	fast path?  If there's only one attribute, AND
		 *	tmpl_num is a simple number, then just find
		 *	that attribute.  This fast path should ideally
		 *	avoid all of the cost of setting up the
		 *	cursors?
		 */
		return 0;

	/*
	 *	Return the raw data, which MUST already have been
	 *	converted to the correct thing.
	 */
	case TMPL_TYPE_DATA:
		fr_assert((in->cast == FR_TYPE_INVALID) || (in->cast == tmpl_value_type(in)));
		*out = tmpl_value(in);
		return 0;

#ifdef HAVE_REGEX
	case TMPL_TYPE_REGEX_XLAT:
		escape = regex_escape;
		FALL_THROUGH;
#endif

	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	{
		ssize_t		ret;
		fr_type_t	cast_type;
		fr_dict_attr_t const *da = NULL;

		box = NULL;
		ret = tmpl_aexpand(request, &box, request, in, escape, NULL);
		if (ret < 0) return ret;

		fr_assert(box != NULL);

		/*
		 *	We can't be TMPL_TYPE_ATTR or TMPL_TYPE_DATA,
		 *	because that was caught above.
		 *
		 *	So we look for an explicit cast, and if we
		 *	don't find that, then the *other* side MUST
		 *	have an explicit data type.
		 */
		if (in->cast != FR_TYPE_INVALID) {
			cast_type = in->cast;

		} else if (other->cast) {
			cast_type = other->cast;

		} else if (tmpl_is_attr(other)) {
			da = tmpl_da(other);
			cast_type = da->type;

		} else if (tmpl_is_data(other)) {
			cast_type = tmpl_value_type(other);

		} else {
			cast_type = FR_TYPE_STRING;
		}

		if (cast_type != box->type) {
			if (fr_value_box_cast_in_place(box, box, cast_type, da) < 0) {
				RPEDEBUG("Failed casting!");
				return -1;
			}
		}

		*out = *to_free = box;
		return 0;
	}

	default:
		break;
	}

	/*
	 *	Other tmpl type, return an error.
	 */
	fr_assert(0);
	return -1;
}


static int cond_realize_attr(request_t *request, fr_value_box_t **realized, fr_value_box_t *box,
			     tmpl_t *vpt, fr_pair_t *vp, fr_dict_attr_t const *da)
{
	fr_type_t cast_type;

	/*
	 *	Sometimes we're casting to a type with enums.  If so,
	 *	use that.
	 */
	if (da) {
		cast_type = da->type;

	} else if (vpt->cast != FR_TYPE_INVALID) {
		/*
		 *	If there's an explicit cast, use that.
		 */
		cast_type = vpt->cast;

	} else {
		/*
		 *	Otherwise the VP is already of the correct type.
		 */
		goto dont_cast;
	}

	/*
	 *	No casting needed.  Just return the data.
	 */
	if (cast_type == vp->da->type) {
	dont_cast:
		*realized = &vp->data;
		return 0;
	}

	fr_value_box_init_null(box);
	if (fr_value_box_cast(request, box, cast_type, da, &vp->data) < 0) {
		if (request) RPEDEBUG("Failed casting %pV to type %s", &vp->data,
				      fr_table_str_by_value(fr_value_box_type_table,
							    vpt->cast, "??"));
		return -1;
	}


	*realized = box;
	return 0;
}

static int cond_compare_attrs(request_t *request, fr_value_box_t *lhs, map_t const *map)
{
	int	       		rcode;
	fr_pair_t		*vp;
	fr_cursor_t		cursor;
	tmpl_cursor_ctx_t	cc;
	fr_value_box_t		*rhs, rhs_cast;
	fr_dict_attr_t const	*da = NULL;

	if (tmpl_is_attr(map->lhs) && (map->lhs->cast == FR_TYPE_INVALID)) da = tmpl_da(map->lhs);

	fr_value_box_clear(&rhs_cast);

	for (vp = tmpl_cursor_init(&rcode, request, &cc, &cursor, request, map->rhs);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (cond_realize_attr(request, &rhs, &rhs_cast, map->rhs, vp, da) < 0) {
			RPEDEBUG("Failed realizing RHS %pV", &vp->data);
			if (rhs == &rhs_cast) fr_value_box_clear(&rhs_cast);
			rcode = -1;
			break;
		}

		fr_assert(lhs->type == rhs->type);

		rcode = fr_value_box_cmp_op(map->op, lhs, rhs);

		if (rhs == &rhs_cast) fr_value_box_clear(&rhs_cast);
		if (rcode != 0) break;
	}

	tmpl_cursor_clear(&cc);
	return rcode;
}

static int cond_compare_virtual(request_t *request, map_t const *map)
{
	int	       		rcode;
	fr_pair_t		*virt, *vp;
	fr_value_box_t		*rhs, rhs_cast;
	fr_cursor_t		cursor;
	tmpl_cursor_ctx_t	cc;

	fr_assert(tmpl_is_attr(map->lhs));
	fr_assert(tmpl_is_attr(map->rhs));

	fr_value_box_clear(&rhs_cast);

	for (vp = tmpl_cursor_init(&rcode, request, &cc, &cursor, request, map->rhs);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (cond_realize_attr(request, &rhs, &rhs_cast, map->rhs, vp, NULL) < 0) {
			RPEDEBUG("Failed realizing RHS %pV", &vp->data);
			if (rhs == &rhs_cast) fr_value_box_clear(&rhs_cast);
			rcode = -1;
			break;
		}

		/*
		 *	Create the virtual check item.
		 */
		MEM(virt = fr_pair_afrom_da(request, tmpl_da(map->lhs)));
		virt->op = map->op;
		fr_value_box_copy(virt, &virt->data, rhs);

		rcode = paircmp_virtual(request, &request->request_pairs, virt);
		talloc_free(virt);
		rcode = (rcode == 0) ? 1 : 0;
		if (rhs == &rhs_cast) fr_value_box_clear(&rhs_cast);
		if (rcode != 0) break;
	}

	tmpl_cursor_clear(&cc);
	return rcode;
}

/** Evaluate a map
 *
 * @param[in] request the request_t
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval_map(request_t *request, UNUSED int depth, fr_cond_t const *c)
{
	int rcode = 0;
	map_t const *map = c->data.map;

	fr_value_box_t *lhs, *lhs_free;
	fr_value_box_t *rhs, *rhs_free;
	regex_t		*preg, *preg_free;

#ifndef NDEBUG
	/*
	 *	At this point, all tmpls MUST have been resolved.
	 */
	fr_assert(!tmpl_is_unresolved(c->data.map->lhs));
	fr_assert(!tmpl_is_unresolved(c->data.map->rhs));
#endif

	EVAL_DEBUG(">>> MAP TYPES LHS: %s, RHS: %s",
		   fr_table_str_by_value(tmpl_type_table, map->lhs->type, "???"),
		   fr_table_str_by_value(tmpl_type_table, map->rhs->type, "???"));

	MAP_VERIFY(map);
	preg = preg_free = NULL;

	/*
	 *	Realize the LHS of a condition.
	 */
	if (cond_realize_tmpl(request, &lhs, &lhs_free, map->lhs, map->rhs) < 0) {
		fr_strerror_const("Failed evaluating left side of condition");
		return -1;
	}

	/*
	 *	Realize the RHS of a condition.
	 */
	if (cond_realize_tmpl(request, &rhs, &rhs_free, map->rhs, map->lhs) < 0) {
		fr_strerror_const("Failed evaluating right side of condition");
		return -1;
	}

	/*
	 *	Precompile the regular expressions.
	 */
	if (map->op == T_OP_REG_EQ) {
		if (!rhs) {
			fr_assert(map->rhs->type == TMPL_TYPE_REGEX);
			preg = tmpl_regex(map->rhs);
		} else {
			ssize_t slen;

			slen = regex_compile(request, &preg_free, rhs->vb_strvalue, rhs->vb_length,
					     tmpl_regex_flags(map->rhs), true, true);
			if (slen <= 0) {
				REMARKER(rhs->vb_strvalue, -slen, "%s", fr_strerror());
				EVAL_DEBUG("FAIL %d", __LINE__);
				return -1;
			}
			preg = preg_free;
		}

		/*
		 *	We have a value on the LHS.  Just go do that.
		 */
		if (lhs) {
			rcode = cond_do_regex(request, lhs, preg);
			goto done;
		}

		/*
		 *	Otherwise loop over the LHS attribute / list.
		 */
		goto check_attrs;
	}

	/*
	 *	We have both left and right sides as #fr_value_box_t,
	 *	we can just evaluate the comparison here.
	 *
	 *	This is largely just cond_cmp_values() ...
	 */
	if (lhs && rhs) {
		rcode = fr_value_box_cmp_op(map->op, lhs, rhs);
		goto done;
	}

	/*
	 *	LHS is a virtual attribute.  The RHS MUST be data, not
	 *	an attribute or a list.
	 */
	if (c->pass2_fixup == PASS2_PAIRCOMPARE) {
		fr_pair_t *vp;

		fr_assert(tmpl_is_attr(map->lhs));

		if (map->op == T_OP_REG_EQ) {
			fr_strerror_const("Virtual attributes cannot be used with regular expressions");
			return -1;
		}

		/*
		 *	&LDAP-Group == &Filter-Id
		 */
		if (tmpl_is_attr(map->rhs)) {
			fr_assert(!lhs);
			fr_assert(!rhs);

			rcode = cond_compare_virtual(request, map);
			goto done;
		}

		/*
		 *	Forbid bad things.
		 */
		if (!rhs) {
			fr_strerror_const("Invalid comparison for virtual attribute");
			return -1;
		}

		MEM(vp = fr_pair_afrom_da(request, tmpl_da(map->lhs)));
		vp->op = c->data.map->op;
		fr_value_box_copy(vp, &vp->data, rhs);

		/*
		 *	Do JUST the virtual attribute comparison.
		 *	Skip all of the rest of the complexity of paircmp().
		 */
		rcode = paircmp_virtual(request, &request->request_pairs, vp);
		talloc_free(vp);
		rcode = (rcode == 0) ? 1 : 0;
		goto done;
	}

check_attrs:
	switch (map->lhs->type) {
	/*
	 *	LHS is an attribute or list
	 */
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR:
	{
		fr_pair_t		*vp;
		fr_cursor_t		cursor;
		tmpl_cursor_ctx_t	cc;

		fr_assert(!lhs);

		for (vp = tmpl_cursor_init(&rcode, request, &cc, &cursor, request, map->lhs);
		     vp;
	     	     vp = fr_cursor_next(&cursor)) {
			fr_value_box_t lhs_cast;

			/*
			 *	Take the value box directly from the
			 *	attribute, _unless_ there's a cast.
			 */
			if (cond_realize_attr(request, &lhs, &lhs_cast, map->lhs, vp, NULL) < 0) {
				rcode = -1;
				goto done;
			}

			/*
			 *	Now that we have a realized LHS, we
			 *	can do a regex comparison, using the
			 *	precompiled regex.
			 */
			if (map->op == T_OP_REG_EQ) {
				rcode = cond_do_regex(request, lhs, preg);
				goto next;
			}

			/*
			 *	We have a realized RHS.  Just do the
			 *	comparisons with the value boxes.
			 *
			 *	Realizing the LHS means that we've
			 *	either used the VP data as-is, or cast
			 *	it to the correct data type.
			 */
			if (rhs) {
				fr_assert(lhs->type == rhs->type);
				rcode = fr_value_box_cmp_op(map->op, lhs, rhs);
				goto next;
			}

			/*
			 *	And we're left with attribute
			 *	comparisons.  We've got to find the
			 *	attribute on the RHS, and do the
			 *	comparisons.
			 *
			 *	This comparison means looping over all
			 *	matching attributes.  We're already
			 *	many layers deep of indentation, so
			 *	just dump this code into a separate
			 *	function.
			 */
			fr_assert(tmpl_is_attr(map->rhs));

			rcode = cond_compare_attrs(request, lhs, map);

		next:
			if (lhs == &lhs_cast) fr_value_box_clear(&lhs_cast);
			lhs = NULL;
			if (rcode != 0) goto done;
			continue;
		}

		tmpl_cursor_clear(&cc);
	}
		break;

	default:
		fr_assert(0);
		rcode = -1;
		break;
	}

	EVAL_DEBUG("<<<");

done:
	talloc_free(lhs_free);
	talloc_free(rhs_free);
	talloc_free(preg_free);
	return rcode;
}

/** Evaluate a fr_cond_t;
 *
 * @param[in] request the request_t
 * @param[in] modreturn the previous module return code
 * @param[in] c the condition to evaluate
 * @return
 *	- -1 on failure.
 *	- -2 on attribute not found.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval(request_t *request, rlm_rcode_t modreturn, fr_cond_t const *c)
{
	int rcode = -1;
	int depth = 0;

#ifdef WITH_EVAL_DEBUG
	char buffer[1024];

	cond_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), c);
	EVAL_DEBUG("%s", buffer);
#endif

	while (c) {
		switch (c->type) {
		case COND_TYPE_TMPL:
			rcode = cond_eval_tmpl(request, depth, c->data.vpt);
			break;

		case COND_TYPE_RCODE:
			rcode = (c->data.rcode == modreturn);
			break;

		case COND_TYPE_MAP:
			rcode = cond_eval_map(request, depth, c);
			break;

		case COND_TYPE_CHILD:
			depth++;
			c = c->data.child;
			continue;

		case COND_TYPE_TRUE:
			rcode = true;
			break;

		case COND_TYPE_FALSE:
			rcode = false;
			break;
		default:
			EVAL_DEBUG("FAIL %d", __LINE__);
			return -1;
		}

		/*
		 *	Errors cause failures.
		 */
		if (rcode < 0) return rcode;

		if (c->negate) rcode = !rcode;

		/*
		 *	We've fallen off of the end of this evaluation
		 *	string.  Go back up to the parent, and then to
		 *	the next sibling of the parent.
		 *
		 *	Do this repeatedly until we have a c->next
		 */
		while (!c->next) {
return_to_parent:
			c = c->parent;
			if (!c) return rcode;

			depth--;
			fr_assert(depth >= 0);
		}

		/*
		 *	Do short-circuit evaluations.
		 */
		switch (c->next->type) {
		case COND_TYPE_AND:
			if (!rcode) goto return_to_parent;

			c = c->next->next; /* skip the && */
			break;

		case COND_TYPE_OR:
			if (rcode) goto return_to_parent;

			c = c->next->next; /* skip the || */
			break;

		default:
			c = c->next;
			break;
		}
	}

	if (rcode < 0) {
		EVAL_DEBUG("FAIL %d", __LINE__);
	}
	return rcode;
}
