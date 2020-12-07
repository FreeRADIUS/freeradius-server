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
	{ L("exists"),		COND_TYPE_EXISTS	},
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

static bool all_digits(char const *string)
{
	char const *p = string;

	fr_assert(p != NULL);

	if (*p == '\0') return false;

	if (*p == '-') p++;

	while (isdigit((int) *p)) p++;

	return (*p == '\0');
}

/** Debug function to dump a cond structure
 *
 */
void cond_debug(fr_cond_t const *cond)
{
	fr_cond_t const *c;

	for (c = cond; c; c =c->next) {
		INFO("cond %s (%p)", fr_table_str_by_value(cond_type_table, c->type, "<INVALID>"), cond);
		INFO("\tnegate : %s", c->negate ? "true" : "false");
		INFO("\tcast   : %s", c->cast ? fr_table_str_by_value(fr_value_box_type_table,
								      c->cast->type, "<INVALID>") : "none");
		INFO("\top     : %s", fr_table_str_by_value(cond_logical_op_table, c->next_op, "<INVALID>"));
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

		case COND_TYPE_EXISTS:
			tmpl_debug(c->data.vpt);
			break;

		case COND_TYPE_CHILD:
			INFO("child (");
			cond_debug(c->data.child);
			INFO(")");
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
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval_tmpl(request_t *request, UNUSED int depth, tmpl_t const *vpt)
{
	int rcode = -1;

	switch (vpt->type) {
	case TMPL_TYPE_UNRESOLVED:
		/*
		 *	Empty string is false, non-empty string
		 *	is true.
		 *
		 *	@todo: Maybe also check for digits?
		 */
		rcode = (*vpt->data.unescaped != '\0');
		break;

	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		if (tmpl_find_vp(NULL, request, vpt) == 0) {
			rcode = true;
		} else {
			rcode = false;
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
			return -1;
		}
		talloc_free(p);

		if (slen == 0) return false;
	}
		return true;

	/*
	 *	Can't have a bare ... (/foo/) ...
	 */
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
		fr_assert(0 == 1);
		FALL_THROUGH;

	default:
		EVAL_DEBUG("FAIL %d", __LINE__);
		rcode = -1;
		break;
	}

	return rcode;
}

#ifdef HAVE_REGEX
/** Perform a regular expressions comparison between two operands
 *
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
static int cond_do_regex(request_t *request, fr_cond_t const *c,
		         fr_value_box_t const *lhs,
		         fr_value_box_t const *rhs)
{
	map_t const *map = c->data.map;

	ssize_t		slen;
	uint32_t	subcaptures;
	int		ret;

	regex_t		*preg, *rreg = NULL;
	fr_regmatch_t	*regmatch;

	if (!fr_cond_assert(lhs != NULL)) return -1;
	if (!fr_cond_assert(lhs->type == FR_TYPE_STRING)) return -1;

	EVAL_DEBUG("CMP WITH REGEX");

	switch (map->rhs->type) {
	case TMPL_TYPE_REGEX: /* pre-compiled to a regex */
		preg = tmpl_regex(map->rhs);
		break;

	default:
		if (!fr_cond_assert(rhs && rhs->type == FR_TYPE_STRING)) return -1;
		if (!fr_cond_assert(rhs && rhs->vb_strvalue)) return -1;
		slen = regex_compile(request, &rreg, rhs->vb_strvalue, rhs->vb_length,
				     tmpl_regex_flags(map->rhs), true, true);
		if (slen <= 0) {
			REMARKER(rhs->vb_strvalue, -slen, "%s", fr_strerror());
			EVAL_DEBUG("FAIL %d", __LINE__);

			return -1;
		}
		preg = rreg;
		break;
	}

	subcaptures = regex_subcapture_count(preg);
	if (!subcaptures) subcaptures = REQUEST_MAX_REGEX + 1;	/* +1 for %{0} (whole match) capture group */
	MEM(regmatch = regex_match_data_alloc(NULL, subcaptures));

	/*
	 *	Evaluate the expression
	 */
	ret = regex_exec(preg, lhs->vb_strvalue, lhs->vb_length, regmatch);
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
	if (preg) talloc_free(rreg);

	return ret;
}
#endif

#ifdef WITH_EVAL_DEBUG
static void cond_print_operands(fr_value_box_t const *lhs, fr_value_box_t const *rhs)
{
	if (lhs) {
		if (lhs->type == FR_TYPE_STRING) {
			EVAL_DEBUG("LHS: \"%pV\" (%zu)" , &lhs->datum, lhs->vb_length);
		} else {
			EVAL_DEBUG("LHS: 0x%pH (%zu)", &lhs->datum, lhs->vb_length);
		}
	} else {
		EVAL_DEBUG("LHS: VIRTUAL");
	}

	if (rhs) {
		if (rhs->type == FR_TYPE_STRING) {
			EVAL_DEBUG("RHS: \"%pV\" (%zu)", &rhs->datum, rhs->vb_length);
		} else {
			EVAL_DEBUG("RHS: 0x%pH (%zu)", &rhs->datum, rhs->vb_length);
		}
	} else {
		EVAL_DEBUG("RHS: COMPILED");
	}
}
#endif

/** Call the correct data comparison function for the condition
 *
 * Deals with regular expression comparisons, virtual attribute
 * comparisons, and data comparisons.
 *
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
static int cond_cmp_values(request_t *request, fr_cond_t const *c, fr_value_box_t const *lhs, fr_value_box_t const *rhs)
{
	map_t const *map = c->data.map;
	int rcode;

#ifdef WITH_EVAL_DEBUG
	EVAL_DEBUG("CMP OPERANDS");
	cond_print_operands(lhs, rhs);
#endif

#ifdef HAVE_REGEX
	/*
	 *	Regex comparison
	 */
	if (map->op == T_OP_REG_EQ) {
		rcode = cond_do_regex(request, c, lhs, rhs);
		goto finish;
	}
#endif
	/*
	 *	Virtual attribute comparison.
	 */
	if (c->pass2_fixup == PASS2_PAIRCOMPARE) {
		fr_pair_t *vp;
		fr_pair_list_t vps;

		fr_pair_list_init(&vps);
		EVAL_DEBUG("CMP WITH PAIRCOMPARE");
		fr_assert(tmpl_is_attr(map->lhs));

		MEM(vp = fr_pair_afrom_da(request, tmpl_da(map->lhs)));
		vp->op = c->data.map->op;

		fr_value_box_copy(vp, &vp->data, rhs);

		fr_pair_list_single_value(vps,*vp);
		rcode = paircmp(request, &request->request_pairs, &vps);
		rcode = (rcode == 0) ? 1 : 0;
		talloc_free(vp);
		goto finish;
	}

	EVAL_DEBUG("CMP WITH VALUE DATA");
	rcode = fr_value_box_cmp_op(map->op, lhs, rhs);
finish:
	switch (rcode) {
	case 0:
		EVAL_DEBUG("FALSE");
		break;

	case 1:
		EVAL_DEBUG("TRUE");
		break;

	default:
		EVAL_DEBUG("ERROR %i", rcode);
		break;
	}

	return rcode;
}


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

/** Convert both operands to the same type
 *
 * If casting is successful, we call cond_cmp_values to do the comparison
 *
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
static int cond_normalise_and_cmp(request_t *request, fr_cond_t const *c, fr_value_box_t const *lhs)
{
	map_t const		*map = c->data.map;

	int			rcode;

	fr_value_box_t const	*rhs = NULL;

	fr_dict_attr_t const	*cast = NULL;
	fr_type_t		cast_type = FR_TYPE_INVALID;

	fr_value_box_t		lhs_cast = { .type = FR_TYPE_INVALID };
	fr_value_box_t		rhs_cast = { .type = FR_TYPE_INVALID };

	xlat_escape_legacy_t	escape = NULL;

	/*
	 *	Cast operand to correct type.
	 */
#define CAST(_s) \
do {\
	if ((cast_type != FR_TYPE_INVALID) && _s && (_s ->type != FR_TYPE_INVALID) && (cast_type != _s->type)) {\
		EVAL_DEBUG("CASTING " #_s " FROM %s TO %s",\
			   fr_table_str_by_value(fr_value_box_type_table, _s->type, "<INVALID>"),\
			   fr_table_str_by_value(fr_value_box_type_table, cast_type, "<INVALID>"));\
		if (fr_value_box_cast(request, &_s ## _cast, cast_type, cast, _s) < 0) {\
			if (request) RPEDEBUG("Failed casting " #_s " operand");\
			rcode = -1;\
			goto finish;\
		}\
		_s = &_s ## _cast;\
	}\
} while (0)

#define CHECK_INT_CAST(_l, _r) \
do {\
	if ((cast_type == FR_TYPE_INVALID) &&\
	    _l && (_l->type == FR_TYPE_STRING) &&\
	    _r && (_r->type == FR_TYPE_STRING) &&\
	    all_digits(lhs->vb_strvalue) && all_digits(rhs->vb_strvalue)) {\
	    	cast_type = FR_TYPE_UINT64;\
	    	EVAL_DEBUG("OPERANDS ARE NUMBER STRINGS, SETTING CAST TO uint64");\
	}\
} while (0)

	/*
	 *	Regular expressions need both operands to be strings
	 */
#ifdef HAVE_REGEX
	if (map->op == T_OP_REG_EQ) {
		cast_type = FR_TYPE_STRING;

		if (tmpl_is_regex_xlat(map->rhs)) escape = regex_escape;
	}
	else
#endif
	/*
	 *	If it's a pair comparison, data gets cast to the
	 *	type of the pair comparison attribute.
	 *
	 *	Magic attribute is always the LHS.
	 */
	if (c->pass2_fixup == PASS2_PAIRCOMPARE) {
		fr_assert(!c->cast);
		fr_assert(tmpl_is_attr(map->lhs));
		fr_assert(!tmpl_is_attr(map->rhs) || !paircmp_find(tmpl_da(map->rhs))); /* expensive assert */

		cast = tmpl_da(map->lhs);

		EVAL_DEBUG("NORMALISATION TYPE %s (PAIRCMP TYPE)",
			   fr_table_str_by_value(fr_value_box_type_table, cast->type, "<INVALID>"));
	/*
	 *	Otherwise we use the explicit cast, or implicit
	 *	cast (from an attribute reference).
	 *	We already have the data for the lhs, so we convert
	 *	it here.
	 */
	} else if (c->cast) {
		cast = c->cast;
		EVAL_DEBUG("NORMALISATION TYPE %s (EXPLICIT CAST)",
			   fr_table_str_by_value(fr_value_box_type_table, cast->type, "<INVALID>"));
	} else if (tmpl_is_attr(map->lhs)) {
		cast = tmpl_da(map->lhs);
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM LHS REF)",
			   fr_table_str_by_value(fr_value_box_type_table, cast->type, "<INVALID>"));
	} else if (tmpl_is_attr(map->rhs)) {
		cast = tmpl_da(map->rhs);
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM RHS REF)",
			   fr_table_str_by_value(fr_value_box_type_table, cast->type, "<INVALID>"));
	} else if (tmpl_is_data(map->lhs)) {
		cast_type = tmpl_value_type(map->lhs);
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM LHS DATA)",
			   fr_table_str_by_value(fr_value_box_type_table, cast_type, "<INVALID>"));
	} else if (tmpl_is_data(map->rhs)) {
		cast_type = tmpl_value_type(map->rhs);
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM RHS DATA)",
			   fr_table_str_by_value(fr_value_box_type_table, cast_type, "<INVALID>"));
	}

	if (cast) cast_type = cast->type;

	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	{
		fr_pair_t		*vp;
		fr_cursor_t		cursor;
		tmpl_cursor_ctx_t	cc;

		for (vp = tmpl_cursor_init(&rcode, request, &cc, &cursor, request, map->rhs);
		     vp;
	     	     vp = fr_cursor_next(&cursor)) {
			rhs = &vp->data;

			CHECK_INT_CAST(lhs, rhs);
			CAST(lhs);
			CAST(rhs);

			rcode = cond_cmp_values(request, c, lhs, rhs);
			if (rcode != 0) break;

			fr_value_box_clear(&rhs_cast);
		}
		tmpl_cursor_clear(&cc);
	}
		break;

	case TMPL_TYPE_DATA:
		rhs = tmpl_value(map->rhs);

		CHECK_INT_CAST(lhs, rhs);
		CAST(lhs);
		CAST(rhs);

		rcode = cond_cmp_values(request, c, lhs, rhs);
		break;

	/*
	 *	Expanded types start as strings, then get converted
	 *	to the type of the attribute or the explicit cast.
	 */
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_REGEX_XLAT:
	{
		ssize_t ret;
		fr_value_box_t data;

		if (!tmpl_is_unresolved(map->rhs)) {
			char *p;

			ret = tmpl_aexpand(request, &p, request, map->rhs, escape, NULL);
			if (ret < 0) {
				EVAL_DEBUG("FAIL [%i]", __LINE__);
				rcode = -1;
				goto finish;
			}
			fr_value_box_bstrndup_shallow(&data, NULL, p, ret, false);
		} else {
			fr_value_box_bstrdup_buffer_shallow(NULL, &data, NULL, map->rhs->data.unescaped, false);
		}
		rhs = &data;

		CHECK_INT_CAST(lhs, rhs);
		CAST(lhs);
		CAST(rhs);

		rcode = cond_cmp_values(request, c, lhs, rhs);
		if (!tmpl_is_unresolved(map->rhs)) talloc_free(data.datum.ptr);

		break;
	}

	/*
	 *	RHS is a compiled regex, we don't need to do anything with it.
	 */
	case TMPL_TYPE_REGEX:
		CAST(lhs);
		rcode = cond_cmp_values(request, c, lhs, NULL);
		break;
	/*
	 *	Unsupported types (should have been parse errors)
	 */
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:		/* should now be a TMPL_TYPE_XLAT */
	case TMPL_TYPE_EXEC_UNRESOLVED:		/* should now be a TMPL_TYPE_EXEC */
	case TMPL_TYPE_REGEX_UNCOMPILED:	/* should now be a TMPL_TYPE_REGEX */
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:	/* Should now be a TMPL_TYPE_REGEX_XLAT */
	case TMPL_TYPE_MAX:
		fr_assert(0);
		rcode = -1;
		break;
	}

finish:
	fr_value_box_clear(&lhs_cast);
	fr_value_box_clear(&rhs_cast);

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

	EVAL_DEBUG(">>> MAP TYPES LHS: %s, RHS: %s",
		   fr_table_str_by_value(tmpl_type_table, map->lhs->type, "???"),
		   fr_table_str_by_value(tmpl_type_table, map->rhs->type, "???"));

	MAP_VERIFY(map);

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
		/*
		 *	Legacy paircmp call, skip processing the magic attribute
		 *	if it's the LHS and cast RHS to the same type.
		 */
		if ((c->pass2_fixup == PASS2_PAIRCOMPARE) && (map->op != T_OP_REG_EQ)) {
#ifndef NDEBUG
			fr_assert(paircmp_find(tmpl_da(map->lhs))); /* expensive assert */
#endif
			rcode = cond_normalise_and_cmp(request, c, NULL);
			break;
		}
		for (vp = tmpl_cursor_init(&rcode, request, &cc, &cursor, request, map->lhs);
		     vp;
	     	     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Evaluate all LHS values, condition evaluates to true
			 *	if we get at least one set of operands that
			 *	evaluates to true.
			 */
	     		rcode = cond_normalise_and_cmp(request, c, &vp->data);
	     		if (rcode != 0) break;
		}

		tmpl_cursor_clear(&cc);
	}
		break;

	case TMPL_TYPE_DATA:
		rcode = cond_normalise_and_cmp(request, c, tmpl_value(map->lhs));
		break;

	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	{
		char		*p = NULL;
		ssize_t		ret;
		fr_value_box_t	data;

		if (!tmpl_is_unresolved(map->lhs)) {
			ret = tmpl_aexpand(request, &p, request, map->lhs, NULL, NULL);
			if (ret < 0) {
				EVAL_DEBUG("FAIL [%i]", __LINE__);
				return ret;
			}

			fr_value_box_bstrndup_shallow(&data, NULL, p, ret, false);
		} else {
			fr_value_box_bstrdup_buffer_shallow(NULL, &data, NULL, map->lhs->data.unescaped, false);
		}

		rcode = cond_normalise_and_cmp(request, c, &data);
		if (p) talloc_free(p);
	}
		break;

	/*
	 *	Unsupported types (should have been parse errors)
	 */
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_EXEC_UNRESOLVED:		/* should now be a TMPL_TYPE_EXEC */
	case TMPL_TYPE_XLAT_UNRESOLVED:		/* should now be a TMPL_TYPE_XLAT */
	case TMPL_TYPE_REGEX_UNCOMPILED:	/* should now be a TMPL_TYPE_REGEX */
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:	/* should now be a TMPL_TYPE_REGEX_XLAT */
	case TMPL_TYPE_REGEX:			/* not allowed as LHS */
	case TMPL_TYPE_REGEX_XLAT:		/* not allowed as LHS */
	case TMPL_TYPE_MAX:
		fr_assert(0);
		rcode = -1;
		break;
	}

	EVAL_DEBUG("<<<");

	return rcode;
}

/** Evaluate a fr_cond_t;
 *
 * @param[in] request the request_t
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return
 *	- -1 on failure.
 *	- -2 on attribute not found.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval(request_t *request, rlm_rcode_t modreturn, int depth, fr_cond_t const *c)
{
	int rcode = -1;
#ifdef WITH_EVAL_DEBUG
	char buffer[1024];

	cond_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), c);
	EVAL_DEBUG("%s", buffer);
#endif

	while (c) {
		switch (c->type) {
		case COND_TYPE_EXISTS:
			rcode = cond_eval_tmpl(request, depth, c->data.vpt);
			/* Existence checks are special, because we expect them to fail */
			if (rcode < 0) rcode = 0;
			break;

		case COND_TYPE_RCODE:
			rcode = (c->data.rcode == modreturn);
			break;

		case COND_TYPE_MAP:
			rcode = cond_eval_map(request, depth, c);
			break;

		case COND_TYPE_CHILD:
			rcode = cond_eval(request, modreturn, depth + 1, c->data.child);
			break;

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

		if (rcode < 0) return rcode;

		if (c->negate) rcode = !rcode;

		if (!c->next) break;

		/*
		 *	FALSE && ... = FALSE
		 */
		if (!rcode && (c->next_op == COND_AND)) return false;

		/*
		 *	TRUE || ... = TRUE
		 */
		if (rcode && (c->next_op == COND_OR)) return true;

		c = c->next;
	}

	if (rcode < 0) {
		EVAL_DEBUG("FAIL %d", __LINE__);
	}
	return rcode;
}
