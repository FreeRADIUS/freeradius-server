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
 * @copyright 2007  The FreeRADIUS server project
 * @copyright 2007  Alan DeKok <aland@deployingradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>

#ifdef WITH_UNLANG
#ifdef WITH_EVAL_DEBUG
#  define EVAL_DEBUG(fmt, ...) printf("EVAL: ");printf(fmt, ## __VA_ARGS__);printf("\n");fflush(stdout)
#else
#  define EVAL_DEBUG(...)
#endif

FR_NAME_NUMBER const modreturn_table[] = {
	{ "reject",		RLM_MODULE_REJECT       },
	{ "fail",		RLM_MODULE_FAIL	 	},
	{ "ok",			RLM_MODULE_OK	   	},
	{ "handled",		RLM_MODULE_HANDLED      },
	{ "invalid",		RLM_MODULE_INVALID      },
	{ "userlock",		RLM_MODULE_USERLOCK     },
	{ "notfound", 		RLM_MODULE_NOTFOUND     },
	{ "noop",		RLM_MODULE_NOOP	 	},
	{ "updated",		RLM_MODULE_UPDATED      },
	{ NULL, 0 }
};


static bool all_digits(char const *string)
{
	char const *p = string;

	rad_assert(p != NULL);

	if (*p == '\0') return false;

	if (*p == '-') p++;

	while (isdigit((int) *p)) p++;

	return (*p == '\0');
}

/** Evaluate a template
 *
 * Converts a vp_tmpl_t to a boolean value.
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] vpt the template to evaluate
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval_tmpl(REQUEST *request, int modreturn, UNUSED int depth, vp_tmpl_t const *vpt)
{
	int rcode;
	int modcode;
	fr_value_box_t data;

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
		modcode = fr_str2int(modreturn_table, vpt->name, RLM_MODULE_UNKNOWN);
		if (modcode != RLM_MODULE_UNKNOWN) {
			rcode = (modcode == modreturn);
			break;
		}

		/*
		 *	Else it's a literal string.  Empty string is
		 *	false, non-empty string is true.
		 *
		 *	@todo: Maybe also check for digits?
		 *
		 *	The VPT *doesn't* have a "bare word" type,
		 *	which arguably it should.
		 */
		rcode = (*vpt->name != '\0');
		break;

	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		if (tmpl_find_vp(NULL, request, vpt) == 0) {
			rcode = true;
		} else {
			rcode = false;
		}
		break;

	case TMPL_TYPE_XLAT_STRUCT:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
	{
		char *p;

		if (!*vpt->name) return false;
		rcode = tmpl_aexpand(request, &p, request, vpt, NULL, NULL);
		if (rcode < 0) {
			EVAL_DEBUG("FAIL %d", __LINE__);
			return -1;
		}
		data.vb_strvalue = p;
		rcode = (data.vb_strvalue && (*data.vb_strvalue != '\0'));
		talloc_free(data.datum.ptr);
	}
		break;

	/*
	 *	Can't have a bare ... (/foo/) ...
	 */
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_STRUCT:
		rad_assert(0 == 1);
		/* FALL-THROUGH */

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
static int cond_do_regex(REQUEST *request, fr_cond_t const *c,
		         fr_value_box_t const *lhs,
		         fr_value_box_t const *rhs)
{
	vp_map_t const *map = c->data.map;

	ssize_t		slen;
	int		ret;

	regex_t		*preg, *rreg = NULL;
	regmatch_t	rxmatch[REQUEST_MAX_REGEX + 1];	/* +1 for %{0} (whole match) capture group */
	size_t		nmatch = sizeof(rxmatch) / sizeof(regmatch_t);

	if (!fr_cond_assert(lhs != NULL)) return -1;
	if (!fr_cond_assert(lhs->type == FR_TYPE_STRING)) return -1;

	EVAL_DEBUG("CMP WITH REGEX %s %s",
		   map->rhs->tmpl_iflag ? "CASE INSENSITIVE" : "CASE SENSITIVE",
		   map->rhs->tmpl_mflag ? "MULTILINE" : "SINGLELINE");

	switch (map->rhs->type) {
	case TMPL_TYPE_REGEX_STRUCT: /* pre-compiled to a regex */
		preg = map->rhs->tmpl_preg;
		break;

	default:
		if (!fr_cond_assert(rhs && rhs->type == FR_TYPE_STRING)) return -1;
		if (!fr_cond_assert(rhs && rhs->vb_strvalue)) return -1;
		slen = regex_compile(request, &rreg, rhs->vb_strvalue, rhs->datum.length,
				     map->rhs->tmpl_iflag, map->rhs->tmpl_mflag, true, true);
		if (slen <= 0) {
			REMARKER(rhs->vb_strvalue, -slen, fr_strerror());
			EVAL_DEBUG("FAIL %d", __LINE__);

			return -1;
		}
		preg = rreg;
		break;
	}

	ret = regex_exec(preg, lhs->vb_strvalue, lhs->datum.length, rxmatch, &nmatch);
	switch (ret) {
	case 0:
		EVAL_DEBUG("CLEARING SUBCAPTURES");
		regex_sub_to_request(request, NULL, NULL, 0, NULL, 0);	/* clear out old entries */
		break;

	case 1:
		EVAL_DEBUG("SETTING SUBCAPTURES");
		regex_sub_to_request(request, &preg, lhs->vb_strvalue, lhs->datum.length, rxmatch, nmatch);
		break;

	case -1:
		EVAL_DEBUG("REGEX ERROR");
		RPEDEBUG("regex failed");
		break;

	default:
		break;
	}

	if (preg) talloc_free(rreg);

	return ret;
}
#endif

#ifdef WITH_EVAL_DEBUG
static void cond_print_operands(fr_value_box_t const *lhs, fr_value_box_t const *rhs)
{
	if (lhs) {
		if (lhs->type == FR_TYPE_STRING) {
			EVAL_DEBUG("LHS: \"%pV\" (%zu)" , &lhs->datum, lhs->datum.length);
		} else {
			EVAL_DEBUG("LHS: 0x%pH (%zu)", &lhs->datum, lhs->datum.length);
		}
	} else {
		EVAL_DEBUG("LHS: VIRTUAL");
	}

	if (rhs) {
		if (rhs->type == FR_TYPE_STRING) {
			EVAL_DEBUG("RHS: \"%pV\" (%zu)", &rhs->datum, rhs->datum.length);
		} else {
			EVAL_DEBUG("RHS: 0x%pH (%zu)", &rhs->datum, rhs->datum.length);
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
static int cond_cmp_values(REQUEST *request, fr_cond_t const *c, fr_value_box_t const *lhs, fr_value_box_t const *rhs)
{
	vp_map_t const *map = c->data.map;
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
		VALUE_PAIR *vp;

		EVAL_DEBUG("CMP WITH PAIRCOMPARE");
		rad_assert(map->lhs->type == TMPL_TYPE_ATTR);

		MEM(vp = fr_pair_afrom_da(request, map->lhs->tmpl_da));
		vp->op = c->data.map->op;

		fr_value_box_copy(vp, &vp->data, rhs);

		rcode = paircmp(request, request->packet->vps, vp, NULL);
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


static size_t regex_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
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
			/* FALL-THROUGH */

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
static int cond_normalise_and_cmp(REQUEST *request, fr_cond_t const *c, fr_value_box_t const *lhs)
{
	vp_map_t const		*map = c->data.map;

	int			rcode;

	fr_value_box_t		*rhs = NULL;

	fr_dict_attr_t const	*cast = NULL;
	fr_type_t		cast_type = FR_TYPE_INVALID;

	fr_value_box_t		lhs_cast = { .type = FR_TYPE_INVALID };
	fr_value_box_t		rhs_cast = { .type = FR_TYPE_INVALID };

	xlat_escape_t		escape = NULL;

	/*
	 *	Cast operand to correct type.
	 *
	 *	With hack for strings that look like integers, to cast them
	 *	to 64 bit unsigned integers.
	 *
	 * @fixme For things like this it'd be useful to have a 64bit signed type.
	 */
#define CAST(_s) \
do {\
	if ((cast_type != FR_TYPE_INVALID) && _s && (_s ->type != FR_TYPE_INVALID) && (cast_type != _s->type)) {\
		EVAL_DEBUG("CASTING " #_s " FROM %s TO %s",\
			   fr_int2str(dict_attr_types, _s->type, "<INVALID>"),\
			   fr_int2str(dict_attr_types, cast_type, "<INVALID>"));\
		if (fr_value_box_cast(request, &_s ## _cast, cast_type, cast, _s) < 0) {\
			RPEDEBUG("Failed casting " #_s " operand");\
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

		if (map->rhs->type == TMPL_TYPE_XLAT_STRUCT) escape = regex_escape;
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
		rad_assert(!c->cast);
		rad_assert(map->lhs->type == TMPL_TYPE_ATTR);
		rad_assert((map->rhs->type != TMPL_TYPE_ATTR) || !paircmp_find(map->rhs->tmpl_da)); /* expensive assert */

		cast = map->lhs->tmpl_da;

		EVAL_DEBUG("NORMALISATION TYPE %s (PAIRCMP TYPE)",
			   fr_int2str(dict_attr_types, cast->type, "<INVALID>"));
	/*
	 *	Otherwise we use the explicit cast, or implicit
	 *	cast (from an attribute reference).
	 *	We already have the data for the lhs, so we convert
	 *	it here.
	 */
	} else if (c->cast) {
		cast = c->cast;
		EVAL_DEBUG("NORMALISATION TYPE %s (EXPLICIT CAST)",
			   fr_int2str(dict_attr_types, cast->type, "<INVALID>"));
	} else if (map->lhs->type == TMPL_TYPE_ATTR) {
		cast = map->lhs->tmpl_da;
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM LHS REF)",
			   fr_int2str(dict_attr_types, cast->type, "<INVALID>"));
	} else if (map->rhs->type == TMPL_TYPE_ATTR) {
		cast = map->rhs->tmpl_da;
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM RHS REF)",
			   fr_int2str(dict_attr_types, cast->type, "<INVALID>"));
	} else if (map->lhs->type == TMPL_TYPE_DATA) {
		cast_type = map->lhs->tmpl_value_type;
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM LHS DATA)",
			   fr_int2str(dict_attr_types, cast_type, "<INVALID>"));
	} else if (map->rhs->type == TMPL_TYPE_DATA) {
		cast_type = map->rhs->tmpl_value_type;
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM RHS DATA)",
			   fr_int2str(dict_attr_types, cast_type, "<INVALID>"));
	}

	if (cast) cast_type = cast->type;

	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	{
		VALUE_PAIR *vp;
		fr_cursor_t cursor;

		for (vp = tmpl_cursor_init(&rcode, &cursor, request, map->rhs);
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
	}
		break;

	case TMPL_TYPE_DATA:
		rhs = &map->rhs->tmpl_value;

		CHECK_INT_CAST(lhs, rhs);
		CAST(lhs);
		CAST(rhs);

		rcode = cond_cmp_values(request, c, lhs, rhs);
		break;

	/*
	 *	Expanded types start as strings, then get converted
	 *	to the type of the attribute or the explicit cast.
	 */
	case TMPL_TYPE_UNPARSED:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
	{
		ssize_t ret;
		fr_value_box_t data;

		memset(&data, 0, sizeof(data));

		if (map->rhs->type != TMPL_TYPE_UNPARSED) {
			char *p;

			ret = tmpl_aexpand(request, &p, request, map->rhs, escape, NULL);
			if (ret < 0) {
				EVAL_DEBUG("FAIL [%i]", __LINE__);
				rcode = -1;
				goto finish;
			}
			data.vb_strvalue = p;
			data.datum.length = ret;

		} else {
			data.vb_strvalue = map->rhs->name;
			data.datum.length = map->rhs->len;
		}
		data.type = FR_TYPE_STRING;

		rad_assert(data.vb_strvalue);

		rhs = &data;

		CHECK_INT_CAST(lhs, rhs);
		CAST(lhs);
		CAST(rhs);

		rcode = cond_cmp_values(request, c, lhs, rhs);
		if (map->rhs->type != TMPL_TYPE_UNPARSED) talloc_free(data.datum.ptr);

		break;
	}

	/*
	 *	RHS is a compiled regex, we don't need to do anything with it.
	 */
	case TMPL_TYPE_REGEX_STRUCT:
		CAST(lhs);
		rcode = cond_cmp_values(request, c, lhs, NULL);
		break;
	/*
	 *	Unsupported types (should have been parse errors)
	 */
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_UNKNOWN:
	case TMPL_TYPE_ATTR_UNDEFINED:
	case TMPL_TYPE_REGEX:	/* Should now be a TMPL_TYPE_REGEX_STRUCT or TMPL_TYPE_XLAT_STRUCT */
		rad_assert(0);
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
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval_map(REQUEST *request, UNUSED int modreturn, UNUSED int depth, fr_cond_t const *c)
{
	int rcode = 0;

	vp_map_t const *map = c->data.map;

	EVAL_DEBUG(">>> MAP TYPES LHS: %s, RHS: %s",
		   fr_int2str(tmpl_names, map->lhs->type, "???"),
		   fr_int2str(tmpl_names, map->rhs->type, "???"));

	MAP_VERIFY(map);

	switch (map->lhs->type) {
	/*
	 *	LHS is an attribute or list
	 */
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR:
	{
		VALUE_PAIR *vp;
		fr_cursor_t cursor;
		/*
		 *	Legacy paircmp call, skip processing the magic attribute
		 *	if it's the LHS and cast RHS to the same type.
		 */
		if ((c->pass2_fixup == PASS2_PAIRCOMPARE) && (map->op != T_OP_REG_EQ)) {
#ifndef NDEBUG
			rad_assert(paircmp_find(map->lhs->tmpl_da)); /* expensive assert */
#endif
			rcode = cond_normalise_and_cmp(request, c, NULL);
			break;
		}
		for (vp = tmpl_cursor_init(&rcode, &cursor, request, map->lhs);
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
	}
		break;

	case TMPL_TYPE_DATA:
		rcode = cond_normalise_and_cmp(request, c, &map->lhs->tmpl_value);
		break;

	case TMPL_TYPE_UNPARSED:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
	{
		char *p = NULL;
		ssize_t ret;
		fr_value_box_t data;

		if (map->lhs->type != TMPL_TYPE_UNPARSED) {
			ret = tmpl_aexpand(request, &p, request, map->lhs, NULL, NULL);
			if (ret < 0) {
				EVAL_DEBUG("FAIL [%i]", __LINE__);
				return ret;
			}
			data.vb_strvalue = p;
			data.datum.length = (size_t)ret;
		} else {
			data.vb_strvalue = map->lhs->name;
			data.datum.length = map->lhs->len;
		}
		rad_assert(data.vb_strvalue);
		data.type = FR_TYPE_STRING;

		rcode = cond_normalise_and_cmp(request, c, &data);
		if (p) talloc_free(p);
	}
		break;

	/*
	 *	Unsupported types (should have been parse errors)
	 */
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_ATTR_UNDEFINED:
	case TMPL_TYPE_UNKNOWN:
	case TMPL_TYPE_REGEX:		/* should now be a TMPL_TYPE_REGEX_STRUCT or TMPL_TYPE_XLAT_STRUCT */
	case TMPL_TYPE_REGEX_STRUCT:	/* not allowed as LHS */
		rad_assert(0);
		rcode = -1;
		break;
	}

	EVAL_DEBUG("<<<");

	return rcode;
}

/** Evaluate a fr_cond_t;
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return
 *	- -1 on failure.
 *	- -2 on attribute not found.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
int cond_eval(REQUEST *request, int modreturn, int depth, fr_cond_t const *c)
{
	int rcode = -1;
#ifdef WITH_EVAL_DEBUG
	char buffer[1024];

	cond_snprint(buffer, sizeof(buffer), c);
	EVAL_DEBUG("%s", buffer);
#endif

	while (c) {
		switch (c->type) {
		case COND_TYPE_EXISTS:
			rcode = cond_eval_tmpl(request, modreturn, depth, c->data.vpt);
			/* Existence checks are special, because we expect them to fail */
			if (rcode < 0) rcode = 0;
			break;

		case COND_TYPE_MAP:
			rcode = cond_eval_map(request, modreturn, depth, c);
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
#endif
