/*
 * evaluate.c	Evaluate complex conditions
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2007  The FreeRADIUS server project
 * Copyright 2007  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>

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
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
int radius_evaluate_tmpl(REQUEST *request, int modreturn, UNUSED int depth, vp_tmpl_t const *vpt)
{
	int rcode;
	int modcode;
	value_data_t data;

	switch (vpt->type) {
	case TMPL_TYPE_LITERAL:
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
		data.strvalue = p;
		rcode = (data.strvalue && (*data.strvalue != '\0'));
		talloc_free(data.ptr);
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
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
static int cond_do_regex(REQUEST *request, fr_cond_t const *c,
		         PW_TYPE lhs_type, value_data_t const *lhs, size_t lhs_len,
		         PW_TYPE rhs_type, value_data_t const *rhs, size_t rhs_len)
{
	vp_map_t const *map = c->data.map;

	ssize_t		slen;
	int		ret;

	regex_t		*preg, *rreg = NULL;
	regmatch_t	rxmatch[REQUEST_MAX_REGEX + 1];	/* +1 for %{0} (whole match) capture group */
	size_t		nmatch = sizeof(rxmatch) / sizeof(regmatch_t);

	if (!lhs || (lhs_type != PW_TYPE_STRING)) return -1;

	EVAL_DEBUG("CMP WITH REGEX %s %s",
		   map->rhs->tmpl_iflag ? "CASE INSENSITIVE" : "CASE SENSITIVE",
		   map->rhs->tmpl_mflag ? "MULTILINE" : "SINGLELINE");

	switch (map->rhs->type) {
	case TMPL_TYPE_REGEX_STRUCT: /* pre-compiled to a regex */
		preg = map->rhs->tmpl_preg;
		break;

	default:
		rad_assert(rhs_type == PW_TYPE_STRING);
		rad_assert(rhs->strvalue);
		slen = regex_compile(request, &rreg, rhs->strvalue, rhs_len,
				     map->rhs->tmpl_iflag, map->rhs->tmpl_mflag, true, true);
		if (slen <= 0) {
			REMARKER(rhs->strvalue, -slen, fr_strerror());
			EVAL_DEBUG("FAIL %d", __LINE__);

			return -1;
		}
		preg = rreg;
		break;
	}

	ret = regex_exec(preg, lhs->strvalue, lhs_len, rxmatch, &nmatch);
	switch (ret) {
	case 0:
		EVAL_DEBUG("CLEARING SUBCAPTURES");
		regex_sub_to_request(request, NULL, NULL, 0, NULL, 0);	/* clear out old entries */
		break;

	case 1:
		EVAL_DEBUG("SETTING SUBCAPTURES");
		regex_sub_to_request(request, &preg, lhs->strvalue, lhs_len, rxmatch, nmatch);
		break;

	case -1:
		EVAL_DEBUG("REGEX ERROR");
		REDEBUG("regex failed: %s", fr_strerror());
		break;

	default:
		break;
	}

	if (preg) talloc_free(rreg);

	return ret;
}
#endif

#ifdef WITH_EVAL_DEBUG
static void cond_print_operands(REQUEST *request,
			   	PW_TYPE lhs_type, value_data_t const *lhs, size_t lhs_len,
			   	PW_TYPE rhs_type, value_data_t const *rhs, size_t rhs_len)
{
	if (lhs) {
		if (lhs_type == PW_TYPE_STRING) {
			EVAL_DEBUG("LHS: \"%s\" (%zu)" , lhs->strvalue, lhs_len);
		} else {
			char *lhs_hex;

			lhs_hex = talloc_array(request, char, (lhs_len * 2) + 1);

			if (lhs_type == PW_TYPE_OCTETS) {
				fr_bin2hex(lhs_hex, lhs->octets, lhs_len);
			} else {
				fr_bin2hex(lhs_hex, (uint8_t const *)lhs, lhs_len);
			}

			EVAL_DEBUG("LHS: 0x%s (%zu)", lhs_hex, lhs_len);

			talloc_free(lhs_hex);
		}
	} else {
		EVAL_DEBUG("LHS: VIRTUAL");
	}

	if (rhs) {
		if (rhs_type == PW_TYPE_STRING) {
			EVAL_DEBUG("RHS: \"%s\" (%zu)" , rhs->strvalue, rhs_len);
		} else {
			char *rhs_hex;

			rhs_hex = talloc_array(request, char, (rhs_len * 2) + 1);

			if (rhs_type == PW_TYPE_OCTETS) {
				fr_bin2hex(rhs_hex, rhs->octets, rhs_len);
			} else {
				fr_bin2hex(rhs_hex, (uint8_t const *)rhs, rhs_len);
			}

			EVAL_DEBUG("RHS: 0x%s (%zu)", rhs_hex, rhs_len);

			talloc_free(rhs_hex);
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
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
static int cond_cmp_values(REQUEST *request, fr_cond_t const *c,
			   PW_TYPE lhs_type, value_data_t const *lhs, size_t lhs_len,
			   PW_TYPE rhs_type, value_data_t const *rhs, size_t rhs_len)
{
	vp_map_t const *map = c->data.map;
	int rcode;

#ifdef WITH_EVAL_DEBUG
		EVAL_DEBUG("CMP OPERANDS");
		cond_print_operands(request, lhs_type, lhs, lhs_len, rhs_type, rhs, rhs_len);
#endif

#ifdef HAVE_REGEX
	/*
	 *	Regex comparison
	 */
	if (map->op == T_OP_REG_EQ) {
		rcode = cond_do_regex(request, c, lhs_type, lhs, lhs_len, rhs_type, rhs, rhs_len);
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

		vp = fr_pair_afrom_da(request, map->lhs->tmpl_da);
		vp->op = c->data.map->op;

		value_data_copy(vp, &vp->data, rhs_type, rhs, rhs_len);
		vp->vp_length = rhs_len;

		rcode = paircompare(request, request->packet->vps, vp, NULL);
		rcode = (rcode == 0) ? 1 : 0;
		talloc_free(vp);
		goto finish;
	}

	/*
	 *	At this point both operands should have been normalised
	 *	to the same type, and there's no special comparisons
	 *	left.
	 */
	rad_assert(lhs_type == rhs_type);

	EVAL_DEBUG("CMP WITH VALUE DATA");
	rcode = value_data_cmp_op(map->op, lhs_type, lhs, lhs_len, rhs_type, rhs, rhs_len);
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

	while (*in && (outlen > 2)) {
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
			*(p++) = '\\';
			outlen--;
			/* FALL-THROUGH */

		default:
			*(p++) = *(in++);
			outlen--;
			break;
		}
	}

	*(p++) = '\0';
	return p - out;
}


/** Convert both operands to the same type
 *
 * If casting is successful, we call cond_cmp_values to do the comparison
 *
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
static int cond_normalise_and_cmp(REQUEST *request, fr_cond_t const *c,
				  PW_TYPE lhs_type, DICT_ATTR const *lhs_enumv,
				  value_data_t const *lhs, size_t lhs_len)
{
	vp_map_t const *map = c->data.map;

	DICT_ATTR const *cast = NULL;
	PW_TYPE cast_type = PW_TYPE_INVALID;

	int rcode;

	PW_TYPE rhs_type = PW_TYPE_INVALID;
	DICT_ATTR const *rhs_enumv = NULL;
	value_data_t const *rhs = NULL;
	size_t rhs_len;

	value_data_t lhs_cast, rhs_cast;
	void *lhs_cast_buff = NULL, *rhs_cast_buff = NULL;

	xlat_escape_t escape = NULL;

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
	if ((cast_type != PW_TYPE_INVALID) && (_s ## _type != PW_TYPE_INVALID) && (cast_type != _s ## _type)) {\
		ssize_t r;\
		EVAL_DEBUG("CASTING " #_s " FROM %s TO %s",\
			   fr_int2str(dict_attr_types, _s ## _type, "<INVALID>"),\
			   fr_int2str(dict_attr_types, cast_type, "<INVALID>"));\
		r = value_data_cast(request, &_s ## _cast, cast_type, cast, _s ## _type, _s ## _enumv, _s, _s ## _len);\
		if (r < 0) {\
			REDEBUG("Failed casting " #_s " operand: %s", fr_strerror());\
			rcode = -1;\
			goto finish;\
		}\
		if (cast && cast->flags.is_pointer) _s ## _cast_buff = _s ## _cast.ptr;\
		_s ## _type = cast_type;\
		_s ## _len = (size_t)r;\
		_s = &_s ## _cast;\
	}\
} while (0)

#define CHECK_INT_CAST(_l, _r) \
do {\
	if ((cast_type == PW_TYPE_INVALID) &&\
	    _l && (_l ## _type == PW_TYPE_STRING) &&\
	    _r && (_r ## _type == PW_TYPE_STRING) &&\
	    all_digits(lhs->strvalue) && all_digits(rhs->strvalue)) {\
	    	cast_type = PW_TYPE_INTEGER64;\
	    	EVAL_DEBUG("OPERANDS ARE NUMBER STRINGS, SETTING CAST TO integer64");\
	}\
} while (0)

	/*
	 *	Regular expressions need both operands to be strings
	 */
#ifdef HAVE_REGEX
	if (map->op == T_OP_REG_EQ) {
		cast_type = PW_TYPE_STRING;

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
#ifndef NDEBUG
		/* expensive assert */
		rad_assert((map->rhs->type != TMPL_TYPE_ATTR) || !radius_find_compare(map->rhs->tmpl_da));
#endif
		cast = map->lhs->tmpl_da;
		cast_type = cast->type;

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
		cast_type = map->lhs->tmpl_data_type;
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM LHS DATA)",
			   fr_int2str(dict_attr_types, cast_type, "<INVALID>"));
	} else if (map->rhs->type == TMPL_TYPE_DATA) {
		cast_type = map->rhs->tmpl_data_type;
		EVAL_DEBUG("NORMALISATION TYPE %s (IMPLICIT FROM RHS DATA)",
			   fr_int2str(dict_attr_types, cast_type, "<INVALID>"));
	}

	if (cast) cast_type = cast->type;

	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	{
		VALUE_PAIR *vp;
		vp_cursor_t cursor;

		for (vp = tmpl_cursor_init(&rcode, &cursor, request, map->rhs);
		     vp;
	     	     vp = tmpl_cursor_next(&cursor, map->rhs)) {
			rhs_type = vp->da->type;
			rhs_enumv = vp->da;
			rhs = &vp->data;
			rhs_len = vp->vp_length;

			CHECK_INT_CAST(lhs, rhs);
			CAST(lhs);
			CAST(rhs);

			rcode = cond_cmp_values(request, c, lhs_type, lhs, lhs_len, rhs_type, rhs, rhs_len);
			if (rcode != 0) break;

			TALLOC_FREE(rhs_cast_buff);
		}
	}
		break;

	case TMPL_TYPE_DATA:
		rhs_type = map->rhs->tmpl_data_type;
		rhs = &map->rhs->tmpl_data_value;
		rhs_len = map->rhs->tmpl_data_length;

		CHECK_INT_CAST(lhs, rhs);
		CAST(lhs);
		CAST(rhs);

		rcode = cond_cmp_values(request, c, lhs_type, lhs, lhs_len, rhs_type, rhs, rhs_len);
		break;

	/*
	 *	Expanded types start as strings, then get converted
	 *	to the type of the attribute or the explicit cast.
	 */
	case TMPL_TYPE_LITERAL:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
	{
		ssize_t ret;
		value_data_t data;

		if (map->rhs->type != TMPL_TYPE_LITERAL) {
			char *p;

			ret = tmpl_aexpand(request, &p, request, map->rhs, escape, NULL);
			if (ret < 0) {
				EVAL_DEBUG("FAIL [%i]", __LINE__);
				rcode = -1;
				goto finish;
			}
			data.strvalue = p;
			rhs_len = ret;

		} else {
			data.strvalue = map->rhs->name;
			rhs_len = map->rhs->len;
		}
		rad_assert(data.strvalue);

		rhs_type = PW_TYPE_STRING;
		rhs = &data;

		CHECK_INT_CAST(lhs, rhs);
		CAST(lhs);
		CAST(rhs);

		rcode = cond_cmp_values(request, c, lhs_type, lhs, lhs_len, rhs_type, rhs, rhs_len);
		if (map->rhs->type != TMPL_TYPE_LITERAL)talloc_free(data.ptr);

		break;
	}

	/*
	 *	RHS is a compiled regex, we don't need to do anything with it.
	 */
	case TMPL_TYPE_REGEX_STRUCT:
		CAST(lhs);
		rcode = cond_cmp_values(request, c, lhs_type, lhs, lhs_len, PW_TYPE_INVALID, NULL, 0);
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
	talloc_free(lhs_cast_buff);
	talloc_free(rhs_cast_buff);

	return rcode;
}


/** Evaluate a map
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
int radius_evaluate_map(REQUEST *request, UNUSED int modreturn, UNUSED int depth, fr_cond_t const *c)
{
	int rcode = 0;

	vp_map_t const *map = c->data.map;

	EVAL_DEBUG(">>> MAP TYPES LHS: %s, RHS: %s",
		   fr_int2str(tmpl_names, map->lhs->type, "???"),
		   fr_int2str(tmpl_names, map->rhs->type, "???"));

	switch (map->lhs->type) {
	/*
	 *	LHS is an attribute or list
	 */
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR:
	{
		VALUE_PAIR *vp;
		vp_cursor_t cursor;
		/*
		 *	Legacy paircompare call, skip processing the magic attribute
		 *	if it's the LHS and cast RHS to the same type.
		 */
		if ((c->pass2_fixup == PASS2_PAIRCOMPARE) && (map->op != T_OP_REG_EQ)) {
#ifndef NDEBUG
			rad_assert(radius_find_compare(map->lhs->tmpl_da)); /* expensive assert */
#endif
			rcode = cond_normalise_and_cmp(request, c, PW_TYPE_INVALID, NULL, NULL, 0);
			break;
		}
		for (vp = tmpl_cursor_init(&rcode, &cursor, request, map->lhs);
		     vp;
	     	     vp = tmpl_cursor_next(&cursor, map->lhs)) {
			/*
			 *	Evaluate all LHS values, condition evaluates to true
			 *	if we get at least one set of operands that
			 *	evaluates to true.
			 */
	     		rcode = cond_normalise_and_cmp(request, c, vp->da->type, vp->da, &vp->data, vp->vp_length);
	     		if (rcode != 0) break;
		}
	}
		break;

	case TMPL_TYPE_DATA:
		rcode = cond_normalise_and_cmp(request, c,
					      map->lhs->tmpl_data_type, NULL, &map->lhs->tmpl_data_value,
					      map->lhs->tmpl_data_length);
		break;

	case TMPL_TYPE_LITERAL:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_XLAT_STRUCT:
	{
		ssize_t ret;
		value_data_t data;

		if (map->lhs->type != TMPL_TYPE_LITERAL) {
			char *p;

			ret = tmpl_aexpand(request, &p, request, map->lhs, NULL, NULL);
			if (ret < 0) {
				EVAL_DEBUG("FAIL [%i]", __LINE__);
				return ret;
			}
			data.strvalue = p;
		} else {
			data.strvalue = map->lhs->name;
			ret = map->lhs->len;
		}
		rad_assert(data.strvalue);

		rcode = cond_normalise_and_cmp(request, c, PW_TYPE_STRING, NULL, &data, ret);
		if (map->lhs->type != TMPL_TYPE_LITERAL) talloc_free(data.ptr);
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
 * @return -1 on failure, -2 on attribute not found, 0 for "no match", 1 for "match".
 */
int radius_evaluate_cond(REQUEST *request, int modreturn, int depth, fr_cond_t const *c)
{
	int rcode = -1;
#ifdef WITH_EVAL_DEBUG
	char buffer[1024];

	fr_cond_sprint(buffer, sizeof(buffer), c);
	EVAL_DEBUG("%s", buffer);
#endif

	while (c) {
		switch (c->type) {
		case COND_TYPE_EXISTS:
			rcode = radius_evaluate_tmpl(request, modreturn, depth, c->data.vpt);
			/* Existence checks are special, because we expect them to fail */
			if (rcode < 0) rcode = 0;
			break;

		case COND_TYPE_MAP:
			rcode = radius_evaluate_map(request, modreturn, depth, c);
			break;

		case COND_TYPE_CHILD:
			rcode = radius_evaluate_cond(request, modreturn, depth + 1, c->data.child);
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


/*
 *	The fr_pair_list_move() function in src/lib/valuepair.c does all sorts of
 *	extra magic that we don't want here.
 *
 *	FIXME: integrate this with the code calling it, so that we
 *	only fr_pair_list_copy() those attributes that we're really going to
 *	use.
 */
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from, bool do_xlat)
{
	int i, j, count, from_count, to_count, tailto;
	vp_cursor_t cursor;
	VALUE_PAIR *vp, *next, **last;
	VALUE_PAIR **from_list, **to_list;
	VALUE_PAIR *append, **append_tail;
	VALUE_PAIR *to_copy;
	bool *edited = NULL;
	REQUEST *fixup = NULL;
	TALLOC_CTX *ctx;

	/*
	 *	Set up arrays for editing, to remove some of the
	 *	O(N^2) dependencies.  This also makes it easier to
	 *	insert and remove attributes.
	 *
	 *	It also means that the operators apply ONLY to the
	 *	attributes in the original list.  With the previous
	 *	implementation of fr_pair_list_move(), adding two attributes
	 *	via "+=" and then "=" would mean that the second one
	 *	wasn't added, because of the existence of the first
	 *	one in the "to" list.  This implementation doesn't
	 *	have that bug.
	 *
	 *	Also, the previous implementation did NOT implement
	 *	"-=" correctly.  If two of the same attributes existed
	 *	in the "to" list, and you tried to subtract something
	 *	matching the *second* value, then the fr_pair_delete_by_num()
	 *	function was called, and the *all* attributes of that
	 *	number were deleted.  With this implementation, only
	 *	the matching attributes are deleted.
	 */
	count = 0;
	for (vp = fr_cursor_init(&cursor, &from); vp; vp = fr_cursor_next(&cursor)) count++;
	from_list = talloc_array(request, VALUE_PAIR *, count);

	for (vp = fr_cursor_init(&cursor, to); vp; vp = fr_cursor_next(&cursor)) count++;
	to_list = talloc_array(request, VALUE_PAIR *, count);

	append = NULL;
	append_tail = &append;

	/*
	 *	Move the lists to the arrays, and break the list
	 *	chains.
	 */
	from_count = 0;
	for (vp = from; vp != NULL; vp = next) {
		next = vp->next;
		from_list[from_count++] = vp;
		vp->next = NULL;
	}

	to_count = 0;
	ctx = talloc_parent(*to);
	to_copy = fr_pair_list_copy(ctx, *to);
	for (vp = to_copy; vp != NULL; vp = next) {
		next = vp->next;
		to_list[to_count++] = vp;
		vp->next = NULL;
	}
	tailto = to_count;
	edited = talloc_zero_array(request, bool, to_count);

	RDEBUG4("::: FROM %d TO %d MAX %d", from_count, to_count, count);

	/*
	 *	Now that we have the lists initialized, start working
	 *	over them.
	 */
	for (i = 0; i < from_count; i++) {
		int found;

		RDEBUG4("::: Examining %s", from_list[i]->da->name);

		if (do_xlat) radius_xlat_do(request, from_list[i]);

		/*
		 *	Attribute should be appended, OR the "to" list
		 *	is empty, and we're supposed to replace or
		 *	"add if not existing".
		 */
		if (from_list[i]->op == T_OP_ADD) goto do_append;

		found = false;
		for (j = 0; j < to_count; j++) {
			if (edited[j] || !to_list[j] || !from_list[i]) continue;

			/*
			 *	Attributes aren't the same, skip them.
			 */
			if (from_list[i]->da != to_list[j]->da) {
				continue;
			}

			/*
			 *	We don't use a "switch" statement here
			 *	because we want to break out of the
			 *	"for" loop over 'j' in most cases.
			 */

			/*
			 *	Over-write the FIRST instance of the
			 *	matching attribute name.  We free the
			 *	one in the "to" list, and move over
			 *	the one in the "from" list.
			 */
			if (from_list[i]->op == T_OP_SET) {
				RDEBUG4("::: OVERWRITING %s FROM %d TO %d",
				       to_list[j]->da->name, i, j);
				fr_pair_list_free(&to_list[j]);
				to_list[j] = from_list[i];
				from_list[i] = NULL;
				edited[j] = true;
				break;
			}

			/*
			 *	Add the attribute only if it does not
			 *	exist... but it exists, so we stop
			 *	looking.
			 */
			if (from_list[i]->op == T_OP_EQ) {
				found = true;
				break;
			}

			/*
			 *	Delete every attribute, independent
			 *	of its value.
			 */
			if (from_list[i]->op == T_OP_CMP_FALSE) {
				goto delete;
			}

			/*
			 *	Delete all matching attributes from
			 *	"to"
			 */
			if ((from_list[i]->op == T_OP_SUB) ||
			    (from_list[i]->op == T_OP_CMP_EQ) ||
			    (from_list[i]->op == T_OP_LE) ||
			    (from_list[i]->op == T_OP_GE)) {
				int rcode;
				int old_op = from_list[i]->op;

				/*
				 *	Check for equality.
				 */
				from_list[i]->op = T_OP_CMP_EQ;

				/*
				 *	If equal, delete the one in
				 *	the "to" list.
				 */
				rcode = radius_compare_vps(NULL, from_list[i],
							   to_list[j]);
				/*
				 *	We may want to do more
				 *	subtractions, so we re-set the
				 *	operator back to it's original
				 *	value.
				 */
				from_list[i]->op = old_op;

				switch (old_op) {
				case T_OP_CMP_EQ:
					if (rcode != 0) goto delete;
					break;

				case T_OP_SUB:
					if (rcode == 0) {
					delete:
						RDEBUG4("::: DELETING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						fr_pair_list_free(&to_list[j]);
						to_list[j] = NULL;
					}
					break;

					/*
					 *	Enforce <=.  If it's
					 *	>, replace it.
					 */
				case T_OP_LE:
					if (rcode > 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						fr_pair_list_free(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = true;
					}
					break;

				case T_OP_GE:
					if (rcode < 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						fr_pair_list_free(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = true;
					}
					break;
				}

				continue;
			}

			rad_assert(0 == 1); /* panic! */
		}

		/*
		 *	We were asked to add it if it didn't exist,
		 *	and it doesn't exist.  Move it over to the
		 *	tail of the "to" list, UNLESS it was already
		 *	moved by another operator.
		 */
		if (!found && from_list[i]) {
			if ((from_list[i]->op == T_OP_EQ) ||
			    (from_list[i]->op == T_OP_LE) ||
			    (from_list[i]->op == T_OP_GE) ||
			    (from_list[i]->op == T_OP_SET)) {
			do_append:
				RDEBUG4("::: APPENDING %s FROM %d TO %d",
				       from_list[i]->da->name, i, tailto);
				*append_tail = from_list[i];
				from_list[i]->op = T_OP_EQ;
				from_list[i] = NULL;
				append_tail = &(*append_tail)->next;
			}
		}
	}

	/*
	 *	Delete attributes in the "from" list.
	 */
	for (i = 0; i < from_count; i++) {
		if (!from_list[i]) continue;

		fr_pair_list_free(&from_list[i]);
	}
	talloc_free(from_list);

	RDEBUG4("::: TO in %d out %d", to_count, tailto);

	/*
	 *	Re-chain the "to" list.
	 */
	fr_pair_list_free(to);
	last = to;

	if (to == &request->packet->vps) {
		fixup = request;
	} else if (request->parent && (to == &request->parent->packet->vps)) {
		fixup = request->parent;
	}

	for (i = 0; i < tailto; i++) {
		if (!to_list[i]) continue;

		vp = to_list[i];
		RDEBUG4("::: to[%d] = %s", i, vp->da->name);

		/*
		 *	Mash the operator to a simple '='.  The
		 *	operators in the "to" list aren't used for
		 *	anything.  BUT they're used in the "detail"
		 *	file and debug output, where we don't want to
		 *	see the operators.
		 */
		vp->op = T_OP_EQ;

		*last = vp;
		last = &(*last)->next;
	}

	/*
	 *	And finally add in the attributes we're appending to
	 *	the tail of the "to" list.
	 */
	*last = append;

	/*
	 *	Fix dumb cache issues
	 */
	if (fixup) {
		fixup->username = NULL;
		fixup->password = NULL;

		for (vp = fixup->packet->vps; vp != NULL; vp = vp->next) {
			if (vp->da->vendor) continue;

			if ((vp->da->attr == PW_USER_NAME) && !fixup->username) {
				fixup->username = vp;

			} else if (vp->da->attr == PW_STRIPPED_USER_NAME) {
				fixup->username = vp;

			} else if (vp->da->attr == PW_USER_PASSWORD) {
				fixup->password = vp;
			}
		}
	}

	rad_assert(request->packet != NULL);

	talloc_free(to_list);
	talloc_free(edited);
}
