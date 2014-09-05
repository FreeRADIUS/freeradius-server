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
#define EVAL_DEBUG(fmt, ...) printf("EVAL: ");printf(fmt, ## __VA_ARGS__);printf("\n");fflush(stdout)

static FR_NAME_NUMBER const template_names[] = {
	{ "literal",	TMPL_TYPE_LITERAL },
	{ "xlat",	TMPL_TYPE_XLAT },
	{ "attr",	TMPL_TYPE_ATTR },
	{ "list",	TMPL_TYPE_LIST },
	{ "regex",	TMPL_TYPE_REGEX },
	{ "exec",	TMPL_TYPE_EXEC },
	{ "data",	TMPL_TYPE_DATA },
	{ "xlat",	TMPL_TYPE_XLAT_STRUCT },
	{ "regex",	TMPL_TYPE_REGEX_STRUCT },

	{ NULL, 0 }
};
#else
#define EVAL_DEBUG(...)
#endif

FR_NAME_NUMBER const modreturn_table[] = {
	{ "reject",     RLM_MODULE_REJECT       },
	{ "fail",       RLM_MODULE_FAIL	 	},
	{ "ok",		RLM_MODULE_OK	   	},
	{ "handled",    RLM_MODULE_HANDLED      },
	{ "invalid",    RLM_MODULE_INVALID      },
	{ "userlock",   RLM_MODULE_USERLOCK     },
	{ "notfound",   RLM_MODULE_NOTFOUND     },
	{ "noop",       RLM_MODULE_NOOP	 	},
	{ "updated",    RLM_MODULE_UPDATED      },
	{ NULL, 0 }
};


static int all_digits(char const *string)
{
	char const *p = string;

	rad_assert(p != NULL);

	if (*p == '-') p++;

	while (isdigit((int) *p)) p++;

	return (*p == '\0');
}

/** Expand the RHS of a template
 *
 * @note Length of expanded string can be found with talloc_array_length(*out) - 1
 *
 * @param out where to write a pointer to the newly allocated buffer.
 * @param request Current request.
 * @param vpt to evaluate.
 * @return -1 on error, else 0.
 */
int radius_expand_tmpl(char **out, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	VALUE_PAIR *vp;
	int ret;
	*out = NULL;

	rad_assert(vpt->type != TMPL_TYPE_LIST);

	switch (vpt->type) {
	case TMPL_TYPE_LITERAL:
		EVAL_DEBUG("TMPL LITERAL");
		*out = talloc_typed_strdup(request, vpt->name);
		break;

	case TMPL_TYPE_EXEC:
		EVAL_DEBUG("TMPL EXEC");
		*out = talloc_array(request, char, 1024);
		if (radius_exec_program(request, vpt->name, true, false, *out, 1024, EXEC_TIMEOUT, NULL, NULL) != 0) {
			TALLOC_FREE(*out);
			return -1;
		}
		break;

	case TMPL_TYPE_REGEX:
		EVAL_DEBUG("TMPL REGEX");
		/* Error in expansion, this is distinct from zero length expansion */
		if (radius_axlat(out, request, vpt->name, NULL, NULL) < 0) {
			rad_assert(!*out);
			return -1;
		}
		break;

	case TMPL_TYPE_XLAT:
		EVAL_DEBUG("TMPL XLAT");
		/* Error in expansion, this is distinct from zero length expansion */
		if (radius_axlat(out, request, vpt->name, NULL, NULL) < 0) {
			rad_assert(!*out);
			return -1;
		}
		break;

	case TMPL_TYPE_XLAT_STRUCT:
		EVAL_DEBUG("TMPL XLAT_STRUCT");
		/* Error in expansion, this is distinct from zero length expansion */
		if (radius_axlat_struct(out, request, vpt->tmpl_xlat, NULL, NULL) < 0) {
			rad_assert(!*out);
			return -1;
		}
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */
		RDEBUG2("   --> %s", *out);
		break;

	case TMPL_TYPE_ATTR:
		EVAL_DEBUG("TMPL ATTR");
		ret = radius_tmpl_get_vp(&vp, request, vpt);
		if (ret < 0) return ret;

		*out = vp_aprint_value(request, vp, false);
		if (!*out) return -1;
		break;

	case TMPL_TYPE_DATA:
	case TMPL_TYPE_REGEX_STRUCT:
		rad_assert(0 == 1);
		/* FALL-THROUGH */

	default:
		break;
	}

	EVAL_DEBUG("Expand tmpl --> %s", *out);
	return 0;
}

/** Evaluate a template
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] vpt the template to evaluate
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
int radius_evaluate_tmpl(REQUEST *request, int modreturn, UNUSED int depth,
			 value_pair_tmpl_t const *vpt)
{
	int rcode;
	int modcode;
	char *buffer;

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
		rcode = (vpt->name != '\0');
		break;

	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		if (radius_tmpl_get_vp(NULL, request, vpt) < 0) {
			rcode = false;
		} else {
			rcode = true;
		}
		break;

	case TMPL_TYPE_XLAT_STRUCT:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
		if (!*vpt->name) return false;
		rcode = radius_expand_tmpl(&buffer, request, vpt);
		if (rcode < 0) {
			EVAL_DEBUG("FAIL %d", __LINE__);
			return -1;
		}
		rcode = (buffer && (*buffer != '\0'));
		talloc_free(buffer);
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
static int do_regex(REQUEST *request, value_pair_map_t const *map)
{
	int compare, rcode, ret;
	regex_t reg, *preg = NULL;
	char *lhs = NULL, *rhs = NULL;
	regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

	/*
	 *  Expand and then compile it.
	 */
	switch (map->src->type) {
	case TMPL_TYPE_REGEX:
		rcode = radius_expand_tmpl(&rhs, request, map->src);
		if (rcode < 0) {
			EVAL_DEBUG("FAIL %d", __LINE__);
			return -1;
		}
		rad_assert(rhs != NULL);

		compare = regcomp(&reg, rhs, REG_EXTENDED | (map->src->tmpl_iflag ? REG_ICASE : 0));
		if (compare != 0) {
			if (debug_flag) {
				char errbuf[128];

				regerror(compare, &reg, errbuf, sizeof(errbuf));
				ERROR("Failed compiling regular expression: %s", errbuf);
			}
			EVAL_DEBUG("FAIL %d", __LINE__);
			ret = -1;
			goto finish;
		}
		preg = &reg;
		break;

	case TMPL_TYPE_REGEX_STRUCT:
		preg = map->src->tmpl_preg;
		break;

	default:
		rad_assert(0);
		ret = -1;
		goto finish;
	}

	rcode = radius_expand_tmpl(&lhs, request, map->dst);
	if (rcode < 0) {
		EVAL_DEBUG("FAIL %d", __LINE__);
		ret = -1;
		goto finish;
	}
	rad_assert(lhs != NULL);

	/*
	 *  regexec doesn't initialise unused elements
	 */
	memset(&rxmatch, 0, sizeof(rxmatch));
	compare = regexec(preg, lhs, REQUEST_MAX_REGEX + 1, rxmatch, 0);
	rad_regcapture(request, compare, lhs, rxmatch);
	ret = (compare == 0);

finish:
	talloc_free(rhs);
	talloc_free(lhs);

	/*
	 *  regcomp allocs extra memory for the expression, so if the
	 *  result wasn't cached we need to free it here.
	 */
	if (preg && (preg == &reg)) regfree(&reg);

	return ret;
}
#endif

/*
 *	Expand a template to a string, parse it as type of "cast", and
 *	create a VP from the data.
 */
static VALUE_PAIR *get_cast_vp(REQUEST *request, value_pair_tmpl_t const *vpt, DICT_ATTR const *cast)
{
	int rcode;
	VALUE_PAIR *vp;
	char *str;

	vp = pairalloc(request, cast);
	if (!vp) return NULL;

	if (vpt->type == TMPL_TYPE_DATA) {
		rad_assert(vp->da->type == vpt->tmpl_da->type);
		pairdatacpy(vp, vpt->tmpl_da, vpt->tmpl_value, vpt->tmpl_length);
		return vp;
	}

	rcode = radius_expand_tmpl(&str, request, vpt);
	if (rcode < 0) {
		pairfree(&vp);
		return NULL;
	}

	if (pairparsevalue(vp, str, 0) < 0) {
		talloc_free(str);
		pairfree(&vp);
		return NULL;
	}

	return vp;
}

/*
 *	Copy data from src to dst, where the attributes are of
 *	different type.
 */
static int do_cast_copy(VALUE_PAIR *dst, VALUE_PAIR const *src)
{
	rad_assert(dst->da->type != src->da->type);

	if (dst->da->type == PW_TYPE_STRING) {
		dst->vp_strvalue = vp_aprint_value(dst, src, false);
		dst->length = strlen(dst->vp_strvalue);
		return 0;
	}

	if (dst->da->type == PW_TYPE_OCTETS) {
		if (src->da->type == PW_TYPE_STRING) {
			pairmemcpy(dst, src->vp_octets, src->length);	/* Copy embedded NULLs */
		} else {
			pairmemcpy(dst, (uint8_t const *) &src->data, src->length);
		}
		return 0;
	}

	if (src->da->type == PW_TYPE_STRING) {
		return pairparsevalue(dst, src->vp_strvalue, 0);
	}

	if ((src->da->type == PW_TYPE_INTEGER64) &&
	    (dst->da->type == PW_TYPE_ETHERNET)) {
		uint8_t array[8];
		uint64_t i;

		i = htonll(src->vp_integer64);
		memcpy(array, &i, 8);

		/*
		 *	For OUIs in the DB.
		 */
		if ((array[0] != 0) || (array[1] != 0)) return -1;

		memcpy(&dst->vp_ether, &array[2], 6);
		dst->length = 6;
		return 0;
	}

	/*
	 *	For integers, we allow the casting of a SMALL type to
	 *	a larger type, but not vice-versa.
	 */
	if (dst->da->type == PW_TYPE_INTEGER64) {
		switch (src->da->type) {
		case PW_TYPE_BYTE:
			dst->vp_integer64 = src->vp_byte;
			break;

		case PW_TYPE_SHORT:
			dst->vp_integer64 = src->vp_short;
			break;

		case PW_TYPE_INTEGER:
			dst->vp_integer64 = src->vp_integer;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
			EVAL_DEBUG("Invalid cast to integer64");
			return -1;

		}
		return 0;
	}

	/*
	 *	We can compare LONG integers to SHORTER ones, so long
	 *	as the long one is on the LHS.
	 */
	if (dst->da->type == PW_TYPE_INTEGER) {
		switch (src->da->type) {
		case PW_TYPE_BYTE:
			dst->vp_integer = src->vp_byte;
			break;

		case PW_TYPE_SHORT:
			dst->vp_integer = src->vp_short;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
			EVAL_DEBUG("Invalid cast to integer");
			return -1;

		}
		return 0;
	}

	if (dst->da->type == PW_TYPE_SHORT) {
		switch (src->da->type) {
		case PW_TYPE_BYTE:
			dst->vp_short = src->vp_byte;
			break;

		case PW_TYPE_OCTETS:
			goto do_octets;

		default:
			EVAL_DEBUG("Invalid cast to short");
			return -1;

		}
		return 0;
	}

	/*
	 *	The attribute we've found has to have a size which is
	 *	compatible with the type of the destination cast.
	 */
	if ((src->length < dict_attr_sizes[dst->da->type][0]) ||
	    (src->length > dict_attr_sizes[dst->da->type][1])) {
		EVAL_DEBUG("Casted attribute is wrong size (%u)", (unsigned int) src->length);
		return -1;
	}

	if (src->da->type == PW_TYPE_OCTETS) {
	do_octets:
		switch (dst->da->type) {
		case PW_TYPE_INTEGER64:
			dst->vp_integer = ntohll(*(uint64_t const *) src->vp_octets);
			break;

		case PW_TYPE_INTEGER:
		case PW_TYPE_DATE:
		case PW_TYPE_SIGNED:
			dst->vp_integer = ntohl(*(uint32_t const *) src->vp_octets);
			break;

		case PW_TYPE_SHORT:
			dst->vp_integer = ntohs(*(uint16_t const *) src->vp_octets);
			break;

		case PW_TYPE_BYTE:
			dst->vp_integer = src->vp_octets[0];
			break;

		default:
			memcpy(&dst->data, src->vp_octets, src->length);
			break;
		}

		dst->length = src->length;
		return 0;
	}

	/*
	 *	Convert host order to network byte order.
	 */
	if ((dst->da->type == PW_TYPE_IPV4_ADDR) &&
	    ((src->da->type == PW_TYPE_INTEGER) ||
	     (src->da->type == PW_TYPE_DATE) ||
	     (src->da->type == PW_TYPE_SIGNED))) {
		dst->vp_ipaddr = htonl(src->vp_integer);

	} else if ((src->da->type == PW_TYPE_IPV4_ADDR) &&
		   ((dst->da->type == PW_TYPE_INTEGER) ||
		    (dst->da->type == PW_TYPE_DATE) ||
		    (dst->da->type == PW_TYPE_SIGNED))) {
		dst->vp_integer = htonl(src->vp_ipaddr);

	} else {		/* they're of the same byte order */
		memcpy(&dst->data, &src->data, src->length);
	}

	dst->length = src->length;

	return 0;
}


/** Evaluate a map
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
int radius_evaluate_map(REQUEST *request, UNUSED int modreturn, UNUSED int depth,
			fr_cond_t const *c)
{
	int rcode;
	char *lhs, *rhs;
	value_pair_map_t *map;

	rad_assert(c->type == COND_TYPE_MAP);
	map = c->data.map;

	rad_assert(map->dst->type != TMPL_TYPE_UNKNOWN);
	rad_assert(map->src->type != TMPL_TYPE_UNKNOWN);
	rad_assert(map->dst->type != TMPL_TYPE_LIST);
	rad_assert(map->src->type != TMPL_TYPE_LIST);
	rad_assert(map->dst->type != TMPL_TYPE_REGEX);
	rad_assert(map->dst->type != TMPL_TYPE_REGEX_STRUCT);

	EVAL_DEBUG("Map %s ? %s",
		   fr_int2str(template_names, map->dst->type, "???"),
		   fr_int2str(template_names, map->src->type, "???"));

	/*
	 *	Verify regexes.
	 */
	if ((map->src->type == TMPL_TYPE_REGEX) ||
	    (map->src->type == TMPL_TYPE_REGEX_STRUCT)) {
		rad_assert(map->op == T_OP_REG_EQ);
	} else {
		rad_assert(!((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)));
	}

	/*
	 *	They're both attributes.  Do attribute-specific work.
	 *
	 *	LHS is DST.  RHS is SRC <sigh>
	 */
	if (!c->cast && (map->src->type == TMPL_TYPE_ATTR) && (map->dst->type == TMPL_TYPE_ATTR)) {
		VALUE_PAIR *lhs_vp, *rhs_vp, *cast_vp;

		EVAL_DEBUG("ATTR to ATTR");
		if ((radius_tmpl_get_vp(&lhs_vp, request, map->dst) < 0) ||
		    (radius_tmpl_get_vp(&rhs_vp, request, map->src) < 0)) return false;

		if (map->dst->tmpl_da->type == map->src->tmpl_da->type) {
			return paircmp_op(lhs_vp, map->op, rhs_vp);
		}

		/*
		 *	Compare a large integer (lhs) to a small integer (rhs).
		 *	We allow this without a cast.
		 */
		rad_assert((map->dst->tmpl_da->type == PW_TYPE_INTEGER64) ||
			   (map->dst->tmpl_da->type == PW_TYPE_INTEGER) ||
			   (map->dst->tmpl_da->type == PW_TYPE_SHORT));
		rad_assert((map->src->tmpl_da->type == PW_TYPE_INTEGER) ||
			   (map->src->tmpl_da->type == PW_TYPE_SHORT) ||
			   (map->src->tmpl_da->type == PW_TYPE_BYTE));

		cast_vp = pairalloc(request, lhs_vp->da);
		if (!cast_vp) return false;

		/*
		 *	Copy the RHS to the casted type.
		 */
		if (do_cast_copy(cast_vp, rhs_vp) < 0) {
			talloc_free(cast_vp);
			return false;
		}

		rcode = paircmp_op(lhs_vp, map->op, cast_vp);
		talloc_free(cast_vp);
		return rcode;
	}

	/*
	 *	LHS is a cast.  Do type-specific comparisons, as if
	 *	the LHS was a real attribute.
	 */
	if (c->cast) {
		VALUE_PAIR *lhs_vp, *rhs_vp;

		/*
		 *	Try to copy data from the VP which is being
		 *	casted, instead of printing it to a string and
		 *	then re-parsing it.
		 */
		if (map->dst->type == TMPL_TYPE_ATTR) {
			VALUE_PAIR *cast_vp;

			if (radius_tmpl_get_vp(&cast_vp, request, map->dst) < 0) return false;

			lhs_vp = pairalloc(request, c->cast);
			if (!lhs_vp) return false;

			/*
			 *	In a separate function for clarity
			 */
			if (do_cast_copy(lhs_vp, cast_vp) < 0) {
				talloc_free(lhs_vp);
				return false;
			}

		} else {
			lhs_vp = get_cast_vp(request, map->dst, c->cast);
		}
		if (!lhs_vp) return false;

		/*
		 *	Get either a real VP, or parse the RHS into a
		 *	VP, and return that.
		 */
		if (map->src->type == TMPL_TYPE_ATTR) {
			if (radius_tmpl_get_vp(&rhs_vp, request, map->src) < 0) return false;
		} else {
			rhs_vp = get_cast_vp(request, map->src, c->cast);
		}

		if (!rhs_vp) return false;

		EVAL_DEBUG("CAST to %s",
			   fr_int2str(dict_attr_types,
				      c->cast->type, "?Unknown?"));

		rcode = paircmp_op(lhs_vp, map->op, rhs_vp);
		pairfree(&lhs_vp);
		if (map->src->type != TMPL_TYPE_ATTR) {
			pairfree(&rhs_vp);
		}
		return rcode;
	}

	/*
	 *	Might be a virtual comparison
	 */
	if ((map->dst->type == TMPL_TYPE_ATTR) &&
	    (map->src->type != TMPL_TYPE_REGEX) &&
	    (map->src->type != TMPL_TYPE_REGEX_STRUCT) &&
	    (c->pass2_fixup == PASS2_PAIRCOMPARE)) {
		int ret;
		VALUE_PAIR *lhs_vp;

		EVAL_DEBUG("virtual ATTR to DATA");

		lhs_vp = get_cast_vp(request, map->src, map->dst->tmpl_da);
		if (!lhs_vp) return false;

		/*
		 *	paircompare requires the operator be set for the
		 *	check attribute.
		 */
		lhs_vp->op = map->op;
		ret = paircompare(request, request->packet->vps, lhs_vp, NULL);
		talloc_free(lhs_vp);
		if (ret == 0) {
			return true;
		}
		return false;
	}
	rad_assert(c->pass2_fixup != PASS2_PAIRCOMPARE);

	/*
	 *	RHS has been pre-parsed into binary data.  Go check
	 *	that.
	 */
	if ((map->dst->type == TMPL_TYPE_ATTR) &&
	    (map->src->type == TMPL_TYPE_DATA)) {
		VALUE_PAIR *lhs_vp, *rhs_vp;

		EVAL_DEBUG("ATTR to DATA");

		if (radius_tmpl_get_vp(&lhs_vp, request, map->dst) < 0) return false;

		rhs_vp = get_cast_vp(request, map->src, map->dst->tmpl_da);
		if (!rhs_vp) return false;

#ifdef WITH_EVAL_DEBUG
		debug_pair(lhs_vp);
		debug_pair(rhs_vp);
#endif

		rcode = paircmp_op(lhs_vp, map->op, rhs_vp);
		pairfree(&rhs_vp);
		return rcode;
	}

	rad_assert(map->src->type != TMPL_TYPE_DATA);
	rad_assert(map->dst->type != TMPL_TYPE_DATA);

#ifdef HAVE_REGEX
	/*
	 *	Parse regular expressions.
	 */
	if ((map->src->type == TMPL_TYPE_REGEX) ||
	    (map->src->type == TMPL_TYPE_REGEX_STRUCT)) {
		return do_regex(request, map);
	}
#endif

	/*
	 *	The RHS now needs to be expanded into a string.
	 */
	rcode = radius_expand_tmpl(&rhs, request, map->src);
	if (rcode < 0) {
		EVAL_DEBUG("FAIL %d", __LINE__);
		return -1;
	}
	rad_assert(rhs != NULL);

	/*
	 *	User-Name == FOO
	 *
	 *	Parse the RHS to be the same DA as the LHS.  do
	 *	comparisons.  So long as it's not a regex, which does
	 *	string comparisons.
	 *
	 *	The LHS may be a virtual attribute, too.
	 */
	if (map->dst->type == TMPL_TYPE_ATTR) {
		VALUE_PAIR *lhs_vp, *rhs_vp;

		EVAL_DEBUG("ATTR to non-REGEX");

		/*
		 *	No LHS means no match
		 */
		if (radius_tmpl_get_vp(&lhs_vp, request, map->dst) < 0) {
			/*
			 *	Not a real attr: might be a dynamic comparison.
			 */
			if ((map->dst->type == TMPL_TYPE_ATTR) &&
			    (map->dst->tmpl_da->vendor == 0) &&
			    radius_find_compare(map->dst->tmpl_da)) {
				rhs_vp = pairalloc(request, map->dst->tmpl_da);
				rad_assert(rhs_vp != NULL);
				if (pairparsevalue(rhs_vp, rhs, 0) < 0) {
					talloc_free(rhs);
					EVAL_DEBUG("FAIL %d", __LINE__);
					return -1;
				}
				talloc_free(rhs);

				rcode = (radius_callback_compare(request, NULL, rhs_vp, NULL, NULL) == 0);
				pairfree(&rhs_vp);
				return rcode;
			}

			return false;
		}

		/*
		 *	Get VP for RHS
		 */
		rhs_vp = pairalloc(request, map->dst->tmpl_da);
		rad_assert(rhs_vp != NULL);
		if (pairparsevalue(rhs_vp, rhs, 0) < 0) {
			talloc_free(rhs);
			pairfree(&rhs_vp);
			EVAL_DEBUG("FAIL %d", __LINE__);
			return -1;
		}

		rcode = paircmp_op(lhs_vp, map->op, rhs_vp);
		talloc_free(rhs);
		pairfree(&rhs_vp);
		return rcode;
	}

	/*
	 *	The LHS is a string.  Expand it.
	 */
	rcode = radius_expand_tmpl(&lhs, request, map->dst);
	if (rcode < 0) {
		EVAL_DEBUG("FAIL %d", __LINE__);
		return -1;
	}
	rad_assert(lhs != NULL);

	EVAL_DEBUG("LHS is %s", lhs);

	/*
	 *	Loop over the string, doing comparisons
	 */
	if (all_digits(lhs) && all_digits(rhs)) {
		int lint, rint;

		lint = strtoul(lhs, NULL, 0);
		rint = strtoul(rhs, NULL, 0);
		talloc_free(lhs);
		talloc_free(rhs);

		switch (map->op) {
		case T_OP_CMP_EQ:
			return (lint == rint);

		case T_OP_NE:
			return (lint != rint);

		case T_OP_LT:
			return (lint < rint);

		case T_OP_GT:
			return (lint > rint);

		case T_OP_LE:
			return (lint <= rint);

		case T_OP_GE:
			return (lint >= rint);

		default:
			break;
		}

	} else {
		rad_assert(lhs != NULL);
		rad_assert(rhs != NULL);

		rcode = strcmp(lhs, rhs);
		talloc_free(lhs);
		talloc_free(rhs);

		switch (map->op) {
		case T_OP_CMP_EQ:
			return (rcode == 0);

		case T_OP_NE:
			return (rcode != 0);

		case T_OP_LT:
			return (rcode < 0);

		case T_OP_GT:
			return (rcode > 0);

		case T_OP_LE:
			return (rcode <= 0);

		case T_OP_GE:
			return (rcode >= 0);

		default:
			break;
		}
	}

	EVAL_DEBUG("FAIL %d", __LINE__);
	return -1;
}


/** Evaluate a fr_cond_t;
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] c the condition to evaluate
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
int radius_evaluate_cond(REQUEST *request, int modreturn, int depth,
			 fr_cond_t const *c)
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
 *	The pairmove() function in src/lib/valuepair.c does all sorts of
 *	extra magic that we don't want here.
 *
 *	FIXME: integrate this with the code calling it, so that we
 *	only paircopy() those attributes that we're really going to
 *	use.
 */
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from, bool do_xlat)
{
	int i, j, count, from_count, to_count, tailto;
	vp_cursor_t cursor;
	VALUE_PAIR *vp, *next, **last;
	VALUE_PAIR **from_list, **to_list;
	int *edited = NULL;
	REQUEST *fixup = NULL;

	if (!request) return;

	/*
	 *	Set up arrays for editing, to remove some of the
	 *	O(N^2) dependencies.  This also makes it easier to
	 *	insert and remove attributes.
	 *
	 *	It also means that the operators apply ONLY to the
	 *	attributes in the original list.  With the previous
	 *	implementation of pairmove(), adding two attributes
	 *	via "+=" and then "=" would mean that the second one
	 *	wasn't added, because of the existence of the first
	 *	one in the "to" list.  This implementation doesn't
	 *	have that bug.
	 *
	 *	Also, the previous implementation did NOT implement
	 *	"-=" correctly.  If two of the same attributes existed
	 *	in the "to" list, and you tried to subtract something
	 *	matching the *second* value, then the pairdelete()
	 *	function was called, and the *all* attributes of that
	 *	number were deleted.  With this implementation, only
	 *	the matching attributes are deleted.
	 */
	count = 0;
	for (vp = fr_cursor_init(&cursor, &from); vp; vp = fr_cursor_next(&cursor)) count++;
	from_list = rad_malloc(sizeof(*from_list) * count);

	for (vp = fr_cursor_init(&cursor, to); vp; vp = fr_cursor_next(&cursor)) count++;
	to_list = rad_malloc(sizeof(*to_list) * count);

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
	for (vp = *to; vp != NULL; vp = next) {
		next = vp->next;
		to_list[to_count++] = vp;
		vp->next = NULL;
	}
	tailto = to_count;
	edited = rad_malloc(sizeof(*edited) * to_count);
	memset(edited, 0, sizeof(*edited) * to_count);

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
		if (from_list[i]->op == T_OP_ADD) goto append;

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
				pairfree(&to_list[j]);
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
						pairfree(&to_list[j]);
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
						pairfree(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = true;
					}
					break;

				case T_OP_GE:
					if (rcode < 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						pairfree(&to_list[j]);
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
			append:
				RDEBUG4("::: APPENDING %s FROM %d TO %d",
				       from_list[i]->da->name, i, tailto);
				to_list[tailto++] = from_list[i];
				from_list[i] = NULL;
			}
		}
	}

	/*
	 *	Delete attributes in the "from" list.
	 */
	for (i = 0; i < from_count; i++) {
		if (!from_list[i]) continue;

		pairfree(&from_list[i]);
	}
	free(from_list);

	RDEBUG4("::: TO in %d out %d", to_count, tailto);

	/*
	 *	Re-chain the "to" list.
	 */
	*to = NULL;
	last = to;

	if (to == &request->packet->vps) {
		fixup = request;
	} else if (request->parent && (to == &request->parent->packet->vps)) {
		fixup = request->parent;
	}
	if (fixup) {
		fixup->username = NULL;
		fixup->password = NULL;
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

		/*
		 *	Fix dumb cache issues
		 */
		if (fixup && !vp->da->vendor) {
			if ((vp->da->attr == PW_USER_NAME) &&
			    !fixup->username) {
				fixup->username = vp;

			} else if (vp->da->attr == PW_STRIPPED_USER_NAME) {
				fixup->username = vp;

			} else if (vp->da->attr == PW_USER_PASSWORD) {
				fixup->password = vp;
			}
		}

		*last = vp;
		last = &(*last)->next;
	}

	rad_assert(request->packet != NULL);

	free(to_list);
	free(edited);
}
