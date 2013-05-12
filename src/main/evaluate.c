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

#ifdef HAVE_PCREPOSIX_H
#include <pcreposix.h>
#else
#ifdef HAVE_REGEX_H
#include <regex.h>

/*
 *  For POSIX Regular expressions.
 *  (0) Means no extended regular expressions.
 *  REG_EXTENDED means use extended regular expressions.
 */
#ifndef REG_EXTENDED
#define REG_EXTENDED (0)
#endif

#ifndef REG_NOSUB
#define REG_NOSUB (0)
#endif
#endif
#endif

#ifdef WITH_UNLANG

#if 0
#define EVAL_DEBUG(fmt, ...) printf("EVAL: ");printf(fmt, ## __VA_ARGS__);printf("\n");fflush(stdout)
#else
#define EVAL_DEBUG(...)
#endif

static const FR_NAME_NUMBER modreturn_table[] = {
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


static int all_digits(const char *string)
{
	const char *p = string;

	if (*p == '-') p++;

	while (isdigit((int) *p)) p++;

	return (*p == '\0');
}

static char *radius_expand_tmpl(REQUEST *request, value_pair_tmpl_t const *vpt)
{
	char *buffer = NULL;
	VALUE_PAIR *vp;

	rad_assert(vpt->type != VPT_TYPE_LIST);

	switch (vpt->type) {
	case VPT_TYPE_LITERAL:
		EVAL_DEBUG("TMPL LITERAL");
		buffer = talloc_strdup(request, vpt->name);
		break;

	case VPT_TYPE_EXEC:
		EVAL_DEBUG("TMPL EXEC");
		buffer = talloc_array(request, char, 1024);
		if (radius_exec_program(vpt->name, request, 1,
					buffer, 1024, NULL, NULL, 0) != 0) {
			talloc_free(buffer);
			return NULL;
		}
		break;

	case VPT_TYPE_REGEX:
		EVAL_DEBUG("TMPL REGEX");
		if (strchr(vpt->name, '%') == NULL) {
			buffer = talloc_strdup(request, vpt->name);
			break;
		}
		/* FALL-THROUGH */

	case VPT_TYPE_XLAT:
		EVAL_DEBUG("TMPL XLAT");
		buffer = NULL;
		if (radius_axlat(&buffer, request, vpt->name, NULL, NULL) == 0) {
			return NULL;
		}
		break;

	case VPT_TYPE_ATTR:
		EVAL_DEBUG("TMPL ATTR");
		vp = radius_vpt_get_vp(request, vpt);
		if (!vp) return NULL;
		buffer = vp_aprint(request, vp);
		break;

	default:
		buffer = NULL;
		break;
	}

	EVAL_DEBUG("Expand tmpl --> %s", buffer);
	return buffer;
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
	case VPT_TYPE_LITERAL:
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

	case VPT_TYPE_ATTR:
	case VPT_TYPE_LIST:
		if (radius_vpt_get_vp(request, vpt) != NULL) {
			rcode = true;
		} else {
			rcode = false;
		}
		break;

		/*
		 *	FIXME: expand the strings
		 *	if not empty, return!
		 */
	case VPT_TYPE_XLAT:
	case VPT_TYPE_EXEC:
		if (!*vpt->name) return false;
		buffer = radius_expand_tmpl(request, vpt);
		if (!buffer) {
			EVAL_DEBUG("FAIL %d", __LINE__);
			return -1;
		}
		rcode = (*buffer != '\0');
		talloc_free(buffer);
		break;

		/*
		 *	Can't have a bare ... (/foo/) ...
		 */
	case VPT_TYPE_REGEX:
		EVAL_DEBUG("FAIL %d", __LINE__);
		rad_assert(0 == 1);
		/* FALL-THROUGH */

	default:
		rcode = -1;
		break;
	}

	return rcode;
}


static int do_regex(REQUEST *request, const char *lhs, const char *rhs, int iflag)
{
	int i, compare;
	int cflags = REG_EXTENDED;
	regex_t reg;
	regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

	if (iflag) cflags |= REG_ICASE;

	/*
	 *	Include substring matches.
	 */
	compare = regcomp(&reg, rhs, cflags);
	if (compare != 0) {
		if (debug_flag) {
			char errbuf[128];

			regerror(compare, &reg, errbuf, sizeof(errbuf));
			EDEBUG("Failed compiling regular expression: %s", errbuf);
		}
		EVAL_DEBUG("FAIL %d", __LINE__);
		return -1;
	}
	
	compare = regexec(&reg, lhs, REQUEST_MAX_REGEX + 1, rxmatch, 0);
	regfree(&reg);

	/*
	 *	Add new %{0}, %{1}, etc.
	 */
	if (compare == 0) for (i = 0; i <= REQUEST_MAX_REGEX; i++) {
		char *r;
			
		free(request_data_get(request, request,
				      REQUEST_DATA_REGEX | i));
		
		/*
		 *	No %{i}, skip it.
		 *	We MAY have %{2} without %{1}.
		 */
		if (rxmatch[i].rm_so == -1) continue;
		
		/*
		 *	Copy substring into allocated buffer
		 */
		r = rad_malloc(rxmatch[i].rm_eo -rxmatch[i].rm_so + 1);
		memcpy(r, lhs + rxmatch[i].rm_so,
		       rxmatch[i].rm_eo - rxmatch[i].rm_so);
		r[rxmatch[i].rm_eo - rxmatch[i].rm_so] = '\0';

		request_data_add(request, request,
				 REQUEST_DATA_REGEX | i,
				 r, free);
		}
	return (compare == 0);
}

/*
 *	Expand a template to a string, parse it as type of "cast", and
 *	create a VP from the data.
 */
static VALUE_PAIR *get_cast_vp(REQUEST *request, value_pair_tmpl_t const *vpt, DICT_ATTR const *cast)
{
	VALUE_PAIR *vp;
	char *str;

	str = radius_expand_tmpl(request, vpt);
	if (!str) return NULL;

	vp = pairalloc(request, cast);
	if (!vp) {
		talloc_free(str);
		return NULL;
	}

	if (!pairparsevalue(vp, str)) {
		talloc_free(str);
		pairfree(&vp);
		return NULL;
	}
	
	return vp;
}

/** Evaluate a map
 *
 * @param[in] request the REQUEST
 * @param[in] modreturn the previous module return code
 * @param[in] depth of the recursion (only used for debugging)
 * @param[in] map the map to evaluate
 * @param[in] iflag for regex case-insensitive comparisons
 * @param[in] cast of the data type to use for evaluations.
 * @return -1 on error, 0 for "no match", 1 for "match".
 */
int radius_evaluate_map(REQUEST *request, UNUSED int modreturn, UNUSED int depth,
			value_pair_map_t const *map, int iflag, DICT_ATTR const *cast)
{
	int rcode;
	char *lhs, *rhs;

	rad_assert(map->dst->type != VPT_TYPE_UNKNOWN);
	rad_assert(map->src->type != VPT_TYPE_UNKNOWN);
	rad_assert(map->dst->type != VPT_TYPE_LIST);
	rad_assert(map->src->type != VPT_TYPE_LIST);
	rad_assert(map->dst->type != VPT_TYPE_REGEX);

	/*
	 *	Verify regexes.
	 */
	if (map->src->type == VPT_TYPE_REGEX) {
		rad_assert(map->op == T_OP_REG_EQ);
	} else {
		rad_assert(!((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)));
	}

	/*
	 *	They're both attributes.  Do attribute-specific work.
	 *
	 *	LHS is DST.  RHS is SRC <sigh>
	 */
	if (!cast && (map->src->type == VPT_TYPE_ATTR) && (map->dst->type == VPT_TYPE_ATTR)) {
		VALUE_PAIR *lhs_vp, *rhs_vp;

		lhs_vp = radius_vpt_get_vp(request, map->dst);
		rhs_vp = radius_vpt_get_vp(request, map->src);

		if (!lhs_vp || !rhs_vp) return false;

		return paircmp_op(lhs_vp, map->op, rhs_vp);
	}

	/*
	 *	LHS is a cast.  Do type-specific comparisons, as if
	 *	the LHS was a real attribute.
	 */
	if (cast) {
		VALUE_PAIR *lhs_vp, *rhs_vp;

		lhs_vp = get_cast_vp(request, map->dst, cast);
		if (!lhs_vp) return false;

		/*
		 *	Get either a real VP, or parse the RHS into a
		 *	VP, and return that.
		 */
		if (map->src->type == VPT_TYPE_ATTR) {
			rhs_vp = radius_vpt_get_vp(request, map->src);
		} else {
			rhs_vp = get_cast_vp(request, map->src, cast);
		}

		if (!rhs_vp) return false;

		rcode = paircmp_op(lhs_vp, map->op, rhs_vp);
		pairfree(&lhs_vp);
		if (map->src->type != VPT_TYPE_ATTR) {
			pairfree(&rhs_vp);
		}
		return rcode;
	}

	/*
	 *	The RHS now needs to be expanded into a string.
	 */
	rhs = radius_expand_tmpl(request, map->src);
	if (!rhs) {
		EVAL_DEBUG("FAIL %d", __LINE__);
		return -1;
	}

	/*
	 *	User-Name == FOO
	 *
	 *	Parse the RHS to be the same DA as the LHS.  do
	 *	comparisons.  So long as it's not a regex, which does
	 *	string comparisons.
	 *
	 *	The LHS may be a virtual attribute, too.
	 */
	if ((map->dst->type == VPT_TYPE_ATTR) &&
	    (map->src->type != VPT_TYPE_REGEX)) {
		VALUE_PAIR *lhs_vp, *rhs_vp;

		/*
		 *	No LHS means no match
		 */
		lhs_vp = radius_vpt_get_vp(request, map->dst);
		if (!lhs_vp) {
			/*
			 *	Not a real attr: might be a dynamic comparison.
			 */
			if ((map->dst->type == VPT_TYPE_ATTR) &&
			    (map->dst->da->vendor == 0) &&
			    radius_find_compare(map->dst->da->attr)) {
				rhs_vp = pairalloc(request, map->dst->da);

				if (!pairparsevalue(rhs_vp, rhs)) {
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
		rhs_vp = pairalloc(request, map->dst->da);
		rad_assert(rhs_vp != NULL);
		if (!pairparsevalue(rhs_vp, rhs)) {
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
	lhs = radius_expand_tmpl(request, map->dst);
	if (!lhs) {
		talloc_free(rhs);
		EVAL_DEBUG("FAIL %d", __LINE__);
		return -1;
	}

	/*
	 *	Compile  the RHS to a regex, and do regex stuff
	 */
	if (map->src->type == VPT_TYPE_REGEX) {
		return do_regex(request, lhs, rhs, iflag);
	}

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

	while (c) {
		switch (c->type) {
		case COND_TYPE_EXISTS:
			rcode = radius_evaluate_tmpl(request, modreturn, depth, c->data.vpt);
			break;

		case COND_TYPE_MAP:
			rcode = radius_evaluate_map(request, modreturn, depth, c->data.map, c->regex_i, c->cast);
			break;

		case COND_TYPE_CHILD:
			rcode = radius_evaluate_cond(request, modreturn, depth + 1, c->data.child);
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
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from)
{
	int i, j, count, from_count, to_count, tailto;
	VALUE_PAIR *vp, *next, **last;
	VALUE_PAIR **from_list, **to_list;
	int *edited = NULL;
	REQUEST *fixup = NULL;

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
	for (vp = from; vp != NULL; vp = vp->next) count++;
	from_list = rad_malloc(sizeof(*from_list) * count);

	for (vp = *to; vp != NULL; vp = vp->next) count++;
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
		(void) talloc_steal(request, vp);
	}

	rad_assert(request != NULL);
	rad_assert(request->packet != NULL);

	free(to_list);
	free(edited);
}
