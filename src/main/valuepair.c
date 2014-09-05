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

/*
 * $Id$
 *
 * @brief Valuepair functions that are radiusd-specific and as such do not
 * 	  belong in the library.
 * @file main/valuepair.c
 *
 * @ingroup AVP
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

const FR_NAME_NUMBER vpt_types[] = {
	{"unknown",		TMPL_TYPE_UNKNOWN },
	{"literal",		TMPL_TYPE_LITERAL },
	{"expanded",		TMPL_TYPE_XLAT },
	{"attribute ref",	TMPL_TYPE_ATTR },
	{"list",		TMPL_TYPE_LIST },
	{"exec",		TMPL_TYPE_EXEC },
	{"value-pair-data",	TMPL_TYPE_DATA }
};

struct cmp {
	DICT_ATTR const *da;
	DICT_ATTR const *from;
	bool	first_only;
	void *instance; /* module instance */
	RAD_COMPARE_FUNC compare;
	struct cmp *next;
};
static struct cmp *cmp;

/** Compares check and vp by value.
 *
 * Does not call any per-attribute comparison function, but does honour
 * check.operator. Basically does "vp.value check.op check.value".
 *
 * @param request Current request.
 * @param check rvalue, and operator.
 * @param vp lvalue.
 * @return 0 if check and vp are equal, -1 if vp value is less than check value, 1 is vp value is more than check
 *	value, -2 on error.
 */
#ifdef HAVE_REGEX
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp)
#else
int radius_compare_vps(UNUSED REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp)
#endif
{
	int ret = 0;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->op == T_OP_CMP_TRUE)  return 0;
	if (check->op == T_OP_CMP_FALSE) return 1;

#ifdef HAVE_REGEX
	if (check->op == T_OP_REG_EQ) {
		int compare;
		regex_t reg;
		char value[1024];
		regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

		vp_prints_value(value, sizeof(value), vp, -1);

		/*
		 *	Include substring matches.
		 */
		compare = regcomp(&reg, check->vp_strvalue, REG_EXTENDED);
		if (compare != 0) {
			char buffer[256];
			regerror(compare, &reg, buffer, sizeof(buffer));

			RDEBUG("Invalid regular expression %s: %s", check->vp_strvalue, buffer);
			return -2;
		}

		memset(&rxmatch, 0, sizeof(rxmatch));	/* regexec does not seem to initialise unused elements */
		compare = regexec(&reg, value, REQUEST_MAX_REGEX + 1, rxmatch, 0);
		regfree(&reg);
		rad_regcapture(request, compare, value, rxmatch);

		ret = (compare == 0) ? 0 : -1;
		goto finish;
	}

	if (check->op == T_OP_REG_NE) {
		int compare;
		regex_t reg;
		char value[1024];
		regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

		vp_prints_value(value, sizeof(value), vp, -1);

		/*
		 *	Include substring matches.
		 */
		compare = regcomp(&reg, check->vp_strvalue, REG_EXTENDED);
		if (compare != 0) {
			char buffer[256];
			regerror(compare, &reg, buffer, sizeof(buffer));

			RDEBUG("Invalid regular expression %s: %s", check->vp_strvalue, buffer);
			return -2;
		}
		compare = regexec(&reg, value,  REQUEST_MAX_REGEX + 1, rxmatch, 0);
		regfree(&reg);

		ret = (compare != 0) ? 0 : -1;
	}
#endif

	/*
	 *	Attributes must be of the same type.
	 *
	 *	FIXME: deal with type mismatch properly if one side contain
	 *	ABINARY, OCTETS or STRING by converting the other side to
	 *	a string
	 *
	 */
	if (vp->da->type != check->da->type) return -1;

	/*
	 *	Tagged attributes are equal if and only if both the
	 *	tag AND value match.
	 */
	if (check->da->flags.has_tag && !TAG_EQ(check->tag, vp->tag)) {
		ret = ((int) vp->tag) - ((int) check->tag);
		if (ret != 0) goto finish;
	}

	/*
	 *	Not a regular expression, compare the types.
	 */
	switch(check->da->type) {
#ifdef WITH_ASCEND_BINARY
		/*
		 *	Ascend binary attributes can be treated
		 *	as opaque objects, I guess...
		 */
		case PW_TYPE_ABINARY:
#endif
		case PW_TYPE_OCTETS:
			if (vp->length != check->length) {
				ret = 1; /* NOT equal */
				break;
			}
			ret = memcmp(vp->vp_strvalue, check->vp_strvalue,
				     vp->length);
			break;

		case PW_TYPE_STRING:
			ret = strcmp(vp->vp_strvalue,
				     check->vp_strvalue);
			break;

		case PW_TYPE_BYTE:
		case PW_TYPE_SHORT:
		case PW_TYPE_INTEGER:
			ret = vp->vp_integer - check->vp_integer;
			break;

		case PW_TYPE_INTEGER64:
			/*
			 *	Don't want integer overflow!
			 */
			if (vp->vp_integer64 < check->vp_integer64) {
				ret = -1;
			} else if (vp->vp_integer64 > check->vp_integer64) {
				ret = +1;
			} else {
				ret = 0;
			}
			break;

		case PW_TYPE_SIGNED:
			if (vp->vp_signed < check->vp_signed) {
				ret = -1;
			} else if (vp->vp_signed > check->vp_signed) {
				ret = +1;
			} else {
				ret = 0;
			}
			break;

		case PW_TYPE_DATE:
			ret = vp->vp_date - check->vp_date;
			break;

		case PW_TYPE_IPV4_ADDR:
			ret = ntohl(vp->vp_ipaddr) - ntohl(check->vp_ipaddr);
			break;

		case PW_TYPE_IPV6_ADDR:
			ret = memcmp(&vp->vp_ipv6addr, &check->vp_ipv6addr,
				     sizeof(vp->vp_ipv6addr));
			break;

		case PW_TYPE_IPV6_PREFIX:
			ret = memcmp(&vp->vp_ipv6prefix, &check->vp_ipv6prefix,
				     sizeof(vp->vp_ipv6prefix));
			break;

		case PW_TYPE_IFID:
			ret = memcmp(&vp->vp_ifid, &check->vp_ifid,
				     sizeof(vp->vp_ifid));
			break;

		default:
			break;
	}

	finish:
	if (ret > 0) {
		return 1;
	}
	if (ret < 0) {
		return -1;
	}
	return 0;
}


/** Compare check and vp. May call the attribute comparison function.
 *
 * Unlike radius_compare_vps() this function will call any attribute-specific
 * comparison functions registered.
 *
 * @param request Current request.
 * @param req list pairs.
 * @param check item to compare.
 * @param check_pairs list.
 * @param reply_pairs list.
 * @return 0 if check and vp are equal, -1 if vp value is less than check value, 1 is vp value is more than check
 *	value.
 */
int radius_callback_compare(REQUEST *request, VALUE_PAIR *req,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs)
{
	struct cmp *c;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->op == T_OP_CMP_TRUE)  return 0;
	if (check->op == T_OP_CMP_FALSE) return 1;

	/*
	 *	See if there is a special compare function.
	 *
	 *	FIXME: use new RB-Tree code.
	 */
	for (c = cmp; c; c = c->next) {
		if (c->da == check->da) {
			return (c->compare)(c->instance, request, req, check,
				check_pairs, reply_pairs);
		}
	}

	if (!req) return -1; /* doesn't exist, don't compare it */

	return radius_compare_vps(request, check, req);
}


/** Find a comparison function for two attributes.
 *
 * @param da to find comparison function for.
 * @return true if a comparison function was found, else false.
 */
int radius_find_compare(DICT_ATTR const *da)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->da == da) {
			return true;
		}
	}

	return false;
}


/** See what attribute we want to compare with.
 *
 * @param da to find comparison function for.
 * @param from reference to compare with
 * @return true if the comparison callback require a matching attribue in the request, else false.
 */
static bool otherattr(DICT_ATTR const *da, DICT_ATTR const **from)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->da == da) {
			*from = c->from;
			return c->first_only;
		}
	}

	*from = da;
	return false;
}

/** Register a function as compare function.
 *
 * @param da to register comparison function for.
 * @param from the attribute we want to compare with. Normally this is the same as attribute.
 *  If null call the comparison function on every attributes in the request if first_only is false
 * @param first_only will decide if we loop over the request attributes or stop on the first one
 * @param func comparison function
 * @param instance argument to comparison function
 * @return 0
 */
int paircompare_register(DICT_ATTR const *da, DICT_ATTR const *from,
			 bool first_only, RAD_COMPARE_FUNC func, void *instance)
{
	struct cmp *c;

	rad_assert(da != NULL);

	paircompare_unregister(da, func);

	c = rad_malloc(sizeof(struct cmp));

	c->compare   = func;
	c->da = da;
	c->from = from;
	c->first_only = first_only;
	c->instance  = instance;
	c->next      = cmp;
	cmp = c;

	return 0;
}

/** Unregister comparison function for an attribute
 *
 * @param da dict reference to unregister for.
 * @param func comparison function to remove.
 */
void paircompare_unregister(DICT_ATTR const *da, RAD_COMPARE_FUNC func)
{
	struct cmp *c, *last;

	last = NULL;
	for (c = cmp; c; c = c->next) {
		if (c->da == da && c->compare == func) {
			break;
		}
		last = c;
	}

	if (c == NULL) return;

	if (last != NULL) {
		last->next = c->next;
	} else {
		cmp = c->next;
	}

	free(c);
}

/** Unregister comparison function for a module
 *
 *  All paircompare() functions for this module will be unregistered.
 *
 * @param instance the module instance
 */
void paircompare_unregister_instance(void *instance)
{
	struct cmp *c, **tail;

	tail = &cmp;
	while ((c = *tail) != NULL) {
		if (c->instance == instance) {
			*tail = c->next;
			free(c);
			continue;
		}

		tail = &(c->next);
	}
}

/** Compare two pair lists except for the password information.
 *
 * For every element in "check" at least one matching copy must be present
 * in "reply".
 *
 * @param[in] request Current request.
 * @param[in] req_list request valuepairs.
 * @param[in] check Check/control valuepairs.
 * @param[in,out] rep_list Reply value pairs.
 *
 * @return 0 on match.
 */
int paircompare(REQUEST *request, VALUE_PAIR *req_list, VALUE_PAIR *check,
		VALUE_PAIR **rep_list)
{
	vp_cursor_t cursor;
	VALUE_PAIR *check_item;
	VALUE_PAIR *auth_item;
	DICT_ATTR const *from;

	int result = 0;
	int compare;
	bool first_only;

	for (check_item = fr_cursor_init(&cursor, &check);
	     check_item;
	     check_item = fr_cursor_next(&cursor)) {
		/*
		 *	If the user is setting a configuration value,
		 *	then don't bother comparing it to any attributes
		 *	sent to us by the user.  It ALWAYS matches.
		 */
		if ((check_item->op == T_OP_SET) ||
		    (check_item->op == T_OP_ADD)) {
			continue;
		}

		if (!check_item->da->vendor) switch (check_item->da->attr) {
		/*
		 *	Attributes we skip during comparison.
		 *	These are "server" check items.
		 */
		case PW_CRYPT_PASSWORD:
		case PW_AUTH_TYPE:
		case PW_AUTZ_TYPE:
		case PW_ACCT_TYPE:
		case PW_SESSION_TYPE:
		case PW_STRIP_USER_NAME:
			continue;
			break;

		/*
		 *	IF the password attribute exists, THEN
		 *	we can do comparisons against it.  If not,
		 *	then the request did NOT contain a
		 *	User-Password attribute, so we CANNOT do
		 *	comparisons against it.
		 *
		 *	This hack makes CHAP-Password work..
		 */
		case PW_USER_PASSWORD:
			if (check_item->op == T_OP_CMP_EQ) {
				WARN("Found User-Password == \"...\"");
				WARN("Are you sure you don't mean Cleartext-Password?");
				WARN("See \"man rlm_pap\" for more information");
			}
			if (pairfind(req_list, PW_USER_PASSWORD, 0, TAG_ANY) == NULL) {
				continue;
			}
			break;
		}

		/*
		 *	See if this item is present in the request.
		 */
		first_only = otherattr(check_item->da, &from);

		auth_item = req_list;
	try_again:
		if (!first_only) {
			while (auth_item != NULL) {
				if ((auth_item->da == from) || (!from)) {
					break;
				}
				auth_item = auth_item->next;
			}
		}

		/*
		 *	Not found, it's not a match.
		 */
		if (auth_item == NULL) {
			/*
			 *	Didn't find it.  If we were *trying*
			 *	to not find it, then we succeeded.
			 */
			if (check_item->op == T_OP_CMP_FALSE) {
				continue;
			} else {
				return -1;
			}
		}

		/*
		 *	Else we found it, but we were trying to not
		 *	find it, so we failed.
		 */
		if (check_item->op == T_OP_CMP_FALSE) {
			return -1;
		}


		/*
		 *	We've got to xlat the string before doing
		 *	the comparison.
		 */
		radius_xlat_do(request, check_item);

		/*
		 *	OK it is present now compare them.
		 */
		compare = radius_callback_compare(request, auth_item,
						  check_item, check, rep_list);

		switch (check_item->op) {
		case T_OP_EQ:
		default:
			RWDEBUG("Invalid operator '%s' for item %s: reverting to '=='",
				fr_int2str(fr_tokens, check_item->op, "<INVALID>"), check_item->da->name);
			/* FALL-THROUGH */
		case T_OP_CMP_TRUE:
		case T_OP_CMP_FALSE:
		case T_OP_CMP_EQ:
			if (compare != 0) result = -1;
			break;

		case T_OP_NE:
			if (compare == 0) result = -1;
			break;

		case T_OP_LT:
			if (compare >= 0) result = -1;
			break;

		case T_OP_GT:
			if (compare <= 0) result = -1;
			break;

		case T_OP_LE:
			if (compare > 0) result = -1;
			break;

		case T_OP_GE:
			if (compare < 0) result = -1;
			break;

#ifdef HAVE_REGEX
		case T_OP_REG_EQ:
		case T_OP_REG_NE:
			if (compare != 0) result = -1;
			break;
#endif
		} /* switch over the operator of the check item */

		/*
		 *	This attribute didn't match, but maybe there's
		 *	another of the same attribute, which DOES match.
		 */
		if ((result != 0) && (!first_only)) {
			auth_item = auth_item->next;
			result = 0;
			goto try_again;
		}

	} /* for every entry in the check item list */

	return result;
}

/** Expands an attribute marked with pairmark_xlat
 *
 * Writes the new value to the vp.
 *
 * @param request Current request.
 * @param vp to expand.
 * @return 0 if successful else -1 (on xlat failure) or -2 (on parse failure).
 *	On failure pair will still no longer be marked for xlat expansion.
 */
int radius_xlat_do(REQUEST *request, VALUE_PAIR *vp)
{
	ssize_t len;

	char buffer[1024];

	if (vp->type != VT_XLAT) return 0;

	vp->type = VT_DATA;

	len = radius_xlat(buffer, sizeof(buffer), request, vp->value.xlat, NULL, NULL);

	rad_const_free(vp->value.xlat);
	vp->value.xlat = NULL;
	if (len < 0) {
		return -1;
	}

	/*
	 *	Parse the string into a new value.
	 */
	if (pairparsevalue(vp, buffer, 0) < 0){
		return -2;
	}

	return 0;
}

/** Create a VALUE_PAIR and add it to a list of VALUE_PAIR s
 *
 * @note This function ALWAYS returns. If we're OOM, then it causes the
 * @note server to exit, so you don't need to check the return value.
 *
 * @param[in] ctx for talloc
 * @param[out] vps List to add new VALUE_PAIR to, if NULL will just
 *	return VALUE_PAIR.
 * @param[in] attribute number.
 * @param[in] vendor number.
 * @return a new VLAUE_PAIR or causes server to exit on error.
 */
VALUE_PAIR *radius_paircreate(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			      unsigned int attribute, unsigned int vendor)
{
	VALUE_PAIR *vp;

	vp = paircreate(ctx, attribute, vendor);
	if (!vp) {
		ERROR("No memory!");
		rad_assert("No memory" == NULL);
		fr_exit_now(1);
	}

	if (vps) pairadd(vps, vp);

	return vp;
}

/** Print a single valuepair to stderr or error log.
 *
 * @param[in] vp list to print.
 */
void debug_pair(VALUE_PAIR *vp)
{
	if (!vp || !debug_flag || !fr_log_fp) return;

	vp_print(fr_log_fp, vp);
}

/** Print a list of valuepairs to stderr or error log.
 *
 * @param[in] vp to print.
 */
void debug_pair_list(VALUE_PAIR *vp)
{
	vp_cursor_t cursor;
	if (!vp || !debug_flag || !fr_log_fp) return;

	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		vp_print(fr_log_fp, vp);
	}
	fflush(fr_log_fp);
}

/** Print a list of valuepairs to the request list.
 *
 * @param[in] level Debug level (1-4).
 * @param[in] request to read logging params from.
 * @param[in] vp to print.
 */
void rdebug_pair_list(int level, REQUEST *request, VALUE_PAIR *vp)
{
	vp_cursor_t cursor;
	char buffer[256];
	if (!vp || !request || !request->log.func) return;

	if (!radlog_debug_enabled(L_DBG, level, request)) return;

	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Take this opportunity to verify all the VALUE_PAIRs are still valid.
		 */
		if (!talloc_get_type(vp, VALUE_PAIR)) {
			REDEBUG("Expected VALUE_PAIR pointer got \"%s\"", talloc_get_name(vp));

			fr_log_talloc_report(vp);
			rad_assert(0);
		}

		vp_prints(buffer, sizeof(buffer), vp);
		RDEBUGX(level, "\t%s", buffer);
	}
}

/** Return a VP from the specified request.
 *
 * @param out where to write the pointer to the resolved VP.
 *	Will be NULL if the attribute couldn't be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return -4 if either the attribute or qualifier were invalid, and the same error codes as radius_tmpl_get_vp for other
 *	error conditions.
 */
int radius_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name)
{
	value_pair_tmpl_t vpt;

	*out = NULL;

	if (radius_parse_attr(&vpt, name, REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
		return -4;
	}

	return radius_tmpl_get_vp(out, request, &vpt);
}

/** Copy VP(s) from the specified request.
 *
 * @param ctx to alloc new VALUE_PAIRs in.
 * @param out where to write the pointer to the copied VP.
 *	Will be NULL if the attribute couldn't be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return -4 if either the attribute or qualifier were invalid, and the same error codes as radius_tmpl_get_vp for other
 *	error conditions.
 */
int radius_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, char const *name)
{
	value_pair_tmpl_t vpt;

	*out = NULL;

	if (radius_parse_attr(&vpt, name, REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
		return -4;
	}

	return radius_tmpl_copy_vp(ctx, out, request, &vpt);
}

void module_failure_msg(REQUEST *request, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vmodule_failure_msg(request, fmt, ap);
	va_end(ap);
}

/** Add a module failure message VALUE_PAIR to the request
 */
void vmodule_failure_msg(REQUEST *request, char const *fmt, va_list ap)
{
	char *p;
	VALUE_PAIR *vp;
	va_list aq;

	if (!fmt || !request->packet) {
		return;
	}

	/*
	 *  If we don't copy the original ap we get a segfault from vasprintf. This is apparently
	 *  due to ap sometimes being implemented with a stack offset which is invalidated if
	 *  ap is passed into another function. See here:
	 *  http://julipedia.meroh.net/2011/09/using-vacopy-to-safely-pass-ap.html
	 *
	 *  I don't buy that explanation, but doing a va_copy here does prevent SEGVs seen when
	 *  running unit tests which generate errors under CI.
	 */
	va_copy(aq, ap);
	p = talloc_vasprintf(request, fmt, aq);
	va_end(aq);

	MEM(vp = pairmake_packet("Module-Failure-Message", NULL, T_OP_ADD));
	if (request->module && (request->module[0] != '\0')) {
		pairsprintf(vp, "%s: %s", request->module, p);
	} else {
		pairsprintf(vp, "%s", p);
	}
	talloc_free(p);
}
