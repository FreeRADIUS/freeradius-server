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
 * @brief Valuepair functions that are radiusd-specific and as such do not
 * 	  belong in the library.
 * @file main/pair.c
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

struct cmp {
	DICT_ATTR const *attribute;
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
	if ((check->op == T_OP_REG_EQ) || (check->op == T_OP_REG_NE)) {
		ssize_t		slen;
		regex_t		*preg = NULL;
		regmatch_t	rxmatch[REQUEST_MAX_REGEX + 1];	/* +1 for %{0} (whole match) capture group */
		size_t		nmatch = sizeof(rxmatch) / sizeof(regmatch_t);

		char *expr = NULL, *value = NULL;
		char const *expr_p, *value_p;

		if (!vp) return -2;

		if (check->da->type == PW_TYPE_STRING) {
			expr_p = check->vp_strvalue;
		} else {
			expr_p = expr = vp_aprints_value(check, check, '\0');
		}

		if (vp->da->type == PW_TYPE_STRING) {
			value_p = vp->vp_strvalue;
		} else {
			value_p = value = vp_aprints_value(vp, vp, '\0');
		}

		if (!expr_p || !value_p) {
			REDEBUG("Error stringifying operand for regular expression");

		regex_error:
			talloc_free(preg);
			talloc_free(expr);
			talloc_free(value);
			return -2;
		}

		/*
		 *	Include substring matches.
		 */
		slen = regex_compile(request, &preg, expr_p, talloc_array_length(expr_p) - 1, false, false, true, true);
		if (slen <= 0) {
			REMARKER(expr_p, -slen, fr_strerror());

			goto regex_error;
		}

		slen = regex_exec(preg, value_p, talloc_array_length(value_p) - 1, rxmatch, &nmatch);
		if (slen < 0) {
			RERROR("%s", fr_strerror());

			goto regex_error;
		}

		if (check->op == T_OP_REG_EQ) {
			/*
			 *	Add in %{0}. %{1}, etc.
			 */
			regex_sub_to_request(request, &preg, value_p, talloc_array_length(value_p) - 1,
					     rxmatch, nmatch);
			ret = (slen == 1) ? 0 : -1;
		} else {
			ret = (slen != 1) ? 0 : -1;
		}

		talloc_free(preg);
		talloc_free(expr);
		talloc_free(value);
		goto finish;
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
	switch (check->da->type) {
#ifdef WITH_ASCEND_BINARY
		/*
		 *	Ascend binary attributes can be treated
		 *	as opaque objects, I guess...
		 */
		case PW_TYPE_ABINARY:
#endif
		case PW_TYPE_OCTETS:
			if (vp->vp_length != check->vp_length) {
				ret = 1; /* NOT equal */
				break;
			}
			ret = memcmp(vp->vp_strvalue, check->vp_strvalue,
				     vp->vp_length);
			break;

		case PW_TYPE_STRING:
			ret = strcmp(vp->vp_strvalue,
				     check->vp_strvalue);
			break;

		case PW_TYPE_BYTE:
			ret = vp->vp_byte - check->vp_byte;
			break;
		case PW_TYPE_SHORT:
			ret = vp->vp_short - check->vp_short;
			break;
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
			ret = memcmp(&vp->vp_ipv6addr, &check->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
			break;

		case PW_TYPE_IPV6_PREFIX:
			ret = memcmp(vp->vp_ipv6prefix, check->vp_ipv6prefix, sizeof(vp->vp_ipv6prefix));
			break;

		case PW_TYPE_IFID:
			ret = memcmp(vp->vp_ifid, check->vp_ifid, sizeof(vp->vp_ifid));
			break;

		default:
			break;
	}

finish:
	if (ret > 0) return 1;
	if (ret < 0) return -1;
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
		if (c->attribute == check->da) {
			return (c->compare)(c->instance, request, req, check,
				check_pairs, reply_pairs);
		}
	}

	if (!req) return -1; /* doesn't exist, don't compare it */

	return radius_compare_vps(request, check, req);
}


/** Find a comparison function for two attributes.
 *
 * @todo this should probably take DA's.
 * @param attribute to find comparison function for.
 * @return true if a comparison function was found, else false.
 */
int radius_find_compare(DICT_ATTR const *attribute)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->attribute == attribute) {
			return true;
		}
	}

	return false;
}


/** See what attribute we want to compare with.
 *
 * @param attribute to find comparison function for.
 * @param from reference to compare with
 * @return true if the comparison callback require a matching attribue in the request, else false.
 */
static bool otherattr(DICT_ATTR const *attribute, DICT_ATTR const **from)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->attribute == attribute) {
			*from = c->from;
			return c->first_only;
		}
	}

	*from = attribute;
	return false;
}

/** Register a function as compare function.
 *
 * @param name the attribute comparison to register
 * @param from the attribute we want to compare with. Normally this is the same as attribute.
 *  If null call the comparison function on every attributes in the request if first_only is false
 * @param first_only will decide if we loop over the request attributes or stop on the first one
 * @param func comparison function
 * @param instance argument to comparison function
 * @return 0
 */
int paircompare_register_byname(char const *name, DICT_ATTR const *from,
				bool first_only, RAD_COMPARE_FUNC func, void *instance)
{
	ATTR_FLAGS flags;
	DICT_ATTR const *da;

	memset(&flags, 0, sizeof(flags));
	flags.compare = 1;

	da = dict_attrbyname(name);
	if (da) {
		if (!da->flags.compare) {
			fr_strerror_printf("Attribute '%s' already exists.", name);
			return -1;
		}
	} else if (from) {
		if (dict_addattr(name, -1, 0, from->type, flags) < 0) {
			fr_strerror_printf("Failed creating attribute '%s'", name);
			return -1;
		}

		da = dict_attrbyname(name);
		if (!da) {
			fr_strerror_printf("Failed finding attribute '%s'", name);
			return -1;
		}

		DEBUG("Creating attribute %s", name);
	}

	return paircompare_register(da, from, first_only, func, instance);
}

/** Register a function as compare function.
 *
 * @param attribute to register comparison function for.
 * @param from the attribute we want to compare with. Normally this is the same as attribute.
 *  If null call the comparison function on every attributes in the request if first_only is false
 * @param first_only will decide if we loop over the request attributes or stop on the first one
 * @param func comparison function
 * @param instance argument to comparison function
 * @return 0
 */
int paircompare_register(DICT_ATTR const *attribute, DICT_ATTR const *from,
			 bool first_only, RAD_COMPARE_FUNC func, void *instance)
{
	struct cmp *c;

	rad_assert(attribute != NULL);

	paircompare_unregister(attribute, func);

	c = rad_malloc(sizeof(struct cmp));

	c->compare   = func;
	c->attribute = attribute;
	c->from = from;
	c->first_only = first_only;
	c->instance  = instance;
	c->next      = cmp;
	cmp = c;

	return 0;
}

/** Unregister comparison function for an attribute
 *
 * @param attribute dict reference to unregister for.
 * @param func comparison function to remove.
 */
void paircompare_unregister(DICT_ATTR const *attribute, RAD_COMPARE_FUNC func)
{
	struct cmp *c, *last;

	last = NULL;
	for (c = cmp; c; c = c->next) {
		if (c->attribute == attribute && c->compare == func) {
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
	VALUE_PAIR *auth_item = NULL;
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
			if (fr_pair_find_by_num(req_list, PW_USER_PASSWORD, 0, TAG_ANY) == NULL) {
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
				VERIFY_VP(auth_item);
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
			fr_assert(auth_item != NULL);
			auth_item = auth_item->next;
			result = 0;
			goto try_again;
		}

	} /* for every entry in the check item list */

	return result;
}

/** Expands an attribute marked with fr_pair_mark_xlat
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
	ssize_t slen;

	char *expanded = NULL;
	if (vp->type != VT_XLAT) return 0;

	vp->type = VT_DATA;

	slen = radius_axlat(&expanded, request, vp->value.xlat, NULL, NULL);
	rad_const_free(vp->value.xlat);
	vp->value.xlat = NULL;
	if (slen < 0) {
		return -1;
	}

	/*
	 *	Parse the string into a new value.
	 *
	 *	If the VALUE_PAIR is being used in a regular expression
	 *	then we just want to copy the new value in unmolested.
	 */
	if ((vp->op == T_OP_REG_EQ) || (vp->op == T_OP_REG_NE)) {
		fr_pair_value_strsteal(vp, expanded);
		return 0;
	}

	if (fr_pair_value_from_str(vp, expanded, -1) < 0){
		talloc_free(expanded);
		return -2;
	}

	talloc_free(expanded);

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
VALUE_PAIR *radius_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			      unsigned int attribute, unsigned int vendor)
{
	VALUE_PAIR *vp;

	vp = fr_pair_afrom_num(ctx, attribute, vendor);
	if (!vp) {
		ERROR("No memory!");
		rad_assert("No memory" == NULL);
		fr_exit_now(1);
	}

	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/** Print a single valuepair to stderr or error log.
 *
 * @param[in] vp list to print.
 */
void debug_pair(VALUE_PAIR *vp)
{
	if (!vp || !rad_debug_lvl || !fr_log_fp) return;

	vp_print(fr_log_fp, vp);
}

/** Print a single valuepair to stderr or error log.
 *
 * @param[in] level Debug level (1-4).
 * @param[in] request to read logging params from.
 * @param[in] vp to print.
 * @param[in] prefix (optional).
 */
void rdebug_pair(log_lvl_t level, REQUEST *request, VALUE_PAIR *vp, char const *prefix)
{
	char buffer[256];
	if (!vp || !request || !request->log.func) return;

	if (!radlog_debug_enabled(L_DBG, level, request)) return;

	vp_prints(buffer, sizeof(buffer), vp);
	RDEBUGX(level, "%s%s", prefix ? prefix : "",  buffer);
}

/** Print a list of VALUE_PAIRs.
 *
 * @param[in] level Debug level (1-4).
 * @param[in] request to read logging params from.
 * @param[in] vp to print.
 * @param[in] prefix (optional).
 */
void rdebug_pair_list(log_lvl_t level, REQUEST *request, VALUE_PAIR *vp, char const *prefix)
{
	vp_cursor_t cursor;
	char buffer[256];
	if (!vp || !request || !request->log.func) return;

	if (!radlog_debug_enabled(L_DBG, level, request)) return;

	RINDENT();
	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);

		vp_prints(buffer, sizeof(buffer), vp);
		RDEBUGX(level, "%s%s", prefix ? prefix : "",  buffer);
	}
	REXDENT();
}

/** Print a list of protocol VALUE_PAIRs.
 *
 * @param[in] level Debug level (1-4).
 * @param[in] request to read logging params from.
 * @param[in] vp to print.
 */
void rdebug_proto_pair_list(log_lvl_t level, REQUEST *request, VALUE_PAIR *vp)
{
	vp_cursor_t cursor;
	char buffer[256];
	if (!vp || !request || !request->log.func) return;

	if (!radlog_debug_enabled(L_DBG, level, request)) return;

	RINDENT();
	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);
		if ((vp->da->vendor == 0) &&
		    ((vp->da->attr & 0xFFFF) > 0xff)) continue;
		vp_prints(buffer, sizeof(buffer), vp);
		RDEBUGX(level, "%s", buffer);
	}
	REXDENT();
}

/** Return a VP from the specified request.
 *
 * @param out where to write the pointer to the resolved VP.
 *	Will be NULL if the attribute couldn't be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return -4 if either the attribute or qualifier were invalid, and the same error codes as tmpl_find_vp for other
 *	error conditions.
 */
int radius_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name)
{
	int rcode;
	vp_tmpl_t vpt;

	*out = NULL;

	if (tmpl_from_attr_str(&vpt, name, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) <= 0) {
		return -4;
	}

	rcode = tmpl_find_vp(out, request, &vpt);

	return rcode;
}

/** Copy VP(s) from the specified request.
 *
 * @param ctx to alloc new VALUE_PAIRs in.
 * @param out where to write the pointer to the copied VP.
 *	Will be NULL if the attribute couldn't be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return -4 if either the attribute or qualifier were invalid, and the same error codes as tmpl_find_vp for other
 *	error conditions.
 */
int radius_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, char const *name)
{
	int rcode;
	vp_tmpl_t vpt;

	*out = NULL;

	if (tmpl_from_attr_str(&vpt, name, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) <= 0) {
		return -4;
	}

	rcode = tmpl_copy_vps(ctx, out, request, &vpt);

	return rcode;
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

	if (!fmt || !request || !request->packet) {
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

	MEM(vp = pair_make_request("Module-Failure-Message", NULL, T_OP_ADD));
	if (request->module && (request->module[0] != '\0')) {
		fr_pair_value_sprintf(vp, "%s: %s", request->module, p);
	} else {
		fr_pair_value_sprintf(vp, "%s", p);
	}
	talloc_free(p);
}
