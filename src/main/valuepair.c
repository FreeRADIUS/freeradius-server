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
	{"unknown",		VPT_TYPE_UNKNOWN },
	{"literal",		VPT_TYPE_LITERAL },
	{"expanded",		VPT_TYPE_XLAT },
	{"attribute ref",	VPT_TYPE_ATTR },
	{"list",		VPT_TYPE_LIST },
	{"exec",		VPT_TYPE_EXEC },
	{"value-pair-data",	VPT_TYPE_DATA }
};

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
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp)
{
	int ret = 0;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->op == T_OP_CMP_TRUE)  return 0;
	if (check->op == T_OP_CMP_FALSE) return 1;

#ifdef HAVE_REGEX_H
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

		case PW_TYPE_IPADDR:
			ret = ntohl(vp->vp_ipaddr) - ntohl(check->vp_ipaddr);
			break;

		case PW_TYPE_IPV6ADDR:
			ret = memcmp(&vp->vp_ipv6addr, &check->vp_ipv6addr,
				     sizeof(vp->vp_ipv6addr));
			break;

		case PW_TYPE_IPV6PREFIX:
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

#ifdef HAVE_REGEX_H
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
	if (!pairparsevalue(vp, buffer)){
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

/** Resolve attribute pair_lists_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of the list
 * in the REQUEST. If the head of the list changes, the pointer will still
 * be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list pair_list_t value to resolve to VALUE_PAIR list.
 *	Will be NULL if list name couldn't be resolved.
 */
VALUE_PAIR **radius_list(REQUEST *request, pair_lists_t list)
{
	if (!request) return NULL;

	switch (list) {
		case PAIR_LIST_UNKNOWN:
		default:
			break;

		case PAIR_LIST_REQUEST:
			return &request->packet->vps;

		case PAIR_LIST_REPLY:
			return &request->reply->vps;

		case PAIR_LIST_CONTROL:
			return &request->config_items;

#ifdef WITH_PROXY
		case PAIR_LIST_PROXY_REQUEST:
			if (!request->proxy) break;
			return &request->proxy->vps;

		case PAIR_LIST_PROXY_REPLY:
			if (!request->proxy) break;
			return &request->proxy_reply->vps;
#endif
#ifdef WITH_COA
		case PAIR_LIST_COA:
			if (request->coa &&
			    (request->coa->proxy->code == PW_CODE_COA_REQUEST)) {
				return &request->coa->proxy->vps;
			}
			break;

		case PAIR_LIST_COA_REPLY:
			if (request->coa && /* match reply with request */
			    (request->coa->proxy->code == PW_CODE_COA_REQUEST) &&
			    request->coa->proxy_reply) {
				return &request->coa->proxy_reply->vps;
			}
			break;

		case PAIR_LIST_DM:
			if (request->coa &&
			    (request->coa->proxy->code == PW_CODE_DISCONNECT_REQUEST)) {
				return &request->coa->proxy->vps;
			}
			break;

		case PAIR_LIST_DM_REPLY:
			if (request->coa && /* match reply with request */
			    (request->coa->proxy->code == PW_CODE_DISCONNECT_REQUEST) &&
			    request->coa->proxy_reply) {
				return &request->coa->proxy->vps;
			}
			break;
#endif
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_int2str(pair_lists, list, "<INVALID>"));

	return NULL;
}


TALLOC_CTX *radius_list_ctx(REQUEST *request, pair_lists_t list_name)
{
	if (!request) return NULL;

		switch (list_name) {
		case PAIR_LIST_REQUEST:
			return request->packet;

		case PAIR_LIST_REPLY:
			return request->reply;

		case PAIR_LIST_CONTROL:
			return request;

#ifdef WITH_PROXY
		case PAIR_LIST_PROXY_REQUEST:
			return request->proxy;

		case PAIR_LIST_PROXY_REPLY:
			return request->proxy_reply;
#endif

#ifdef WITH_COA
		case PAIR_LIST_COA:
			if (!request->coa) return NULL;
			rad_assert(request->coa->proxy != NULL);
			if (request->coa->proxy->code != PW_CODE_COA_REQUEST) return NULL;
			return request->coa->proxy;

		case PAIR_LIST_COA_REPLY:
			if (!request->coa) return NULL;
			rad_assert(request->coa->proxy != NULL);
			if (request->coa->proxy->code != PW_CODE_COA_REQUEST) return NULL;
			return request->coa->proxy_reply;

		case PAIR_LIST_DM:
			if (!request->coa) return NULL;
			rad_assert(request->coa->proxy != NULL);
			if (request->coa->proxy->code != PW_CODE_DISCONNECT_REQUEST) return NULL;
			return request->coa->proxy;

		case PAIR_LIST_DM_REPLY:
			if (!request->coa) return NULL;
			rad_assert(request->coa->proxy != NULL);
			if (request->coa->proxy->code != PW_CODE_DISCONNECT_REQUEST) return NULL;
			return request->coa->proxy_reply;
#endif

		default:
			break;
		}

		return NULL;
}

/*
 *	Debug print a map / VP
 */
static void debug_map(REQUEST *request, value_pair_map_t const *map, VALUE_PAIR const *vp)
{
	char *value;
	char buffer[1024];

	switch (map->src->type) {
		/*
		 *	Just print the value being assigned
		 */
		default:
		case VPT_TYPE_LITERAL:
			vp_prints_value(buffer, sizeof(buffer), vp, '\'');
			value = buffer;
			break;

		case VPT_TYPE_XLAT:
		case VPT_TYPE_XLAT_STRUCT:
			vp_prints_value(buffer, sizeof(buffer), vp, '"');
			value = buffer;
			break;

		case VPT_TYPE_DATA:
			vp_prints_value(buffer, sizeof(buffer), vp, '\'');
			value = buffer;
			break;

		/*
		 *	Just printing the value doesn't make sense, but we still
		 *	want to know what it was...
		 */
		case VPT_TYPE_LIST:
			vp_prints_value(buffer, sizeof(buffer), vp, '\'');
			value = talloc_typed_asprintf(request, "&%s%s -> %s", map->src->name, vp->da->name, buffer);
			break;

		case VPT_TYPE_ATTR:
			vp_prints_value(buffer, sizeof(buffer), vp, '\'');
			value = talloc_typed_asprintf(request, "&%s -> %s", map->src->name, buffer);
			break;
	}

	switch (map->dst->type) {
		case VPT_TYPE_LIST:
			RDEBUG("\t%s%s %s %s", map->dst->name, vp->da->name,
			       fr_int2str(fr_tokens, vp->op, "<INVALID>"), value);
			break;

		case VPT_TYPE_ATTR:
			RDEBUG("\t%s %s %s", map->dst->name,
			       fr_int2str(fr_tokens, vp->op, "<INVALID>"), value);
			break;

		default:
			break;
	}

	if (value != buffer) talloc_free(value);
}

#define DEBUG_OVERWRITE(_old, _new) \
do {\
	if (RDEBUG_ENABLED3) {\
		char *old = vp_aprint_value(request, _old);\
		char *new = vp_aprint_value(request, _new);\
		RDEBUG3("Overwriting value \"%s\" with \"%s\"", old, new);\
		talloc_free(old);\
		talloc_free(new);\
	}\
} while (0)

/** Convert value_pair_map_t to VALUE_PAIR(s) and add them to a REQUEST.
 *
 * Takes a single value_pair_map_t, resolves request and list identifiers
 * to pointers in the current request, then attempts to retrieve module
 * specific value(s) using callback, and adds the resulting values to the
 * correct request/list.
 *
 * @param request The current request.
 * @param map specifying destination attribute and location and src identifier.
 * @param func to retrieve module specific values and convert them to
 *	VALUE_PAIRS.
 * @param ctx to be passed to func.
 * @param src name to be used in debugging if different from map value.
 * @return -1 if the operation failed, -2 in the source attribute wasn't valid, 0 on success.
 */
int radius_map2request(REQUEST *request, value_pair_map_t const *map,
		       UNUSED char const *src, radius_tmpl_getvalue_t func, void *ctx)
{
	int rcode;
	int num;
	VALUE_PAIR **list, *vp, *dst, *head = NULL;
	bool found = false;
	REQUEST *context;
	TALLOC_CTX *parent;
	vp_cursor_t dst_list, src_list;

	/*
	 *	Sanity check inputs.  We can have a list or attribute
	 *	as a destination.
	 */
	if ((map->dst->type != VPT_TYPE_LIST) &&
	    (map->dst->type != VPT_TYPE_ATTR)) {
		REDEBUG("Invalid mapping destination");
		return -2;
	}

	context = request;
	if (radius_request(&context, map->dst->vpt_request) < 0) {
		REDEBUG("Mapping \"%s\" -> \"%s\" invalid in this context", map->src->name, map->dst->name);
		return -2;
	}

	/*
	 *	If there's no CoA packet and we're updating it,
	 *	auto-allocate it.
	 */
	if (((map->dst->vpt_list == PAIR_LIST_COA) ||
	     (map->dst->vpt_list == PAIR_LIST_DM)) && !request->coa) {
		request_alloc_coa(context);
		context->coa->proxy->code = (map->dst->vpt_list == PAIR_LIST_COA) ?
					    PW_CODE_COA_REQUEST :
					    PW_CODE_DISCONNECT_REQUEST;
	}

	list = radius_list(context, map->dst->vpt_list);
	if (!list) {
		REDEBUG("Mapping \"%s\" -> \"%s\" invalid in this context", map->src->name, map->dst->name);

		return -2;
	}

	parent = radius_list_ctx(context, map->dst->vpt_list);

	/*
	 *	The callback should either return -1 to signify operations error,
	 *	-2 when it can't find the attribute or list being referenced, or
	 *	0 to signify success. It may return "sucess", but still have no
	 *	VPs to work with.
	 */
	rcode = func(&head, request, map, ctx);
	if (rcode < 0) {
		rad_assert(!head);
		return rcode;
	}
	if (!head) return rcode;

	/*
	 *	Reparent the VPs (func may return multiple)
	 */
	for (vp = fr_cursor_init(&src_list, &head);
	     vp;
	     vp = fr_cursor_next(&src_list)) {
		VERIFY_VP(vp);

		if (debug_flag) debug_map(request, map, vp);
		(void) talloc_steal(parent, vp);
	}

	/*
	 *	The destination is a list (which is a completely different set of operations)
	 */
	if (map->dst->type == VPT_TYPE_LIST) {
		switch (map->op) {
		case T_OP_CMP_FALSE:
			/* We don't need the src VPs (should just be 'ANY') */
			pairfree(&head);
			/* Clear the entire dst list */
			pairfree(list);

			if (map->dst->vpt_list == PAIR_LIST_REQUEST) {
				context->username = NULL;
				context->password = NULL;
			}
			return 0;

		case T_OP_SET:
			if (map->src->type == VPT_TYPE_LIST) {
				pairfree(list);
				*list = head;
			} else {
		case T_OP_EQ:
				rad_assert(map->src->type == VPT_TYPE_EXEC);
				pairmove(parent, list, &head);
				pairfree(&head);
			}
			goto finish;

		case T_OP_ADD:
			pairadd(list, head);
			head = NULL;
			goto finish;

		default:
			pairfree(&head);
			return -1;
		}
	}

	/*
	 *	Find the destination attribute.  We leave with either
	 *	the dst_list and vp pointing to the attribute or the VP
	 *	being NULL (no attribute at that index).
	 */
	num = map->dst->vpt_num;
	(void) fr_cursor_init(&dst_list, list);
	if (num != NUM_ANY) {
		while ((dst = fr_cursor_next_by_da(&dst_list, map->dst->vpt_da, map->dst->vpt_tag))) {
			if (num-- == 0) break;
		}
	} else {
		dst = fr_cursor_next_by_da(&dst_list, map->dst->vpt_da, map->dst->vpt_tag);
	}
	rad_assert(!dst || (map->dst->vpt_da == dst->da));

	/*
	 *	The destination is an attribute
	 */
	switch (map->op) {
	default:
		break;
	/*
	 * 	!* - Remove all attributes which match dst in the specified list.
	 *	This doesn't use attributes returned by the func(), and immediately frees them.
	 */
	case T_OP_CMP_FALSE:
		/* We don't need the src VPs (should just be 'ANY') */
		pairfree(&head);
		if (!dst) return 0;

		/*
		 *	Wildcard: delete all of the matching ones, based on tag.
		 */
		if (map->dst->vpt_num == NUM_ANY) {
			pairdelete(list, map->dst->vpt_da->attr, map->dst->vpt_da->vendor, map->dst->vpt_tag);
			dst = NULL;
		/*
		 *	We've found the Nth one.  Delete it, and only it.
		 */
		} else {
			dst = fr_cursor_remove(&dst_list);
			pairfree(&dst);
		}

		/*
		 *	Check that the User-Name and User-Password
		 *	caches point to the correct attribute.
		 */
		goto finish;

	/*
	 *	-= - Delete attributes in the dst list which match any of the
	 *	src_list attributes.
	 *
	 *	This operation has two modes:
	 *	- If map->dst->vpt_num > 0, we check each of the src_list attributes against
	 *	  the dst attribute, to see if any of their values match.
	 *	- If map->dst->vpt_num == NUM_ANY, we compare all instances of the dst attribute
	 *	  against each of the src_list attributes.
	 */
	case T_OP_SUB:
		/* We didn't find any attributes earlier */
		if (!dst) {
			pairfree(&head);
			return 0;
		}

		/*
		 *	Instance specific[n] delete
		 */
		if (map->dst->vpt_num != NUM_ANY) {
			for (vp = fr_cursor_first(&src_list);
			     vp;
			     vp = fr_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = radius_compare_vps(request, vp, dst);
				if (rcode == 0) {
					dst = fr_cursor_remove(&dst_list);
					pairfree(&dst);
					found = true;
				}
			}
			pairfree(&head);
			if (!found) return 0;
			goto finish;
		}

		/*
		 *	All instances[*] delete
		 */
		for (dst = fr_cursor_current(&dst_list);
		     dst;
		     dst = fr_cursor_next_by_da(&dst_list, map->dst->vpt_da, map->dst->vpt_tag)) {
			for (vp = fr_cursor_first(&src_list);
			     vp;
			     vp = fr_cursor_next(&src_list)) {
				head->op = T_OP_CMP_EQ;
				rcode = radius_compare_vps(request, vp, dst);
				if (rcode == 0) {
					dst = fr_cursor_remove(&dst_list);
					pairfree(&dst);
					found = true;
				}
			}
		}
		pairfree(&head);
		if (!found) return 0;
		goto finish;
	}

	/*
	 *	Another fixup pass to set tags on attributes were about to insert
	 */
	if (map->dst->vpt_tag != TAG_ANY) {
		for (vp = fr_cursor_init(&src_list, &head);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			vp->tag = map->dst->vpt_tag;
		}
	}

	switch (map->op) {
	/*
	 *	= - Set only if not already set
	 */
	case T_OP_EQ:
		if (dst) {
			RDEBUG3("Refusing to overwrite (use :=)");
			pairfree(&head);
			return 0;
		}

		/* Insert first instance (if multiple) */
		fr_cursor_first(&src_list);
		fr_cursor_insert(&dst_list, fr_cursor_remove(&src_list));
		/* Free any we didn't insert */
		pairfree(&head);
		break;

	/*
	 *	:= - Overwrite existing attribute with last src_list attribute
	 */
	case T_OP_SET:
		/* Wind to last instance */
		fr_cursor_last(&src_list);
		if (dst) {
			dst = fr_cursor_remove(&dst_list);
			DEBUG_OVERWRITE(dst, fr_cursor_current(&src_list));
			pairfree(&dst);
		}
		fr_cursor_insert(&dst_list, fr_cursor_remove(&src_list));
		/* Free any we didn't insert */
		pairfree(&head);
		break;

	/*
	 *	+= - Add all src_list attributes to the destination
	 */
	case T_OP_ADD:
		/* Insert all the instances! (if multiple) */
		pairadd(list, head);
		head = NULL;
		break;

	/*
	 *	Filtering operators
	 */
	default:
		/*
		 *	If the dst doesn't exist, the filters will add
		 *	it with the given value.
		 */
		if (!dst) {
			RDEBUG3("No existing attribute to filter, adding instead");
			fr_cursor_insert(&dst_list, head);
			head = NULL;
			goto finish;
		}

		/*
		 *	The LHS exists.  We need to limit it's value based on
		 *	the operator, and the value of the RHS.
		 */
		found = false;
		for (vp = fr_cursor_first(&src_list);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			vp->op = map->op;
			rcode = radius_compare_vps(request, vp, dst);
			vp->op = T_OP_SET;

			switch (map->op) {
			case T_OP_CMP_EQ:
				if (rcode == 0) continue;
			replace:
				dst = fr_cursor_remove(&dst_list);
				DEBUG_OVERWRITE(dst, fr_cursor_current(&src_list));
				pairfree(&dst);
				fr_cursor_insert(&dst_list, fr_cursor_remove(&src_list));
				found = true;
				continue;

			case T_OP_LE:
				if (rcode <= 0) continue;
				goto replace;

			case T_OP_GE:
				if (rcode >= 0) continue;
				goto replace;

			default:
				pairfree(&head);
				return -1;
			}
		}
		pairfree(&head);
		if (!found) return 0;

		break;
	}

finish:
	rad_assert(!head);

	if (map->dst->vpt_list == PAIR_LIST_REQUEST) {
		context->username = pairfind(*list, PW_USER_NAME, 0, TAG_ANY);
		context->password = pairfind(*list, PW_USER_PASSWORD, 0, TAG_ANY);
	}
	return 0;
}

/** Process map which has exec as a src
 *
 * Evaluate maps which specify exec as a src. This may be used by various sorts of update sections, and so
 * has been broken out into it's own function.
 *
 * @param[out] out Where to write the VALUE_PAIR(s).
 * @param[in] request structure (used only for talloc).
 * @param[in] map the map. The LHS (dst) must be VPT_TYPE_ATTR or VPT_TYPE_LIST. The RHS (src) must be VPT_TYPE_EXEC.
 * @return -1 on failure, 0 on success.
 */
int radius_mapexec(VALUE_PAIR **out, REQUEST *request, value_pair_map_t const *map)
{
	int result;
	char *expanded = NULL;
	char answer[1024];
	VALUE_PAIR **input_pairs = NULL;
	VALUE_PAIR *output_pairs = NULL;

	*out = NULL;

	rad_assert(map->src->type == VPT_TYPE_EXEC);
	rad_assert((map->dst->type == VPT_TYPE_ATTR) || (map->dst->type == VPT_TYPE_LIST));

	/*
	 *	We always put the request pairs into the environment
	 */
	input_pairs = radius_list(request, PAIR_LIST_REQUEST);

	/*
	 *	Automagically switch output type depending on our destination
	 *	If dst is a list, then we create attributes from the output of the program
	 *	if dst is an attribute, then we create an attribute of that type and then
	 *	call pairparsevalue on the output of the script.
	 */
	result = radius_exec_program(request, map->src->name, true, true,
				     answer, sizeof(answer), EXEC_TIMEOUT,
				     input_pairs ? *input_pairs : NULL,
				     (map->dst->type == VPT_TYPE_LIST) ? &output_pairs : NULL);
	talloc_free(expanded);
	if (result != 0) {
		talloc_free(output_pairs);
		return -1;
	}

	switch (map->dst->type) {
	case VPT_TYPE_LIST:
		if (!output_pairs) {
			REDEBUG("No valid attributes received from program");
			return -2;
		}
		*out = output_pairs;

		return 0;
	case VPT_TYPE_ATTR:
	{
		VALUE_PAIR *vp;

		vp = pairalloc(request, map->dst->vpt_da);
		if (!vp) return -1;
		vp->op = map->op;
		if (!pairparsevalue(vp, answer)) {
			pairfree(&vp);
			return -2;
		}
		*out = vp;

		return 0;
	}
	default:
		rad_assert(0);
	}

	return -1;
}

/** Convert a map to a VALUE_PAIR.
 *
 * @param[out] out Where to write the VALUE_PAIR(s), which may be NULL if not found
 * @param[in] request structure (used only for talloc)
 * @param[in] map the map. The LHS (dst) has to be VPT_TYPE_ATTR or VPT_TYPE_LIST.
 * @param[in] ctx unused
 * @return 0 on success, -1 on failure
 */
int radius_map2vp(VALUE_PAIR **out, REQUEST *request, value_pair_map_t const *map, UNUSED void *ctx)
{
	int rcode = 0;
	VALUE_PAIR *vp = NULL, *found, **from = NULL;
	DICT_ATTR const *da;
	REQUEST *context = request;
	vp_cursor_t cursor;

	*out = NULL;

	/*
	 *	Special case for !*, we don't need to parse RHS as this is a unary operator.
	 */
	if (map->op == T_OP_CMP_FALSE) {
		/*
		 *  Were deleting all the attributes in a list. This isn't like the other
		 *  mappings because lists aren't represented as attributes (yet),
		 *  so we can't return a <list> attribute with the !* operator for
		 *  radius_pairmove() to consume, and need to do the work here instead.
		 */
		if (map->dst->type == VPT_TYPE_LIST) {
			if (radius_request(&context, map->dst->vpt_request) == 0) {
				from = radius_list(context, map->dst->vpt_list);
			}
			if (!from) return 0;

			pairfree(from);

			/* @fixme hacky! */
			if (map->dst->vpt_list == PAIR_LIST_REQUEST) {
				context->username = NULL;
				context->password = NULL;
			}

			return 0;
		}

		/* Not a list, but an attribute, radius_pairmove() will perform that actual delete */
		vp = pairalloc(request, map->dst->vpt_da);
		if (!vp) return -1;
		vp->op = map->op;
		*out = vp;

		return 0;
	}

	/*
	 *	List to list found, this is a special case because we don't need
	 *	to allocate any attributes, just finding the current list, and change
	 *	the op.
	 */
	if ((map->dst->type == VPT_TYPE_LIST) && (map->src->type == VPT_TYPE_LIST)) {
		if (radius_request(&context, map->src->vpt_request) == 0) {
			from = radius_list(context, map->src->vpt_list);
		}
		if (!from) return 0;

		found = paircopy(request, *from);

		/*
		 *	List to list copy is empty if the src list has no attributes.
		 */
		if (!found) return 0;

		for (vp = fr_cursor_init(&cursor, &found);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			vp->op = T_OP_ADD;
		}

		*out = found;

		return 0;
	}

	/*
	 *	Deal with all non-list operations.
	 */
	da = map->dst->vpt_da ? map->dst->vpt_da : map->src->vpt_da;

	switch (map->src->type) {
	case VPT_TYPE_XLAT:
	case VPT_TYPE_XLAT_STRUCT:
	case VPT_TYPE_LITERAL:
	case VPT_TYPE_DATA:
		vp = pairalloc(request, da);
		if (!vp) return -1;
		vp->op = map->op;
		break;
	default:
		break;
	}


	/*
	 *	And parse the RHS
	 */
	switch (map->src->type) {
		ssize_t slen;
		char *str;

	case VPT_TYPE_XLAT_STRUCT:
		rad_assert(map->dst->vpt_da);	/* Need to know where were going to write the new attribute */
		rad_assert(map->src->vpt_xlat != NULL);

		str = NULL;
		slen = radius_axlat_struct(&str, request, map->src->vpt_xlat, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			goto error;
		}

		/*
		 *	We do the debug printing because radius_axlat_struct
		 *	doesn't have access to the original string.  It's been
		 *	mangled during the parsing to xlat_exp_t
		 */
		RDEBUG2("EXPAND %s", map->src->name);
		RDEBUG2("   --> %s", str);

		rcode = pairparsevalue(vp, str);
		talloc_free(str);
		if (!rcode) {
			pairfree(&vp);
			rcode = -1;
			goto error;
		}
		break;

	case VPT_TYPE_XLAT:
		rad_assert(map->dst->vpt_da);	/* Need to know where were going to write the new attribute */

		str = NULL;
		slen = radius_axlat(&str, request, map->src->name, NULL, NULL);
		if (slen < 0) {
			rcode = slen;
			goto error;
		}
		rcode = pairparsevalue(vp, str);
		talloc_free(str);
		if (!rcode) {
			pairfree(&vp);
			rcode = -1;
			goto error;
		}
		break;

	case VPT_TYPE_LITERAL:
		if (!pairparsevalue(vp, map->src->name)) {
			rcode = 0;
			goto error;
		}
		break;

	case VPT_TYPE_ATTR:
		rad_assert(!map->dst->vpt_da ||
			   (map->src->vpt_da->type == map->dst->vpt_da->type) ||
			   (map->src->vpt_da->type == PW_TYPE_OCTETS) ||
			   (map->dst->vpt_da->type == PW_TYPE_OCTETS));

		/*
		 *	Special case, destination is a list, found all instance of an attribute.
		 */
		if (map->dst->type == VPT_TYPE_LIST) {
			context = request;

			if (radius_request(&context, map->src->vpt_request) == 0) {
				from = radius_list(context, map->src->vpt_list);
			}

			/*
			 *	Can't add the attribute if the list isn't
			 *	valid.
			 */
			if (!from) {
				rcode = 0;
				goto error;
			}

			found = paircopy2(request, *from, map->src->vpt_da->attr, map->src->vpt_da->vendor,
					  map->src->vpt_tag);
			if (!found) {
				REDEBUG("Attribute \"%s\" not found in request", map->src->name);
				rcode = 0;
				goto error;
			}

			for (vp = fr_cursor_init(&cursor, &found);
			     vp;
			     vp = fr_cursor_next(&cursor)) {
				vp->op = T_OP_ADD;
			}

			*out = found;
			return 0;
		}

		if (radius_vpt_get_vp(&found, request, map->src) < 0) {
			REDEBUG("Attribute \"%s\" not found in request", map->src->name);
			rcode = 0;
			goto error;
		}

		/*
		 *	Copy the data over verbatim, assuming it's
		 *	actually data.
		 */
		vp = paircopyvpdata(request, da, found);
		if (!vp) {
			return -1;
		}
		vp->op = map->op;

		break;

	case VPT_TYPE_DATA:
		rad_assert(map->src && map->src->vpt_da);
		rad_assert(map->dst && map->dst->vpt_da);
		rad_assert(map->src->vpt_da->type == map->dst->vpt_da->type);
		memcpy(&vp->data, map->src->vpt_value, sizeof(vp->data));
		vp->length = map->src->vpt_length;
		break;

	/*
	 *	This essentially does the same as rlm_exec xlat, except it's non-configurable.
	 *	It's only really here as a convenience for people who expect the contents of
	 *	backticks to be executed in a shell.
	 *
	 *	exec string is xlat expanded and arguments are shell escaped.
	 */
	case VPT_TYPE_EXEC:
		return radius_mapexec(out, request, map);
	default:
		rad_assert(0);	/* Should have been caught at parse time */
	error:
		pairfree(&vp);
		return rcode;
	}

	*out = vp;
	return 0;
}

/** Convert a valuepair string to valuepair map
 *
 * Takes a valuepair string with list and request qualifiers, converts it into a
 * value_pair_map_t and inserts it into the appropriate list.
 *
 * @param out Where to write the new map (must be freed with talloc_free()).
 * @param request Current request.
 * @param raw string to parse.
 * @param dst_request_def to use if attribute isn't qualified.
 * @param dst_list_def to use if attribute isn't qualified.
 * @param src_request_def to use if attribute isn't qualified.
 * @param src_list_def to use if attribute isn't qualified.
 * @return 0 on success, < 0 on error.
 */
int radius_strpair2map(value_pair_map_t **out, REQUEST *request, char const *raw,
		       request_refs_t dst_request_def, pair_lists_t dst_list_def,
		       request_refs_t src_request_def, pair_lists_t src_list_def)
{
	char const *p = raw;
	FR_TOKEN ret;

	VALUE_PAIR_RAW tokens;
	value_pair_map_t *map;

	ret = pairread(&p, &tokens);
	if (ret != T_EOL) {
		REDEBUG("Failed tokenising attribute string: %s", fr_strerror());
		return -1;
	}

	map = radius_str2map(request, tokens.l_opand, T_BARE_WORD, tokens.op, tokens.r_opand, tokens.quote,
			     dst_request_def, dst_list_def, src_request_def, src_list_def);
	if (!map) {
		REDEBUG("Failed parsing attribute string: %s", fr_strerror());
		return -1;
	}
	*out = map;

	return 0;
}

/** Return a VP from a value_pair_tmpl_t
 *
 * @param out where to write the retrieved vp.
 * @param request current request.
 * @param vpt the value pair template
 * @return -1 if VP could not be found, -2 if list could not be found, -3 if context could not be found.
 */
int radius_vpt_get_vp(VALUE_PAIR **out, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	VALUE_PAIR **vps, *vp;

	if (out) *out = NULL;

	if (radius_request(&request, vpt->vpt_request) < 0) {
		return -3;
	}

	vps = radius_list(request, vpt->vpt_list);
	if (!vps) {
		return -2;
	}

	switch (vpt->type) {
		/*
		 *	May not may not be found, but it *is* a known
		 *	name.
		 */
	case VPT_TYPE_ATTR:
	{
		int num;
		vp_cursor_t cursor;

		if (vpt->vpt_num == NUM_ANY) {
			vp = pairfind(*vps, vpt->vpt_da->attr, vpt->vpt_da->vendor, vpt->vpt_tag);
			if (!vp) return -1;
			break;
		}

		(void) fr_cursor_init(&cursor, vps);
		num = vpt->vpt_num;
		while((vp = fr_cursor_next_by_da(&cursor, vpt->vpt_da, vpt->vpt_tag))) {
			VERIFY_VP(vp);
			if (num-- == 0) goto finish;
		}
		return -1;
	}

	case VPT_TYPE_LIST:
		vp = *vps;
		break;

	default:
		/*
		 *	literal, xlat, regex, exec, data.
		 *	no attribute.
		 */
		return -1;
	}

finish:
	if (out) *out = vp;

	return 0;
}

/** Return a VP from the specified request.
 *
 * @param out where to write the pointer to the resolved VP.
 *	Will be NULL if the attribute couldn't be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return -4 if either the attribute or qualifier were invalid, and the same error codes as radius_vpt_get_vp for other
 *	error conditions.
 */
int radius_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name)
{
	value_pair_tmpl_t vpt;

	*out = NULL;

	if (radius_parse_attr(&vpt, name, REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
		return -4;
	}

	return radius_vpt_get_vp(out, request, &vpt);
}

/** Copy pairs matching a VPT in the current request
 *
 * @param out where to write the copied vps.
 * @param request current request.
 * @param vpt the value pair template
 * @return -1 if VP could not be found, -2 if list could not be found, -3 if context could not be found.
 */
int radius_vpt_copy_vp(VALUE_PAIR **out, REQUEST *request, value_pair_tmpl_t const *vpt)
{
	VALUE_PAIR **vps, *vp;
	REQUEST *current = request;

	if (out) *out = NULL;

	if (radius_request(&current, vpt->vpt_request) < 0) {
		return -3;
	}

	vps = radius_list(request, vpt->vpt_list);
	if (!vps) {
		return -2;
	}

	switch (vpt->type) {
	/*
	 *	May not may not be found, but it *is* a known name.
	 */
	case VPT_TYPE_ATTR:
		vp = paircopy2(request, *vps, vpt->vpt_da->attr, vpt->vpt_da->vendor, vpt->vpt_tag);
		if (!vp) {
			return -1;
		}
		break;

	case VPT_TYPE_LIST:
		vp = paircopy(request, *vps);

		break;

	default:
		/*
		 *	literal, xlat, regex, exec, data.
		 *	no attribute.
		 */
		return -1;
	}

	if (out) {
		*out = vp;
	}

	return 0;
}

/** Copy a VP from the specified request.
 *
 * @param out where to write the pointer to the copied VP.
 *	Will be NULL if the attribute couldn't be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return -4 if either the attribute or qualifier were invalid, and the same error codes as radius_vpt_get_vp for other
 *	error conditions.
 */
int radius_copy_vp(VALUE_PAIR **out, REQUEST *request, char const *name)
{
	value_pair_tmpl_t vpt;

	*out = NULL;

	if (radius_parse_attr(&vpt, name, REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
		return -4;
	}

	return radius_vpt_copy_vp(out, request, &vpt);
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

	vp = paircreate(request->packet, PW_MODULE_FAILURE_MESSAGE, 0);
	if (!vp) {
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
	p = talloc_vasprintf(vp, fmt, aq);
	talloc_set_type(p, char);
	va_end(aq);
	if (request->module && *request->module) {
		pairsprintf(vp, "%s: %s", request->module, p);
	} else {
		pairsprintf(vp, "%s", p);
	}
	talloc_free(p);
	pairadd(&request->packet->vps, vp);
}
