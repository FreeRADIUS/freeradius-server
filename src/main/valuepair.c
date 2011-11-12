/** Valuepair functions that are radiusd-specific and as such do not belong in
 * the library.
 *
 * @file main/valuepair.c
 *
 * @ingroup AVP
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_PCREPOSIX_H
#include <pcreposix.h>
#else
#ifdef HAVE_REGEX_H
#	include <regex.h>

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

const FR_NAME_NUMBER pair_lists[] = {
	{ "request",		PAIR_LIST_REQUEST },
	{ "reply",		PAIR_LIST_REPLY },
	{ "config",		PAIR_LIST_CONTROL },
	{ "control",		PAIR_LIST_CONTROL },
#ifdef WITH_PROXY
	{ "proxy-request",	PAIR_LIST_PROXY_REQUEST },
	{ "proxy-reply",	PAIR_LIST_PROXY_REPLY },
#endif
#ifdef WITH_COA
	{ "coa",		PAIR_LIST_COA },
	{ "coa-reply",		PAIR_LIST_COA_REPLY },
	{ "disconnect",		PAIR_LIST_DM },
	{ "disconnect-reply",	PAIR_LIST_DM_REPLY },
#endif
	{  NULL , -1 }
};

struct cmp {
	unsigned int attribute;
	unsigned int otherattr;
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
 * @param request Current request
 * @param check rvalue, and operator
 * @param vp lvalue
 */
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp)
{
	int ret = -2;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->operator == T_OP_CMP_TRUE)  return 0;
	if (check->operator == T_OP_CMP_FALSE) return 1;

#ifdef HAVE_REGEX_H
	if (check->operator == T_OP_REG_EQ) {
		int i, compare;
		regex_t reg;
		char name[1024];
		char value[1024];
		regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

		snprintf(name, sizeof(name), "%%{%s}", check->name);
		radius_xlat(value, sizeof(value), name, request, NULL);

		/*
		 *	Include substring matches.
		 */
		compare = regcomp(&reg, check->vp_strvalue, REG_EXTENDED);
		if (compare != 0) {
			char buffer[256];
			regerror(compare, &reg, buffer, sizeof(buffer));

			RDEBUG("Invalid regular expression %s: %s",
			       check->vp_strvalue, buffer);
			return -1;
		}
		compare = regexec(&reg, value,  REQUEST_MAX_REGEX + 1,
				  rxmatch, 0);
		regfree(&reg);

		/*
		 *	Add %{0}, %{1}, etc.
		 */
		for (i = 0; i <= REQUEST_MAX_REGEX; i++) {
			char *p;
			char buffer[sizeof(check->vp_strvalue)];

			/*
			 *	Didn't match: delete old
			 *	match, if it existed.
			 */
			if ((compare != 0) ||
			    (rxmatch[i].rm_so == -1)) {
				p = request_data_get(request, request,
						     REQUEST_DATA_REGEX | i);
				if (p) {
					free(p);
					continue;
				}

				/*
				 *	No previous match
				 *	to delete, stop.
				 */
				break;
			}

			/*
			 *	Copy substring into buffer.
			 */
			memcpy(buffer, value + rxmatch[i].rm_so,
			       rxmatch[i].rm_eo - rxmatch[i].rm_so);
			buffer[rxmatch[i].rm_eo - rxmatch[i].rm_so] = '\0';

			/*
			 *	Copy substring, and add it to
			 *	the request.
			 *
			 *	Note that we don't check
			 *	for out of memory, which is
			 *	the only error we can get...
			 */
			p = strdup(buffer);
			request_data_add(request, request,
					 REQUEST_DATA_REGEX | i,
					 p, free);
		}
		if (compare == 0) return 0;
		return -1;
	}

	if (check->operator == T_OP_REG_NE) {
		int compare;
		regex_t reg;
		char name[1024];
		char value[1024];
		regmatch_t rxmatch[REQUEST_MAX_REGEX + 1];

		snprintf(name, sizeof(name), "%%{%s}", check->name);
		radius_xlat(value, sizeof(value), name, request, NULL);

		/*
		 *	Include substring matches.
		 */
		compare = regcomp(&reg, (char *)check->vp_strvalue,
				  REG_EXTENDED);
		if (compare != 0) {
			char buffer[256];
			regerror(compare, &reg, buffer, sizeof(buffer));

			RDEBUG("Invalid regular expression %s: %s",
			       check->vp_strvalue, buffer);
			return -1;
		}
		compare = regexec(&reg, value,  REQUEST_MAX_REGEX + 1,
				  rxmatch, 0);
		regfree(&reg);

		if (compare != 0) return 0;
		return -1;

	}
#endif

	/*
	 *	Tagged attributes are equal if and only if both the
	 *	tag AND value match.
	 */
	if (check->flags.has_tag) {
		ret = ((int) vp->flags.tag) - ((int) check->flags.tag);
		if (ret != 0) return ret;
	}

	/*
	 *	Not a regular expression, compare the types.
	 */
	switch(check->type) {
#ifdef ASCEND_BINARY
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
			ret = strcmp((char *)vp->vp_strvalue,
				     (char *)check->vp_strvalue);
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

	return ret;
}


/** Compare check and vp. May call the attribute compare function.
 *
 * Unlike radius_compare_vps() this function will call any attribute-specific
 * comparison function.
 *
 * @param req Current request
 * @param request value pairs in the reqiest
 * @param check
 * @param check_pairs
 * @param reply_pairs value pairs in the reply
 * @return 
 */
int radius_callback_compare(REQUEST *req, VALUE_PAIR *request,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs)
{
	struct cmp *c;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if (check->operator == T_OP_CMP_TRUE)  return 0;
	if (check->operator == T_OP_CMP_FALSE) return 1;

	/*
	 *	See if there is a special compare function.
	 *
	 *	FIXME: use new RB-Tree code.
	 */
	for (c = cmp; c; c = c->next) {
		if ((c->attribute == check->attribute) &&
		    (check->vendor == 0)) {
			return (c->compare)(c->instance, req, request, check,
				check_pairs, reply_pairs);
		}
	}

	if (!request) return -1; /* doesn't exist, don't compare it */

	return radius_compare_vps(req, check, request);
}


/** Find a comparison function for two attributes.
 *
 * @param attribute
 */
int radius_find_compare(unsigned int attribute)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->attribute == attribute) {
			return TRUE;
		}
	}

	return FALSE;
}


/** See what attribute we want to compare with.
 *
 * @param attribute
 */
static int otherattr(unsigned int attribute)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->attribute == attribute) {
			return c->otherattr;
		}
	}

	return attribute;
}

/** Register a function as compare function.
 *
 * @param attribute
 * @param other_attr we want to compare with. Normally this is the
 *	same as attribute.
 * You can set this to:
 *	- -1	The same as attribute.
 *	- 0	Always call compare function, not tied to request attribute.
 *	- >0	Attribute to compare with. For example, PW_GROUP in a check
 *		item needs to be compared with PW_USER_NAME in the incoming request.
 * @param func comparison function
 * @param instance argument to comparison function
 * @return 0
 */
int paircompare_register(unsigned int attribute, int other_attr, 
			 RAD_COMPARE_FUNC func, void *instance)
{
	struct cmp *c;

	paircompare_unregister(attribute, func);

	c = rad_malloc(sizeof(struct cmp));

	c->compare   = func;
	c->attribute = attribute;
	c->otherattr = other_attr;
	c->instance  = instance;
	c->next      = cmp;
	cmp = c;

	return 0;
}

/** Unregister comparison function for an attribute
 *
 * @param attribute attribute to unregister for.
 * @param func comparison function to remove.
 * @return Void.
 */
void paircompare_unregister(unsigned int attribute, RAD_COMPARE_FUNC func)
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

/** Compare two pair lists except for the password information.
 *
 * For every element in "check" at least one matching copy must be present
 * in "reply".
 *
 * @param req Current request
 * @param request request valuepairs
 * @param check check/control valuepairs
 * @param[in,out] reply reply value pairs
 *
 * @return 0 on match.
 */
int paircompare(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
		VALUE_PAIR **reply)
{
	VALUE_PAIR *check_item;
	VALUE_PAIR *auth_item;
	
	int result = 0;
	int compare;
	int other;

	for (check_item = check;
	     check_item != NULL;
	     check_item = check_item->next) {
		/*
		 *	If the user is setting a configuration value,
		 *	then don't bother comparing it to any attributes
		 *	sent to us by the user.  It ALWAYS matches.
		 */
		if ((check_item->operator == T_OP_SET) ||
		    (check_item->operator == T_OP_ADD)) {
			continue;
		}

		switch (check_item->attribute) {
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
				if (check_item->operator == T_OP_CMP_EQ) {
					DEBUG("WARNING: Found User-Password == \"...\".");
					DEBUG("WARNING: Are you sure you don't mean Cleartext-Password?");
					DEBUG("WARNING: See \"man rlm_pap\" for more information.");
				}
				if (pairfind(request, PW_USER_PASSWORD, 0) == NULL) {
					continue;
				}
				break;
		}

		/*
		 *	See if this item is present in the request.
		 */
		other = otherattr(check_item->attribute);

		auth_item = request;
	try_again:
		if (other >= 0) {
			while (auth_item != NULL) {
				if ((auth_item->attribute == 
				    (unsigned int) other) ||
				    (other == 0)) {
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
			if (check_item->operator == T_OP_CMP_FALSE) {
				continue;
			} else {
				return -1;
			}
		}

		/*
		 *	Else we found it, but we were trying to not
		 *	find it, so we failed.
		 */
		if (check_item->operator == T_OP_CMP_FALSE) {
			return -1;
		}


		/*
		 *	We've got to xlat the string before doing
		 *	the comparison.
		 */
		if (check_item->flags.do_xlat) {
			int rcode;
			char buffer[sizeof(check_item->vp_strvalue)];

			check_item->flags.do_xlat = 0;
			rcode = radius_xlat(buffer, sizeof(buffer),
					    check_item->vp_strvalue,
					    req, NULL);

			/*
			 *	Parse the string into a new value.
			 */
			pairparsevalue(check_item, buffer);
		}

		/*
		 *	OK it is present now compare them.
		 */
		compare = radius_callback_compare(req, auth_item, check_item,
						  check, reply);

		switch (check_item->operator) {
			case T_OP_EQ:
			default:
				radlog(L_INFO,  "Invalid operator for item %s: "
						"reverting to '=='", check_item->name);

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
		if ((result != 0) && (other >= 0)) {
			auth_item = auth_item->next;
			result = 0;
			goto try_again;
		}

	} /* for every entry in the check item list */

	return result;
}

/** Move pairs, replacing/over-writing them, and doing xlat.
 *
 * Move attributes from one list to the other if not already present.
 */
void pairxlatmove(REQUEST *req, VALUE_PAIR **to, VALUE_PAIR **from)
{
	VALUE_PAIR **tailto, *i, *j, *next;
	VALUE_PAIR *tailfrom = NULL;
	VALUE_PAIR *found;

	/*
	 *	Point "tailto" to the end of the "to" list.
	 */
	tailto = to;
	for (i = *to; i; i = i->next) {
		tailto = &i->next;
	}

	/*
	 *	Loop over the "from" list.
	 */
	for (i = *from; i; i = next) {
		next = i->next;

		/*
		 *	Don't move 'fallthrough' over.
		 */
		if (i->attribute == PW_FALL_THROUGH) {
			tailfrom = i;
			continue;
		}

		/*
		 *	We've got to xlat the string before moving
		 *	it over.
		 */
		if (i->flags.do_xlat) {
			int rcode;
			char buffer[sizeof(i->vp_strvalue)];

			i->flags.do_xlat = 0;
			rcode = radius_xlat(buffer, sizeof(buffer),
					    i->vp_strvalue,
					    req, NULL);

			/*
			 *	Parse the string into a new value.
			 */
			pairparsevalue(i, buffer);
		}

		found = pairfind(*to, i->attribute, i->vendor);
		switch (i->operator) {

			/*
			 *	If a similar attribute is found,
			 *	delete it.
			 */
			case T_OP_SUB:		/* -= */
				if (found) {
					if (!i->vp_strvalue[0] ||
				    	    (strcmp((char *)found->vp_strvalue,
					    	    (char *)i->vp_strvalue) == 0)) {
				  		pairdelete(to, found->attribute,
				  			found->vendor);

					/*
					 *	'tailto' may have been
					 *	deleted...
					 */
					tailto = to;
					for (j = *to; j; j = j->next) {
						tailto = &j->next;
					}
				}
			}
			tailfrom = i;
			continue;
			break;

			/*
			 *	Add it, if it's not already there.
			 */
			case T_OP_EQ:		/* = */
				if (found) {
					tailfrom = i;
					continue; /* with the loop */
				}
				break;

			/*
			 *	If a similar attribute is found,
			 *	replace it with the new one.  Otherwise,
			 *	add the new one to the list.
			 */
			case T_OP_SET:		/* := */
				if (found) {
					VALUE_PAIR *vp;

					vp = found->next;
					memcpy(found, i, sizeof(*found));
					found->next = vp;
					tailfrom = i;
					continue;
				}
				break;

			/*
			 *	FIXME: Add support for <=, >=, <, >
			 *
			 *	which will mean (for integers)
			 *	'make the attribute the smaller, etc'
			 */

			/*
			 *  Add the new element to the list, even
			 *  if similar ones already exist.
			 */
			default:
			case T_OP_ADD:		/* += */
				break;
		}

		if (tailfrom) {
			tailfrom->next = next;
		} else {
			*from = next;
		}

		/*
		 *	If ALL of the 'to' attributes have been deleted,
		 *	then ensure that the 'tail' is updated to point
		 *	to the head.
		 */
		if (!*to) {
			tailto = to;
		}
		*tailto = i;
		if (i) {
			i->next = NULL;
			tailto = &i->next;
		}
	} /* loop over the 'from' list */
}

/** Create a pair and add it to a particular list of VPs
 *
 * Note that this function ALWAYS returns. If we're OOM, then it causes the
 * server to exit!
 */
VALUE_PAIR *radius_paircreate(UNUSED REQUEST *request, VALUE_PAIR **vps,
			      unsigned int attribute, unsigned int vendor, int type)
{
	VALUE_PAIR *vp;

	vp = paircreate(attribute, vendor, type);
	if (!vp) {
		radlog(L_ERR, "No memory!");
		rad_assert("No memory" == NULL);
		_exit(1);
	}

	if (vps) pairadd(vps, vp);

	return vp;
}

/** Create a pair, and add it to a particular list of VPs
 *
 * Note that this function ALWAYS returns.  If we're OOM, then it causes the
 * server to exit!
 *
 * @param[in] request current request.
 * @param[in] vps to modify.
 * @param[in] attribute name.
 * @param[in] value attribute value.
 * @param[in] operator fr_tokens value.
 * @return a new VALUE_PAIR.
 */
VALUE_PAIR *radius_pairmake(UNUSED REQUEST *request, VALUE_PAIR **vps,
			    const char *attribute, const char *value,
			    int operator)
{
	VALUE_PAIR *vp;

	vp = pairmake(attribute, value, operator);
	if (!vp) return NULL;

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
	if (!vp || !debug_flag || !fr_log_fp) return;

	while (vp) {
		vp_print(fr_log_fp, vp);
		vp = vp->next;
	}
	fflush(fr_log_fp);
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
			return &request->proxy->vps;

		case PAIR_LIST_PROXY_REPLY:
			return &request->proxy_reply->vps;
#endif
#ifdef WITH_COA
		case PAIR_LIST_COA:
			if (request->coa &&
			    (request->coa->proxy->code == PW_COA_REQUEST)) {
				return &request->coa->proxy->vps;
			}
			break;

		case PAIR_LIST_COA_REPLY:
			if (request->coa && /* match reply with request */
			    (request->coa->proxy->code == PW_COA_REQUEST) &&
			    request->coa->proxy_reply) {
				return &request->coa->proxy_reply->vps;
			}
			break;

		case PAIR_LIST_DM:
			if (request->coa &&
			    (request->coa->proxy->code == PW_DISCONNECT_REQUEST)) {
				return &request->coa->proxy->vps;
			}
			break;

		case PAIR_LIST_DM_REPLY:
			if (request->coa && /* match reply with request */
			    (request->coa->proxy->code == PW_DISCONNECT_REQUEST) &&
			    request->coa->proxy_reply) {
			   	return &request->coa->proxy->vps;
			}
			break;
#endif
	}
	
	return NULL;
}

/** Resolve attribute name to a list.
 *
 * Check the name string for qualifiers that specify a list and return
 * an pair_lists_t value for that list. This value may be passed to
 * radius_list, along with the current request, to get a pointer to the
 * actual list in the request.
 * 
 * If qualifiers were consumed, write a new pointer into name to the
 * char after the last qualifier to be consumed.
 *
 * radius_list_name should be called before passing a name string that
 * may contain qualifiers to dict_attrbyname.
 *
 * @see dict_attrbyname
 *
 * @param[in,out] name of attribute.
 * @param[in] unknown the list to return if no qualifiers were found.
 * @return PAIR_LIST_UNKOWN if qualifiers couldn't be resolved to a list.
 */
pair_lists_t radius_list_name(const char **name, pair_lists_t unknown)
{
	const char *p = *name;
	const char *q;
	
	/* This should never be a NULL pointer or zero length string */
	rad_assert(name && *name);

	/*
	 *	We couldn't determine the list if:
	 *	
	 * 	A colon delimiter was found, but the next char was a 
	 *	number, indicating a tag, not a list qualifier.
	 *
	 *	No colon was found and the first char was upper case 
	 *	indicating an attribute.
	 *
	 *	This allows the function to be used to resolve list names too.
	 */
	q = strchr(p, ':');
	if (((q && (q[1] >= '0') && (q[1] <= '9'))) ||
	    (!q && isupper((int) *p))) {
		return unknown;
	}
	
	if (q) {
		*name = (q + 1);	/* Consume the list and delimiter */
	} else {
		q = (p + strlen(p));	/* Consume the entire string */
		*name = q;
	}
	
	return fr_substr2int(pair_lists, p, PAIR_LIST_UNKNOWN, (q - p));
}

/** Resolve attribute name to a request.
 * 
 * Check the name string for qualifiers that reference a parent request and
 * write the pointer to this request to 'request'.
 *
 * If qualifiers were consumed, write a new pointer into name to the
 * char after the last qualifier to be consumed.
 *
 * radius_ref_request should be called before radius_list_name.
 *
 * @see radius_list_name
 * @param[in,out] request current request.
 * @param[in,out] name of attribute.
 * @return FALSE if qualifiers found but not in a tunnel, else TRUE.
 */
int radius_ref_request(REQUEST **request, const char **name)
{
	rad_assert(name && *name);
	rad_assert(request && *request);
	
	if (strncmp(*name, "outer.", 6) == 0) {
		if (!(*request)->parent) {
			return FALSE;
		}
		*request = (*request)->parent;
		*name += 6;
	}
	
	return TRUE;
}

/** Return a VP from the specified request.
 *
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @param vp_p where to write the pointer to the resolved VP. 
 *	Will be NULL if the attribute couldn't be resolved.
 * @return False if either the attribute or qualifier were invalid, else true
 */
int radius_get_vp(REQUEST *request, const char *name, VALUE_PAIR **vp_p)
{
	VALUE_PAIR **vps;
	pair_lists_t list;
	
	const DICT_ATTR *da;
	
	*vp_p = NULL;
	
	if (!radius_ref_request(&request, &name)) {
		RDEBUG("WARNING: Attribute name refers to outer request"
		       " but not in a tunnel.");
		return TRUE;	/* Discuss, we don't actually know if
				   the attrname was valid... */
	}
	
	list = radius_list_name(&name, PAIR_LIST_REQUEST);
	if (list == PAIR_LIST_UNKNOWN) {
		RDEBUG("ERROR: Invalid list qualifier");
		return FALSE;
	}
	
	da = dict_attrbyname(name);
	if (!da) {
		RDEBUG("ERROR: Attribute \"%s\" unknown", name);
		return FALSE;
	}

	vps = radius_list(request, list);
	rad_assert(vps);
	
	/*
	 *	May not may not be found, but it *is* a known name.
	 */
	*vp_p = pairfind(*vps, da->attr, da->vendor);
	return TRUE;
}
