/*
 * valuepair.c	Valuepair functions that are radiusd-specific
 *		and as such do not belong in the library.
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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

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

struct cmp {
	int attribute;
	int otherattr;
	void *instance; /* module instance */
	RAD_COMPARE_FUNC compare;
	struct cmp *next;
};
static struct cmp *cmp;

int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp)
{
	int ret = -2;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if( check->operator == T_OP_CMP_TRUE )
	         return 0;
	if( check->operator == T_OP_CMP_FALSE )
	         return 1;

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


/*
 *	Compare 2 attributes. May call the attribute compare function.
 */
int radius_callback_compare(REQUEST *req, VALUE_PAIR *request,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs)
{
	struct cmp *c;

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if( check->operator == T_OP_CMP_TRUE )
	         return 0;  /* always return 0/EQUAL */
	if( check->operator == T_OP_CMP_FALSE )
	         return 1;  /* always return 1/NOT EQUAL */

	/*
	 *	See if there is a special compare function.
	 *
	 *	FIXME: use new RB-Tree code.
	 */
	for (c = cmp; c; c = c->next)
		if (c->attribute == check->attribute) {
			return (c->compare)(c->instance, req, request, check,
				check_pairs, reply_pairs);
		}

	if (!request) return -1; /* doesn't exist, don't compare it */

	return radius_compare_vps(req, check, request);
}


/*
 *	Find a comparison function for two attributes.
 */
int radius_find_compare(int attribute)
{
	struct cmp *c;

	for (c = cmp; c; c = c->next) {
		if (c->attribute == attribute) {
			return TRUE;
		}
	}

	return FALSE;
}


/*
 *	See what attribute we want to compare with.
 */
static int otherattr(int attr)
{
	struct cmp	*c;

	for (c = cmp; c; c = c->next) {
		if (c->attribute == attr)
			return c->otherattr;
	}

	return attr;
}

/*
 *	Register a function as compare function.
 *	compare_attr is the attribute in the request we want to
 *	compare with. Normally this is the same as "attr".
 *	You can set this to:
 *
 *	-1   the same as "attr"
 *	0    always call compare function, not tied to request attribute
 *	>0   Attribute to compare with.
 *
 *	For example, PW_GROUP in a check item needs to be compared
 *	with PW_USER_NAME in the incoming request.
 */
int paircompare_register(int attr, int compare_attr, RAD_COMPARE_FUNC fun, void *instance)
{
	struct cmp	*c;

	paircompare_unregister(attr, fun);

	c = rad_malloc(sizeof(struct cmp));

	c->compare = fun;
	c->attribute = attr;
	c->otherattr = compare_attr;
	c->instance = instance;
	c->next = cmp;
	cmp = c;

	return 0;
}

/*
 *	Unregister a function.
 */
void paircompare_unregister(int attr, RAD_COMPARE_FUNC fun)
{
	struct cmp	*c, *last;

	last = NULL;
	for (c = cmp; c; c = c->next) {
		if (c->attribute == attr && c->compare == fun)
			break;
		last = c;
	}

	if (c == NULL) return;

	if (last != NULL)
		last->next = c->next;
	else
		cmp = c->next;

	free(c);
}

/*
 *	Compare two pair lists except for the password information.
 *	For every element in "check" at least one matching copy must
 *	be present in "reply".
 *
 *	Return 0 on match.
 */
int paircompare(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check, VALUE_PAIR **reply)
{
	VALUE_PAIR *check_item;
	VALUE_PAIR *auth_item;
	int result = 0;
	int compare;
	int other;

	for (check_item = check; check_item != NULL; check_item = check_item->next) {
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
				if (pairfind(request, PW_USER_PASSWORD) == NULL) {
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
			for (; auth_item != NULL; auth_item = auth_item->next) {
				if (auth_item->attribute == other || other == 0)
					break;
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
			if (check_item->operator == T_OP_CMP_FALSE)
				continue;
			else
				return -1;
		}

		/*
		 *	Else we found it, but we were trying to not
		 *	find it, so we failed.
		 */
		if (check_item->operator == T_OP_CMP_FALSE)
			return -1;


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
				/*FALLTHRU*/
		        case T_OP_CMP_TRUE:    /* compare always == 0 */
		        case T_OP_CMP_FALSE:   /* compare always == 1 */
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

/*
 *	Move pairs, replacing/over-writing them, and doing xlat.
 */
/*
 *	Move attributes from one list to the other
 *	if not already present.
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
	for(i = *to; i; i = i->next) {
		tailto = &i->next;
	}

	/*
	 *	Loop over the "from" list.
	 */
	for(i = *from; i; i = next) {
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

		found = pairfind(*to, i->attribute);
		switch (i->operator) {

			/*
			 *  If a similar attribute is found,
			 *  delete it.
			 */
		case T_OP_SUB:		/* -= */
			if (found) {
				if (!i->vp_strvalue[0] ||
				    (strcmp((char *)found->vp_strvalue,
					    (char *)i->vp_strvalue) == 0)){
					pairdelete(to, found->attribute);

					/*
					 *	'tailto' may have been
					 *	deleted...
					 */
					tailto = to;
					for(j = *to; j; j = j->next) {
						tailto = &j->next;
					}
				}
			}
			tailfrom = i;
			continue;
			break;

			/*
			 *  Add it, if it's not already there.
			 */
		case T_OP_EQ:		/* = */
			if (found) {
				tailfrom = i;
				continue; /* with the loop */
			}
			break;

			/*
			 *  If a similar attribute is found,
			 *  replace it with the new one.  Otherwise,
			 *  add the new one to the list.
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
			 *  FIXME: Add support for <=, >=, <, >
			 *
			 *  which will mean (for integers)
			 *  'make the attribute the smaller, etc'
			 */

			/*
			 *  Add the new element to the list, even
			 *  if similar ones already exist.
			 */
		default:
		case T_OP_ADD:		/* += */
			break;
		}

		if (tailfrom)
			tailfrom->next = next;
		else
			*from = next;

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

/*
 *	Create a pair, and add it to a particular list of VPs
 *
 *	Note that this function ALWAYS returns.  If we're OOM, then
 *	it causes the server to exit!
 */
VALUE_PAIR *radius_paircreate(REQUEST *request, VALUE_PAIR **vps,
			      int attribute, int type)
{
	VALUE_PAIR *vp;

	request = request;	/* -Wunused */

	vp = paircreate(attribute, type);
	if (!vp) {
		radlog(L_ERR, "No memory!");
		rad_assert("No memory" == NULL);
		_exit(1);
	}

	if (vps) pairadd(vps, vp);

	return vp;
}

/*
 *	Create a pair, and add it to a particular list of VPs
 *
 *	Note that this function ALWAYS returns.  If we're OOM, then
 *	it causes the server to exit!
 */
VALUE_PAIR *radius_pairmake(REQUEST *request, VALUE_PAIR **vps,
			    const char *attribute, const char *value,
			    int operator)
{
	VALUE_PAIR *vp;

	request = request;	/* -Wunused */

	vp = pairmake(attribute, value, operator);
	if (!vp) return NULL;

	if (vps) pairadd(vps, vp);

	return vp;
}

void debug_pair(VALUE_PAIR *vp)
{
	if (!vp || !debug_flag || !fr_log_fp) return;

	fputc('\t', fr_log_fp);
	vp_print(fr_log_fp, vp);
	fputc('\n', fr_log_fp);
}

void debug_pair_list(VALUE_PAIR *vp)
{
	if (!vp || !debug_flag || !fr_log_fp) return;

	while (vp) {
		fputc('\t', fr_log_fp);
		vp_print(fr_log_fp, vp);
		fputc('\n', fr_log_fp);
		vp = vp->next;
	}
	fflush(fr_log_fp);
}
