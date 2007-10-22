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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

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

#include "radiusd.h"

struct cmp {
	int attribute;
	int otherattr;
	void *instance; /* module instance */
	RAD_COMPARE_FUNC compare;
	struct cmp *next;
};
static struct cmp *cmp;


/*
 *	Compare 2 attributes. May call the attribute compare function.
 */
static int paircompare(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
		       VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	int ret = -2;
	struct cmp *c;

	/*
	 *	Sanity check.
	 */
#if 0
	if (request->attribute != check->attribute)
		return -2;
#endif

	/*
	 *      Check for =* and !* and return appropriately
	 */
	if( check->operator == T_OP_CMP_TRUE )
	         return 0;  /* always return 0/EQUAL */
	if( check->operator == T_OP_CMP_FALSE )
	         return 1;  /* always return 1/NOT EQUAL */

	/*
	 *	See if there is a special compare function.
	 */
	for (c = cmp; c; c = c->next)
		if (c->attribute == check->attribute)
			return (c->compare)(c->instance, req, request, check,
				check_pairs, reply_pairs);

	switch(check->type) {
#ifdef ASCEND_BINARY
		/*
		 *	Ascend binary attributes can be treated
		 *	as opaque objects, I guess...
		 */
		case PW_TYPE_ABINARY:
#endif
		case PW_TYPE_OCTETS:
			if (request->length != check->length) {
				ret = 1; /* NOT equal */
				break;
			}
			ret = memcmp(request->strvalue, check->strvalue,
					request->length);
			break;
		case PW_TYPE_STRING:
			ret = strcmp((char *)request->strvalue,
					(char *)check->strvalue);
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_DATE:
			ret = request->lvalue - check->lvalue;
			break;
		case PW_TYPE_IPADDR:
			ret = ntohl(request->lvalue) - ntohl(check->lvalue);
			break;
		default:
			break;
	}

	return ret;
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

	if (compare_attr < 0)
		compare_attr = attr;
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
int paircmp(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check, VALUE_PAIR **reply)
{
	VALUE_PAIR *check_item;
	VALUE_PAIR *auth_item;
	int result = 0;
	int compare;
	int other;
#ifdef HAVE_REGEX_H
	regex_t reg;
#endif

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
			case PW_PASSWORD:
				if (pairfind(request, PW_PASSWORD) == NULL) {
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
		for (; auth_item != NULL; auth_item = auth_item->next) {
			if (auth_item->attribute == other || other == 0)
				break;
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
			char buffer[sizeof(check_item->strvalue)];

			check_item->flags.do_xlat = 0;
			rcode = radius_xlat(buffer, sizeof(buffer),
					    check_item->strvalue,
					    req, NULL);

			/*
			 *	Parse the string into a new value.
			 */
			pairparsevalue(check_item, buffer);
		}

		/*
		 *	OK it is present now compare them.
		 */
		compare = paircompare(req, auth_item, check_item, check, reply);

		switch (check_item->operator) {
			case T_OP_EQ:
			default:
				radlog(L_ERR,  "Invalid operator for item %s: "
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
			{
				int i;
				regmatch_t rxmatch[9];

				/*
				 *	Include substring matches.
				 */
				regcomp(&reg, (char *)check_item->strvalue,
					REG_EXTENDED);
				compare = regexec(&reg,
						  (char *)auth_item->strvalue,
						  REQUEST_MAX_REGEX + 1,
						  rxmatch, 0);
				regfree(&reg);

				/*
				 *	Add %{0}, %{1}, etc.
				 */
				for (i = 0; i <= REQUEST_MAX_REGEX; i++) {
					char *p;
					char buffer[sizeof(check_item->strvalue)];

					/*
					 *	Didn't match: delete old
					 *	match, if it existed.
					 */
					if ((compare != 0) ||
					    (rxmatch[i].rm_so == -1)) {
						p = request_data_get(req, req,
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
					memcpy(buffer,
					       auth_item->strvalue + rxmatch[i].rm_so,
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
					request_data_add(req,
							 req,
							 REQUEST_DATA_REGEX | i,
							 p, free);
				}
			}				
				if (compare != 0) result = -1;
				break;

			case T_OP_REG_NE:
				regcomp(&reg, (char *)check_item->strvalue, REG_EXTENDED|REG_NOSUB);
				compare = regexec(&reg, (char *)auth_item->strvalue,
						0, NULL, 0);
				regfree(&reg);
				if (compare == 0) result = -1;
				break;
#endif

		} /* switch over the operator of the check item */

		/*
		 *	This attribute didn't match, but maybe there's
		 *	another of the same attribute, which DOES match.
		 */
		if (result != 0) {
			auth_item = auth_item->next;
			result = 0;
			goto try_again;
		}

	} /* for every entry in the check item list */

	return 0;		/* it matched */
}

/*
 *      Compare two attributes simply.  Calls paircompare.
 */

int simplepaircmp(REQUEST *req, VALUE_PAIR *first, VALUE_PAIR *second)
{
	return paircompare( req, first, second, NULL, NULL );
}


/*
 *	Compare a Connect-Info and a Connect-Rate
 */
static int connectcmp(void *instance,
		      REQUEST *req UNUSED,
		      VALUE_PAIR *request,
		      VALUE_PAIR *check,
		      VALUE_PAIR *check_pairs,
		      VALUE_PAIR **reply_pairs)
{
	int rate;

	instance = instance;
	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	rate = atoi((char *)request->strvalue);
	return rate - check->lvalue;
}


/*
 *	Compare a portno with a range.
 */
static int portcmp(void *instance,
		   REQUEST *req UNUSED, VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	char buf[MAX_STRING_LEN];
	char *s, *p;
	uint32_t lo, hi;
	uint32_t port = request->lvalue;

	instance = instance;
	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	if ((strchr((char *)check->strvalue, ',') == NULL) &&
			(strchr((char *)check->strvalue, '-') == NULL)) {
		return (request->lvalue - check->lvalue);
	}

	/* Same size */
	strcpy(buf, (char *)check->strvalue);
	s = strtok(buf, ",");

	while (s != NULL) {
		if ((p = strchr(s, '-')) != NULL)
			p++;
		else
			p = s;
		lo = strtoul(s, NULL, 10);
		hi = strtoul(p, NULL, 10);
		if (lo <= port && port <= hi) {
			return 0;
		}
		s = strtok(NULL, ",");
	}

	return -1;
}

/*
 *	Compare prefix/suffix.
 *
 *	If they compare:
 *	- if PW_STRIP_USER_NAME is present in check_pairs,
 *	  strip the username of prefix/suffix.
 *	- if PW_STRIP_USER_NAME is not present in check_pairs,
 *	  add a PW_STRIPPED_USER_NAME to the request.
 */
static int presufcmp(void *instance,
		     REQUEST *req UNUSED,
		     VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	VALUE_PAIR *vp;
	char *name = (char *)request->strvalue;
	char rest[MAX_STRING_LEN];
	int len, namelen;
	int ret = -1;

	instance = instance;
	reply_pairs = reply_pairs; /* shut the compiler up */

#if 0 /* DEBUG */
	printf("Comparing %s and %s, check->attr is %d\n",
		name, check->strvalue, check->attribute);
#endif

	len = strlen((char *)check->strvalue);
	switch (check->attribute) {
		case PW_PREFIX:
			ret = strncmp(name, (char *)check->strvalue, len);
			if (ret == 0 && rest)
				strcpy(rest, name + len);
			break;
		case PW_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len,
					(char *)check->strvalue);
			if (ret == 0 && rest) {
				strNcpy(rest, name, namelen - len + 1);
			}
			break;
	}
	if (ret != 0)
		return ret;

	if ((vp = pairfind(check_pairs, PW_STRIP_USER_NAME)) != NULL) {
		if (vp->lvalue == 1) {
			/*
			 *	I don't think we want to update the User-Name
			 *	attribute in place... - atd
			 */
			strcpy((char *)request->strvalue, rest);
			request->length = strlen(rest);
		} else {
			return ret;
		}
	} else {
		if ((vp = pairfind(check_pairs, PW_STRIPPED_USER_NAME)) != NULL){
			strcpy((char *)vp->strvalue, rest);
			vp->length = strlen(rest);
		} else if ((vp = paircreate(PW_STRIPPED_USER_NAME,
				PW_TYPE_STRING)) != NULL) {
			strcpy((char *)vp->strvalue, rest);
			vp->length = strlen(rest);
			pairadd(&request, vp);
		} /* else no memory! Die, die!: FIXME!! */
	}

	return ret;
}


/*
 *	Compare the current time to a range.
 */
static int timecmp(void *instance,
		   REQUEST *req UNUSED,
		   VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	instance = instance;
	request = request;	/* shut the compiler up */
	check_pairs = check_pairs;
	reply_pairs = reply_pairs;

	if (timestr_match((char *)check->strvalue,
			  req ? req->timestamp : time(NULL)) >= 0) {
		return 0;
	}
	return -1;
}

/*
 *	Matches if there is NO SUCH ATTRIBUTE as the one named
 *	in check->strvalue.  If there IS such an attribute, it
 *	doesn't match.
 *
 *	This is ugly, and definitely non-optimal.  We should be
 *	doing the lookup only ONCE, and storing the result
 *	in check->lvalue...
 */
static int attrcmp(void *instance,
		   REQUEST *req UNUSED,
		   VALUE_PAIR *request, VALUE_PAIR *check,
		   VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	VALUE_PAIR *pair;
	DICT_ATTR  *dict;
	int attr;

	instance = instance;
	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	if (check->lvalue == 0) {
		dict = dict_attrbyname((char *)check->strvalue);
		if (dict == NULL) {
			return -1;
		}
		attr = dict->attr;
	} else {
		attr = check->lvalue;
	}

	/*
	 *	If there's no such attribute, then return MATCH,
	 *	else FAILURE.
	 */
	pair = pairfind(request, attr);
	if (pair == NULL) {
		return 0;
	}

	return -1;
}

/*
 *	Compare the expiration date.
 */
static int expirecmp(void *instance, REQUEST *req UNUSED,
		     VALUE_PAIR *request, VALUE_PAIR *check,
		     VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	time_t now;

	instance = instance;
	request = request;	/* shut the compiler up */
	check_pairs = check_pairs;
	reply_pairs = reply_pairs;

	/*
	 *  FIXME!  This should be request->timestamp!
	 */
	now = time(NULL);

	if (now <= (signed)check->lvalue) {
		return 0;
	}

	return +1;
}

/*
 *	Compare the request packet type.
 */
static int packetcmp(void *instance UNUSED, REQUEST *req,
		     VALUE_PAIR *request UNUSED,
		     VALUE_PAIR *check,
		     VALUE_PAIR *check_pairs UNUSED,
		     VALUE_PAIR **reply_pairs UNUSED)
{
	if (req->packet->code == check->lvalue) {
		return 0;
	}

	return 1;
}

/*
 *	Compare the response packet type.
 */
static int responsecmp(void *instance UNUSED,
		       REQUEST *req,
		       VALUE_PAIR *request UNUSED,
		       VALUE_PAIR *check,
		       VALUE_PAIR *check_pairs UNUSED,
		       VALUE_PAIR **reply_pairs UNUSED)
{
	if (req->reply->code == check->lvalue) {
		return 0;
	}

	return 1;
}

/*
 *	Register server-builtin special attributes.
 */
void pair_builtincompare_init(void)
{
	paircompare_register(PW_NAS_PORT, -1, portcmp, NULL);
	paircompare_register(PW_PREFIX, PW_USER_NAME, presufcmp, NULL);
	paircompare_register(PW_SUFFIX, PW_USER_NAME, presufcmp, NULL);
	paircompare_register(PW_CONNECT_RATE, PW_CONNECT_INFO, connectcmp, NULL);
	paircompare_register(PW_CURRENT_TIME, 0, timecmp, NULL);
	paircompare_register(PW_NO_SUCH_ATTRIBUTE, 0, attrcmp, NULL);
	paircompare_register(PW_EXPIRATION, 0, expirecmp, NULL);
	paircompare_register(PW_PACKET_TYPE, 0, packetcmp, NULL);
	paircompare_register(PW_RESPONSE_PACKET_TYPE, 0, responsecmp, NULL);
}

void paircompare_builtin_free(void)
{
	struct cmp *c, *next;
	
	for (c = cmp; c != NULL; c = next) {
		next = c->next;
		free(c);
	}
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
			continue;
		}

		/*
		 *	We've got to xlat the string before moving
		 *	it over.
		 */
		if (i->flags.do_xlat) {
			int rcode;
			char buffer[sizeof(i->strvalue)];

			i->flags.do_xlat = 0;
			rcode = radius_xlat(buffer, sizeof(buffer),
					    i->strvalue,
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
				if (!i->strvalue[0] ||
				    (strcmp((char *)found->strvalue,
					    (char *)i->strvalue) == 0)){
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
