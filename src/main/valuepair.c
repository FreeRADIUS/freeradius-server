/*
 * valuepair.c	Valuepair functions that are radiusd-specific
 *		and as such do not belong in the library.
 *
 * Version:	@(#)valuepair.c	 1.00  08-Aug-1999  miquels@cistron.nl
 */

char valuepair2_sccsid[] =
"@(#)valuepair.c	1.00 Copyright 1999 Cistron Internet Services B.V.";

#include	"autoconf.h"

#include	<sys/types.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<netinet/in.h>

#ifdef HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"

struct cmp {
	int		attribute;
	int		otherattr;
	COMPARE		compare;
	struct cmp	*next;
};
static struct cmp *cmp;


/*
 *	Compare 2 attributes. May call the attribute compare function.
 */
int paircompare(VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	int		ret = -2;
	struct cmp	*c;

	/*
	 *	Sanity check.
	 */
#if 0
	if (request->attribute != check->attribute)
		return -2;
#endif

	/*
	 *	See if there is a special compare function.
	 */
	for (c = cmp; c; c = c->next)
		if (c->attribute == check->attribute)
			return (c->compare)(request, check,
				check_pairs, reply_pairs);

	switch(check->type) {
		case PW_TYPE_STRING:
			ret = strcmp(request->strvalue, check->strvalue);
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_DATE:
			ret = request->lvalue - check->lvalue;
			break;
		case PW_TYPE_IPADDR:
			 ret = ntohl(request->lvalue) -
			       ntohl(check->lvalue);
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
 *	Otherattr is the attribute in the request we want to
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
int paircompare_register(int attr, int otherattr, COMPARE fun)
{
	struct cmp	*c;

	paircompare_unregister(attr, fun);

	if ((c = malloc(sizeof(struct cmp))) == NULL)
		return -1;
	if (otherattr < 0) otherattr = attr;
	c->compare = fun;
	c->attribute = attr;
	c->otherattr = otherattr;
	c->next = cmp;
	cmp = c;

	return 0;
}

/*
 *	Unregister a function.
 */
void paircompare_unregister(int attr, COMPARE fun)
{
	struct cmp	*c, *last;

	last = NULL;
	for (c = cmp; c; c = c->next) {
		if (c->attribute == attr && c->compare == fun)
			break;
		last = c;
	}

	if (c == NULL) return;

	if (last)
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
int paircmp(VALUE_PAIR *request, VALUE_PAIR *check, VALUE_PAIR **reply)
{
	VALUE_PAIR	*check_item = check;
	VALUE_PAIR	*auth_item;
	int		result = 0;
	int		compare;
	int		other;

	while (result == 0 && check_item != NULL) {
		switch (check_item->attribute) {
			/*
			 *	Attributes we skip during comparison.
			 *	These are "server" check items.
			 */
			case PW_EXPIRATION:
			case PW_LOGIN_TIME:
			case PW_PASSWORD:
			case PW_CRYPT_PASSWORD:
			case PW_AUTHTYPE:
                        case PAM_AUTH_ATTR:
			case PW_SIMULTANEOUS_USE:
			case PW_STRIP_USER_NAME:
				check_item = check_item->next;
				continue;
		}
		/*
		 *	See if this item is present in the request.
		 */
		other = otherattr(check_item->attribute);
		auth_item = request;
		for (; auth_item != NULL; auth_item = auth_item->next) {
			if (auth_item->attribute == other || other == 0)
				break;
		}

		if (auth_item == NULL) {
			result = -1;
			continue;
		}

		/*
		 *	OK it is present now compare them.
		 */
		
		compare = paircompare(auth_item, check_item, check, reply);

		switch (check_item->operator)
		  {
		  default:
		    log(L_ERR,  "Invalid operator for item %s: "
				"reverting to '='", check_item->name);
		    /*FALLTHRU*/
		  case T_OP_EQ:
		    if (compare != 0) return -1;
		    break;

		  case T_OP_NE:
		    if (compare == 0) return -1;
		    break;

		  case T_OP_LT:
		    if (compare >= 0) return -1;
		    break;

		  case T_OP_GT:
		    if (compare <= 0) return -1;
		    break;
		    
		  case T_OP_LE:
		    if (compare > 0) return -1;
		    break;

		  case T_OP_GE:
		    if (compare < 0) return -1;
		    break;
		  }

		if (result == 0)
			check_item = check_item->next;
	}

	return result;
}


/*
 *	Compare a Connect-Info and a Connect-Rate
 */
static int connectcmp(VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	int	rate;

	rate = atoi(request->strvalue);
	return rate - check->lvalue;
}


/*
 *	Compare a portno with a range.
 */
static int portcmp(VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	char		buf[MAX_STRING_LEN];
	char		*s, *p;
	int		lo, hi;
	int		port = request->lvalue;

	/* Same size */
	strcpy(buf, check->strvalue);
	s = strtok(buf, ",");

	while (s) {
		if ((p = strchr(s, '-')) != NULL)
			p++;
		else
			p = s;
		lo = atoi(s);
		hi = atoi(p);
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
static int presufcmp(VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	VALUE_PAIR	*vp;
	char		*name = request->strvalue;
	char		rest[MAX_STRING_LEN];
	int		len, namelen;
	int		ret = -1;

#if 0 /* DEBUG */
	printf("Comparing %s and %s, check->attr is %d\n",
		name, check->strvalue, check->attribute);
#endif

	len = strlen(check->strvalue);
	switch (check->attribute) {
		case PW_PREFIX:
			ret = strncmp(name, check->strvalue, len);
			if (ret == 0 && rest)
				strcpy(rest, name + len);
			break;
		case PW_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len, check->strvalue);
			if (ret == 0 && rest) {
				strncpy(rest, name, namelen - len);
				rest[namelen - len] = 0;
			}
			break;
	}
	if (ret != 0)
		return ret;

	if (pairfind(check_pairs, PW_STRIP_USER_NAME)) {
		strcpy(request->strvalue, rest);
		request->length = strlen(rest);
	} else {
		if ((vp = pairfind(check_pairs, PW_STRIPPED_USER_NAME)) != NULL){
			strcpy(vp->strvalue, rest);
			request->length = strlen(rest);
		} else if ((vp = paircreate(PW_STRIPPED_USER_NAME,
			    PW_TYPE_STRING)) != NULL) {
			strcpy(vp->strvalue, rest);
			request->length = strlen(rest);
			pairadd(&request, vp);
		}
	}

	return ret;
}

/*
 *	Register server-builtin special attributes.
 */
void pair_builtincompare_init(void)
{
	paircompare_register(PW_NAS_PORT_ID, -1, portcmp);
	paircompare_register(PW_PREFIX, PW_USER_NAME, presufcmp);
	paircompare_register(PW_SUFFIX, PW_USER_NAME, presufcmp);
	paircompare_register(PW_CONNECT_RATE, PW_CONNECT_INFO, connectcmp);
}

