/*
 * paircmp.c	Valuepair functions for various attributes
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

#include <freeradius-devel/autoconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <freeradius-devel/radiusd.h>


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

	rate = atoi((char *)request->vp_strvalue);
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

	if ((strchr((char *)check->vp_strvalue, ',') == NULL) &&
			(strchr((char *)check->vp_strvalue, '-') == NULL)) {
		return (request->lvalue - check->lvalue);
	}

	/* Same size */
	strcpy(buf, (char *)check->vp_strvalue);
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
	char *name = (char *)request->vp_strvalue;
	char rest[MAX_STRING_LEN];
	int len, namelen;
	int ret = -1;

	instance = instance;
	reply_pairs = reply_pairs; /* shut the compiler up */

#if 0 /* DEBUG */
	printf("Comparing %s and %s, check->attr is %d\n",
		name, check->vp_strvalue, check->attribute);
#endif

	len = strlen((char *)check->vp_strvalue);
	switch (check->attribute) {
		case PW_PREFIX:
			ret = strncmp(name, (char *)check->vp_strvalue, len);
			if (ret == 0 && rest)
				strcpy(rest, name + len);
			break;
		case PW_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len,
					(char *)check->vp_strvalue);
			if (ret == 0 && rest) {
				strNcpy(rest, name, namelen - len + 1);
			}
			break;
	}
	if (ret != 0)
		return ret;

	/*
	 *	If Strip-User-Name == No, then don't do any more.
	 */
	vp = pairfind(check_pairs, PW_STRIP_USER_NAME);
	if (vp && !vp->lvalue) return ret;

	/*
	 *	See where to put the stripped user name.
	 */
	vp = pairfind(check_pairs, PW_STRIPPED_USER_NAME);
	if (!vp) {
		vp = paircreate(PW_STRIPPED_USER_NAME, PW_TYPE_STRING);
		if (!vp) return ret; /* no memory, do anything? */

		pairadd(&request, vp);
	}

	strcpy((char *)vp->vp_strvalue, rest);
	vp->length = strlen(rest);

	return ret;
}


/*
 *	Matches if there is NO SUCH ATTRIBUTE as the one named
 *	in check->vp_strvalue.  If there IS such an attribute, it
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
		dict = dict_attrbyname((char *)check->vp_strvalue);
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
	paircompare_register(PW_NO_SUCH_ATTRIBUTE, 0, attrcmp, NULL);
	paircompare_register(PW_PACKET_TYPE, 0, packetcmp, NULL);
	paircompare_register(PW_RESPONSE_PACKET_TYPE, 0, responsecmp, NULL);
}

void pair_builtincompare_detach(void)
{
	paircompare_unregister(PW_NAS_PORT, portcmp);
	paircompare_unregister(PW_PREFIX, presufcmp);
	paircompare_unregister(PW_SUFFIX, presufcmp);
	paircompare_unregister(PW_CONNECT_RATE, connectcmp);
	paircompare_unregister(PW_NO_SUCH_ATTRIBUTE, attrcmp);
	paircompare_unregister(PW_PACKET_TYPE, packetcmp);
	paircompare_unregister(PW_RESPONSE_PACKET_TYPE, responsecmp);
}
