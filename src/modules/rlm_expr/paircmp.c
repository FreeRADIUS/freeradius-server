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

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include "rlm_expr.h"

/*
 *	Compare a Connect-Info and a Connect-Rate
 */
static int connectcmp(UNUSED void *instance,
		      REQUEST *req UNUSED,
		      VALUE_PAIR *request,
		      VALUE_PAIR *check,
		      UNUSED VALUE_PAIR *check_pairs,
		      UNUSED VALUE_PAIR **reply_pairs)
{
	int rate;

	rate = atoi((char *)request->vp_strvalue);
	return rate - check->vp_integer;
}


/*
 *	Compare a portno with a range.
 */
static int portcmp(UNUSED void *instance, REQUEST *req UNUSED, VALUE_PAIR *request, VALUE_PAIR *check,
		   UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	char buf[MAX_STRING_LEN];
	char *s, *p, *next;
	uint32_t lo, hi;
	uint32_t port;

	if (!request) return -1;

	port = request->vp_integer;

	if ((strchr((char *)check->vp_strvalue, ',') == NULL) &&
			(strchr((char *)check->vp_strvalue, '-') == NULL)) {
		return (request->vp_integer - check->vp_integer);
	}

	/* Same size */
	strcpy(buf, check->vp_strvalue);

	s = buf;
	while (1) {
		next = strchr(s, ',');
		if (next) *next = '\0';

		if ((p = strchr(s, '-')) != NULL)
			p++;
		else
			p = s;
		lo = strtoul(s, NULL, 10);
		hi = strtoul(p, NULL, 10);
		if (lo <= port && port <= hi) {
			return 0;
		}

		if (!next) break;
		s = next + 1;
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
static int presufcmp(UNUSED void *instance,
		     REQUEST *req,
		     VALUE_PAIR *request, VALUE_PAIR *check,
		     VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	VALUE_PAIR *vp;
	char *name;
	char rest[MAX_STRING_LEN];
	int len, namelen;
	int ret = -1;

	if (!request) return -1;

	name = request->vp_strvalue;

#if 0 /* DEBUG */
	printf("Comparing %s and %s, check->attr is %d\n",
		name, check->vp_strvalue, check->attribute);
#endif

	len = strlen((char *)check->vp_strvalue);
	if (check->da->vendor == 0) switch (check->da->attr) {
		case PW_PREFIX:
			ret = strncmp(name, check->vp_strvalue, len);
			if (ret == 0)
				strlcpy(rest, name + len, sizeof(rest));
			break;
		case PW_SUFFIX:
			namelen = strlen(name);
			if (namelen < len)
				break;
			ret = strcmp(name + namelen - len,
					(char *)check->vp_strvalue);
			if (ret == 0) {
				strlcpy(rest, name, namelen - len + 1);
			}
			break;
	}
	if (ret != 0)
		return ret;

	/*
	 *	If Strip-User-Name == No, then don't do any more.
	 */
	vp = pairfind(check_pairs, PW_STRIP_USER_NAME, 0, TAG_ANY);
	if (vp && !vp->vp_integer) return ret;

	/*
	 *	See where to put the stripped user name.
	 */
	vp = pairfind(check_pairs, PW_STRIPPED_USER_NAME, 0, TAG_ANY);
	if (!vp) {
		/*
		 *	If "request" is NULL, then the memory will be
		 *	lost!
		 */
		vp = radius_paircreate(req, &request, PW_STRIPPED_USER_NAME, 0);
		if (!vp) return ret;
		req->username = vp;
	}

	strlcpy((char *)vp->vp_strvalue, rest, sizeof(vp->vp_strvalue));
	vp->length = strlen(vp->vp_strvalue);

	return ret;
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
	if (req->packet->code == check->vp_integer) {
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
	if (req->reply->code == check->vp_integer) {
		return 0;
	}

	return 1;
}

/*
 *	Generic comparisons, via xlat.
 */
static int genericcmp(void *instance UNUSED,
		      REQUEST *req,
		      VALUE_PAIR *request UNUSED,
		      VALUE_PAIR *check,
		      VALUE_PAIR *check_pairs UNUSED,
		      VALUE_PAIR **reply_pairs UNUSED)
{
	if ((check->op != T_OP_REG_EQ) &&
	    (check->op != T_OP_REG_NE)) {
		int rcode;
		char name[1024];
		char value[1024];
		VALUE_PAIR *vp;

		snprintf(name, sizeof(name), "%%{%s}", check->da->name);

		radius_xlat(value, sizeof(value), name, req, NULL, NULL);
		vp = pairmake(req, NULL, check->da->name, value, check->op);

		/*
		 *	Paircmp returns 0 for failed comparison,
		 *	1 for succeeded.
		 */
		rcode = paircmp(check, vp);

		/*
		 *	We're being called from radius_callback_compare,
		 *	which wants 0 for success, and 1 for fail (sigh)
		 *
		 *	We should really fix the API so that it is
		 *	consistent.  i.e. the comparison callbacks should
		 *	return ONLY the resut of comparing A to B.
		 *	The radius_callback_cmp function should then
		 *	take care of using the operator to see if the
		 *	condition (A OP B) is true or not.
		 *
		 *	This would also allow "<", etc. to work in the
		 *	callback functions...
		 *
		 *	See rlm_ldap, ...groupcmp() for something that
		 *	returns 0 for matched, and 1 for didn't match.
		 */
		rcode = !rcode;
		pairfree(&vp);

		return rcode;
	}

	/*
	 *	Will do the xlat for us
	 */
	return radius_compare_vps(req, check, NULL);
}

static int generic_attrs[] = {
	PW_CLIENT_IP_ADDRESS,
	PW_PACKET_SRC_IP_ADDRESS,
	PW_PACKET_DST_IP_ADDRESS,
	PW_PACKET_SRC_PORT,
	PW_PACKET_DST_PORT,
	PW_REQUEST_PROCESSING_STAGE,
	PW_PACKET_SRC_IPV6_ADDRESS,
	PW_PACKET_DST_IPV6_ADDRESS,
	PW_VIRTUAL_SERVER,
	0
};

/*
 *	Register server-builtin special attributes.
 */
void pair_builtincompare_add(void)
{
	int i;

	paircompare_register(PW_NAS_PORT, PW_NAS_PORT, portcmp, NULL);
	paircompare_register(PW_PREFIX, PW_USER_NAME, presufcmp, NULL);
	paircompare_register(PW_SUFFIX, PW_USER_NAME, presufcmp, NULL);
	paircompare_register(PW_CONNECT_RATE, PW_CONNECT_INFO, connectcmp, NULL);
	paircompare_register(PW_PACKET_TYPE, 0, packetcmp, NULL);
	paircompare_register(PW_RESPONSE_PACKET_TYPE, 0, responsecmp, NULL);

	for (i = 0; generic_attrs[i] != 0; i++) {
		paircompare_register(generic_attrs[i], -1, genericcmp, NULL);
	}
}

void pair_builtincompare_del(void)
{
	int i;

	paircompare_unregister(PW_NAS_PORT, portcmp);
	paircompare_unregister(PW_PREFIX, presufcmp);
	paircompare_unregister(PW_SUFFIX, presufcmp);
	paircompare_unregister(PW_CONNECT_RATE, connectcmp);
	paircompare_unregister(PW_PACKET_TYPE, packetcmp);
	paircompare_unregister(PW_RESPONSE_PACKET_TYPE, responsecmp);

	for (i = 0; generic_attrs[i] != 0; i++) {
		paircompare_unregister(generic_attrs[i], genericcmp);
	}

}
