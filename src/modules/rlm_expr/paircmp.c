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

#include <freeradius-devel/radiusd.h>
#include "rlm_expr.h"

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
	return rate - check->vp_integer;
}


/*
 *	Compare a portno with a range.
 */
static int portcmp(void *instance,
		   REQUEST *req UNUSED, VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	char buf[MAX_STRING_LEN];
	char *s, *p, *next;
	uint32_t lo, hi;
	uint32_t port = request->vp_integer;

	instance = instance;
	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

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
	char *name = request->vp_strvalue;
	char rest[MAX_STRING_LEN];
	int len, namelen;
	int ret = -1;

#if 0 /* DEBUG */
	printf("Comparing %s and %s, check->attr is %d\n",
		name, check->vp_strvalue, check->attribute);
#endif

	len = strlen((char *)check->vp_strvalue);
	switch (check->attribute) {
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
	vp = pairfind(check_pairs, PW_STRIP_USER_NAME);
	if (vp && !vp->vp_integer) return ret;

	/*
	 *	See where to put the stripped user name.
	 */
	vp = pairfind(check_pairs, PW_STRIPPED_USER_NAME);
	if (!vp) {
		/*
		 *	If "request" is NULL, then the memory will be
		 *	lost!
		 */
		vp = radius_paircreate(req, &request,
				       PW_STRIPPED_USER_NAME, PW_TYPE_STRING);
		if (vp) req->username = vp;
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
	if ((check->operator != T_OP_REG_EQ) &&
	    (check->operator != T_OP_REG_EQ)) {
		int rcode;
		char name[1024];
		char value[1024];
		VALUE_PAIR *vp;

		snprintf(name, sizeof(name), "%%{%s}", check->name);

		rcode = radius_xlat(value, sizeof(value), name, req, NULL);
		vp = pairmake(check->name, value, T_OP_EQ);

		rcode = radius_compare_vps(req, check, vp);
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
void pair_builtincompare_init(void)
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

void pair_builtincompare_detach(void)
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
