/*
 * rlm_chap.c
 *
 * Version:  $Id$
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
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 *
 * Nov 03 2001, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Added authorize() function to set Auth-Type if Chap-Password exists
 * - Added module messages when rejecting user
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#include "rad_assert.h"

static const char rcsid[] = "$Id$";

static int digest_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;

	/* quiet the compiler */
	instance = instance;

	/*
	 *	We need both of these attributes to do the authentication.
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_RESPONSE);
	if (vp == NULL) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Check the sanity of the attribute.
	 */
	if (vp->length != 32) {
		DEBUG("ERROR: Received invalid Digest-Response attribute (length %d should be 32)", vp->length);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We need these, too.
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_ATTRIBUTES);
	if (vp == NULL) {
		DEBUG("ERROR: Received Digest-Response without Digest-Attributes");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Loop through the Digest-Attributes, sanity checking them.
	 */
	DEBUG("    rlm_digest: Converting Digest-Attributes to something sane...");
	while (vp) {
		int length = vp->length;
		int attrlen;
		uint8_t *p = &vp->strvalue[0];
		VALUE_PAIR *sub;

		/*
		 *	Until this stupidly encoded attribure is exhausted.
		 */
		while (length > 0) {
			/*
			 *	The attribute type must be valid
			 */
			if ((p[0] == 0) || (p[0] > 10)) {
				DEBUG("ERROR: Received Digest-Attributes with invalid sub-attribute %d", p[0]);
				return RLM_MODULE_INVALID;
			}

			attrlen = p[1];	/* stupid VSA format */
			
			/*
			 *	Too short.
			 */
			if (attrlen < 3) {
				DEBUG("ERROR: Received Digest-Attributes with short sub-attribute %d, of length %d", p[0], attrlen);
				return RLM_MODULE_INVALID;
			}
			
			/*
			 *	Too long.
			 */
			if (attrlen > length) {
				DEBUG("ERROR: Received Digest-Attributes with long sub-attribute %d, of length %d", p[0], attrlen);
				return RLM_MODULE_INVALID;
			}

			/*
			 *	Create a new attribute, broken out of
			 *	the stupid sub-attribute crap.
			 *
			 *	Didn't they know that VSA's exist?
			 */
			sub = paircreate(PW_DIGEST_REALM - 1 + p[0],
					 PW_TYPE_STRING);
			if (!sub) {
				exit(1); /* out of memory */
			}
			memcpy(&sub->strvalue[0], &p[2], attrlen - 2);
			sub->strvalue[attrlen - 2] = '\0';
			sub->length = attrlen - 2;

			if (debug_flag) {
			  putchar('\t');
			  vp_print(stdout, sub);
			  putchar('\n');
			}

			/*
			 *	And add it to the request pairs.
			 */
			pairadd(&request->packet->vps, sub);

			/*
			 *	FIXME: Check for the existence
			 *	of the necessary attributes!
			 */

			length -= attrlen;
			p += attrlen;			
		} /* loop over this one attribute */

		/*
		 *	Find the next one, if it exists.
		 */
		vp = pairfind(vp->next, PW_DIGEST_ATTRIBUTES);
	}

	/*
	 *	Everything's OK, add a digest authentication type.
	 */
	if (pairfind(request->config_items, PW_AUTHTYPE) == NULL) {
		DEBUG("rlm_digest: Adding Auth-Type = DIGEST");
		pairadd(&request->config_items,
			pairmake("Auth-Type", "DIGEST", T_OP_EQ));
	}

	return RLM_MODULE_OK;
}

/*
 *	Convert a string in hex to one in binary
 */
static void hex2bin(uint8_t *out, const uint8_t *in)
{
	unsigned int tmp;

	while (*in) {
		sscanf(in, "%02x", &tmp);
		*out = tmp;
		out++;
		in += 2;
	}
}

/*
 *	Perform all of the wondrous variants of digest authentication.
 */
static int digest_authenticate(void *instance, REQUEST *request)
{
	int i;
	int a1_len, a2_len, kd_len;
	uint8_t a1[(MAX_STRING_LEN + 1) * 5]; /* can be 5 attributes */
	uint8_t a2[(MAX_STRING_LEN + 1) * 3]; /* can be 3 attributes */
	uint8_t kd[(MAX_STRING_LEN + 1) * 5];
	uint8_t hash[16];	/* MD5 output */
	VALUE_PAIR *vp;
	VALUE_PAIR *qop, *nonce;

	/*
	 *	We require access to the plain-text password.
	 */
	vp = pairfind(request->config_items, PW_PASSWORD);
	if (!vp) {
		radlog(L_AUTH, "rlm_digest: Configuration item \"User-Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We require access to the Digest-Nonce-Value
	 */
	nonce = pairfind(request->packet->vps, PW_DIGEST_NONCE);
	if (!nonce) {
		DEBUG("ERROR: No Digest-Nonce: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	A1 = Digest-User-Name ":" Realm ":" Password
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_USER_NAME);
	if (!vp) {
		DEBUG("ERROR: No Digest-User-Name: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[0], &vp->strvalue[0], vp->length);
	a1_len = vp->length;

	a1[a1_len] = ':';
	a1_len++;

	vp = pairfind(request->packet->vps, PW_DIGEST_REALM);
	if (!vp) {
		DEBUG("ERROR: No Digest-Realm: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[a1_len], &vp->strvalue[0], vp->length);
	a1_len += vp->length;

	a1[a1_len] = ':';
	a1_len++;

	vp = pairfind(request->config_items, PW_PASSWORD);
	if (!vp) {
		DEBUG("ERROR: No User-Password: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[a1_len], &vp->strvalue[0], vp->length);
	a1_len += vp->length;

	a1[a1_len] = '\0';
	DEBUG2("A1 = %s", a1);

	/*
	 *	See which variant we calculate.
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_ALGORITHM);
	if ((vp != NULL) &&
	    (strcasecmp(vp->strvalue, "MD5-sess") == 0)) {
		librad_md5_calc(hash, &a1[0], a1_len);
		memcpy(&a1[0], hash, 16);
		a1_len = 16;

		a1[a1_len] = ':';
		a1_len++;

		/*
		 *	Tack on the Digest-Nonce
		 */
		hex2bin(&a1[a1_len], &nonce->strvalue[0]);
		a1_len += (nonce->length >> 1); /* FIXME: CHECK LENGTH */

		a1[a1_len] = ':';
		a1_len++;

		vp = pairfind(request->packet->vps, PW_DIGEST_CNONCE);
		if (!vp) {
		  DEBUG("ERROR: No Digest-CNonce: Cannot perform Digest authentication");
		  return RLM_MODULE_INVALID;
		}

		hex2bin(&a1[a1_len], &vp->strvalue[0]);
		a1_len += (vp->length >> 1); /* FIXME: CHECK LENGTH */

	} else if ((vp != NULL) &&
		   (strcasecmp(vp->strvalue, "MD5") != 0)) {
		/*
		 *	We check for "MD5-sess" and "MD5".
		 *	Anything else is an error.
		 */
		DEBUG("ERROR: Unknown Digest-Algorithm \"%s\": Cannot perform Digest authentication", vp->strvalue);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	A2 = Digest-Method ":" Digest-URI
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_METHOD);
	if (!vp) {
		DEBUG("ERROR: No Digest-Method: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a2[0], &vp->strvalue[0], vp->length);
	a2_len = vp->length;

	a2[a2_len] = ':';
	a2_len++;

	vp = pairfind(request->packet->vps, PW_DIGEST_URI);
	if (!vp) {
		DEBUG("ERROR: No Digest-URI: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a2[a2_len], &vp->strvalue[0], vp->length);
	a2_len += vp->length;

	/*
	 *  QOP is "auth-int", tack on ": Digest-Body-Digest"
	 */
	qop = pairfind(request->packet->vps, PW_DIGEST_QOP);
	if ((qop != NULL) &&
	    (strcasecmp(qop->strvalue, "auth-int") == 0)) {
		VALUE_PAIR *body;

		/*
		 *	Add in Digest-Body-Digest
		 */
		a2[a2_len] = ':';
		a2_len++;

		/*
		 *  Must be a hex representation of an MD5 digest.
		 */
		body = pairfind(request->packet->vps, PW_DIGEST_BODY_DIGEST);
		if (!body) {
			DEBUG("ERROR: No Digest-Body-Digest: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}

		rad_assert(body->length == 32);	/* FIXME: check in 'auth' */
		hex2bin(&a2[a2_len], &body->strvalue[0]);
		a2_len += (body->length >> 1);

	} else if ((qop != NULL) &&
		   (strcasecmp(qop->strvalue, "auth") != 0)) {	
		DEBUG("ERROR: Unknown Digest-QOP \"%s\": Cannot perform Digest authentication", qop->strvalue);
		return RLM_MODULE_INVALID;
	}

	a2[a2_len] = '\0';
	DEBUG2("A2 = %s", a2);

	/*
	 *     KD = H(A1) : Digest-Nonce ... : H(A2)
	 */
	librad_md5_calc(&hash[0], &a1[0], a1_len);

	for (i = 0; i < 16; i++) {
		sprintf(&kd[i * 2], "%02x", hash[i]);
	}

#ifndef NDEBUG
	if (debug_flag) {
		printf("H(A1) = ");
		for (i = 0; i < 16; i++) {
			printf("%02x", hash[i]);
		}
		printf("\n");
	}
#endif
	kd_len = 32;

	kd[kd_len] = ':';
	kd_len++;
	
	memcpy(&kd[kd_len], nonce->strvalue, nonce->length);
	kd_len += nonce->length;

	/*
	 *	No QOP defined.  Do RFC 2069 compatibility.
	 */
	if (!qop) {
		/*
		 *	Do nothing here.
		 */

	} else {		/* Digest-QOP MUST be "auth" or "auth-int" */
		/*
		 *	Tack on ":" Digest-Nonce-Count ":" Digest-CNonce
		 *	       ":" Digest-QOP
		 */
		kd[kd_len] = ':';
		kd_len++;

		vp = pairfind(request->packet->vps, PW_DIGEST_NONCE_COUNT);
		if (!vp) {
			DEBUG("ERROR: No Digest-Nonce-Count: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}
		memcpy(&kd[kd_len], &vp->strvalue[0], vp->length);
		kd_len += vp->length;

		kd[kd_len] = ':';
		kd_len++;

		vp = pairfind(request->packet->vps, PW_DIGEST_CNONCE);
		if (!vp) {
			DEBUG("ERROR: No Digest-CNonce: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}
		memcpy(&kd[kd_len], &vp->strvalue[0], vp->length);
		kd_len += vp->length;

		kd[kd_len] = ':';
		kd_len++;

		memcpy(&kd[kd_len], &qop->strvalue[0], qop->length);
		kd_len += qop->length;
	}

	/*
	 *	Tack on ":" H(A2)
	 */
	kd[kd_len] = ':';
	kd_len++;

	librad_md5_calc(&hash[0], &a2[0], a2_len);

	for (i = 0; i < 16; i++) {
		sprintf(&kd[kd_len + (i * 2)], "%02x", hash[i]);
	}

#ifndef NDEBUG
	if (debug_flag) {
		printf("H(A2) = ");
		for (i = 0; i < 16; i++) {
			printf("%02x", hash[i]);
		}
		printf("\n");
	}
#endif
	kd_len += 32;

	kd[kd_len] = 0;

	DEBUG2("KD = %s\n", &kd[0]);

	/*
	 *	Take the hash of KD.
	 */
	librad_md5_calc(&hash[0], &kd[0], kd_len);
	memcpy(&kd[0], &hash[0], 16);

	/*
	 *	Get the binary value of Digest-Response
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_RESPONSE);
	rad_assert(vp != NULL);

	hex2bin(&hash[0], &vp->strvalue[0]);

#ifndef NDEBUG
	if (debug_flag) {
		printf("EXPECTED ");
		for (i = 0; i < 16; i++) {
			printf("%02x", kd[i]);
		}
		printf("\n");
		
		printf("RECEIVED ");
		for (i = 0; i < 16; i++) {
			printf("%02x", hash[i]);
		}
		printf("\n");
	}
#endif

	/*
	 *  And finally, compare the digest in the packet with KD.
	 */
	if (memcmp(&kd[0], &hash[0], 16) == 0) {
		return RLM_MODULE_OK;
	}

	DEBUG("rlm_digest: FAILED authentication");
	return RLM_MODULE_REJECT;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_digest = {
	"DIGEST",	
	0,				/* type */
	NULL,				/* initialization */
	NULL,				/* instantiation */
	{
		digest_authenticate,	/* authentication */
		digest_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL			/* checksimul */
	},
	NULL,				/* detach */
	NULL,				/* destroy */
};
