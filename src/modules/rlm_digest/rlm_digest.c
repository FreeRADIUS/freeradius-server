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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

static int digest_fix(REQUEST *request)
{
	VALUE_PAIR *vp;

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
		return RLM_MODULE_NOOP;
	}

	/*
	 *	We need these, too.
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_ATTRIBUTES);
	if (vp == NULL) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Check for proper format of the Digest-Attributes
	 */
	RDEBUG("Checking for correctly formatted Digest-Attributes");
	while (vp) {
		int length = vp->length;
		int attrlen;
		uint8_t *p = &vp->vp_octets[0];

		/*
		 *	Until this stupidly encoded attribute is exhausted.
		 */
		while (length > 0) {
			/*
			 *	The attribute type must be valid
			 */
			if ((p[0] == 0) || (p[0] > 10)) {
				RDEBUG("Not formatted as Digest-Attributes");
				return RLM_MODULE_NOOP;
			}

			attrlen = p[1];	/* stupid VSA format */

			/*
			 *	Too short.
			 */
			if (attrlen < 3) {
				RDEBUG("Not formatted as Digest-Attributes");
				return RLM_MODULE_NOOP;
			}

			/*
			 *	Too long.
			 */
			if (attrlen > length) {
				RDEBUG("Not formatted as Digest-Attributes");
				return RLM_MODULE_NOOP;
			}

			length -= attrlen;
			p += attrlen;
		} /* loop over this one attribute */

		/*
		 *	Find the next one, if it exists.
		 */
		vp = pairfind(vp->next, PW_DIGEST_ATTRIBUTES);
	}

	/*
	 *	Convert them to something sane.
	 */
	RDEBUG("Digest-Attributes look OK.  Converting them to something more usful.");
	vp = pairfind(request->packet->vps, PW_DIGEST_ATTRIBUTES);
	while (vp) {
		int length = vp->length;
		int attrlen;
		uint8_t *p = &vp->vp_octets[0];
		VALUE_PAIR *sub;

		/*
		 *	Until this stupidly encoded attribute is exhausted.
		 */
		while (length > 0) {
			/*
			 *	The attribute type must be valid
			 */
			if ((p[0] == 0) || (p[0] > 10)) {
				RDEBUG("ERROR: Received Digest-Attributes with invalid sub-attribute %d", p[0]);
				return RLM_MODULE_INVALID;
			}

			attrlen = p[1];	/* stupid VSA format */

			/*
			 *	Too short.
			 */
			if (attrlen < 3) {
				RDEBUG("ERROR: Received Digest-Attributes with short sub-attribute %d, of length %d", p[0], attrlen);
				return RLM_MODULE_INVALID;
			}

			/*
			 *	Too long.
			 */
			if (attrlen > length) {
				RDEBUG("ERROR: Received Digest-Attributes with long sub-attribute %d, of length %d", p[0], attrlen);
				return RLM_MODULE_INVALID;
			}

			/*
			 *	Create a new attribute, broken out of
			 *	the stupid sub-attribute crap.
			 *
			 *	Didn't they know that VSA's exist?
			 */
			sub = radius_paircreate(request, &request->packet->vps,
						PW_DIGEST_REALM - 1 + p[0],
						PW_TYPE_STRING);
			memcpy(&sub->vp_octets[0], &p[2], attrlen - 2);
			sub->vp_octets[attrlen - 2] = '\0';
			sub->length = attrlen - 2;

			if ((debug_flag > 1) && fr_log_fp) {
			  vp_print(fr_log_fp, sub);
			}

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

	return RLM_MODULE_OK;
}

static int digest_authorize(void *instance, REQUEST *request)
{
	int rcode;

	/* quiet the compiler */
	instance = instance;

	/*
	 *	Double-check and fix the attributes.
	 */	  
	rcode = digest_fix(request);
	if (rcode != RLM_MODULE_OK) return rcode;


	if (pairfind(request->config_items, PW_AUTHTYPE)) {
		RDEBUG2("WARNING: Auth-Type already set.  Not setting to DIGEST");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Everything's OK, add a digest authentication type.
	 */
	RDEBUG("Adding Auth-Type = DIGEST");
	pairadd(&request->config_items,
		pairmake("Auth-Type", "DIGEST", T_OP_EQ));

	return RLM_MODULE_OK;
}

/*
 *	Perform all of the wondrous variants of digest authentication.
 */
static int digest_authenticate(void *instance, REQUEST *request)
{
	int i;
	size_t a1_len, a2_len, kd_len;
	uint8_t a1[(MAX_STRING_LEN + 1) * 5]; /* can be 5 attributes */
	uint8_t a2[(MAX_STRING_LEN + 1) * 3]; /* can be 3 attributes */
	uint8_t kd[(MAX_STRING_LEN + 1) * 5];
	uint8_t hash[16];	/* MD5 output */
	VALUE_PAIR *vp, *passwd, *algo;
	VALUE_PAIR *qop, *nonce;

	instance = instance;	/* -Wunused */

	/*
	 *	We require access to the plain-text password, or to the
	 *	Digest-HA1 parameter.
	 */
	passwd = pairfind(request->config_items, PW_DIGEST_HA1);
	if (passwd) {
		if (passwd->length != 32) {
			radlog_request(L_AUTH, 0, request, "Digest-HA1 has invalid length, authentication failed.");
			return RLM_MODULE_INVALID;
		}
	} else {
		passwd = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD);
	}
	if (!passwd) {
		radlog_request(L_AUTH, 0, request, "Cleartext-Password or Digest-HA1 is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We need these, too.
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_ATTRIBUTES);
	if (vp == NULL) {
	error:
		RDEBUG("ERROR: You set 'Auth-Type = Digest' for a request that does not contain any digest attributes!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Look for the "internal" FreeRADIUS Digest attributes.
	 *	If they don't exist, it means that someone forced
	 *	Auth-Type = digest, without putting "digest" into the
	 *	"authorize" section.  In that case, try to decode the
	 *	attributes here.
	 */
	if (!pairfind(request->packet->vps, PW_DIGEST_NONCE)) {
		int rcode;

		rcode = digest_fix(request);

		/*
		 *	NOOP means "couldn't find the attributes".
		 *	That's bad.
		 */
		if (rcode == RLM_MODULE_NOOP) goto error;

		if (rcode != RLM_MODULE_OK) return rcode;
	}

	/*
	 *	We require access to the Digest-Nonce-Value
	 */
	nonce = pairfind(request->packet->vps, PW_DIGEST_NONCE);
	if (!nonce) {
		RDEBUG("ERROR: No Digest-Nonce: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	A1 = Digest-User-Name ":" Realm ":" Password
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_USER_NAME);
	if (!vp) {
		RDEBUG("ERROR: No Digest-User-Name: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[0], &vp->vp_octets[0], vp->length);
	a1_len = vp->length;

	a1[a1_len] = ':';
	a1_len++;

	vp = pairfind(request->packet->vps, PW_DIGEST_REALM);
	if (!vp) {
		RDEBUG("ERROR: No Digest-Realm: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[a1_len], &vp->vp_octets[0], vp->length);
	a1_len += vp->length;

	a1[a1_len] = ':';
	a1_len++;

	if (passwd->attribute == PW_CLEARTEXT_PASSWORD) {
		memcpy(&a1[a1_len], &passwd->vp_octets[0], passwd->length);
		a1_len += passwd->length;
		a1[a1_len] = '\0';
		RDEBUG2("A1 = %s", a1);
	} else {
		a1[a1_len] = '\0';
		RDEBUG2("A1 = %s (using Digest-HA1)", a1);
		a1_len = 16;
	}

	/*
	 *	See which variant we calculate.
	 *	Assume MD5 if no Digest-Algorithm attribute received
	 */
	algo = pairfind(request->packet->vps, PW_DIGEST_ALGORITHM);
	if ((algo == NULL) ||
	    (strcasecmp(algo->vp_strvalue, "MD5") == 0)) {
		/*
		 *	Set A1 to Digest-HA1 if no User-Password found
		 */
		if (passwd->attribute == PW_DIGEST_HA1) {
			if (fr_hex2bin(passwd->vp_strvalue, &a1[0], 16) != 16) {
				RDEBUG2("Invalid text in Digest-HA1");
				return RLM_MODULE_INVALID;
			}
		}

	} else if (strcasecmp(algo->vp_strvalue, "MD5-sess") == 0) {
		/*
		 *	K1 = H(A1) : Digest-Nonce ... : H(A2)
		 *
		 *	If we find Digest-HA1, we assume it contains
		 *	H(A1).
		 */
		if (passwd->attribute == PW_CLEARTEXT_PASSWORD) {
			fr_md5_calc(hash, &a1[0], a1_len);
			fr_bin2hex(hash, (char *) &a1[0], 16);
		} else {	/* MUST be Digest-HA1 */
			memcpy(&a1[0], passwd->vp_strvalue, 32);
		}
		a1_len = 32;

		a1[a1_len] = ':';
		a1_len++;

		/*
		 *	Tack on the Digest-Nonce. Length must be even
		 */
		if ((nonce->length & 1) != 0) {
			RDEBUG("ERROR: Received Digest-Nonce hex string with invalid length: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}
		memcpy(&a1[a1_len], &nonce->vp_octets[0], nonce->length);
		a1_len += nonce->length;

		a1[a1_len] = ':';
		a1_len++;

		vp = pairfind(request->packet->vps, PW_DIGEST_CNONCE);
		if (!vp) {
			RDEBUG("ERROR: No Digest-CNonce: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}

		/*
		 *      Digest-CNonce length must be even
		 */
		if ((vp->length & 1) != 0) {
			RDEBUG("ERROR: Received Digest-CNonce hex string with invalid length: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}
		memcpy(&a1[a1_len], &vp->vp_octets[0], vp->length);
		a1_len += vp->length;

	} else if ((algo != NULL) &&
		   (strcasecmp(algo->vp_strvalue, "MD5") != 0)) {
		/*
		 *	We check for "MD5-sess" and "MD5".
		 *	Anything else is an error.
		 */
		RDEBUG("ERROR: Unknown Digest-Algorithm \"%s\": Cannot perform Digest authentication", vp->vp_strvalue);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	A2 = Digest-Method ":" Digest-URI
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_METHOD);
	if (!vp) {
		RDEBUG("ERROR: No Digest-Method: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a2[0], &vp->vp_octets[0], vp->length);
	a2_len = vp->length;

	a2[a2_len] = ':';
	a2_len++;

	vp = pairfind(request->packet->vps, PW_DIGEST_URI);
	if (!vp) {
		RDEBUG("ERROR: No Digest-URI: Cannot perform Digest authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a2[a2_len], &vp->vp_octets[0], vp->length);
	a2_len += vp->length;

	/*
	 *  QOP is "auth-int", tack on ": Digest-Body-Digest"
	 */
	qop = pairfind(request->packet->vps, PW_DIGEST_QOP);
	if ((qop != NULL) &&
	    (strcasecmp(qop->vp_strvalue, "auth-int") == 0)) {
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
			RDEBUG("ERROR: No Digest-Body-Digest: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}

		if ((a2_len + body->length) > sizeof(a2)) {
			RDEBUG("ERROR: Digest-Body-Digest is too long");
			return RLM_MODULE_INVALID;
		}

		memcpy(a2 + a2_len, body->vp_octets, body->length);
		a2_len += body->length;

	} else if ((qop != NULL) &&
		   (strcasecmp(qop->vp_strvalue, "auth") != 0)) {
		RDEBUG("ERROR: Unknown Digest-QOP \"%s\": Cannot perform Digest authentication", qop->vp_strvalue);
		return RLM_MODULE_INVALID;
	}

	a2[a2_len] = '\0';
	RDEBUG2("A2 = %s", a2);

	/*
	 *     KD = H(A1) : Digest-Nonce ... : H(A2).
	 *     Compute MD5 if Digest-Algorithm == "MD5-Sess",
	 *     or if we found a User-Password.
	 */
	if (((algo != NULL) &&
	     (strcasecmp(algo->vp_strvalue, "MD5-Sess") == 0)) ||
	    (passwd->attribute == PW_CLEARTEXT_PASSWORD)) {
		a1[a1_len] = '\0';
		fr_md5_calc(&hash[0], &a1[0], a1_len);
	} else {
		memcpy(&hash[0], &a1[0], a1_len);
	}
	fr_bin2hex(hash, (char *) kd, sizeof(hash));

#ifndef NRDEBUG
	if (debug_flag > 1) {
		fr_printf_log("H(A1) = ");
		for (i = 0; i < 16; i++) {
			fr_printf_log("%02x", hash[i]);
		}
		fr_printf_log("\n");
	}
#endif
	kd_len = 32;

	kd[kd_len] = ':';
	kd_len++;

	memcpy(&kd[kd_len], nonce->vp_octets, nonce->length);
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
			RDEBUG("ERROR: No Digest-Nonce-Count: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}
		memcpy(&kd[kd_len], &vp->vp_octets[0], vp->length);
		kd_len += vp->length;

		kd[kd_len] = ':';
		kd_len++;

		vp = pairfind(request->packet->vps, PW_DIGEST_CNONCE);
		if (!vp) {
			RDEBUG("ERROR: No Digest-CNonce: Cannot perform Digest authentication");
			return RLM_MODULE_INVALID;
		}
		memcpy(&kd[kd_len], &vp->vp_octets[0], vp->length);
		kd_len += vp->length;

		kd[kd_len] = ':';
		kd_len++;

		memcpy(&kd[kd_len], &qop->vp_octets[0], qop->length);
		kd_len += qop->length;
	}

	/*
	 *	Tack on ":" H(A2)
	 */
	kd[kd_len] = ':';
	kd_len++;

	fr_md5_calc(&hash[0], &a2[0], a2_len);

	fr_bin2hex(hash, (char *) kd + kd_len, sizeof(hash));

#ifndef NRDEBUG
	if (debug_flag > 1) {
		fr_printf_log("H(A2) = ");
		for (i = 0; i < 16; i++) {
			fr_printf_log("%02x", hash[i]);
		}
		fr_printf_log("\n");
	}
#endif
	kd_len += 32;

	kd[kd_len] = 0;

	RDEBUG2("KD = %s\n", &kd[0]);

	/*
	 *	Take the hash of KD.
	 */
	fr_md5_calc(&hash[0], &kd[0], kd_len);
	memcpy(&kd[0], &hash[0], 16);

	/*
	 *	Get the binary value of Digest-Response
	 */
	vp = pairfind(request->packet->vps, PW_DIGEST_RESPONSE);
	if (!vp) {
		RDEBUG("ERROR: No Digest-Response attribute in the request.  Cannot perform digest authentication");
		return RLM_MODULE_INVALID;
	}

	if (fr_hex2bin(&vp->vp_strvalue[0], &hash[0], vp->length >> 1) != (vp->length >> 1)) {
		RDEBUG2("Invalid text in Digest-Response");
		return RLM_MODULE_INVALID;
	}

#ifndef NRDEBUG
	if (debug_flag > 1) {
		fr_printf_log("EXPECTED ");
		for (i = 0; i < 16; i++) {
			fr_printf_log("%02x", kd[i]);
		}
		fr_printf_log("\n");

		fr_printf_log("RECEIVED ");
		for (i = 0; i < 16; i++) {
			fr_printf_log("%02x", hash[i]);
		}
		fr_printf_log("\n");
	}
#endif

	/*
	 *  And finally, compare the digest in the packet with KD.
	 */
	if (memcmp(&kd[0], &hash[0], 16) == 0) {
		return RLM_MODULE_OK;
	}

	RDEBUG("FAILED authentication");
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
	RLM_MODULE_INIT,
	"digest",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		digest_authenticate,	/* authentication */
		digest_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
