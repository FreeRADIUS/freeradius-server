/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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

/**
 * $Id$
 * @file rlm_hmac.c
 * @brief Handles HMAC auth requests, required by STUN/TURN and others
 *        Based on rlm_digest
 *
 * @copyright 2013 Daniel Pocock http://danielpocock.com
 * @copyright 2002,2006  The FreeRADIUS server project
 * @copyright 2002  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#define HMAC_SHA1_DIGEST_LEN 20

static int hmac_fix(REQUEST *request)
{
	VALUE_PAIR *first, *i;
	vp_cursor_t cursor;
	
	/*
	 *	We need both of these attributes to do the authentication.
	 */
	first = pairfind(request->packet->vps, PW_HMAC_CODE, 0, TAG_ANY);
	if (!first) {
		// FIXME - HMAC doesn't have response!    --  return RLM_MODULE_NOOP;
	}

	/*
	 *	Check the sanity of the attribute.
	 */
	if (first->length != 20) {
		// FIXME - HMAC doesn't have response!    --  return RLM_MODULE_NOOP;
	}

	/*
	 *	Check for proper format of the HMAC-Attributes
	 */
	RDEBUG("Checking for correctly formatted HMAC-Attributes");
	
	first = pairfind(request->packet->vps, PW_HMAC_ATTRIBUTES, 0, TAG_ANY);
	if (!first) {
		return RLM_MODULE_NOOP;
	}
	
	paircursor(&cursor, &first);
	while ((i = pairfindnext(&cursor, PW_HMAC_ATTRIBUTES, 0, TAG_ANY))) {
		int length = i->length;
		int attrlen;
		uint8_t const *p = i->vp_octets;

		/*
		 *	Until this stupidly encoded attribute is exhausted.
		 */
		while (length > 0) {
			/*
			 *	The attribute type must be valid
			 */
			if ((p[0] == 0) || (p[0] > 10)) {
				RDEBUG("Not formatted as HMAC-Attributes: TLV type (%u) invalid", (unsigned int) p[0]);
				return RLM_MODULE_NOOP;
			}

			attrlen = p[1];	/* stupid VSA format */

			/*
			 *	Too short.
			 */
			if (attrlen < 3) {
				RDEBUG("Not formatted as HMAC-Attributes: TLV too short");
				return RLM_MODULE_NOOP;
			}

			/*
			 *	Too long.
			 */
			if (attrlen > length) {
				RDEBUG("Not formatted as HMAC-Attributes: TLV too long)");
				return RLM_MODULE_NOOP;
			}

			length -= attrlen;
			p += attrlen;
		} /* loop over this one attribute */
	}

	/*
	 *	Convert them to something sane.
	 */
	RDEBUG("HMAC-Attributes look OK.  Converting them to something more useful.");
	pairfirst(&cursor);
	while ((i = pairfindnext(&cursor, PW_HMAC_ATTRIBUTES, 0, TAG_ANY))) {
		int length = i->length;
		int attrlen;
		uint8_t const *p = &i->vp_octets[0];
		char *q;
		VALUE_PAIR *sub;

		/*
		 *	Until this stupidly encoded attribute is exhausted.
		 */
		while (length > 0) {
			/*
			 *	The attribute type must be valid
			 */
			if ((p[0] == 0) || (p[0] > 10)) {
				REDEBUG("Received HMAC-Attributes with invalid sub-attribute %d", p[0]);
				return RLM_MODULE_INVALID;
			}

			attrlen = p[1];	/* stupid VSA format */

			/*
			 *	Too short.
			 */
			if (attrlen < 3) {
				REDEBUG("Received HMAC-Attributes with short sub-attribute %d, of length %d", p[0], attrlen);
				return RLM_MODULE_INVALID;
			}

			/*
			 *	Too long.
			 */
			if (attrlen > length) {
				REDEBUG("Received HMAC-Attributes with long sub-attribute %d, of length %d", p[0], attrlen);
				return RLM_MODULE_INVALID;
			}

			/*
			 *	Create a new attribute, broken out of
			 *	the stupid sub-attribute crap.
			 *
			 *	Didn't they know that VSA's exist?
			 */
			sub = radius_paircreate(request, &request->packet->vps,
						PW_HMAC_REALM - 1 + p[0], 0);
			sub->length = attrlen - 2;
			sub->vp_strvalue = q = talloc_array(sub, char, sub->length + 1);
			memcpy(q, p + 2, attrlen - 2);
			q[attrlen - 2] = '\0';

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
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t mod_authorize(UNUSED void *instance, REQUEST *request)
{
	rlm_rcode_t rcode;

	/*
	 *	Double-check and fix the attributes.
	 */	
	rcode = hmac_fix(request);
	if (rcode != RLM_MODULE_OK) return rcode;


	if (pairfind(request->config_items, PW_AUTHTYPE, 0, TAG_ANY)) {
		RWDEBUG2("Auth-Type already set.  Not setting to HMAC");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Everything's OK, add a digest authentication type.
	 */
	RDEBUG("Adding Auth-Type = HMAC");
	pairmake_config("Auth-Type", "HMAC", T_OP_EQ);

	return RLM_MODULE_OK;
}

/*
 *	Perform all of the wondrous variants of digest authentication.
 */
static rlm_rcode_t mod_authenticate(UNUSED void *instance, REQUEST *request)
{
	int i;
	size_t a1_len, message_body_len, key_len = 16, digest_len = HMAC_SHA1_DIGEST_LEN;
	uint8_t a1[(MAX_STRING_LEN + 1) * 5]; /* can be 5 attributes */
	uint8_t message_body[(MAX_STRING_LEN + 1) * 3];
	uint8_t key[16];	/* MD5 output */
	uint8_t digest[HMAC_SHA1_DIGEST_LEN];	/* HMAC output */
	VALUE_PAIR *vp, *passwd, *algo, *nonce;

	/*
	 *	We require access to the plain-text password, or to the
	 *	Digest-HA1 parameter.
	 */
	passwd = pairfind(request->config_items, PW_DIGEST_HA1, 0, TAG_ANY);
	if (passwd) {
		if (passwd->length != 32) {
			RAUTH("Digest-HA1 has invalid length, authentication failed.");
			return RLM_MODULE_INVALID;
		}
	} else {
		passwd = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	}
	if (!passwd) {
		RAUTH("Cleartext-Password or Digest-HA1 is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We need these, too.
	 */
	vp = pairfind(request->packet->vps, PW_HMAC_ATTRIBUTES, 0, TAG_ANY);
	if (!vp) {
	error:
		REDEBUG("You set 'Auth-Type = HMAC' for a request that does not contain any HMAC attributes!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Look for the "internal" FreeRADIUS HMAC attributes.
	 *	If they don't exist, it means that someone forced
	 *	Auth-Type = HMAC, without putting "hmac" into the
	 *	"authorize" section.  In that case, try to decode the
	 *	attributes here.
	 */
	if (!pairfind(request->packet->vps, PW_HMAC_NONCE, 0, TAG_ANY)) {
		int rcode;

		rcode = hmac_fix(request);

		/*
		 *	NOOP means "couldn't find the attributes".
		 *	That's bad.
		 */
		if (rcode == RLM_MODULE_NOOP) goto error;

		if (rcode != RLM_MODULE_OK) return rcode;
	}

	/*
	 *	We don't really use the HMAC-Nonce-Value for now, but we
	 *	obtain it here in case we need it in future.
	 */
	nonce = pairfind(request->packet->vps, PW_HMAC_NONCE, 0, TAG_ANY);
	if (!nonce) {
		REDEBUG("No HMAC-Nonce: Cannot perform HMAC authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	A1 = HMAC-User-Name ":" Realm ":" Password
	 */
	vp = pairfind(request->packet->vps, PW_HMAC_USER_NAME, 0, TAG_ANY);
	if (!vp) {
		REDEBUG("No HMAC-User-Name: Cannot perform HMAC authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[0], vp->vp_octets, vp->length);
	a1_len = vp->length;

	a1[a1_len] = ':';
	a1_len++;

	vp = pairfind(request->packet->vps, PW_HMAC_REALM, 0, TAG_ANY);
	if (!vp) {
		REDEBUG("No HMAC-Realm: Cannot perform HMAC authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&a1[a1_len], vp->vp_octets, vp->length);
	a1_len += vp->length;

	a1[a1_len] = ':';
	a1_len++;

	if (passwd->da->attr == PW_CLEARTEXT_PASSWORD) {
		memcpy(&a1[a1_len], passwd->vp_octets, passwd->length);
		a1_len += passwd->length;
		a1[a1_len] = '\0';
		RDEBUG2("A1 = %s", a1);
	} else {
		a1[a1_len] = '\0';
		RDEBUG2("A1 = %s (using Digest-HA1)", a1);
	}

	/*
	 *	In TURN, A1 is always hashed with MD5 while HMAC is SHA1
	 */

	/*
	 *	Set A1 to Digest-HA1 if no User-Password found
	 */
	if (passwd->da->attr == PW_DIGEST_HA1) {
		if (fr_hex2bin(passwd->vp_strvalue, &key[0], 16) != 16) {
			RDEBUG2("Invalid text in Digest-HA1");
			return RLM_MODULE_INVALID;
		}
	} else if (passwd->da->attr == PW_CLEARTEXT_PASSWORD) {
		fr_md5_calc(key, &a1[0], a1_len);
		fr_bin2hex(key, (char *) &a1[0], 16);
	} else {
		RDEBUG2("No useable password");
		return RLM_MODULE_INVALID;
	}
		

	/*
	 *	See which variant we calculate.
	 *	Assume SHA1 if no HMAC-Algorithm attribute received
	 */
	algo = pairfind(request->packet->vps, PW_HMAC_ALGORITHM, 0, TAG_ANY);
	if ((!algo) ||
	    (strcasecmp(algo->vp_strvalue, "HMAC-SHA1") == 0)) {

	} else {
		/*
		 *	We only handle HMAC-SHA1, anything else is an error.
		 */
		REDEBUG("Unknown HMAC-Algorithm \"%s\": Cannot perform HMAC authentication", vp->vp_strvalue);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Message body is the other input to HMAC
	 */
	vp = pairfind(request->packet->vps, PW_HMAC_BODY, 0, TAG_ANY);
	if (!vp) {
		REDEBUG("No HMAC-Body: Cannot perform HMAC authentication");
		return RLM_MODULE_INVALID;
	}
	memcpy(&message_body[0], vp->vp_octets, vp->length);
	message_body_len = vp->length;
	RDEBUG2("message_body_len = %ld", message_body_len);

	/*
	 *	Now we have both HMAC inputs, the key = H(A1) and message body
	 *	We can perform the HMAC
	 */
	
	fr_hmac_sha1(&message_body[0], message_body_len, &key[0], key_len, &digest[0]);
	
#ifndef NRDEBUG
	if (debug_flag > 1) {
		//fr_printf_log("Message (size) = [%s] (%d)\n", message_body, message_body_len);
		fr_printf_log("H(A1) = ");
		for (i = 0; i < 16; i++) {
			fr_printf_log("%02x", key[i]);
		}
		fr_printf_log("\n");
		fr_printf_log("HMAC = ");
		for (i = 0; i < 20; i++) {
			fr_printf_log("%02x", digest[i]);
		}
		fr_printf_log("\n");
	}
#endif

	/*
	 *	Get the binary value of Digest-Response
	 */
	/* FIXME - maybe we should also offer comparison if request contains a MAC
	vp = pairfind(request->packet->vps, PW_DIGEST_RESPONSE, 0, TAG_ANY);
	if (!vp) {
		REDEBUG("No Digest-Response attribute in the request.  Cannot perform digest authentication");
		return RLM_MODULE_INVALID;
	}

	if (fr_hex2bin(vp->vp_strvalue, &hash[0], vp->length >> 1) != (vp->length >> 1)) {
		RDEBUG2("Invalid text in Digest-Response");
		return RLM_MODULE_INVALID;
	} */

#ifndef NRDEBUG
/*	if (debug_flag > 1) {   // FIXME - adapt for HMAC
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
	} */
#endif

	/*
	 *  And finally, compare the digest in the packet with KD.
	 */
	/* FIXME - maybe we should also offer comparison if request contains a MAC
	if (memcmp(&kd[0], &hash[0], 16) == 0) {
		return RLM_MODULE_OK;
	}

	RDEBUG("FAILED authentication");
	return RLM_MODULE_REJECT; */

	vp = pairfind(request->reply->vps, PW_HMAC_CODE, 0, TAG_ANY);
	if(!vp) {
		vp = pairmake(request->reply, &request->reply->vps, "HMAC-Code", NULL, T_OP_EQ);
		if(!vp) {
			REDEBUG("allocation failure");
			return RLM_MODULE_INVALID;
		}
	}
	vp->length = digest_len;
	vp->vp_strvalue = talloc_memdup(vp->vp_strvalue, digest, digest_len);
	vp->type = VT_DATA;
	RDEBUG("HMAC done");
	return RLM_MODULE_OK;
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
module_t rlm_hmac = {
	RLM_MODULE_INIT,
	"hmac",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	0,
	NULL,				/* CONF_PARSER */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		mod_authenticate,	/* authentication */
		mod_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
