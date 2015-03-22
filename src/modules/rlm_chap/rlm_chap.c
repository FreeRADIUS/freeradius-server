/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_chap.c
 * @brief Process chap authentication requests.
 *
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, REQUEST *request)
{
	if (!pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) {
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->config, PW_AUTHTYPE, 0, TAG_ANY) != NULL) {
		RWDEBUG2("&control:Auth-Type already set.  Not setting to CHAP");
		return RLM_MODULE_NOOP;
	}

	RINDENT();
	RDEBUG("&control:Auth-Type := CHAP");
	REXDENT();
	pairmake_config("Auth-Type", "CHAP", T_OP_EQ);

	return RLM_MODULE_OK;
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance,
				     REQUEST *request)
{
	VALUE_PAIR *password, *chap;
	uint8_t pass_str[MAX_STRING_LEN];

	if (!request->username) {
		RWDEBUG("&request:User-Name attribute is required for authentication");
		return RLM_MODULE_INVALID;
	}

	chap = pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY);
	if (!chap) {
		REDEBUG("You set '&control:Auth-Type = CHAP' for a request that "
			"does not contain a CHAP-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	if (chap->vp_length == 0) {
		REDEBUG("&request:CHAP-Password is empty");
		return RLM_MODULE_INVALID;
	}

	if (chap->vp_length != CHAP_VALUE_LENGTH + 1) {
		REDEBUG("&request:CHAP-Password has invalid length");
		return RLM_MODULE_INVALID;
	}

	password = pairfind(request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	if (password == NULL) {
		if (pairfind(request->config, PW_USER_PASSWORD, 0, TAG_ANY) != NULL){
			REDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			REDEBUG("!!! Please update your configuration so that the \"known !!!");
			REDEBUG("!!! good\" cleartext password is in Cleartext-Password,  !!!");
			REDEBUG("!!! and NOT in User-Password.                            !!!");
			REDEBUG("!!!						          !!!");
			REDEBUG("!!! Authentication will fail because of this.	          !!!");
			REDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		}

		REDEBUG("&control:Cleartext-Password is required for authentication");
		return RLM_MODULE_INVALID;
	}

	rad_chap_encode(request->packet, pass_str, chap->vp_octets[0], password);

	if (RDEBUG_ENABLED3) {
		uint8_t const *p;
		size_t length;
		VALUE_PAIR *vp;
		char buffer[CHAP_VALUE_LENGTH * 2 + 1];

		RDEBUG3("Comparing with \"known good\" &control:Cleartext-Password value \"%s\"",
			password->vp_strvalue);

		vp = pairfind(request->packet->vps, PW_CHAP_CHALLENGE, 0, TAG_ANY);
		if (vp) {
			RDEBUG2("Using challenge from &request:CHAP-Challenge");
			p = vp->vp_octets;
			length = vp->vp_length;
		} else {
			RDEBUG2("Using challenge from authenticator field");
			p = request->packet->vector;
			length = sizeof(request->packet->vector);
		}

		fr_bin2hex(buffer, p, length);
		RINDENT();
		RDEBUG3("CHAP challenge : %s", buffer);

		fr_bin2hex(buffer, chap->vp_octets + 1, CHAP_VALUE_LENGTH);
		RDEBUG3("Client sent    : %s", buffer);

		fr_bin2hex(buffer, pass_str + 1, CHAP_VALUE_LENGTH);
		RDEBUG3("We calculated  : %s", buffer);
		REXDENT();
	} else {
		RDEBUG2("Comparing with \"known good\" Cleartext-Password");
	}

	if (rad_digest_cmp(pass_str + 1, chap->vp_octets + 1, CHAP_VALUE_LENGTH) != 0) {
		REDEBUG("Password comparison failed: password is incorrect");
		return RLM_MODULE_REJECT;
	}

	RDEBUG("CHAP user \"%s\" authenticated successfully", request->username->vp_strvalue);

	return RLM_MODULE_OK;
}


/*
 *	Access-Requests can have the CHAP-Challenge implicitly taken
 *	from the request authenticator.  If the NAS has done that,
 *	then we need to copy the data to a real CHAP-Challenge
 *	attribute when proxying.  Otherwise when we proxy the request,
 *	the new authenticator is different, and the CHAP calculations
 *	will fail.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(UNUSED void *instance,
				 REQUEST *request)
{
	VALUE_PAIR *vp;

	/*
	 *	For Access-Requests, which have CHAP-Password,
	 *	and no CHAP-Challenge, copy it over from the request.
	 */
	if (request->packet->code != PW_CODE_ACCESS_REQUEST) return RLM_MODULE_NOOP;

	if (!pairfind(request->proxy->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) return RLM_MODULE_NOOP;

	vp = radius_paircreate(request, &request->proxy->vps, PW_CHAP_CHALLENGE, 0);
	if (!vp) return RLM_MODULE_FAIL;

	pairmemcpy(vp, request->packet->vector, sizeof(request->packet->vector));

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
extern module_t rlm_chap;
module_t rlm_chap = {
	RLM_MODULE_INIT,
	"CHAP",
	0,   	/* type */
	0,
	NULL,				/* CONF_PARSER */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		mod_authenticate,	/* authentication */
		mod_authorize,	 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		mod_pre_proxy,	      	/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
