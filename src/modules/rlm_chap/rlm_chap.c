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
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 *
 * Nov 03 2001, Kostas Kalevras <kkalev@noc.ntua.gr>
 * - Added authorize() function to set Auth-Type if Chap-Password exists
 * - Added module messages when rejecting user
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

static int chap_authorize(void *instance, REQUEST *request)
{

	/* quiet the compiler */
	instance = instance;
	request = request;

	if (!pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0)) {
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->config_items, PW_AUTHTYPE, 0) != NULL) {
		RDEBUG2("WARNING: Auth-Type already set.  Not setting to CHAP");
		return RLM_MODULE_NOOP;
	}

	RDEBUG("Setting 'Auth-Type := CHAP'");
	pairadd(&request->config_items,
		pairmake("Auth-Type", "CHAP", T_OP_EQ));
	return RLM_MODULE_OK;
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int chap_authenticate(void *instance, REQUEST *request)
{
	VALUE_PAIR *passwd_item, *chap;
	uint8_t pass_str[MAX_STRING_LEN];
	VALUE_PAIR *module_fmsg_vp;
	char module_fmsg[MAX_STRING_LEN];

	/* quiet the compiler */
	instance = instance;
	request = request;

	if (!request->username) {
		radlog_request(L_AUTH, 0, request, "rlm_chap: Attribute \"User-Name\" is required for authentication.\n");
		return RLM_MODULE_INVALID;
	}

	chap = pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0);
	if (!chap) {
		RDEBUG("ERROR: You set 'Auth-Type = CHAP' for a request that does not contain a CHAP-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	if (chap->length == 0) {
		RDEBUG("ERROR: CHAP-Password is empty");
		return RLM_MODULE_INVALID;
	}

	if (chap->length != CHAP_VALUE_LENGTH + 1) {
		RDEBUG("ERROR: CHAP-Password has invalid length");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Don't print out the CHAP password here.  It's binary crap.
	 */
	RDEBUG("login attempt by \"%s\" with CHAP password",
		request->username->vp_strvalue);

	if ((passwd_item = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0)) == NULL){
	  RDEBUG("Cleartext-Password is required for authentication");
		snprintf(module_fmsg, sizeof(module_fmsg),
			 "rlm_chap: Clear text password not available");
		module_fmsg_vp = pairmake("Module-Failure-Message",
					  module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_INVALID;
	}

	RDEBUG("Using clear text password \"%s\" for user %s authentication.",
	      passwd_item->vp_strvalue, request->username->vp_strvalue);

	rad_chap_encode(request->packet,pass_str,
			chap->vp_octets[0],passwd_item);

	if (memcmp(pass_str + 1, chap->vp_octets + 1,
		   CHAP_VALUE_LENGTH) != 0){
		RDEBUG("Password check failed");
		snprintf(module_fmsg, sizeof(module_fmsg),
			 "rlm_chap: Wrong user password");
		module_fmsg_vp = pairmake("Module-Failure-Message",
					  module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_REJECT;
	}

	RDEBUG("chap user %s authenticated succesfully",
	      request->username->vp_strvalue);

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
module_t rlm_chap = {
	 RLM_MODULE_INIT,
	"CHAP",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		chap_authenticate,	/* authentication */
		chap_authorize,	 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
