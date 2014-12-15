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
 * @file auth_wbclient.c
 * @brief NTLM authentication against the wbclient library
 *
 * @copyright 2014  Matthew Newton
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <wbclient.h>

#include "rlm_mschap.h"
#include "mschap.h"
#include "auth_wbclient.h"

#define NT_LENGTH 24

/*
 *	Check NTLM authentication using ntlm_auth server via a socket
 *	Returns -1 for failure and 0 on auth success
 */
int do_auth_wbclient(rlm_mschap_t *inst, REQUEST *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH])
{
	int rcode = -1;
	struct wbcAuthUserParams authparams;
	wbcErr err;
	int len;
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	char user_name[500];
	char domain_name[500];
	uint8_t resp[NT_LENGTH];

	/*
	 * Clear the auth parameters - this is important, as
	 * there are options that will cause wbcAuthenticateUserEx
	 * to bomb out if not zero.
	 */
	memset(&authparams, 0, sizeof(authparams));


	/*
	 * Get the username and domain from the configuration
	 */
	len = radius_xlat(user_name, sizeof(user_name), request, inst->ntlm_username, NULL, NULL);
	if (len < 0) goto done;

	authparams.account_name = user_name;

	if (inst->ntlm_domain) {
		len = radius_xlat(domain_name, sizeof(domain_name), request, inst->ntlm_domain, NULL, NULL);
		if (len < 0) goto done;

		authparams.domain_name = domain_name;
	} else {
		RDEBUG("no domain specified; authentication may fail because of this");
	}


	/*
	 * Build the wbcAuthUserParams structure with what we know
	 */
	//authparams.workstation_name = NULL;
	//authparams.flags = 0;
	//authparams.parameter_control = 0;
	authparams.level = WBC_AUTH_USER_LEVEL_RESPONSE;
	//authparams.password.response.lm_length = 0;
	authparams.password.response.nt_length = NT_LENGTH;

	memcpy(resp, response, NT_LENGTH);
	authparams.password.response.nt_data = resp;

	memcpy(authparams.password.response.challenge, challenge,
	       sizeof(authparams.password.response.challenge));


	/*
	 * Send auth request across to winbind
	 */
	RDEBUG("sending authentication request user='%s' domain='%s'", authparams.account_name,
								       authparams.domain_name);

	err = wbcAuthenticateUserEx(&authparams, &info, &error);


	/*
	 * Try and give some useful feedback on what happened
	 */
	switch (err) {
	case WBC_ERR_SUCCESS:
		rcode = 0;
		RDEBUG("Authenticated successfully");
		/* Grab the nthashhash from the result */
		memcpy(nthashhash, info->user_session_key, NT_DIGEST_LENGTH);
		break;
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		RERROR("Check that winbind is running and that FreeRADIUS");
		RERROR("has permission to connect to the winbind socket!");
		break;
	case WBC_ERR_DOMAIN_NOT_FOUND:
		RERROR("domain not found");
		break;
	case WBC_ERR_AUTH_ERROR:
		RDEBUG("authentication failed (check domain is correct)");
		break;
	default:
		RDEBUG("other error %d", err);
		break;
	}

	if (err != WBC_ERR_SUCCESS) {
		RDEBUG("authentication failed: wbcErr %d", err);
		if (error && error->display_string) {
			RDEBUG("wbcErr %s", error->display_string);
		}
	}


done:
	if (info) wbcFreeMemory(info);
	if (error) wbcFreeMemory(error);

	return rcode;
}

