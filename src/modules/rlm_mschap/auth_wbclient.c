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
 * @file auth_wbclient.c
 * @brief NTLM authentication against the wbclient library
 *
 * @copyright 2015  Matthew Newton
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <wbclient.h>
#include <core/ntstatus.h>

#include "rlm_mschap.h"
#include "mschap.h"
#include "auth_wbclient.h"

/* Samba does not export this constant yet */
#ifndef WBC_MSV1_0_ALLOW_MSVCHAPV2
#define WBC_MSV1_0_ALLOW_MSVCHAPV2 0x00010000
#endif

#define NT_LENGTH 24

/*
 *	Check NTLM authentication direct to winbind via
 *	Samba's libwbclient library
 *
 *	Returns:
 *	 0    success
 *	 -1   auth failure
 *	 -648 password expired
 */
int do_auth_wbclient(rlm_mschap_t *inst, REQUEST *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH])
{
	int rcode = -1;
	struct wbcContext *wb_ctx;
	struct wbcAuthUserParams authparams;
	wbcErr err;
	int len;
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	char user_name_buf[500];
	char domain_name_buf[500];
	uint8_t resp[NT_LENGTH];

	/*
	 * Clear the auth parameters - this is important, as
	 * there are options that will cause wbcAuthenticateUserEx
	 * to bomb out if not zero.
	 */
	memset(&authparams, 0, sizeof(authparams));

	/*
	 * wb_username must be set for this function to be called
	 */
	rad_assert(inst->wb_username);

	/*
	 * Get the username and domain from the configuration
	 */
	len = tmpl_expand(&authparams.account_name, user_name_buf, sizeof(user_name_buf),
			  request, inst->wb_username, NULL, NULL);
	if (len < 0) {
		REDEBUG2("Unable to expand winbind_username");
		goto done;
	}

	if (inst->wb_domain) {
		len = tmpl_expand(&authparams.domain_name, domain_name_buf, sizeof(domain_name_buf),
				  request, inst->wb_domain, NULL, NULL);
		if (len < 0) {
			REDEBUG2("Unable to expand winbind_domain");
			goto done;
		}
	} else {
		RWDEBUG2("No domain specified; authentication may fail because of this");
	}


	/*
	 * Build the wbcAuthUserParams structure with what we know
	 */
	authparams.level = WBC_AUTH_USER_LEVEL_RESPONSE;
	authparams.password.response.nt_length = NT_LENGTH;

	memcpy(resp, response, NT_LENGTH);
	authparams.password.response.nt_data = resp;

	memcpy(authparams.password.response.challenge, challenge,
	       sizeof(authparams.password.response.challenge));

	authparams.parameter_control |= WBC_MSV1_0_ALLOW_MSVCHAPV2;

	/*
	 * Send auth request across to winbind
	 */
	wb_ctx = fr_connection_get(inst->wb_pool, request);
	if (wb_ctx == NULL) {
		RERROR("Unable to get winbind connection from pool");
		goto done;
	}

	RDEBUG2("sending authentication request user='%s' domain='%s'", authparams.account_name,
									authparams.domain_name);

	err = wbcCtxAuthenticateUserEx(wb_ctx, &authparams, &info, &error);

	fr_connection_release(inst->wb_pool, request, wb_ctx);


	/*
	 * Try and give some useful feedback on what happened. There are only
	 * a few errors that can actually be returned from wbcCtxAuthenticateUserEx.
	 */
	switch (err) {
	case WBC_ERR_SUCCESS:
		rcode = 0;
		RDEBUG2("Authenticated successfully");
		/* Grab the nthashhash from the result */
		memcpy(nthashhash, info->user_session_key, NT_DIGEST_LENGTH);
		break;
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		RERROR("Unable to contact winbind!");
		RDEBUG2("Check that winbind is running and that FreeRADIUS has");
		RDEBUG2("permission to connect to the winbind privileged socket.");
		break;
	case WBC_ERR_DOMAIN_NOT_FOUND:
		REDEBUG2("Domain not found");
		break;
	case WBC_ERR_AUTH_ERROR:
		if (!error) {
			REDEBUG2("Authentication failed");
			break;
		}

		/*
		 * The password needs to be changed, so set rcode appropriately.
		 */
		if (error->nt_status & NT_STATUS_PASSWORD_EXPIRED ||
		    error->nt_status & NT_STATUS_PASSWORD_MUST_CHANGE) {
			rcode = -648;
		}

		/*
		 * Return the NT_STATUS human readable error string, if there is one.
		 */
		if (error->display_string) {
			REDEBUG2("%s [0x%X]", error->display_string, error->nt_status);
		} else {
			REDEBUG2("Authentication failed [0x%X]", error->nt_status);
		}
		break;
	default:
		/*
		 * Only errors left are 
		 *   WBC_ERR_INVALID_PARAM
		 *   WBC_ERR_NO_MEMORY
		 * neither of which are particularly likely.
		 */
		if (error && error->display_string) {
			REDEBUG2("libwbclient error: wbcErr %d (%s)", err, error->display_string);
		} else {
			REDEBUG2("libwbclient error: wbcErr %d", err);
		}
		break;
	}


done:
	if (info) wbcFreeMemory(info);
	if (error) wbcFreeMemory(error);

	return rcode;
}

