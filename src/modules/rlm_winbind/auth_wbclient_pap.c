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
 * @file auth_wbclient_pap.c
 * @brief PAP authentication against the wbclient library
 *
 * @author Matthew Newton (matthew@newtoncomputing.co.uk)
 *
 * @copyright 2015-2016 Matthew Newton
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <wbclient.h>
#include <core/ntstatus.h>

#include "rlm_winbind.h"
#include "auth_wbclient_pap.h"

/** PAP authentication direct to winbind via Samba's libwbclient library
 *
 * @param[in] request The current request
 * @param[in] env The call_env for the current winbind authentication
 * @param[in] t The module thread instance data.
 *
 * @return
 *	- 0	Success
 *	- -1	Authentication failure
 *	- -648	Password expired
 *
 */
int do_auth_wbclient_pap(request_t *request, winbind_auth_call_env_t *env, rlm_winbind_thread_t *t)
{
	int				ret = -1;
	winbind_ctx_t			*wbctx;
	struct wbcContext		*wb_ctx;
	struct wbcAuthUserParams	authparams;
	wbcErr				err;
	struct wbcAuthUserInfo		*info = NULL;
	struct wbcAuthErrorInfo		*error = NULL;

	/*
	 * Clear the auth parameters - this is important, as
	 * there are options that will cause wbcAuthenticateUserEx
	 * to bomb out if not zero.
	 */
	memset(&authparams, 0, sizeof(authparams));

	/*
	 * username must be set for this function to be called
	 */
	fr_assert(env->username.type == FR_TYPE_STRING);

	authparams.account_name = env->username.vb_strvalue;

	if (env->domain.type == FR_TYPE_STRING) {
		authparams.domain_name = env->domain.vb_strvalue;
	} else {
		RWDEBUG2("No domain specified; authentication may fail because of this");
	}


	/*
	 * Build the wbcAuthUserParams structure with what we know
	 */
	authparams.level = WBC_AUTH_USER_LEVEL_PLAIN;
	authparams.password.plaintext = env->password.vb_strvalue;

	/*
	 * Parameters documented as part of the MSV1_0_SUBAUTH_LOGON structure
	 * at https://msdn.microsoft.com/aa378767.aspx
	 */
	authparams.parameter_control |= WBC_MSV1_0_CLEARTEXT_PASSWORD_ALLOWED |
					WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
					WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	/*
	 * Send auth request across to winbind
	 */
	wbctx = winbind_slab_reserve(t->slab);
	if (!wbctx) {
		RERROR("Unable to get winbind context");
		goto done;
	}
	wb_ctx = wbctx->ctx;

	RDEBUG2("Sending authentication request user='%s' domain='%s'", authparams.account_name,
									authparams.domain_name);

	err = wbcCtxAuthenticateUserEx(wb_ctx, &authparams, &info, &error);

	winbind_slab_release(wbctx);

	/*
	 * Try and give some useful feedback on what happened. There are only
	 * a few errors that can actually be returned from wbcCtxAuthenticateUserEx.
	 */
	switch (err) {
	case WBC_ERR_SUCCESS:
		ret = 0;
		RDEBUG2("Authenticated successfully");
		break;

	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		RERROR("Unable to contact winbindd");
		RDEBUG2("Check that winbind is running and that FreeRADIUS has");
		RDEBUG2("permission to connect to the winbind privileged socket");
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
		 * The password needs to be changed, set ret appropriately.
		 */
		if (error->nt_status == NT_STATUS_PASSWORD_EXPIRED ||
		    error->nt_status == NT_STATUS_PASSWORD_MUST_CHANGE) {
			ret = -648;
		}

		/*
		 * Return the NT_STATUS human readable error string, if there is one.
		 */
		if (error->display_string) {
			REDEBUG2("%s [0x%X]", error->display_string, error->nt_status);
		} else {
			REDEBUG2("Unknown authentication failure [0x%X]", error->nt_status);
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
			REDEBUG2("Failed authenticating user: %s (%s)", error->display_string, wbcErrorString(err));
		} else {
			REDEBUG2("Failed authenticating user: Winbind error (%s)", wbcErrorString(err));
		}
		break;
	}


done:
	if (info) wbcFreeMemory(info);
	if (error) wbcFreeMemory(error);

	return ret;
}

