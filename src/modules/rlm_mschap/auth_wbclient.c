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
 * @copyright 2015 Matthew Newton
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

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

/** Use Winbind to normalise a username
 *
 * @param[in] ctx	The talloc context where the result is parented from
 * @param[in] wb_ctx	The winbind context
 * @param[in] dom_name	The domain of the user
 * @param[in] name	The username (without the domain) to be normalised
 * @return
 *	- The username with the casing according to the Winbind remote server.
 *	- NULL if the username could not be found.
 */
static char *wbclient_normalise_username(TALLOC_CTX *ctx, struct wbcContext *wb_ctx,
					 char const *dom_name, char const *name)
{
	struct wbcDomainSid	sid;
	enum wbcSidType		name_type;
	wbcErr			err;
	char			*res_domain = NULL;
	char			*res_name = NULL;
	char			*res = NULL;

	/* Step 1: Convert a name to a sid */
	err = wbcCtxLookupName(wb_ctx, dom_name, name, &sid, &name_type);
	if (!WBC_ERROR_IS_OK(err)) return NULL;

	/* Step 2: Convert the sid back to a name */
	err = wbcCtxLookupSid(wb_ctx, &sid, &res_domain, &res_name, &name_type);
	if (!WBC_ERROR_IS_OK(err)) return NULL;

	MEM(res = talloc_strdup(ctx, res_name));

	wbcFreeMemory(res_domain);
	wbcFreeMemory(res_name);

	return res;
}

/** Check NTLM authentication direct to winbind via Samba's libwbclient library
 *
 * @return
 *	- 0 success.
 *	- -1 auth failure.
 *	- -648 password expired.
 */
int do_auth_wbclient(rlm_mschap_t const *inst, REQUEST *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH])
{
	int				ret = -1;
	struct wbcContext		*wb_ctx = NULL;
	struct wbcAuthUserParams	*authparams;
	wbcErr				err;
	ssize_t				slen;
	struct wbcAuthUserInfo		*info = NULL;
	struct wbcAuthErrorInfo		*error = NULL;
	uint8_t				resp[NT_LENGTH];

	/*
	 *	wb_username must be set for this function to be called
	 */
	rad_assert(inst->wb_username);

	MEM(authparams = talloc_zero_pooled_object(NULL, wbcAuthUserParams, 2, 1024));
	/*
	 *	Domain first so we don't leave holes in the pool
	 */
	if (inst->wb_domain) {
		slen = tmpl_aexpand(authparams, &authparams->domain_name, request, inst->wb_domain, NULL, NULL);
		if (slen < 0) {
			REDEBUG2("Unable to expand winbind_domain");
			goto finish;
		}
	} else {
		RWDEBUG2("No domain specified; authentication may fail because of this");
	}

	/*
	 *	Get the username and domain from the configuration
	 */
	slen = tmpl_aexpand(authparams, &authparams->account_name, request, inst->wb_username, NULL, NULL);
	if (slen < 0) {
		REDEBUG2("Unable to expand winbind_username");
		goto finish;
	}

	/*
	 * Build the wbcAuthUserParams structure with what we know
	 */
	authparams->level = WBC_AUTH_USER_LEVEL_RESPONSE;
	authparams->password.response.nt_length = NT_LENGTH;

	memcpy(resp, response, NT_LENGTH);
	authparams->password.response.nt_data = resp;

	memcpy(authparams->password.response.challenge, challenge, sizeof(authparams->password.response.challenge));

	authparams->parameter_control |= WBC_MSV1_0_ALLOW_MSVCHAPV2 |
					WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
					WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	/*
	 * Send auth request across to winbind
	 */
	wb_ctx = fr_pool_connection_get(inst->wb_pool, request);
	if (wb_ctx == NULL) {
		RERROR("Unable to get winbind connection from pool");
		goto finish;
	}

	RDEBUG2("Sending authentication request user \"%pV\" domain \"%pV\"",
		fr_box_strvalue_buffer(authparams->account_name),
		fr_box_strvalue_buffer(authparams->domain_name));

	err = wbcCtxAuthenticateUserEx(wb_ctx, authparams, &info, &error);
	if (err == WBC_ERR_AUTH_ERROR && inst->wb_retry_with_normalised_username) {
		VALUE_PAIR 	*vp_response;
		VALUE_PAIR	*vp_challenge;
		VALUE_PAIR	*vp_chap_user_name;
		char		*normalised_username = NULL;

		normalised_username = wbclient_normalise_username(authparams, wb_ctx, authparams->domain_name,
								  authparams->account_name);
		if (!normalised_username) goto release;

		RDEBUG2("Starting retry, normalised username \"%pV\" -> \"%pV\"",
			fr_box_strvalue_buffer(authparams->account_name),
			fr_box_strvalue_buffer(normalised_username));

		if (talloc_memcmp_bstr(authparams->account_name, normalised_username) == 0) goto release;

		TALLOC_FREE(authparams->account_name);
		authparams->account_name = normalised_username;

		/* Set MS-CHAP-USER-NAME */
		MEM(pair_update_request(&vp_chap_user_name, attr_ms_chap_user_name) >= 0);
		fr_pair_value_bstrncpy(vp_chap_user_name,
				       normalised_username, talloc_array_length(normalised_username) - 1);

		RDEBUG2("Retrying authentication request user \"%pV\" domain \"%s\"",
			fr_box_strvalue_buffer(authparams->account_name),
			fr_box_strvalue_buffer(normalised_username));

		/* Recalculate hash */
		vp_challenge = fr_pair_find_by_da(request->packet->vps, attr_ms_chap_challenge, TAG_ANY);
		if (!vp_challenge) {
			RERROR("Unable to get MS-CHAP-Challenge");
			goto release;
		}

		vp_response = fr_pair_find_by_da(request->packet->vps, attr_ms_chap2_response, TAG_ANY);
		if (!vp_response) {
			RERROR("Unable to get MS-CHAP2-Response");
			goto release;
		}

		mschap_challenge_hash(authparams->password.response.challenge,
				      vp_response->vp_octets + 2,
				      vp_challenge->vp_octets,
				      vp_chap_user_name->vp_strvalue, vp_chap_user_name->vp_length, talloc);

		err = wbcCtxAuthenticateUserEx(wb_ctx, authparams, &info, &error);
release:
		talloc_free(normalised_username);
	}

	fr_pool_connection_release(inst->wb_pool, request, wb_ctx);

	/*
	 * Try and give some useful feedback on what happened. There are only
	 * a few errors that can actually be returned from wbcCtxAuthenticateUserEx.
	 */
	switch (err) {
	case WBC_ERR_SUCCESS:
		ret = 0;
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
		 * The password needs to be changed, so set ret appropriately.
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

finish:
	talloc_free(authparams);
	if (info) wbcFreeMemory(info);
	if (error) wbcFreeMemory(error);

	return ret;
}

