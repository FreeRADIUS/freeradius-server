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
 * @file rlm_winbind.c
 * @brief Authenticates against Active Directory or Samba using winbind
 *
 * @author Matthew Newton <matthew@newtoncomputing.co.uk>
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Matthew Newton <matthew@newtoncomputing.co.uk>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_winbind.h"
#include "auth_wbclient_pap.h"

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("winbind_username", PW_TYPE_TMPL, rlm_winbind_t, wb_username) },
	{ FR_CONF_OFFSET("winbind_domain", PW_TYPE_TMPL, rlm_winbind_t, wb_domain) },
	CONF_PARSER_TERMINATOR
};

/*
 *	Free connection pool winbind context
 */
static int _mod_conn_free(struct wbcContext **wb_ctx)
{
	wbcCtxFree(*wb_ctx);

	return 0;
}

/*
 *	Create connection pool winbind context
 */
static void *mod_conn_create(TALLOC_CTX *ctx, UNUSED void *instance, UNUSED struct timeval const *timeout)
{
	struct wbcContext **wb_ctx;

	wb_ctx = talloc_zero(ctx, struct wbcContext *);
	*wb_ctx = wbcCtxCreate();

	if (*wb_ctx == NULL) {
		ERROR("failed to create winbind context");
		talloc_free(wb_ctx);
		return NULL;
	}

	talloc_set_destructor(wb_ctx, _mod_conn_free);

	return *wb_ctx;
}


static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_winbind_t		*inst = instance;

	if (!inst->wb_username) {
		cf_log_err_cs(conf, "winbind_username must be defined to use rlm_winbind");
		return -1;
	}

	inst->wb_pool = module_connection_pool_init(conf, inst, mod_conn_create, NULL, NULL, NULL, NULL);
	if (!inst->wb_pool) {
		cf_log_err_cs(conf, "Unable to initialise winbind connection pool");
		return -1;
	}

	return 0;
}

/*
 *	Tidy up instance
 */
static int mod_detach(UNUSED void *instance)
{
	rlm_winbind_t *inst = instance;

	fr_connection_pool_free(inst->wb_pool);
	return 0;
}


/** Authorize for libwbclient/winbind authentication
 *
 * Just check there is a password available so we can authenticate
 * against winbind, and if so set Auth-Type to ourself.
 *
 * @param[in] instanvce Module instance
 * @param[in] request The current request
 * @return
 *	- #RLM_MODULE_NOOP unable to use winbind authentication
 *	- #RLM_MODULE_OK Auth-Type has been set to winbind
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, REQUEST *request)
{
	if (!request->password || (request->password->da->attr != PW_USER_PASSWORD)) {
		RDEBUG("No User-Password found in the request; not doing winbind authentication.");
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_num(request->control, 0, PW_AUTH_TYPE, TAG_ANY) != NULL) {
		RWDEBUG2("Auth-type already set, not setting to winbind");
		return RLM_MODULE_NOOP;
	}

	RDEBUG("Setting Auth-Type to winbind");
	pair_make_config("Auth-Type", "winbind", T_OP_EQ);

	return RLM_MODULE_OK;
}


/** Authenticate the user via libwbclient and winbind
 *
 * @param[in] instance Module instance
 * @param[in] request The current request
 * @return One of the RLM_MODULE_* values
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_winbind_t *inst = instance;

	/*
	 *	Check the admin hasn't been silly
	 */
	if (!request->password ||
	    (request->password->da->vendor != 0) ||
	    (request->password->da->attr != PW_USER_PASSWORD)) {
		REDEBUG("You set 'Auth-Type = winbind' for a request that does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (request->password->vp_length == 0) {
		REDEBUG("Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Debug the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG3("Login attempt with password \"%s\" (%zd)", request->password->vp_strvalue, request->password->vp_length);
	} else {
		RDEBUG("Login attempt with password");
	}

	/*
	 *	Authenticate and return OK if successful. No need for
	 *	many debug outputs or errors as the auth function is
	 *	chatty enough.
	 */
	if (do_auth_wbclient_pap(inst, request) == 0) {
		RDEBUG("User authenticated successfully using winbind");
		return RLM_MODULE_OK;
	}

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
extern module_t rlm_winbind;
module_t rlm_winbind = {
	.magic		= RLM_MODULE_INIT,
	.name		= "winbind",
	.type		= RLM_TYPE_HUP_SAFE,
	.inst_size	= sizeof(rlm_winbind_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
