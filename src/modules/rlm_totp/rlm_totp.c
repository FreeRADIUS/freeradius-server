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
 * @file rlm_totp.c
 * @brief Execute commands and parse the results.
 *
 * @copyright 2021  The FreeRADIUS server project
 * @copyright 2021  Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/base32.h>

#include <freeradius-devel/unlang/call_env.h>

#include "totp.h"

typedef struct {
	fr_value_box_t		secret;
	fr_value_box_t		key;
	fr_value_box_t		user_password;
} rlm_totp_call_env_t;

static const call_env_method_t method_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_totp_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("secret", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE, rlm_totp_call_env_t, secret),
				     .pair.dflt = "&control.TOTP.Secret", .pair.dflt_quote = T_BARE_WORD },

		{ FR_CALL_ENV_OFFSET("key", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE, rlm_totp_call_env_t, key),
				     .pair.dflt = "&control.TOTP.key", .pair.dflt_quote = T_BARE_WORD },

		{ FR_CALL_ENV_OFFSET("user_password", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE, rlm_totp_call_env_t, user_password),
				     .pair.dflt = "&request.TOTP.From-User", .pair.dflt_quote = T_BARE_WORD },

		CALL_ENV_TERMINATOR
	}
};

/* Define a structure for the configuration variables */
typedef struct rlm_totp_t {
	fr_totp_t	totp;			//! configuration entries passed to libfreeradius-totp
} rlm_totp_t;

/* Map configuration file names to internal variables */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("time_step", rlm_totp_t, totp.time_step), .dflt = "30" },
	{ FR_CONF_OFFSET("otp_length", rlm_totp_t, totp.otp_length), .dflt = "6" },
	{ FR_CONF_OFFSET("lookback_steps", rlm_totp_t, totp.lookback_steps), .dflt = "1" },
	{ FR_CONF_OFFSET("lookback_interval", rlm_totp_t, totp.lookback_interval), .dflt = "30" },
	{ FR_CONF_OFFSET("lookforward_steps", rlm_totp_t, totp.lookforward_steps), .dflt = "0" },
	CONF_PARSER_TERMINATOR
};

/*
 *  Do the authentication
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_totp_call_env_t	*env_data = talloc_get_type_abort(mctx->env_data, rlm_totp_call_env_t);
	rlm_totp_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_totp_t);
	fr_value_box_t		*user_password = &env_data->user_password;
	fr_value_box_t		*secret = &env_data->secret;
	fr_value_box_t		*key = &env_data->key;

	uint8_t const		*our_key;
	size_t			our_keylen;
	uint8_t			buffer[80];	/* multiple of 5*8 characters */

	if (fr_type_is_null(user_password->type)) RETURN_MODULE_NOOP;

	if (user_password->vb_length == 0) {
		RWARN("TOTP.From-User is empty");
		RETURN_MODULE_FAIL;
	}

	if ((user_password->vb_length != 6) && (user_password->vb_length != 8)) {
		RWARN("TOTP.From-User has incorrect length. Expected 6 or 8, got %zu", user_password->vb_length);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Look for the raw key first.
	 */
	if (!fr_type_is_null(key->type)) {
		our_key = key->vb_octets;
		our_keylen = key->vb_length;

	} else {
		ssize_t len;

		if (fr_type_is_null(secret->type)) RETURN_MODULE_NOOP;

		len = fr_base32_decode(&FR_DBUFF_TMP((uint8_t *) buffer, sizeof(buffer)), &FR_SBUFF_IN(secret->vb_strvalue, secret->vb_length), true, true);
		if (len < 0) {
			RERROR("TOTP.Secret cannot be decoded");
			RETURN_MODULE_FAIL;
		}

		our_key = buffer;
		our_keylen = len;
	}

	switch (fr_totp_cmp(&inst->totp, request, fr_time_to_sec(request->packet->timestamp), our_key, our_keylen, user_password->vb_strvalue)) {
	case 0:
		RETURN_MODULE_OK;

	case -2:
		RETURN_MODULE_FAIL;

	default:
		RETURN_MODULE_REJECT;
	}
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_totp_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_totp_t);

	FR_INTEGER_BOUND_CHECK("time_step", inst->totp.time_step, >=, 5);
	FR_INTEGER_BOUND_CHECK("time_step", inst->totp.time_step, <=, 120);

	FR_INTEGER_BOUND_CHECK("lookback_steps", inst->totp.lookback_steps, >=, 1);
	FR_INTEGER_BOUND_CHECK("lookback_steps", inst->totp.lookback_steps, <=, 10);

	FR_INTEGER_BOUND_CHECK("lookforward_steps", inst->totp.lookforward_steps, <=, 10);

	FR_INTEGER_BOUND_CHECK("lookback_interval", inst->totp.lookback_interval, <=, inst->totp.time_step);

	FR_INTEGER_BOUND_CHECK("otp_length", inst->totp.otp_length, >=, 6);
	FR_INTEGER_BOUND_CHECK("otp_length", inst->totp.otp_length, <=, 8);

	if (inst->totp.otp_length == 7) inst->totp.otp_length = 8;

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_totp;
module_rlm_t rlm_totp = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "totp",
		.inst_size	= sizeof(rlm_totp_t),
		.config		= module_config,
		.instantiate	= mod_instantiate
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate, .method_env = &method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
