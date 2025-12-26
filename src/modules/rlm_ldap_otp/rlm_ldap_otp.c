/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file rlm_ldap_otp.c
 * @brief LDAP with local OTP authentication module.
 *
 * @copyright 2025 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/base32.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/unlang/call_env.h>

#include "rlm_ldap_otp.h"

typedef struct {
	uint32_t	time_step;
	uint32_t	otp_length;
	uint32_t	lookback_steps;
	uint32_t	lookback_interval;
	uint32_t	lookforward_steps;
} fr_totp_t;

int fr_totp_cmp(fr_totp_t const *cfg, request_t *request, time_t now, uint8_t const *key, size_t keylen, char const *totp);

typedef struct {
	fr_value_box_t		secret;
	fr_value_box_t		user_password;
} rlm_ldap_otp_call_env_t;

static const call_env_method_t method_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_ldap_otp_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("secret", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, rlm_ldap_otp_call_env_t, secret),
				     .pair.dflt = "control.LDAP-OTP-Secret", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("user_password", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, rlm_ldap_otp_call_env_t, user_password),
				     .pair.dflt = "request.User-Password", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

typedef struct {
	fr_totp_t		totp;
} rlm_ldap_otp_t;

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("time_step", rlm_ldap_otp_t, totp.time_step), .dflt = "30" },
	{ FR_CONF_OFFSET("otp_length", rlm_ldap_otp_t, totp.otp_length), .dflt = "6" },
	{ FR_CONF_OFFSET("lookback_steps", rlm_ldap_otp_t, totp.lookback_steps), .dflt = "1" },
	{ FR_CONF_OFFSET("lookback_interval", rlm_ldap_otp_t, totp.lookback_interval), .dflt = "30" },
	{ FR_CONF_OFFSET("lookforward_steps", rlm_ldap_otp_t, totp.lookforward_steps), .dflt = "0" },
	CONF_PARSER_TERMINATOR
};

static unlang_action_t CC_HINT(nonnull) mod_authenticate(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_otp_call_env_t	*env_data = talloc_get_type_abort(mctx->env_data, rlm_ldap_otp_call_env_t);
	rlm_ldap_otp_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_ldap_otp_t);
	fr_value_box_t		*user_password = &env_data->user_password;
	fr_value_box_t		*secret = &env_data->secret;

	uint8_t const		*our_key;
	size_t			our_keylen;
	uint8_t			buffer[80];
	time_t			now;

	if (fr_type_is_null(user_password->type)) RETURN_UNLANG_NOOP;

	if (user_password->vb_length == 0) {
		RWARN("User-Password is empty");
		RETURN_UNLANG_FAIL;
	}

	if ((user_password->vb_length != 6) && (user_password->vb_length != 8)) {
		RWARN("OTP has incorrect length. Expected 6 or 8, got %zu", user_password->vb_length);
		RETURN_UNLANG_FAIL;
	}

	if (fr_type_is_null(secret->type)) {
		RWARN("LDAP-OTP-Secret not found in control list");
		RETURN_UNLANG_NOOP;
	}

	ssize_t len = fr_base32_decode(&FR_DBUFF_TMP((uint8_t *) buffer, sizeof(buffer)), &FR_SBUFF_IN(secret->vb_strvalue, secret->vb_length), true, true);
	if (len < 0) {
		RERROR("LDAP-OTP-Secret cannot be decoded");
		RETURN_UNLANG_FAIL;
	}

	our_key = buffer;
	our_keylen = len;

	now = fr_time_to_sec(request->packet->timestamp);

	switch (fr_totp_cmp(&inst->totp, request, now, our_key, our_keylen, user_password->vb_strvalue)) {
	case 0:
		RETURN_UNLANG_OK;

	case -2:
		RETURN_UNLANG_FAIL;

	default:
		RETURN_UNLANG_REJECT;
	}
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_ldap_otp_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_ldap_otp_t);

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

extern module_rlm_t rlm_ldap_otp;
module_rlm_t rlm_ldap_otp = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "ldap_otp",
		.inst_size	= sizeof(rlm_ldap_otp_t),
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
