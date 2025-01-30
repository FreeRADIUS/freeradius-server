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
 * @copyright 2001,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/util/chap.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/call_env.h>

typedef struct {
	fr_dict_enum_value_t		*auth_type;
	size_t				min_challenge_len;
} rlm_chap_t;

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("min_challenge_len", FR_TYPE_SIZE, 0, rlm_chap_t, min_challenge_len), .dflt = "16" },
	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_value_box_t	chap_challenge;
} chap_xlat_call_env_t;

static const call_env_method_t chap_xlat_method_env = { \
	FR_CALL_ENV_METHOD_OUT(chap_xlat_call_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_OFFSET("chap_challenge", FR_TYPE_OCTETS,
				     CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT,
				     chap_xlat_call_env_t,
				     chap_challenge), .pair.dflt = "&Chap-Challenge", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

typedef struct {
	fr_value_box_t	chap_password;
	fr_value_box_t	chap_challenge;
	tmpl_t		*chap_challenge_tmpl;
} chap_autz_call_env_t;

static const call_env_method_t chap_autz_method_env = { \
	FR_CALL_ENV_METHOD_OUT(chap_autz_call_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_OFFSET("chap_password", FR_TYPE_OCTETS,
				     CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT,
				     chap_autz_call_env_t, chap_password),
				     .pair.dflt = "&Chap-Password", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("chap_challenge", FR_TYPE_OCTETS,
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT,
					  chap_autz_call_env_t, chap_challenge, chap_challenge_tmpl),
					  .pair.dflt = "&Chap-Challenge", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

typedef struct {
	fr_value_box_t	username;
	fr_value_box_t	chap_password;
	fr_value_box_t	chap_challenge;
} chap_auth_call_env_t;

static const call_env_method_t chap_auth_method_env = { \
	FR_CALL_ENV_METHOD_OUT(chap_auth_call_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING,
				     CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT,
				     chap_auth_call_env_t, username),
				     .pair.dflt = "&User-Name", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("chap_password", FR_TYPE_OCTETS,
				     CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT,
				     chap_auth_call_env_t, chap_password),
				     .pair.dflt = "&Chap-Password", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("chap_challenge", FR_TYPE_OCTETS,
				     CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT,
				     chap_auth_call_env_t, chap_challenge),
				     .pair.dflt = "&Chap-Challenge", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_chap_dict[];
fr_dict_autoload_t rlm_chap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_cleartext_password;

extern fr_dict_attr_autoload_t rlm_chap_dict_attr[];
fr_dict_attr_autoload_t rlm_chap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ NULL }
};

static xlat_arg_parser_t const xlat_func_chap_password_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Produce a CHAP-Password hash value
 *
 * Example:
@verbatim
%chap.password(<password>) == 0x<id><md5_hash>
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_chap_password(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	     xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *in)
{
	rlm_chap_t const	*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_chap_t);
	uint8_t			chap_password[1 + FR_CHAP_CHALLENGE_LENGTH];
	fr_value_box_t		*vb;
	uint8_t	const		*challenge;
	size_t			challenge_len;
	fr_value_box_t		*in_head = fr_value_box_list_head(in);
	chap_xlat_call_env_t	*env_data = talloc_get_type_abort(xctx->env_data, chap_xlat_call_env_t);

	/*
	 *	Use Chap-Challenge pair if present,
	 *	Request Authenticator otherwise.
	 */
	if ((env_data->chap_challenge.type == FR_TYPE_OCTETS) &&
	    (env_data->chap_challenge.vb_length >= inst->min_challenge_len)) {
		challenge = env_data->chap_challenge.vb_octets;
		challenge_len = env_data->chap_challenge.vb_length;
	} else {
		if (env_data->chap_challenge.type == FR_TYPE_OCTETS)
			RWDEBUG("request.CHAP-Challenge shorter than minimum length (%ld)", inst->min_challenge_len);
		challenge = request->packet->vector;
		challenge_len = RADIUS_AUTH_VECTOR_LENGTH;
	}
	fr_chap_encode(chap_password, (uint8_t)(fr_rand() & 0xff), challenge, challenge_len,
				       in_head->vb_strvalue, in_head->vb_length);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, chap_password, sizeof(chap_password), false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_pair_t		*vp;
	rlm_chap_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_chap_t);
	chap_autz_call_env_t	*env_data = talloc_get_type_abort(mctx->env_data, chap_autz_call_env_t);

	if (fr_pair_find_by_da(&request->control_pairs, NULL, attr_auth_type) != NULL) {
		RDEBUG3("Auth-Type is already set.  Not setting 'Auth-Type := %s'", mctx->mi->name);
		RETURN_MODULE_NOOP;
	}

	/*
	 *	This case means the warnings below won't be printed
	 *	unless there's a CHAP-Password in the request.
	 */
	if (env_data->chap_password.type != FR_TYPE_OCTETS) {
		RETURN_MODULE_NOOP;
	}

	/*
	 *	Create the CHAP-Challenge if it wasn't already in the packet.
	 *
	 *	This is so that the rest of the code does not need to
	 *	understand CHAP.
	 */
	if (env_data->chap_challenge.type != FR_TYPE_OCTETS) {
		RDEBUG2("Creating %s from request authenticator", env_data->chap_challenge_tmpl->name);

		MEM(vp = fr_pair_afrom_da(request->request_ctx, tmpl_attr_tail_da(env_data->chap_challenge_tmpl)));
		fr_pair_value_memdup(vp, request->packet->vector, sizeof(request->packet->vector), true);
		fr_pair_append(&request->request_pairs, vp);
	}

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup CHAP authentication",
		     mctx->mi->name, mctx->mi->name);
		RETURN_MODULE_NOOP;
	}

	if (!module_rlm_section_type_set(request, attr_auth_type, inst->auth_type)) {
		RETURN_MODULE_NOOP;
	}

	RETURN_MODULE_OK;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_chap_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_chap_t);
	fr_pair_t		*known_good;
	uint8_t			pass_str[1 + FR_CHAP_CHALLENGE_LENGTH];
	chap_auth_call_env_t	*env_data = talloc_get_type_abort(mctx->env_data, chap_auth_call_env_t);

	int			ret;

	fr_dict_attr_t const	*allowed_passwords[] = { attr_cleartext_password };
	bool			ephemeral;

	uint8_t	const		*challenge;
	size_t			challenge_len;

	if (env_data->username.type != FR_TYPE_STRING) {
		REDEBUG("User-Name attribute is required for authentication");
		RETURN_MODULE_INVALID;
	}

	if (env_data->chap_password.type != FR_TYPE_OCTETS) {
		REDEBUG("You set 'control.Auth-Type = CHAP' for a request that "
			"does not contain a CHAP-Password attribute!");
		RETURN_MODULE_INVALID;
	}

	if (env_data->chap_password.vb_length == 0) {
		REDEBUG("request.CHAP-Password is empty");
		RETURN_MODULE_INVALID;
	}

	if (env_data->chap_password.vb_length != FR_CHAP_CHALLENGE_LENGTH + 1) {
		REDEBUG("request.CHAP-Password has invalid length");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Retrieve the normalised version of
	 *	the known_good password, without
	 *	mangling the current password attributes
	 *	in the request.
	 */
	known_good = password_find(&ephemeral, request, request,
				   allowed_passwords, NUM_ELEMENTS(allowed_passwords),
				   false);
	if (!known_good) {
		REDEBUG("No \"known good\" password found for user");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Output is id + password hash
	 */

	/*
	 *	Use Chap-Challenge pair if present,
	 *	Request Authenticator otherwise.
	 */
	if ((env_data->chap_challenge.type == FR_TYPE_OCTETS) &&
	    (env_data->chap_challenge.vb_length >= inst->min_challenge_len)) {
		challenge = env_data->chap_challenge.vb_octets;
		challenge_len = env_data->chap_challenge.vb_length;
	} else {
		if (env_data->chap_challenge.type == FR_TYPE_OCTETS)
			RWDEBUG("request.CHAP-Challenge shorter than minimum length (%ld)", inst->min_challenge_len);
		challenge = request->packet->vector;
		challenge_len = RADIUS_AUTH_VECTOR_LENGTH;
	}
	fr_chap_encode(pass_str, env_data->chap_password.vb_octets[0], challenge, challenge_len,
		       known_good->vp_strvalue, known_good->vp_length);

	/*
	 *	The password_find function already emits
	 *	a log message about the password attribute contents
	 *	so we don't need to duplicate it here.
	 */
	if (RDEBUG_ENABLED3) {
		uint8_t	const	*p;
		size_t		length;

		if (env_data->chap_challenge.type == FR_TYPE_OCTETS) {
			RDEBUG2("Using challenge from request.CHAP-Challenge");
			p = env_data->chap_challenge.vb_octets;
			length = env_data->chap_challenge.vb_length;
		} else {
			RDEBUG2("Using challenge from authenticator field");
			p = request->packet->vector;
			length = sizeof(request->packet->vector);
		}

		RINDENT();
		RDEBUG3("CHAP challenge : %pH", fr_box_octets(p, length));
		RDEBUG3("Client sent    : %pH", fr_box_octets(env_data->chap_password.vb_octets + 1,
							      FR_CHAP_CHALLENGE_LENGTH));
		RDEBUG3("We calculated  : %pH", fr_box_octets(pass_str + 1, FR_CHAP_CHALLENGE_LENGTH));
		REXDENT();
	}

	/*
	 *	Skip the id field at the beginning of the
	 *	password and chap response.
	 */
	ret = fr_digest_cmp(pass_str + 1, env_data->chap_password.vb_octets + 1, FR_CHAP_CHALLENGE_LENGTH);
	if (ephemeral) TALLOC_FREE(known_good);
	if (ret != 0) {
		REDEBUG("Password comparison failed: password is incorrect");

		RETURN_MODULE_REJECT;
	}

	RDEBUG2("CHAP user \"%pV\" authenticated successfully", &env_data->username);

	RETURN_MODULE_OK;
}

/*
 *	Create instance for our module. Allocate space for
 *	instance structure and read configuration parameters
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_chap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_chap_t);

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, mctx->mi->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  CHAP authentication will likely not work",
		     mctx->mi->name);
	}

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t	*xlat;

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "password", xlat_func_chap_password,
						       FR_TYPE_OCTETS)) == NULL)) return -1;
	xlat_func_args_set(xlat, xlat_func_chap_password_args);
	xlat_func_call_env_set(xlat, &chap_xlat_method_env);

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
extern module_rlm_t rlm_chap;
module_rlm_t rlm_chap = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "chap",
		.inst_size	= sizeof(rlm_chap_t),
		.bootstrap	= mod_bootstrap,
		.config		= module_config,
		.instantiate	= mod_instantiate
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate, .method_env = &chap_auth_method_env },
			{ .section = SECTION_NAME("recv", "Access-Request"), .method = mod_authorize, .method_env = &chap_autz_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
