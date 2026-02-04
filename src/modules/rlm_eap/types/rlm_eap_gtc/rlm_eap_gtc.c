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
 * @file rlm_eap_gtc.c
 * @brief EAP-GTC inner authentication method.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/interpret.h>

static int auth_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED conf_parser_t const *rule);

/*
 *	EAP-GTC is just ASCII data carried inside of the EAP session.
 *	The length of the data is indicated by the encapsulating EAP
 *	protocol.
 */
typedef struct {
	char const		*challenge;
	fr_dict_enum_value_t const	*auth_type;
} rlm_eap_gtc_t;

typedef struct {
	unlang_result_t		section_result;
} rlm_eap_gtc_rctx_t;

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("challenge", rlm_eap_gtc_t, challenge), .dflt = "Password: " },
	{ FR_CONF_OFFSET_TYPE_FLAGS("auth_type", FR_TYPE_VOID, 0, rlm_eap_gtc_t, auth_type), .func = auth_type_parse,  .dflt = "pap" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_gtc_dict[];
fr_dict_autoload_t rlm_eap_gtc_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_eap_gtc_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_gtc_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};

static unlang_action_t mod_session_init(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request);

/** Translate a string auth_type into an enumeration value
 *
 * @param[in] ctx	to allocate data.
 * @param[out] out	Where to write the auth_type we created or resolved.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the auth_type.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int auth_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	char const	*auth_type = cf_pair_value(cf_item_to_pair(ci));

	if (fr_dict_enum_add_name_next(fr_dict_attr_unconst(attr_auth_type), auth_type) < 0) {
		cf_log_err(ci, "Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	*((fr_dict_enum_value_t **)out) = UNCONST(fr_dict_enum_value_t *, fr_dict_enum_by_name(attr_auth_type, auth_type, -1));

	return 0;
}

/*
 *	Keep processing the Auth-Type until it doesn't return YIELD.
 */
static unlang_action_t gtc_resume(unlang_result_t *p_result, module_ctx_t const *mctx,  request_t *request)
{
	rlm_eap_gtc_rctx_t *rctx = talloc_get_type_abort(mctx->rctx, rlm_eap_gtc_rctx_t);
	rlm_rcode_t	rcode;

	eap_session_t	*eap_session = eap_session_get(request->parent);
	eap_round_t	*eap_round = eap_session->this_round;

	rcode = rctx->section_result.rcode;
	if (rcode != RLM_MODULE_OK) {
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		RETURN_UNLANG_RCODE(rcode);
	}

	eap_round->request->code = FR_EAP_CODE_SUCCESS;
	RETURN_UNLANG_OK;
}

/*
 *	Authenticate a previously sent challenge.
 */
static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_gtc_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_gtc_t);
	rlm_eap_gtc_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, rlm_eap_gtc_rctx_t);

	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_round_t		*eap_round = eap_session->this_round;

	fr_pair_t		*vp;
	CONF_SECTION		*unlang;

	/*
	 *	Get the Password.Cleartext for this user.
	 */

	/*
	 *	Sanity check the response.  We need at least one byte
	 *	of data.
	 */
	if (eap_round->response->length <= 4) {
		REDEBUG("Corrupted data");
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	EAP packets can be ~64k long maximum, and
	 *	we don't like that.
	 */
	if (eap_round->response->type.length > 128) {
		REDEBUG("Response is too large to understand");
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	If there was a User-Password in the request,
	 *	why the heck are they using EAP-GTC?
	 */
	MEM(pair_update_request(&vp, attr_user_password) >= 0);
	fr_pair_value_bstrndup(vp, (char const *)eap_round->response->type.data, eap_round->response->type.length, true);

	unlang = cf_section_find(unlang_call_current(request), "authenticate", inst->auth_type->name);
	if (!unlang) unlang = cf_section_find(unlang_call_current(request->parent), "authenticate", inst->auth_type->name);
	if (!unlang) {
		RDEBUG2("authenticate %s { ... } sub-section not found.",
			inst->auth_type->name);
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		RETURN_UNLANG_FAIL;
	}

	return unlang_module_yield_to_section(&rctx->section_result, request, unlang, RLM_MODULE_FAIL, gtc_resume, NULL, 0, rctx);
}


/*
 *	Initiate the EAP-GTC session by sending a challenge to the peer.
 */
static unlang_action_t mod_session_init(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t	*eap_session = eap_session_get(request->parent);
	char		challenge_str[1024];
	int		length;
	eap_round_t	*eap_round = eap_session->this_round;
	rlm_eap_gtc_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_gtc_t);

	if (xlat_eval(challenge_str, sizeof(challenge_str), request, inst->challenge, NULL, NULL) < 0) {
		RETURN_UNLANG_FAIL;
	}

	length = strlen(challenge_str);

	/*
	 *	We're sending a request...
	 */
	eap_round->request->code = FR_EAP_CODE_REQUEST;

	eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, length);
	if (!eap_round->request->type.data) RETURN_UNLANG_FAIL;

	memcpy(eap_round->request->type.data, challenge_str, length);
	eap_round->request->type.length = length;

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'eap_session->this_round', which will be given back
	 *	to us...
	 */
	eap_session->process = mod_process;

	RETURN_UNLANG_HANDLED;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_gtc;
rlm_eap_submodule_t rlm_eap_gtc = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "eap_gtc",
		MODULE_INST(rlm_eap_gtc_t),
		MODULE_RCTX(rlm_eap_gtc_rctx_t),
		.config		= submodule_config,
	},
	.provides	= { FR_EAP_METHOD_GTC },
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.clone_parent_lists = true		/* HACK */
};
