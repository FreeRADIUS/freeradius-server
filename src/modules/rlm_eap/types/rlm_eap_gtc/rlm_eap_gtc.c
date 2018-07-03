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

#define LOG_PREFIX "rlm_eap_gtc - "

#include <stdio.h>
#include <stdlib.h>

#include <freeradius-devel/unlang.h>
#include "eap.h"

#include <freeradius-devel/rad_assert.h>

static int auth_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

/*
 *	EAP-GTC is just ASCII data carried inside of the EAP session.
 *	The length of the data is indicated by the encapsulating EAP
 *	protocol.
 */
typedef struct rlm_eap_gtc_t {
	char const		*challenge;
	fr_dict_enum_t const	*auth_type;
} rlm_eap_gtc_t;

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("challenge", FR_TYPE_STRING, rlm_eap_gtc_t, challenge), .dflt = "Password: " },
	{ FR_CONF_OFFSET("auth_type", FR_TYPE_VOID, rlm_eap_gtc_t, auth_type), .func = auth_type_parse,  .dflt = "pap" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_eap_gtc_dict[];
fr_dict_autoload_t rlm_eap_gtc_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_eap_gtc_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_gtc_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, eap_session_t *eap_session);

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
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*auth_type = cf_pair_value(cf_item_to_pair(ci));

	if (fr_dict_enum_add_alias_next(attr_auth_type, auth_type) < 0) {
		cf_log_err(ci, "Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	*((fr_dict_enum_t **)out) = fr_dict_enum_by_alias(attr_auth_type, auth_type, -1);

	return 0;
}

/*
 *	Keep processing the Auth-Type until it doesn't return YIELD.
 */
static rlm_rcode_t mod_process_auth_type(UNUSED void *instance, eap_session_t *eap_session)
{
	rlm_rcode_t	rcode;
	eap_round_t	*eap_round = eap_session->this_round;
	REQUEST		*request = eap_session->request;

	rcode = unlang_interpret_continue(request);

	if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_REJECT;

	if (rcode == RLM_MODULE_YIELD) return rcode;

	if (rcode != RLM_MODULE_OK) {
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		return rcode;
	}

	eap_round->request->code = FR_EAP_CODE_SUCCESS;
	return RLM_MODULE_OK;
}

/*
 *	Authenticate a previously sent challenge.
 */
static rlm_rcode_t mod_process(void *instance, eap_session_t *eap_session)
{
	int		rcode;
	VALUE_PAIR	*vp;
	eap_round_t	*eap_round = eap_session->this_round;
	rlm_eap_gtc_t	*inst = talloc_get_type_abort(instance, rlm_eap_gtc_t);
	REQUEST		*request = eap_session->request;
	CONF_SECTION	*unlang;

	/*
	 *	Get the Cleartext-Password for this user.
	 */

	/*
	 *	Sanity check the response.  We need at least one byte
	 *	of data.
	 */
	if (eap_round->response->length <= 4) {
		REDEBUG("Corrupted data");
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		return RLM_MODULE_INVALID;
	}

	/*
	 *	EAP packets can be ~64k long maximum, and
	 *	we don't like that.
	 */
	if (eap_round->response->type.length > 128) {
		REDEBUG("Response is too large to understand");
		eap_round->request->code = FR_EAP_CODE_FAILURE;
		return RLM_MODULE_INVALID;
	}

	/*
	 *	If there was a User-Password in the request,
	 *	why the heck are they using EAP-GTC?
	 */
	MEM(pair_update_request(&vp, attr_user_password) >= 0);
	fr_pair_value_bstrncpy(vp, eap_round->response->type.data, eap_round->response->type.length);
	vp->vp_tainted = true;

	/*
	 *	Add the password to the request, and allow
	 *	another module to do the work of authenticating it.
	 */
	request->password = vp;

	unlang = cf_section_find(request->server_cs, "authenticate", inst->auth_type->alias);
	if (!unlang) {
		/*
		 *	Call the authenticate section of the *current* virtual server.
		 */
		rcode = process_authenticate(inst->auth_type->value->vb_uint32, request);
		if (rcode != RLM_MODULE_OK) {
			eap_round->request->code = FR_EAP_CODE_FAILURE;
			return rcode;
		}

		eap_round->request->code = FR_EAP_CODE_SUCCESS;
		return RLM_MODULE_OK;
	}

	unlang_push_section(request, unlang, RLM_MODULE_FAIL, UNLANG_TOP_FRAME);

	eap_session->process = mod_process_auth_type;

	return eap_session->process(inst, eap_session);
}


/*
 *	Initiate the EAP-GTC session by sending a challenge to the peer.
 */
static rlm_rcode_t mod_session_init(void *instance, eap_session_t *eap_session)
{
	char		challenge_str[1024];
	int		length;
	eap_round_t	*eap_round = eap_session->this_round;
	rlm_eap_gtc_t	*inst = (rlm_eap_gtc_t *) instance;

	if (xlat_eval(challenge_str, sizeof(challenge_str), eap_session->request, inst->challenge, NULL, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	length = strlen(challenge_str);

	/*
	 *	We're sending a request...
	 */
	eap_round->request->code = FR_EAP_CODE_REQUEST;

	eap_round->request->type.data = talloc_array(eap_round->request, uint8_t, length);
	if (!eap_round->request->type.data) return RLM_MODULE_FAIL;

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

	return RLM_MODULE_HANDLED;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_gtc;
rlm_eap_submodule_t rlm_eap_gtc = {
	.name		= "eap_gtc",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_GTC },
	.inst_size	= sizeof(rlm_eap_gtc_t),
	.config		= submodule_config,

	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
