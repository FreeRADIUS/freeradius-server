/*
 * rlm_eap_gtc.c    Handles that are called from eap
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2003,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_eap_gtc - "

#include <stdio.h>
#include <stdlib.h>

#include "eap.h"

#include <freeradius-devel/rad_assert.h>

/*
 *	EAP-GTC is just ASCII data carried inside of the EAP session.
 *	The length of the data is indicated by the encapsulating EAP
 *	protocol.
 */
typedef struct rlm_eap_gtc_t {
	char const	*challenge;
	char const	*auth_type_name;
	int		auth_type;
} rlm_eap_gtc_t;

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("challenge", FR_TYPE_STRING, rlm_eap_gtc_t, challenge), .dflt = "Password: " },
	{ FR_CONF_OFFSET("auth_type", FR_TYPE_STRING, rlm_eap_gtc_t, auth_type_name), .dflt = "PAP" },
	CONF_PARSER_TERMINATOR
};

static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, eap_session_t *eap_session);

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
		eap_round->request->code = PW_EAP_FAILURE;
		return rcode;
	}

	eap_round->request->code = PW_EAP_SUCCESS;
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
	rlm_eap_gtc_t	*inst = (rlm_eap_gtc_t *)instance;
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
		ERROR("Corrupted data");
		eap_round->request->code = PW_EAP_FAILURE;
		return RLM_MODULE_INVALID;
	}

	/*
	 *	EAP packets can be ~64k long maximum, and
	 *	we don't like that.
	 */
	if (eap_round->response->type.length > 128) {
		ERROR("Response is too large to understand");
		eap_round->request->code = PW_EAP_FAILURE;
		return RLM_MODULE_INVALID;
	}

	/*
	 *	If there was a User-Password in the request,
	 *	why the heck are they using EAP-GTC?
	 */
	fr_pair_delete_by_num(&request->packet->vps, 0, PW_USER_PASSWORD, TAG_ANY);

	MEM(vp = pair_make_request("User-Password", NULL, T_OP_EQ));
	fr_pair_value_bstrncpy(vp, eap_round->response->type.data, eap_round->response->type.length);
	vp->vp_tainted = true;

	/*
	 *	Add the password to the request, and allow
	 *	another module to do the work of authenticating it.
	 */
	request->password = vp;

	unlang = cf_subsection_find_name2(request->server_cs, "process", inst->auth_type_name);
	if (!unlang) {
		/*
		 *	Call the authenticate section of the *current* virtual server.
		 */
		rcode = process_authenticate(inst->auth_type, request);
		if (rcode != RLM_MODULE_OK) {
			eap_round->request->code = PW_EAP_FAILURE;
			return rcode;
		}

		eap_round->request->code = PW_EAP_SUCCESS;
		return RLM_MODULE_OK;
	}

	unlang_push_section(request, unlang, RLM_MODULE_FAIL);

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
	eap_round->request->code = PW_EAP_REQUEST;

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

	return RLM_MODULE_OK;
}

/*
 *	Attach the module.
 */
static int mod_instantiate(UNUSED rlm_eap_config_t const *config, void *instance, CONF_SECTION *cs)
{
	rlm_eap_gtc_t	*inst = talloc_get_type_abort(instance, rlm_eap_gtc_t);
	fr_dict_enum_t	*dval;

	if (!inst->auth_type_name) {
		ERROR("You must specify 'auth_type'");
		return -1;
	}

	dval = fr_dict_enum_by_alias(NULL, fr_dict_attr_by_num(NULL, 0, PW_AUTH_TYPE), inst->auth_type_name);
	if (!dval) {
		cf_log_err_by_name(cs, "auth_type", "Unknown Auth-Type %s",
				   inst->auth_type_name);
		return -1;
	}
	inst->auth_type = fr_unbox_uint32(dval->value);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_gtc;
rlm_eap_submodule_t rlm_eap_gtc = {
	.name		= "eap_gtc",
	.magic		= RLM_MODULE_INIT,

	.inst_size	= sizeof(rlm_eap_gtc_t),
	.config		= submodule_config,

	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
