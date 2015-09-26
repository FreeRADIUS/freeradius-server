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

static CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("challenge", PW_TYPE_STRING, rlm_eap_gtc_t, challenge), .dflt = "Password: " },

	{ FR_CONF_OFFSET("auth_type", PW_TYPE_STRING, rlm_eap_gtc_t, auth_type_name), .dflt = "PAP" },
	CONF_PARSER_TERMINATOR
};


static int CC_HINT(nonnull) mod_process(void *instance, eap_handler_t *handler);

/*
 *	Attach the module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_gtc_t	*inst;
	DICT_VALUE	*dval;

	*instance = inst = talloc_zero(cs, rlm_eap_gtc_t);
	if (!inst) return -1;

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	if (inst->auth_type_name && *inst->auth_type_name) {
		dval = dict_valbyname(PW_AUTH_TYPE, 0, inst->auth_type_name);
		if (!dval) {
			ERROR("rlm_eap_gtc: Unknown Auth-Type %s",
			      inst->auth_type_name);
			return -1;
		}

		inst->auth_type = dval->value;
	} else {
		inst->auth_type = PW_AUTH_TYPE_LOCAL;
	}
	return 0;
}

/*
 *	Initiate the EAP-GTC session by sending a challenge to the peer.
 */
static int mod_session_init(void *instance, eap_handler_t *handler)
{
	char challenge_str[1024];
	int length;
	EAP_DS *eap_ds = handler->eap_ds;
	rlm_eap_gtc_t *inst = (rlm_eap_gtc_t *) instance;

	if (radius_xlat(challenge_str, sizeof(challenge_str), handler->request, inst->challenge, NULL, NULL) < 0) {
		return 0;
	}

	length = strlen(challenge_str);

	/*
	 *	We're sending a request...
	 */
	eap_ds->request->code = PW_EAP_REQUEST;

	eap_ds->request->type.data = talloc_array(eap_ds->request,
						  uint8_t, length);
	if (!eap_ds->request->type.data) {
		return 0;
	}

	memcpy(eap_ds->request->type.data, challenge_str, length);
	eap_ds->request->type.length = length;

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'handler->eap_ds', which will be given back
	 *	to us...
	 */
	handler->process = mod_process;

	return 1;
}


/*
 *	Authenticate a previously sent challenge.
 */
static int mod_process(void *instance, eap_handler_t *handler)
{
	VALUE_PAIR *vp;
	EAP_DS *eap_ds = handler->eap_ds;
	rlm_eap_gtc_t *inst = (rlm_eap_gtc_t *) instance;
	REQUEST *request = handler->request;

	/*
	 *	Get the Cleartext-Password for this user.
	 */

	/*
	 *	Sanity check the response.  We need at least one byte
	 *	of data.
	 */
	if (eap_ds->response->length <= 4) {
		ERROR("rlm_eap_gtc: corrupted data");
		eap_ds->request->code = PW_EAP_FAILURE;
		return 0;
	}

#if 0
	if ((rad_debug_lvl > 2) && fr_log_fp) {
		int i;

		for (i = 0; i < eap_ds->response->length - 4; i++) {
			if ((i & 0x0f) == 0) fprintf(fr_log_fp, "%d: ", i);

			fprintf(fr_log_fp, "%02x ", eap_ds->response->type.data[i]);

			if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
		}
	}
#endif

	/*
	 *	Handle passwords here.
	 */
	if (inst->auth_type == PW_AUTH_TYPE_LOCAL) {
		/*
		 *	For now, do cleartext password authentication.
		 */
		vp = fr_pair_find_by_num(request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
		if (!vp) {
			REDEBUG2("Cleartext-Password is required for authentication");
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}

		if (eap_ds->response->type.length != vp->vp_length) {
			REDEBUG2("Passwords are of different length. %u %u", (unsigned) eap_ds->response->type.length, (unsigned) vp->vp_length);
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}

		if (memcmp(eap_ds->response->type.data,
			   vp->vp_strvalue, vp->vp_length) != 0) {
			REDEBUG2("Passwords are different");
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}

		/*
		 *	EAP packets can be ~64k long maximum, and
		 *	we don't like that.
		 */
	} else if (eap_ds->response->type.length <= 128) {
		int rcode;
		char *p;

		/*
		 *	If there was a User-Password in the request,
		 *	why the heck are they using EAP-GTC?
		 */
		fr_pair_delete_by_num(&request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);

		vp = pair_make_request("User-Password", NULL, T_OP_EQ);
		if (!vp) {
			return 0;
		}
		vp->vp_length = eap_ds->response->type.length;
		vp->vp_strvalue = p = talloc_array(vp, char, vp->vp_length + 1);
		vp->type = VT_DATA;
		memcpy(p, eap_ds->response->type.data, vp->vp_length);
		p[vp->vp_length] = 0;

		/*
		 *	Add the password to the request, and allow
		 *	another module to do the work of authenticating it.
		 */
		request->password = vp;

		/*
		 *	This is a wild & crazy hack.
		 */
		rcode = process_authenticate(inst->auth_type, request);
		if (rcode != RLM_MODULE_OK) {
			eap_ds->request->code = PW_EAP_FAILURE;
			return 0;
		}

	} else {
		ERROR("rlm_eap_gtc: Response is too large to understand");
		eap_ds->request->code = PW_EAP_FAILURE;
		return 0;

	}

	eap_ds->request->code = PW_EAP_SUCCESS;

	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_gtc;
rlm_eap_module_t rlm_eap_gtc = {
	.name		= "eap_gtc",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
