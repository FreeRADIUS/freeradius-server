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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2003  The FreeRADIUS server project
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "eap.h"

#include <rad_assert.h>

/*
 *	EAP-GTC is just ASCII data carried inside of the EAP session.
 *	The length of the data is indicated by the encapsulating EAP
 *	protocol.
 */
typedef struct rlm_eap_gtc_t {
	const char *challenge;
	const char *response;
} rlm_eap_gtc_t;

static CONF_PARSER module_config[] = {
	{ "challenge", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_gtc_t, challenge), NULL, "Password: " },

	{ "response", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_gtc_t, response), NULL, "%{config:User-Password}" },

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};


/*
 *	Detach the module.
 */
static int gtc_detach(void *arg)
{
	rlm_eap_gtc_t *inst = (rlm_eap_gtc_t *) arg;

	if (inst->challenge) free(inst->challenge);
	if (inst->response) free(inst->response);

	free(inst);

	return 0;
}

/*
 *	Attach the module.
 */
static int gtc_attach(CONF_SECTION *cs, void **instance)
{
	rlm_eap_gtc_t *inst;

	inst = malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_ttls: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		gtc_detach(inst);
		return -1;
	}

	return 0;
}

/*
 *	Initiate the EAP-GTC session by sending a challenge to the peer.
 */
static int gtc_initiate(void *type_data, EAP_HANDLER *handler)
{
	int length;
	EAP_DS *eap_ds = handler->eap_ds;
	rlm_eap_gtc_t *inst = (rlm_eap_gtc_t *) type_data;

	/*
	 *	FIXME: call radius_xlat on the challenge
	 */
	length = strlen(inst->challenge);

	/*
	 *	We're sending a request...
	 */
	eap_ds->request->code = PW_EAP_REQUEST;

	eap_ds->request->type.data = malloc(length);
	if (eap_ds->request->type.data == NULL) {
		radlog(L_ERR, "rlm_eap_gtc: out of memory");
		return 0;
	}

	memcpy(eap_ds->request->type.data, inst->challenge, length);
	eap_ds->request->type.length = length;

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'handler->eap_ds', which will be given back
	 *	to us...
	 */
	handler->stage = AUTHENTICATE;
	
	return 1;
}


/*
 *	Authenticate a previously sent challenge.
 */
static int gtc_authenticate(void *arg, EAP_HANDLER *handler)
{
	EAP_DS *eap_ds = handler->eap_ds;
	VALUE_PAIR *vp;

	/*
	 *	Get the User-Password for this user.
	 */
	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == AUTHENTICATE);

	/*
	 *	Sanity check the response.  We need at least one byte
	 *	of data.
	 */
	if (eap_ds->response->length <= 4) {
		radlog(L_ERR, "rlm_eap_gtc: corrupted data");
		return 0;
	}
	
#ifndef NDEBUG
	if (debug_flag > 2) {
		int i;

		for (i = 0; i < eap_ds->response->length - 4; i++) {
			if ((i & 0x0f) == 0) printf("%d: ", i);

			printf("%02x ", eap_ds->response->type.data[i]);
			
			if ((i & 0x0f) == 0x0f) printf("\n");
		}
	}
#endif

	/*
	 *	For now, do clear-text password authentication.
	 *
	 *	FIXME: allow crypt, md5, or other passwords.
	 */
	vp = pairfind(handler->request->config_items, PW_PASSWORD);
	if (!vp) {
		DEBUG2("  rlm_eap_gtc: ERROR: Clear-test User-Password is required for authentication.");
		return 0;
	}

	if ((eap_ds->response->length - 4) != vp->length) {
		DEBUG2("  rlm_eap_gtc: ERROR: Passwords are of different length.");
		return 0;
	}

	if (memcmp(eap_ds->response->type.data,
		   vp->strvalue, vp->length) != 0) {
		DEBUG2("  rlm_eap_gtc: ERROR: Passwords are different");
		return 0;
	}

	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_gtc = {
	"eap_gtc",
	gtc_attach,	      		/* attach */
	gtc_initiate,			/* Start the initial request */
	NULL,				/* authorization */
	gtc_authenticate,		/* authentication */
	gtc_detach     			/* detach */
};
