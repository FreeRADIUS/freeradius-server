/*
 * rlm_eap_mschapv2.c    Handles that are called from eap
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
 * Copyright 2000,2001  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "eap_mschapv2.h"

#include <rad_assert.h>

/*
 *	Compose the response.
 */
static int eapmschapv2_compose(EAP_DS *eap_ds, VALUE_PAIR *reply)
{
	uint8_t *ptr;
	int code;
	int length;

	eap_ds->request->type.type = PW_EAP_MSCHAPV2;

	if (reply) switch (reply->attribute) {
	case PW_MSCHAP_CHALLENGE:
	  code = PW_EAP_MSCHAPV2_CHALLENGE;
	  length = 1 + reply->length;
	  break;

	case PW_MSCHAP2_SUCCESS:
	  length = 1 + reply->length;
	  code = PW_EAP_MSCHAPV2_SUCCESS;
	  break;
		
	case PW_MSCHAP_ERROR:
	  length = 1 + reply->length;
	  code = PW_EAP_MSCHAPV2_FAILURE;
	  break;
		
	default:
		radlog(L_ERR, "rlm_eap_mschapv2: Internal sanity check failed");
		return 0;
		break;
	} else {
	  code = PW_EAP_MSCHAPV2_ACK;
	  length = 1;
	}

	/*
	 *	Allocate room for the EAP-MS-CHAPv2 data.
	 */
	eap_ds->request->type.data = malloc(length);
	if (eap_ds->request->type.data == NULL) {
		radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
		return 0;
	}
	eap_ds->request->type.length = length;

	ptr = eap_ds->request->type.data;
	*ptr = code;

	/*
	 *	Just an ACK.  Do nothing more.
	 */
	if (!reply) return 1;

	/*
	 *	Copy the Challenge, success, or error over.
	 */
	memcpy(ptr + 1, reply->strvalue, reply->length);

	return 1;
}


/*
 *	Initiate the EAP-MSCHAPV2 session by sending a challenge to the peer.
 */
static int mschapv2_initiate(void *type_data, EAP_HANDLER *handler)
{
	int		i;
	VALUE_PAIR	*challenge;
	mschapv2_opaque_t *data;

	type_data = type_data;	/* -Wunused */

	challenge = pairmake("MS-CHAP-Challenge", "0x00", T_OP_EQ);
	if (!challenge) {
		radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
		return 0;
	}

	/*
	 *	Get a random challenge.
	 */
	challenge->length = MSCHAPV2_CHALLENGE_LEN;
	for (i = 0; i < MSCHAPV2_CHALLENGE_LEN; i++) {
		challenge->strvalue[i] = lrad_rand();
	}
	radlog(L_INFO, "rlm_eap_mschapv2: Issuing Challenge");

	/*
	 *	Keep track of the challenge.
	 */
	data = malloc(sizeof(mschapv2_opaque_t));
	rad_assert(data != NULL);

	/*
	 *	We're at the stage where we're challenging the user.
	 */
	data->code = PW_EAP_MSCHAPV2_CHALLENGE;
	memcpy(data->challenge, challenge->strvalue, MSCHAPV2_CHALLENGE_LEN);

	handler->opaque = data;
	handler->free_opaque = free;
	
	/*
	 *	Compose the EAP-MSCHAPV2 packet out of the data structure,
	 *	and free it.
	 */
	eapmschapv2_compose(handler->eap_ds, challenge);
	pairfree(&challenge);

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
static int mschapv2_authenticate(void *arg, EAP_HANDLER *handler)
{
	int rcode;
	mschapv2_opaque_t *data;
	EAP_DS *eap_ds = handler->eap_ds;
	VALUE_PAIR *challenge, *response;

	/*
	 *	Get the User-Password for this user.
	 */
	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == AUTHENTICATE);

	data = (mschapv2_opaque_t *) handler->opaque;

	/*
	 *	Sanity check the response.
	 */
	if (eap_ds->response->length <= 4) {
		radlog(L_ERR, "rlm_eap_mschapv2: corrupted data");
		return 0;
	}

	/*
	 *	Switch over the MS-CHAP type.
	 */
	switch (eap_ds->response->type.data[0]) {
		/*
		 *	We should get an ACK from the client ONLY if we've
		 *	sent them a SUCCESS packet.
		 */
		case PW_EAP_MSCHAPV2_ACK:
		if (data->code != PW_EAP_MSCHAPV2_SUCCESS) {
			radlog(L_ERR, "rlm_eap_mschapv2: Unexpected ACK received");
			return 0;
		}

		/*
		 *	And upon receiving the clients ACK, we do nothing
		 *	other than return EAP-Success, with no EAP-MS-CHAPv2
		 *	data.
		 */
		return 1;
		break;

		/*
		 *	We should get a response ONLY after we've sent
		 *	a challenge.
		 */
		case PW_EAP_MSCHAPV2_RESPONSE:
		if (data->code != PW_EAP_MSCHAPV2_CHALLENGE) {
			radlog(L_ERR, "rlm_eap_mschapv2: Unexpected response received");
			return 0;
		}

		/*
		 *	4 for EAP header, 1 for EAP-MSCHAPv2 code, and
		 *	50 for 
		 */
		if (eap_ds->response->length < (4 + 1 + MSCHAPV2_RESPONSE_LEN)) {
			radlog(L_ERR, "rlm_eap_mschapv2: MS-CHAPV2-Response is too short (%d)", eap_ds->response->length - 5);
			return 0;
		}
		break;

		/*
		 *	Something else, we don't know what it is.
		 */
		default:
		radlog(L_ERR, "rlm_eap_mschapv2: Invalid response type %d",
		       eap_ds->response->type.data[0]);
		return 0;
	}

	/*
	 *	We now know that the user has sent us a response
	 *	to the challenge.  Let's try to authenticate it.
	 *
	 *	We do this by taking the challenge from 'data',
	 *	the response from the EAP packet, and creating VALUE_PAIR's
	 *	to pass to the 'mschap' module.  This is a little wonky,
	 *	but it works.
	 */
	challenge = pairmake("MS-CHAP-Challenge", "0x00", T_OP_EQ);
	if (!challenge) {
		radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
		return 0;
	}
	challenge->length = MSCHAPV2_CHALLENGE_LEN;
	memcpy(challenge->strvalue, data->challenge, MSCHAPV2_CHALLENGE_LEN);

	response = pairmake("MS-CHAP2-Response", "0x00", T_OP_EQ);
	if (!challenge) {
		radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
		return 0;
	}
	response->length = MSCHAPV2_RESPONSE_LEN;
	memcpy(response->strvalue, &eap_ds->response->type.data[1],
	       MSCHAPV2_CHALLENGE_LEN);

	/*
	 *	Add the pairs to the request, and call the 'mschap'
	 *	module.
	 */
	pairadd(&handler->request->packet->vps, challenge);
	pairadd(&handler->request->packet->vps, response);

	/*
	 *	This is a wild & crazy hack.
	 */
	rcode = module_authenticate(PW_AUTHTYPE_MS_CHAP, handler->request);

	/*
	 *	Take the response from the mschap module, and
	 *	return success or failure, depending on the result.
	 */
	if (rcode == RLM_MODULE_OK) {
		response = paircopy2(handler->request->reply->vps,
				     PW_MSCHAP2_SUCCESS);
		data->code = PW_EAP_MSCHAPV2_SUCCESS;
	} else {
		response = paircopy2(handler->request->reply->vps,
				     PW_MSCHAP_ERROR);
		data->code = PW_EAP_MSCHAPV2_FAILURE;
	}

	/*
	 *	No response, die.
	 */
	if (!response) {
		radlog(L_ERR, "rlm_eap_mschapv2: No MS-CHAPv2-Success or MS-CHAP-Error was found.");
		return 0;
	}

	/*
	 *	Compose the response (whatever it is),
	 *	and return it to the over-lying EAP module.
	 */
	eapmschapv2_compose(handler->eap_ds, response);
	pairfree(&response);

	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_mschapv2 = {
	"eap_mschapv2",
	NULL,				/* attach */
	mschapv2_initiate,	        /* Start the initial request */
	NULL,				/* authorization */
	mschapv2_authenticate,		/* authentication */
	NULL				/* detach */
};
