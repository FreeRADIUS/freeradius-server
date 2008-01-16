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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2003,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>

#include <stdio.h>
#include <stdlib.h>

#include "eap_mschapv2.h"

#include <freeradius-devel/rad_assert.h>

typedef struct rlm_eap_mschapv2_t {
        int with_ntdomain_hack;
} rlm_eap_mschapv2_t;

static CONF_PARSER module_config[] = {
	{ "with_ntdomain_hack",     PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_mschapv2_t,with_ntdomain_hack), NULL, "no" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Detach the module.
 */
static int mschapv2_detach(void *arg)
{
	rlm_eap_mschapv2_t *inst = (rlm_eap_mschapv2_t *) arg;

	free(inst);

	return 0;
}


/*
 *	Attach the module.
 */
static int mschapv2_attach(CONF_SECTION *cs, void **instance)
{
	rlm_eap_mschapv2_t *inst;

	inst = malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		mschapv2_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Compose the response.
 */
static int eapmschapv2_compose(EAP_HANDLER *handler, VALUE_PAIR *reply)
{
	uint8_t *ptr;
	int16_t length;
	mschapv2_header_t *hdr;
	EAP_DS *eap_ds = handler->eap_ds;

	eap_ds->request->code = PW_EAP_REQUEST;
	eap_ds->request->type.type = PW_EAP_MSCHAPV2;

	switch (reply->attribute) {
	case PW_MSCHAP_CHALLENGE:
		/*
		 *   0                   1                   2                   3
		 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Code      |   Identifier  |            Length             |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Type      |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |   MS-Length   |  Value-Size   |  Challenge...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                             Challenge...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |                             Name...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		length = MSCHAPV2_HEADER_LEN + MSCHAPV2_CHALLENGE_LEN + strlen(handler->identity);
		eap_ds->request->type.data = malloc(length);
		/*
		 *	Allocate room for the EAP-MS-CHAPv2 data.
		 */
		if (eap_ds->request->type.data == NULL) {
			radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
			return 0;
		}
		eap_ds->request->type.length = length;

		ptr = eap_ds->request->type.data;
		hdr = (mschapv2_header_t *) ptr;

		hdr->opcode = PW_EAP_MSCHAPV2_CHALLENGE;
		hdr->mschapv2_id = eap_ds->response->id + 1;
		length = htons(length);
		memcpy(hdr->ms_length, &length, sizeof(uint16_t));
		hdr->value_size = MSCHAPV2_CHALLENGE_LEN;

		ptr += MSCHAPV2_HEADER_LEN;

		/*
		 *	Copy the Challenge, success, or error over.
		 */
		memcpy(ptr, reply->vp_strvalue, reply->length);
		memcpy((ptr + reply->length), handler->identity, strlen(handler->identity));
		break;

	case PW_MSCHAP2_SUCCESS:
		/*
		 *   0                   1                   2                   3
		 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Code      |   Identifier  |            Length             |
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |     Type      |   OpCode      |  MS-CHAPv2-ID |  MS-Length...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 *  |   MS-Length   |                    Message...
		 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		DEBUG2("MSCHAP Success\n");
		length = 46;
		eap_ds->request->type.data = malloc(length);
		/*
		 *	Allocate room for the EAP-MS-CHAPv2 data.
		 */
		if (eap_ds->request->type.data == NULL) {
			radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
			return 0;
		}
		memset(eap_ds->request->type.data, 0, length);
		eap_ds->request->type.length = length;

		eap_ds->request->type.data[0] = PW_EAP_MSCHAPV2_SUCCESS;
		eap_ds->request->type.data[1] = eap_ds->response->id;
		length = htons(length);
		memcpy((eap_ds->request->type.data + 2), &length, sizeof(uint16_t));
		memcpy((eap_ds->request->type.data + 4), reply->vp_strvalue + 1, 42);
		break;

	case PW_MSCHAP_ERROR:
		DEBUG2("MSCHAP Failure\n");
		length = 4 + MSCHAPV2_FAILURE_MESSAGE_LEN;
		eap_ds->request->type.data = malloc(length);

		/*
		 *	Allocate room for the EAP-MS-CHAPv2 data.
		 */
		if (eap_ds->request->type.data == NULL) {
			radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
			return 0;
		}
		memset(eap_ds->request->type.data, 0, length);
		eap_ds->request->type.length = length;

		eap_ds->request->type.data[0] = PW_EAP_MSCHAPV2_FAILURE;
		eap_ds->request->type.data[1] = eap_ds->response->id;
		length = htons(length);
		memcpy((eap_ds->request->type.data + 2), &length, sizeof(uint16_t));
		memcpy((eap_ds->request->type.data + 4), MSCHAPV2_FAILURE_MESSAGE, MSCHAPV2_FAILURE_MESSAGE_LEN);
		break;

	default:
		radlog(L_ERR, "rlm_eap_mschapv2: Internal sanity check failed");
		return 0;
		break;
	}

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
		challenge->vp_strvalue[i] = fr_rand();
	}
	DEBUG2("rlm_eap_mschapv2: Issuing Challenge");

	/*
	 *	Keep track of the challenge.
	 */
	data = malloc(sizeof(mschapv2_opaque_t));
	rad_assert(data != NULL);

	/*
	 *	We're at the stage where we're challenging the user.
	 */
	data->code = PW_EAP_MSCHAPV2_CHALLENGE;
	memcpy(data->challenge, challenge->vp_strvalue, MSCHAPV2_CHALLENGE_LEN);

	handler->opaque = data;
	handler->free_opaque = free;

	/*
	 *	Compose the EAP-MSCHAPV2 packet out of the data structure,
	 *	and free it.
	 */
	eapmschapv2_compose(handler, challenge);
	pairfree(&challenge);

	/*
	 *	The EAP session doesn't have enough information to
	 *	proxy the "inside EAP" protocol.  Disable EAP proxying.
	 */
	handler->request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;

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
 *	Do post-proxy processing,
 *	0 = fail
 *	1 = OK.
 *
 *	Called from rlm_eap.c, eap_postproxy().
 */
static int mschap_postproxy(EAP_HANDLER *handler, void *tunnel_data)
{
	VALUE_PAIR *response = NULL;
	mschapv2_opaque_t *data;

	data = (mschapv2_opaque_t *) handler->opaque;
	rad_assert(data != NULL);

	tunnel_data = tunnel_data; /* -Wunused */

	DEBUG2("  rlm_eap_mschapv2: Passing reply from proxy back into the tunnel %p %d.",
	       handler->request, handler->request->reply->code);

	/*
	 *	There is only a limited number of possibilities.
	 */
	switch (handler->request->reply->code) {
	case PW_AUTHENTICATION_ACK:
		DEBUG("  rlm_eap_mschapv2: Authentication succeeded.");
		/*
		 *	Move the attribute, so it doesn't go into
		 *	the reply.
		 */
		pairmove2(&response,
			  &handler->request->reply->vps,
			  PW_MSCHAP2_SUCCESS);
		break;

	default:
	case PW_AUTHENTICATION_REJECT:
		DEBUG("  rlm_eap_mschapv2: Authentication did not succeed.");
		return 0;
	}

	/*
	 *	No response, die.
	 */
	if (!response) {
		radlog(L_ERR, "rlm_eap_mschapv2: No MS-CHAPv2-Success or MS-CHAP-Error was found.");
		return 0;
	}

	/*
	 *	Done doing EAP proxy stuff.
	 */
	handler->request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;
	eapmschapv2_compose(handler, response);
	data->code = PW_EAP_MSCHAPV2_SUCCESS;

	/*
	 *	Delete MPPE keys & encryption policy
	 *
	 *	FIXME: Use intelligent names...
	 */
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 7));
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 8));
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 16));
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 17));

	/*
	 *	And we need to challenge the user, not ack/reject them,
	 *	so we re-write the ACK to a challenge.  Yuck.
	 */
	handler->request->reply->code = PW_ACCESS_CHALLENGE;
	pairfree(&response);

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
		 *	It's a success.  Don't proxy it.
		 */
		handler->request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;

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
		 *	Ensure that we have at least enough data
		 *	to do the following checks.
		 *
		 *	EAP header (4), EAP type, MS-CHAP opcode,
		 *	MS-CHAP ident, MS-CHAP data length (2),
		 *	MS-CHAP value length.
		 */
		if (eap_ds->response->length < (4 + 1 + 1 + 1 + 2 + 1)) {
			radlog(L_ERR, "rlm_eap_mschapv2: Response is too short");
			return 0;
		}

		/*
		 *	The 'value_size' is the size of the response,
		 *	which is supposed to be the response (48
		 *	bytes) plus 1 byte of flags at the end.
		 */
		if (eap_ds->response->type.data[4] != 49) {
			radlog(L_ERR, "rlm_eap_mschapv2: Response is of incorrect length %d", eap_ds->response->type.data[4]);
			return 0;
		}

		/*
		 *	The MS-Length field is 5 + value_size + length
		 *	of name, which is put after the response.
		 */
		if (((eap_ds->response->type.data[2] << 8) |
		     eap_ds->response->type.data[3]) < (5 + 49)) {
			radlog(L_ERR, "rlm_eap_mschapv2: Response contains contradictory length %d %d",
			      (eap_ds->response->type.data[2] << 8) |
			       eap_ds->response->type.data[3], 5 + 49);
			return 0;
		}
		break;

	case PW_EAP_MSCHAPV2_SUCCESS:
		if (data->code != PW_EAP_MSCHAPV2_SUCCESS) {
			radlog(L_ERR, "rlm_eap_mschapv2: Unexpected success received");
			return 0;
		}

		/*
		 *	It's a success.  Don't proxy it.
		 */
		handler->request->options &= ~RAD_REQUEST_OPTION_PROXY_EAP;

		eap_ds->request->code = PW_EAP_SUCCESS;
		return 1;
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
	memcpy(challenge->vp_strvalue, data->challenge, MSCHAPV2_CHALLENGE_LEN);

	response = pairmake("MS-CHAP2-Response", "0x00", T_OP_EQ);
	if (!response) {
		pairfree(&challenge);
		radlog(L_ERR, "rlm_eap_mschapv2: out of memory");
		return 0;
	}

	response->length = MSCHAPV2_RESPONSE_LEN;
	memcpy(response->vp_strvalue + 2, &eap_ds->response->type.data[5],
	       MSCHAPV2_RESPONSE_LEN - 2);
	response->vp_strvalue[0] = eap_ds->response->type.data[1];
	response->vp_strvalue[1] = eap_ds->response->type.data[5 + MSCHAPV2_RESPONSE_LEN];

	/*
	 *	Add the pairs to the request, and call the 'mschap'
	 *	module.
	 */
	pairadd(&handler->request->packet->vps, challenge);
	pairadd(&handler->request->packet->vps, response);

	/*
	 *	If this options is set, then we do NOT authenticate the
	 *	user here.  Instead, now that we've added the MS-CHAP
	 *	attributes to the request, we STOP, and let the outer
	 *	tunnel code handle it.
	 *
	 *	This means that the outer tunnel code will DELETE the
	 *	EAP attributes, and proxy the MS-CHAP attributes to a
	 *	home server.
	 */
	if (handler->request->options & RAD_REQUEST_OPTION_PROXY_EAP) {
		char *username = NULL;
		eap_tunnel_data_t *tunnel;
		rlm_eap_mschapv2_t *inst = (rlm_eap_mschapv2_t *) arg;

		/*
		 *	Set up the callbacks for the tunnel
		 */
		tunnel = rad_malloc(sizeof(*tunnel));
		memset(tunnel, 0, sizeof(*tunnel));

		tunnel->tls_session = arg;
		tunnel->callback = mschap_postproxy;

		/*
		 *	Associate the callback with the request.
		 */
		rcode = request_data_add(handler->request,
					 handler->request->proxy,
					 REQUEST_DATA_EAP_TUNNEL_CALLBACK,
					 tunnel, free);
		rad_assert(rcode == 0);

		/*
		 *	The State attribute is NOT supposed to
		 *	go into the proxied packet, it will confuse
		 *	other RADIUS servers, and they will discard
		 *	the request.
		 *
		 *	The PEAP module will take care of adding
		 *	the State attribute back, before passing
		 *	the handler & request back into the tunnel.
		 */
		pairdelete(&handler->request->packet->vps, PW_STATE);

		/*
		 *	Fix the User-Name when proxying, to strip off
		 *	the NT Domain, if we're told to, and a User-Name
		 *	exists, and there's a \\, meaning an NT-Domain
		 *	in the user name, THEN discard the user name.
		 */
		if (inst->with_ntdomain_hack &&
		    ((challenge = pairfind(handler->request->packet->vps,
					   PW_USER_NAME)) != NULL) &&
		    ((username = strchr(challenge->vp_strvalue, '\\')) != NULL)) {
			/*
			 *	Wipe out the NT domain.
			 *
			 *	FIXME: Put it into MS-CHAP-Domain?
			 */
			username++; /* skip the \\ */
			memmove(challenge->vp_strvalue,
				username,
				strlen(username) + 1); /* include \0 */
			challenge->length = strlen(challenge->vp_strvalue);
		}

		/*
		 *	Remember that in the post-proxy stage, we've got
		 *	to do the work below, AFTER the call to MS-CHAP
		 *	authentication...
		 */
		return 1;
	}

	/*
	 *	This is a wild & crazy hack.
	 */
	rcode = module_authenticate(PW_AUTHTYPE_MS_CHAP, handler->request);

	/*
	 *	Delete MPPE keys & encryption policy.  We don't
	 *	want these here.
	 */
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 7));
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 8));
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 16));
	pairdelete(&handler->request->reply->vps, ((311 << 16) | 17));

	/*
	 *	Take the response from the mschap module, and
	 *	return success or failure, depending on the result.
	 */
	response = NULL;
	if (rcode == RLM_MODULE_OK) {
		pairmove2(&response, &handler->request->reply->vps,
			 PW_MSCHAP2_SUCCESS);
		data->code = PW_EAP_MSCHAPV2_SUCCESS;
	} else {
		/*
		 *	Don't return anything in the error message.
		 */
		eap_ds->request->code = PW_EAP_FAILURE;
		return 1;
#if 0
		pairmove2(&handler->request->reply->vps, &response
			  PW_MSCHAP_ERROR);
		data->code = PW_EAP_MSCHAPV2_FAILURE;
#endif
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
	eapmschapv2_compose(handler, response);
	pairfree(&response);

	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_mschapv2 = {
	"eap_mschapv2",
	mschapv2_attach,		/* attach */
	mschapv2_initiate,	        /* Start the initial request */
	NULL,				/* authorization */
	mschapv2_authenticate,		/* authentication */
	mschapv2_detach			/* detach */
};
