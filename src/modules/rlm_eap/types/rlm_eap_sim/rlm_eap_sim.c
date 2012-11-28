/*
 * rlm_eap_sim.c    Handles that are called from eap for SIM
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
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
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright 2003,2006  The FreeRADIUS server project
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "../../eap.h"
#include "eap_types.h"
#include "eap_sim.h"

#include <freeradius-devel/rad_assert.h>

struct eap_sim_server_state {
	enum eapsim_serverstates state;
	struct eapsim_keys keys;
	int  sim_id;
};

/*
 * Add value pair to reply
 */
static void add_reply(VALUE_PAIR** vp,
		      const char* name, const uint8_t *value, size_t len)
{
	VALUE_PAIR *reply_attr;
	reply_attr = pairmake(name, "", T_OP_EQ);
	if (!reply_attr) {
		DEBUG("rlm_eap_sim: "
		      "add_reply failed to create attribute %s: %s\n",
		      name, fr_strerror());
		return;
	}

	memcpy(reply_attr->vp_strvalue, value, len);
	reply_attr->length = len;
	pairadd(vp, reply_attr);
}

static void eap_sim_state_free(void *opaque)
{
	struct eap_sim_server_state *ess = (struct eap_sim_server_state *)opaque;

	if (!ess) return;

	free(ess);
}

/*
 *	build a reply to be sent.
 */
static int eap_sim_compose(EAP_HANDLER *handler)
{
	/* we will set the ID on requests, since we have to HMAC it */
	handler->eap_ds->set_request_id = 1;

	return map_eapsim_basictypes(handler->request->reply,
				     handler->eap_ds->request);
}

static int eap_sim_sendstart(EAP_HANDLER *handler)
{
	VALUE_PAIR **vps, *newvp;
	uint16_t *words;
	struct eap_sim_server_state *ess;

	rad_assert(handler->request != NULL);
	rad_assert(handler->request->reply);

	ess = (struct eap_sim_server_state *)handler->opaque;

	/* these are the outgoing attributes */
	vps = &handler->request->reply->vps;

	rad_assert(vps != NULL);

	/*
	 * add appropriate TLVs for the EAP things we wish to send.
	 */

	/* the version list. We support only version 1. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_VERSION_LIST, 0,
			   PW_TYPE_OCTETS);
	words = (uint16_t *)newvp->vp_strvalue;
	newvp->length = 3*sizeof(uint16_t);
	words[0] = htons(1*sizeof(uint16_t));
	words[1] = htons(EAP_SIM_VERSION);
	words[2] = 0;
	pairadd(vps, newvp);

	/* set the EAP_ID - new value */
	newvp = paircreate(ATTRIBUTE_EAP_ID, 0, PW_TYPE_INTEGER);
	newvp->vp_integer = ess->sim_id++;
	pairreplace(vps, newvp);

	/* record it in the ess */
	ess->keys.versionlistlen = 2;
	memcpy(ess->keys.versionlist, words+1, ess->keys.versionlistlen);

	/* the ANY_ID attribute. We do not support re-auth or pseudonym */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_FULLAUTH_ID_REQ,
			   0, PW_TYPE_OCTETS);
	newvp->length = 2;
	newvp->vp_strvalue[0]=0;
	newvp->vp_strvalue[0]=1;
	pairadd(vps, newvp);

	/* the SUBTYPE, set to start. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, 0, PW_TYPE_INTEGER);
	newvp->vp_integer = eapsim_start;
	pairreplace(vps, newvp);

	return 1;
}

static int eap_sim_getchalans(VALUE_PAIR *vps, int chalno,
			      struct eap_sim_server_state *ess)
{
	VALUE_PAIR *vp;

	rad_assert(chalno >= 0 && chalno < 3);

	vp = pairfind(vps, ATTRIBUTE_EAP_SIM_RAND1+chalno, 0);
	if(vp == NULL) {
		/* bad, we can't find stuff! */
		DEBUG2("   eap-sim can not find sim-challenge%d",chalno+1);
		return 0;
	}
	if(vp->length != EAPSIM_RAND_SIZE) {
		DEBUG2("   eap-sim chal%d is not 8-bytes: %d", chalno+1,
		       (int) vp->length);
		return 0;
	}
	memcpy(ess->keys.rand[chalno], vp->vp_strvalue, EAPSIM_RAND_SIZE);

	vp = pairfind(vps, ATTRIBUTE_EAP_SIM_SRES1+chalno, 0);
	if(vp == NULL) {
		/* bad, we can't find stuff! */
		DEBUG2("   eap-sim can not find sim-sres%d",chalno+1);
		return 0;
	}
	if(vp->length != EAPSIM_SRES_SIZE) {
		DEBUG2("   eap-sim sres%d is not 16-bytes: %d", chalno+1,
		       (int) vp->length);
		return 0;
	}
	memcpy(ess->keys.sres[chalno], vp->vp_strvalue, EAPSIM_SRES_SIZE);

	vp = pairfind(vps, ATTRIBUTE_EAP_SIM_KC1+chalno, 0);
	if(vp == NULL) {
		/* bad, we can't find stuff! */
		DEBUG2("   eap-sim can not find sim-kc%d",chalno+1);
		return 0;
	}
	if(vp->length != EAPSIM_Kc_SIZE) {
		DEBUG2("   eap-sim kc%d is not 8-bytes: %d", chalno+1,
		       (int) vp->length);
		return 0;
	}
	memcpy(ess->keys.Kc[chalno], vp->vp_strvalue, EAPSIM_Kc_SIZE);

	return 1;
}

/*
 * this code sends the challenge itself.
 *
 * Challenges will come from one of three places eventually:
 *
 * 1  from attributes like ATTRIBUTE_EAP_SIM_RANDx
 *            (these might be retrived from a database)
 *
 * 2  from internally implemented SIM authenticators
 *            (a simple one based upon XOR will be provided)
 *
 * 3  from some kind of SS7 interface.
 *
 * For now, they only come from attributes.
 * It might be that the best way to do 2/3 will be with a different
 * module to generate/calculate things.
 *
 */
static int eap_sim_sendchallenge(EAP_HANDLER *handler)
{
	struct eap_sim_server_state *ess;
	VALUE_PAIR **invps, **outvps, *newvp;

	ess = (struct eap_sim_server_state *)handler->opaque;
	rad_assert(handler->request != NULL);
	rad_assert(handler->request->reply);

	/* invps is the data from the client.
	 * but, this is for non-protocol data here. We should
	 * already have consumed any client originated data.
	 */
	invps = &handler->request->packet->vps;

	/* outvps is the data to the client. */
	outvps= &handler->request->reply->vps;

	if ((debug_flag > 0) && fr_log_fp) {
		fprintf(fr_log_fp, "+++> EAP-sim decoded packet:\n");
		debug_pair_list(*invps);
	}

	/* okay, we got the challenges! Put them into an attribute */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RAND,
			   0, PW_TYPE_OCTETS);
	memset(newvp->vp_strvalue,    0, 2); /* clear reserved bytes */
	memcpy(newvp->vp_strvalue+2+EAPSIM_RAND_SIZE*0, ess->keys.rand[0], EAPSIM_RAND_SIZE);
	memcpy(newvp->vp_strvalue+2+EAPSIM_RAND_SIZE*1, ess->keys.rand[1], EAPSIM_RAND_SIZE);
	memcpy(newvp->vp_strvalue+2+EAPSIM_RAND_SIZE*2, ess->keys.rand[2], EAPSIM_RAND_SIZE);
	newvp->length = 2+EAPSIM_RAND_SIZE*3;
	pairadd(outvps, newvp);

	/* set the EAP_ID - new value */
	newvp = paircreate(ATTRIBUTE_EAP_ID, 0, PW_TYPE_INTEGER);
	newvp->vp_integer = ess->sim_id++;
	pairreplace(outvps, newvp);

	/* make a copy of the identity */
	ess->keys.identitylen = strlen(handler->identity);
	memcpy(ess->keys.identity, handler->identity, ess->keys.identitylen);

	/* use the SIM identity, if available */
	newvp = pairfind(*invps, ATTRIBUTE_EAP_SIM_BASE + PW_EAP_SIM_IDENTITY, 0);
	if (newvp && newvp->length > 2) {
		uint16_t len;

		memcpy(&len, newvp->vp_octets, sizeof(uint16_t));
		len = ntohs(len);
		if (len <= newvp->length - 2 && len <= MAX_STRING_LEN) {
			ess->keys.identitylen = len;
			memcpy(ess->keys.identity, newvp->vp_octets + 2,
			       ess->keys.identitylen);
		}
	}

	/* all set, calculate keys! */
	eapsim_calculate_keys(&ess->keys);

#ifdef EAP_SIM_DEBUG_PRF
	eapsim_dump_mk(&ess->keys);
#endif

	/*
	 * need to include an AT_MAC attribute so that it will get
	 * calculated. The NONCE_MT and the MAC are both 16 bytes, so
	 * we store the NONCE_MT in the MAC for the encoder, which
	 * will pull it out before it does the operation.
	 */

	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
			   0, PW_TYPE_OCTETS);
	memcpy(newvp->vp_strvalue, ess->keys.nonce_mt, 16);
	newvp->length = 16;
	pairreplace(outvps, newvp);

	newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, 0, PW_TYPE_OCTETS);
	memcpy(newvp->vp_strvalue, ess->keys.K_aut, 16);
	newvp->length = 16;
	pairreplace(outvps, newvp);

	/* the SUBTYPE, set to challenge. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, 0, PW_TYPE_INTEGER);
	newvp->vp_integer = eapsim_challenge;
	pairreplace(outvps, newvp);

	return 1;
}

#ifndef EAPTLS_MPPE_KEY_LEN
#define EAPTLS_MPPE_KEY_LEN     32
#endif

/*
 * this code sends the success message.
 *
 * the only work to be done is the add the appropriate SEND/RECV
 * radius attributes derived from the MSK.
 *
 */
static int eap_sim_sendsuccess(EAP_HANDLER *handler)
{
        unsigned char *p;
	struct eap_sim_server_state *ess;
	VALUE_PAIR **outvps;
	VALUE_PAIR *newvp;

	/* outvps is the data to the client. */
	outvps= &handler->request->reply->vps;
	ess = (struct eap_sim_server_state *)handler->opaque;

	/* set the EAP_ID - new value */
	newvp = paircreate(ATTRIBUTE_EAP_ID, 0, PW_TYPE_INTEGER);
	newvp->vp_integer = ess->sim_id++;
	pairreplace(outvps, newvp);

	p = ess->keys.msk;
	add_reply(outvps, "MS-MPPE-Recv-Key", p, EAPTLS_MPPE_KEY_LEN);
	p += EAPTLS_MPPE_KEY_LEN;
	add_reply(outvps, "MS-MPPE-Send-Key", p, EAPTLS_MPPE_KEY_LEN);
	return 1;
}


/*
 * run the server state machine.
 */
static void eap_sim_stateenter(EAP_HANDLER *handler,
			       struct eap_sim_server_state *ess,
			       enum eapsim_serverstates newstate)
{
	switch(newstate) {
	case eapsim_server_start:
		/*
		 * send the EAP-SIM Start message, listing the
		 * versions that we support.
		 */
		eap_sim_sendstart(handler);
		break;

	case eapsim_server_challenge:
		/*
		 * send the EAP-SIM Challenge message.
		 */
		eap_sim_sendchallenge(handler);
		break;

	case eapsim_server_success:
		/*
		 * send the EAP Success message
		 */
  	        eap_sim_sendsuccess(handler);
		handler->eap_ds->request->code = PW_EAP_SUCCESS;
		break;

	default:
		/*
		 * nothing to do for this transition.
		 */
		break;
	}

	ess->state = newstate;

	/* build the target packet */
	eap_sim_compose(handler);
}

/*
 *	Initiate the EAP-SIM session by starting the state machine
 *      and initiating the state.
 */
static int eap_sim_initiate(void *type_data, EAP_HANDLER *handler)
{
	struct eap_sim_server_state *ess;
	VALUE_PAIR *vp;
	VALUE_PAIR *outvps;
	time_t n;

	outvps = handler->request->reply->vps;

	type_data = type_data;  /* shut up compiler */

	vp = pairfind(outvps, ATTRIBUTE_EAP_SIM_RAND1, 0);
	if(vp == NULL) {
	        DEBUG2("   can not initiate sim, no RAND1 attribute");
		return 0;
	}

	ess = malloc(sizeof(struct eap_sim_server_state));
	if(ess == NULL) {
		DEBUG2("   no space for eap sim state");
		return 0;
	}

	handler->opaque = ((void *)ess);
	handler->free_opaque = eap_sim_state_free;

	handler->stage = AUTHENTICATE;

	/*
	 * save the keying material, because it could change on a subsequent
	 * retrival.
	 *
	 */
	if((eap_sim_getchalans(outvps, 0, ess) +
	    eap_sim_getchalans(outvps, 1, ess) +
	    eap_sim_getchalans(outvps, 2, ess)) != 3)
	{
	        DEBUG2("   can not initiate sim, missing attributes");
		return 0;
	}

	/*
	 * this value doesn't have be strong, but it is good if it
	 * is different now and then
	 */
	time(&n);
	ess->sim_id = (n & 0xff);

	eap_sim_stateenter(handler, ess, eapsim_server_start);

	return 1;
}


/*
 * process an EAP-Sim/Response/Start.
 *
 * verify that client chose a version, and provided a NONCE_MT,
 * and if so, then change states to challenge, and send the new
 * challenge, else, resend the Request/Start.
 *
 */
static int process_eap_sim_start(EAP_HANDLER *handler, VALUE_PAIR *vps)
{
	VALUE_PAIR *nonce_vp, *selectedversion_vp;
	struct eap_sim_server_state *ess;
	uint16_t simversion;

	ess = (struct eap_sim_server_state *)handler->opaque;

	nonce_vp = pairfind(vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_NONCE_MT, 0);
	selectedversion_vp = pairfind(vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_SELECTED_VERSION, 0);

	if(nonce_vp == NULL ||
	   selectedversion_vp == NULL) {
		DEBUG2("   client did not select a version and send a NONCE");
		eap_sim_stateenter(handler, ess, eapsim_server_start);
		return 1;
	}

	/*
	 * okay, good got stuff that we need. Check the version we found.
	 */
	if(selectedversion_vp->length < 2) {
		DEBUG2("   EAP-Sim version field is too short.");
		return 0;
	}
	memcpy(&simversion, selectedversion_vp->vp_strvalue, sizeof(simversion));
	simversion = ntohs(simversion);
	if(simversion != EAP_SIM_VERSION) {
		DEBUG2("   EAP-Sim version %d is unknown.", simversion);
		return 0;
	}

	/* record it for later keying */
 	memcpy(ess->keys.versionselect, selectedversion_vp->vp_strvalue,
	       sizeof(ess->keys.versionselect));

	/*
	 * double check the nonce size.
	 */
	if(nonce_vp->length != 18) {
	  DEBUG2("   EAP-Sim nonce_mt must be 16 bytes (+2 bytes padding), not %d", (int) nonce_vp->length);
		return 0;
	}
	memcpy(ess->keys.nonce_mt, nonce_vp->vp_strvalue+2, 16);

	/* everything looks good, change states */
	eap_sim_stateenter(handler, ess, eapsim_server_challenge);
	return 1;
}


/*
 * process an EAP-Sim/Response/Challenge
 *
 * verify that MAC that we received matches what we would have
 * calculated from the packet with the SRESx appended.
 *
 */
static int process_eap_sim_challenge(EAP_HANDLER *handler, VALUE_PAIR *vps)
{
	struct eap_sim_server_state *ess;
	uint8_t srescat[EAPSIM_SRES_SIZE*3];
	uint8_t calcmac[EAPSIM_CALCMAC_SIZE];

	ess = (struct eap_sim_server_state *)handler->opaque;

	memcpy(srescat +(0*EAPSIM_SRES_SIZE), ess->keys.sres[0], EAPSIM_SRES_SIZE);
	memcpy(srescat +(1*EAPSIM_SRES_SIZE), ess->keys.sres[1], EAPSIM_SRES_SIZE);
	memcpy(srescat +(2*EAPSIM_SRES_SIZE), ess->keys.sres[2], EAPSIM_SRES_SIZE);

	/* verify the MAC, now that we have all the keys. */
	if(eapsim_checkmac(vps, ess->keys.K_aut,
			   srescat, sizeof(srescat),
			   calcmac)) {
		DEBUG2("MAC check succeed\n");
	} else {
		int i, j;
		char macline[20*3];
		char *m = macline;

		j=0;
		for (i = 0; i < EAPSIM_CALCMAC_SIZE; i++) {
			if(j==4) {
			  *m++ = '_';
			  j=0;
			}
			j++;

			sprintf(m, "%02x", calcmac[i]);
			m = m + strlen(m);
		}
		DEBUG2("calculated MAC (%s) did not match", macline);
		return 0;
	}

	/* everything looks good, change states */
	eap_sim_stateenter(handler, ess, eapsim_server_success);
	return 1;
}


/*
 *	Authenticate a previously sent challenge.
 */
static int eap_sim_authenticate(void *arg, EAP_HANDLER *handler)
{
	struct eap_sim_server_state *ess;
	VALUE_PAIR *vp, *vps;
	enum eapsim_subtype subtype;
	int success;

	arg = arg; /* shut up compiler */

	ess = (struct eap_sim_server_state *)handler->opaque;

	/* vps is the data from the client */
	vps = handler->request->packet->vps;

	success= unmap_eapsim_basictypes(handler->request->packet,
					 handler->eap_ds->response->type.data,
					 handler->eap_ds->response->type.length);

	if(!success) {
	  return 0;
	}

	/* see what kind of message we have gotten */
	if((vp = pairfind(vps, ATTRIBUTE_EAP_SIM_SUBTYPE, 0)) == NULL)
	{
		DEBUG2("   no subtype attribute was created, message dropped");
		return 0;
	}
	subtype = vp->vp_integer;

	/*
	 *	Client error supersedes anything else.
	 */
	if (subtype == eapsim_client_error) {
		return 0;
	}

	switch(ess->state) {
	case eapsim_server_start:
		switch(subtype) {
		default:
			/*
			 * pretty much anything else here is illegal,
			 * so we will retransmit the request.
			 */
			eap_sim_stateenter(handler, ess, eapsim_server_start);
			return 1;

		case eapsim_start:
			/*
			 * a response to our EAP-Sim/Request/Start!
			 *
			 */
			return process_eap_sim_start(handler, vps);
		}
		break;
	case eapsim_server_challenge:
		switch(subtype) {
		default:
			/*
			 * pretty much anything else here is illegal,
			 * so we will retransmit the request.
			 */
			eap_sim_stateenter(handler, ess, eapsim_server_challenge);
			return 1;

		case eapsim_challenge:
			/*
			 * a response to our EAP-Sim/Request/Challenge!
			 *
			 */
			return process_eap_sim_challenge(handler, vps);
		}
		break;

	default:
		/* if we get into some other state, die, as this
		 * is a coding error!
		 */
		DEBUG2("  illegal-unknown state reached in eap_sim_authenticate\n");
		rad_assert(0 == 1);
 	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_sim = {
	"eap_sim",
	NULL,				/* XXX attach */
	eap_sim_initiate,		/* Start the initial request */
	NULL,				/* XXX authorization */
	eap_sim_authenticate,		/* authentication */
	NULL				/* XXX detach */
};
