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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright 2003  The FreeRADIUS server project
 *
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "../../eap.h"
#include "eap_types.h"
#include "eap_sim.h"

#include <rad_assert.h>

struct eap_sim_server_state {
	enum eapsim_serverstates state;
	struct eapsim_keys keys;
	
};

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
	u_int16_t *words;
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
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_VERSION_LIST,
			PW_TYPE_OCTETS);
	words = (u_int16_t *)newvp->strvalue;
	newvp->length = 3*sizeof(u_int16_t);
	words[0] = htons(1);
	words[1] = htons(EAP_SIM_VERSION);
	words[2] = 0;
	pairadd(vps, newvp);

	/* record it in the ess */
	ess->keys.versionlistlen = 4;
	memcpy(ess->keys.versionlist, words, ess->keys.versionlistlen);

	/* the ANY_ID attribute. We do not support re-auth or pseudonym */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_FULLAUTH_ID_REQ,
			   PW_TYPE_OCTETS);
	newvp->length = 2;
	newvp->strvalue[0]=0;
	newvp->strvalue[0]=1;
	pairadd(vps, newvp);

	/* the SUBTYPE, set to start. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_start;
	pairreplace(vps, newvp);

	return 1;
}

static int eap_sim_getchalans(VALUE_PAIR *vps, int chalno,
			      struct eap_sim_server_state *ess)
{
	VALUE_PAIR *vp;

	rad_assert(chalno >= 0 && chalno < 3);

	vp = pairfind(vps, ATTRIBUTE_EAP_SIM_CHAL1+chalno);
	if(vp == NULL) {
		/* bad, we can't find stuff! */
		DEBUG2("   eap-sim can not find sim-challenge%d",chalno+1);
		return 0;
	}
	if(vp->length != 16) {
		DEBUG2("   eap-sim chal%d is not 16-bytes: %d", chalno+1,
		       vp->length);
		return 0;
	}
	memcpy(ess->keys.rand[chalno], vp->strvalue, EAPSIM_RAND_SIZE);

	vp = pairfind(vps, ATTRIBUTE_EAP_SIM_SRES1+chalno);
	if(vp == NULL) {
		/* bad, we can't find stuff! */
		DEBUG2("   eap-sim can not find sim-sres%d",chalno+1);
		return 0;
	}
	if(vp->length != EAPSIM_SRES_SIZE) {
		DEBUG2("   eap-sim sres%d is not 16-bytes: %d", chalno+1,
		       vp->length);
		return 0;
	}
	memcpy(ess->keys.sres[chalno], vp->strvalue, EAPSIM_SRES_SIZE);

	vp = pairfind(vps, ATTRIBUTE_EAP_SIM_KC1+chalno);
	if(vp == NULL) {
		/* bad, we can't find stuff! */
		DEBUG2("   eap-sim can not find sim-kc%d",chalno+1);
		return 0;
	}
	if(vp->length != 8) {
		DEBUG2("   eap-sim kc%d is not 8-bytes: %d", chalno+1,
		       vp->length);
		return 0;
	}
	memcpy(ess->keys.Kc[chalno], vp->strvalue, EAPSIM_Kc_SIZE);

	return 1;
}

/*
 * this code sends the challenge itself.
 *
 * Challenges will come from one of three places eventually:
 *
 * 1  from attributes like ATTRIBUTE_EAP_SIM_CHALx
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

	printf("+++> EAP-sim decoded packet:\n");
	vp_printlist(stdout, *invps);
	
	/*
	 * find the challenges and responses, record them in the state,
	 */
	if((eap_sim_getchalans(*outvps, 0, ess) +
	    eap_sim_getchalans(*outvps, 1, ess) +
	    eap_sim_getchalans(*outvps, 2, ess)) != 3)
	{
		return 0;
	}

	/* okay, we got the challenges! Put them into an attribute */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RAND,
			   PW_TYPE_OCTETS);
	memcpy(newvp->strvalue+ 0, ess->keys.rand[0], 16);
	memcpy(newvp->strvalue+16, ess->keys.rand[1], 16);
	memcpy(newvp->strvalue+32, ess->keys.rand[2], 16);
	newvp->length = 48;
	pairadd(outvps, newvp);

	/* make a copy of the identity */
	ess->keys.identitylen = strlen(handler->identity);
	memcpy(ess->keys.identity, handler->identity, ess->keys.identitylen);

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
			   PW_TYPE_OCTETS);
	memcpy(newvp->strvalue, ess->keys.nonce_mt, 16);
	newvp->length = 16;
	pairreplace(outvps, newvp);

	newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue, ess->keys.K_aut, 16);
	newvp->length = 16;
	pairreplace(outvps, newvp);

	/* the SUBTYPE, set to challenge. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_challenge;
	pairreplace(outvps, newvp);

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

	type_data = type_data;  /* shut up compiler */

	vp = pairfind(handler->request->reply->vps, ATTRIBUTE_EAP_SIM_CHAL1);
	if(vp == NULL) {
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
	u_int16_t simversion;

	ess = (struct eap_sim_server_state *)handler->opaque;

	nonce_vp = pairfind(vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_NONCE_MT);
	selectedversion_vp = pairfind(vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_SELECTED_VERSION);
	
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
	memcpy(&simversion, selectedversion_vp->strvalue, sizeof(simversion));
	simversion = ntohs(simversion);
	if(simversion != EAP_SIM_VERSION) {
		DEBUG2("   EAP-Sim version %d is unknown.", simversion);
		return 0;
	}

	/* record it for later keying */
 	memcpy(ess->keys.versionselect, selectedversion_vp->strvalue,
	       sizeof(ess->keys.versionselect));

	/*
	 * double check the nonce size.
	 */
	if(nonce_vp->length != 18) {
		DEBUG2("   EAP-Sim nonce_mt must be 16 bytes (+2 bytes padding), not %d", nonce_vp->length);
		return 0;
	}
	memcpy(ess->keys.nonce_mt, nonce_vp->strvalue+2, 16);
	
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
	unsigned char srescat[EAPSIM_SRES_SIZE*3];
	unsigned char calcmac[EAPSIM_CALCMAC_SIZE];

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
		unsigned char macline[20*3];
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

	arg = arg; /* shut up compiler */

	ess = (struct eap_sim_server_state *)handler->opaque;

	/* vps is the data from the client */
	vps = handler->request->packet->vps;

	unmap_eapsim_basictypes(handler->request->packet,
				handler->eap_ds->response->type.data,
				handler->eap_ds->response->type.length);


	/* see what kind of message we have gotten */
	if((vp = pairfind(vps, ATTRIBUTE_EAP_SIM_SUBTYPE)) == NULL)
	{
		DEBUG2("   no subtype attribute was created, message dropped");
		return 0;
	}
	subtype = vp->lvalue;

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
		abort();
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

/*
 * $Log$
 * Revision 1.1  2003-10-29 02:49:19  mcr
 * 	initial commit of eap-sim
 *
 * Revision 1.3  2003/09/14 00:44:42  mcr
 * 	finished trivial challenge state.
 *
 *
 */
