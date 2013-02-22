/*
 * rlm_eap_tnc.c    Handles that are called from eap
 *
 *   This software is Copyright (C) 2006,2007 FH Hannover
 *
 *   Portions of this code unrelated to FreeRADIUS are available
 *   separately under a commercial license.  If you require an
 *   implementation of EAP-TNC that is not under the GPLv2, please
 *   contact tnc@inform.fh-hannover.de for details.
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
 *   Modifications to integrate with FreeRADIUS configuration
 *   Copyright (C) 2007 Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "tncs_connect.h"
#include "eap_tnc.h"
#include "tncs.h"
#include <freeradius-devel/rad_assert.h>

typedef struct rlm_eap_tnc_t {
	char	*vlan_access;
	char	*vlan_isolate;
	char	*tnc_path;
} rlm_eap_tnc_t;

static int sessionCounter=0;

/*
 *	Initiate the EAP-MD5 session by sending a challenge to the peer.
 *  Initiate the EAP-TNC session by sending a EAP Request witch Start Bit set 
 *  and with no data
 */
static int tnc_initiate(void *type_data, EAP_HANDLER *handler)
{
	uint8_t flags_ver = 1; //set version to 1
	rlm_eap_tnc_t *inst = type_data;
	TNC_PACKET *reply;

	if (!handler->request || !handler->request->parent) {
		DEBUG("rlm_eap_tnc: EAP-TNC can only be run inside of a TLS-based method.");
		return 0;
	}

	/*
	 *	FIXME: Update this when the TTLS and PEAP methods can
	 *	run EAP-TLC *after* the user has been authenticated.
	 *	This likely means moving the phase2 handlers to a
	 *	common code base.
	 */
	if (1) {
		DEBUG("rlm-eap_tnc: EAP-TNC can only be run after the user has been authenticated.");
		return 0;
	}

	DEBUG("tnc_initiate: %ld", handler->timestamp);

	if(connectToTncs(inst->tnc_path)==-1){
		DEBUG("Could not connect to TNCS");
	}

	/*
	 *	Allocate an EAP-MD5 packet.
	 */
	reply = eaptnc_alloc();
	if (reply == NULL)  {
		radlog(L_ERR, "rlm_eap_tnc: out of memory");
		return 0;
	}

	/*
	 *	Fill it with data.
	 */
	reply->code = PW_TNC_REQUEST;
	flags_ver = SET_START(flags_ver); //set start-flag
	DEBUG("$$$$$$$$$$$$$$$$Flags: %d", flags_ver);
	reply->flags_ver = flags_ver;
	reply->length = 1+1; /* one byte of flags_ver */


	/*
	 *	Compose the EAP-TNC packet out of the data structure,
	 *	and free it.
	 */
	eaptnc_compose(handler->eap_ds, reply);
	eaptnc_free(&reply);

    //put sessionAttribute to Handler and increase sessionCounter
    handler->opaque = calloc(sizeof(TNC_ConnectionID), 1);
    if (handler->opaque == NULL)  {
	radlog(L_ERR, "rlm_eap_tnc: out of memory");
	return 0;
    }
    handler->free_opaque = free;
    memcpy(handler->opaque, &sessionCounter, sizeof(int));
    sessionCounter++;
    
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

static void setVlanAttribute(rlm_eap_tnc_t *inst, EAP_HANDLER *handler,
			     VlanAccessMode mode){
	VALUE_PAIR *vp;
    char *vlanNumber = NULL;
    switch(mode){
        case VLAN_ISOLATE:
            vlanNumber = inst->vlan_isolate;
	    vp = pairfind(handler->request->config_items, PW_TNC_VLAN_ISOLATE,
	    		  TAG_ANY);
	    if (vp) vlanNumber = vp->vp_strvalue;
            break;
        case VLAN_ACCESS:
            vlanNumber = inst->vlan_access;
	    vp = pairfind(handler->request->config_items, PW_TNC_VLAN_ACCESS,
	    		  TAG_ANY);
	    if (vp) vlanNumber = vp->vp_strvalue;
            break;

    default:
	    DEBUG2("  rlm_eap_tnc: Internal error.  Not setting vlan number");
	    return;
    }
    pairadd(&handler->request->reply->vps,
	    pairmake("Tunnel-Type", "VLAN", T_OP_SET));
    
    pairadd(&handler->request->reply->vps,
	    pairmake("Tunnel-Medium-Type", "IEEE-802", T_OP_SET));
    
    pairadd(&handler->request->reply->vps,
	    pairmake("Tunnel-Private-Group-ID", vlanNumber, T_OP_SET));
    
}

/*
 *	Authenticate a previously sent challenge.
 */
static int tnc_authenticate(void *type_arg, EAP_HANDLER *handler)
{
    TNC_PACKET	*packet;
    TNC_PACKET	*reply;
    TNC_ConnectionID connId = *((TNC_ConnectionID *) (handler->opaque));
    TNC_ConnectionState state;
    rlm_eap_tnc_t *inst = type_arg;
    int isAcknowledgement = 0;
    TNC_UInt32 tnccsMsgLength = 0;
    int isLengthIncluded;
    int moreFragments;
    TNC_UInt32 overallLength;
    TNC_BufferReference outMessage;
    TNC_UInt32 outMessageLength = 2;
    int outIsLengthIncluded=0;
    int outMoreFragments=0;
    TNC_UInt32 outOverallLength=0;

    DEBUG2("HANDLER_OPAQUE: %d", (int) *((TNC_ConnectionID *) (handler->opaque)));
    DEBUG2("TNC-AUTHENTICATE is starting now for %d..........", (int) connId);

	/*
	 *	Get the User-Password for this user.
	 */
    rad_assert(handler->request != NULL);
	rad_assert(handler->stage == AUTHENTICATE);
    
	/*
	 *	Extract the EAP-TNC packet.
	 */
    if (!(packet = eaptnc_extract(handler->eap_ds)))
		return 0;

	/*
	 *	Create a reply, and initialize it.
	 */
	reply = eaptnc_alloc();
	if (!reply) {
		eaptnc_free(&packet);
		return 0;
	}
    
	reply->id = handler->eap_ds->request->id;
	reply->length = 0;
    if(packet->data_length==0){
        tnccsMsgLength = packet->length-TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH;
    }else{
        tnccsMsgLength = packet->length-TNC_PACKET_LENGTH;
    }
    isLengthIncluded = TNC_LENGTH_INCLUDED(packet->flags_ver);
    moreFragments = TNC_MORE_FRAGMENTS(packet->flags_ver);
    overallLength = packet->data_length;
    if(isLengthIncluded == 0 
        && moreFragments == 0 
        && overallLength == 0 
        && tnccsMsgLength == 0
        && TNC_START(packet->flags_ver)==0){
        
        isAcknowledgement = 1;
    }
    
    DEBUG("Data received: (%d)", (int) tnccsMsgLength);
/*    int i;
    for(i=0;i<tnccsMsgLength;i++){
        DEBUG2("%c", (packet->data)[i]);
    }
    DEBUG2("\n");
   */
    state = exchangeTNCCSMessages(inst->tnc_path,
                                  connId,
                                  isAcknowledgement,
                                  packet->data, 
                                  tnccsMsgLength, 
                                  isLengthIncluded, 
                                  moreFragments, 
                                  overallLength, 
                                  &outMessage, 
                                  &outMessageLength,
                                  &outIsLengthIncluded,
                                  &outMoreFragments,
                                  &outOverallLength);
    DEBUG("GOT State %08x from TNCS", (unsigned int) state);
    if(state == TNC_CONNECTION_EAP_ACKNOWLEDGEMENT){ //send back acknoledgement
        reply->code = PW_TNC_REQUEST;
        reply->data = NULL;
        reply->data_length = 0;
        reply->flags_ver = 1;
        reply->length =TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH; 
    }else{ //send back normal message
        DEBUG("GOT Message from TNCS (length: %d)", (int) outMessageLength);
        
 /*       for(i=0;i<outMessageLength;i++){
            DEBUG2("%c", outMessage[i]);
        }
        DEBUG2("\n");
 */
        DEBUG("outIsLengthIncluded: %d, outMoreFragments: %d, outOverallLength: %d", 
                outIsLengthIncluded, outMoreFragments, (int) outOverallLength);
        DEBUG("NEW STATE: %08x", (unsigned int) state);
        switch(state){
            case TNC_CONNECTION_STATE_HANDSHAKE:
                reply->code = PW_TNC_REQUEST;
                DEBUG2("Set Reply->Code to EAP-REQUEST\n");
                break;
            case TNC_CONNECTION_STATE_ACCESS_ALLOWED:
                reply->code = PW_TNC_SUCCESS;
                setVlanAttribute(inst, handler,VLAN_ACCESS);
                break;
            case TNC_CONNECTION_STATE_ACCESS_NONE:
                reply->code = PW_TNC_FAILURE;
                //setVlanAttribute(inst, handler, VLAN_ISOLATE);
                break;
            case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
                reply->code = PW_TNC_SUCCESS;
                setVlanAttribute(inst, handler, VLAN_ISOLATE);
                break;
            default:
                reply->code= PW_TNC_FAILURE;
                
        }
        if(outMessage!=NULL && outMessageLength!=0){
            reply->data = outMessage;
        }
        reply->flags_ver = 1;
        if(outIsLengthIncluded){
            reply->flags_ver = SET_LENGTH_INCLUDED(reply->flags_ver);
            reply->data_length = outOverallLength;
            reply->length = TNC_PACKET_LENGTH + outMessageLength;
            DEBUG("SET LENGTH: %d", reply->length);
            DEBUG("SET DATALENGTH: %d", (int) outOverallLength);
        }else{
            reply->data_length = 0;
            reply->length = TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH + outMessageLength;        
            DEBUG("SET LENGTH: %d", reply->length);
        }
        if(outMoreFragments){
            reply->flags_ver = SET_MORE_FRAGMENTS(reply->flags_ver);
        }
    }
    
	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eaptnc_compose(handler->eap_ds, reply);
    	eaptnc_free(&reply);

    handler->stage = AUTHENTICATE;
    
	eaptnc_free(&packet);
	return 1;
}


static CONF_PARSER module_config[] = {
	{ "vlan_access", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_tnc_t, vlan_access), NULL, NULL },
	{ "vlan_isolate", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_tnc_t, vlan_isolate), NULL, NULL },
	{ "tnc_path", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_tnc_t, tnc_path), NULL,
	"/usr/local/lib/libTNCS.so"},

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/*
 *	Attach the EAP-TNC module.
 */
static int tnc_attach(CONF_SECTION *cs, void **instance)
{
	rlm_eap_tnc_t *inst;

	*instance = inst = talloc_zero(cs, rlm_eap_tnc_t);
	if (!inst) return -1;

	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	
	if (!inst->vlan_access || !inst->vlan_isolate) {
		radlog(L_ERR, "rlm_eap_tnc: Must set both vlan_access and vlan_isolate");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_tnc = {
	"eap_tnc",
	tnc_attach,			/* attach */
	tnc_initiate,			/* Start the initial request */
	NULL,				/* authorization */
	tnc_authenticate,		/* authentication */
	NULL			      	/* detach */
};
