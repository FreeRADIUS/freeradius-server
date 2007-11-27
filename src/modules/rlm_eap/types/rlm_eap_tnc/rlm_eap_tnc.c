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
 */

#include <freeradius-devel/autoconf.h>

#include <stdio.h>
#include <stdlib.h>

#include "tncs_connect.h"
#include "eap_tnc.h"
#include "tncs.h"
#include <freeradius-devel/rad_assert.h>



static int sessionCounter=0;
static char* vlanAccess=0;
static char* vlanIsolate=0;
static char* pathToSO=0;

static void init(void){
    FILE *f;
    f = fopen("/etc/tnc/tncs_fhh.conf", "r");
    if(f==NULL){
        DEBUG("Could not open tncs_fhh.conf, use default values for VLANs (96,97)");
        vlanAccess = "96";
        vlanIsolate = "97";
    }else{
        char *line = calloc(sizeof(char), 212);
        while(fgets(line, 212, f)!=NULL){
            //DEBUG("line: %s", line);
            if(strncmp(line, "VLAN_ACCESS=",12)==0){
                int i;
                for(i=12;i<20;i++){
                    if(line[i]==' ' || line[i]=='\n'){
                        vlanAccess= calloc(i-12+1, sizeof(char));
                        memcpy(vlanAccess, &(line[12]), i-12);
                        break;
                        //memcpy(&vlanAccess[i-13],"\n", 1);
                    }
                }
            }
            if(strncmp(line, "VLAN_ISOLATE=", 13)==0){
                int i;
                for(i=13;i<20;i++){
                    if(line[i]==' ' || line[i]=='\n'){
                        vlanIsolate= calloc(i-13, sizeof(char));
                        memcpy(vlanIsolate, &(line[13]), i-13);
                        break;
                    }
                }
            }
            //also inits path to TNCS-SO
            if(strncmp(line, "TNCS_PATH=", 10)==0){
                int i;
                for(i=10;i<212;i++){
                    if(line[i]==' ' || line[i]=='\n'){
                        pathToSO= calloc(i-9, sizeof(char));
                        memcpy(pathToSO, &(line[10]), i-10);
                        pathToSO[i]='\0';
                        break;
                    }
                }            
            }
        }
        DEBUG("VLAN_ISOLATE: %s", vlanIsolate);
        DEBUG("VLAN_ACCESS: %s", vlanAccess);
        DEBUG("PATH to SO: %s", pathToSO);
    }
    fclose(f);
}

/*
 *	Initiate the EAP-MD5 session by sending a challenge to the peer.
 *  Initiate the EAP-TNC session by sending a EAP Request witch Start Bit set 
 *  and with no data
 */
static int tnc_initiate(void *type_data, EAP_HANDLER *handler)
{
	if (!handler->request || !handler->request->parent) {
		DEBUG2("rlm_eap_tnc: Must be run inside of a TLS method");
		return 0;
	}

	DEBUG("tnc_initiate: %ld", handler->timestamp);
    if(vlanAccess==0 || vlanIsolate==0 || pathToSO==0){
        init();
    }
	TNC_PACKET	*reply;
	
	if(connectToTncs(pathToSO)==-1){
		DEBUG("Could not connect to TNCS");
	}else{
		
	}

	type_data = type_data;	/* -Wunused */
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
	uint8_t flags_ver = 1; //set version to 1
	flags_ver = SET_START(flags_ver); //set start-flag
	DEBUG("$$$$$$$$$$$$$$$$Flags: %d", flags_ver);
	reply->flags_ver = flags_ver;
	reply->length = 1+1; /* one byte of flags_ver */


	/*
	 *	Compose the EAP-TNC packet out of the data structure,
	 *	and free it.
	 */
	eaptnc_compose(handler->eap_ds, reply);

    //put sessionAttribute to Handler and increase sessionCounter
    handler->opaque = calloc(sizeof(TNC_ConnectionID), 1);
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

static void setVlanAttribute(EAP_HANDLER *handler, VlanAccessMode mode){
    char *vlanNumber = "1";
    switch(mode){
        case VLAN_ISOLATE:
            vlanNumber = vlanIsolate;
            break;
        case VLAN_ACCESS:
            vlanNumber = vlanAccess;
            break;
    }
    VALUE_PAIR *tunnelType = pairmake("Tunnel-Type", "VLAN", T_OP_SET);
    pairadd(&handler->request->reply->vps, tunnelType);
    
    VALUE_PAIR *tunnelMedium;
    tunnelMedium = pairmake("Tunnel-Medium-Type", "IEEE-802", T_OP_SET);
    pairadd(&handler->request->reply->vps, tunnelMedium);
    
    
    VALUE_PAIR *vlanId;
    vlanId = pairmake("Tunnel-Private-Group-ID", vlanNumber, T_OP_SET);
    pairadd(&handler->request->reply->vps, vlanId);
    DEBUG2("XXXXXXXXXXXXXXXXXX added VALUE_Pair!\n");
    
}

/*
 *	Authenticate a previously sent challenge.
 */
static int tnc_authenticate(UNUSED void *arg, EAP_HANDLER *handler)
{
    TNC_PACKET	*packet;
    TNC_PACKET	*reply;
    DEBUG2("HANDLER_OPAQUE: %d\n", *((TNC_ConnectionID *) (handler->opaque)));
    TNC_ConnectionID connId = *((TNC_ConnectionID *) (handler->opaque));
    DEBUG2("XXXXXXXXXXXX TNC-AUTHENTICATE is starting now for %d..........\n", connId);

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
		return 0;
	}
    
	reply->id = handler->eap_ds->request->id;
	reply->length = 0;
    TNC_UInt32 tnccsMsgLength = 0;
    if(packet->data_length==0){
        tnccsMsgLength = packet->length-TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH;
    }else{
        tnccsMsgLength = packet->length-TNC_PACKET_LENGTH;
    }
    TNC_BufferReference outMessage;
    TNC_UInt32 outMessageLength = 2;
    int isLengthIncluded = TNC_LENGTH_INCLUDED(packet->flags_ver);
    TNC_UInt32 overallLength = packet->data_length;
    int moreFragments = TNC_MORE_FRAGMENTS(packet->flags_ver);
    int outIsLengthIncluded=0;
    int outMoreFragments=0;
    TNC_UInt32 outOverallLength=0;
    int isAcknoledgement = 0;
    if(isLengthIncluded == 0 
        && moreFragments == 0 
        && overallLength == 0 
        && tnccsMsgLength == 0
        && TNC_START(packet->flags_ver)==0){
        
        isAcknoledgement = 1;
    }
    
    DEBUG("Data received: (%d)\n", tnccsMsgLength);
/*    int i;
    for(i=0;i<tnccsMsgLength;i++){
        DEBUG2("%c", (packet->data)[i]);
    }
    DEBUG2("\n");
   */
    TNC_ConnectionState state = exchangeTNCCSMessages(pathToSO,
                                                        connId,
                                                        isAcknoledgement,
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
    DEBUG("GOT State %d from TNCS", state);
    if(state == TNC_CONNECTION_EAP_ACKNOWLEDGEMENT){ //send back acknoledgement
        reply->code = PW_TNC_REQUEST;
        reply->data = NULL;
        reply->data_length = 0;
        reply->flags_ver = 1;
        reply->length =TNC_PACKET_LENGTH_WITHOUT_DATA_LENGTH; 
    }else{ //send back normal message
        DEBUG("GOT Message from TNCS (length: %d)", outMessageLength);
        
 /*       for(i=0;i<outMessageLength;i++){
            DEBUG2("%c", outMessage[i]);
        }
        DEBUG2("\n");
 */
        DEBUG("outIsLengthIncluded: %d, outMoreFragments: %d, outOverallLength: %d", 
                outIsLengthIncluded, outMoreFragments, outOverallLength);
        DEBUG("NEW STATE: %d", state);
        switch(state){
            case TNC_CONNECTION_STATE_HANDSHAKE:
                reply->code = PW_TNC_REQUEST;
                DEBUG2("Set Reply->Code to EAP-REQUEST\n");
                break;
            case TNC_CONNECTION_STATE_ACCESS_ALLOWED:
                reply->code = PW_TNC_SUCCESS;
                setVlanAttribute(handler,VLAN_ACCESS);
                break;
            case TNC_CONNECTION_STATE_ACCESS_NONE:
                reply->code = PW_TNC_FAILURE;
                //setVlanAttribute(handler, VLAN_ISOLATE);
                break;
            case TNC_CONNECTION_STATE_ACCESS_ISOLATED:
                reply->code = PW_TNC_SUCCESS;
                setVlanAttribute(handler, VLAN_ISOLATE);
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
            DEBUG("SET DATALENGTH: %d", outOverallLength);
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
    
    handler->stage = AUTHENTICATE;
    
	eaptnc_free(&packet);
	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_tnc = {
	"eap_tnc",
	NULL,				/* attach */
	tnc_initiate,			/* Start the initial request */
	NULL,				/* authorization */
	tnc_authenticate,		/* authentication */
	NULL				/* detach */
};
