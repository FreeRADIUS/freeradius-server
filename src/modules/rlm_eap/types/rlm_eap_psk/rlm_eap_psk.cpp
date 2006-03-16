/* $Id$ */

/*
 * rlm_eap_psk.cpp
 *
 * Implementation of the interface between the radius server and 
 * the eap-psk protocol
 *
 * 
 * Copyright (C) France Télécom R&D (DR&D/MAPS/NSS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */



#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>


#include "eap_psk.h"
#include "eap_psk_ssm.h"

static CONF_PARSER moduleConfig[] = {
	{ "private_key", PW_TYPE_STRING_PTR,
	  offsetof(PSK_CONF, privateKey), NULL, NULL },
	{ "server_name", PW_TYPE_STRING_PTR,
	  offsetof(PSK_CONF, id_s), NULL, "pskserver" },
	{ "peer_nai_attribute", PW_TYPE_STRING_PTR,
	  offsetof(PSK_CONF, peerNaiAttribute), NULL, "eapPskPeerNAI" },
	{ "peer_key_attribute", PW_TYPE_STRING_PTR,
	  offsetof(PSK_CONF, peerKeyAttribute), NULL, "eapPskPeerKey" },
	{ "users_file_path", PW_TYPE_STRING_PTR,
	  offsetof(PSK_CONF, usersFilePath), NULL, "/etc/raddb/users.psk" },
	{ "nb_retry", PW_TYPE_INTEGER,
	  offsetof(PSK_CONF, nbRetry), NULL, "3" },
	{ "max_delay", PW_TYPE_INTEGER,
	  offsetof(PSK_CONF, maxDelay), NULL, "5" },
	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};


/** 
 *@memo		this function add value pair to reply
 */
static void addReply(VALUE_PAIR** vp, 
		      const char* name, unsigned char* value, int len)
{
	VALUE_PAIR *reply_attr;
	reply_attr = pairmake(name, "", T_OP_EQ);
	if (!reply_attr) {
		DEBUG("rlm_eap_psk: "
		      "add_reply failed to create attribute %s: %s\n", 
		      name, librad_errstr);
		return;
	}

	memcpy(reply_attr->vp_octets, value, len);
	reply_attr->length = len;
	pairadd(vp, reply_attr);
}

/*
 *@memo  	this function detaches the module
 */
static int pskDetach(void *arg)
{
	PSK_CONF *inst = (PSK_CONF *) arg;

	if (inst->privateKey) free(inst->privateKey);
	if (inst->id_s) free(inst->id_s);
	if (inst->peerNaiAttribute) free(inst->peerNaiAttribute);
	if (inst->peerKeyAttribute) free(inst->peerKeyAttribute);
	if(inst->usersFilePath) free(inst->usersFilePath);

	free(inst);

	return 0;
}


/*
 *@memo	         this function attaches the module
 */
static int pskAttach(CONF_SECTION *cs, void **instance)
{
	PSK_CONF *inst;

	inst = (PSK_CONF*)malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_psk: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	// parse the configuration attributes
	if (cf_section_parse(cs, inst, moduleConfig) < 0) {
	  pskDetach(inst);
	  return -1;
	}
	
	*instance = inst;
	return 0;
}



/** 
 *@memo		this function begins the conversation when the EAP-Identity response is received
 *              send an initial eap-psk request, ie IDREQ
 *@param        handler, pointer to specific information about the eap-psk protocol
 */
static int pskInitiate(void *type_arg, EAP_HANDLER *handler)
{
  PSK_SESSION *session;
  PSK_CONF *conf=(PSK_CONF*)type_arg;

  if(conf==NULL)
    {
      radlog(L_ERR,"rlm_eap_psk: Cannot initiate EAP-PSK without having its configuration");
      return 0;
    }

  DEBUG2("rlm_eap_psk: privateKey: %s",conf->privateKey);
  DEBUG2("rlm_eap_psk: id_s: %s", conf->id_s);
  DEBUG2("rlm_eap_psk: peerNaiAttribute: %s", conf->peerNaiAttribute);
  DEBUG2("rlm_eap_psk: peerKeyAttribute: %s", conf->peerKeyAttribute);
  DEBUG2("rlm_eap_psk: usersFilePath: %s", conf->usersFilePath);

  // allocate memory in order to save the state of session
  handler->opaque=malloc(sizeof(PSK_SESSION));
  if(!handler->opaque) {
    radlog(L_ERR,"rlm_eap_psk: Out of memory");
    return 0;
  }

  // save this pointer in the handler
  session=(PSK_SESSION *)handler->opaque;
  handler->free_opaque=pskFreeSession;

  // initializing session information
  memset(session,0,sizeof(PSK_SESSION));
  session->state=INIT;
   
  handler->stage=AUTHENTICATE;

  // initiate the eap-psk protocol
  return pskProcess(conf,session,NULL,handler->eap_ds->request);
  
}




/** 
 *@memo		this function uses specific EAP-Type authentication mechanism to authenticate the user
 *              may be called many times
 *@param        handler, pointer to specific information about the eap-psk protocol
 */
static int pskAuthenticate(void *arg, EAP_HANDLER *handler)
{
  PSK_SESSION *session;
  PSK_CONF *conf=(PSK_CONF*)arg;
  int resul;
  
  if(conf==NULL)
    {
      radlog(L_ERR,"rlm_eap_psk: Cannot authenticate without having EAP-PSK configuration");
      return 0;
    }
  
  if(!handler->opaque) {
    radlog(L_ERR,"rlm_eap_psk: Cannot authenticate without EAP-PSK session information");
    return 0;
  }
  
  // find the session information
  session=(PSK_SESSION *)handler->opaque;

  resul=pskProcess(conf,session,handler->eap_ds->response,handler->eap_ds->request);
  
  if(handler->eap_ds->request->code==PW_EAP_SUCCESS) {
    // sending keys
    addReply(&handler->request->reply->vps,"MS-MPPE-Recv-Key",session->msk,32);
    addReply(&handler->request->reply->vps,"MS-MPPE-Send-Key",&session->msk[32],32);
  }
  
  return resul;
  
}


EAP_TYPE rlm_eap_psk = {
	"eap_psk",
	pskAttach,		// attach
	pskInitiate,		// Start the initial request, after Identity
	NULL,
	pskAuthenticate,        // authentication
	pskDetach		// detach
};
