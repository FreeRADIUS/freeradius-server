/* $Id$ */

/*
 * eap_psk_ssm.cpp
 *
 * Implementation of the Server State Machine (SSM)
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
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "radiusd.h"
#include "modpriv.h"
#include "modules.h"
#include "modcall.h"
#include "conffile.h"
#include "ltdl.h"


#include "eap_psk_ssm.h"
#include "AES.h"
#include "OMAC.h"
#include "EAX.h"
#include "SOBMMO.h"

#include "userinfo.h"


/*  PSK Packet Format in EAP 
 *  --- ------ ------ -- ---
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |   Identifier  |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |   Data 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-
 */


int pskProcess(PSK_CONF *conf, PSK_SESSION *session, EAP_PACKET *recvPacket, EAP_PACKET *sentPacket){

  // error cases
  if(conf==NULL || session==NULL)
    {
      radlog(L_ERR,"rlm_eap_psk: Cannot authenticate without EAP-PSK configuration and session information");
      return 0;
    }
  
  if(recvPacket && (recvPacket->code!=PW_EAP_RESPONSE || recvPacket->type.type!=EAPPSK_TYPE))
    {
      radlog(L_ERR,"pskProcess: EAP-PSK Response expected");
      return 0;
    }  

  switch(session->state)
    {
    case INIT: return pskInit(conf,session,sentPacket);
    case RANDSENT:
		if(recvPacket) return pskRandSent(conf,session, recvPacket,sentPacket);
    case PCHANNEL: 
		if(recvPacket) return pskPChannel(conf,session,recvPacket,sentPacket);
    default:
      radlog(L_ERR,"pskProcess: Impossible to process the EAP-PSK authentication");
      return 0;
    }

}


int pskInit(PSK_CONF *conf, PSK_SESSION *session, EAP_PACKET *sentPacket){

  char hexstr[1024];
  
  session->nbRetry=0;
  session->pChannelReplayCounter=0;
  session->authStatus=PSK_STATUS_CONT;
  session->isSupportedExt=1;
  session->extType=0;
  
  sentPacket->code=PW_EAP_REQUEST;
  sentPacket->length=PSK_RANDOM_NUMBER_SIZE+EAP_HEADER_SIZE;
  sentPacket->type.type=EAPPSK_TYPE;
  sentPacket->type.length=PSK_RANDOM_NUMBER_SIZE;
  sentPacket->type.data=NULL;
  sentPacket->type.data=(unsigned char*)malloc(PSK_RANDOM_NUMBER_SIZE);
  
  if(sentPacket->type.data==NULL)
    {
      radlog(L_ERR,"pskInit: Out of memory");
      return 0;
    }
  
  // generate a 128-bit random value and put this value in session->rand_s
  if(!pskGetRandomBytes(sentPacket->type.data,PSK_RANDOM_NUMBER_SIZE)) {
    radlog(L_ERR,"pskInit: problem during random number generation");
    return 0;
  }
  
  pskConvertHex((char *)sentPacket->type.data, (char *)hexstr,PSK_RANDOM_NUMBER_SIZE);
  DEBUG2("pskInit: random number RA :");
  DEBUG2((char *)hexstr);
  
  // save this value in session information
  memcpy(session->rand_s,sentPacket->type.data,PSK_RANDOM_NUMBER_SIZE);
  
  session->state=RANDSENT;
 
  return 1;
  
}


int pskRandSent(PSK_CONF *conf, PSK_SESSION *session, EAP_PACKET *recvPacket, EAP_PACKET *sentPacket){
  
  /* the received packet is shown below
   * 
   * 0                   1                   2                   3
   * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Code=2     |  Identifier   |            Length             |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |  Type EAP-PSK |                                               |
   * +-+-+-+-+-+-+-+-+                                               +
   * |                                                               |
   * +                                                               +
   * |                             RAND_P                            |
   * +                                                               +
   * |                                                               |
   * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |               |                                               |
   * +-+-+-+-+-+-+-+-+                                               +
   * |                                                               |
   * +                                                               +
   * |                             MAC_P                             |
   * +                                                               +
   * |                                                               |
   * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |               |                                               |
   * +-+-+-+-+-+-+-+-+                                               :
   * :                              ID_P                             :
   * :                                                               :
   * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */


  psk_message_2 *psk_msg_2;
  psk_message_3 *psk_msg_3;
  int identitySize;
  char hexstr[1024];
 
  unsigned char buffer[PSK_MAC_SIZE];
  unsigned char *data;
  unsigned char *ptr;
  unsigned char buftmp[PSK_AK_SIZE+PSK_KDK_SIZE];
  
  //user profile
  userinfo_t*    uinfo = NULL;
  
  char **psk_vals;
  char *psk_val;
  int i=0;
  char **atts;
  unsigned char privateKey[PSK_SIZE];

  // for the mac calculation
  OMAC om;
  AES c;
  
  // for the key derivation
  SOBMMO sob;
  unsigned char *block;
  // counter values
  unsigned char counterValues[]={	
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09};
  

  // for the pchannel
  unsigned char nn[PSK_RANDOM_NUMBER_SIZE];
  unsigned char eapHeader[EAP_HEADER_SIZE];
  EAX eax;



  if(recvPacket->length<(EAP_HEADER_SIZE+PSK_RANDOM_NUMBER_SIZE+PSK_MAC_SIZE+1))
    {
      // the packet is malformed
      DEBUG2("pskPChannel: the packet is malformed: the authentication must fail");
      sentPacket->code=PW_EAP_FAILURE;
      
      return 1;
    }
  
  // retrieve the identity of the peer, ID_P
  identitySize=recvPacket->length-(EAP_HEADER_SIZE+PSK_RANDOM_NUMBER_SIZE+PSK_MAC_SIZE);
  session->id_p=(unsigned char *)malloc(identitySize+1);
  if(session->id_p==NULL)
    {
      radlog(L_ERR,"pskRandSent: Out of memory");
      return 0;
    }
  psk_msg_2=(psk_message_2*)recvPacket->type.data;
  memcpy(session->id_p,&(psk_msg_2->id_p),identitySize);
  session->id_p[identitySize]='\0'; 

  // search the peer identity in the user file whose path is conf->usersFilePath
  
  uinfo = pskGetUserInfo((char*)conf->usersFilePath, (char*)session->id_p);
  if (uinfo)
    {
      
      DEBUG2("pskRandSent: identity successfully checked");
      DEBUG2("pskRandSent: saving peer information");
      
      // save keys                                                    
      memcpy(session->ak,uinfo->AK,PSK_AK_SIZE);
      memcpy(session->kdk,uinfo->KDK,PSK_KDK_SIZE);
      
      DEBUG2("pskRandSent: found user %s in %s",session->id_p, conf->usersFilePath);
      
      free(uinfo);
      
    } else {
      
      // the peer identity wasn't found
      DEBUG2("pskRandSent: the peer identity isn't valid");
      DEBUG2("pskRandSent: the authentication must fail");
      sentPacket->code=PW_EAP_FAILURE;
      
      return 1;  
    }
  
  // calculate the following MAC: MAC(session->ak, ID_P || conf->id_s || session->rand_s || RAND_P)
  
  // making the formula
  data=(unsigned char *)malloc(strlen((char*)session->id_p)+strlen((char*)conf->id_s)+2*PSK_RANDOM_NUMBER_SIZE);
  if(data==NULL) {
    radlog(L_ERR,"pskRandSent: out of memory");
    return 0;
  }
  ptr=data;
  memcpy(ptr,session->id_p,strlen((char*)session->id_p));
  ptr+=strlen((char*)session->id_p);
  memcpy(ptr,conf->id_s,strlen((char*)conf->id_s));
  ptr+=strlen((char*)conf->id_s);
  memcpy(ptr,session->rand_s,PSK_RANDOM_NUMBER_SIZE);
  ptr+=PSK_RANDOM_NUMBER_SIZE;
  memcpy(ptr,psk_msg_2->rand_p,PSK_RANDOM_NUMBER_SIZE);
  
  pskConvertHex((char *)data, (char *)hexstr,strlen((char*)session->id_p)+strlen((char*)conf->id_s)+2*PSK_RANDOM_NUMBER_SIZE);
  DEBUG2("pskRandSent: [B||A||RA||RB] :");
  DEBUG2((char *)hexstr);
  
  pskConvertHex((char *)(session->ak), (char *)hexstr,PSK_AK_SIZE);
  DEBUG2("pskRandSent: AK :");
  DEBUG2((char *)hexstr);


  // obtain the mac

  c.makeKey(session->ak,PSK_AK_SIZE,DIR_ENCRYPT);
  om.init(&c);
  om.update(data,strlen((char*)session->id_p)+strlen((char*)conf->id_s)+2*PSK_RANDOM_NUMBER_SIZE);
  om.final(buffer);
  free(data);
  
  pskConvertHex((char *)buffer, (char *)hexstr,PSK_MAC_SIZE);
  DEBUG2("pskRandSent: MAC of [B||A||RA||RB] :");
  DEBUG2((char *)hexstr);
  

  if(memcmp(buffer,psk_msg_2->mac_p,PSK_MAC_SIZE))
    {
      // the received MAC attribute is not correct
      DEBUG2("pskRandSent: the received MAC attribute isn't correct");
      DEBUG2("pskRandSent: the authentication must fail");
      sentPacket->code=PW_EAP_FAILURE;
      
      return 1;
    }

  
  DEBUG2("pskRandSent: the received MAC attribute is correct");
  
  // KEY DERIVATION
  
  // initialize the sobmmo
  sob.initialize(session->kdk,&c,psk_msg_2->rand_p,9,counterValues);
  
  // get the TEK
  block=sob.getOutputBlock(1);
  memcpy(session->tek,block,PSK_TEK_SIZE);
  free(block);
  
  pskConvertHex((char *)session->tek, (char *)hexstr, PSK_TEK_SIZE);
  DEBUG2("pskRandSent: TEK :");
  DEBUG2((char *)hexstr);
  
  // get the MSK
  for(int i=0;i<4;i++)
    {
      block=sob.getOutputBlock(i+2);
      memcpy(&session->msk[i*16],block,16);
      free(block);
    }
			       
  pskConvertHex((char *)session->msk, (char *)hexstr, PSK_MSK_SIZE);
  DEBUG2("pskRandSent: MSK :");
  DEBUG2((char *)hexstr);
  
  // get the EMSK
  for(int i=0;i<4;i++)
    {
      block=sob.getOutputBlock(i+6);
      memcpy(&session->emsk[i*16],block,16);
      free(block);
    }
  
  pskConvertHex((char *)session->emsk, (char *)hexstr, PSK_EMSK_SIZE);
  DEBUG2("pskRandSent: EMSK :");
  DEBUG2((char *)hexstr);
			       
			       
  // obtain the mac of [A||RB]
  data=(unsigned char *)malloc(strlen((char*)conf->id_s)+PSK_RANDOM_NUMBER_SIZE);
  if(data==NULL) {
    radlog(L_ERR,"pskRandSent: out of memory");
    return 0;
  }
  memcpy(data,conf->id_s,strlen((char*)conf->id_s));
  memcpy(data+strlen((char*)conf->id_s),psk_msg_2->rand_p,PSK_RANDOM_NUMBER_SIZE);
  
  pskConvertHex((char *)data, (char *)hexstr,strlen((char*)conf->id_s)+PSK_RANDOM_NUMBER_SIZE);
  DEBUG2("pskRandSent: [A||RB] :");
  DEBUG2((char *)hexstr);
  
  c.makeKey(session->ak,PSK_AK_SIZE,DIR_ENCRYPT);
  om.init(&c);
  om.update(data,strlen((char*)conf->id_s)+PSK_RANDOM_NUMBER_SIZE);
  om.final(buffer);
  free(data);
  
  pskConvertHex((char *)&buffer, (char *)hexstr,16);
  DEBUG2("pskRandSent: MAC of [A||RB] :");
  DEBUG2((char *)hexstr);
  

  if(session->extType==0)
    {
      // standard authentication
      
      sentPacket->code=PW_EAP_REQUEST;
      sentPacket->length=EAP_HEADER_SIZE+2*PSK_MAC_SIZE+PSK_PCHANNEL_REPLAY_COUNTER_SIZE+1;
      sentPacket->type.type=EAPPSK_TYPE;
      sentPacket->type.length=2*PSK_MAC_SIZE+PSK_PCHANNEL_REPLAY_COUNTER_SIZE+1;
      sentPacket->type.data=NULL;
      sentPacket->type.data=(unsigned char*)malloc(2*PSK_MAC_SIZE+PSK_PCHANNEL_REPLAY_COUNTER_SIZE+1);
      
      if(sentPacket->type.data==NULL)
	{
	  radlog(L_ERR,"pskRandSent: Out of memory");
	  return 0;
	}

      psk_msg_3=(psk_message_3*)sentPacket->type.data;

      // add to sentPacket the following MAC: MAC(session->AK, conf->id_s || RAND_P)
      memcpy(psk_msg_3->mac_s,buffer,PSK_MAC_SIZE);

      // add to sentPacket the following information: 
      // R = DONE_SUCCESS (the R flag is equal to session->authStatus)
      // E=0
      psk_msg_3->nonce=htonl(session->pChannelReplayCounter);
      
      // calculate the EAP header
      eapHeader[0]=sentPacket->code;
      eapHeader[1]=(recvPacket->id)+1; // we suppose that the identifier is incremented by 1

      sentPacket->length=htons(sentPacket->length);
      memcpy(&(eapHeader[2]),&(sentPacket->length),2);
      sentPacket->length=ntohs(sentPacket->length);

      eapHeader[4]=sentPacket->type.type;

      pskConvertHex((char *)eapHeader, (char *)hexstr,EAP_HEADER_SIZE);
      DEBUG2("pskRandSent: eapHeader :");
      DEBUG2((char *)hexstr);
      
      // the replay counter is the least significant bytes of the nonce !
      memset(nn,0,PSK_RANDOM_NUMBER_SIZE);
      memcpy(&nn[PSK_RANDOM_NUMBER_SIZE-PSK_PCHANNEL_REPLAY_COUNTER_SIZE],&(psk_msg_3->nonce),PSK_PCHANNEL_REPLAY_COUNTER_SIZE);

      pskConvertHex((char *)nn, (char *)hexstr,PSK_RANDOM_NUMBER_SIZE);
      DEBUG2("pskRandSent: nn :");
      DEBUG2((char *)hexstr);

      session->authStatus=PSK_STATUS_DONE_SUCCESS;

      // EAX encryption
      
      eax.initialize(session->tek, PSK_TEK_SIZE, AES_BLOCKSIZE, &c);

      eax.provideNonce((byte*)nn,PSK_RANDOM_NUMBER_SIZE);
      eax.provideHeader((byte*)eapHeader,EAP_HEADER_SIZE);
      eax.computeCiphertext((byte*)&(session->authStatus),sizeof(session->authStatus),(byte*)&(psk_msg_3->flags));
      eax.computeTag((byte*)psk_msg_3->tag);
       
      // !!! BE CAREFUL !!! 
      // the authorization isn't taken into account in this implementation
      // that's why R=DONE_SUCCESS
      
    } else {
      // extended authentication
      

      // !!!!! NOT IMPLEMENTED !!!!!!
      return 0;

      /*

      // call the extension which must update the session->authStatus, i.e. the result of the EAP-PSK authentication
      // see the pskExtension function declaration for more details
      void *payloadOut=NULL;
      int sizePayloadOut=0;
      int resul;
      resul=pskExtension(conf,session,PSK_STATUS_CONT,NULL,0,&payloadOut,&sizePayloadOut);

      if(!resul || (sizePayloadOut<1) || (sizePayloadOut>EXT_PAYLOAD_MAX_LEN))
	{
	  //the extension has failed
	  // the authentication must fail
	  // the sentPacket must be a EAP_Failure packet
	  return 1;
	}
      
      // add to sentPacket the following information:
      // R = CONT or DONE_FAILURE or DONE_SUCCESS thanks to session->authStatus
      // E = 1
      // EXT_Type=session->extType
      // EXT_payload=payloadOut
      
      */
      
    }   

  session->pChannelReplayCounter++;

  session->state=PCHANNEL;
  

  return 1;
  
}



int pskPChannel(PSK_CONF *conf, PSK_SESSION *session, EAP_PACKET *recvPacket, EAP_PACKET *sentPacket){

  /* the received packet is shown below
   *
   * 0                   1                   2                   3
   * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Code=2     |  Identifier   |            Length             |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |  Type EAP-PSK |               Nonce...                                                                      :
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *     ...Nonce    |                                               |
   * +-+-+-+-+-+-+-+-+                                               +
   * |                                                               |
   * +                                                               +
   * |                             TAG                               |
   * +                                                               +
   * |                                                               |
   * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |               | R |E| Reserved|EXT_Type (opt)|                |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++                +
   * :                                                               :
   * :        EXT_Payload (optional)                                 :
   * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   * EXT_Type and EXT_Payload must be in the EAP packet when E is set to 1
   * EXT_Payload could be null
   *
  */

  psk_message_4 *psk_msg_4;

  // for the pchannel
  unsigned char eapHeader[EAP_HEADER_SIZE];
  unsigned char nn[PSK_RANDOM_NUMBER_SIZE];
  EAX eax;
  AES c;
  bool st;
  unsigned char flags;
  
  if(recvPacket->length<(EAP_HEADER_SIZE+PSK_PCHANNEL_REPLAY_COUNTER_SIZE+PSK_MAC_SIZE+1))
    {	
      // the packet is malformed
      // the session->nbRetry isn't incremented
      // sentPacket must be the previous request sent by the server ###### PB TIMER ########
      
      DEBUG2("pskPChannel: receiving a invalid EAP-PSK packet: the packet is malformed");
      DEBUG2("pskPChannel: the authentication must fail");
      sentPacket->code=PW_EAP_FAILURE;
      
      return 1;  
    }
  
  
  psk_msg_4=(psk_message_4*)recvPacket->type.data;


  if(ntohl(psk_msg_4->nonce)!=session->pChannelReplayCounter)
    {
      // the received packet isn't awaited
      // the session->nbRetry isn't incremented
      // sentPacket must be the previous request sent by the server

      DEBUG2("pskPChannel: receiving a invalid EAP-PSK packet: the replay counter isn't valid");
      DEBUG2("pskPChannel: the authentication must fail");
      sentPacket->code=PW_EAP_FAILURE;
      
      return 1;  
    }
  
  // decrypt the received packet with the EAX mode and check the EAP header

   // calculate the EAP header
  eapHeader[0]=recvPacket->code;
  eapHeader[1]=recvPacket->id;
  
  recvPacket->length=htons(recvPacket->length);
  memcpy(&(eapHeader[2]),&(recvPacket->length),2);
  recvPacket->length=ntohs(recvPacket->length);
  
  eapHeader[4]=recvPacket->type.type;
  
  // the replay counter is the least significant bytes of the nonce !
  memset(nn,0,PSK_RANDOM_NUMBER_SIZE);
  memcpy(&nn[PSK_RANDOM_NUMBER_SIZE-PSK_PCHANNEL_REPLAY_COUNTER_SIZE],&(psk_msg_4->nonce),PSK_PCHANNEL_REPLAY_COUNTER_SIZE);

  // EAX encryption
  
  eax.initialize(session->tek, PSK_TEK_SIZE, AES_BLOCKSIZE, &c);
    
  eax.provideNonce((byte*)nn,PSK_RANDOM_NUMBER_SIZE);
  eax.provideHeader((byte*)eapHeader,EAP_HEADER_SIZE);
  eax.provideCiphertext((byte*)&(psk_msg_4->flags),sizeof(psk_msg_4->flags));
  st=eax.checkTag((byte*)psk_msg_4->tag);
  
  if(!st){
    // the decryption ends by a failure
    
    DEBUG2("pskPChannel: receiving a invalid EAP-PSK packet: the decryption fails");
    DEBUG2("pskPChannel: the authentication must fail");
    sentPacket->code=PW_EAP_FAILURE;
    
    return 1;      
  }

  
  eax.computePlaintext((byte*)&(psk_msg_4->flags),sizeof(psk_msg_4->flags),(byte*)&flags);
  
  if((((flags & PSK_IS_EXT)==PSK_IS_EXT) && recvPacket->length<(EAP_HEADER_SIZE+PSK_PCHANNEL_REPLAY_COUNTER_SIZE+PSK_MAC_SIZE+2)) || (((flags & PSK_IS_EXT)==0) && recvPacket->length!=(EAP_HEADER_SIZE+PSK_PCHANNEL_REPLAY_COUNTER_SIZE+PSK_MAC_SIZE+1)))
    {
      // the packet is malformed
      // the authentication must fail
      // the sentPacket must be a EAP_Failure packet

      DEBUG2("pskPChannel: the packet is malformed: the authentication must fail");
      sentPacket->code=PW_EAP_FAILURE;
      
      return 1;
     }
  

   if(session->extType==0 && ((flags & PSK_IS_EXT)==PSK_IS_EXT))
     {
       // error: standard authentication awaited
       // the authentication must fail
       // the sentPacket must be a EAP_Failure packet
       
       DEBUG2("pskPChannel: the packet is malformed: the authentication must fail");
       sentPacket->code=PW_EAP_FAILURE;
       
       return 1;
     }

   if(session->extType!=0 && ((flags & PSK_IS_EXT)==0))
     {
       // error: extended authentication awaited
       // the authentication must fail
       // the sentPacket must be a EAP_Failure packet

       DEBUG2("pskPChannel: the packet is malformed: the authentication must fail");
       sentPacket->code=PW_EAP_FAILURE;

       return 1;
     }

   if((flags & PSK_IS_EXT)==0)
     {
       // standard authentication
       
       if(((flags & PSK_STATUS_DONE_SUCCESS)==PSK_STATUS_DONE_SUCCESS) && session->authStatus==PSK_STATUS_DONE_SUCCESS)
	 {
	   // sentPacket must be an EAP_Success packet
	   // indicate to the lower layer that the MSK and the EMSK are ready
	   // the EAP-PSK authentication will end after sending sentPacket

	   sentPacket->code=PW_EAP_SUCCESS;

	 } else {
	   // sentPacket must be an EAP_Failure packet
	   // the EAP-PSK authentication will end after sending sentPacket

	   sentPacket->code=PW_EAP_FAILURE;

	 }
       
     } else {
       // extended authentication


       // !!!!! NOT IMPLEMENTED !!!!!
       return 0;


       /*              
       if(session->isSupportedExt)
	 {
	   
	   if(recvPacket->data.EXT_Payload)
	     {

	       // call the extension which must update the session->authStatus, i.e. the result of the EAP-PSK authentication
	       // see the pskExtension function declaration for more details
	       void *payloadOut=NULL;
	       int sizePayloadOut=0;
	       int sizePayloadIn=recvPacket->length-27; // (27=5+16+4+1+1)
	       int resul;
	       resul=pskExtension(conf,session,recvPacket->data.R,recvPacket->data.EXT_Payload,sizePayloadIn,&payloadOut,&sizePayloadOut); 
	       
	       if(!resul || (sizePayloadOut<1) || (sizePayloadOut>EXT_PAYLOAD_MAX_LEN))
		 {
		   //the extension has failed
		   // the authentication must fail
		   // the sentPacket must be a EAP_Failure packet
		   return 1;
		 }
	       
	       if(recvPacket->data.R != CONT) {
		 // sentPacket must be an EAP_Success packet or an EAP_Failure packet thanks to the server policy and the received R flag
		 // indicate to the lower layer that the MSK and the EMSK are ready in case an EAP_Success packet must be sent
		 // the EAP-PSK authentication will end after sending sentPacket
		 return 1;
	       }
	       
	       // add to sentPacket the following information:
	       // R = CONT or DONE_FAILURE or DONE_SUCCESS thanks to session->authStatus
	       // E = 1
	       // EXT_Type=session->extType
	       // EXT_payload=payloadOut
	       
	     } else {
	       // the peer doesn't support the specified extension

	       session->isSupportedExt=0;

	       if(recvPacket->data.R != CONT) {
		 // sentPacket must be an EAP_Success packet or an EAP_Failure packet thanks to the server policy and the received R flag
		 // indicate to the lower layer that the MSK and the EMSK are ready in case of an EAP_Success packet must be sent
		 // the EAP-PSK authentication will end after sending sentPacket
		 return 1;
	       }
	       
	       // add to sentPacket the following information:
	       // R = DONE_FAILURE or DONE_SUCCESS thanks to the server policy
	       // E = 1
	       // EXT_Type=session->extType
	     }
	   
	 } else {
	   
	    if(recvPacket->data.R != CONT && recvPacket->data.EXT_Payload==NULL) {
	      // sentPacket must be an EAP_Success packet or an EAP_Failure packet thanks to the server policy and the received R flag
	      // indicate to the lower layer that the MSK and the EMSK are ready in case of an EAP_Success packet must be sent
	      // the EAP-PSK authentication will end after sending sentPacket
	      return 1;

	    } else {
	      // the packet is malformed
	      // the authentication must fail
	      // the sentPacket must be a EAP_Failure packet
	      return 1;
	    }
	      
	 }
       */
       
       session->pChannelReplayCounter++;
       // use the EAX mode to encrypt the EXT_Payload and protect the EAP header
       
       // !!!! NOT IMPLEMENTED !!!!
       // only standard authentication supported

       session->pChannelReplayCounter++;
       
     }
   
   // stay in this state
   return 1;
   
}			



int pskExtension(PSK_CONF *conf, PSK_SESSION *session, unsigned short receivedStatus, void *dataIn, int sizeDataIn, void **dataOut, int *sizeDataOut){
  
  // this functionality makes it possible to do authorization, account refilling...

  // this function must update the session->authStatus variable thanks to its policy, the received R flag, i.e. the receivedStatus variable, and the received data
  
  // !!! Be careful !!!
  // dataOut mustn't be NULL

  // !!!! NOT IMPLEMENTED !!!!
  return 0;

}



/** 
 *@memo		this function frees the session data
 *@param        opaque, pointer to a structure which contains information session
 */
void pskFreeSession(void *opaque){
  PSK_SESSION *session;
  
  DEBUG2("pskFreeSession:");
  
  if(!opaque) return;
  
  session=(PSK_SESSION *)opaque;
  if(!session) return;
  
  if(session->id_p) {
    free(session->id_p);
  }

  free(session);
  
  opaque=NULL;
  
  DEBUG2("pskFreeSession: finished");

}
