/*
 * rlm_securid.c
 *
 * Version:  $Id: $
 *
 * supports "next-token code" and "new-pin" modes
 *
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
 * Copyright 2011 The FreeRADIUS server project
 * Copyright 201  Alan DeKok <aland@networkradius.com>
 */

#include <freeradius-devel/ident.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <ctype.h>

#include "rlm_securid.h"

/* RADIUS PROTOCOL ATTRUBUTES */
#define PW_ATTRIBUTE_NAME_PROMPT         76 /* Prompt */
#define PW_ATTRIBUTE_VALUE_NO_ECHO       0  /* No-Echo */
#define PW_ATTRIBUTE_VALUE_ECHO          1  /* Echo */

typedef enum {
     RC_SECURID_AUTH_SUCCESS = 0,
     RC_SECURID_AUTH_FAILURE = -3,
     RC_SECURID_AUTH_ACCESS_DENIED_FAILURE = -4,
     RC_SECURID_AUTH_INVALID_SERVER_FAILURE = -5,
     RC_SECURID_AUTH_CHALLENGE = -17
}
SECURID_AUTH_RC;


static const CONF_PARSER module_config[] = {
       { "timer_expire", PW_TYPE_INTEGER,offsetof(rlm_securid_t, timer_limit),
	 NULL, "600"},
       { "max_sessions", PW_TYPE_INTEGER,offsetof(rlm_securid_t, max_sessions),
	 NULL, "2048"},
       { "max_trips_per_session", PW_TYPE_INTEGER,offsetof(rlm_securid_t, max_trips_per_session),
	 NULL, NULL},
       { "max_round_trips", PW_TYPE_INTEGER,offsetof(rlm_securid_t, max_trips_per_session),
	 NULL, "6"},
       { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/* comparison function to find session in the tree */
static int securid_session_cmp(const void *a, const void *b)
{
	int rcode;
	const SECURID_SESSION *one = a;
	const SECURID_SESSION *two = b;

	rad_assert(one != NULL);
	rad_assert(two != NULL);

	rcode = fr_ipaddr_cmp(&one->src_ipaddr, &two->src_ipaddr);
	if (rcode != 0) return rcode;

	return memcmp(one->state, two->state, sizeof(one->state));
}


static SECURID_AUTH_RC securidAuth(void *instance, REQUEST *request,
				   const char* username, 
				   const char* passcode,
				   char* replyMsgBuffer,int replyMsgBufferSize)
{
	rlm_securid_t *inst = (rlm_securid_t *) instance;
	int         acmRet;
	SECURID_SESSION *pSecurid_session=NULL;
	int rc=-1;

	if (!username) {
		radlog(L_ERR, "SecurID username is NULL");
		return RC_SECURID_AUTH_FAILURE;		
	}

	if (!passcode) {
		radlog(L_ERR, "SecurID passcode is NULL for %s user",username);
		return RC_SECURID_AUTH_FAILURE;		
	}

	memset(replyMsgBuffer,replyMsgBufferSize,0);


	pSecurid_session = securid_sessionlist_find(inst,request);
	if (pSecurid_session == NULL) {
		/* securid session not found */
		SDI_HANDLE  sdiHandle = SDI_HANDLE_NONE;

		acmRet = SD_Init(&sdiHandle);
		if (acmRet != ACM_OK) {
			radlog(L_ERR, "Cannot communicate with the ACE/Server");
			return -1;
		}

		acmRet = SD_Lock(sdiHandle, (SD_CHAR*)username);
		if (acmRet != ACM_OK) {
			radlog(L_ERR,"SecurID: Access denied. Name [%s] lock failed.",username);
			return -2;
		}

		acmRet = SD_Check(sdiHandle, (SD_CHAR*)passcode, (SD_CHAR*)username);
		switch (acmRet) {
		case ACM_OK:
		     /* we are in now */
		     radlog(L_INFO,"SecurID authentication successful for [%s].",username);
		     SD_Close(sdiHandle);

		     /* strncpy(replyMsgBuffer,"PASSCODE Accepted",replyMsgBufferSize-1); */
		     return RC_SECURID_AUTH_SUCCESS;
		case ACM_ACCESS_DENIED:         
		     /* not this time */
			 radlog(L_AUTH, "rlm_securid: [%s] Access denied",username);
		     SD_Close(sdiHandle);

		     /* strncpy(replyMsgBuffer,"Access denied",replyMsgBufferSize-1); */
		     return RC_SECURID_AUTH_ACCESS_DENIED_FAILURE;
		case ACM_INVALID_SERVER:
		     radlog(L_ERR,"SecurID: Invalid ACE server.");
		     /* strncpy(replyMsgBuffer,"Access not possible. Internal error",replyMsgBufferSize-1); */
		     return RC_SECURID_AUTH_INVALID_SERVER_FAILURE;
		case ACM_NEW_PIN_REQUIRED:
		     DEBUG2("New securid pin required for user [%s]",username);

		     /* create a new session */
		     pSecurid_session = securid_session_alloc();
		     pSecurid_session->sdiHandle = sdiHandle; /* save ACE handle for future use */
		     pSecurid_session->securidSessionState = NEW_PIN_REQUIRED_STATE;
		     pSecurid_session->identity = strdup(username);

		     /* insert new session in the session list */
		     securid_sessionlist_add(inst,request,pSecurid_session);
		
		     strncpy(replyMsgBuffer," \r\n   Enter your new PIN, containing 4 to 6 digits,\r\n                or\r\n   <Ctrl-D> to cancel the New PIN procedure:",replyMsgBufferSize-1);
		     return RC_SECURID_AUTH_CHALLENGE;
		case ACM_NEXT_CODE_REQUIRED:
		     DEBUG2("Next securid token code required for user [%s]",username);

		     /* create a new session */
		     pSecurid_session = securid_session_alloc();
		     pSecurid_session->sdiHandle = sdiHandle;
		     pSecurid_session->securidSessionState = NEXT_CODE_REQUIRED_STATE;
		     pSecurid_session->identity = strdup(username);

		     /* insert new session in the session list */
		     securid_sessionlist_add(inst,request,pSecurid_session);
		     
		     strncpy(replyMsgBuffer,"\r\nPlease Enter the Next Code from Your Token:",replyMsgBufferSize-1);
		     return RC_SECURID_AUTH_CHALLENGE;
		default:
			radlog(L_ERR,"SecurID: Unexpected error from ACE/Agent API acmRet=%d",acmRet);
			return RC_SECURID_AUTH_FAILURE;
  
			
		}
	} else {
		/* existing session found */
		RDEBUG("Continuing previous session found for user [%s]",username);

		/* continue previous session */
		switch (pSecurid_session->securidSessionState) {
		     case NEXT_CODE_REQUIRED_STATE:
			  DEBUG2("Securid NEXT_CODE_REQUIRED_STATE: User [%s]",username);
			  /* next token code mode */

			  acmRet = SD_Next(pSecurid_session->sdiHandle, (SD_CHAR*)passcode);
			  if (acmRet == ACM_OK) {
				radlog(L_INFO,"Next SecurID token accepted for [%s].",pSecurid_session->identity);
				/* strncpy(replyMsgBuffer,"Next PASSCODE Accepted",replyMsgBufferSize-1);  */
				rc = RC_SECURID_AUTH_SUCCESS;
			  } else {
				radlog(L_INFO,"SecurID: Next token rejected for [%s].",pSecurid_session->identity);

				/* strncpy(replyMsgBuffer,"Next token rejected",replyMsgBufferSize-1); */
				rc = RC_SECURID_AUTH_FAILURE;
			  }
			  /* deallocate session */
			  securid_session_free(inst,request,pSecurid_session);
			  
			  return rc;
		     case NEW_PIN_REQUIRED_STATE:
			  DEBUG2("SecurID NEW_PIN_REQUIRED_STATE: User [%s]",username);

			  /* save the previous pin */
			  if (pSecurid_session->pin) {
				free(pSecurid_session->pin);
				pSecurid_session->pin = NULL;
			  }
			  pSecurid_session->pin = strdup(passcode);

			  strncpy(replyMsgBuffer,"\r\n                 Please re-enter new PIN:",replyMsgBufferSize-1);

			  /* set next state */
			  pSecurid_session->securidSessionState = NEW_PIN_USER_CONFIRM_STATE;

			  /* insert the updated session in the session list */
			  securid_sessionlist_add(inst,request,pSecurid_session);
			  return RC_SECURID_AUTH_CHALLENGE;			   
			  
		     case NEW_PIN_USER_CONFIRM_STATE:
			  DEBUG2("SecurID NEW_PIN_USER_CONFIRM_STATE: User [%s]",username);
			  /* compare previous pin and current pin */
			  if (!pSecurid_session->pin || strcmp(pSecurid_session->pin,passcode)) {
				DEBUG2("Pin confirmation failed. Pins do not match [%s] and [%s]",
					    SAFE_STR(pSecurid_session->pin),
					    passcode);
				/* pins do not match */

				/* challenge the user again */
				strncpy(replyMsgBuffer," \r\nPINs do not match. Please try again.\r\n\r\n   Enter your new PIN, containing 4 to 6 digits,\r\n                or\r\n   <Ctrl-D> to cancel the New PIN procedure: ",replyMsgBufferSize-1);

				pSecurid_session->securidSessionState = NEW_PIN_REQUIRED_STATE;

				/* insert the updated session in the session list */
				securid_sessionlist_add(inst,request,pSecurid_session);
				rc = RC_SECURID_AUTH_CHALLENGE;

			  } else {
				/* pins match */
				DEBUG2("Pin confirmation succeeded. Pins match");
				acmRet = SD_Pin(pSecurid_session->sdiHandle, (SD_CHAR*)passcode);
				if (acmRet == ACM_NEW_PIN_ACCEPTED)
				{
					radlog(L_INFO,"New SecurID pin accepted for [%s].",pSecurid_session->identity);

					pSecurid_session->securidSessionState = NEW_PIN_AUTH_VALIDATE_STATE;

					/* insert the updated session in the session list */
					securid_sessionlist_add(inst,request,pSecurid_session);

					rc = RC_SECURID_AUTH_CHALLENGE;
					strncpy(replyMsgBuffer," \r\n\r\nWait for the code on your card to change, then enter new PIN and TokenCode\r\n\r\nEnter PASSCODE:",replyMsgBufferSize-1);
				} else {
					radlog(L_INFO,"SecurID: New SecurID pin rejected for [%s].",pSecurid_session->identity);
					SD_Pin(pSecurid_session->sdiHandle, (SD_CHAR*)"");  /* cancel PIN */
					

					/* strncpy(replyMsgBuffer,"New PIN Rejected",replyMsgBufferSize-1); */
					rc = RC_SECURID_AUTH_FAILURE;

					/* deallocate session */
					securid_session_free(inst,request,pSecurid_session);

				}
			  }
			  return rc;		  
		     case NEW_PIN_AUTH_VALIDATE_STATE:
				acmRet = SD_Check(pSecurid_session->sdiHandle, (SD_CHAR*)passcode, (SD_CHAR*)username);
				if (acmRet == ACM_OK) {
					radlog(L_INFO,"New SecurID passcode accepted for [%s].",pSecurid_session->identity);

					/* strncpy(replyMsgBuffer,"PASSCODE Accepted",replyMsgBufferSize-1); */
					rc = RC_SECURID_AUTH_SUCCESS;

				} else {
					radlog(L_INFO,"SecurID: New passcode rejected for [%s].",pSecurid_session->identity);

					/* strncpy(replyMsgBuffer,"New PASSCODE Rejected",replyMsgBufferSize-1);  */
					rc = RC_SECURID_AUTH_FAILURE;
				}

				/* deallocate session */
				securid_session_free(inst,request,pSecurid_session);

				return rc;
		     default:
			  radlog(L_ERR|L_CONS, "rlm_securid: Invalid session state %d for user [%s]",
					       pSecurid_session->securidSessionState,
					       username);
			  break;	
		}
	}
	
	return 0;
		
}

/******************************************/
static int securid_detach(void *instance)
{
	rlm_securid_t *inst = (rlm_securid_t *) instance;

	/* delete session tree */
	if (inst->session_tree) {
		rbtree_free(inst->session_tree);
		inst->session_tree = NULL;
	}

	pthread_mutex_destroy(&(inst->session_mutex));

	free(inst);
	return 0;
}


static int securid_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_securid_t *inst;

	/* Set up a storage area for instance data */
	inst = rad_malloc(sizeof(*inst));
	if (!inst)  return -1;
	memset(inst, 0, sizeof(*inst));

        /* If the configuration parameters can't be parsed, then fail. */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		radlog(L_ERR|L_CONS, "rlm_securid: Unable to parse configuration section.");
		securid_detach(inst);
		return -1;
        }

	/*
	 *	Lookup sessions in the tree.  We don't free them in
	 *	the tree, as that's taken care of elsewhere...
	 */
	inst->session_tree = rbtree_create(securid_session_cmp, NULL, 0);
	if (!inst->session_tree) {
		radlog(L_ERR|L_CONS, "rlm_securid: Cannot initialize session tree.");
		securid_detach(inst);
		return -1;
	}

	pthread_mutex_init(&(inst->session_mutex), NULL);

        *instance = inst;
        return 0;
}




/*
 *	Authenticate the user via one of any well-known password.
 */
static int securid_authenticate(void *instance, REQUEST *request)
{
	int rc;
	int   moduleRC;
	rlm_securid_t *inst = instance;
	VALUE_PAIR *module_fmsg_vp;
	VALUE_PAIR *vp_replyPrompt=NULL;
	VALUE_PAIR *vp_replyMessage=NULL;
	char  replyMsgBuffer[MAX_STRING_LEN]="";
	const char *username=NULL, *password=NULL;
	char module_fmsg[MAX_STRING_LEN]="";

	
	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_securid: Attribute \"User-Name\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	if (!request->password) {
		radlog_request(L_AUTH, 0, request, "Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Clear-text passwords are the only ones we support.
	 */
	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog_request(L_AUTH, 0, request, "Attribute \"User-Password\" is required for authentication. Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (request->password->length == 0) {
		snprintf(module_fmsg,sizeof(module_fmsg),"rlm_securid: empty password supplied");
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	shortcuts
	 */
	username = request->username->vp_strvalue;
	password = request->password->vp_strvalue;
	
	RDEBUG("User [%s] login attempt with password [%s]",username,password);
	
	rc = securidAuth(inst,request,username,password,replyMsgBuffer,sizeof(replyMsgBuffer));
	
	switch (rc) {
		case RC_SECURID_AUTH_SUCCESS:
			if (replyMsgBuffer[0] != '\0') {
				/* Generate Reply-Message attribute with reply message data */
				vp_replyMessage = pairmake("Reply-Message", replyMsgBuffer, T_OP_EQ);

				/* make sure message ends with '\0' */
				if (vp_replyMessage->length < (int) sizeof(vp_replyMessage->vp_strvalue)) 
				{
					vp_replyMessage->vp_strvalue[vp_replyMessage->length] = '\0';
					vp_replyMessage->length++;
				}
				pairadd(&request->reply->vps,vp_replyMessage);
		     }

		     moduleRC = RLM_MODULE_OK;
		     break;
		case RC_SECURID_AUTH_CHALLENGE:
		     /* reply with Access-challenge message code (11) */

		     /* Generate Prompt attribute */
		     vp_replyPrompt = paircreate(PW_ATTRIBUTE_NAME_PROMPT , PW_TYPE_INTEGER); /* name="Prompt" */
		     rad_assert(vp_replyPrompt != NULL);
		     vp_replyPrompt->vp_integer = PW_ATTRIBUTE_VALUE_NO_ECHO; /* value=No-Echo 0 */
		     pairadd(&request->reply->vps,vp_replyPrompt);

		     /* Generate Reply-Message attribute with challenge data */
		     vp_replyMessage = pairmake("Reply-Message", replyMsgBuffer, T_OP_EQ);

		     /* make sure message ends with '\0' */
		     if (vp_replyMessage->length < (int) sizeof(vp_replyMessage->vp_strvalue)) {
			vp_replyMessage->vp_strvalue[vp_replyMessage->length] = '\0';
			vp_replyMessage->length++;
		     }

		     pairadd(&request->reply->vps,vp_replyMessage);

		     /* Mark the packet as a Acceess-Challenge Packet */
		     request->reply->code = PW_ACCESS_CHALLENGE;
		     RDEBUG("Sending Access-Challenge.");
		     moduleRC = RLM_MODULE_HANDLED;
		     break;
		case RC_SECURID_AUTH_FAILURE:
		case RC_SECURID_AUTH_ACCESS_DENIED_FAILURE:
		case RC_SECURID_AUTH_INVALID_SERVER_FAILURE:
		default:
			if (replyMsgBuffer[0] != '\0') {
				/* Generate Reply-Message attribute with reply message data */
				vp_replyMessage = pairmake("Reply-Message", replyMsgBuffer, T_OP_EQ);

				/* make sure message ends with '\0' */
				if (vp_replyMessage->length < (int) sizeof(vp_replyMessage->vp_strvalue)) {
					vp_replyMessage->vp_strvalue[vp_replyMessage->length] = '\0';
					vp_replyMessage->length++;
				}
				pairadd(&request->reply->vps,vp_replyMessage);
			}
			moduleRC = RLM_MODULE_REJECT;
			break;
	}

	return moduleRC;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_securid = {
	RLM_MODULE_INIT,
	"securid",
	RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,   	/* type */
	securid_instantiate,		/* instantiation */
	securid_detach,			/* detach */
	{
		securid_authenticate,	/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
