/*
 * rlm_pap.c
 *
 * Version:  $Id$
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
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#include "../../include/md5.h"
#include "../../include/sha1.h"

#define PAP_ENC_INVALID	-1
#define PAP_ENC_CLEAR		0
#define PAP_ENC_CRYPT		1
#define PAP_ENC_MD5		2
#define PAP_ENC_SHA1		3
#define PAP_MAX_ENC		3

#define PAP_INST_FREE(inst) \
	free((char *)inst->scheme); \
	free(inst)

static const char rcsid[] = "$Id$";

/*
 *      Define a structure for our module configuration.
 *
 *      These variables do not need to be in a structure, but it's
 *      a lot cleaner to do so, and a pointer to the structure can
 *      be used as the instance handle.
 */
typedef struct rlm_pap_t {
        char *scheme;  /* password encryption scheme */
	int sch;
} rlm_pap_t;

/*
 *      A mapping of configuration file names to internal variables.
 *
 *      Note that the string is dynamically allocated, so it MUST
 *      be freed.  When the configuration file parse re-reads the string,
 *      it free's the old one, and strdup's the new one, placing the pointer
 *      to the strdup'd string into 'config.string'.  This gets around
 *      buffer over-flows.
 */
static CONF_PARSER module_config[] = {
  { "encryption_scheme", PW_TYPE_STRING_PTR, offsetof(rlm_pap_t,scheme), NULL, "crypt" },
  { NULL, -1, 0, NULL, NULL }
};

static const char *pap_hextab = "0123456789abcdef";

/*
 *  Smaller & faster than snprintf("%x");
 *  Completely stolen from ns_mta_md5 module
 */
static void pap_hexify(char *buffer, char *str, int len)
{
	char *pch = str;
	char ch;
	int i;
	
	for(i = 0;i < len; i ++) {
		ch = pch[i];
		buffer[2*i] = pap_hextab[(ch>>4) & 15];
		buffer[2*i + 1] = pap_hextab[ch & 15];
	}
	return;
}

static int pap_instantiate(CONF_SECTION *conf, void **instance)
{
        rlm_pap_t *inst;

        /*
         *      Set up a storage area for instance data
         */
        inst = rad_malloc(sizeof(*inst));

        /*
         *      If the configuration parameters can't be parsed, then
         *      fail.
         */
        if (cf_section_parse(conf, inst, module_config) < 0) {
                free(inst);
                return -1;
        }
	inst->sch = PAP_ENC_INVALID;
	if (inst->scheme == NULL || strlen(inst->scheme) == 0){
		radlog(L_ERR, "rlm_pap: Wrong password scheme passed");
		PAP_INST_FREE(inst);
		return -1;
	}
	if (strcasecmp(inst->scheme,"clear") == 0)
		inst->sch = PAP_ENC_CLEAR;
	else if (strcasecmp(inst->scheme,"crypt") == 0){
		inst->sch = PAP_ENC_CRYPT;
	}
	else if (strcasecmp(inst->scheme,"md5") == 0)
		inst->sch = PAP_ENC_MD5;
	else if (strcasecmp(inst->scheme,"sha1") == 0)
		inst->sch = PAP_ENC_SHA1;
	else{
		radlog(L_ERR, "rlm_pap: Wrong password scheme passed");
		PAP_INST_FREE(inst);
		return -1;
	}

        *instance = inst;

        return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int pap_authenticate(void *instance, REQUEST *request)
{
	VALUE_PAIR *passwd_item;
	VALUE_PAIR *module_fmsg_vp;
	char module_fmsg[MAX_STRING_LEN];
	MD5_CTX md5_context;
	SHA1_CTX sha1_context;
	char digest[20];
	char buff[MAX_STRING_LEN];
	rlm_pap_t *inst = (rlm_pap_t *) instance;

	/* quiet the compiler */
	instance = instance;
	request = request;

	if(!request->username){
		radlog(L_AUTH, "rlm_pap: Attribute \"User-Name\" is required for authentication.\n");
		return RLM_MODULE_INVALID;
	}

	if (!request->password){
		radlog(L_AUTH, "rlm_pap: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_pap: Attribute \"Password\" is required for authentication. Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	if (request->password->length == 0) {
		radlog(L_ERR, "rlm_pap: empty password supplied");
		return RLM_MODULE_INVALID;
	}

	DEBUG("rlm_pap: login attempt by \"%s\" with password %s", 
		request->username->strvalue, request->password->strvalue);

	if (((passwd_item = pairfind(request->config_items, PW_PASSWORD)) == NULL) ||
	    (passwd_item->length == 0) || (passwd_item->strvalue[0] == 0)) {
		DEBUG("rlm_pap: No password (or empty password) to check against for for user %s",request->username->strvalue);
		snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: User password not available");
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_INVALID;
	}

	DEBUG("rlm_pap: Using password \"%s\" for user %s authentication.",
	      passwd_item->strvalue, request->username->strvalue);
	
	if (inst->sch == PAP_ENC_INVALID || inst->sch > PAP_MAX_ENC){
		radlog(L_ERR, "rlm_pap: Wrong password scheme");
		return RLM_MODULE_FAIL;
	}
	switch(inst->sch){
		default:
			radlog(L_ERR, "rlm_pap: Wrong password scheme");
			return RLM_MODULE_FAIL;
			break;
		case PAP_ENC_CLEAR:
			DEBUG("rlm_pap: Using clear text password.");
			if (strcmp((char *) passwd_item->strvalue,
				   (char *) request->password->strvalue) != 0){
				DEBUG("rlm_pap: Passwords don't match");
				snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: CLEAR TEXT password check failed");
				module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
			}
			break;
		case PAP_ENC_CRYPT:
			DEBUG("rlm_pap: Using CRYPT encryption.");
			if (lrad_crypt_check((char *) request->password->strvalue,
								 (char *) passwd_item->strvalue) != 0) {
				DEBUG("rlm_pap: Passwords don't match");
				snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: CRYPT password check failed");
				module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
			}
			break;
		case PAP_ENC_MD5:
			DEBUG("rlm_pap: Using MD5 encryption.");

			if (passwd_item->length != 32) {
				DEBUG("rlm_pap: Configured MD5 password has incorrect length");
				snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured MD5 password has incorrect length");
				module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
			}

			MD5Init(&md5_context);
			MD5Update(&md5_context, request->password->strvalue, request->password->length);
			MD5Final(digest, &md5_context);
			pap_hexify(buff,digest,16);
			buff[32] = '\0';
			if (strcmp((char *)passwd_item->strvalue, buff) != 0){
				DEBUG("rlm_pap: Passwords don't match");
				snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: MD5 password check failed");
				module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
			}
			break;
		case PAP_ENC_SHA1:

			DEBUG("rlm_pap: Using SHA1 encryption.");

			if (passwd_item->length != 40) {
				DEBUG("rlm_pap: Configured SHA1 password has incorrect length");
				snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured SHA1 password has incorrect length");
				module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
			}

			SHA1Init(&sha1_context);
			SHA1Update(&sha1_context, request->password->strvalue, request->password->length);
			SHA1Final(digest,&sha1_context);
			pap_hexify(buff,digest,20);
			buff[40] = '\0';
			if (strcmp((char *)passwd_item->strvalue, buff) != 0){
				DEBUG("rlm_pap: Passwords don't match");
				snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: SHA1 password check failed");
				module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
			}
			break;
	}

	DEBUG("rlm_pap: User authenticated succesfully");

	return RLM_MODULE_OK;
}

static int pap_detach(void *instance)
{
	rlm_pap_t *inst = (rlm_pap_t *) instance;

	PAP_INST_FREE(inst);
	return 0;
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
module_t rlm_pap = {
	"PAP",	
	0,				/* type */
	NULL,				/* initialization */
	pap_instantiate,		/* instantiation */
	{
		pap_authenticate,	/* authentication */
		NULL,		 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
	pap_detach,			/* detach */
	NULL,				/* destroy */
};
