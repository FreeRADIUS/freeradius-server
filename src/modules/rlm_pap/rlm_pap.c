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
#include <ctype.h>

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
#define PAP_ENC_NT		4
#define PAP_ENC_LM		5
#define PAP_ENC_AUTO		6
#define PAP_MAX_ENC		6


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
	char norm_passwd;
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
  { "encryption_scheme", PW_TYPE_STRING_PTR, offsetof(rlm_pap_t,scheme), NULL, "auto" },
  { NULL, -1, 0, NULL, NULL }
};

static const LRAD_NAME_NUMBER schemes[] = {
  { "clear", PAP_ENC_CLEAR },
  { "crypt", PAP_ENC_CRYPT },
  { "md5", PAP_ENC_MD5 },
  { "sha1", PAP_ENC_SHA1 },
  { "nt", PAP_ENC_NT },
  { "lm", PAP_ENC_LM },
  { "auto", PAP_ENC_AUTO },
  { NULL, PAP_ENC_INVALID }
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
	buffer[len * 2] = '\0';
	return;
}

/*
 *	hex2bin converts hexadecimal strings into binary
 */
static int hex2bin (const char *szHex, unsigned char* szBin, int len)
{
	char * c1, * c2;
	int i;

   	for (i = 0; i < len; i++) {
		if( !(c1 = memchr(pap_hextab, tolower((int) szHex[i << 1]), 16)) ||
		    !(c2 = memchr(pap_hextab, tolower((int) szHex[(i << 1) + 1]), 16)))
		     break;
                 szBin[i] = ((c1-pap_hextab)<<4) + (c2-pap_hextab);
        }

        return i;
}


static int pap_detach(void *instance)
{
	rlm_pap_t *inst = (rlm_pap_t *) instance;

	if (inst->scheme) free((char *)inst->scheme);
	free(inst);

	return 0;
}


static int pap_instantiate(CONF_SECTION *conf, void **instance)
{
        rlm_pap_t *inst;

        /*
         *      Set up a storage area for instance data
         */
        inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

        /*
         *      If the configuration parameters can't be parsed, then
         *      fail.
         */
        if (cf_section_parse(conf, inst, module_config) < 0) {
		pap_detach(inst);
                return -1;
        }
	if (inst->scheme == NULL || strlen(inst->scheme) == 0){
		radlog(L_ERR, "rlm_pap: No scheme defined");
		pap_detach(inst);
		return -1;
	}

	inst->sch = lrad_str2int(schemes, inst->scheme, PAP_ENC_INVALID);
	if (inst->sch == PAP_ENC_INVALID) {
		radlog(L_ERR, "rlm_pap: Unknown scheme \"%s\"", inst->scheme);
		pap_detach(inst);
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
	rlm_pap_t *inst = instance;
	VALUE_PAIR *vp;
	VALUE_PAIR *module_fmsg_vp;
	char module_fmsg[MAX_STRING_LEN];
	MD5_CTX md5_context;
	SHA1_CTX sha1_context;
	char digest[40];
	char buff[MAX_STRING_LEN];
	char buff2[MAX_STRING_LEN + 50];
	int scheme = PAP_ENC_INVALID;

	/* quiet the compiler */
	instance = instance;
	request = request;

	if (!request->password){
		radlog(L_AUTH, "rlm_pap: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Clear-text passwords are the only ones we support.
	 */
	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "rlm_pap: Attribute \"User-Password\" is required for authentication. Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (request->password->length == 0) {
		snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: empty password supplied");
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_INVALID;
	}

	DEBUG("rlm_pap: login attempt with password %s",
	      request->password->strvalue);

	/*
	 *	First, auto-detect passwords, by attribute in the
	 *	config items.
	 */
	if (inst->sch == PAP_ENC_AUTO) {
		for (vp = request->config_items; vp != NULL; vp = vp->next) {
			switch (vp->attribute) {
			case PW_USER_PASSWORD:
				goto do_clear;
				
			case PW_CRYPT_PASSWORD:
				goto do_crypt;
				
				
			case PW_MD5_PASSWORD:
				goto do_md5;
				
			case PW_SHA_PASSWORD:
				goto do_sha;
				
			case PW_NT_PASSWORD:
				goto do_nt;

			case PW_LM_PASSWORD:
				goto do_lm;

			default:
				break;	/* ignore it */
				
			}
		}

	fail:
		DEBUG("rlm_pap: No password configured for the user.  Cannot do authentication");
		return RLM_MODULE_FAIL;

	} else {
		vp = NULL;
		
		if (inst->sch == PAP_ENC_CRYPT) {
			vp = pairfind(request->config_items, PW_CRYPT_PASSWORD);
		}

		/*
		 *	Old-style: all passwords are in User-Password.
		 */
		if (!vp) {
			vp = pairfind(request->config_items, PW_USER_PASSWORD);
			if (!vp) goto fail;
		}
	}

	/*
	 *	Now that we've decided what to do, go do it.
	 */
	switch (scheme) {
	case PAP_ENC_CLEAR:
	do_clear:
		DEBUG("rlm_pap: Using clear text password.");
		if (strcmp((char *) vp->strvalue,
			   (char *) request->password->strvalue) != 0){
			DEBUG("rlm_pap: Passwords don't match");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: CLEAR TEXT password check failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
	done:
		DEBUG("rlm_pap: User authenticated succesfully");
		return RLM_MODULE_OK;
		break;
		
	case PAP_ENC_CRYPT:
	do_crypt:
		DEBUG("rlm_pap: Using CRYPT encryption.");
		if (lrad_crypt_check((char *) request->password->strvalue,
				     (char *) vp->strvalue) != 0) {
			DEBUG("rlm_pap: Passwords don't match");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: CRYPT password check failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		goto done;
		break;
		
	case PW_MD5_PASSWORD:
	do_md5:
		DEBUG("rlm_pap: Using MD5 encryption.");

		if (vp->length != 32) {
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
		if (strcasecmp((char *)vp->strvalue, buff) != 0){
			DEBUG("rlm_pap: Passwords don't match");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: MD5 password check failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		goto done;
		break;
		
	case PW_SHA_PASSWORD:
	do_sha:
		DEBUG("rlm_pap: Using SHA1 encryption.");
		
		if (vp->length != 40) {
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
		if (strcasecmp((char *)vp->strvalue, buff) != 0){
			DEBUG("rlm_pap: Passwords don't match");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: SHA1 password check failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		goto done;
		break;
		
	case PW_NT_PASSWORD:
	do_nt:
		DEBUG("rlm_pap: Using NT encryption.");

		if  (vp->length == 32) {
			vp->length = hex2bin(vp->strvalue, vp->strvalue, 16);
		}
		if (vp->length != 16) {
			DEBUG("rlm_pap: Configured NT-Password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured NT-Password has incorrect length");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		
		sprintf(buff2,"%%{mschap:NT-Hash %s}",request->password->strvalue);
		if (!radius_xlat(digest,sizeof(digest),buff2,request,NULL)){
			DEBUG("rlm_pap: mschap xlat failed");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: mschap xlat failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		pap_hexify(buff,vp->strvalue,16);
		DEBUG("rlm_pap: Encrypted password: %s", digest);
		if (strcasecmp(buff, digest) != 0){
			DEBUG("rlm_pap: Passwords don't match");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: NT password check failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				return RLM_MODULE_REJECT;
		}
		goto done;
		break;
		
	case PW_LM_PASSWORD:
	do_lm:
		DEBUG("rlm_pap: Using LM encryption.");
		
		if  (vp->length == 32) {
			vp->length = hex2bin(vp->strvalue, vp->strvalue, 16);
		}
		if (vp->length != 16) {
			DEBUG("rlm_pap: Configured LM-Password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured LM-Password has incorrect length");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		sprintf(buff2,"%%{mschap:LM-Hash %s}",request->password->strvalue);
		if (!radius_xlat(digest,sizeof(digest),buff2,request,NULL)){
			DEBUG("rlm_pap: mschap xlat failed");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: mschap xlat failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		pap_hexify(buff,vp->strvalue,16);
		DEBUG("rlm_pap: Encrypted password: %s",buff);
		if (strcasecmp(buff, digest) != 0){
			DEBUG("rlm_pap: Passwords don't match");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: LM password check failed");
			module_fmsg_vp = pairmake("Module-Failure-Message",module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		goto done;
		break;

	default:
		break;
	}

	DEBUG("rlm_pap: No password configured for the user.  Cannot do authentication");
	return RLM_MODULE_FAIL;
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
