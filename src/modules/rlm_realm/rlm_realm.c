/*
 * rlm_realm.c	
 *
 * Version:	$Id$
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
 * Copyright 2000  The FreeRADIUS server project
 * FIXME add copyrights
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libradius.h"
#include "radiusd.h"
#include "modules.h"

static const char rcsid[] = "$Id$";

#define  REALM_FORMAT_PREFIX   0
#define  REALM_FORMAT_SUFFIX   1

typedef struct realm_config_t {
        int        format;
        char       *formatstring;
        char       *delim;
} realm_config_t;

static realm_config_t config;

static CONF_PARSER module_config[] = {
  { "format", PW_TYPE_STRING_PTR, &config.formatstring, "suffix" },
  { "delimiter", PW_TYPE_STRING_PTR, &config.delim, "@" },
  { NULL, -1, NULL, NULL }    /* end the list */
};

/*
 *	Internal function to cut down on duplicated code.
 *
 *	Returns NULL on don't proxy, realm otherwise.
 */
static REALM *check_for_realm(void *instance, REQUEST *request)
{
	char namebuf[MAX_STRING_LEN];
	char *username;
	char *realmname = (char *)NULL;
	char *ptr;
	VALUE_PAIR *vp;
	REALM *realm;

        struct realm_config_t *inst = instance;

	namebuf[0] = '\0';
	username = namebuf;

	/*
	 *	If the request has a proxy entry, then it's a proxy
	 *	reply, and we're walking through the module list again.
	 *
	 *	In that case, don't bother trying to proxy the request
	 *	again.
	 *
	 *	Also, if there's no User-Name attribute, we can't
	 *	proxy it, either.
	 */
	if ((request->proxy != NULL) ||
	    (request->username == NULL)) {
		return NULL;
	}

	strncpy(namebuf, request->username->strvalue, MAX_STRING_LEN-1);

	switch(inst->format)
	{

	case REALM_FORMAT_SUFFIX:
	  
	  /* DEBUG2("  rlm_realm: Checking for suffix after \"%c\"", inst->delim[0]); */

		realmname = strchr(username, inst->delim[0]);		
		if (realmname) {
			*realmname = '\0';
			realmname++;
		}
		break;
		
	case REALM_FORMAT_PREFIX:
		
		/* DEBUG2("  rlm_realm: Checking for prefix before \"%c\"", inst->delim[0]); */
		
		ptr = strchr(username, inst->delim[0]);
		if (ptr) {
			*ptr = '\0';
		     ptr++;
		     realmname = username;
		     username = ptr;	
		}
		break;
	       
	default:
		realmname = NULL;
		break;
	}

	/*
	 *	Allow NULL realms.
	 */
	realm = realm_find(realmname);
	if (!realm) {
		return NULL;
	}
	
	/* make sure it's proxyable realm */
	if (realm->notrealm) {
		return NULL;
	}

	DEBUG2("  rlm_realm: Proxying request from user %s to realm %s",
	       username, realm->realm);

	/*
	 *	If we've been told to strip the realm off, then do so.
	 */
	if (realm->striprealm) {
		/*
		 *	Create the Stripped-User-Name attribute, if it
		 *	doesn't exist.
		 *
		 */
		vp = pairfind(request->packet->vps, PW_STRIPPED_USER_NAME);
		if (!vp) {
			vp = paircreate(PW_STRIPPED_USER_NAME, PW_TYPE_STRING);
			if (!vp) {
				radlog(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			strcpy(vp->strvalue, username);
			vp->length = strlen((char *)vp->strvalue);
			pairadd(&request->packet->vps, vp);
			request->username = vp;
		}
	}

	/*
	 *	Don't add a 'Realm' attribute, proxy.c does
	 *	that for us.
	 */

	/*
	 *	Perhaps accounting proxying was turned off.
	 */
	if ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
	    (realm->acct_port == 0)) {
		/* log a warning that the packet isn't getting proxied ??? */
		DEBUG2("rlm_realm:  acct_port is not set.  proxy cancelled");
		return NULL;
	}

	/*
	 *	Perhaps authentication proxying was turned off.
	 */
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    (realm->auth_port == 0)) {
		/* log a warning that the packet isn't getting proxied ??? */
		DEBUG2("rlm_realm:  auth_port is not set.  proxy cancelled");
		return NULL;
	}


	return realm;
}

/*
 *	Maybe add a "Proxy-To-Realm" attribute to the request.
 *
 *	If it's a LOCAL realm, then don't bother.
 */
static void add_proxy_to_realm(VALUE_PAIR **vps, REALM *realm)
{
	VALUE_PAIR *vp;

	/*
	 *	If it's the LOCAL realm, we do NOT proxy it, but
	 *	we DO strip the User-Name, if told to do so.
	 */
	if (strcmp(realm->server, "LOCAL") == 0) {
		return;
	}

	/*
	 *	Tell the server to proxy this request to another
	 *	realm.
	 */
	vp = pairmake("Proxy-To-Realm", realm->realm, T_OP_EQ);
	if (!vp) {
		radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	
	/*
	 *  Add it, even if it's already present.
	 */
	pairadd(vps, vp);
}

/*
 *  Perform the realm module instantiation.  Configuration info is
 *  stored in *instance for later use.
 */

static int realm_instantiate(CONF_SECTION *conf, void **instance)
{
        struct realm_config_t *inst;

        /* setup a storage area for instance data */
        inst = malloc(sizeof(struct realm_config_t));
        if(!inst) {
               radlog(L_ERR|L_CONS, "Out of memory\n");
	       return -1;
	}

	if(cf_section_parse(conf, module_config) < 0) {
	       free(inst);
               return -1;
	}

        /* copy the configuration info into the instance data */

	if(strcasecmp(config.formatstring, "suffix") == 0) {
	     inst->format = REALM_FORMAT_SUFFIX;
	} else if(strcasecmp(config.formatstring, "prefix") == 0) {
	     inst->format = REALM_FORMAT_PREFIX;
        } else {
	     radlog(L_ERR, "Bad value \"%s\" for realm format value", config.formatstring);
	     free(inst);
	     return -1;
	}
	if(strlen(config.delim) != 1) {
	     radlog(L_ERR, "Bad value \"%s\" for realm delimiter value", config.delim);
	     free(inst);
	     return -1;
	}
	inst->delim = config.delim;

	/* set these to NULL to prevent other instances from reusing the data */

	config.formatstring = NULL;
	config.delim = NULL;

	*instance = inst;
	return 0;

}



 

/*
 *  Examine a request for a username with an realm, and if it
 *  corresponds to something in the realms file, set that realm as
 *  Proxy-To.
 *
 *  This should very nearly duplicate the old proxy_send() code
 */
static int realm_authorize(void *instance, REQUEST *request)
{
	REALM *realm;

	/*
	 *	Check if we've got to proxy the request.
	 *	If not, return without adding a Proxy-To-Realm
	 *	attribute.
	 */
	realm = check_for_realm(instance, request);
	if (!realm) {
		return RLM_MODULE_OK;
	}

	/*
	 *	Maybe add a Proxy-To-Realm attribute to the request.
	 */
	add_proxy_to_realm(&request->config_items, realm);

	return RLM_MODULE_UPDATED; /* try the next module */
}

/*
 * This does the exact same thing as the realm_authorize, it's just called
 * differently.
 */
static int realm_preacct(void *instance, REQUEST *request)
{
	const char *name = (char *)request->username->strvalue;
	REALM *realm;

	if (!name)
	  return RLM_MODULE_OK;
	

	/*
	 *	Check if we've got to proxy the request.
	 *	If not, return without adding a Proxy-To-Realm
	 *	attribute.
	 */
	realm = check_for_realm(instance, request);
	if (!realm) {
		return RLM_MODULE_OK;
	}


	/*
	 *	Maybe add a Proxy-To-Realm attribute to the request.
	 */
	add_proxy_to_realm(&request->config_items, realm);

	return RLM_MODULE_OK; /* try the next module */
}

/* globally exported name */
module_t rlm_realm = {
  "realm",
  0,				/* type: reserved */
  NULL,				/* initialization */
  realm_instantiate,	       	/* instantiation */
  realm_authorize,		/* authorization */
  NULL,				/* authentication */
  realm_preacct,		/* preaccounting */
  NULL,				/* accounting */
  NULL,				/* checksimul */
  NULL,				/* detach */
  NULL,				/* destroy */
};
