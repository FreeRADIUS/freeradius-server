#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libradius.h"
#include "radiusd.h"
#include "modules.h"

static const char rcsid[] = "$Id$";


/*
 *	Internal function to cut down on duplicated code.
 *
 *	Returns NULL on don't proxy, realm otherwise.
 */
static REALM *check_for_realm(REQUEST *request)
{
	const char *name;
	char *realmname;
	VALUE_PAIR *vp;
	REALM *realm;

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

	name = request->username->strvalue;
	realmname = strrchr(name, '@');
	if (realmname != NULL)
	  realmname++;
	
	realm = realm_find(realmname);
	if (realm == NULL)
	  return NULL;

	DEBUG2("  rlm_realm: Proxying request from user %s to realm %s",
	       name, realm->realm);

	/*
	 *	If we've been told to strip the realm off, then do so.
	 */
	if (realm->striprealm) {
		/*
		 *	Create the Stripped-User-Name attribute, if it
		 *	doesn't exist.
		 *
		 *	This code is copied from rlm_preprocess.
		 */
		vp = pairfind(request->packet->vps, PW_STRIPPED_USER_NAME);
		if (!vp) {
			vp = paircreate(PW_STRIPPED_USER_NAME, PW_TYPE_STRING);
			if (!vp) {
				log(L_ERR|L_CONS, "no memory");
				exit(1);
			}
			strcpy(vp->strvalue, name);
			vp->length = strlen(vp->strvalue);
			pairadd(&request->packet->vps, vp);
			request->username = vp;
		}
		
		/*
		 *	Let's strip the Stripped-User-Name attribute.
		 */
		realmname = strrchr(vp->strvalue, '@');
		if (realmname != NULL) {
			*realmname = '\0';
			vp->length = strlen(vp->strvalue);
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
		return NULL;
	}

	/*
	 *	Perhaps authentication proxying was turned off.
	 */
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    (realm->auth_port == 0)) {
		/* log a warning that the packet isn't getting proxied ??? */
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
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	
	/*
	 *  Add it, even if it's already present.
	 */
	pairadd(vps, vp);
}

/*
 *  Examine a request for a username with an @suffix, and if it
 *  corresponds to something in the realms file, set that realm as
 *  Proxy-To.
 *
 *  This should very nearly duplicate the old proxy_send() code
 */
static int realm_authorize(REQUEST *request,
			   VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	REALM *realm;

	reply_pairs = reply_pairs; /* -Wunused */
	
	/*
	 *	Check if we've got to proxy the request.
	 *	If not, return without adding a Proxy-To-Realm
	 *	attribute.
	 */
	realm = check_for_realm(request);
	if (!realm) {
		return RLM_MODULE_OK;
	}

	/*
	 *	Maybe add a Proxy-To-Realm attribute to the request.
	 */
	add_proxy_to_realm(check_pairs, realm);

	return RLM_MODULE_OK; /* try the next module */
}

/*
 * This does the exact same thing as the realm_authorize, it's just called
 * differently.
 */
static int realm_preacct(REQUEST *request)
{
	const char *name = request->username->strvalue;
	REALM *realm;
	
	if (!name)
	  return RLM_MODULE_OK;
	

	/*
	 *	Check if we've got to proxy the request.
	 *	If not, return without adding a Proxy-To-Realm
	 *	attribute.
	 */
	realm = check_for_realm(request);
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
  "Realm",
  0,				/* type: reserved */
  NULL,				/* initialization */
  realm_authorize,		/* authorization */
  NULL,				/* authentication */
  realm_preacct,		/* preaccounting */
  NULL,				/* accounting */
  NULL,				/* detach */
};
