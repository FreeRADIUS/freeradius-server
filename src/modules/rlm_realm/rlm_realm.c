#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libradius.h"
#include "radiusd.h"
#include "modules.h"

static const char rcsid[] = "$Id$";

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
	char *realmname;
	VALUE_PAIR *vp;
	REALM *realm;
	const char *name = request->username->strvalue;

	/*
	 *	If the request has a proxy entry, then it's a proxy
	 *	reply, and we're walking through the module list again.
	 *
	 *	In that case, don't bother trying to proxy the request
	 *	again.
	 */
	if (request->proxy != NULL) {
		return RLM_AUTZ_NOTFOUND;
	}
	
	reply_pairs = reply_pairs; /* -Wunused */
	
	/*
	 *	Find realms from the END, so that 'joe@realm1@realm2'
	 *	can work.
	 */
	realmname = strrchr(name, '@');
	if (realmname != NULL)
		realmname++;

	realm = realm_find(realmname);
	if (realm == NULL)
	  return RLM_AUTZ_NOTFOUND;
	
	if (realm->notsuffix)
	  return RLM_AUTZ_NOTFOUND;
	
	DEBUG2("  rlm_realm: Proxying request from user %s to realm %s",
	       name, realm->realm);

	/*
	 *	Create the Stripped-User-Name attribute, if it doesn't exist.
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
	*realmname = '\0';
	vp->length = strlen(vp->strvalue);

	/*
	 *  'realmname' may be NULL, while realm->realm isn't.
	 */
	vp = pairmake("Proxy-To-Realm", realm->realm, T_OP_EQ);
	if (!vp) {
	  log(L_ERR|L_CONS, "no memory");
	  exit(1);
	}
	
	/*
	 *  Add it, even if it's already present.
	 */
	pairadd(check_pairs, vp);
	
	/*
	 *  Add a 'realm' attribute to the incoming request.
	 */
	vp = pairmake("Realm", realm->realm, T_OP_EQ);
	if (!vp) {
	  log(L_ERR|L_CONS, "no memory");
	  exit(1);
	}
	pairadd(&request->packet->vps, vp);
	
	return RLM_AUTZ_NOTFOUND; /* try the next module */
}

/*
 * This does the exact same thing as the realm_authorize, it's just called
 * differently.
 */
static int realm_preacct(REQUEST *request)
{
	const char *name = request->username->strvalue;
	char *realmname;
	VALUE_PAIR *vp;
	REALM *realm;
	
	if (!name)
	  return RLM_PRAC_OK;
	
	/*
	 *	If the request has a proxy entry, then it's a proxy
	 *	reply, and we're walking through the module list again.
	 *
	 *	In that case, don't bother trying to proxy the request
	 *	again.
	 */
	if (request->proxy != NULL) {
		return RLM_PRAC_OK;
	}

	realmname = strrchr(name, '@');
	if (realmname != NULL)
	  realmname++;
	
	realm = realm_find(realmname);
	if (realm == NULL)
	  return RLM_PRAC_OK;

	DEBUG2("  rlm_realm: Proxying request from user %s to realm %s",
	       name, realm->realm);

	/*
	 *	Create the Stripped-User-Name attribute, if it doesn't exist.
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
	*realmname = '\0';
	vp->length = strlen(vp->strvalue);

	/*
	 *  'realmname' may be NULL, while realm->realm isn't.
	 */
	vp = pairmake("Proxy-To-Realm", realm->realm, T_OP_EQ);
	if (!vp) {
	  log(L_ERR|L_CONS, "no memory");
	  exit(1);
	}
	
	/*
	 *  Add it, even if it's already present.
	 */
	pairadd(&request->config_items, vp);
	
	/*
	 *  Add a 'realm' attribute to the incoming request.
	 */
	vp = pairmake("Realm", realm->realm, T_OP_EQ);
	if (!vp) {
	  log(L_ERR|L_CONS, "no memory");
	  exit(1);
	}
	pairadd(&request->packet->vps, vp);
	return RLM_PRAC_OK; /* try the next module */
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
