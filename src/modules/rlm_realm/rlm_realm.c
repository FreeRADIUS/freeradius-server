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
  const char *realmname;
  VALUE_PAIR *vp;
  REALM *realm;
  const char *name = request->username->strvalue;

  reply_pairs = reply_pairs; /* -Wunused */

  if ((realmname = strrchr(name, '@')) != NULL)
    realmname++;
  if ((realm = realm_find(realmname ? realmname : "NULL")) == NULL)
    return RLM_AUTZ_NOTFOUND;

  if (realm->notsuffix)
    return RLM_AUTZ_NOTFOUND;

  vp = pairmake("Proxy-To-Realm", realmname, T_OP_EQ);
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
  vp = pairmake("Realm", realmname, T_OP_EQ);
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
  const char *name=request->username->strvalue;
  const char *realmname;
  VALUE_PAIR *vp;
  REALM *realm;

  if(!name)
    return RLM_PRAC_OK;

  if ((realmname = strrchr(name, '@')) != NULL)
    realmname++;

  if ((realm = realm_find(realmname ? realmname : "NULL")) == NULL)
    return RLM_PRAC_OK;

  vp = pairmake("Proxy-To-Realm", realmname, T_OP_EQ);
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
  vp = pairmake("Realm", realmname, T_OP_EQ);
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
