#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libradius.h"
#include "radiusd.h"
#include "modules.h"

/* Examine a request for a username with an @suffix, and if it corresponds
 * to something in the realms file, set that realm as Proxy-To.
 *
 * This should very nearly duplicate the old proxy_send() code */
static int realm_authorize(REQUEST *request,
			   VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
  const char *realmname;
  VALUE_PAIR *proxypair;
  REALM *realm;
  const char *name=request->username->strvalue;

  reply_pairs = reply_pairs; /* -Wunused */

  if ((realmname = strrchr(name, '@')) != NULL)
    realmname++;
  if ((realm = realm_find(realmname ? realmname : "NULL")) == NULL)
    return RLM_AUTZ_NOTFOUND;

  if(realm->notsuffix)
    return RLM_AUTZ_NOTFOUND;

  if(!(proxypair=paircreate(PW_PROXY_TO_REALM, PW_TYPE_STRING))) {
    log(L_ERR|L_CONS, "no memory");
    exit(1);
  }
  strNcpy(proxypair->strvalue, realmname, sizeof proxypair->strvalue);
  proxypair->length=strlen(proxypair->strvalue);
  proxypair->operator=T_OP_SET;
  proxypair->next=0;
  pairmove(check_pairs, &proxypair);

  return RLM_AUTZ_NOTFOUND; /* try the next module */
}

/* This does the exact same thing as the realm_authorize, it's just called
 * differently. */
static int realm_preacct(REQUEST *request)
{
  const char *name=request->username->strvalue;
  const char *realmname;
  VALUE_PAIR *proxypair;
  REALM *realm;

  if(!name)
    return RLM_PRAC_OK;

  if ((realmname = strrchr(name, '@')) != NULL)
    realmname++;
  if ((realm = realm_find(realmname ? realmname : "NULL")) == NULL)
    return RLM_PRAC_OK;

  if(!(proxypair=paircreate(PW_PROXY_TO_REALM, PW_TYPE_STRING))) {
    log(L_ERR|L_CONS, "no memory");
    exit(1);
  }
  strNcpy(proxypair->strvalue, realmname, sizeof proxypair->strvalue);
  proxypair->length=strlen(proxypair->strvalue);
  proxypair->operator=T_OP_SET;
  proxypair->next=0;
  pairmove(&request->config_items, &proxypair);

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
