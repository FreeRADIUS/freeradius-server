/*
 * rlm_ns_mta_md5 Functions to authenticate using NS-MTA-MD5 passwords.
 *		Taken from the hacks for qmail located at nrg4u.com
 *		by Andre Oppermann.
 *
 *   NS-MTA-MD5 passwords are 64 byte strings, the first  
 *   32 bytes being the password hash and the last 32 bytes 
 *   the salt.  The clear text password and the salt are MD5 
 *   hashed[1].  If the resulting hash concatenated with the salt
 *   are equivalent to the original NS-MTA-MD5 password the 
 *   password is correct. 
 *
 *   [1] Read the source for details.
 *
 *  Version:	$Id$
 *
 * bob Auth-Type := NS-MTA-MD5, NS-MTA-MD5-Password := "f8b4eac9f051a61eebe266f9c29a193626d8eb25c2598c55c8874260b24eb435"
 *     Reply-Message = "NS-MTA-MD5 is working!"
 *
 * password = "testpass".
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "md5.h"

#define HASH_LEN 100

static const char *ns_mta_hextab = "0123456789abcdef";

/*
 *  Smaller & faster than snprintf("%x");
 */
static void ns_mta_hexify(char *buffer, char *str, int len)
{
  char *pch = str;
  char ch;
  int i;

  for(i = 0;i < len; i ++) {
    ch = pch[i];
    buffer[2*i] = ns_mta_hextab[(ch>>4) & 15];
    buffer[2*i + 1] = ns_mta_hextab[ch & 15];
  }
  return;
}

/*
 *	Do the hash.
 */
static char *ns_mta_hash_alg(char *buffer, const char *salt, const char *passwd)
{
  MD5_CTX context;
  char saltstr[2048];
  unsigned char digest[16];

  snprintf(saltstr, sizeof(saltstr), "%s%c%s%c%s",salt, 89, passwd, 247, salt);

  MD5Init(&context);
  MD5Update(&context,(unsigned char *)saltstr,strlen(saltstr));
  MD5Final(digest,&context);
  ns_mta_hexify(buffer,(char*)digest,16);
  buffer[32] = '\0';
  return(buffer);
}

/*
 *  Take the clear
 */
static int ns_mta_md5_pass(const char *clear, const char *encrypted)
{
  char hashed[HASH_LEN];
  char salt[33];

  if (!strlen(encrypted) == 64) {
    DEBUG2("NS-MTA-MD5 hash not 64 bytes");
    return -1;
  }

  memcpy(salt, &encrypted[32], 32);
  salt[32] = 0;
  ns_mta_hash_alg(hashed, salt, clear);
  memcpy(&hashed[32], salt, 33);

  if (strcasecmp(hashed,encrypted) == 0) {
    return 0;
  }

  return -1;
}

/*
 *  Validate User-Name / Passwd
 */
static int module_auth(void *instance, REQUEST *request)
{
	VALUE_PAIR *md5_password;
	
	/*
	 *	We can only authenticate user requests which HAVE
	 *	a Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_ns_m5a_md5: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_ns_mta_md5: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Find the MD5 encrypted password
	 */
	md5_password = pairfind(request->config_items, PW_NS_MTA_MD5_PASSWORD);
	if (!md5_password) {
		radlog(L_AUTH, "rlm_ns_mta_md5: Cannot find NS-MTA-MD5-Password attribute.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Check their password against the encrypted one.
	 */
	if (ns_mta_md5_pass(request->password->strvalue,
			    md5_password->strvalue) < 0) {
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

module_t rlm_ns_mta_md5 = {
  "NS-MTA-MD5",
  0,				/* type: reserved */
  NULL,				/* initialize */
  NULL,				/* instantiation */
  NULL,				/* authorize */
  module_auth,			/* authenticate */
  NULL,				/* pre-accounting */
  NULL,				/* accounting */
  NULL,				/* checksimul */
  NULL,				/* detach */
  NULL,				/* destroy */
};
