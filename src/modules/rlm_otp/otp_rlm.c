/*
 * $Id$
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
 * Copyright 2000,2001,2002  The FreeRADIUS server project
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005-2007 TRI-D Systems, Inc.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "extern.h"
#include "otp.h"

/* Global data */
static unsigned char hmac_key[16];	/* to protect State attribute  */
static int ninstance = 0;		/* #instances, for global init */

/* A mapping of configuration file names to internal variables. */
static const CONF_PARSER module_config[] = {
  { "otpd_rp", PW_TYPE_STRING_PTR, offsetof(otp_option_t, otpd_rp),
    NULL, OTP_OTPD_RP },
  { "challenge_prompt", PW_TYPE_STRING_PTR,offsetof(otp_option_t, chal_prompt),
    NULL, OTP_CHALLENGE_PROMPT },
  { "challenge_length", PW_TYPE_INTEGER, offsetof(otp_option_t, challenge_len),
    NULL, "6" },
  { "challenge_delay", PW_TYPE_INTEGER, offsetof(otp_option_t, challenge_delay),
    NULL, "30" },
  { "allow_sync", PW_TYPE_BOOLEAN, offsetof(otp_option_t, allow_sync),
    NULL, "yes" },
  { "allow_async", PW_TYPE_BOOLEAN, offsetof(otp_option_t, allow_async),
    NULL, "no" },

  { "mschapv2_mppe", PW_TYPE_INTEGER,
    offsetof(otp_option_t, mschapv2_mppe_policy), NULL, "2" },
  { "mschapv2_mppe_bits", PW_TYPE_INTEGER,
    offsetof(otp_option_t, mschapv2_mppe_types), NULL, "2" },
  { "mschap_mppe", PW_TYPE_INTEGER,
    offsetof(otp_option_t, mschap_mppe_policy), NULL, "2" },
  { "mschap_mppe_bits", PW_TYPE_INTEGER,
    offsetof(otp_option_t, mschap_mppe_types), NULL, "2" },

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/* per-instance initialization */
static int
otp_instantiate(CONF_SECTION *conf, void **instance)
{
  otp_option_t *opt;
  char *p;

  /* Set up a storage area for instance data. */
  opt = rad_malloc(sizeof(*opt));
  (void) memset(opt, 0, sizeof(*opt));

  /* If the configuration parameters can't be parsed, then fail. */
  if (cf_section_parse(conf, opt, module_config) < 0) {
    free(opt);
    return -1;
  }

  /* Onetime initialization. */
  if (!ninstance) {
    /* Generate a random key, used to protect the State attribute. */
    otp_get_random(hmac_key, sizeof(hmac_key));

    /* Initialize the passcode encoding/checking functions. */
    otp_pwe_init();

    /*
     * Don't do this again.
     * Only the main thread instantiates and detaches instances,
     * so this does not need mutex protection.
     */
    ninstance++;
  }

  /* Verify ranges for those vars that are limited. */
  if ((opt->challenge_len < 5) ||
      (opt->challenge_len > OTP_MAX_CHALLENGE_LEN)) {
    opt->challenge_len = 6;
    (void) radlog(L_ERR, "rlm_otp: %s: invalid challenge_length, range 5-%d, "
                         "using default of 6",
                  __func__, OTP_MAX_CHALLENGE_LEN);
  }

  /* Enforce a single "%" sequence, which must be "%s" */
  p = strchr(opt->chal_prompt, '%');
  if ((p == NULL) || (p != strrchr(opt->chal_prompt, '%')) ||
      strncmp(p,"%s",2)) {
    free(opt->chal_prompt);
    opt->chal_prompt = strdup(OTP_CHALLENGE_PROMPT);
    (void) radlog(L_ERR, "rlm_otp: %s: invalid challenge_prompt, "
                         "using default of \"%s\"",
                  __func__, OTP_CHALLENGE_PROMPT);
  }

  if (!opt->allow_sync && !opt->allow_async) {
    (void) radlog(L_ERR, "rlm_otp: %s: at least one of "
                         "{allow_async, allow_sync} must be set",
                  __func__);
    free(opt);
    return -1;
  }

  if ((opt->mschapv2_mppe_policy > 2) || (opt->mschapv2_mppe_policy < 0)) {
    opt->mschapv2_mppe_policy = 2;
    (void) radlog(L_ERR, "rlm_otp: %s: invalid value for mschapv2_mppe, "
                         "using default of 2",
                  __func__);
  }

  if ((opt->mschapv2_mppe_types > 2) || (opt->mschapv2_mppe_types < 0)) {
    opt->mschapv2_mppe_types = 2;
    (void) radlog(L_ERR, "rlm_otp: %s: invalid value for mschapv2_mppe_bits, "
                         "using default of 2",
                  __func__);
  }

  if ((opt->mschap_mppe_policy > 2) || (opt->mschap_mppe_policy < 0)) {
    opt->mschap_mppe_policy = 2;
    (void) radlog(L_ERR, "rlm_otp: %s: invalid value for mschap_mppe, "
                         "using default of 2",
                  __func__);
  }

  if (opt->mschap_mppe_types != 2) {
    opt->mschap_mppe_types = 2;
    (void) radlog(L_ERR, "rlm_otp: %s: invalid value for mschap_mppe_bits, "
                         "using default of 2",
                  __func__);
  }

  /* set the instance name (for use with authorize()) */
  opt->name = cf_section_name2(conf);
  if (!opt->name)
    opt->name = cf_section_name1(conf);
  if (!opt->name) {
    (void) radlog(L_ERR|L_CONS,
                  "rlm_otp: %s: no instance name (this can't happen)",
                  __func__);
    free(opt);
    return -1;
  }

  *instance = opt;
  return 0;
}


/* Generate a challenge to be presented to the user. */
static int
otp_authorize(void *instance, REQUEST *request)
{
  otp_option_t *inst = (otp_option_t *) instance;

  char challenge[OTP_MAX_CHALLENGE_LEN + 1];	/* +1 for '\0' terminator */
  int auth_type_found;
  otp_pwe_t pwe;

  /* Early exit if Auth-Type != inst->name */
  {
    VALUE_PAIR *vp;

    auth_type_found = 0;
    if ((vp = pairfind(request->config_items, PW_AUTHTYPE)) != NULL) {
      auth_type_found = 1;
      if (strcmp(vp->vp_strvalue, inst->name))
        return RLM_MODULE_NOOP;
    }
  }

  /* The State attribute will be present if this is a response. */
  if (pairfind(request->packet->vps, PW_STATE) != NULL) {
    DEBUG("rlm_otp: autz: Found response to Access-Challenge");
    return RLM_MODULE_OK;
  }

  /* User-Name attribute required. */
  if (!request->username) {
    (void) radlog(L_AUTH, "rlm_otp: %s: Attribute \"User-Name\" required "
                          "for authentication.",
                  __func__);
    return RLM_MODULE_INVALID;
  }

  if ((pwe = otp_pwe_present(request)) == 0) {
    (void) radlog(L_AUTH, "rlm_otp: %s: Attribute \"User-Password\" "
                          "or equivalent required for authentication.",
                  __func__);
    return RLM_MODULE_INVALID;
  }

  /*
   * We used to check for special "challenge" and "resync" passcodes
   * here, but these are complicated to explain and application is
   * limited.  More importantly, since we've removed all actual OTP
   * code (now we ask otpd), it's awkward for us to support them.
   * Should the need arise to reinstate these options, the most likely
   * choice is to duplicate some otpd code here.
   */

  if (inst->allow_sync && !inst->allow_async) {
    /* This is the token sync response. */
    if (!auth_type_found)
      pairadd(&request->config_items,
              pairmake("Auth-Type", inst->name, T_OP_EQ));
    return RLM_MODULE_OK;
  }

  /* Generate a random challenge. */
  otp_async_challenge(challenge, inst->challenge_len);

  /*
   * Create the State attribute, which will be returned to us along with
   * the response.  We will need this to verify the response.  It must
   * be hmac protected to prevent insertion of arbitrary State by an
   * inside attacker.  If we won't actually use the State (server config
   * doesn't allow async), we just use a trivial State.  We always create
   * at least a trivial State, so otp_authorize() can quickly pass on to
   * otp_authenticate().
   */
  {
    int32_t now = htonl(time(NULL));	/* low-order 32 bits on LP64 */
    char state[OTP_MAX_RADSTATE_LEN];

    if (otp_gen_state(state, NULL, challenge, inst->challenge_len, 0,
                      now, hmac_key) != 0) {
      (void) radlog(L_ERR, "rlm_otp: %s: failed to generate radstate",__func__);
      return RLM_MODULE_FAIL;
    }
    pairadd(&request->reply->vps, pairmake("State", state, T_OP_EQ));
  }

  /* Add the challenge to the reply. */
  {
    char *u_challenge;	/* challenge with addt'l presentation text */

    u_challenge = rad_malloc(strlen(inst->chal_prompt) +
                             OTP_MAX_CHALLENGE_LEN + 1);
    (void) sprintf(u_challenge, inst->chal_prompt, challenge);
    pairadd(&request->reply->vps,
            pairmake("Reply-Message", u_challenge, T_OP_EQ));
    free(u_challenge);
  }

  /*
   * Mark the packet as an Access-Challenge packet.
   * The server will take care of sending it to the user.
   */
  request->reply->code = PW_ACCESS_CHALLENGE;
  DEBUG("rlm_otp: Sending Access-Challenge.");

  if (!auth_type_found)
    pairadd(&request->config_items, pairmake("Auth-Type", inst->name, T_OP_EQ));
  return RLM_MODULE_HANDLED;
}


/* Verify the response entered by the user. */
static int
otp_authenticate(void *instance, REQUEST *request)
{
  otp_option_t *inst = (otp_option_t *) instance;

  char *username;
  int rc;
  otp_pwe_t pwe;
  VALUE_PAIR *vp;
  unsigned char challenge[OTP_MAX_CHALLENGE_LEN];	/* cf. authorize() */
  char passcode[OTP_MAX_PASSCODE_LEN + 1];

  challenge[0] = '\0';	/* initialize for otp_pw_valid() */

  /* User-Name attribute required. */
  if (!request->username) {
    (void) radlog(L_AUTH, "rlm_otp: %s: Attribute \"User-Name\" required "
                          "for authentication.",
                  __func__);
    return RLM_MODULE_INVALID;
  }
  username = request->username->vp_strvalue;

  if ((pwe = otp_pwe_present(request)) == 0) {
    (void) radlog(L_AUTH, "rlm_otp: %s: Attribute \"User-Password\" "
                          "or equivalent required for authentication.",
                  __func__);
    return RLM_MODULE_INVALID;
  }

  /* Add a message to the auth log. */
  pairadd(&request->packet->vps, pairmake("Module-Failure-Message",
                                          "rlm_otp", T_OP_EQ));
  pairadd(&request->packet->vps, pairmake("Module-Success-Message",
                                          "rlm_otp", T_OP_EQ));

  /* Retrieve the challenge (from State attribute). */
  if ((vp = pairfind(request->packet->vps, PW_STATE)) != NULL) {
    unsigned char	state[OTP_MAX_RADSTATE_LEN];
    unsigned char	raw_state[OTP_MAX_RADSTATE_LEN];
    unsigned char	rad_state[OTP_MAX_RADSTATE_LEN];
    int32_t		then;		/* state timestamp       */
    int			e_length;	/* expected State length */

    /* set expected State length */
    e_length = inst->challenge_len * 2 + 8 + 8 + 32; /* see otp_gen_state() */

    if (vp->length != e_length) {
      (void) radlog(L_AUTH, "rlm_otp: %s: bad radstate for [%s]: length",
                    __func__, username);
      return RLM_MODULE_INVALID;
    }

    /*
     * Verify the state.
     */

    /* ASCII decode; this is why OTP_MAX_RADSTATE_LEN has +1 */
    (void) memcpy(rad_state, vp->vp_strvalue, vp->length);
    rad_state[e_length] = '\0';
    if (otp_a2x(rad_state, raw_state) == -1) {
      (void) radlog(L_AUTH, "rlm_otp: %s: bad radstate for [%s]: not hex",
                    __func__, username);
      return RLM_MODULE_INVALID;
    }

    /* extract data from State */
    (void) memcpy(challenge, raw_state, inst->challenge_len);
    /* skip flag data */
    (void) memcpy(&then, raw_state + inst->challenge_len + 4, 4);

    /* generate new state from returned input data */
    if (otp_gen_state(NULL, state, challenge, inst->challenge_len, 0,
                      then, hmac_key) != 0) {
      (void) radlog(L_ERR, "rlm_otp: %s: failed to generate radstate",
                    __func__);
      return RLM_MODULE_FAIL;
    }
    /* compare generated state against returned state to verify hmac */
    if (memcmp(state, vp->vp_strvalue, vp->length)) {
      (void) radlog(L_AUTH, "rlm_otp: %s: bad radstate for [%s]: hmac",
                    __func__, username);
      return RLM_MODULE_REJECT;
    }

    /* State is valid, but check expiry. */
    then = ntohl(then);
    if (time(NULL) - then > inst->challenge_delay) {
      (void) radlog(L_AUTH, "rlm_otp: %s: bad radstate for [%s]: expired",
                    __func__, username);
      return RLM_MODULE_REJECT;
    }
  } /* if (State present) */

  /* do it */
  rc = otp_pw_valid(request, pwe, challenge, inst, passcode);

  /* Add MPPE data as needed. */
  if (rc == RLM_MODULE_OK)
    otp_mppe(request, pwe, inst, passcode);

  return rc;
}


/* per-instance destruction */
static int
otp_detach(void *instance)
{
  free(instance);
  /*
   * Only the main thread instantiates and detaches instances,
   * so this does not need mutex protection.
   */
  if (--ninstance == 0)
    (void) memset(hmac_key, 0, sizeof(hmac_key));

  return 0;
}


/*
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_otp = {
  RLM_MODULE_INIT,
  "otp",
  RLM_TYPE_THREAD_SAFE,		/* type */
  otp_instantiate,		/* instantiation */
  otp_detach,			/* detach */
  {
    otp_authenticate,		/* authentication */
    otp_authorize,		/* authorization */
    NULL,			/* preaccounting */
    NULL,			/* accounting */
    NULL,			/* checksimul */
    NULL,			/* pre-proxy */
    NULL,			/* post-proxy */
    NULL			/* post-auth */
  },
};
