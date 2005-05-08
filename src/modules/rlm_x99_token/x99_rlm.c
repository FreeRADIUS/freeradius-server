/*
 * x99_rlm.c
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000,2001,2002  The FreeRADIUS server project
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005 Frank Cusack
 */

/*
 * STRONG WARNING SECTION:
 *
 * ANSI X9.9 has been withdrawn as a standard, due to the weakness of DES.
 * An attacker can learn the token's secret by observing two
 * challenge/response pairs.  See ANSI document X9 TG-24-1999
 * <URL:http://www.x9.org/docs/TG24_1999.pdf>.
 *
 * Please read the accompanying docs.
 */

/*
 * TODO: support setting multiple auth-types in authorize()
 * TODO: support soft PIN? ???
 * TODO: support other than ILP32 (for State)
 */


#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>	/* htonl() */

#include "x99.h"
#ifdef FREERADIUS
#include "modules.h"
#endif

static const char rcsid[] = "$Id$";

/* Global data */
static int rnd_fd;			/* fd for random device           */
static unsigned char hmac_key[16];	/* to protect State attribute     */

/* A mapping of configuration file names to internal variables. */
static const CONF_PARSER module_config[] = {
    { "pwdfile", PW_TYPE_STRING_PTR, offsetof(x99_token_t, pwdfile),
      NULL, PWDFILE },
    { "syncdir", PW_TYPE_STRING_PTR, offsetof(x99_token_t, syncdir),
      NULL, SYNCDIR },
    { "challenge_prompt", PW_TYPE_STRING_PTR, offsetof(x99_token_t,chal_prompt),
      NULL, CHALLENGE_PROMPT },
    { "challenge_length", PW_TYPE_INTEGER, offsetof(x99_token_t, chal_len),
      NULL, "6" },
    { "challenge_delay", PW_TYPE_INTEGER, offsetof(x99_token_t, chal_delay),
      NULL, "30" },
    { "softfail", PW_TYPE_INTEGER, offsetof(x99_token_t, softfail),
      NULL, "5" },
    { "hardfail", PW_TYPE_INTEGER, offsetof(x99_token_t, hardfail),
      NULL, "0" },
    { "allow_sync", PW_TYPE_BOOLEAN, offsetof(x99_token_t, allow_sync),
      NULL, "yes" },
    { "fast_sync", PW_TYPE_BOOLEAN, offsetof(x99_token_t, fast_sync),
      NULL, "yes" },
    { "allow_async", PW_TYPE_BOOLEAN, offsetof(x99_token_t, allow_async),
      NULL, "no" },
    { "challenge_req", PW_TYPE_STRING_PTR, offsetof(x99_token_t, chal_req),
      NULL, CHALLENGE_REQ },
    { "resync_req", PW_TYPE_STRING_PTR, offsetof(x99_token_t, resync_req),
      NULL, RESYNC_REQ },
    { "ewindow_size", PW_TYPE_INTEGER, offsetof(x99_token_t, ewindow_size),
      NULL, "0" },
    { "ewindow2_size", PW_TYPE_INTEGER, offsetof(x99_token_t, ewindow2_size),
      NULL, "0" },
    { "ewindow2_delay", PW_TYPE_INTEGER, offsetof(x99_token_t, ewindow2_delay),
      NULL, "60" },
    { "mschapv2_mppe", PW_TYPE_INTEGER,
      offsetof(x99_token_t, mschapv2_mppe_policy), NULL, "2" },
    { "mschapv2_mppe_bits", PW_TYPE_INTEGER,
      offsetof(x99_token_t, mschapv2_mppe_types), NULL, "2" },
    { "mschap_mppe", PW_TYPE_INTEGER,
      offsetof(x99_token_t, mschap_mppe_policy), NULL, "2" },
    { "mschap_mppe_bits", PW_TYPE_INTEGER,
      offsetof(x99_token_t, mschap_mppe_types), NULL, "2" },
#if 0
    { "twindow_min", PW_TYPE_INTEGER, offsetof(x99_token_t, twindow_min),
      NULL, "0" },
    { "twindow_max", PW_TYPE_INTEGER, offsetof(x99_token_t, twindow_max),
      NULL, "0" },
#endif

    { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/* transform x99_pw_valid() return code into an rlm return code */
static int
x99rc2rlmrc(int rc)
{
    switch (rc) {
    case X99_RC_OK:                     return RLM_MODULE_OK;
    case X99_RC_USER_UNKNOWN:           return RLM_MODULE_REJECT;
    case X99_RC_AUTHINFO_UNAVAIL:       return RLM_MODULE_REJECT;
    case X99_RC_AUTH_ERR:               return RLM_MODULE_REJECT;
    case X99_RC_MAXTRIES:               return RLM_MODULE_USERLOCK;
    case X99_RC_SERVICE_ERR:            return RLM_MODULE_FAIL;
    default:                            return RLM_MODULE_FAIL;
    }
}


/* per-module initialization */
static int
x99_token_init(void)
{
    if ((rnd_fd = open(DEVURANDOM, O_RDONLY)) == -1) {
	x99_log(X99_LOG_ERR, "init: error opening %s: %s", DEVURANDOM,
		strerror(errno));
	return -1;
    }

    /* Generate a random key, used to protect the State attribute. */
    if (x99_get_random(rnd_fd, hmac_key, sizeof(hmac_key)) == -1) {
	x99_log(X99_LOG_ERR, "init: failed to obtain random data for hmac_key");
	return -1;
    }

    /* Initialize the passcode encoding/checking functions. */
    x99_pwe_init();

    return 0;
}


/* per-instance initialization */
static int
x99_token_instantiate(CONF_SECTION *conf, void **instance)
{
    x99_token_t *data;
    char *p;
    struct stat st;

    /* Set up a storage area for instance data. */
    data = rad_malloc(sizeof(*data));
    (void) memset(data, 0, sizeof(*data));

    /* If the configuration parameters can't be parsed, then fail. */
    if (cf_section_parse(conf, data, module_config) < 0) {
	free(data);
	return -1;
    }

    /* Verify ranges for those vars that are limited. */
    if ((data->chal_len < 5) || (data->chal_len > MAX_CHALLENGE_LEN)) {
	data->chal_len = 6;
	x99_log(X99_LOG_ERR,
		"invalid challenge_length, range 5-%d, using default of 6",
		MAX_CHALLENGE_LEN);

    }

    /* Enforce a single "%" sequence, which must be "%s" */
    p = strchr(data->chal_prompt, '%');
    if ((p == NULL) || (p != strrchr(data->chal_prompt, '%')) ||
	strncmp(p,"%s",2)){
	free(data->chal_prompt);
	data->chal_prompt = strdup(CHALLENGE_PROMPT);
	x99_log(X99_LOG_ERR,
		"invalid challenge_prompt, using default of \"%s\"",
		CHALLENGE_PROMPT);
    }

    if (data->softfail < 0) {
	data->softfail = 5;
	x99_log(X99_LOG_ERR, "softfail must be at least 1 "
		"(or 0 == infinite), using default of 5");
    }

    if (data->hardfail < 0) {
	data->hardfail = 0;
	x99_log(X99_LOG_ERR, "hardfail must be at least 1 "
		"(or 0 == infinite), using default of 0");
    }

    if (data->fast_sync && !data->allow_sync) {
	data->fast_sync = 0;
	x99_log(X99_LOG_INFO,
		"fast_sync is yes, but allow_sync is no; disabling fast_sync");
    }

    if (!data->allow_sync && !data->allow_async) {
	x99_log(X99_LOG_ERR,
		"at least one of {allow_async, allow_sync} must be set");
	free(data);
	return -1;
    }

    if ((data->ewindow_size > MAX_EWINDOW_SIZE) || (data->ewindow_size < 0)) {
	data->ewindow_size = 0;
	x99_log(X99_LOG_ERR, "max ewindow_size is %d, using default of 0",
		MAX_EWINDOW_SIZE);
    }

    if (data->ewindow2_size && (data->ewindow2_size < data->ewindow_size)) {
	data->ewindow2_size = 0;
	x99_log(X99_LOG_ERR, "ewindow2_size must be at least as large as "
			     "ewindow_size, using default of 0");
    }

    if (data->ewindow2_size && !data->ewindow2_delay) {
	data->ewindow2_size = 0;
	x99_log(X99_LOG_ERR, "ewindow2_size is non-zero, "
			     "but ewindow2_delay is zero; disabling ewindow2");
    }

    if ((data->mschapv2_mppe_policy > 2) || (data->mschapv2_mppe_policy < 0)) {
	data->mschapv2_mppe_policy = 2;
	x99_log(X99_LOG_ERR,
		"invalid value for mschapv2_mppe, using default of 2");
    }

    if ((data->mschapv2_mppe_types > 2) || (data->mschapv2_mppe_types < 0)) {
	data->mschapv2_mppe_types = 2;
	x99_log(X99_LOG_ERR,
		"invalid value for mschapv2_mppe_bits, using default of 2");
    }

    if ((data->mschap_mppe_policy > 2) || (data->mschap_mppe_policy < 0)) {
	data->mschap_mppe_policy = 2;
	x99_log(X99_LOG_ERR,
		"invalid value for mschap_mppe, using default of 2");
    }

    if (data->mschap_mppe_types != 2) {
	data->mschap_mppe_types = 2;
	x99_log(X99_LOG_ERR,
		"invalid value for mschap_mppe_bits, using default of 2");
    }

#if 0
    if (data->twindow_max - data->twindow_min > MAX_TWINDOW_SIZE) {
	data->twindow_min = data->twindow_max = 0;
	x99_log(X99_LOG_ERR, "max time window size is %d, using default of 0",
		MAX_TWINDOW_SIZE);
    }
    if ((data->twindow_min > 0) || (data->twindow_max < 0) ||
	(data->twindow_max < data->twindow_min)) {
	data->twindow_min = data->twindow_max = 0;
	x99_log(X99_LOG_ERR,
		"invalid values for time window, using default of 0");
    }
#endif

    if (stat(data->syncdir, &st) != 0) {
	x99_log(X99_LOG_ERR, "syncdir %s error: %s",
		data->syncdir, strerror(errno));
	free(data);
	return -1;
    }
    if (st.st_mode != (S_IFDIR|S_IRWXU)) {
	x99_log(X99_LOG_ERR, "syncdir %s has loose permissions", data->syncdir);
	free(data);
	return -1;
    }

    /* Set the instance name (for use with authorize()) */
    data->name = cf_section_name2(conf);
    if (!data->name)
	data->name = cf_section_name1(conf);
    if (!data->name) {
	x99_log(X99_LOG_CRIT, "no instance name (this can't happen)");
	free(data);
	return -1;
    }

    *instance = data;
    return 0;
}


/* Generate a challenge to be presented to the user. */
static int
x99_token_authorize(void *instance, REQUEST *request)
{
    x99_token_t *inst = (x99_token_t *) instance;

    char challenge[MAX_CHALLENGE_LEN + 1];	/* +1 for '\0' terminator */
    char *state;
    int rc;

    int auth_type_found;
    int32_t sflags = 0; /* flags for state */
    struct x99_pwe_cmp_t data = {
	.request = request,
	.inst = inst,
	.returned_vps = NULL
    };


    /* Early exit if Auth-Type != inst->name */
    auth_type_found = 0;
    if ((vp = pairfind(request->config_items, PW_AUTHTYPE)) != NULL) {
	auth_type_found = 1;
	if (strcmp(vp->strvalue, inst->name)) {
	    return RLM_MODULE_NOOP;
	}
    }

    /* The State attribute will be present if this is a response. */
    if (pairfind(request->packet->vps, PW_STATE) != NULL) {
	DEBUG("rlm_x99_token: autz: Found response to Access-Challenge");
	return RLM_MODULE_OK;
    }

    /* User-Name attribute required. */
    if (!request->username) {
	x99_log(X99_LOG_AUTH,
		"autz: Attribute \"User-Name\" required for authentication.");
	return RLM_MODULE_INVALID;
    }

    if ((data.pwattr = x99_pwe_present(request)) == 0) {
	x99_log(X99_LOG_AUTH, "autz: Attribute \"User-Password\" "
		"or equivalent required for authentication.");
	return RLM_MODULE_INVALID;
    }

    /* fast_sync mode (challenge only if requested) */
    if (inst->fast_sync) {
	if ((!x99_pwe_cmp(&data, inst->resync_req) &&
		/* Set a bit indicating resync */ (sflags |= htonl(1))) ||
	    !x99_pwe_cmp(&data, inst->chal_req)) {
	    /*
	     * Generate a challenge if requested.  Note that we do this
	     * even if configuration doesn't allow async mode.
	     */
	    DEBUG("rlm_x99_token: autz: fast_sync challenge requested");
	    goto gen_challenge;

	} else {
	    /* Otherwise, this is the token sync response. */
	    if (!auth_type_found)
		pairadd(&request->config_items,
			pairmake("Auth-Type", "x99_token", T_OP_EQ));
	    return RLM_MODULE_OK;

	}
    } /* if (fast_sync && card supports sync mode) */

gen_challenge:
    /* Set the resync bit by default if the user can't choose. */
    if (!inst->fast_sync)
	sflags |= htonl(1);

    /* Generate a random challenge. */
    if (x99_get_challenge(rnd_fd, challenge, inst->chal_len) == -1) {
	x99_log(X99_LOG_ERR, "autz: failed to obtain random challenge");
	return RLM_MODULE_FAIL;
    }

    /*
     * Create the State attribute, which will be returned to us along with
     * the response.  We will need this to verify the response.  It must
     * be hmac protected to prevent insertion of arbitrary State by an
     * inside attacker.  If we won't actually use the State (server config
     * doesn't allow async), we just use a trivial State.  We always create
     * at least a trivial State, so x99_token_authorize() can quickly pass
     * on to x99_token_authenticate().
     */
    if (inst->allow_async) {
	time_t now = time(NULL);

	if (sizeof(now) != 4 || sizeof(long) != 4) {
	    x99_log(X99_LOG_ERR, "autz: only ILP32 arch is supported");
	    return RLM_MODULE_FAIL;
	}
	now = htonl(now);

	if (x99_gen_state(&state, NULL, challenge, sflags, now, hmac_key) != 0){
	    x99_log(X99_LOG_ERR, "autz: failed to generate state");
	    return RLM_MODULE_FAIL;
	}
    } else {
	/* x2 b/c pairmake() string->octet needs even num of digits */
	state = rad_malloc(3 + inst->chal_len * 2);
	(void) sprintf(state, "0x%s%s", challenge, challenge);
    }
    pairadd(&request->reply->vps, pairmake("State", state, T_OP_EQ));
    free(state);

    /* Add the challenge to the reply. */
    {
	char *u_challenge;	/* challenge with addt'l presentation text */

	u_challenge = rad_malloc(strlen(inst->chal_prompt)+MAX_CHALLENGE_LEN+1);
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
    DEBUG("rlm_x99_token: Sending Access-Challenge.");

    /* TODO: support config-specific auth-type */
    if (!auth_type_found)
	pairadd(&request->config_items,
		pairmake("Auth-Type", "x99_token", T_OP_EQ));
    return RLM_MODULE_HANDLED;
}


/* Verify the response entered by the user. */
static int
x99_token_authenticate(void *instance, REQUEST *request)
{
    x99_token_t *inst = (x99_token_t *) instance;

    char *username;
    int rc;
    int resync = 0;	/* resync flag for async mode */

    char challenge[MAX_CHALLENGE_LEN + 1];
    VALUE_PAIR *add_vps = NULL;

    struct x99_pwe_cmp_t data = {
	.request = request,
	.inst = inst,
	.returned_vps = &add_vps
    };

    /* User-Name attribute required. */
    if (!request->username) {
	x99_log(X99_LOG_AUTH,
		"auth: Attribute \"User-Name\" required for authentication.");
	return RLM_MODULE_INVALID;
    }
    username = request->username->strvalue;

    if ((data.pwattr = x99_pwe_present(request)) == 0) {
	x99_log(X99_LOG_AUTH, "auth: Attribute \"User-Password\" "
			      "or equivalent required for authentication.");
	return RLM_MODULE_INVALID;
    }

    /* Add a message to the auth log. */
    pairadd(&request->packet->vps, pairmake("Module-Failure-Message",
					    X99_MODULE_NAME, T_OP_EQ));
    pairadd(&request->packet->vps, pairmake("Module-Success-Message",
					    X99_MODULE_NAME, T_OP_EQ));

    /* Retrieve the challenge (from State attribute). */
    challenge[0] = '\0';
    {
	VALUE_PAIR	*vp;
	unsigned char	*state;
	int32_t		sflags = 0; 	/* state flags */
	time_t		then;		/* state timestamp */

	if ((vp = pairfind(request->packet->vps, PW_STATE)) != NULL) {
	    int e_length = inst->chal_len;

	    /* Extend expected length if state should have been protected. */
	    if (inst->allow_async)
		e_length += 4 + 4 + 16; /* sflags + time + hmac */

	    if (vp->length != e_length) {
		x99_log(X99_LOG_AUTH,
			"auth: bad state for [%s]: length", username);
		return RLM_MODULE_INVALID;
	    }

	    if (inst->allow_async) {
		/* Verify the state. */
		(void) memset(challenge, 0, sizeof(challenge));
		(void) memcpy(challenge, vp->strvalue, inst->chal_len);
		(void) memcpy(&sflags, vp->strvalue + inst->chal_len, 4);
		(void) memcpy(&then, vp->strvalue + inst->chal_len + 4, 4);
		if (x99_gen_state(NULL, &state, challenge,
				  sflags, then, hmac_key) != 0) {
		    x99_log(X99_LOG_ERR, "auth: failed to generate state");
		    return RLM_MODULE_FAIL;
		}
		if (memcmp(state, vp->strvalue, vp->length)) {
		    x99_log(X99_LOG_AUTH,
			    "auth: bad state for [%s]: hmac", username);
		    free(state);
		    return RLM_MODULE_REJECT;
		}
		free(state);

		/* State is valid, but check expiry. */
		then = ntohl(then);
		if (time(NULL) - then > inst->chal_delay) {
		    x99_log(X99_LOG_AUTH,
			    "auth: bad state for [%s]: expired", username);
		    return RLM_MODULE_REJECT;
		}
		resync = ntohl(sflags) & 1;
	    } /* if (State should have been protected) */
	} /* if (State present) */
    } /* code block */

    /* do it */
    rc = x99rc2rlmrc(x99_pw_valid(username, challenge, NULL, inst, resync,
				  x99_pwe_cmp, &data, "auth"));

    /* Handle any vps returned from x99_pwe_cmp(). */
    if (rc == RLM_MODULE_OK) {
	pairadd(&request->reply->vps, add_vps);
    } else {
	pairfree(&add_vps);
    }
    return rc;
}


/* per-instance destruction */
static int
x99_token_detach(void *instance)
{
    x99_token_t *inst = (x99_token_t *) instance;

    free(inst->pwdfile);
    free(inst->syncdir);
    free(inst->chal_prompt);
    free(inst->chal_req);
    free(inst->resync_req);
    free(instance);
    return 0;
}


/* per-module destruction */
static int
x99_token_destroy(void)
{
    (void) memset(hmac_key, 0, sizeof(hmac_key));
    (void) close(rnd_fd);
    return 0;
}

/*
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_x99_token = {
	"x99_token",
	RLM_TYPE_THREAD_SAFE,		/* type */
	x99_token_init,			/* initialization */
	x99_token_instantiate,		/* instantiation */
	{
		x99_token_authenticate,	/* authentication */
		x99_token_authorize,	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
	x99_token_detach,		/* detach */
	x99_token_destroy,		/* destroy */
};
