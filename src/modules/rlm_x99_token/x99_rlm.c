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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2001  Google, Inc.
 */

/*
 * STRONG WARNING SECTION:
 *
 * ANSI X9.9 has been withdrawn as a standard, due to the weakness of DES.
 * An attacker can learn the token's secret by observing two
 * challenge/response pairs.  See ANSI document X9 TG-24-1999
 * <URL:http://www.x9.org/TG24_1999.pdf>.
 * 
 * Please read the accompanying docs.
 */

/*
 * TODO: support key changing synchronous modes
 * TODO: support time synchronous modes
 * TODO: add a flag to control challenge issuance for unknown usernames?
 * TODO: add required password support? (before challenged, eg "challenge")
 * TODO: support other than ILP32 (for State)
 */

#include "autoconf.h"
#include "libradius.h"
#include "x99.h"
#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/des.h>
#include <netinet/in.h>	/* htonl() */

static const char rcsid[] = "$Id$";

/* Global data */
static int rnd_fd;			/* fd for random device           */
static unsigned char hmac_key[16];	/* to protect State attribute     */

/* struct used for instance data */
typedef struct x99_token_t {
    char *pwdfile;	/* file containing user:card_type:key entries      */
    char *syncdir;	/* dir containing sync mode and state info         */
    char *chal_text;	/* text to present challenge to user, must have %s */
    int chal_len;	/* challenge length, min 5 digits                  */
    int maxdelay;	/* max delay time for response, in seconds         */
    int maxfail;	/* max number of auth fails before disabling user  */
    int allow_sync;	/* useful to override pwdfile card_type settings   */
    int allow_async;	/* C/R mode allowed? (to resync card)              */
    int ewindow_size;	/* sync mode event window size (right side value)  */
#if 0
    int twindow_min;	/* sync mode time window left side                 */
    int twindow_max;	/* sync mode time window right side                */
#endif
} x99_token_t;

/* A mapping of configuration file names to internal variables. */
static CONF_PARSER module_config[] = {
    { "pwdfile", PW_TYPE_STRING_PTR, offsetof(x99_token_t, pwdfile),
      NULL, "/etc/x99passwd" },
    { "syncdir", PW_TYPE_STRING_PTR, offsetof(x99_token_t, syncdir),
      NULL, "/etc/x99sync.d" },
    { "chal_text", PW_TYPE_STRING_PTR, offsetof(x99_token_t, chal_text),
      NULL, CHALLENGE_TEXT },
    { "chal_len", PW_TYPE_INTEGER, offsetof(x99_token_t, chal_len),
      NULL, "6" },
    { "maxdelay", PW_TYPE_INTEGER, offsetof(x99_token_t, maxdelay),
      NULL, "30" },
    { "maxfail", PW_TYPE_INTEGER, offsetof(x99_token_t, maxfail),
      NULL, "5" },
    { "allow_sync", PW_TYPE_BOOLEAN, offsetof(x99_token_t, allow_sync),
      NULL, "yes" },
    { "allow_async", PW_TYPE_BOOLEAN, offsetof(x99_token_t, allow_async),
      NULL, "no" },
    { "ewindow_size", PW_TYPE_INTEGER, offsetof(x99_token_t, ewindow_size),
      NULL, "0" },
#if 0
    { "twindow_min", PW_TYPE_INTEGER, offsetof(x99_token_t, twindow_min),
      NULL, "0" },
    { "twindow_max", PW_TYPE_INTEGER, offsetof(x99_token_t, twindow_max),
      NULL, "0" },
#endif

    { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/* per-module initialization */
static int
x99_token_init(void)
{
    if ((rnd_fd = open(DEVURANDOM, O_RDONLY)) == -1) {
	/* Don't bother reporting the error code, probably wrong for MT */
	radlog(L_ERR, "rlm_x99_token: init: error opening %s", DEVURANDOM);
	return -1;
    }

    /* Generate a random key, used to protect the State attribute. */
    if (x99_get_random(rnd_fd, hmac_key, sizeof(hmac_key)) == -1) {
	radlog(L_ERR, "rlm_x99_token: init: failed to obtain random data "
		      "for hmac_key");
	return -1;
    }

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

    /* If the configuration parameters can't be parsed, then fail. */
    if (cf_section_parse(conf, data, module_config) < 0) {
	free(data);
	return -1;
    }

    /* Verify ranges for those vars that are limited. */
    if (data->chal_len < 5 || data->chal_len > MAX_CHALLENGE_LEN) {
	data->chal_len = 6;
	radlog(L_ERR, "rlm_x99_token: invalid challenge length, range 5-%d, "
		      "using default of 6", MAX_CHALLENGE_LEN);

    }

    /* Enforce a single '%' character, which must be "%s" */
    p = strchr(data->chal_text, '%');
    if (p == NULL || p != strrchr(data->chal_text, '%') || strncmp(p,"%s",2)) {
	free(data->chal_text);
	data->chal_text = strdup(CHALLENGE_TEXT);
	radlog(L_ERR, "rlm_x99_token: invalid challenge text, "
		      "using default of \"%s\"", CHALLENGE_TEXT);
    }

    if (data->maxfail < 1 ) {
	data->maxfail = 5;
	radlog(L_ERR, "rlm_x99_token: maxfail must be at least 1, "
		      "using default of 5");
    }

    if (data->ewindow_size > MAX_EWINDOW_SIZE || data->ewindow_size < 0) {
	data->ewindow_size = 0;
	radlog(L_ERR, "rlm_x99_token: max event window size is %d, "
		      "using default of 0", MAX_EWINDOW_SIZE);
    }

#if 0
    if (data->twindow_max - data->twindow_min > MAX_TWINDOW_SIZE) {
	data->twindow_min = data->twindow_max = 0;
	radlog(L_ERR, "rlm_x99_token: max time window size is %d, "
		      "using default of 0", MAX_TWINDOW_SIZE);
    }
    if (data->twindow_min > 0 || data->twindow_max < 0 ||
	data->twindow_max < data->twindow_min) {
	data->twindow_min = data->twindow_max = 0;
	radlog(L_ERR, "rlm_x99_token: invalid values for time window, "
		      "using default of 0");
    }
#endif

    if (stat(data->syncdir, &st) != 0) {
	radlog(L_ERR, "rlm_x99_token: syncdir %s error: %s",
	       data->syncdir, strerror(errno));
	return -1;
    }
    if (st.st_mode != (S_IFDIR|S_IRWXU)) {
	radlog(L_ERR, "rlm_x99_token: syncdir %s has loose permissions",
	       data->syncdir);
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

    unsigned char rawchallenge[MAX_CHALLENGE_LEN];
    char challenge[MAX_CHALLENGE_LEN + 1];	/* +1 for '\0' terminator */
    char *state;
    int i;

    x99_user_info_t user_info;
    int rc;

    /* The State attribute will be present if this is a response. */
    if (pairfind(request->packet->vps, PW_STATE) != NULL) {
	DEBUG("rlm_x99_token: autz: Found response to access challenge");
	return RLM_MODULE_OK;
    }

    /* User-Name attribute required (but we don't use it). */
    if (!request->username) {
	radlog(L_AUTH, "rlm_x99_token: autz: Attribute \"User-Name\" is "
		       "required for authentication.");
	return RLM_MODULE_INVALID;
    }

#if 0
    /*
     * Unlike TACACS+, RADIUS has the NAS ask for the password before
     * sending any data to the server.  So the password here is junk
     * (we haven't presented the challenge yet).  We might want to
     * use it later so a user can multiplex on different card types.
     * Or for other reasons?
     */
    if (!request->password) {
	radlog(L_AUTH, "rlm_x99_token: autz: Attribute \"Password\" is "
		       "required for authentication.");
	return RLM_MODULE_INVALID;
    }

    /* Ensure that we're being passed a plain-text password. */
    if (request->password->attribute != PW_PASSWORD) {
	radlog(L_AUTH, "rlm_x99_token: autz: Attribute \"Password\" is "
		       "required for authentication.  Cannot use \"%s\".",
	       request->password->name);
	return RLM_MODULE_INVALID;
    }
#endif /* 0 */

    /* Look up the user's info. */
    if ((rc = x99_get_user_info(inst->pwdfile, request->username->strvalue,
				&user_info)) == -2) {
	radlog(L_ERR, "rlm_x99_token: autz: error reading user info");
	return RLM_MODULE_FAIL;
    }
    if (rc == -1) {
	/* x99_get_user_info() also logs, but we want to record the autz bit */
	radlog(L_AUTH, "rlm_x99_token: autz: user not found");
	/* if (!always_challenge) { return RLM_MODULE_INVALID; } */
    }

    /* Generate a random challenge. */
    if (x99_get_random(rnd_fd, rawchallenge, inst->chal_len) == -1) {
	radlog(L_ERR, "rlm_x99_token: autz: failed to obtain random data");
	return RLM_MODULE_FAIL;
    }

    /* Convert our challenge bytes to a decimal string representation. */
    (void) memset(challenge, 0, sizeof(challenge));
    for(i = 0; i < inst->chal_len; ++i) {
	challenge[i] = '0' + rawchallenge[i] % 10;
    }

    /*
     * Create the State attribute, which will be returned to us along with
     * the response.  We will need this to verify the response.  Create
     * a strong state if the user will be able use this with their token.
     * Otherwise, we discard it anyway, so don't "waste" time with hmac.
     * We always create at least a trivial state, so x99_token_authorize()
     * can easily pass on to x99_token_authenticate().
     */
    if (user_info.card_id & X99_CF_AM) {
	time_t now = time(NULL);

	if (sizeof(now) != 4 || sizeof(long) != 4) {
	    radlog(L_ERR, "rlm_x99_token: autz: only ILP32 arch is supported");
	    return RLM_MODULE_FAIL;
	}
	now = htonl(now);

	if (x99_gen_state(&state, NULL, challenge, now, hmac_key) != 0) {
	    radlog(L_ERR, "rlm_x99_token: autz: failed to generate state");
	    return RLM_MODULE_FAIL;
	}
    } else {
	state = rad_malloc(3 + inst->chal_len * 2);
	sprintf(state, "0x%s%s", challenge, challenge);
    }
    pairadd(&request->reply->vps, pairmake("State", state, T_OP_EQ));
    free(state);

    /* Add the challenge to the reply. */
    {
	char *u_challenge;	/* challenge with addt'l presentation text */

	u_challenge = rad_malloc(strlen(inst->chal_text) + MAX_CHALLENGE_LEN+1);
	sprintf(u_challenge, inst->chal_text, challenge);
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

    return RLM_MODULE_HANDLED;
}


/* Verify the response entered by the user. */
static int
x99_token_authenticate(void *instance, REQUEST *request)
{
    x99_token_t *inst = (x99_token_t *) instance;

    x99_user_info_t  user_info;
    char *username;
    int i, failcount;
    time_t last_async;

    char challenge[MAX_CHALLENGE_LEN + 1];
    char e_response[9], u_response[9];		/* expected, user response */

    /* User-Name attribute required. */
    if (!request->username) {
	radlog(L_AUTH, "rlm_x99_token: auth: Attribute \"User-Name\" is "
		       "required for authentication.");
	return RLM_MODULE_INVALID;
    }
    username = request->username->strvalue;

    /* Password attribute required. */
    if (!request->password) {
	radlog(L_AUTH, "rlm_x99_token: auth: Attribute \"Password\" is "
		       "required for authentication.");
	return RLM_MODULE_INVALID;
    }
    /* Early exit for response too long. */
    if (request->password->length > 8)
	return RLM_MODULE_REJECT;

    /* Setup u_response. */
    (void) memset(u_response, 0, sizeof(u_response));
    (void) memcpy(u_response, request->password->strvalue,
		  request->password->length);
    /*
     * One vendor (at least) uses a '-' in 7 digit display mode.
     * In case the luser actually types it in, we need to s/-//.
     */
    if (u_response[3] == '-')
	(void) memmove(&u_response[3], &u_response[4], 5);

    /* Look up the user's info. */
    if (x99_get_user_info(inst->pwdfile, username, &user_info) != 0) {
	radlog(L_AUTH, "rlm_x99_token: auth: error reading user [%s] info",
	       username);
	return RLM_MODULE_REJECT;
    }

    /* Retrieve the challenge (from State attribute). */
    {
	VALUE_PAIR	*vp;
	unsigned char	*state;
	time_t		then;

	if ((vp = pairfind(request->packet->vps, PW_STATE)) != NULL) {
	    int e_length = inst->chal_len;

	    /* Extend expected length if state should have been protected. */
	    if (user_info.card_id & X99_CF_AM)
		e_length += 4 + 16; /* time + hmac */

	    if (vp->length != e_length) {
		radlog(L_AUTH, "rlm_x99_token: auth: bad state for [%s]: "
			       "length", username);
		return RLM_MODULE_INVALID;
	    }

	    /* Fast path if we didn't protect the state. */
	    if (!(user_info.card_id & X99_CF_AM))
		goto good_state;

	    /* Verify the state. */
	    (void) memset(challenge, 0, sizeof(challenge));
	    (void) memcpy(challenge, vp->strvalue, inst->chal_len);
	    (void) memcpy(&then, vp->strvalue + inst->chal_len, 4);
	    if (x99_gen_state(NULL, &state, challenge, then, hmac_key) != 0) {
		radlog(L_ERR, "rlm_x99_token: auth: failed to generate state");
		return RLM_MODULE_FAIL;
	    }
	    if (memcmp(state, vp->strvalue, vp->length)) {
		radlog(L_AUTH, "rlm_x99_token: auth: bad state for [%s]: "
			       "hmac", username);
		free(state);
		return RLM_MODULE_REJECT;
	    }
	    free(state);

	    /* State is valid, but check expiry. */
	    then = ntohl(then);
	    if (then + inst->maxdelay < time(NULL)) {
		radlog(L_AUTH, "rlm_x99_token: auth: bad state for [%s]: "
			       "expired", username);
		return RLM_MODULE_REJECT;
	    }
good_state:
	    /* State is good! */

	} else {
	    /* This shouldn't happen, authorize code should handle it. */
	    radlog(L_ERR, "rlm_x99_token: auth: bad state for [%s]: "
			  "missing", username);
	    return RLM_MODULE_FAIL;
	}
    }

    /*
     * Check failure count.  We try to "fail secure", but it's not perfect
     * as we may be able to read the value but not set it.
     */
    if (x99_get_failcount(inst->syncdir, username, &failcount) < 0) {
	radlog(L_ERR, "rlm_x99_token: auth: unable to get failure count "
		      "for [%s]", username);
	return RLM_MODULE_FAIL;
    }
    if (failcount >= inst->maxfail) {
	radlog(L_AUTH, "rlm_x99_token: auth: %d/%d failed/max authentications "
		       "for [%s]", failcount, inst->maxfail, username);
	if (x99_incr_failcount(inst->syncdir, username) != 0) {
	    radlog(L_ERR, "rlm_x99_token: auth: unable to increment failure "
			  "count for locked out user [%s]", username);
	}
	return RLM_MODULE_USERLOCK;
    }

    /* Don't bother to check async response if the card doesn't support it. */
    if (!(user_info.card_id & X99_CF_AM))
	goto sync_response;

    /* Perform any site-specific transforms of the challenge. */
    if (x99_challenge_transform(username, challenge) != 0) {
	radlog(L_ERR, "rlm_x99_token: auth: challenge transform failed "
		      "for [%s]", username);
	return RLM_MODULE_FAIL;
    }

    /* Calculate and test the async response. */
    if (x99_response(challenge, e_response, user_info.card_id,
		     user_info.keyblock) != 0) {
	radlog(L_ERR, "rlm_x99_token: auth: unable to calculate async "
		      "response for [%s], to challenge %s",
		      username, challenge);
	return RLM_MODULE_FAIL;
    }
    DEBUG("rlm_x99_token: auth: [%s], async challenge %s, "
	  "expecting response %s", username, challenge, e_response);

    if (!strcmp(e_response, u_response)) {
	/* Password matches.  Is this allowed? */
	if (!inst->allow_async) {
	    radlog(L_AUTH, "rlm_x99_token: auth: bad async for [%s]: "
			   "disallowed by config", username);
	    return RLM_MODULE_REJECT;
	}
	if (x99_get_last_async(inst->syncdir, username, &last_async) != 0) {
	    radlog(L_ERR, "rlm_x99_token: auth: unable to get last async "
			  "auth time for [%s]", username);
	    return RLM_MODULE_FAIL;
	}
	if (last_async + inst->maxdelay > time(NULL)) {
	    radlog(L_AUTH, "rlm_x99_token: auth: bad async for [%s]: "
			   "too soon", username);
	    return RLM_MODULE_REJECT;
	}

	if (user_info.card_id & X99_CF_SM) {
	    radlog(L_INFO, "rlm_x99_token: auth: [%s] authenticated "
			   "in async mode", username);
	    /* Resync the card. */
	    if (x99_get_sync_data(inst->syncdir, username, user_info.card_id,
				  1, 0, challenge, user_info.keyblock) != 0) {
		radlog(L_ERR, "rlm_x99_token: auth: unable to get "
			      "sync data e:%d t:%d for [%s] (for resync)",
			      1, 0, username);
	    } else if (x99_set_sync_data(inst->syncdir, username, challenge,
					 user_info.keyblock) != 0) {
		radlog(L_ERR, "rlm_x99_token: auth: unable to set sync "
			      "data for [%s] (for resync)", username);
	    }
	}

	/* Reset counters. */
	if (x99_reset_failcount(inst->syncdir, username) != 0) {
	    radlog(L_ERR, "rlm_x99_token: auth: unable to reset "
			  "failure count for [%s]", username);
	}
	if (x99_upd_last_async(inst->syncdir, username) != 0) {
	    radlog(L_ERR, "rlm_x99_token: auth: unable to update "
			  "last async time for [%s]", username);
	    /*
	     * Up to here, we allowed resync failures to fall through, but
	     * if we let this one slip by we will be open to replay attacks
	     * over the lifetime of the State attribute (inst->maxdelay).
	     */
	    return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
    } /* if (user authenticated async) */

sync_response:
    /* Calculate and test sync responses in the window. */
    if ((user_info.card_id & X99_CF_SM) && inst->allow_sync) {
	for (i = 0; i <= inst->ewindow_size; ++i) {
	    /* Get sync challenge and key. */
	    if (x99_get_sync_data(inst->syncdir, username, user_info.card_id,
				  i, 0, challenge, user_info.keyblock) != 0) {
		radlog(L_ERR, "rlm_x99_token: auth: unable to get "
			      "sync data e:%d t:%d for [%s]",
			      i, 0, username);
		return RLM_MODULE_FAIL;
	    }

	    /* Calculate sync response. */
	    if (x99_response(challenge, e_response, user_info.card_id,
			     user_info.keyblock) != 0) {
		radlog(L_ERR, "rlm_x99_token: auth: unable to calculate "
			      "sync response e:%d t:%d for [%s], to "
			      "challenge %s", i, 0, username, challenge);
		return RLM_MODULE_FAIL;
	    }
	    DEBUG("rlm_x99_token: auth: [%s], sync challenge %d %s, "
		  "expecting response %s", username, i, challenge, e_response);

	    /* Test user-supplied password. */
	    if (!strcmp(e_response, u_response)) {
		/* Yay!  User authenticated via sync mode.  Resync. */
		if (x99_get_sync_data(inst->syncdir,username,user_info.card_id,
				      1,0,challenge,user_info.keyblock) != 0) {
		    radlog(L_ERR, "rlm_x99_token: auth: unable to get "
				  "sync data e:%d t:%d for [%s] (for resync)",
				  1, 0, username);
		} else if (x99_set_sync_data(inst->syncdir, username, challenge,
					     user_info.keyblock) != 0) {
		    radlog(L_ERR, "rlm_x99_token: auth: unable to set sync "
				  "data for [%s] (for resync)", username);
		}
		if (x99_reset_failcount(inst->syncdir, username) != 0) {
		    radlog(L_ERR, "rlm_x99_token: auth: unable to reset "
				  "failure count for [%s]", username);
		}
		return RLM_MODULE_OK;
	    }

	} /* for (each slot in the window) */
    } /* if (card is in sync mode and sync mode allowed) */

    /* Both async and sync mode failed. */
    if (x99_incr_failcount(inst->syncdir, username) != 0) {
	radlog(L_ERR, "rlm_x99_token: auth: unable to increment failure "
		      "count for user [%s]", username);
    }
    return RLM_MODULE_REJECT;
}


/* per-instance destruction */
static int
x99_token_detach(void *instance)
{
    x99_token_t *inst = (x99_token_t *) instance;

    free(inst->pwdfile);
    free(inst->syncdir);
    free(inst->chal_text);
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
		NULL			/* checksimul */
	},
	x99_token_detach,		/* detach */
	x99_token_destroy,		/* destroy */
};
