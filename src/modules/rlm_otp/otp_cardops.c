/*
 * otp_cardops.c
 * $Id$
 *
 * Passcode verification functions for otp.
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
 *
 * Copyright 2002-2005  Google, Inc.
 * Copyright 2005 TRI-D Systems, Inc.
 */

static const char rcsid[] = "$Id$";

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE	/* RTLD_DEFAULT */
#endif
#include <dlfcn.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "otp.h"
#include "otp_cardops.h"

/* Global data */
cardops_t otp_cardops[OTP_MAX_VENDORS];	/* cardops objects */
int otp_num_cardops = 0;		/* number of cardops modules loaded */


/*
 * Test for passcode validity.
 *
 * If challenge is supplied, it is used to generate the card response
 * against which the passcode will be compared.  If challenge is not
 * supplied, or if the comparison fails, synchronous responses are
 * generated and tested.  NOTE: for async authentications, sync mode
 * responses are still considered valid!  (Assuming module configuration
 * allows sync mode.)
 *
 * If passcode is supplied, a simple string comparison is done, else if
 * cmp is supplied, it is called to test for validity.  The cmp function
 * is required for RADIUS, where we might have a CHAP response instead
 * of the plaintext of the passcode from the user.
 *
 * If challenge is supplied, then resync is used to determine if the card
 * should be resynced or if this is a one-off response.  (If challenge is
 * not supplied, this is sync mode response and the card is always resynced.)
 *
 * Returns one of the OTP_RC_* return codes.  challenge is overwritten.
 */
int
otp_pw_valid(const char *username, char *challenge, const char *passcode,
             int resync, const otp_option_t *opt,
             cmpfunc_t cmpfunc, void *data,
             const char *log_prefix)
{
  int	rc, nmatch, i;
  int	e = 0, t = 0;	/* must initialize for async auth path */
  int	fc;		/* failcondition */

    	/* expected response */
  char 	e_response[OTP_MAX_RESPONSE_LEN + OTP_MAX_PIN_LEN + 1];
  int	pin_offset = 0;	/* pin offset in e_response (prepend or append) */

  otp_card_info_t	card_info  = { .cardops = NULL };
  otp_user_state_t	user_state = { .locked = 0 };

  time_t now = time(NULL);

  /*
   * In the Cyclades ACS environment (2.3.0 tested), the runtime linker
   * apparently does not run static constructors in ELF .ctors sections.
   * Since that is how we initialize cardops modules, we have an ugly
   * workaround here.  Our other choice is to implement cardops modules
   * as full-fledged shared libraries, which is just too much work.
   */
  if (otp_num_cardops == 0) {
    void (*cardops_init)(void);

    /* ctors did not run; execute all known constructors */
    if ((cardops_init = dlsym(RTLD_DEFAULT, "cryptocard_init")))
      (*cardops_init)();
    if ((cardops_init = dlsym(RTLD_DEFAULT, "trid_init")))
      (*cardops_init)();
  }

  /* sanity */
  if (!challenge) {
    rc = OTP_RC_SERVICE_ERR;
    goto auth_done_service_err;
  }
  if (!passcode && !cmpfunc) {
    otp_log(OTP_LOG_CRIT, "%s: Can't test passcode validity!", log_prefix);
    rc = OTP_RC_SERVICE_ERR;
    goto auth_done_service_err;
  }

  /* Look up user info. */
  rc = otp_get_card_info(opt->pwdfile, username, &card_info);
  if (rc == -1) {
    otp_log(OTP_LOG_INFO, "%s: user [%s] not found in %s",
            log_prefix, username, opt->pwdfile);
    rc = OTP_RC_USER_UNKNOWN;
    goto auth_done_service_err;
  } else if (rc == -2) {
#if 0
    /* otp_get_card_info() logs a more useful message, this is noisy. */
    otp_log(OTP_LOG_ERR, "%s: error reading user [%s] info",
            log_prefix, username);
#endif
    rc = OTP_RC_AUTHINFO_UNAVAIL;
    goto auth_done_service_err;
  }
  card_info.username = username;

  /* Find the correct cardops module. */
  for (i = 0; otp_cardops[i].prefix; i++) {
    if (!strncasecmp(otp_cardops[i].prefix, card_info.card,
                     otp_cardops[i].prefix_len)) {
      card_info.cardops = &otp_cardops[i];
      break;
    }
  }
  if (!card_info.cardops) {
    otp_log(OTP_LOG_ERR, "%s: invalid card type '%s' for [%s]",
            log_prefix, card_info.card, username);
    rc = OTP_RC_SERVICE_ERR;
    goto auth_done_service_err;
  }

  /* Convert name to a feature mask once, for fast operations later. */
  if (card_info.cardops->name2fm(card_info.card, &card_info.featuremask)) {
    otp_log(OTP_LOG_ERR, "%s: invalid card type '%s' for [%s]",
            log_prefix, card_info.card, username);
    rc = OTP_RC_SERVICE_ERR;
    goto auth_done_service_err;
  }

  /* Convert keystring to a keyblock. */
  if (card_info.cardops->keystring2keyblock(card_info.keystring,
                                            card_info.keyblock) < 0) {
    otp_log(OTP_LOG_ERR, "%s: invalid key '%s' for [%s]",
            log_prefix, card_info.keystring, username);
    rc = OTP_RC_SERVICE_ERR;
    goto auth_done_service_err;
  }

  /* Adjust e_response for PIN prepend. */
  if (opt->prepend_pin) {
    (void) strcpy(e_response, card_info.pin);
    pin_offset = strlen(e_response);
  }

  /* Get user state. */
  if (otp_state_get(opt, username, &user_state, log_prefix) != 0) {
    otp_log(OTP_LOG_ERR, "%s: unable to get state for [%s]",
            log_prefix, username);
    rc = OTP_RC_SERVICE_ERR;
    goto auth_done_service_err;
  }
  if (user_state.nullstate) {
    if (card_info.cardops->nullstate(opt, &card_info, &user_state,
                                     now, log_prefix)) {
      otp_log(OTP_LOG_ERR, "%s: unable to set null state for [%s]",
              log_prefix, username);
      rc = OTP_RC_SERVICE_ERR;
      goto auth_done_service_err;
    }
  }

  /* Set fc (failcondition). */
  if (opt->hardfail && user_state.failcount >= (unsigned) opt->hardfail) {
    /* NOTE: persistent softfail stops working */
    fc = OTP_FC_FAIL_HARD;
  } else if (opt->softfail && user_state.authtime == INT32_MAX) {
    fc = OTP_FC_FAIL_SOFT;
  } else if (opt->softfail &&
             user_state.failcount >= (unsigned) opt->softfail) {
    uint32_t when;
    int fcount;

    /*
     * Determine the next time this user can authenticate.
     *
     * Once we hit softfail, we introduce a 1m delay before the user
     * can authenticate.  For each successive failed authentication,
     * we double the delay time, up to a max of 32 minutes.  While in
     * the "delay mode" of operation, all authentication ATTEMPTS are
     * considered failures.  Also, each attempt during the delay period
     * restarts the clock.
     *
     * The advantage of a delay instead of a simple lockout is that an
     * attacker can't lock out a user as easily; the user need only wait
     * a bit before he can authenticate.
     *
     * Note that if the user waits for the delay period to expire, he
     * is no longer in softfail and can only use ewindow, not rwindow.
     */
    fcount = user_state.failcount - opt->softfail;
    /*
     * when and authtime are uint32, but time is saved as int32,
     * so this can't overflow
     */
    when = user_state.authtime +
           (fcount > 5 ? 32 * 60 : (1 << fcount) * 60);
    if ((uint32_t) now < when)
      fc = OTP_FC_FAIL_SOFT;
    else
      fc = OTP_FC_FAIL_NONE;
  } else {
    fc = OTP_FC_FAIL_NONE;
  }

async_response:
  /*
   * Test async response.
   */
  if (*challenge && (card_info.featuremask & OTP_CF_AM) && opt->allow_async) {
    ssize_t chal_len;

    /* Perform any site-specific transforms of the challenge. */
    if ((chal_len = otp_challenge_transform(username,
                                            challenge, opt->chal_len)) < 0) {
      otp_log(OTP_LOG_ERR, "%s: challenge transform failed for [%s]",
              log_prefix, username);
      rc = OTP_RC_SERVICE_ERR;
      goto auth_done_service_err;
      /* NB: state not updated. */
    }

    /* Calculate the async response. */
    if (card_info.cardops->response(&card_info, challenge, chal_len,
                                    &e_response[pin_offset],
                                    log_prefix) != 0) {
      otp_log(OTP_LOG_ERR, "%s: unable to calculate async response for [%s], "
                           "to challenge %s", log_prefix, username, challenge);
      rc = OTP_RC_SERVICE_ERR;
      goto auth_done_service_err;
      /* NB: state not updated. */
    }

    /* NOTE: We do not display the PIN. */
    if (opt->debug) {
      char s[OTP_MAX_CHALLENGE_LEN * 2 + 1];

      otp_log(OTP_LOG_DEBUG,
              "%s: [%s], async challenge %s, expecting response %s",
              log_prefix, username,
              card_info.cardops->printchallenge(s, challenge, chal_len),
              &e_response[pin_offset]);
    }

    /* Add PIN if needed. */
    if (!opt->prepend_pin)
      (void) strcat(e_response, card_info.pin);

    /* Test user-supplied passcode. */
    if (passcode)
      nmatch = strcmp(passcode, e_response);
    else
      nmatch = cmpfunc(data, e_response);
    if (!nmatch) {
      if (!opt->allow_async) {
        otp_log(OTP_LOG_AUTH,
                "%s: bad async auth for [%s]: valid but disallowed by config",
                log_prefix, username);
        rc = OTP_RC_AUTH_ERR;
        goto auth_done;
      }
      if (fc == OTP_FC_FAIL_HARD) {
        otp_log(OTP_LOG_AUTH,
                "%s: bad async auth for [%s]: valid but in hardfail "
                " (%d/%d failed/max)", log_prefix, username,
                user_state.failcount, opt->hardfail);
        rc = OTP_RC_MAXTRIES;
        goto auth_done;
      }
      if (fc == OTP_FC_FAIL_SOFT) {
        otp_log(OTP_LOG_AUTH,
                "%s: bad async auth for [%s]: valid but in softfail "
                " (%d/%d failed/max)", log_prefix, username,
                user_state.failcount, opt->softfail);
        rc = OTP_RC_MAXTRIES;
        goto auth_done;
      }
#ifdef FREERADIUS
      if ((uint32_t) now - user_state.authtime < (unsigned) opt->chal_delay) {
        otp_log(OTP_LOG_AUTH,
                "%s: bad async auth for [%s]: valid but too soon",
                log_prefix, username);
        rc = OTP_RC_MAXTRIES;
        goto auth_done;
      }
#endif

      /* Authenticated in async mode. */
      rc = OTP_RC_OK;
      /* special log message for sync users */
      if (card_info.featuremask & OTP_CF_SM)
        otp_log(OTP_LOG_INFO, "%s: [%s] authenticated in async mode",
                log_prefix, username);
      goto auth_done;
    } /* if (user authenticated async) */
  } /* if (async mode possible) */

sync_response:
  /*
   * Calculate and test sync responses in the window.  Note that we
   * always accept a sync response, even if a challenge or resync was
   * explicitly requested.
   *
   * Note that we always start at the t=0 e=0 window position, even
   * though we may already know a previous authentication is further
   * ahead in the window (when in softfail).  This has the effect that
   * an rwindow softfail override can occur in a sequence like 6,3,4.
   * That is, the user can always move backwards in the window to
   * restart the rwindow sequence, as long as they don't go beyond
   * (prior to) the last successful authentication.
   */
  if ((card_info.featuremask & OTP_CF_SM) && opt->allow_sync) {
    int tend, end, ewindow, rwindow;

    /* set ending ewin counter */
    if (card_info.featuremask & OTP_CF_FRW) {
      /* force rwindow for e+t cards */
      rwindow = (card_info.featuremask & OTP_CF_FRW) >> OTP_CF_FRW_SHIFT;
      ewindow = 0; /* quiet compiler */
    } else {
      ewindow = opt->ewindow_size;
      /* Increase window for softfail+rwindow. */
      if (opt->rwindow_size && fc == OTP_FC_FAIL_SOFT)
        rwindow = opt->rwindow_size;
      else
        rwindow = 0;
    }
    end = rwindow ? rwindow : ewindow;

    /* Setup initial challenge. */
    (void) memcpy(challenge, user_state.challenge, user_state.clen);

    /* Test each sync response in the window. */
    tend = card_info.cardops->maxtwin(&card_info, user_state.csd);
    for (t = 0; t <= tend; ++t) {
      for (e = 0; e <= end; ++e) {
        /* Get next challenge. */
        rc = card_info.cardops->challenge(&card_info, &user_state, challenge,
                                          now, t, e, log_prefix);
        if (rc == -1) {
          otp_log(OTP_LOG_ERR,
                  "%s: unable to get sync challenge t:%d e:%d for [%s]",
                  log_prefix, t, e, username);
          rc = OTP_RC_SERVICE_ERR;
          goto auth_done_service_err;
          /* NB: state not updated. */
        } else if (rc == -2) {
          /*
           * For event synchronous modes, we can never go backwards (the
           * challenge() method can only walk forward on the event counter),
           * so there is an implicit guarantee that we'll never get a
           * response matching an event in the past.
           *
           * But for time synchronous modes, challenge() can walk backwards,
           * in order to accomodate clock drift.  We must never allow a
           * successful auth for a correct passcode earlier in time than
           * one already used successfully, so we skip out early here.
           */
          if (opt->debug)
            otp_log(OTP_LOG_DEBUG,
                    "%s: [%s], sync challenge t:%d e:%d is early",
                    log_prefix, username, t, e);
          continue;
        }

        /* Calculate sync response. */
        if (card_info.cardops->response(&card_info, challenge, user_state.clen,
                                        &e_response[pin_offset],
                                        log_prefix) != 0) {
          otp_log(OTP_LOG_ERR,
                  "%s: unable to calculate sync response "
                  "t:%d e:%d for [%s], to challenge %s",
                  log_prefix, t, e, username, challenge);
          rc = OTP_RC_SERVICE_ERR;
          goto auth_done_service_err;
          /* NB: state not updated. */
        }

        /* NOTE: We do not display the PIN. */
        if (opt->debug) {
          char s[OTP_MAX_CHALLENGE_LEN * 2 + 1];

          otp_log(OTP_LOG_DEBUG, "%s: [%s], sync challenge t:%d e:%d %s, "
                                 "expecting response %s",
                  log_prefix, username, t, e,
                  card_info.cardops->printchallenge(s, challenge,
                                                    user_state.clen),
                  &e_response[pin_offset]);
        }

        /* Add PIN if needed. */
        if (!opt->prepend_pin)
          (void) strcat(e_response, card_info.pin);

        /* Test user-supplied passcode. */
        if (passcode)
          nmatch = strcmp(passcode, e_response);
        else
          nmatch = cmpfunc(data, e_response);
        if (!nmatch) {
          if (fc == OTP_FC_FAIL_HARD) {
            otp_log(OTP_LOG_AUTH,
                    "%s: bad sync auth for [%s]: valid but in hardfail "
                    " (%d/%d failed/max)", log_prefix, username,
                    user_state.failcount, opt->hardfail);
            rc = OTP_RC_MAXTRIES;
          } else if (fc == OTP_FC_FAIL_SOFT) {
            /*
             * rwindow logic
             */
            if (!rwindow) {
              /* rwindow mode not configured */
              otp_log(OTP_LOG_AUTH,
                      "%s: bad sync auth for [%s]: valid but in softfail "
                      " (%d/%d failed/max)", log_prefix, username,
                      user_state.failcount, opt->softfail);
              rc = OTP_RC_MAXTRIES;
              goto auth_done;
            }

            /*
             * User must enter two consecutive correct sync passcodes
             * for rwindow softfail override.
             */
            if (card_info.cardops->isconsecutive(&card_info, &user_state,
                                                 e, log_prefix)) {
              /*
               * This is the 2nd of two consecutive responses, is it
               * soon enough?  Note that for persistent softfail we can't
               * enforce rwindow_delay b/c the previous authtime is also
               * the persistent softfail sentinel.
               */
              if (user_state.authtime == INT32_MAX ||
                  now - user_state.authtime < (unsigned) opt->rwindow_delay) {
                otp_log(OTP_LOG_AUTH,
                        "%s: rwindow softfail override for [%s] at "
                        "window position t:%d e:%d", log_prefix, username,
                        t, e);
                rc = OTP_RC_OK;
                goto sync_done;
              } else {
                /* consecutive but not soon enough */
                otp_log(OTP_LOG_AUTH,
                        "%s: late override for [%s] at "
                        "window position t:%d e:%d", log_prefix, username,
                        t, e);
                rc = OTP_RC_AUTH_ERR;
              }
            } /* if (passcode is consecutive */

            /* passcode correct, but not consecutive or not soon enough */
#if defined(FREERADIUS)
            DEBUG("rlm_otp_token: auth: [%s] rwindow candidate "
                  "at window position t:%d e:%d", username, t, e);
#elif defined(PAM)
            if (opt->debug)
              otp_log(OTP_LOG_DEBUG,
                      "%s: auth: [%s] rwindow candidate "
                      "at window position t:%d e:%d", log_prefix, username,
                      t, e);
#endif
            rc = OTP_RC_AUTH_ERR;

          } else {
            /* normal sync mode auth */
            rc = OTP_RC_OK;
          } /* else (!hardfail && !softfail) */

sync_done:
          /* force resync; this only has an effect if (rc == OTP_RC_OK) */
          resync = 1;
          /* update csd (et al.) on successful auth or rwindow candidate */
          if (card_info.cardops->updatecsd(&user_state, now, t, e, rc) != 0) {
            otp_log(OTP_LOG_ERR, "%s: unable to update csd for [%s]",
                    log_prefix, username);
            rc = OTP_RC_SERVICE_ERR;
            goto auth_done_service_err;
            /* NB: state not updated. */
          }
          goto auth_done;

        } /* if (passcode is valid) */
      } /* for (each slot in the ewindow) */
    } /* for (each slot in the twindow) */
  } /* if (sync mode possible) */

  /* Both async and sync mode failed. */
  rc = OTP_RC_AUTH_ERR;

auth_done:
  if (rc == OTP_RC_OK) {
    if (resync)
      (void) memcpy(user_state.challenge, challenge, user_state.clen);
    user_state.failcount   = 0;
    user_state.authtime    = now;
  } else {
    if (++user_state.failcount == UINT_MAX)
      user_state.failcount--;
    /* authtime set to INT32_MAX by nullstate(); leave it to force softfail */
    if (user_state.authtime != INT32_MAX)
      user_state.authtime = (int32_t) now;	/* cast prevents overflow */
    /*
     * Note that we don't update the challenge.  Even for softfail (where
     * we might have actually had a good auth), we want the challenge
     * unchanged because we always start our sync loop at e=0 t=0 (and so
     * challenge must stay as the 0'th challenge regardless of next valid
     * window position, because the challenge() method can't return
     * arbitrary event window positions--since we start at e=0 the challenge
     * must be the 0th challenge, i.e. unchanged).
     */
  } /* else (rc != OTP_RC_OK) */
  user_state.updated = 1;

auth_done_service_err:	/* exit here for system errors */
  /*
   * Release and update state.
   *
   * We "fail-out" if we can't do this, because for sync mode the
   * response can be reused until state data is updated, an obvious
   * replay attack.
   *
   * For async mode with RADIUS, if we can't update the last auth
   * time, we will be open to a less obvious replay attack over the
   * lifetime of the State attribute (opt->chal_delay): if someone
   * that can see RADIUS traffic captures an Access-Request containing
   * a State attribute, and can cause the NAS to cycle the request id
   * within opt->chal_delay secs, then they can login to the NAS and
   * insert the captured State attribute into the new Access-Request,
   * and we'll give an Access-Accept.
   */
  if (user_state.locked) {
    if (otp_state_put(username, &user_state, log_prefix) != 0) {
      otp_log(OTP_LOG_ERR, "%s: unable to put state for [%s]",
              log_prefix, username);
      rc = OTP_RC_SERVICE_ERR;	/* no matter what it might have been */
    }
  }

  return rc;
}
