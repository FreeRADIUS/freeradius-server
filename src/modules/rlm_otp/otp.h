/*
 * otp.h
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301,  USA
 *
 * Copyright 2001-2005 Google, Inc.
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

#ifndef OTP_H
#define OTP_H

#ifndef _REENTRANT
#define _REENTRANT
#endif
#include <pthread.h>

#include <inttypes.h>
#include <openssl/des.h> /* des_cblock */
#include <time.h>        /* time_t */
#include <sys/types.h>   /* size_t and ssize_t */

/*
 * Things you might like to change (although most are configurables)
 */

/* Default passwd file */
#define OTP_PWDFILE "/etc/otppasswd"

/* state manager rendezvous point */
#define OTP_LSMD_RP "/var/run/lsmd/socket"

/* Default prompt for presentation of challenge */
#define OTP_CHALLENGE_PROMPT "Challenge: %s\n Response: "

/* Must be a multiple of sizeof(des_cblock) (8); read src before changing. */
#define OTP_MAX_CHALLENGE_LEN 16

/* Password that means "challenge me" in fast_sync mode */
#define OTP_CHALLENGE_REQ "challenge"

/* Password that means "challenge me and resync" in fast_sync mode */
#define OTP_RESYNC_REQ "resync"

/* Max event window size for sync modes */
#define OTP_MAX_EWINDOW_SIZE 10
/* Max time window size for sync modes.  More than 10 may not be usable. */
#define OTP_MAX_TWINDOW_SIZE 10

/*
 * PRNG device that does not block;
 * /dev/urandom is "merely" cryptographically strong on Linux. :-)
 */
#define OTP_DEVURANDOM "/dev/urandom"


/*
 * You shouldn't change anything past this point
 */


/* struct used for instance/option data */
typedef struct otp_option_t {
  char *pwdfile;	/* file containing user:card_type:key entries      */
  char *lsmd_rp;	/* state manager rendezvous point                  */
  char *chal_prompt;	/* text to present challenge to user, must have %s */
  int chal_len;	        /* challenge length, min 5 digits                  */
  int softfail;	        /* number of auth fails before time delay starts   */
  int hardfail;	        /* number of auth fails when user is locked out    */
  int fast_sync;	/* response-before-challenge mode                  */
  int allow_sync;	/* useful to override pwdfile card_type settings   */
  int allow_async;	/* C/R mode allowed?                               */
  char *chal_req;	/* keyword requesting challenge for fast_sync mode */
  char *resync_req;	/* keyword requesting resync for fast_sync mode    */
  int prepend_pin;	/* prepend (vs. append) PIN?                       */
  int ewindow_size;	/* sync mode event window size (right side value)  */
  int rwindow_size;	/* softfail override event window size             */
  int rwindow_delay;	/* softfail override max time delay                */
  int site_transform;	/* apply site transform to challenge? (undoc)      */
  int debug;		/* print debug info?                               */
#if defined(FREERADIUS)
  /* freeradius-specific items */
  int chal_delay;		/* max delay time for response, in seconds */
  const char *name;		/* instance name for otp_token_authorize() */
  int mschapv2_mppe_policy;	/* whether or not do to mppe for mschapv2  */
  int mschapv2_mppe_types;	/* key type/length for mschapv2/mppe       */
  int mschap_mppe_policy;	/* whether or not do to mppe for mschap    */
  int mschap_mppe_types;	/* key type/length for mschap/mppe         */
#elif defined(PAM)
  /* PAM specific items */
  char *fast_prompt;	/* fast mode prompt                                */
#endif
} otp_option_t;

/* user-specific info */
#define OTP_MAX_CARDNAME_LEN 32
#define OTP_MAX_KEY_LEN 256
#define OTP_MAX_PIN_LEN 256
struct cardops_t;
typedef struct otp_card_info_t {
  const char *username;
  struct cardops_t *cardops;

  char card[OTP_MAX_CARDNAME_LEN + 1];
  uint32_t featuremask;

  char keystring[OTP_MAX_KEY_LEN * 2 + 1];
  unsigned char keyblock[OTP_MAX_KEY_LEN];
  char pin[OTP_MAX_PIN_LEN + 1];
#if 0
  void *keyschedule;
#endif
} otp_card_info_t;

/* state manager fd pool */
typedef struct lsmd_fd_t {
  pthread_mutex_t	mutex;
  int			fd;
  struct lsmd_fd_t	*next;
} lsmd_fd_t;

/* user-specific state info */
#define OTP_MAX_CSD_LEN 64
#define OTP_MAX_RD_LEN 8
typedef struct otp_user_state_t {
  int		locked;			/* locked aka success flag        */
  lsmd_fd_t	*fdp;			/* fd for return data             */
  int		nullstate;		/* null state?                    */
  int		updated;		/* state updated? (1 unless err)  */
  ssize_t	clen;			/* challenge length               */

  unsigned char	challenge[OTP_MAX_CHALLENGE_LEN];	/* prev sync chal */
  char		csd[OTP_MAX_CSD_LEN+1];	/* card-specific data             */
  char		rd[OTP_MAX_RD_LEN+1];	/* rwindow data                   */
  uint32_t	failcount;		/* number of consecutive failures */
  uint32_t	authtime;		/* time of last auth              */
  uint32_t   	mincardtime;		/* minimum cardtime               */

  int32_t	scratch1;		/* card-specific scratch data     */
  int32_t	scratch2;		/* card-specific scratch data     */
  int32_t	scratch3;		/* card-specific scratch data     */
} otp_user_state_t;

/* fc (failcondition) shortcuts */
#define OTP_FC_FAIL_NONE 0	/* no failures */
#define OTP_FC_FAIL_HARD 1	/* failed hard */
#define OTP_FC_FAIL_SOFT 2	/* failed soft */

/* otp_cardops.c */
/* return codes from otp_pw_valid() */
#define OTP_RC_OK		0
#define OTP_RC_USER_UNKNOWN	1
#define OTP_RC_AUTHINFO_UNAVAIL	2
#define OTP_RC_AUTH_ERR		3
#define OTP_RC_MAXTRIES		4
#define OTP_RC_SERVICE_ERR	5
struct otp_pwe_cmp_t;
typedef int (*cmpfunc_t)(struct otp_pwe_cmp_t *, const char *, const char *);
extern int otp_pw_valid(const char *, char *, const char *, int,
                        const otp_option_t *, cmpfunc_t, void *, const char *);

/* otp_x99.c */
extern int otp_x99_mac(const unsigned char *, size_t, unsigned char [8],
                       const unsigned char [OTP_MAX_KEY_LEN], const char *);

/* otp_hotp.c */
extern int otp_hotp_mac(const unsigned char [8], unsigned char [7],
                        const unsigned char [OTP_MAX_KEY_LEN], size_t,
                        int, const char *);

/* otp_util.c */
/* Character maps for generic hex and vendor specific decimal modes */
extern const char otp_hex_conversion[];
extern const char otp_cc_dec_conversion[];
extern const char otp_snk_dec_conversion[];
extern const char otp_sc_friendly_conversion[];

extern int otp_get_random(int, unsigned char *, int, const char *);
extern int otp_async_challenge(int, char *, int, const char *);

extern ssize_t otp_keystring2keyblock(const char *, unsigned char []);
extern char *otp_keyblock2keystring(char *, const unsigned char [], size_t,
                                    const char [17]);

extern int otp_get_card_info(const char *, const char *, otp_card_info_t *,
                             const char *);

/* otp_state.c */
extern int otp_state_get(const otp_option_t *, const char *,
                         otp_user_state_t *, const char *);
extern int otp_state_put(const char *, otp_user_state_t *, const char *);

/* otp_site.c */
extern ssize_t otp_challenge_transform(const char *,
                                       unsigned char [OTP_MAX_CHALLENGE_LEN],
                                       size_t);

/* otp_log.c */
extern void otp_log(int, const char *, ...);

#if defined(FREERADIUS)
#include "otp_rad.h"
#elif defined(PAM)
#include "otp_pam.h"
#endif

#endif /* OTP_H */
