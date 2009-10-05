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
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

#ifndef EXTERN_H
#define EXTERN_H

#include <freeradius-devel/ident.h>
RCSIDH(extern_h, "$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <sys/types.h>
#include <pthread.h>

#include "otp.h"	/* OTP_MAX_CHALLENGE_LEN, otp_pwe_t */

/* otpd rendezvous point */
#define OTP_OTPD_RP "/var/run/otpd/socket"

/* Default prompt for presentation of challenge */
#define OTP_CHALLENGE_PROMPT "Challenge: %s\n Response: "


/*
 * You shouldn't change anything past this point
 */


/* struct used for instance/option data */
typedef struct otp_option_t {
  const char *name;	/* instance name for otp_token_authorize()         */
  char *otpd_rp;	/* otpd rendezvous point                           */
  char *chal_prompt;	/* text to present challenge to user, must have %s */
  int challenge_len;	/* challenge length, min 5 digits                  */
  int challenge_delay;	/* max delay time for response, in seconds         */
  int allow_sync;	/* useful to override pwdfile card_type settings   */
  int allow_async;	/* C/R mode allowed?                               */

  int mschapv2_mppe_policy;	/* whether or not do to mppe for mschapv2  */
  int mschapv2_mppe_types;	/* key type/length for mschapv2/mppe       */
  int mschap_mppe_policy;	/* whether or not do to mppe for mschap    */
  int mschap_mppe_types;	/* key type/length for mschap/mppe         */
} otp_option_t;

/* otp_mppe.c */
void otp_mppe(REQUEST *, otp_pwe_t, const otp_option_t *, const char *);

/* otp_pw_valid.c */
extern int otp_pw_valid(REQUEST *, int, const char *, const otp_option_t *,
                        char []);

/* otp_radstate.c */
#define OTP_MAX_RADSTATE_LEN 2 + (OTP_MAX_CHALLENGE_LEN * 2 + 8 + 8 + 32)*2 + 1
extern int otp_gen_state(char [OTP_MAX_RADSTATE_LEN],
                         unsigned char [OTP_MAX_RADSTATE_LEN],
                         const unsigned char [OTP_MAX_CHALLENGE_LEN], size_t,
                         int32_t, int32_t, const unsigned char [16]);

/* otp_pwe.c */
extern DICT_ATTR *pwattr[8];
extern void otp_pwe_init(void);
extern otp_pwe_t otp_pwe_present(const REQUEST *);

/* otp_util.c */
extern void otp_get_random(char *, size_t);
extern void otp_async_challenge(char [OTP_MAX_CHALLENGE_LEN + 1], int);
extern int otp_a2x(const char *, unsigned char *);
extern void otp_x2a(const unsigned char *, size_t, char *);
extern void _otp_pthread_mutex_init(pthread_mutex_t *,
                                    const pthread_mutexattr_t *, const char *);
extern void _otp_pthread_mutex_lock(pthread_mutex_t *, const char *);
extern int _otp_pthread_mutex_trylock(pthread_mutex_t *, const char *);
extern void _otp_pthread_mutex_unlock(pthread_mutex_t *, const char *);

#define otp_pthread_mutex_init(a, b) _otp_pthread_mutex_init((a), (b), __func__)
#define otp_pthread_mutex_lock(a) _otp_pthread_mutex_lock((a), __func__)
#define otp_pthread_mutex_trylock(a) _otp_pthread_mutex_trylock((a), __func__)
#define otp_pthread_mutex_unlock(a) _otp_pthread_mutex_unlock((a), __func__)

#endif /* EXTERN_H */
