/*
 * x99_rad.h
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
 * Copyright 2001,2002  Google, Inc.
 */

#ifndef X99_RAD_H
#define X99_RAD_H

#define X99_LOG_ERR  L_ERR
#define X99_LOG_AUTH L_AUTH
#define X99_LOG_INFO L_INFO

/* struct used for instance data */
typedef struct x99_token_t {
    char *pwdfile;	/* file containing user:card_type:key entries      */
    char *syncdir;	/* dir containing sync mode and state info         */
    char *chal_text;	/* text to present challenge to user, must have %s */
    int chal_len;	/* challenge length, min 5 digits                  */
    int maxdelay;	/* max delay time for response, in seconds         */
    int softfail;	/* number of auth fails before time delay starts   */
    int hardfail;	/* number of auth fails when user is locked out    */
    int allow_sync;	/* useful to override pwdfile card_type settings   */
    int fast_sync;	/* response-before-challenge mode                  */
    int allow_async;	/* C/R mode allowed?                               */
    char *chal_req;	/* keyword requesting challenge for fast_sync mode */
    char *resync_req;	/* keyword requesting resync for fast_sync mode    */
    int ewindow_size;	/* sync mode event window size (right side value)  */
    int mschapv2_mppe_policy;	/* whether or not do to mppe for mschapv2  */
    int mschapv2_mppe_types;	/* key type/length for mschapv2/mppe       */
    int mschap_mppe_policy;	/* whether or not do to mppe for mschap    */
    int mschap_mppe_types;	/* key type/length for mschap/mppe         */
#if 0
    int twindow_min;	/* sync mode time window left side                 */
    int twindow_max;	/* sync mode time window right side                */
#endif
} x99_token_t;

/* x99_state.c */
extern int x99_gen_state(char **ascii_state, unsigned char **raw_state,
			 const char challenge[MAX_CHALLENGE_LEN + 1],
			 int32_t flags, int32_t when,
			 const unsigned char key[16]);

/* x99_pwe.c */
#include "radiusd.h"     /* REQUEST */
#include "libradius.h"   /* VALUE_PAIR */
extern void x99_pwe_init(void);
extern int x99_pw_present(const REQUEST *request);
extern int x99_pw_valid(const REQUEST *request, x99_token_t *inst,
			int attr, const char *password, VALUE_PAIR **vps);

#endif /* X99_RAD_H */

