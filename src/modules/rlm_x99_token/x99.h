/*
 * x99.h
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

#ifndef X99_H
#define X99_H

#include <openssl/des.h> /* des_cblock */

/*
 * Things you might like to change (although most are configurables)
 */

/* Default passwd file */
#define PWDFILE "/etc/x99passwd"

/* Default sync dir */
#define SYNCDIR "/etc/x99sync.d"

/* Default prompt for presentation of challenge */
#define CHALLENGE_PROMPT "Challenge: %s\n Response: "

/* Must be a multiple of sizeof(des_cblock) (8); read docs before changing. */
#define MAX_CHALLENGE_LEN 32

/* Password that means "challenge me" in fast_sync mode */
#define CHALLENGE_REQ "challenge"

/* Password that means "challenge me and resync" in fast_sync mode */
#define RESYNC_REQ "resync"

/* Max event window size for sync modes */
#define MAX_EWINDOW_SIZE 10
/* Max time window size for sync modes.  More than 10 may not be usable. */
#define MAX_TWINDOW_SIZE 10

/*
 * PRNG device that does not block;
 * /dev/urandom is "merely" cryptographically strong on Linux. :-)
 */
#define DEVURANDOM "/dev/urandom"


/*
 * You shouldn't change anything past this point
 */


/* struct used for instance/option data */
typedef struct x99_token_t {
    char *pwdfile;	/* file containing user:card_type:key entries      */
    char *syncdir;	/* dir containing sync mode and state info         */
    char *chal_prompt;	/* text to present challenge to user, must have %s */
    int chal_len;	/* challenge length, min 5 digits                  */
    int softfail;	/* number of auth fails before time delay starts   */
    int hardfail;	/* number of auth fails when user is locked out    */
    int allow_sync;	/* useful to override pwdfile card_type settings   */
    int fast_sync;	/* response-before-challenge mode                  */
    int allow_async;	/* C/R mode allowed?                               */
    char *chal_req;	/* keyword requesting challenge for fast_sync mode */
    char *resync_req;	/* keyword requesting resync for fast_sync mode    */
    int ewindow_size;	/* sync mode event window size (right side value)  */
#if defined(FREERADIUS)
    /* freeradius-specific items */
    int maxdelay;		/* max delay time for response, in seconds */
    int mschapv2_mppe_policy;	/* whether or not do to mppe for mschapv2  */
    int mschapv2_mppe_types;	/* key type/length for mschapv2/mppe       */
    int mschap_mppe_policy;	/* whether or not do to mppe for mschap    */
    int mschap_mppe_types;	/* key type/length for mschap/mppe         */
#elif defined(PAM)
    /* PAM specific items */
    int debug;		/* print debug info?                               */
    char *fast_prompt;	/* fast mode prompt                                */
#endif
#if 0
    int twindow_min;	/* sync mode time window left side                 */
    int twindow_max;	/* sync mode time window right side                */
#endif
} x99_token_t;

/* Bit maps for Card Features.  It is OK to insert values at will. */
#define X99_CF_NONE		0
/* Vendors */
#define X99_CF_CRYPTOCARD	0x01 << 0  /* CRYPTOCard             */
#define X99_CF_SNK		0x01 << 1  /* Symantec nee Axent nee */
					   /* AssureNet Pathways nee */
					   /* Digital Pathways       */
					   /* "SecureNet Key"        */
#define X99_CF_ACTIVCARD	0x01 << 2  /* ActivCard              */
#define X99_CF_SCOMPUTING	0x01 << 3  /* Secure Computing       */
#define X99_CF_VASCO		0x01 << 4  /* Vasco                  */
/* modes */
#define X99_CF_AM		0x01 << 5  /* async mode (chal/resp) */
#define X99_CF_ES		0x01 << 6  /* event synchronous      */
#define X99_CF_TS		0x01 << 7  /* time synchronous       */
/* display modes */
#define X99_CF_HD		0x01 << 8  /* hex display            */
#define X99_CF_DD		0x01 << 9  /* dec display            */
#define X99_CF_R8		0x01 << 10 /* 8 digit response       */
#define X99_CF_R7		0x01 << 11 /* 7 digit response       */
#define X99_CF_R6		0x01 << 12 /* 6 digit response       */
#define X99_CF_MAX		0x01 << 31 /* MAX placeholder        */

/* mask to test for sync mode */
#define X99_CF_SM (X99_CF_ES|X99_CF_TS)

/* cards and their features */
#define CRYPTOCARD_H8_RC (X99_CF_CRYPTOCARD|X99_CF_HD|X99_CF_R8|X99_CF_AM)
#define CRYPTOCARD_H7_RC (X99_CF_CRYPTOCARD|X99_CF_HD|X99_CF_R7|X99_CF_AM)
#define CRYPTOCARD_D8_RC (X99_CF_CRYPTOCARD|X99_CF_DD|X99_CF_R8|X99_CF_AM)
#define CRYPTOCARD_D7_RC (X99_CF_CRYPTOCARD|X99_CF_DD|X99_CF_R7|X99_CF_AM)
#define CRYPTOCARD_H8_ES (X99_CF_CRYPTOCARD|X99_CF_HD|X99_CF_R8|X99_CF_ES)
#define CRYPTOCARD_H7_ES (X99_CF_CRYPTOCARD|X99_CF_HD|X99_CF_R7|X99_CF_ES)
#define CRYPTOCARD_D8_ES (X99_CF_CRYPTOCARD|X99_CF_DD|X99_CF_R8|X99_CF_ES)
#define CRYPTOCARD_D7_ES (X99_CF_CRYPTOCARD|X99_CF_DD|X99_CF_R7|X99_CF_ES)
#define CRYPTOCARD_H8_RS (CRYPTOCARD_H8_RC|CRYPTOCARD_H8_ES)
#define CRYPTOCARD_H7_RS (CRYPTOCARD_H7_RC|CRYPTOCARD_H7_ES)
#define CRYPTOCARD_D8_RS (CRYPTOCARD_D8_RC|CRYPTOCARD_D8_ES)
#define CRYPTOCARD_D7_RS (CRYPTOCARD_D7_RC|CRYPTOCARD_D7_ES)

/* user-specific info */
typedef struct x99_user_info_t {
    uint32_t card_id;
    des_cblock keyblock;
} x99_user_info_t;


/* x99_mac.c */
extern int x99_response(const char *challenge, char response[17],
			uint32_t card_id, des_cblock keyblock);
extern int x99_mac(const char *input, des_cblock output, des_cblock keyblock);

/* x99_util.c */
/* Character maps for generic hex and vendor specific decimal modes */
extern const char x99_hex_conversion[];
extern const char x99_cc_dec_conversion[];
extern const char x99_snk_dec_conversion[];
extern const char x99_sc_friendly_conversion[];

extern int x99_get_challenge(int fd, char *challenge, int len);
extern int x99_get_random(int fd, unsigned char *rnd_data, int req_bytes);

extern int x99_string_to_keyblock(const char *s, des_cblock keyblock);
extern void x99_keyblock_to_string(char *s, const des_cblock keyblock,
				   const char conversion[17]);

extern int x99_get_user_info(const char *pwdfile, const char *username,
			     x99_user_info_t *user_info);

/* x99_sync.c */
extern int x99_get_sync_data(const char *syncdir, const char *username,
			     uint32_t card_id, int ewin, int twin,
			     char challenge[MAX_CHALLENGE_LEN + 1],
			     des_cblock keyblock);
extern int x99_set_sync_data(const char *syncdir, const char *username,
			     const char *challenge, const des_cblock keyblock);
extern int x99_check_failcount(const char *syncdir, const x99_token_t *inst);
extern int x99_incr_failcount(const char *syncdir, const char *username);
extern int x99_reset_failcount(const char *syncdir, const char *username);
extern int x99_get_last_auth(const char *syncdir, const char *username,
			      time_t *last_auth);
extern int x99_upd_last_auth(const char *syncdir, const char *username);

/* x99_site.c */
extern int x99_challenge_transform(const char *username,
				   char challenge[MAX_CHALLENGE_LEN + 1]);

/* x99_log.c */
extern void x99_log(int level, const char *format, ...);

#if defined(FREERADIUS)
#include "x99_rad.h"
#elif defined(PAM)
#include "x99_pam.h"
#endif

#endif /* X99_H */

