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
 * Copyright 2001  Google, Inc.
 */

#ifndef X99_H
#define X99_H

#include <openssl/des.h> /* des_cblock */

/*
 * Things you might like to change
 */

/* Default text for presentation of challenge */
#define CHALLENGE_TEXT "Challenge: %s\n Response: "
/* Must be a multiple of sizeof(des_cblock) (8); read docs before changing. */
#define MAX_CHALLENGE_LEN 32
/* Password that means "challenge me" in fast_sync mode */
#define CHALLENGE_REQ "challenge"

/* Max event window size for sync modes */
#define MAX_EWINDOW_SIZE 10
/* Max time window size for sync modes.  More than 10 may not be usable. */
#define MAX_TWINDOW_SIZE 10


/*
 * You shouldn't change anything past this point
 */

/*
 * PRNG device that does not block;
 * /dev/urandom is "merely" cryptographically strong on Linux. :-)
 */
#define DEVURANDOM "/dev/urandom"

/* Bit maps for Card Features.  It is OK to insert values at will. */
#define X99_CF_NONE		0
/* Vendors */
#define X99_CF_CRYPTOCARD	0x01 << 0  /* CRYPTOCard             */
#define X99_CF_SNK		0x01 << 1  /* Symantec ne Axent ne   */
					   /* AssureNet Pathways ne  */
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

/* x99_state.c */
extern int x99_gen_state(char **ascii_state, unsigned char **raw_state,
			 const char challenge[MAX_CHALLENGE_LEN + 1],
			 int32_t when, const unsigned char key[16]);

/* x99_util.c */
/* Character maps for generic hex and vendor specific decimal modes */
extern const char x99_hex_conversion[];
extern const char x99_cc_dec_conversion[];
extern const char x99_snk_dec_conversion[];
extern const char x99_sc_friendly_conversion[];

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
extern int x99_get_failcount(const char *syncdir, const char *username,
			     int *failcount);
extern int x99_incr_failcount(const char *syncdir, const char *username);
extern int x99_reset_failcount(const char *syncdir, const char *username);
extern int x99_get_last_async(const char *syncdir, const char *username,
			      time_t *last_async);
extern int x99_upd_last_async(const char *syncdir, const char *username);

/* x99_site.c */
extern int x99_challenge_transform(const char *username,
				   char challenge[MAX_CHALLENGE_LEN + 1]);

#endif /* X99_H */

