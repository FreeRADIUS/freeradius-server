/*
 * x99_cardops.h
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
 * Copyright 2005 Frank Cusack
 */

#ifndef X99_CARDOPS_H
#define X99_CARDOPS_H

/*
 * Card Features bitmask.
 */
#define X99_CF_NONE		0
/* sync/async modes */
#define X99_CF_AM		0x01 << 1  /* async mode (chal/resp) */
#define X99_CF_ES		0x01 << 2  /* event synchronous      */
#define X99_CF_TS		0x01 << 3  /* time synchronous       */
#define X99_CF_SM		(X99_CF_ES|X99_CF_TS)
/* display modes */
#define X99_CF_HD		0x01 << 4  /* hex display            */
#define X99_CF_DD		0x01 << 5  /* dec display            */
#define X99_CF_R8		0x01 << 6  /* 8 digit response       */
#define X99_CF_R7		0x01 << 7  /* 7 digit response       */
#define X99_CF_R6		0x01 << 8  /* 6 digit response       */

#define X99_CF_MAX		0x01 << 31 /* MAX placeholder        */

#define X99_MAX_RESPONSE_LEN 16		/* Secure Computing can do 16 */

/* cardops object */
typedef struct cardops_t {
    const char *prefix;
    size_t prefix_len;	/* to avoid strlen(prefix) */

    int (*name2fm)(const char *name, uint32_t *featuremask);
    int (*keystring2keyblock)(const char *keystring, unsigned char keyblock[]);
    int (*challenge)(const char *syncdir, x99_user_info_t *user_info,
		     int ewin, int twin, char challenge[]);
    int (*response)(x99_user_info_t *user_info, const char *challenge,
		    char response[X99_MAX_RESPONSE_LEN + 1]);
} cardops_t;
#define X99_MAX_VENDORS 16
extern cardops_t x99_cardops[X99_MAX_VENDORS];
extern int x99_num_cardops;

#endif /* X99_CARDOPS_H */
