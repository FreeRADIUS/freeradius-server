/*
 * otp_cardops.h
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
 * Copyright 2005 TRI-D Systems, Inc.
 */

#ifndef OTP_CARDOPS_H
#define OTP_CARDOPS_H

#include "otp.h"

/*
 * Card Features bitmask.
 */
#define OTP_CF_NONE		0
/* sync/async modes */
#define OTP_CF_AM		0x01 << 1  /* async mode (chal/resp) */
#define OTP_CF_ES		0x01 << 2  /* event synchronous      */
#define OTP_CF_TS		0x01 << 3  /* time synchronous       */
#define OTP_CF_SM		(OTP_CF_ES|OTP_CF_TS)
/* display modes */
#define OTP_CF_HD		0x01 << 4  /* hex display            */
#define OTP_CF_DD		0x01 << 5  /* dec display            */
#define OTP_CF_R8		0x01 << 6  /* 8 digit response       */
#define OTP_CF_R7		0x01 << 7  /* 7 digit response       */
#define OTP_CF_R6		0x01 << 8  /* 6 digit response       */
/* nominal twindow (TRI-D) */
#define OTP_CF_TW0		0x01 << 9  /* twindow 2^0            */
#define OTP_CF_TW1		0x01 << 10 /* twindow 2^1            */
#define OTP_CF_TW2		0x01 << 11 /* twindow 2^2            */
#define OTP_CF_TW3		0x01 << 12 /* twindow 2^3            */
#define OTP_CF_TW		(OTP_CF_TW0|OTP_CF_TW1|OTP_CF_TW2|OTP_CF_TW3)
#define OTP_CF_TW_SHIFT		9          /* convert mask to value  */
/* force rwindow for event+time sync cards (TRI-D) */
#define OTP_CF_FRW0		0x01 << 13 /* force event window 2^0 */
#define OTP_CF_FRW1		0x01 << 14 /* force event window 2^1 */
#define OTP_CF_FRW2		0x01 << 15 /* force event window 2^2 */
#define OTP_CF_FRW		(OTP_CF_FRW0|OTP_CF_FRW1|OTP_CF_FRW2)
#define OTP_CF_FRW_SHIFT	13         /* convert mask to value  */
/* vendor specific */
#define OTP_CF_VS1		0x01 << 16 /* vendor specific 1      */
#define OTP_CF_VS2		0x01 << 17 /* vendor specific 2      */
#define OTP_CF_VS3		0x01 << 18 /* vendor specific 3      */
#define OTP_CF_VS4		0x01 << 19 /* vendor specific 4      */

#define OTP_CF_MAX		0x01 << 31 /* MAX placeholder        */

#define OTP_MAX_RESPONSE_LEN 16		/* Secure Computing can do 16 */

/* cardops object */
typedef struct cardops_t {
  const char *prefix;
  size_t prefix_len;	/* to avoid strlen(prefix) */

  int (*name2fm)(const char *, uint32_t *);
  int (*keystring2keyblock)(const char *, unsigned char [OTP_MAX_KEY_LEN]);
  int (*nullstate)(const otp_option_t *, const otp_user_info_t *,
                   otp_user_state_t *, time_t, const char *);
  int (*challenge)(const otp_user_info_t *, const char [OTP_MAX_CSD_LEN + 1],
                   time_t, char [OTP_MAX_CHALLENGE_LEN + 1], unsigned,
                   unsigned, const char *);
  int (*response)(otp_user_info_t *, const char [OTP_MAX_CSD_LEN + 1],
                  const char [OTP_MAX_CHALLENGE_LEN + 1],
                  char [OTP_MAX_RESPONSE_LEN + 1], const char *);
  int (*updatecsd)(const otp_user_info_t *, otp_user_state_t *,
                   const char [OTP_MAX_CHALLENGE_LEN + 1],
                   int, time_t, int, const char *);
  int (*isearly)(const otp_user_state_t *, time_t, int, const char *);
  int (*nexttwin)(int);
  int (*maxtwin)(const otp_user_info_t *, const char [OTP_MAX_CSD_LEN + 1],
                 time_t);
  time_t (*twin2authtime)(const char [OTP_MAX_CSD_LEN + 1], time_t, int,
                          const char *);
} cardops_t;
#define OTP_MAX_VENDORS 16
extern cardops_t otp_cardops[OTP_MAX_VENDORS];
extern int otp_num_cardops;

#endif /* OTP_CARDOPS_H */
