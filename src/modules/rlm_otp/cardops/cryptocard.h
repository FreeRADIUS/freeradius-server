/*
 * cryptocard.h
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

#ifndef CRYPTOCARD_H
#define CRYPTOCARD_H

#include "../otp_cardops.h"

/* card modes */
#define CRYPTOCARD_H8_RC (OTP_CF_HD|OTP_CF_R8|OTP_CF_AM)
#define CRYPTOCARD_H7_RC (OTP_CF_HD|OTP_CF_R7|OTP_CF_AM)
#define CRYPTOCARD_D8_RC (OTP_CF_DD|OTP_CF_R8|OTP_CF_AM)
#define CRYPTOCARD_D7_RC (OTP_CF_DD|OTP_CF_R7|OTP_CF_AM)
#define CRYPTOCARD_H8_ES (OTP_CF_HD|OTP_CF_R8|OTP_CF_ES)
#define CRYPTOCARD_H7_ES (OTP_CF_HD|OTP_CF_R7|OTP_CF_ES)
#define CRYPTOCARD_D8_ES (OTP_CF_DD|OTP_CF_R8|OTP_CF_ES)
#define CRYPTOCARD_D7_ES (OTP_CF_DD|OTP_CF_R7|OTP_CF_ES)
#define CRYPTOCARD_H8_RS (CRYPTOCARD_H8_RC|CRYPTOCARD_H8_ES)
#define CRYPTOCARD_H7_RS (CRYPTOCARD_H7_RC|CRYPTOCARD_H7_ES)
#define CRYPTOCARD_D8_RS (CRYPTOCARD_D8_RC|CRYPTOCARD_D8_ES)
#define CRYPTOCARD_D7_RS (CRYPTOCARD_D7_RC|CRYPTOCARD_D7_ES)

static int cryptocard_name2fm(const char *, uint32_t *);
static int cryptocard_keystring2keyblock(const char *, unsigned char []);
static int cryptocard_nullstate(const otp_option_t *, const otp_user_info_t *,
                                otp_user_state_t *, const char *);
static int cryptocard_challenge(const otp_user_info_t *,
                                const char [OTP_MAX_CSD_LEN + 1],
                                char [OTP_MAX_CHALLENGE_LEN + 1],
                                unsigned, const char *);
static int cryptocard_response(otp_user_info_t *, char *, const char *,
                               char [OTP_MAX_RESPONSE_LEN + 1], const char *);
static int cryptocard_updatecsd(const otp_user_info_t *, otp_user_state_t *,
                                const char *);

#ifdef __GNUC__
__attribute__ ((constructor))
#endif
void cryptocard_init(void);

#endif /* CRYPTOCARD_H */
