/*
 * otp_rad.h
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
 * Copyright 2005 TRI-D Systems, Inc.
 */

#ifndef OTP_RAD_H
#define OTP_RAD_H

#include "autoconf.h"
#include "radiusd.h"
#define OTP_LOG_DEBUG L_DBG
#define OTP_LOG_ERR   L_ERR
#define OTP_LOG_AUTH  L_AUTH
#define OTP_LOG_INFO  L_INFO
#define OTP_LOG_CRIT  (L_ERR|L_CONS)

/* otp_radstate.c */
extern int otp_gen_state(char **, unsigned char **,
                         const unsigned char [OTP_MAX_CHALLENGE_LEN], size_t,
                         int32_t, int32_t, const unsigned char [16]);

/* otp_pwe.c */
#include "libradius.h"   /* VALUE_PAIR */
struct otp_pwe_cmp_t {
  const REQUEST		*request;
  const otp_option_t	*inst;
  int			pwattr;	/* return value from otp_pwe_present() */
  VALUE_PAIR		**returned_vps;
};
extern void otp_pwe_init(void);
extern int otp_pwe_present(const REQUEST *);
extern int otp_pwe_cmp(struct otp_pwe_cmp_t *, const char *);

#endif /* OTP_RAD_H */
