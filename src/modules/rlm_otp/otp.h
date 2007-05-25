/*
 * $Id$
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  For alternative licensing terms, contact licensing@tri-dsystems.com.
 *
 * Copyright 2005-2007 TRI-D Systems, Inc.
 */

#ifndef OTP_H
#define OTP_H

#include <freeradius-devel/ident.h>
RCSIDH(otp_h, "$Id$")

#include <sys/types.h>

/*
 * NOTE: This file must be synced between plugins/otpd/lsmd/gsmd/changepin.
 */

#ifndef OTP_MAX_CHALLENGE_LEN
#define OTP_MAX_CHALLENGE_LEN	16
#elif OTP_MAX_CHALLENGE_LEN != 16
#error OTP_MAX_CHALLENGE_LEN
#endif

#define OTP_RC_OK		0
#define OTP_RC_USER_UNKNOWN	1
#define OTP_RC_AUTHINFO_UNAVAIL	2
#define OTP_RC_AUTH_ERR		3
#define OTP_RC_MAXTRIES		4
#define OTP_RC_SERVICE_ERR	5
#define OTP_RC_NEXTPASSCODE	6
#define OTP_RC_IPIN		7

#define OTP_MAX_USERNAME_LEN		31
/* only needs to be MAX_PIN_LEN (16) + MAX_RESPONSE_LEN (16) */
#define OTP_MAX_PASSCODE_LEN		47
#define OTP_MAX_CHAP_CHALLENGE_LEN	16
#define OTP_MAX_CHAP_RESPONSE_LEN	50

typedef enum otp_pwe_t {
  PWE_PAP = 1,
  PWE_CHAP = 3,
  PWE_MSCHAP = 5,
  PWE_MSCHAP2 = 7,
} otp_pwe_t;

typedef struct otp_request_t {
  int	version;					/* 2 */
  char	username[OTP_MAX_USERNAME_LEN + 1];
  char	challenge[OTP_MAX_CHALLENGE_LEN + 1];		/* USER challenge */
  struct {
    otp_pwe_t	  pwe;
    union {
      struct {
        char	  passcode[OTP_MAX_PASSCODE_LEN + 1];
      } pap;
      struct {
        unsigned char challenge[OTP_MAX_CHAP_CHALLENGE_LEN]; /* CHAP chal */
        size_t	  clen;
        unsigned char response[OTP_MAX_CHAP_RESPONSE_LEN];
        size_t	  rlen;
      } chap;
    } u;
  } pwe;
  int		allow_async;		/* async auth allowed?           */
  int		allow_sync;		/* sync auth allowed?            */
  unsigned	challenge_delay;	/* min delay between async auths */
  int		resync;			/* resync on async auth?         */
} otp_request_t;

typedef struct otp_reply_t {
  int	version;					/* 1 */
  int	rc;
  char	passcode[OTP_MAX_PASSCODE_LEN + 1];
} otp_reply_t;

#endif /* OTP_H */
