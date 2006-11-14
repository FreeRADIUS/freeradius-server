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
 * Copyright 2006 TRI-D Systems, Inc.
 */

#ifndef OTP_PW_VALID_H
#define OTP_PW_VALID_H

#include <freeradius-devel/ident.h>
RCSIDH(otp_pw_valid_h, "$Id$")

#include <pthread.h>
#include <sys/types.h>
#include "extern.h"	/* otp_option_t */
#include "otp.h"	/* otp_request_t, otp_reply_t */

typedef struct otp_fd_t {
  pthread_mutex_t	mutex;
  const char		*path;	/* allows diff instances to use diff otpds */
  int			fd;
  struct otp_fd_t	*next;
} otp_fd_t;

static int otprc2rlmrc(int);
static int otp_verify(const otp_option_t *,
                      const otp_request_t *, otp_reply_t *);
static int otp_read(otp_fd_t *, char *, size_t);
static int otp_write(otp_fd_t *, const char *, size_t);
static int otp_connect(const char *);
static otp_fd_t *otp_getfd(const otp_option_t *);
static void otp_putfd(otp_fd_t *, int);

#endif /* OTP_PW_VALID_H */
