/*
 * otp_state.h
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

#ifndef OTP_STATE_H
#define OTP_STATE_H

#include "otp.h"

static int otp_state_parse(const char *, size_t, const char *,
                           otp_user_state_t *, const char *);
static ssize_t otp_state_unparse(char *, size_t, const char *,
				 otp_user_state_t *, const char *);
static int xread(lsmd_fd_t *, char *, size_t, const char *);
static int xwrite(lsmd_fd_t *, const char *, size_t, const char *);
static int otp_state_connect(const char *, const char *);
static lsmd_fd_t *otp_state_getfd(const otp_option_t *, const char *);
static void otp_state_putfd(lsmd_fd_t *, int, const char *);

#endif /* OTP_STATE_H */
