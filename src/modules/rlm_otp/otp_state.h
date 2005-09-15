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
 * Copyright 2005 Frank Cusack
 */

#ifndef OTP_STATE_H
#define OTP_STATE_H

#include "otp.h"

static int otp_state_parse(const char *buf, size_t buflen,
			   const char *username, otp_user_state_t *user_state,
			   const char *log_prefix);
static int otp_state_unparse(char *buf, size_t buflen, const char *username,
			     otp_user_state_t *user_state,
			     const char *log_prefix);
static int xread(int *fdp, char *buf, size_t len, const char *log_prefix);
static int xwrite(int *fdp, const char *buf, size_t len,
		  const char *log_prefix);
static int *otp_state_getfd(const otp_option_t *opt, const char *log_prefix);
static void otp_state_putfd(int *fdp, int close_p);

#endif /* OTP_STATE_H */
