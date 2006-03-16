/*
 * otp_site.c
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
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

/*
 * IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT
 *
 * In order to safely use challenge/response (async) mode, you must
 * - implement a site-specific transform of the challenge, and/or
 * - only allow async mode from secure locations.
 *
 * Please read the accompanying docs for more info.
 *
 * IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT
 */

#include "otp.h"
#include <string.h>

static const char rcsid[] = "$Id$";


/*
 * The default transform appends the first 2 username chars to the
 * challenge.  This results in a challenge that generally cannot be
 * entered on any supported token, thus forcing a site-specific
 * implementation to support async mode.
 */
ssize_t
otp_challenge_transform(const char *username,
                        unsigned char challenge[OTP_MAX_CHALLENGE_LEN],
                        size_t clen)
{
  /* overwrite challenge in-place if not enough room */
  switch (OTP_MAX_CHALLENGE_LEN - clen) {
    case 0: clen -= 2; break;
    case 1: clen -= 1; break;
  }

  /* append first 2 username chars to challenge */
  if (*username)
    challenge[clen++] = *username++;
  if (*username)
    challenge[clen++] = *username++;

  return clen;
}
