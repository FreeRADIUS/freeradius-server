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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005 TRI-D Systems, Inc.
 */

/*
 * IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT
 *
 * In order to safely use challenge/response (async) mode, you must
 * - implement a site-specific transform of the challenge, and/or
 * - only allow async mode from secure locations.
 *
 * Note that you cannot easily just disallow async mode completely
 * as you typically must provide a way to resynchronize the token.
 *
 * Please read the accompanying docs for more info.
 *
 * IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT  IMPORTANT
 */

#include "otp.h"
#include <string.h>

static const char rcsid[] = "$Id$";


ssize_t
otp_challenge_transform(
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                        const char *username,
                        unsigned char challenge[OTP_MAX_CHALLENGE_LEN],
                        size_t clen)
{
  unsigned i;

  for (i = 0; i < clen; ++clen)
    challenge[i] = '\0';

  return clen;
}
