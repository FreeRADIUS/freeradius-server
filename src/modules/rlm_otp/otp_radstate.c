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
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

/* avoid inclusion of these FR headers which conflict w/ OpenSSL */
#define _FR_MD4_H
#define _FR_SHA1_H

#include "extern.h"

#include <string.h>
#include <openssl/des.h> /* des_cblock */
#include <openssl/md5.h>
#include <openssl/hmac.h>

/*
 * Generate the State attribute, suitable for passing to pairmake().
 * 'challenge' must be a null terminated string, and be sized at least
 * as large as indicated in the function definition.
 *
 * Returns 0 on success, non-zero otherwise.  For successful returns,
 * 'rad_state' (suitable for passing to pairmake()) and 'raw_state',
 * if non-NULL, will be filled in.
 *
 * In the simplest implementation, we would just use the challenge as state.
 * Unfortunately, the RADIUS secret protects only the User-Password
 * attribute; an attacker that can remove packets from the wire and insert
 * new ones can simply insert a replayed state without having to know
 * the secret.  If not for an attacker that can remove packets from the
 * network, I believe trivial state to be secure.
 *
 * So, we have to make up for that deficiency by signing our state with
 * data unique to this specific request.  A NAS would use the Request
 * Authenticator, but we don't know what that will be when the State is
 * returned to us, so we'll use the time.  So our replay prevention
 * is limited to a time interval (inst->challenge_delay).  We could keep
 * track of all challenges issued over that time interval for
 * better protection.
 *
 * Our state, then, is
 *   (challenge + flags + time + hmac(challenge + resync + time, key)),
 * where '+' denotes concatentation, 'challenge' is ... the challenge,
 * 'flags' is a 32-bit value that can be used to record additional info,
 * 'time' is the 32-bit time (LSB if time_t is 64 bits), and 'key' is a
 * random key, generated in otp_instantiate().  'flags' and 'time' are
 * in network byte order.
 *
 * As the signing key is unique to each server, only the server which
 * generates a challenge can verify it; this should be OK if your NAS's
 * load balance across RADIUS servers using a "first available" algorithm.
 * If your NAS's round-robin and don't "stick" to the same server if they
 * see a State attribute (ugh), you could use the RADIUS secret instead,
 * but read RFC 2104 first, and make very sure you really want to do this.
 *
 * Since only the "same server" can verify State, 'flags' and 'time' doesn't
 * really need to be in network byte order, but we do it anyway.
 *
 * The State attribute is an octet string, however some versions of Cisco
 * IOS and Catalyst OS (at least IOS 12.1(26)E4 and CatOS 7.6.12) treat it
 * as an ASCII string (they only return data up to the first NUL byte).
 * So we must handle state as an ASCII string (0x00 -> 0x3030).
 */
int
otp_gen_state(char rad_state[OTP_MAX_RADSTATE_LEN],
              unsigned char raw_state[OTP_MAX_RADSTATE_LEN],
              const unsigned char challenge[OTP_MAX_CHALLENGE_LEN],
              size_t clen,
              int32_t flags, int32_t when, const unsigned char key[16])
{
  HMAC_CTX hmac_ctx;
  unsigned char hmac[MD5_DIGEST_LENGTH];
  char *p;
  char state[OTP_MAX_RADSTATE_LEN];

  /*
   * Generate the hmac.  We already have a dependency on openssl for
   * DES, so we'll use it's hmac functionality also -- saves us from
   * having to collect the data to be signed into one contiguous piece.
   */
  HMAC_Init(&hmac_ctx, key, sizeof(key[0] * 16), EVP_md5());
  HMAC_Update(&hmac_ctx, challenge, clen);
  HMAC_Update(&hmac_ctx, (unsigned char *) &flags, 4);
  HMAC_Update(&hmac_ctx, (unsigned char *) &when, 4);
  HMAC_Final(&hmac_ctx, hmac, NULL);
  HMAC_cleanup(&hmac_ctx);

  /*
   * Generate the state.  Note that it is in ASCII.  The challenge
   * value doesn't have to be ASCII encoded, as it is already
   * ASCII, but we do it anyway, for consistency.
   */
#if 0
  /*
   * We used to malloc() state (here and in callers).  We leave this
   * here to show how OTP_MAX_RADSTATE_LEN is composed.  Note that
   * it has to be double all the values below to account for an
   * extra ASCII expansion (see Cisco notes, below).
   */
  state = rad_malloc(clen * 2 +			/* challenge */
                     8 +			/* flags     */
                     8 +			/* time      */
                     sizeof(hmac) * 2 +		/* hmac      */
                     1);			/* '\0'      */
#endif
  p = state;
  /* Add the challenge. */
  otp_x2a(challenge, clen, p);
  p += clen * 2;
  /* Add the flags and time. */
  otp_x2a((unsigned char *) &flags, 4, p);
  p += 8;
  otp_x2a((unsigned char *) &when, 4, p);
  p += 8;
  /* Add the hmac. */
  otp_x2a(hmac, 16, p);

  /*
   * Expand state (already ASCII) into ASCII again (0x31 -> 0x3331).
   * pairmake() forces us to do this (it will reduce it back to binary),
   * and to include a leading "0x".
   */
  if (rad_state) {
    (void) sprintf(rad_state, "0x");
    p = rad_state + 2;
    otp_x2a(state, strlen(state), p);
  }

  if (raw_state)
    (void) memcpy(raw_state, state, sizeof(state));

  return 0;
}
