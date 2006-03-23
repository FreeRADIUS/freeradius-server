/*
 * otp_hotp.c
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301,  USA
 *
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

#include <openssl/hmac.h>

#include "otp.h"

static const char rcsid[] = "$Id$";


/*
 * This implements HOTP per RFC4226, for Digit = 6, 7, 8, 9.
 * (Not explicit in RFC4226, except mentioned as an aside in section E.2,
 *  the maximum OTP length is 9 digits due to the 32-bit restriction in
 *  step 3.  Note that sample code in RFC4226 is wrong in that they allow
 *  Digit = 1-5 as well; RFC4226 is explicit that the minimum value for
 *  Digit is 6.)
 *
 * The HOTP algorithm is:
 * 1. HS = HMAC-SHA-1(K, C)
 *    Take the SHA-1 HMAC of the key (K) and counter (C).
 * 2. S = DT(HS)
 *    Take the "Dynamic Truncation" of the HMAC.
 * 3. HOTP = StToNum(S) % 10^Digit
 *    Take the modulus of S as a bigendian integer.
 *
 * Returns 0 on success, -1 on failure.  output is the ASCII HOTP on success.
 */
int
otp_hotp_mac(const unsigned char counter[8], unsigned char output[7],
             const unsigned char keyblock[OTP_MAX_KEY_LEN], size_t key_len,
             int d, const char *log_prefix)
{
  unsigned char hmac[EVP_MAX_MD_SIZE];	/* >=20 */
  int hmac_len = 0;
  uint32_t dbc;		/* "dynamic binary code" from HOTP draft */
  long dmod[10] = { 0, 0, 0, 0, 0, 0,		/* modulus table */
                    1000000L, 10000000L, 100000000L, 1000000000L };
  char *fmt[10] = { 0, 0, 0, 0, 0, 0,		/* format table  */
                    "%06lu", "%07lu", "%08lu", "%09lu" };

  /* 1. hmac */
  if (!HMAC(EVP_sha1(), keyblock, key_len, counter, 8, hmac, &hmac_len) ||
      hmac_len != 20) {
    otp_log(OTP_LOG_ERR, "%s: %s: HMAC failed", log_prefix, __func__);
    return -1;
  }

  /* 2. the truncate step is unnecessarily complex */
  {
    int offset;

    offset = hmac[19] & 0x0F;
    /* we can't just cast hmac[offset] because of alignment and endianness */
    dbc = (hmac[offset] & 0x7F) << 24 |
          hmac[offset + 1]      << 16 |
          hmac[offset + 2]      << 8  |
          hmac[offset + 3];
  }

  /* 3. int conversion and modulus (as string) */
  (void) sprintf(output, fmt[d], dbc % dmod[d]);

  return 0;
}
