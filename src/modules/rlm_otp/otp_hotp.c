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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2005 TRI-D Systems, Inc.
 */

#include <openssl/hmac.h>

#include "otp.h"

static const char rcsid[] = "$Id$";


/*
 * This implements HOTP per draft-mraihi-oath-hmac-otp-04.txt, for Digit = 6.
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
             const char *log_prefix)
{
  unsigned char hmac[EVP_MAX_MD_SIZE];	/* >=20 */
  int hmac_len = 0;
  uint32_t dbc;		/* "dynamic binary code" from HOTP draft */

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
  (void) sprintf(output, "%06lu", dbc % 1000000L);

  return 0;
}
