/*
 * otp_x99.c
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

#include "otp.h"

#include <string.h>
#include <openssl/des.h>

static const char rcsid[] = "$Id$";


/*
 * The ANSI X9.9 MAC algorithm is:
 * 1. Perform a CBC mode DES encryption of the plaintext.  The last plaintext
 *    block must be zero padded.
 * 2. The MAC is the most significant 32 bits of the last cipherblock.
 *
 * Most tokens support a max of an 8 character challenge, but at least one
 * (CRYPTOCard RB-1) supports performing the full CBC mode encryption
 * of an arbitrary length challenge.  So we don't limit ourselves
 * to just an ECB mode encryption.
 *
 * This routine returns the entire 64 bit last cipherblock, at least one sync
 * mode needs this (and ANSI X9.9 states that the MAC can be 48, and 64 bit
 * MACs should be supported).  Returns 0 on success, non-zero otherwise.
 */
int
otp_x99_mac(const unsigned char *input, size_t len, unsigned char output[8],
            const unsigned char keyblock[OTP_MAX_KEY_LEN],
            const char *log_prefix)
{
  des_key_schedule ks;
  des_cblock ivec;
  des_cblock l_output[OTP_MAX_CHALLENGE_LEN / sizeof(des_cblock)];
  int rc;

  /*
   * Setup and verify the key.
   * This may be a bit expensive to do every time, but it
   * makes more sense for calling functions to deal with
   * the key itself, rather than the schedule.  In practice,
   * I don't think this will amount to much, but I haven't
   * actually profiled it.
   * TODO: store in card_info after generating
   */
  if ((rc = des_set_key_checked((const_des_cblock *) keyblock, ks)) != 0) {
    otp_log(OTP_LOG_ERR, "%s: otp_x99_mac: DES key %s", log_prefix,
            rc == -1 ? "has incorrect parity" : "is weak");
    return -1;
  }

  (void) memset(ivec, 0, sizeof(ivec));
  des_cbc_encrypt(input, (unsigned char *) l_output, len,
                  ks, &ivec, DES_ENCRYPT);
  (void) memcpy(output, l_output[(len - 1) / 8], 8);
  return 0;
}

