/*
 * x99_mac.c
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
 * Copyright 2001  Google, Inc.
 */

#include "autoconf.h"
#include "radiusd.h"
#include "x99.h"

#include <string.h>
#include <openssl/des.h>

static const char rcsid[] = "$Id$";


/*
 * The X9.9 MAC is used by tokens in the following manner:
 * 1. Convert the challenge to ASCII bytes (eg "12345" -> 0x3132333435).
 * 2. Pad LSB of a 64-bit block w/ 0 bytes if challenge < 8 bytes (digits).
 * 3. Encrypt w/ DES.
 * 4. Convert the most significant 32 bits of the ciphertext
 *    to 8 hex digits as a string (eg 0x1234567f -> "1234567f").
 * 5. Apply any vendor specific transformations on chars "a" thru "f".
 *
 * Most (?) tokens probably support a max of an 8 character challenge,
 * but at least one supports performing the full CBC mode encryption
 * of an arbitrary length challenge.  So we don't limit ourselves
 * to just an ECB mode encryption.
 */
/* Returns 0 on success, non-zero otherwise.  response sized as indicated. */
int
x99_response(const char *challenge, char response[9],
	     uint32_t card_id, des_cblock keyblock)
{
    des_cblock output;
    char l_response[17];
    const char *conversion;

    /* Step 1, 2, 3. */
    if (x99_mac(challenge, output, keyblock) != 0)
	return -1;

    /* Step 4, 5 */
    if (card_id & X99_CF_DD) {
	if (card_id & X99_CF_SNK) {
	    conversion = x99_snk_dec_conversion;
	} else if (card_id & X99_CF_CRYPTOCARD) {
	    conversion = x99_cc_dec_conversion;
	} else {
	    /* This should not happen. */
	    radlog(L_ERR, "rlm_x99_token: x99_response: bad card mode/vendor");
	    return -1;
	}
    } else {
	/* Hex display */
	conversion = x99_hex_conversion;
    }
    x99_keyblock_to_string(l_response, output, conversion);
    (void) memcpy(response, l_response, 8);
    response[8] = '\0';

    if (card_id & X99_CF_R7) {
	if (card_id & X99_CF_CRYPTOCARD) {
	    (void) memmove(&response[3], &response[4], 5);
	} else {
	    /* This should not happen. */
	    radlog(L_ERR, "rlm_x99_token: x99_response: bad card mode/vendor");
	    return -1;
	}
    }

    return 0;
}


/*
 * The ANSI X9.9 MAC algorithm is:
 * 1. Perform a CBC mode DES encryption of the plaintext.  The last plaintext
 *    block must be zero padded.
 * 2. The MAC is the most significant 32 bits of the last cipherblock.
 *
 * This routine returns the entire 64 bit last cipherblock, at least one sync
 * mode needs this.  Returns 0 on success, non-zero otherwise.
 */
int
x99_mac(const char *input, des_cblock output, des_cblock keyblock)
{
    des_key_schedule ks;
    des_cblock ivec;
    des_cblock l_output[MAX_CHALLENGE_LEN / sizeof(des_cblock)];
    int chal_len = strlen(input);
    int rc;

    /*
     * Setup and verify the key.
     * This may be a bit expensive to do every time, but it
     * makes more sense for calling functions to deal with
     * the key itself, rather than the schedule.  In practice,
     * I don't think this will amount to much, but I haven't
     * actually profiled it.
     */
    if ((rc = des_set_key_checked((const_des_cblock *) keyblock, ks)) != 0) {
	radlog(L_ERR, "rlm_x99_token: x99_mac: DES key %s",
	       rc == -1 ? "has incorrect parity" : "is weak");
	return -1;
    }

    (void) memset(ivec, 0, sizeof(ivec));
    des_cbc_encrypt(input, (unsigned char *) l_output, chal_len,
		    ks, &ivec, DES_ENCRYPT);
    (void) memcpy(output, l_output[(chal_len - 1) / 8], 8);
    return 0;
}

