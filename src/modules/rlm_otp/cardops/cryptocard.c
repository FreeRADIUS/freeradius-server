/*
 * cryptocard.c
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

#include <string.h>

#include "../otp.h"
#include "../otp_cardops.h"
#include "cryptocard.h"

/* Card name to feature mask mappings */
static struct {
    const char *name;
    uint32_t fm;
} card[] = {
    { "cryptocard-h8-rc", CRYPTOCARD_H8_RC },
    { "cryptocard-d8-rc", CRYPTOCARD_D8_RC },
    { "cryptocard-h7-rc", CRYPTOCARD_H7_RC },
    { "cryptocard-d7-rc", CRYPTOCARD_D7_RC },
    { "cryptocard-h8-es", CRYPTOCARD_H8_ES },
    { "cryptocard-d8-es", CRYPTOCARD_D8_ES },
    { "cryptocard-h7-es", CRYPTOCARD_H7_ES },
    { "cryptocard-d7-es", CRYPTOCARD_D7_ES },
    { "cryptocard-h8-rs", CRYPTOCARD_H8_RS },
    { "cryptocard-d8-rs", CRYPTOCARD_D8_RS },
    { "cryptocard-h7-rs", CRYPTOCARD_H7_RS },
    { "cryptocard-d7-rs", CRYPTOCARD_D7_RS },

    { NULL, 0 }				/* end of list */
};


/*
 * Convert card name to feature mask.
 * Returns 0 on success, non-zero otherwise.
 */
static int
cryptocard_name2fm(const char *name, uint32_t *featuremask)
{
    int i;

    for (i = 0; card[i].name; ++i) {
	if (!strcasecmp(name, card[i].name)) {
	    *featuremask = card[i].fm;
	    return 0;
	}
    }
    return 1;
}


/*
 * Convert an ASCII keystring to a keyblock.
 * Returns 0 on success, non-zero otherwise.
 */
static int
cryptocard_keystring2keyblock(const char *keystring, unsigned char keyblock[])
{
    /* 64-bit DES key with optional line ending */
    if ((strlen(keystring) & ~1) != 16)
	return 1;

    return otp_keystring2keyblock(keystring, keyblock);
}


/*
 * Return a synchronous challenge.
 * Returns 0 on success, non-zero otherwise.
 */
static int
cryptocard_challenge(const char *syncdir, otp_user_info_t *user_info,
		     int ewin,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
		     int twin,
		     char challenge[OTP_MAX_CHALLENGE_LEN + 1])
{
    unsigned char output[8];
    int i, rc = -1;

    if (ewin == 0) {
	/* Return currently stored next challenge. */
	return otp_get_sync_challenge(syncdir, user_info->username, challenge);

    } else if (challenge[0]) {
	/* iterate once on the supplied challenge */
	ewin = 1;
    } else {
	/* iterate ewin times on the stored next challenge */
	rc = otp_get_sync_challenge(syncdir, user_info->username, challenge);
	if (rc)
	    return rc;
    }
    /* CRYPTOCard sync challenges are always 8 bytes. */
    if (strlen(challenge) != 8) {
	return -1;
    }

    while (ewin--) {
	if ((rc = otp_x99_mac(challenge, 8, output,
			      user_info->keyblock)) == 0) {
	    /* convert the mac into the next challenge */
	    for (i = 0; i < 8; ++i) {
		output[i] &= 0x0f;
		if (output[i] > 9)
		    output[i] -= 10;
		output[i] |= 0x30;
	    }
	    (void) memcpy(challenge, output, 8);
	    challenge[8] = '\0';
	} else {
	    /* something went wrong */
	    break;
	}
    }

    return rc;
}


/*
 * Return the expected card response for a given challenge.
 * Returns 0 on success, non-zero otherwise.
 *
 * The X9.9 MAC is used by CRYPTOcard in the following manner:
 *
 * 1. Convert the challenge to ASCII (eg "12345" -> 0x3132333435).
 *    We don't actually do a conversion, the challenge is already ASCII.
 *    Note that Secure Computing SafeWord Gold/Platinum tokens can use
 *    "raw" challenge bytes.
 * 2. Use the challenge as the plaintext input to the X9.9 MAC algorithm.
 *
 * 3. Convert the 32 bit MAC to ASCII (eg 0x1234567f -> "1234567f").
 *    Note that SafeWord Gold/Platinum tokens can display a 64 bit MAC.
 * 4. Possibly apply transformations on chars "a" thru "f".
 * 5. Truncate the response for 7 digit display modes.
 */
static int
cryptocard_response(otp_user_info_t *user_info, const char *challenge,
		    char response[OTP_MAX_RESPONSE_LEN + 1])
{
    unsigned char output[8];
    char l_response[17];
    const char *conversion;

    /* Step 1, 2. */
    if (otp_x99_mac(challenge, strlen(challenge), output,
		    user_info->keyblock) !=0)
	return 1;

    /* Setup for step 4. */
    if (user_info->featuremask & OTP_CF_DD)
	conversion = otp_cc_dec_conversion;
    else
	conversion = otp_hex_conversion;

    /* Step 3, 4. */
    otp_keyblock2keystring(l_response, output, conversion);
    (void) memcpy(response, l_response, 8);
    response[8] = '\0';

    /* Step 5. */
    if (user_info->featuremask & OTP_CF_R7)
	(void) memmove(&response[3], &response[4], 5);

    return 0;
}


/* cardops instance */
static cardops_t cryptocard_cardops = {
  .prefix		= "cryptocard",
  .prefix_len		= 10, /* strlen("cryptocard") */

  .name2fm		= cryptocard_name2fm,
  .keystring2keyblock	= cryptocard_keystring2keyblock,
  .challenge		= cryptocard_challenge,
  .response		= cryptocard_response
};

/* constructor */
void
cryptocard_init(void)
{
    if (otp_num_cardops == OTP_MAX_VENDORS) {
	otp_log(OTP_LOG_ERR, "cryptocard_init: module limit exceeded");
	return;
    }

    otp_cardops[otp_num_cardops++] = cryptocard_cardops;
    otp_log(OTP_LOG_DEBUG, "cryptocard_init: loaded");
}
