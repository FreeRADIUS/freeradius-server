/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file totp.c
 * @brief Common function for TOTP validation.
 *
 * @copyright 2023 The FreeRADIUS server project
 */
#include <freeradius-devel/totp/base.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/debug.h>

/** Implement RFC 6238 TOTP algorithm (HMAC-SHA1).
 *
 *	Appendix B has test vectors.  Note that the test vectors are
 *	for 8-character challenges, and not for 6 character
 *	challenges!
 *
 * @param[in] cfg      Instance of fr_totp_t
 * @param[in] key      Key to decrypt.
 * @param[in] keylen   Length of key field.
 * @param[in] totp     TOTP password entered by the user.
 * @return
 *	-  0  On Success
 *	- -1  On Failure
 */
int fr_totp_cmp(fr_totp_t const *cfg, time_t now, uint8_t const *key, size_t keylen, char const *totp)
{
	time_t then;
	unsigned int i;
	uint8_t offset;
	uint32_t challenge;
	uint64_t padded;
	uint8_t data[8];
	uint8_t digest[SHA1_DIGEST_LENGTH];
	char buffer[9];
	char buf_now[32], buf_then[32];

	fr_assert(cfg != NULL);
	fr_assert(cfg->otp_length == 6 || cfg->otp_length == 8);
	fr_assert(key != NULL);
	fr_assert(totp != NULL);

	if (!cfg) {
		fr_strerror_const("Invalid 'cfg' parameter value.");
		return -1;
	}

	if (cfg->otp_length != 6 && cfg->otp_length != 8) {
		fr_strerror_const("The 'cfg->opt_length' has incorrect length. Expected 6 or 8.");
		return -1;
	}

	if (keylen < 1) {
		fr_strerror_const("Invalid 'keylen' parameter value.");
		return -1;
	}

	if (!totp || strlen(totp) < 1) {
		fr_strerror_const("Invalid 'totp' parameter value.");
		return -1;
	}

	/*
	 *	First try to authenticate against the current OTP, then step
	 *	back in increments of BACK_STEP_SECS, up to BACK_STEPS times,
	 *	to authenticate properly in cases of long transit delay, as
	 *	described in RFC 6238, secion 5.2.
	 */

	for (i = 0, then = now; i <= cfg->lookback_steps; i++, then -= cfg->lookback_steps) {
		fr_sbuff_t snow = FR_SBUFF_IN(buf_now, sizeof(buf_now));
		fr_sbuff_t sthen = FR_SBUFF_IN(buf_then, sizeof(buf_then));

		padded = ((uint64_t) now) / cfg->time_step;
		data[0] = padded >> 56;
		data[1] = padded >> 48;
		data[2] = padded >> 40;
		data[3] = padded >> 32;
		data[4] = padded >> 24;
		data[5] = padded >> 16;
		data[6] = padded >> 8;
		data[7] = padded & 0xff;

		/*
		 *	Encrypt the network order time with the key.
		 */
		fr_hmac_sha1(digest, data, 8, key, keylen);

		/*
		 *	Take the least significant 4 bits.
		 */
		offset = digest[SHA1_DIGEST_LENGTH - 1] & 0x0f;

		/*
		 *	Grab the 32bits at "offset", and drop the high bit.
		 */
		challenge = (digest[offset] & 0x7f) << 24;
		challenge |= digest[offset + 1] << 16;
		challenge |= digest[offset + 2] << 8;
		challenge |= digest[offset + 3];

		/*
		 *	The token is the last 6 digits in the number (or 8 for testing)..
		 */
		snprintf(buffer, sizeof(buffer), ((cfg->otp_length == 6) ? "%06u" : "%08u"),
				 challenge % ((cfg->otp_length == 6) ? 1000000 : 100000000));

		fr_time_strftime_local(&snow, fr_time_wrap(now), "%a %b %d %H:%M:%S %Y");
		fr_time_strftime_local(&sthen, fr_time_wrap(then), "%a %b %d %H:%M:%S %Y");

		DEBUG3("Now: %zu (%s), Then: %zu (%s)", (size_t) now, fr_sbuff_start(&snow), (size_t) then, fr_sbuff_start(&sthen));
		DEBUG3("Expected %s", buffer);
		DEBUG3("Received %s", totp);

		if (fr_digest_cmp((uint8_t const *) buffer, (uint8_t const *) totp, cfg->otp_length) == 0) return 0;
	}

	return -1;
}