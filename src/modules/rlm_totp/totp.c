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
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/debug.h>

#include "totp.h"

#ifdef TESTING
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/base32.h>

#undef RDEBUG_ENABLED3
#define RDEBUG_ENABLED3 (!request)
#undef RDEBUG3
#define RDEBUG3(fmt, ...) totp_log(fmt, ## __VA_ARGS__)

DIAG_OFF(format-nonliteral)

static void totp_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	printf("\n");
}
#endif

/** Implement RFC 6238 TOTP algorithm (HMAC-SHA1).
 *
 *	Appendix B has test vectors.  Note that the test vectors are
 *	for 8-character challenges, and not for 6 character
 *	challenges!
 *
 * @param[in] cfg	Instance of fr_totp_t
 * @param[in] request	The current request
 * @param[in] now	The current time
 * @param[in] key	Key to encrypt.
 * @param[in] keylen	Length of key field.
 * @param[in] totp	TOTP password entered by the user.
 * @return
 *	-  0  On Success
 *	- -1  On Failure
 *	- -2  On incorrect arguments
 */
int fr_totp_cmp(fr_totp_t const *cfg, request_t *request, time_t now, uint8_t const *key, size_t keylen, char const *totp)
{
	time_t		diff, then;
	uint32_t	steps;
	unsigned int	i;
	uint8_t		offset;
	uint32_t	challenge;
	uint64_t	padded;
	uint8_t		data[8];
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	char		buffer[9];

	fr_assert(cfg->otp_length == 6 || cfg->otp_length == 8);


	if (cfg->otp_length != 6 && cfg->otp_length != 8) {
		fr_strerror_const("The 'opt_length' has incorrect length. Expected 6 or 8.");
		return -2;
	}

	if (keylen < 1) {
		fr_strerror_const("Invalid 'keylen' parameter value.");
		return -2;
	}

	if (!*totp) {
		fr_strerror_const("Invalid 'totp' parameter value.");
		return -2;
	}

	/*
	 *	First try to authenticate against the current OTP, then step
	 *	back and forwards in increments of `lookback_interval`, up to `lookback_steps` times,
	 *	to authenticate properly in cases of long transit delay, as
	 *	described in RFC 6238, section 5.2.
	 */
	steps = cfg->lookback_steps > cfg->lookforward_steps ? cfg->lookback_steps : cfg->lookforward_steps;
	for (i = 0, diff = 0; i <= steps; i++, diff += cfg->lookback_interval) {
		if (i > cfg->lookback_steps) goto forwards;
		then = now - diff;
	repeat:
		padded = ((uint64_t) then) / cfg->time_step;
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

		if (RDEBUG_ENABLED3) {
			char buf_now[32], buf_then[32];
			fr_sbuff_t snow = FR_SBUFF_IN(buf_now, sizeof(buf_now));
			fr_sbuff_t sthen = FR_SBUFF_IN(buf_then, sizeof(buf_then));

			fr_time_strftime_local(&snow, fr_time_wrap(now), "%a %b %d %H:%M:%S %Y");
			fr_time_strftime_local(&sthen, fr_time_wrap(then), "%a %b %d %H:%M:%S %Y");

			RDEBUG3("Now: %zu (%s), Then: %zu (%s)", (size_t) now, fr_sbuff_start(&snow), (size_t) then, fr_sbuff_start(&sthen));
			RDEBUG3("Expected %s", buffer);
			RDEBUG3("Received %s", totp);
		}

		if (fr_digest_cmp((uint8_t const *) buffer, (uint8_t const *) totp, cfg->otp_length) == 0) return 0;

		/*
		 *	We've tested backwards, now do the equivalent time slot forwards
		 */
		if ((then < now) && (i <= cfg->lookforward_steps)) {
		forwards:
			then = now + diff;
			goto repeat;
		}
	}

	return -1;
}

#ifdef TESTING
int main(int argc, char **argv)
{
	size_t len;
	uint8_t *p;
	uint8_t key[80];
	fr_totp_t totp = {
		.time_step = 30,
		.otp_length = 8,
		.lookback_steps = 1,
		.lookback_interval = 1,
	};

	if (argc < 2) {
		fprintf(stderr, "totp: Expected command 'decode' or 'totp'\n");
		return 1;
	}

	if (strcmp(argv[1], "decode") == 0) {
		if (argc < 3) {
			fprintf(stderr, "totp: Expected arguments as - decode <base32-data> \n");
			return 1;
		}

		len = fr_base32_decode(&FR_DBUFF_TMP(key, sizeof(key)), &FR_SBUFF_IN(argv[2], strlen(argv[2])), true, true);
		printf("Decoded %ld %s\n", len, key);

		for (p = key; p < (key + len); p++) {
			printf("%02x ", *p);
		}
		printf("\n");

		return 0;
	}

	/*
	 *	TOTP <time> <key> <8-character-expected-token>
	 */
	if (strcmp(argv[1], "totp") == 0) {
		uint64_t now;

		if (argc < 5) {
			fprintf(stderr, "totp: Expected arguments as - totp <time> <key> <totp>\n");
			return 1;
		}

		(void) sscanf(argv[2], "%llu", &now);

		if (fr_totp_cmp(&totp, NULL, (time_t) now, (uint8_t const *) argv[3], strlen(argv[3]), argv[4]) == 0) {
			return 0;
		}
		printf("Fail\n");
		return 1;
	}

	fprintf(stderr, "Unknown command %s\n", argv[1]);
	return 1;
}
#endif
