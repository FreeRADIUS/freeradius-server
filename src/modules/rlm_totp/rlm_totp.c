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
 * @file rlm_totp.c
 * @brief Execute commands and parse the results.
 *
 * @copyright 2021  The FreeRADIUS server project
 * @copyright 2021  Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#define TIME_STEP (30)
#define BACK_STEPS (1)
#define BACK_STEP_SECS (30)

/*
 *	RFC 4648 base32 decoding.
 */
static const uint8_t alphabet[UINT8_MAX] = {
	['A'] = 1,
	['B'] = 2,
	['C'] = 3,
	['D'] = 4,
	['E'] = 5,
	['F'] = 6,
	['G'] = 7,
	['H'] = 8,
	['I'] = 9,
	['J'] = 10,
	['K'] = 11,
	['L'] = 12,
	['M'] = 13,
	['N'] = 14,
	['O'] = 15,
	['P'] = 16,
	['Q'] = 17,
	['R'] = 18,
	['S'] = 19,
	['T'] = 20,
	['U'] = 21,
	['V'] = 22,
	['W'] = 23,
	['X'] = 24,
	['Y'] = 25,
	['Z'] = 26,
	['2'] = 27,
	['3'] = 28,
	['4'] = 29,
	['5'] = 30,
	['6'] = 31,
	['7'] = 32,
};

static ssize_t base32_decode(uint8_t *out, size_t outlen, char const *in)
{
	uint8_t *p, *end, *b;
	char const *q;

	p = out;
	end = p + outlen;

	memset(out, 0, outlen);

	/*
	 *	Convert ASCII to binary.
	 */
	for (q = in; *q != '\0'; q++) {
		/*
		 *	Padding at the end, stop.
		 */
		if (*q == '=') {
			break;
		}

		if (!alphabet[*((uint8_t const *) q)]) return -1;

		*(p++) = alphabet[*((uint8_t const *) q)] - 1;

		if (p == end) return -1; /* too much data */
	}

	/*
	 *	Reset to the end of the actual data we have
	 */
	end = p;

	/*
	 *	Convert input 5-bit groups into output 8-bit groups.
	 *	We do this in 8-byte blocks.
	 *
	 *	00011111 00022222 00033333 00044444 00055555 00066666 00077777 00088888
	 *
	 *	Will get converted to
	 *
	 *	11111222 22333334 44445555 56666677 77788888
	 */	
	for (p = b = out; p < end; p += 8) {
		b[0] = p[0] << 3;
		b[0] |= p[1] >> 2;

		b[1] = p[1] << 6;
		b[1] |= p[2] << 1;
		b[1] |= p[3] >> 4;

		b[2] = p[3] << 4;
		b[2] |= p[4] >> 1;

		b[3] = p[4] << 7;
		b[3] |= p[5] << 2;
		b[3] |= p[6] >> 3;

		b[4] = p[6] << 5;
		b[4] |= p[7];

		b += 5;

		/*
		 *	Clear out the remaining 3 octets of this block.
		 */
		b[0] = 0;
		b[1] = 0;
		b[2] = 0;
	}

	return b - out;
}

#ifndef TESTING
#define TESTING_UNUSED
#define LEN 6
#define PRINT "%06u"
#define DIV 1000000

#else
#define LEN 8
#define PRINT "%08u"
#define DIV 100000000


#undef RDEBUG3
#define RDEBUG3(fmt, ...)	printf(fmt "\n", ## __VA_ARGS__)
#define TESTING_UNUSED UNUSED
#endif

/*
 *	Implement RFC 6238 TOTP algorithm.
 *
 *	Appendix B has test vectors.  Note that the test vectors are
 *	for 8-character challenges, and not for 6 character
 *	challenges!
 */
static int totp_cmp(TESTING_UNUSED REQUEST *request, time_t now, uint8_t const *key, size_t keylen, char const *totp)
{
	uint8_t offset;
	uint32_t challenge;
	uint64_t padded;
	char buffer[9];
	uint8_t data[8];
	uint8_t digest[SHA1_DIGEST_LENGTH];
	time_t then;
	int i;

	/*
	 *	First try to authenticate against the current OTP, then step
	 *	back in increments of BACK_STEP_SECS, up to BACK_STEPS times,
	 *	to authenticate properly in cases of long transit delay, as
	 *	described in RFC 6238, secion 5.2.
	 */
	for (i = 0, then = now; i <= BACK_STEPS; i++, then -= BACK_STEP_SECS) {
	       padded = (uint64_t) then / TIME_STEP;
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
	       snprintf(buffer, sizeof(buffer), PRINT, challenge % DIV);

	       RDEBUG3("Now: %zu, Then: %zu", (size_t) now, (size_t) then);
	       RDEBUG3("Expected %s", buffer);
	       RDEBUG3("Received %s", totp);

	       if (rad_digest_cmp((uint8_t const *) buffer, (uint8_t const *) totp, LEN) == 0)
		      return 0;
	}
	return 1;
}

#ifndef TESTING

/*
 *  Do the authentication
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, REQUEST *request)
{
	VALUE_PAIR *vp, *password;
	uint8_t const *key;
	size_t keylen;
	uint8_t buffer[80];	/* multiple of 5*8 characters */
	uint64_t now = time(NULL);

	password = fr_pair_find_by_num(request->packet->vps, PW_TOTP_PASSWORD, 0, TAG_ANY);
	if (!password) return RLM_MODULE_NOOP;

	if (password->vp_length != 6) {
		REDEBUG("TOTP-Password has incorrect length %d", (int) password->vp_length);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Look for the raw key first.
	 */
	vp = fr_pair_find_by_num(request->config, PW_TOTP_KEY, 0, TAG_ANY);
	if (vp) {
		key = vp->vp_octets;
		keylen = vp->vp_length;

	} else {
		ssize_t len;

		vp = fr_pair_find_by_num(request->config, PW_TOTP_SECRET, 0, TAG_ANY);
		if (!vp) return RLM_MODULE_NOOP;

		len = base32_decode(buffer, sizeof(buffer), vp->vp_strvalue);
		if (len < 0) {
			REDEBUG("TOTP-Secret cannot be decoded");
			return RLM_MODULE_FAIL;
		}

		key = buffer;
		keylen = len;
	}

	if (totp_cmp(request, now, key, keylen, password->vp_strvalue) == 0)
		     return RLM_MODULE_OK;
	}
	return RLM_MODULE_FAIL;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_totp;
module_t rlm_totp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "totp",
	.type		= RLM_TYPE_THREAD_SAFE,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
	},
};

#else /* TESTING */
/*
 *	./totp decode KEY_BASE32
 *
 *	./totp totp now KEY TOTP
 */
int main(int argc, char **argv)
{
	size_t len;
	uint8_t *p;
	uint8_t key[80];

	if (argc < 2) return 0;

	if (strcmp(argv[1], "decode") == 0) {
		if (argc < 3) return 0;

		len = base32_decode(key, sizeof(key), argv[2]);
		printf("Decoded %ld %s\n", len, key);

		for (p = key; p < (key + len); p++) {
			printf("%02x ", *p);
		};
		printf("\n");

		return 0;
	}

	/*
	 *	TOTP <time> <key> <8-character-expected-token>
	 */
	if (strcmp(argv[1], "totp") == 0) {
		uint64_t now;

		if (argc < 5) return 0;

		if (strcmp(argv[2], "now") == 0) {
			now = time(NULL);
		} else {
			(void) sscanf(argv[2], "%llu", &now);
		}

		printf ("=== Time = %llu, TIME_STEP = %d, BACK_STEPS = %d, BACK_STEP_SECS = %d ===\n",
			 now, TIME_STEP, BACK_STEPS, BACK_STEP_SECS);

		if (totp_cmp(NULL, (time_t) now, (uint8_t const *) argv[3],
			     strlen(argv[3]), argv[4]) == 0) {
		       return 0;
		}
		printf("Fail\n");
		return 1;
	}

	fprintf(stderr, "Unknown command %s\n", argv[1]);
	return 1;
}
#endif
