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
 * @copyright 2021  Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/interpret.h>

typedef struct {
	fr_value_box_t		secret;
	fr_value_box_t		key;
	fr_value_box_t		user_password;
} rlm_totp_call_env_t;

/* Define a structure for the configuration variables */
typedef struct rlm_totp_t {
	char const	*name;	//!< name of this instance
	fr_totp_t   totp;	//!< Parameter sets for fr_totp_cmp()
} rlm_totp_t;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_totp_dict[];
fr_dict_autoload_t rlm_totp_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_totp;
static fr_dict_attr_t const *attr_totp_secret;
static fr_dict_attr_t const *attr_totp_key;
static fr_dict_attr_t const *attr_totp_from_user;

extern fr_dict_attr_autoload_t rlm_totp_dict_attr[];
fr_dict_attr_autoload_t rlm_totp_dict_attr[] = {
	{ .out = &attr_totp, .name = "TOTP", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_totp_secret, .name = "TOTP.Secret", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_totp_key, .name = "TOTP.Key", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_totp_from_user, .name = "TOTP.From-User", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ NULL }
};

/* Define a structure for the configuration variables */
typedef struct rlm_totp_t {
	char const	*name;			//!< name of this instance */
	uint32_t	time_step;		//!< seconds
	uint32_t	otp_length;		//!< forced to 6 or 8
	uint32_t	lookback_steps;		//!< number of steps to look back
	uint32_t	lookback_interval;	//!< interval in seconds between steps
} rlm_totp_t;

#ifndef TESTING
/* Map configuration file names to internal variables */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("time_step", FR_TYPE_UINT32, rlm_totp_t, time_step), .dflt = "30" },
	{ FR_CONF_OFFSET("otp_length", FR_TYPE_UINT32, rlm_totp_t, otp_length), .dflt = "6" },
	{ FR_CONF_OFFSET("lookback_steps", FR_TYPE_UINT32, rlm_totp_t, lookback_steps), .dflt = "1" },
	{ FR_CONF_OFFSET("lookback_interval", FR_TYPE_UINT32, rlm_totp_t, lookback_interval), .dflt = "30" },
	CONF_PARSER_TERMINATOR
};

#define TIME_STEP      (inst->time_step)
#define OTP_LEN        (inst->otp_length)
#define BACK_STEPS     (inst->lookback_steps)
#define BACK_STEP_SECS (inst->lookback_interval)
#else
#define TIME_STEP	(30)
#define OTP_LEN		(8)
#define BACK_STEPS	(1)
#define BACK_STEP_SECS	(30)
#endif

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
# define TESTING_UNUSED
# define LEN 6
# define PRINT "%06u"
# define DIV 1000000
#else /* TESTING */
# define LEN 8
# define PRINT "%08u"
# define DIV 100000000
# undef RDEBUG3
# define RDEBUG3(fmt, ...)	printf(fmt "\n", ## __VA_ARGS__)
# define TESTING_UNUSED UNUSED
#endif

#ifndef TESTING
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_totp_t   *inst = talloc_get_type_abort(mctx->inst->data, rlm_totp_t);
	CONF_SECTION *conf = mctx->inst->conf;

	inst->name = cf_section_name2(conf);
		if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_totp_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_totp_t);

	FR_INTEGER_BOUND_CHECK("time_step", inst->time_step, >=, 5);
	FR_INTEGER_BOUND_CHECK("time_step", inst->time_step, <=, 120);

	FR_INTEGER_BOUND_CHECK("lookback_steps", inst->lookback_steps, >=, 1);
	FR_INTEGER_BOUND_CHECK("lookback_steps", inst->lookback_steps, <=, 10);

	FR_INTEGER_BOUND_CHECK("lookback_interval", inst->lookback_interval, <=, inst->time_step);

	FR_INTEGER_BOUND_CHECK("otp_length", inst->otp_length, >=, 6);
	FR_INTEGER_BOUND_CHECK("otp_length", inst->otp_length, <=, 8);

	if (inst->otp_length == 7) inst->otp_length = 8;

	return 0;
}
#endif

/*
 *	Implement RFC 6238 TOTP algorithm.
 *
 *	Appendix B has test vectors.  Note that the test vectors are
 *	for 8-character challenges, and not for 6 character
 *	challenges!
 */
static int totp_cmp(TESTING_UNUSED request_t *request, time_t now, uint8_t const *key, size_t keylen, char const *totp, TESTING_UNUSED rlm_totp_t const *inst)
{
	time_t then;
	unsigned int i;
	uint8_t offset;
	uint32_t challenge;
	uint64_t padded;
	char buffer[9];
	uint8_t data[8];
	uint8_t digest[SHA1_DIGEST_LENGTH];

	/*
	 *	First try to authenticate against the current OTP, then step
	 *	back in increments of BACK_STEP_SECS, up to BACK_STEPS times,
	 *	to authenticate properly in cases of long transit delay, as
	 *	described in RFC 6238, secion 5.2.
	 */

	for (i = 0, then = now; i <= BACK_STEPS; i++, then -= BACK_STEP_SECS) {
		padded = ((uint64_t) now) / TIME_STEP;
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
		snprintf(buffer, sizeof(buffer), ((OTP_LEN == 6) ? "%06u" : "%08u"),
				 challenge % ((OTP_LEN == 6) ? 1000000 : 100000000));

		RDEBUG3("Now: %zu, Then: %zu", (size_t) now, (size_t) then);
		RDEBUG3("Expected %s", buffer);
		RDEBUG3("Received %s", totp);

		if (fr_digest_cmp((uint8_t const *) buffer, (uint8_t const *) totp, LEN) == 0) return 0;
	}

	return 1;
}

#ifndef TESTING

/*
 *  Do the authentication
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_totp_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_totp_t);
	fr_pair_t        *secret, *from_user, *key;
	uint8_t const    *our_key;
	size_t            our_keylen;
	uint8_t           buffer[80];	/* multiple of 5*8 characters */
	fr_dbuff_t        out;

	fr_dbuff_init(&out, (uint8_t *)buffer, sizeof(buffer));

	from_user = fr_pair_find_by_da(&request->request_pairs, NULL, attr_totp_from_user);
	if (!from_user) {
		REDEBUG("&request.TOTP.From-User is needed");
		RETURN_MODULE_INVALID;
	}

	if ((from_user->vp_length != 6) && (from_user->vp_length != 8)) {
		RDEBUG("&request.TOTP.From-User has incorrect length. Expected 6 or 8, got %zu", from_user->vp_length);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Look for the raw key first in &request.TOTP.Key
	 */
	key = fr_pair_find_by_da(&request->control_pairs, NULL, attr_totp_key);
	if (key) {
		our_key = key->vp_octets;
		our_keylen = key->vp_length;
	} else {
		ssize_t len;

		/* then let's see &control.TOTP.Secret */
		secret = fr_pair_find_by_da(&request->control_pairs, NULL, attr_totp_secret);
		if (!secret) {
			REDEBUG("&control.TOTP.Secret is needed");
			RETURN_MODULE_INVALID;
		}

		len = fr_base32_decode(&out, &FR_SBUFF_IN(secret->vp_strvalue, secret->vp_length), true, true);
		if (len < 0) {
			RDEBUG("&control.TOTP.Secret cannot be decoded");
			RETURN_MODULE_FAIL;
		}

		our_key = buffer;
		our_keylen = len;
	}

	if (fr_totp_cmp(&inst->totp, fr_time_to_sec(request->packet->timestamp), our_key, our_keylen, from_user->vp_strvalue) != 0) RETURN_MODULE_FAIL;

	RETURN_MODULE_OK;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_totp;
module_rlm_t rlm_totp = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "totp",
		.type		= MODULE_TYPE_THREAD_SAFE,
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,	.method = mod_authenticate },
		{ .name1 = CF_IDENT_ANY,	.name2 = CF_IDENT_ANY,	.method = mod_authenticate },
		MODULE_NAME_TERMINATOR
	}
};

#else /* TESTING */
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
		}
		printf("\n");

		return 0;
	}

	/*
	 *	TOTP <time> <key> <8-character-expected-token>
	 */
	if (strcmp(argv[1], "totp") == 0) {
		uint64_t now;

		if (argc < 5) return 0;

		(void) sscanf(argv[2], "%llu", &now);

		if (totp_cmp(NULL, (time_t) now, (uint8_t const *) argv[3], strlen(argv[3]), argv[4], NULL) == 0) {
			return 0;
		}
		printf("Fail\n");
		return 1;
	}

	fprintf(stderr, "Unknown command %s\n", argv[1]);
	return 1;
}
#endif
