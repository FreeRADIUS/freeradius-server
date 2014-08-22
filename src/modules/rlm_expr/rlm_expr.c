/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
 * @file rlm_expr.c
 * @brief Register many xlat expansions including the expr expansion.
 *
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2002  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/base64.h>
#include <freeradius-devel/modules.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#include <ctype.h>

#include "rlm_expr.h"

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_expr_t {
	char const *xlat_name;
	char const *allowed_chars;
} rlm_expr_t;

static const CONF_PARSER module_config[] = {
	{ "safe_characters", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_expr_t, allowed_chars), "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /" },
	{NULL, -1, 0, NULL, NULL}
};

typedef enum expr_token_t {
	TOKEN_NONE = 0,
	TOKEN_INTEGER,
	TOKEN_ADD,
	TOKEN_SUBTRACT,
	TOKEN_DIVIDE,
	TOKEN_REMAINDER,
	TOKEN_MULTIPLY,
	TOKEN_AND,
	TOKEN_OR,
	TOKEN_POWER,
	TOKEN_LAST
} expr_token_t;

typedef struct expr_map_t {
	char op;
	expr_token_t token;
} expr_map_t;

static expr_map_t map[] =
{
	{'+',	TOKEN_ADD },
	{'-',	TOKEN_SUBTRACT },
	{'/',	TOKEN_DIVIDE },
	{'*',	TOKEN_MULTIPLY },
	{'%',	TOKEN_REMAINDER },
	{'&',	TOKEN_AND },
	{'|',	TOKEN_OR },
	{'^',	TOKEN_POWER },
	{0,	TOKEN_LAST}
};

/*
 *	Lookup tables for randstr char classes
 */
static char randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static char randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

/*
 *	Characters humans rarely confuse. Reduces char set considerably
 *	should only be used for things such as one time passwords.
 */
static char randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

static char const hextab[] = "0123456789abcdef";

static int get_number(REQUEST *request, char const **string, int64_t *answer)
{
	int		i, found;
	int64_t		result;
	int64_t		x;
	char const 	*p;
	expr_token_t	this;

	/*
	 *  Loop over the input.
	 */
	result = 0;
	this = TOKEN_NONE;

	for (p = *string; *p != '\0'; /* nothing */) {
		if ((*p == ' ') ||
		    (*p == '\t')) {
			p++;
			continue;
		}

		/*
		 *  Discover which token it is.
		 */
		found = false;
		for (i = 0; map[i].token != TOKEN_LAST; i++) {
			if (*p == map[i].op) {
				if (this != TOKEN_NONE) {
					RDEBUG2("Invalid operator at \"%s\"", p);
					return -1;
				}
				this = map[i].token;
				p++;
				found = true;
				break;
			}
		}

		/*
		 *  Found the algebraic operator.  Get the next number.
		 */
		if (found) {
			continue;
		}

		/*
		 *  End of a group.  Stop.
		 */
		if (*p == ')') {
			if (this != TOKEN_NONE) {
				RDEBUG2("Trailing operator before end sub-expression at \"%s\"", p);
				return -1;
			}
			p++;
			break;
		}

		/*
		 *  Start of a group.  Call ourselves recursively.
		 */
		if (*p == '(') {
			p++;

			found = get_number(request, &p, &x);
			if (found < 0) {
				return -1;
			}
		} else {
			/*
			 *  No algrebraic operator found, the next thing
			 *  MUST be a number.
			 *
			 *  If it isn't, then we die.
			 */
			if ((*p == '0') && (p[1] == 'x')) {
				char *end;

				x = strtoul(p, &end, 16);
				p = end;
				goto calc;
			}


			if ((*p < '0') || (*p > '9')) {
				RDEBUG2("Not a number at \"%s\"", p);
				return -1;
			}

			/*
			 *  This is doing it the hard way, but it also allows
			 *  us to increment 'p'.
			 */
			x = 0;
			while ((*p >= '0') && (*p <= '9')) {
				x *= 10;
				x += (*p - '0');
				p++;
			}
		}

	calc:
		switch (this) {
		default:
		case TOKEN_NONE:
			result = x;
			break;

		case TOKEN_ADD:
			result += x;
			break;

		case TOKEN_SUBTRACT:
			result -= x;
			break;

		case TOKEN_DIVIDE:
			if (x == 0) {
				result = 0; /* we don't have NaN for integers */
			} else {
				result /= x;
			}
			break;

		case TOKEN_REMAINDER:
			if (x == 0) {
				result = 0; /* we don't have NaN for integers */
				break;
			}
			result %= x;
			break;

		case TOKEN_MULTIPLY:
			result *= x;
			break;

		case TOKEN_AND:
			result &= x;
			break;

		case TOKEN_OR:
			result |= x;
			break;

		case TOKEN_POWER:
			if ((x > 255) || (x < 0)) {
				REDEBUG("Exponent must be between 0-255");
				return -1;
			}
			x = fr_pow((int32_t) result, (uint8_t) x);
			break;
		}

		/*
		 *  We've used this token.
		 */
		this = TOKEN_NONE;
	}

	/*
	 *  And return the answer to the caller.
	 */
	*string = p;
	*answer = result;
	return 0;
}

/*
 *  Do xlat of strings!
 */
static ssize_t expr_xlat(UNUSED void *instance, REQUEST *request, char const *fmt,
			 char *out, size_t outlen)
{
	int		rcode;
	int64_t		result;
	char const 	*p;

	p = fmt;
	rcode = get_number(request, &p, &result);
	if (rcode < 0) {
		return -1;
	}

	/*
	 *  We MUST have eaten the entire input string.
	 */
	if (*p != '\0') {
		RDEBUG2("Failed at %s", p);
		return -1;
	}

	snprintf(out, outlen, "%lld", (long long int)result);
	return strlen(out);
}

/** Generate a random integer value
 *
 */
static ssize_t rand_xlat(UNUSED void *instance, UNUSED REQUEST *request, char const *fmt,
			 char *out, size_t outlen)
{
	int64_t		result;

	result = atoi(fmt);

	/*
	 *	Too small or too big.
	 */
	if (result <= 0) {
		*out = '\0';
		return -1;
	}
	if (result >= (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	snprintf(out, outlen, "%ld", (long int) result);
	return strlen(out);
}

/** Generate a string of random chars
 *
 *  Build strings of random chars, useful for generating tokens and passcodes
 *  Format similar to String::Random.
 */
static ssize_t randstr_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			    char const *fmt, char *out, size_t outlen)
{
	char const 	*p;
	unsigned int	result;
	size_t		freespace = outlen;

	if (outlen <= 1) return 0;

	*out = '\0';

	p = fmt;
	while (*p && (--freespace > 0)) {
		result = fr_rand();
		switch (*p) {
		/*
		 *  Lowercase letters
		 */
		case 'c':
			*out++ = 'a' + (result % 26);
			break;

		/*
		 *  Uppercase letters
		 */
		case 'C':
			*out++ = 'A' + (result % 26);
			break;

		/*
		 *  Numbers
		 */
		case 'n':
			*out++ = '0' + (result % 10);
			break;

		/*
		 *  Alpha numeric
		 */
		case 'a':
			*out++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
			break;

		/*
		 *  Punctuation
		 */
		case '!':
			*out++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
			break;

		/*
		 *  Alpa numeric + punctuation
		 */
		case '.':
			*out++ = '!' + (result % 95);
			break;

		/*
		 *  Alpha numeric + salt chars './'
		 */
		case 's':
			*out++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
			break;

		/*
		 *  Chars suitable for One Time Password tokens.
		 *  Alpha numeric with easily confused char pairs removed.
		 */
		case 'o':
			*out++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
			break;

		/*
		 *  Binary data as hexits (we don't really support
		 *  non printable chars).
		 */
		case 'h':
			if (freespace < 2) {
				break;
			}

			snprintf(out, 3, "%02x", result % 256);

			/* Already decremented */
			freespace -= 1;
			out += 2;
			break;

		/*
		 *  Binary data with uppercase hexits
		 */
		case 'H':
			if (freespace < 2) {
				break;
			}

			snprintf(out, 3, "%02X", result % 256);

			/* Already decremented */
			freespace -= 1;
			out += 2;
			break;

		default:
			ERROR("rlm_expr: invalid character class '%c'", *p);

			return -1;
		}

		p++;
	}

	*out++ = '\0';

	return outlen - freespace;
}

/** URLencode special characters
 *
 * Example: "%{urlquote:http://example.org/}" == "http%3A%47%47example.org%47"
 */
static ssize_t urlquote_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			     char const *fmt, char *out, size_t outlen)
{
	char const 	*p;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (isalnum(*p)) {
			*out++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*out++ = *p++;
			break;

		default:
			if (freespace < 3)
				break;

			/* MUST be upper case hex to be compliant */
			snprintf(out, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			/* Already decremented */
			freespace -= 2;
			out += 3;
		}
	}

	*out = '\0';

	return outlen - freespace;
}

/** URLdecode special characters
 *
 * Example: "%{urlunquote:http%%3A%%47%%47example.org%%47}" == "http://example.org/"
 * Mind the double % in the quoted string, otherwise unlang would start parsing it
 */
static ssize_t urlunquote_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			       char const *fmt, char *out, size_t outlen)
{
	char const *p;
	char *c1, *c2;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (*p != '%') {
			*out++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower(*++p), 16)) ||
		    !(c2 = memchr(hextab, tolower(*++p), 16))) {
		   	REMARKER(fmt, p - fmt, "None hex char in % sequence");
		   	return -1;
		}
		p++;
		*out++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*out = '\0';

	return outlen - freespace;
}

/** Equivalent to the old safe_characters functionality in rlm_sql
 *
 * @verbatim Example: "%{escape:<img>foo.jpg</img>}" == "=60img=62foo.jpg=60/img=62" @endverbatim
 */
static ssize_t escape_xlat(void *instance, UNUSED REQUEST *request,
			   char const *fmt, char *out, size_t outlen)
{
	rlm_expr_t *inst = instance;
	char const *p;
	size_t freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((*p > 31) && strchr(inst->allowed_chars, *p)) {
			*out++ = *p++;
			continue;
		}

		if (freespace < 3)
			break;

		snprintf(out, 4, "=%02X", (uint8_t)*p++);

		/* Already decremented */
		freespace -= 2;
		out += 3;
	}

	*out = '\0';

	return outlen - freespace;
}

/** Equivalent to the old safe_characters functionality in rlm_sql
 *
 * @verbatim Example: "%{unescape:=60img=62foo.jpg=60/img=62}" == "<img>foo.jpg</img>" @endverbatim
 */
static ssize_t unescape_xlat(void *instance, UNUSED REQUEST *request,
			       char const *fmt, char *out, size_t outlen)
{
	rlm_expr_t *inst = instance;
	char const *p;
	char *c1, *c2, c3;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (*p != '=') {
		next:

			*out++ = *p++;
			continue;
		}

		/* Is a = char */

		if (!(c1 = memchr(hextab, tolower(*(p + 1)), 16)) ||
		    !(c2 = memchr(hextab, tolower(*(p + 2)), 16))) goto next;
		c3 = ((c1 - hextab) << 4) + (c2 - hextab);

		/*
		 *	It was just random occurrence which just happens
		 *	to match the escape sequence for a safe character.
		 *	Copy it across verbatim.
		 */
		if (strchr(inst->allowed_chars, c3)) goto next;
		*out++ = c3;
		p += 3;
	}

	*out = '\0';

	return outlen - freespace;
}

/** Convert a string to lowercase
 *
 * Example: "%{tolower:Bar}" == "bar"
 *
 * Probably only works for ASCII
 */
static ssize_t lc_xlat(UNUSED void *instance, UNUSED REQUEST *request,
		       char const *fmt, char *out, size_t outlen)
{
	char *q;
	char const *p;

	if (outlen <= 1) return 0;

	for (p = fmt, q = out; *p != '\0'; p++, outlen--) {
		if (outlen <= 1) break;

		*(q++) = tolower((int) *p);
	}

	*q = '\0';

	return strlen(out);
}

/** Convert a string to uppercase
 *
 * Example: "%{toupper:Foo}" == "FOO"
 *
 * Probably only works for ASCII
 */
static ssize_t uc_xlat(UNUSED void *instance, UNUSED REQUEST *request,
		       char const *fmt, char *out, size_t outlen)
{
	char *q;
	char const *p;

	if (outlen <= 1) return 0;

	for (p = fmt, q = out; *p != '\0'; p++, outlen--) {
		if (outlen <= 1) break;

		*(q++) = toupper((int) *p);
	}

	*q = '\0';

	return strlen(out);
}

/** Calculate the MD5 hash of a string or attribute.
 *
 * Example: "%{md5:foo}" == "acbd18db4cc2f85cedef654fccc4a4d8"
 */
static ssize_t md5_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			char const *fmt, char *out, size_t outlen)
{
	uint8_t digest[16];
	ssize_t i, len, inlen;
	uint8_t const *p;
	FR_MD5_CTX ctx;

	/*
	 *	We need room for at least one octet of output.
	 */
	if (outlen < 3) {
		*out = '\0';
		return 0;
	}

	inlen = xlat_fmt_to_ref(&p, request, fmt);
	if (inlen < 0) {
		return -1;
	}

	fr_md5_init(&ctx);
	fr_md5_update(&ctx, p, inlen);
	fr_md5_final(digest, &ctx);

	/*
	 *	Each digest octet takes two hex digits, plus one for
	 *	the terminating NUL.
	 */
	len = (outlen / 2) - 1;
	if (len > 16) len = 16;

	for (i = 0; i < len; i++) {
		snprintf(out + i * 2, 3, "%02x", digest[i]);
	}

	return strlen(out);
}

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example: "%{sha1:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
static ssize_t sha1_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	uint8_t digest[20];
	ssize_t i, len, inlen;
	uint8_t const *p;
	fr_SHA1_CTX ctx;

	/*
	 *      We need room for at least one octet of output.
	 */
	if (outlen < 3) {
		*out = '\0';
		return 0;
	}

	inlen = xlat_fmt_to_ref(&p, request, fmt);
	if (inlen < 0) {
		return -1;
	}

	fr_sha1_init(&ctx);
	fr_sha1_update(&ctx, p, inlen);
	fr_sha1_final(digest, &ctx);

	/*
	 *      Each digest octet takes two hex digits, plus one for
	 *      the terminating NUL. SHA1 is 160 bits (20 bytes)
	 */
	len = (outlen / 2) - 1;
	if (len > 20) len = 20;

	for (i = 0; i < len; i++) {
		snprintf(out + i * 2, 3, "%02x", digest[i]);
	}

	return strlen(out);
}

/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example: "%{sha256:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
#ifdef HAVE_OPENSSL_EVP_H
static ssize_t evp_md_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			   char const *fmt, char *out, size_t outlen, EVP_MD const *md)
{
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned int digestlen, i, len;
	ssize_t inlen;
	uint8_t const *p;

	EVP_MD_CTX *ctx;

	/*
	 *      We need room for at least one octet of output.
	 */
	if (outlen < 3) {
		*out = '\0';
		return 0;
	}

	inlen = xlat_fmt_to_ref(&p, request, fmt);
	if (inlen < 0) {
		return -1;
	}

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, p, inlen);
	EVP_DigestFinal_ex(ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(ctx);

	/*
	 *      Each digest octet takes two hex digits, plus one for
	 *      the terminating NUL.
	 */
	len = (outlen / 2) - 1;
	if (len > digestlen) len = digestlen;

	for (i = 0; i < len; i++) {
		snprintf(out + i * 2, 3, "%02x", digest[i]);
	}
	return strlen(out);
}

#  define EVP_MD_XLAT(_md) \
static ssize_t _md##_xlat(UNUSED void *instance, UNUSED REQUEST *request, char const *fmt, char *out, size_t outlen)\
{\
	return evp_md_xlat(instance, request, fmt, out, outlen, EVP_##_md());\
}

EVP_MD_XLAT(sha256);
EVP_MD_XLAT(sha512);
#endif

/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example: "%{hmacmd5:foo bar}" == "Zm9v"
 */
static ssize_t hmac_md5_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			     char const *fmt, char *out, size_t outlen)
{
	uint8_t const *data, *key;
	char const *p;
	ssize_t data_len, key_len;
	uint8_t digest[MD5_DIGEST_LENGTH];
	char data_ref[256];

	if (outlen <= (sizeof(digest) * 2)) {
		REDEBUG("Insufficient space to write digest, needed %zu bytes, have %zu bytes",
			(sizeof(digest) * 2) + 1, outlen);
		return -1;
	}

	p = strchr(fmt, ' ');
	if (!p) {
		REDEBUG("HMAC requires exactly two arguments (&data &key)");
		return -1;
	}

	if ((size_t)(p - fmt) >= sizeof(data_ref)) {
		REDEBUG("Insufficient space to store HMAC input data, needed %zu bytes, have %zu bytes",
		       (p - fmt) + 1, sizeof(data_ref));

		return -1;
	}
	strlcpy(data_ref, fmt, (p - fmt) + 1);

	data_len = xlat_fmt_to_ref(&data, request, data_ref);
	if (data_len < 0) return -1;

	while (isspace(*p) && p++);

	key_len = xlat_fmt_to_ref(&key, request, p);
	if (key_len < 0) return -1;

	fr_hmac_md5(digest, data, data_len, key, key_len);

	return fr_bin2hex(out, digest, sizeof(digest));
}

/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example: "%{hmacsha1:foo bar}" == "Zm9v"
 */
static ssize_t hmac_sha1_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			      char const *fmt, char *out, size_t outlen)
{
	uint8_t const *data, *key;
	char const *p;
	ssize_t data_len, key_len;
	uint8_t digest[SHA1_DIGEST_LENGTH];
	char data_ref[256];

	if (outlen <= (sizeof(digest) * 2)) {
		REDEBUG("Insufficient space to write digest, needed %zu bytes, have %zu bytes",
			(sizeof(digest) * 2) + 1, outlen);
		return -1;
	}

	p = strchr(fmt, ' ');
	if (!p) {
		REDEBUG("HMAC requires exactly two arguments (&data &key)");
		return -1;
	}

	if ((size_t)(p - fmt) >= sizeof(data_ref)) {
		REDEBUG("Insufficient space to store HMAC input data, needed %zu bytes, have %zu bytes",
		        (p - fmt) + 1, sizeof(data_ref));

		return -1;
	}
	strlcpy(data_ref, fmt, (p - fmt) + 1);

	data_len = xlat_fmt_to_ref(&data, request, data_ref);
	if (data_len < 0) return -1;

	while (isspace(*p) && p++);

	key_len = xlat_fmt_to_ref(&key, request, p);
	if (key_len < 0) return -1;

	fr_hmac_sha1(digest, data, data_len, key, key_len);

	return fr_bin2hex(out, digest, sizeof(digest));
}

/** Encode string or attribute as base64
 *
 * Example: "%{base64:foo}" == "Zm9v"
 */
static ssize_t base64_xlat(UNUSED void *instance, UNUSED REQUEST *request,
			   char const *fmt, char *out, size_t outlen)
{
	ssize_t inlen;
	uint8_t const *p;

	inlen = xlat_fmt_to_ref(&p, request, fmt);
	if (inlen < 0) {
		return -1;
	}

	/*
	 *  We can accurately calculate the length of the output string
	 *  if it's larger than outlen, the output would be useless so abort.
	 */
	if ((inlen < 0) || ((FR_BASE64_ENC_LENGTH(inlen) + 1) > (ssize_t) outlen)) {
		REDEBUG("xlat failed");
		*out = '\0';
		return -1;
	}

	return fr_base64_encode(out, outlen, p, inlen);
}

/** Convert base64 to hex
 *
 * Example: "%{base64tohex:Zm9v}" == "666f6f"
 */
static ssize_t base64_to_hex_xlat(UNUSED void *instance, UNUSED REQUEST *request,
				  char const *fmt, char *out, size_t outlen)
{
	uint8_t decbuf[1024];

	ssize_t declen;
	ssize_t len = strlen(fmt);

	*out = '\0';

	declen = fr_base64_decode(decbuf, sizeof(decbuf), fmt, len);
	if (declen < 0) {
		REDEBUG("Base64 string invalid");
		return -1;
	}

	if ((size_t)((declen * 2) + 1) > outlen) {
		REDEBUG("Base64 conversion failed, output buffer exhausted, needed %zd bytes, have %zd bytes",
			(declen * 2) + 1, outlen);
		return -1;
	}

	return fr_bin2hex(out, decbuf, declen);
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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_expr_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	xlat_register(inst->xlat_name, expr_xlat, NULL, inst);

	/*
	 *	FIXME: unregister these, too
	 */
	xlat_register("rand", rand_xlat, NULL, inst);
	xlat_register("randstr", randstr_xlat, NULL, inst);
	xlat_register("urlquote", urlquote_xlat, NULL, inst);
	xlat_register("urlunquote", urlunquote_xlat, NULL, inst);
	xlat_register("escape", escape_xlat, NULL, inst);
	xlat_register("unescape", unescape_xlat, NULL, inst);
	xlat_register("tolower", lc_xlat, NULL, inst);
	xlat_register("toupper", uc_xlat, NULL, inst);
	xlat_register("md5", md5_xlat, NULL, inst);
	xlat_register("sha1", sha1_xlat, NULL, inst);
#ifdef HAVE_OPENSSL_EVP_H
	xlat_register("sha256", sha256_xlat, NULL, inst);
	xlat_register("sha512", sha512_xlat, NULL, inst);
#endif
	xlat_register("hmacmd5", hmac_md5_xlat, NULL, inst);
	xlat_register("hmacsha1", hmac_sha1_xlat, NULL, inst);
	xlat_register("base64", base64_xlat, NULL, inst);
	xlat_register("base64tohex", base64_to_hex_xlat, NULL, inst);

	/*
	 *	Initialize various paircompare functions
	 */
	pair_builtincompare_add(instance);
	return 0;
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
module_t rlm_expr = {
	RLM_MODULE_INIT,
	"expr",				/* Name */
	0,   	/* type */
	sizeof(rlm_expr_t),
	module_config,
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* pre-accounting */
		NULL			/* accounting */
	},
};
