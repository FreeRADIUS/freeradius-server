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
#include <freeradius-devel/rad_assert.h>

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
	{ FR_CONF_OFFSET("safe_characters", FR_TYPE_STRING, rlm_expr_t, allowed_chars), .dflt = "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /" },
	CONF_PARSER_TERMINATOR
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

/** Calculate powers
 *
 * @author Orson Peters
 * @note Borrowed from the gist here: https://gist.github.com/nightcracker/3551590.
 *
 * @param base a 32bit signed integer.
 * @param exp amount to raise base by.
 * @return base ^ pow, or 0 on underflow/overflow.
 */
static int64_t fr_pow(int64_t base, int64_t exp)
{
	static const uint8_t highest_bit_set[] = {
		0, 1, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5,
		5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6 // anything past 63 is a guaranteed overflow with base > 1
	};

	int64_t result = 1;

	if (exp > 63) {
		if (base == 1) {
			return 1;
		}

		if (base == -1) {
			return 1 - 2 * (exp & 1);
		}
		return 0;	/* overflow */
	}

	switch (highest_bit_set[exp]) {
	case 6:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 5:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 4:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 3:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 2:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 1:
		if (exp & 1) result *= base;
	default:
		return result;
	}
}

/*
 *	Start of expression calculator.
 */
typedef enum expr_token_t {
	TOKEN_NONE = 0,
	TOKEN_INTEGER,

	TOKEN_AND,
	TOKEN_OR,

	TOKEN_LSHIFT,
	TOKEN_RSHIFT,

	TOKEN_ADD,
	TOKEN_SUBTRACT,

	TOKEN_DIVIDE,
	TOKEN_REMAINDER,
	TOKEN_MULTIPLY,

	TOKEN_POWER,
	TOKEN_LAST
} expr_token_t;

static int precedence[TOKEN_LAST + 1] = {
	0, 0, 1, 1,		/* and or */
	2, 2, 3, 3,		/* shift add */
	4, 4, 4, 5,		/* mul, pow */
	0
};

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

static bool get_expression(REQUEST *request, char const **string, int64_t *answer, expr_token_t prev);

static bool get_number(REQUEST *request, char const **string, int64_t *answer)
{
	int64_t x;
	bool invert = false;
	bool negative = false;
	char const *p = *string;
	vp_tmpl_t *vpt = NULL;

	/*
	 *	Look for a number.
	 */
	while (isspace((int) *p)) p++;

	/*
	 *	~1 == 0xff...ffe
	 */
	if (*p == '~') {
		invert = true;
		p++;
	}

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
		goto done;
	}

	if (*p == '-') {
		negative = true;
		p++;
	}

	/*
	 *	Look for an attribute.
	 */
	if (*p == '&') {
		int		i, max, err;
		ssize_t		slen;
		VALUE_PAIR	*vp;
		fr_cursor_t	cursor;

		p += 1;

		slen = tmpl_afrom_attr_substr(request, &vpt, p, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
		if (slen <= 0) {
			REDEBUG("Failed parsing attribute name '%s': %s", p, fr_strerror());
			return false;
		}

		p += slen;

		if (vpt->tmpl_num == NUM_COUNT) {
			REDEBUG("Attribute count is not supported");
			return false;
		}

		if (vpt->tmpl_num == NUM_ALL) {
			max = 65535;
		} else {
			max = 1;
		}

		x = 0;
		for (i = 0, vp = tmpl_cursor_init(&err, &cursor, request, vpt);
		     (i < max) && (vp != NULL);
		     i++, vp = fr_cursor_next(&cursor)) {
			int64_t y;

			if (vp->vp_type != FR_TYPE_UINT64) {
				fr_value_box_t	value;

				if (fr_value_box_cast(vp, &value, FR_TYPE_UINT64, NULL, &vp->data) < 0) {
					REDEBUG("Failed converting &%.*s to an integer value: %s", (int) vpt->len,
						vpt->name, fr_strerror());
					return false;
				}
				if (value.vb_uint64 > INT64_MAX) {
				overflow:
					talloc_free(vpt);
					REDEBUG("Value of &%.*s (%"PRIu64 ") would overflow a signed 64bit integer "
						"(our internal arithmetic type)", (int)vpt->len, vpt->name, value.vb_uint64);
					return false;
				}
				y = (int64_t)value.vb_uint64;

				RINDENT();
				RDEBUG3("&%.*s --> %" PRIu64, (int)vpt->len, vpt->name, y);
				REXDENT();
			} else {
				if (vp->vp_uint64 > INT64_MAX) goto overflow;
				y = (int64_t)vp->vp_uint64;
			}

			/*
			 *	Check for overflow without actually overflowing.
			 */
			if ((y > 0) && (x > (int64_t) INT64_MAX - y)) goto overflow;

			if ((y < 0) && (x < (int64_t) INT64_MIN - y)) goto overflow;

			x += y;
		} /* loop over all found VPs */

		if (err != 0) {
			RWDEBUG("Can't find &%.*s.  Using 0 as operand value", (int)vpt->len, vpt->name);
			goto done;
		}

		goto done;
	}

	/*
	 *	Do brackets recursively
	 */
	if (*p == '(') {
		p++;
		if (!get_expression(request, &p, &x, TOKEN_NONE)) return false;

		if (*p != ')') {
			RDEBUG("No trailing ')'");
			return false;
		}
		p++;
		goto done;
	}

	if ((*p < '0') || (*p > '9')) {
		RDEBUG2("Not a number at \"%s\"", p);
		return false;
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

done:
	if (vpt) talloc_free(vpt);

	if (invert) x = ~x;

	if (negative) x = -x;

	*string = p;
	*answer = x;
	return true;
}

static bool calc_result(REQUEST *request, int64_t lhs, expr_token_t op, int64_t rhs, int64_t *answer)
{
	switch (op) {
	default:
	case TOKEN_SUBTRACT:
		rhs = -rhs;
		/* FALL-THROUGH */

	case TOKEN_ADD:
		if ((rhs > 0) && (lhs > (int64_t) INT64_MAX - rhs)) {
		overflow:
			REDEBUG("Numerical overflow in expression!");
			return false;
		}

		if ((rhs < 0) && (lhs < (int64_t) INT64_MIN - rhs)) goto overflow;

		*answer = lhs + rhs;
		break;

	case TOKEN_DIVIDE:
		if (rhs == 0) {
			REDEBUG("Division by zero in expression!");
			return false;
		}

		*answer = lhs / rhs;
		break;

	case TOKEN_REMAINDER:
		if (rhs == 0) {
			RDEBUG("Division by zero!");
			return false;
		}

		*answer = lhs % rhs;
		break;

	case TOKEN_MULTIPLY:
		*answer = lhs * rhs;
		break;

	case TOKEN_LSHIFT:
		if (rhs > 63) {
			RDEBUG("Shift must be less than 63 (was %lld)", (long long int) rhs);
			return false;
		}

		*answer = lhs << rhs;
		break;

	case TOKEN_RSHIFT:
		if (rhs > 63) {
			RDEBUG("Shift must be less than 63 (was %lld)", (long long int) rhs);
			return false;
		}

		*answer = lhs >> rhs;
		break;

	case TOKEN_AND:
		*answer = lhs & rhs;
		break;

	case TOKEN_OR:
		*answer = lhs | rhs;
		break;

	case TOKEN_POWER:
		if (rhs > 63) {
			REDEBUG("Exponent must be between 0-63 (was %lld)", (long long int) rhs);
			return false;
		}

		if (lhs > 65535) {
			REDEBUG("Base must be between 0-65535 (was %lld)", (long long int) lhs);
			return false;
		}

		*answer = fr_pow(lhs, rhs);
		break;
	}

	return true;
}

static bool get_operator(REQUEST *request, char const **string, expr_token_t *op)
{
	int		i;
	char const	*p = *string;

	/*
	 *	All tokens are one character.
	 */
	for (i = 0; map[i].token != TOKEN_LAST; i++) {
		if (*p == map[i].op) {
			*op = map[i].token;
			*string = p + 1;
			return true;
		}
	}

	if ((p[0] == '<') && (p[1] == '<')) {
		*op = TOKEN_LSHIFT;
		*string = p + 2;
		return true;
	}

	if ((p[0] == '>') && (p[1] == '>')) {
		*op = TOKEN_RSHIFT;
		*string = p + 2;
		return true;
	}

	RDEBUG("Expected operator at \"%s\"", p);
	return false;
}


static bool get_expression(REQUEST *request, char const **string, int64_t *answer, expr_token_t prev)
{
	int64_t		lhs, rhs;
	char const 	*p, *op_p;
	expr_token_t	this;

	p = *string;

	if (!get_number(request, &p, &lhs)) return false;

redo:
	while (isspace((int) *p)) p++;

	/*
	 *	A number by itself is OK.
	 */
	if (!*p || (*p == ')')) {
		*answer = lhs;
		*string = p;
		return true;
	}

	/*
	 *	Peek at the operator.
	 */
	op_p = p;
	if (!get_operator(request, &p, &this)) return false;

	/*
	 *	a + b + c ... = (a + b) + c ...
	 *	a * b + c ... = (a * b) + c ...
	 *
	 *	Feed the current number to the caller, who will take
	 *	care of continuing.
	 */
	if (precedence[this] <= precedence[prev]) {
		*answer = lhs;
		*string = op_p;
		return true;
	}

	/*
	 *	a + b * c ... = a + (b * c) ...
	 */
	if (!get_expression(request, &p, &rhs, this)) return false;

	if (!calc_result(request, lhs, this, rhs, answer)) return false;

	/*
	 *	There may be more to calculate.  The answer we
	 *	calculated here is now the LHS of the lower priority
	 *	operation which follows the current expression.  e.g.
	 *
	 *	a * b + c ... = (a * b) + c ...
	 *	              =       d + c ...
	 */
	lhs = *answer;
	goto redo;
}

/*
 *  Do xlat of strings!
 */
static ssize_t expr_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	int64_t		result;
	char const 	*p;

	p = fmt;

	if (!get_expression(request, &p, &result, TOKEN_NONE)) {
		return -1;
	}

	if (*p) {
		RDEBUG("Invalid text after expression: %s", p);
		return -1;
	}

	snprintf(*out, outlen, "%lld", (long long int) result);
	return strlen(*out);
}

/** Generate a random integer value
 *
 */
static ssize_t rand_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 UNUSED REQUEST *request, char const *fmt)
{
	int64_t		result;

	result = atoi(fmt);

	/*
	 *	Too small or too big.
	 */
	if (result <= 0) return -1;
	if (result >= (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	snprintf(*out, outlen, "%ld", (long int) result);
	return strlen(*out);
}

/** Generate a string of random chars
 *
 *  Build strings of random chars, useful for generating tokens and passcodes
 *  Format similar to String::Random.
 */
static ssize_t randstr_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, char const *fmt)
{
	char const 	*p;
	char		*out_p = *out;
	unsigned int	result;
	unsigned int	number;
	size_t		freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		number = 0;

		/*
		 *	Modifiers are polite.
		 *
		 *	But we limit it to 100, because we don't want
		 *	utter stupidity.
		 */
		while (isdigit((int) *p)) {
			if (number >= 100) {
				p++;
				continue;
			}

			number *= 10;
			number += *p - '0';
			p++;
		}

	redo:
		result = fr_rand();

		switch (*p) {
		/*
		 *  Lowercase letters
		 */
		case 'c':
			*out_p++ = 'a' + (result % 26);
			break;

		/*
		 *  Uppercase letters
		 */
		case 'C':
			*out_p++ = 'A' + (result % 26);
			break;

		/*
		 *  Numbers
		 */
		case 'n':
			*out_p++ = '0' + (result % 10);
			break;

		/*
		 *  Alpha numeric
		 */
		case 'a':
			*out_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
			break;

		/*
		 *  Punctuation
		 */
		case '!':
			*out_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
			break;

		/*
		 *  Alpa numeric + punctuation
		 */
		case '.':
			*out_p++ = '!' + (result % 95);
			break;

		/*
		 *  Alpha numeric + salt chars './'
		 */
		case 's':
			*out_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
			break;

		/*
		 *  Chars suitable for One Time Password tokens.
		 *  Alpha numeric with easily confused char pairs removed.
		 */
		case 'o':
			*out_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
			break;

		/*
		 *  Binary data as hexits (we don't really support
		 *  non printable chars).
		 */
		case 'h':
			if (freespace < 2) {
				break;
			}

			snprintf(out_p, 3, "%02x", result % 256);

			/* Already decremented */
			freespace -= 1;
			out_p += 2;
			break;

		/*
		 *  Binary data with uppercase hexits
		 */
		case 'H':
			if (freespace < 2) {
				break;
			}

			snprintf(out_p, 3, "%02X", result % 256);

			/* Already decremented */
			freespace -= 1;
			out_p += 2;
			break;

		default:
			REDEBUG("Invalid character class '%c'", *p);

			return -1;
		}

		if (number > 0) {
			number--;
			goto redo;
		}

		p++;
	}

	*out_p++ = '\0';

	return outlen - freespace;
}

/** URLencode special characters
 *
 * Example: "%{urlquote:http://example.org/}" == "http%3A%47%47example.org%47"
 */
static ssize_t urlquote_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     UNUSED REQUEST *request, char const *fmt)
{
	char const 	*p;
	char		*out_p = *out;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (isalnum(*p)) {
			*out_p++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*out_p++ = *p++;
			break;

		default:
			if (freespace < 3)
				break;

			/* MUST be upper case hex to be compliant */
			snprintf(out_p, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			/* Already decremented */
			freespace -= 2;
			out_p += 3;
		}
	}

	*out_p = '\0';

	return outlen - freespace;
}

/** URLdecode special characters
 *
 * Example: "%{urlunquote:http%%3A%%47%%47example.org%%47}" == "http://example.org/"
 *
 * Remember to escape % with %% in strings, else xlat will try to parse it.
 */
static ssize_t urlunquote_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			       REQUEST *request, char const *fmt)
{
	char const *p;
	char *out_p = *out;
	char *c1, *c2;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (*p != '%') {
			*out_p++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower(*++p), 16)) ||
		    !(c2 = memchr(hextab, tolower(*++p), 16))) {
			REMARKER(fmt, p - fmt, "Non-hex char in % sequence");
		   	return -1;
		}
		p++;
		*out_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*out_p = '\0';

	return outlen - freespace;
}

/** Equivalent to the old safe_characters functionality in rlm_sql but with utf8 support
 *
 * @verbatim Example: "%{escape:<img>foo.jpg</img>}" == "=60img=62foo.jpg=60/img=62" @endverbatim
 */
static ssize_t escape_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   void const *mod_inst, UNUSED void const *xlat_inst,
			   UNUSED REQUEST *request, char const *fmt)
{
	rlm_expr_t const *inst = mod_inst;
	char const *p = fmt;
	char *out_p = *out;
	size_t freespace = outlen;

	while (p[0]) {
		int chr_len = 1;
		int ret = 1;	/* -Werror=uninitialized */

		if (fr_utf8_strchr(&chr_len, inst->allowed_chars, p) == NULL) {
			/*
			 *	'=' 1 + ([hex]{2}) * chr_len)
			 */
			if (freespace <= (size_t)(1 + (chr_len * 3))) break;

			switch (chr_len) {
			case 4:
				ret = snprintf(out_p, freespace, "=%02X=%02X=%02X=%02X",
					       (uint8_t)p[0], (uint8_t)p[1], (uint8_t)p[2], (uint8_t)p[3]);
				break;

			case 3:
				ret = snprintf(out_p, freespace, "=%02X=%02X=%02X",
					       (uint8_t)p[0], (uint8_t)p[1], (uint8_t)p[2]);
				break;

			case 2:
				ret = snprintf(out_p, freespace, "=%02X=%02X", (uint8_t)p[0], (uint8_t)p[1]);
				break;

			case 1:
				ret = snprintf(out_p, freespace, "=%02X", (uint8_t)p[0]);
				break;
			}

			p += chr_len;
			out_p += ret;
			freespace -= ret;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (freespace <= 1) break;

		/*
		 *	Allowed character (copy whole mb chars at once)
		 */
		memcpy(out_p, p, chr_len);
		out_p += chr_len;
		p += chr_len;
		freespace -= chr_len;
	}
	*out_p = '\0';

	return outlen - freespace;
}

/** Equivalent to the old safe_characters functionality in rlm_sql
 *
 * @verbatim Example: "%{unescape:=60img=62foo.jpg=60/img=62}" == "<img>foo.jpg</img>" @endverbatim
 */
static ssize_t unescape_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     UNUSED REQUEST *request, char const *fmt)
{
	char const *p;
	char *out_p = *out;
	char *c1, *c2, c3;
	size_t	freespace = outlen;

	if (outlen <= 1) return 0;

	p = fmt;
	while (*p && (--freespace > 0)) {
		if (*p != '=') {
		next:

			*out_p++ = *p++;
			continue;
		}

		/* Is a = char */

		if (!(c1 = memchr(hextab, tolower(*(p + 1)), 16)) ||
		    !(c2 = memchr(hextab, tolower(*(p + 2)), 16))) goto next;
		c3 = ((c1 - hextab) << 4) + (c2 - hextab);

		*out_p++ = c3;
		p += 3;
	}

	*out_p = '\0';

	return outlen - freespace;
}

/** Convert a string to lowercase
 *
 * Example: "%{tolower:Bar}" == "bar"
 *
 * Probably only works for ASCII
 */
static ssize_t tolower_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    UNUSED REQUEST *request, char const *fmt)
{
	char *q;
	char const *p;

	if (outlen <= 1) return 0;

	for (p = fmt, q = *out; *p != '\0'; p++, outlen--) {
		if (outlen <= 1) break;

		*(q++) = tolower((int) *p);
	}

	*q = '\0';

	return strlen(*out);
}

/** Convert a string to uppercase
 *
 * Example: "%{toupper:Foo}" == "FOO"
 *
 * Probably only works for ASCII
 */
static ssize_t toupper_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    UNUSED REQUEST *request, char const *fmt)
{
	char *q;
	char const *p;

	if (outlen <= 1) return 0;

	for (p = fmt, q = *out; *p != '\0'; p++, outlen--) {
		if (outlen <= 1) break;

		*(q++) = toupper((int) *p);
	}

	*q = '\0';

	return strlen(*out);
}

/** Decodes data or &Attr-Name to data
 *
 * This needs to die, and hopefully will die, when xlat functions accept
 * xlat node structures.
 *
 * @param out		fr_value_box_t containing a shallow copy of the attribute,
 *			or the fmt string.
 * @param request	current request.
 * @param fmt		string.
 * @returns
 *	- The length of the data.
 *	- -1 on failure.
 */
static int fr_value_box_from_fmt(fr_value_box_t *out, REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	while (isspace((int) *fmt)) fmt++;

	/*
	 *	Not an attribute reference?  Just use the input format.
	 */
	if (*fmt != '&') {
		memset(out, 0, sizeof(*out));
		out->vb_strvalue = fmt;
		out->datum.length = talloc_array_length(fmt) - 1;
		out->type = FR_TYPE_STRING;
		return 0;
	}

	/*
	 *	If it's an attribute reference, get the underlying
	 *	attribute, and then store the data in network byte
	 *	order.
	 */
	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) return -1;

	/*
	 *	These are large types.  Return pointers to the
	 *	data instead of copying the data.
	 */
	fr_value_box_copy_shallow(NULL, out, &vp->data);

	return 0;
}

static int fr_value_box_to_bin(TALLOC_CTX *ctx, REQUEST *request, uint8_t **out, size_t *outlen, fr_value_box_t const *in)
{
	fr_value_box_t bin;

	switch (in->type) {
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		memcpy(out, &in->datum.ptr, sizeof(in));
		*outlen = in->datum.length;
		return 0;

	default:
		if (fr_value_box_cast(ctx, &bin, FR_TYPE_OCTETS, NULL, in) < 0) {
			RPERROR("Failed casting xlat input to 'octets'");
			return -1;
		}
		memcpy(out, &bin.datum.ptr, sizeof(in));
		*outlen = bin.datum.length;
		return 0;
	}
}

#define VALUE_FROM_FMT(_tmp_ctx, _p, _len, _request, _fmt) \
	fr_value_box_t _value; \
	if (fr_value_box_from_fmt(&_value, _request, _fmt) < 0) return -1; \
	if (!_tmp_ctx) _tmp_ctx = talloc_new(_request); \
	if (fr_value_box_to_bin(_tmp_ctx, _request, &_p, &_len, &_value) < 0) { \
		talloc_free(_tmp_ctx); \
		return -1; \
	}


/** Calculate the MD5 hash of a string or attribute.
 *
 * Example: "%{md5:foo}" == "acbd18db4cc2f85cedef654fccc4a4d8"
 */
static ssize_t md5_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			REQUEST *request, char const *fmt)
{
	uint8_t		digest[16];
	size_t		i, len, inlen;
	uint8_t		*p;
	FR_MD5_CTX	md5_ctx;
	TALLOC_CTX	*tmp_ctx = NULL;

	VALUE_FROM_FMT(tmp_ctx, p, inlen, request, fmt);

	fr_md5_init(&md5_ctx);
	fr_md5_update(&md5_ctx, p, inlen);
	fr_md5_final(digest, &md5_ctx);

	/*
	 *	Each digest octet takes two hex digits, plus one for
	 *	the terminating NUL.
	 */
	len = (outlen / 2) - 1;
	if (len > 16) len = 16;

	for (i = 0; i < len; i++) snprintf((*out) + (i * 2), 3, "%02x", digest[i]);

	talloc_free(tmp_ctx);

	return strlen(*out);
}

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example: "%{sha1:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
static ssize_t sha1_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	uint8_t		digest[20];
	size_t		i, len, inlen;
	uint8_t		*p;
	fr_sha1_ctx 	sha1_ctx;
	TALLOC_CTX	*tmp_ctx = NULL;

	VALUE_FROM_FMT(tmp_ctx, p, inlen, request, fmt);

	fr_sha1_init(&sha1_ctx);
	fr_sha1_update(&sha1_ctx, p, inlen);
	fr_sha1_final(digest, &sha1_ctx);

	/*
	 *      Each digest octet takes two hex digits, plus one for
	 *      the terminating NUL. SHA1 is 160 bits (20 bytes)
	 */
	len = (outlen / 2) - 1;
	if (len > 20) len = 20;

	for (i = 0; i < len; i++) snprintf((*out) + (i * 2), 3, "%02x", digest[i]);

	talloc_free(tmp_ctx);

	return strlen(*out);
}

/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example: "%{sha256:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
 */
#ifdef HAVE_OPENSSL_EVP_H
static ssize_t evp_md_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt, EVP_MD const *md)
{
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digestlen, i, len;
	size_t		inlen;
	uint8_t		*p;
	EVP_MD_CTX	*md_ctx;
	TALLOC_CTX	*tmp_ctx = NULL;

	VALUE_FROM_FMT(tmp_ctx, p, inlen, request, fmt);

	md_ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, p, inlen);
	EVP_DigestFinal_ex(md_ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(md_ctx);

	/*
	 *      Each digest octet takes two hex digits, plus one for
	 *      the terminating NUL.
	 */
	len = (outlen / 2) - 1;
	if (len > digestlen) len = digestlen;

	for (i = 0; i < len; i++) snprintf((*out) + (i * 2), 3, "%02x", digest[i]);

	talloc_free(tmp_ctx);

	return strlen(*out);
}

#  define EVP_MD_XLAT(_md) \
static ssize_t _md##_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,\
			  void const *mod_inst, void const *xlat_inst,\
			  REQUEST *request, char const *fmt)\
{\
	return evp_md_xlat(ctx, out, outlen, mod_inst, xlat_inst, request, fmt, EVP_##_md());\
}

EVP_MD_XLAT(sha256)
EVP_MD_XLAT(sha512)

#  ifdef HAVE_EVP_SHA3_512
EVP_MD_XLAT(sha3_256)
EVP_MD_XLAT(sha3_512)
#  endif
#endif

/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example: "%{hmacmd5:foo bar}" == "Zm9v"
 */
static ssize_t hmac_md5_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     REQUEST *request, char const *fmt)
{

	char const	*p, *q;
	uint8_t		digest[MD5_DIGEST_LENGTH];

	char		*data_fmt;

	uint8_t		*data_p, *key_p;
	size_t		data_len, key_len;
	TALLOC_CTX	*tmp_ctx = NULL;

	if (outlen <= (sizeof(digest) * 2)) {
		REDEBUG("Insufficient space to write digest, needed %zu bytes, have %zu bytes",
			(sizeof(digest) * 2) + 1, outlen);
		return -1;
	}

	p = fmt;
	while (isspace(*p)) p++;

	/*
	 *	Find the delimiting char
	 */
	q = strchr(p, ' ');
	if (!q) {
		REDEBUG("HMAC requires exactly two arguments (&data &key)");
		return -1;
	}

	tmp_ctx = talloc_new(ctx);
	data_fmt = talloc_bstrndup(tmp_ctx, p, q - p);
	p = q + 1;

	{
		VALUE_FROM_FMT(tmp_ctx, data_p, data_len, request, data_fmt);
	}
	{
		VALUE_FROM_FMT(tmp_ctx, key_p, key_len, request, p);
	}
	fr_hmac_md5(digest, data_p, data_len, key_p, key_len);
	talloc_free(tmp_ctx);

	return fr_bin2hex(*out, digest, sizeof(digest));
}

/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example: "%{hmacsha1:foo bar}" == "Zm9v"
 */
static ssize_t hmac_sha1_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	char const	*p, *q;
	uint8_t		digest[SHA1_DIGEST_LENGTH];

	char		*data_fmt;

	uint8_t		*data_p, *key_p;
	size_t		data_len, key_len;
	TALLOC_CTX	*tmp_ctx = NULL;

	if (outlen <= (sizeof(digest) * 2)) {
		REDEBUG("Insufficient space to write digest, needed %zu bytes, have %zu bytes",
			(sizeof(digest) * 2) + 1, outlen);
		return -1;
	}

	p = fmt;
	while (isspace(*p)) p++;

	/*
	 *	Find the delimiting char
	 */
	q = strchr(p, ' ');
	if (!q) {
		REDEBUG("HMAC requires exactly two arguments (&data &key)");
		return -1;
	}

	tmp_ctx = talloc_new(ctx);
	data_fmt = talloc_bstrndup(tmp_ctx, p, q - p);
	p = q + 1;

	{
		VALUE_FROM_FMT(tmp_ctx, data_p, data_len, request, data_fmt);
	}
	{
		VALUE_FROM_FMT(tmp_ctx, key_p, key_len, request, p);
	}

	fr_hmac_sha1(digest, data_p, data_len, key_p, key_len);

	talloc_free(tmp_ctx);

	return fr_bin2hex(*out, digest, sizeof(digest));
}

/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example: "%{pairs:request:}" == "User-Name = 'foo', User-Password = 'bar'"
 */
static ssize_t pairs_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*vpt = NULL;
	fr_cursor_t	cursor;
	size_t		len, freespace = outlen;
	char		*p = *out;

	VALUE_PAIR *vp;

	if (tmpl_afrom_attr_str(ctx, &vpt, fmt, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) <= 0) {
		REDEBUG("%s", fr_strerror());
		return -1;
	}

	for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     	FR_TOKEN op = vp->op;

	     	vp->op = T_OP_EQ;
		len = fr_pair_snprint(p, freespace, vp);
		vp->op = op;

		if (is_truncated(len, freespace)) {
		no_space:
			talloc_free(vpt);
			REDEBUG("Insufficient space to store pair string, needed %zu bytes have %zu bytes",
				(p - *out) + len, outlen);
			return -1;
		}
		p += len;
		freespace -= len;

		if (freespace < 2) {
			len = 2;
			goto no_space;
		}

		*p++ = ',';
		*p++ = ' ';
		freespace -= 2;
	}

	/* Trim the trailing ', ' */
	if (p != *out) p -= 2;
	*p = '\0';
	talloc_free(vpt);

	return (p - *out);
}

/** Encode string or attribute as base64
 *
 * Example: "%{base64:foo}" == "Zm9v"
 */
static ssize_t base64_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	size_t		inlen;
	uint8_t		*p;
	TALLOC_CTX	*tmp_ctx = NULL;
	ssize_t		ret;

	VALUE_FROM_FMT(tmp_ctx, p, inlen, request, fmt);

	/*
	 *  We can accurately calculate the length of the output string
	 *  if it's larger than outlen, the output would be useless so abort.
	 */
	if ((FR_BASE64_ENC_LENGTH(inlen) + 1) > outlen) {
		REDEBUG("xlat failed");

		talloc_free(tmp_ctx);

		return -1;
	}

	ret = fr_base64_encode(*out, outlen, p, inlen);
	talloc_free(tmp_ctx);

	return ret;
}

/** Convert base64 to hex
 *
 * Example: "%{base64tohex:Zm9v}" == "666f6f"
 */
static ssize_t base64_to_hex_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				  REQUEST *request, char const *fmt)
{
	uint8_t decbuf[1024];

	ssize_t declen;
	ssize_t len = strlen(fmt);

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

	return fr_bin2hex(*out, decbuf, declen);
}

/** Split an attribute into multiple new attributes based on a delimiter
 *
 * @todo should support multibyte delimiter for string types.
 *
 * Example: "%{explode:&ref <delim>}"
 */
static ssize_t explode_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			    REQUEST *request, char const *fmt)
{
	vp_tmpl_t	*vpt = NULL;
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor, to_merge;
	VALUE_PAIR 	*head = NULL;
	ssize_t		slen;
	int		count = 0;
	char const	*p = fmt;
	char		delim;

	/*
	 *  Trim whitespace
	 */
	while (isspace(*p) && p++);

	slen = tmpl_afrom_attr_substr(ctx, &vpt, p, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
	if (slen <= 0) {
		REDEBUG("%s", fr_strerror());
		return -1;
	}

	p += slen;

	if (*p++ != ' ') {
	arg_error:
		talloc_free(vpt);
		REDEBUG("explode needs exactly two arguments: &ref <delim>");
		return -1;
	}

	if (*p == '\0') goto arg_error;

	delim = *p;

	fr_cursor_init(&to_merge, &head);

	vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
	while (vp) {
	     	VALUE_PAIR *nvp;
	     	char const *end;
		char const *q;

		/*
		 *	This can theoretically operate on lists too
		 *	so we need to check the type of each attribute.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			break;

		default:
			goto next;
		}

		p = vp->vp_ptr;
		end = p + vp->vp_length;
		while (p < end) {
			q = memchr(p, delim, end - p);
			if (!q) {
				/* Delimiter not present in attribute */
				if (p == vp->vp_ptr) goto next;
				q = end;
			}

			/* Skip zero length */
			if (q == p) {
				p = q + 1;
				continue;
			}

			nvp = fr_pair_afrom_da(talloc_parent(vp), vp->da);
			if (!nvp) {
				fr_pair_list_free(&head);
				return -1;
			}
			nvp->tag = vp->tag;

			switch (vp->vp_type) {
			case FR_TYPE_OCTETS:
			{
				uint8_t *buff;

				buff = talloc_array(nvp, uint8_t, q - p);
				memcpy(buff, p, q - p);
				fr_pair_value_memsteal(nvp, buff);
			}
				break;

			case FR_TYPE_STRING:
			{
				char *buff;

				buff = talloc_array(nvp, char, (q - p) + 1);
				memcpy(buff, p, q - p);
				buff[q - p] = '\0';
				fr_pair_value_strsteal(nvp, (char *)buff);
			}
				break;

			default:
				rad_assert(0);
			}

			fr_cursor_append(&to_merge, nvp);

			p = q + 1;	/* next */

			count++;
		}

		/*
		 *	Remove the unexploded version
		 */
		vp = fr_cursor_remove(&cursor);
		talloc_free(vp);
		/*
		 *	Remove sets cursor->current to
		 *	the next iter value.
		 */
		vp = fr_cursor_current(&cursor);
		continue;

	next:
	    	vp = fr_cursor_next(&cursor);
	}

	fr_cursor_merge(&cursor, &to_merge);
	talloc_free(vpt);

	return snprintf(*out, outlen, "%i", count);
}

/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %{nexttime:1h} would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %{rand:} to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 */
static ssize_t next_time_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	long		num;

	char const 	*p;
	char 		*q;
	time_t		now;
	struct tm	*local, local_buff;

	now = time(NULL);
	local = localtime_r(&now, &local_buff);

	p = fmt;

	num = strtoul(p, &q, 10);
	if (!q || *q == '\0') {
		REDEBUG("nexttime: <int> must be followed by period specifier (h|d|w|m|y)");
		return -1;
	}

	if (p == q) {
		num = 1;
	} else {
		p += q - p;
	}

	local->tm_sec = 0;
	local->tm_min = 0;

	switch (*p) {
	case 'h':
		local->tm_hour += num;
		break;

	case 'd':
		local->tm_hour = 0;
		local->tm_mday += num;
		break;

	case 'w':
		local->tm_hour = 0;
		local->tm_mday += (7 - local->tm_wday) + (7 * (num-1));
		break;

	case 'm':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon += num;
		break;

	case 'y':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon = 0;
		local->tm_year += num;
		break;

	default:
		REDEBUG("nexttime: Invalid period specifier '%c', must be h|d|w|m|y", *p);
		return -1;
	}

	return snprintf(*out, outlen, "%" PRIu64, (uint64_t)(mktime(local) - now));
}


/** Parse the 3 arguments to lpad / rpad.
 *
 * Parses a fmt string with the components @verbatim <tmpl> <pad_len> <pad_char>@endverbatim
 *
 * @param[out] vpt_p		Template to retrieve value to pad.
 * @param[out] pad_len_p	Length the string needs to be padded to.
 * @param[out] pad_char_p	Char to use for padding.
 * @param[in] request		The current request.
 * @param[in] fmt		string to parse.
 *
 * @return
 *	- <= 0 the negative offset the parse error ocurred at.
 *	- >0 how many bytes of fmt were parsed.
 */
static ssize_t parse_pad(vp_tmpl_t **vpt_p, size_t *pad_len_p, char *pad_char_p, REQUEST *request, char const *fmt)
{
	ssize_t		slen;
	unsigned long	pad_len;
	char const	*p;
	char		*end;
	vp_tmpl_t	*vpt;

	*pad_char_p = ' ';		/* the default */

	*vpt_p = NULL;

	p = fmt;
	while (isspace((int) *p)) p++;

	if (*p != '&') {
		RDEBUG("First argument must be an attribute reference");
		return 0;
	}

	slen = tmpl_afrom_attr_substr(request, &vpt, p, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
	if (slen <= 0) {
		RDEBUG("Failed parsing input string: %s", fr_strerror());
		return slen;
	}

	p = fmt + slen;

	while (isspace((int) *p)) p++;

	pad_len = strtoul(p, &end, 10);
	if ((pad_len == ULONG_MAX) || (pad_len > 8192)) {
		talloc_free(vpt);
		RDEBUG("Invalid pad_len found at: %s", p);
		return fmt - p;
	}

	p += (end - p);

	/*
	 *	The pad_char_p character is optional.
	 *
	 *	But we must have a space after the previous number,
	 *	and we must have only ONE pad_char_p character.
	 */
	if (*p) {
		if (!isspace(*p)) {
			talloc_free(vpt);
			RDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		while (isspace((int) *p)) p++;

		if (p[1] != '\0') {
			talloc_free(vpt);
			RDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		*pad_char_p = *p++;
	}

	*vpt_p = vpt;
	*pad_len_p = pad_len;

	return p - fmt;
}


/** left pad a string
 *
 *  %{lpad:&Attribute-Name length 'x'}
 */
static ssize_t lpad_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	vp_tmpl_t	*vpt;
	char		*to_pad = NULL;

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!rad_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return -1;

	/*
	 *	Already big enough, no padding required...
	 */
	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	/*
	 *	Realloc is actually pretty cheap in most cases...
	 */
	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to shift the string to the right, and pad with
	 *	"fill" characters.
	 */
	memmove(to_pad + (pad - len), to_pad, len + 1);
	memset(to_pad, fill, pad - len);

	*out = to_pad;

	return pad;
}

/** right pad a string
 *
 *  %{rpad:&Attribute-Name length 'x'}
 */
static ssize_t rpad_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	vp_tmpl_t	*vpt;
	char		*to_pad = NULL;

	rad_assert(!*out);

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!rad_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return 0;

	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to pad with "fill" characters.
	 */
	memset(to_pad + len, fill, pad - len);
	to_pad[pad] = '\0';

	*out = to_pad;

	return pad;
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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_expr_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	xlat_register(inst, inst->xlat_name, expr_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	xlat_register(inst, "rand", rand_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "randstr", randstr_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "urlquote", urlquote_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "urlunquote", urlunquote_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "escape", escape_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "unescape", unescape_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "tolower", tolower_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "toupper", toupper_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "md5", md5_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "sha1", sha1_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
#ifdef HAVE_OPENSSL_EVP_H
	xlat_register(inst, "sha256", sha256_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "sha512", sha512_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
#endif
	xlat_register(inst, "hmacmd5", hmac_md5_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "hmacsha1", hmac_sha1_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "pairs", pairs_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	xlat_register(inst, "base64", base64_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "base64tohex", base64_to_hex_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	xlat_register(inst, "explode", explode_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	xlat_register(inst, "nexttime", next_time_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(inst, "lpad", lpad_xlat, NULL, NULL, 0, 0, true);
	xlat_register(inst, "rpad", rpad_xlat, NULL, NULL, 0, 0, true);

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
extern rad_module_t rlm_expr;
rad_module_t rlm_expr = {
	.magic		= RLM_MODULE_INIT,
	.name		= "expr",
	.inst_size	= sizeof(rlm_expr_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
};
