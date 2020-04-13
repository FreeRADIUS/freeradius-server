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
 * @brief Register an xlat expansion to perform basic mathematical operations.
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 * @copyright 2002 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/server/base.h>

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>

#include <ctype.h>

#include "rlm_expr.h"

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const *xlat_name;
} rlm_expr_t;

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
		if (base == 1) return 1;
		if (base == -1) return 1 - 2 * (exp & 1);
		return 0;	/* overflow */
	}

	switch (highest_bit_set[exp]) {
	case 6:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
		/* FALL-THROUGH */
	case 5:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
		/* FALL-THROUGH */
	case 4:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
		/* FALL-THROUGH */
	case 3:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
		/* FALL-THROUGH */
	case 2:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
		/* FALL-THROUGH */
	case 1:
		if (exp & 1) result *= base;
		/* FALL-THROUGH */
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

typedef struct {
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
	fr_skip_whitespace(p);

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

		slen = tmpl_afrom_attr_substr(request, NULL, &vpt, p, -1, &(vp_tmpl_rules_t){ .dict_def = request->dict });
		if (slen <= 0) {
			RPEDEBUG("Failed parsing attribute name '%s'", p);
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
			int64_t		y;
			fr_value_box_t	value;

			if (vp->vp_type != FR_TYPE_UINT64) {
				if (fr_value_box_cast(vp, &value, FR_TYPE_UINT64, NULL, &vp->data) < 0) {
					RPEDEBUG("Failed converting &%.*s to an integer value", (int) vpt->len,
						 vpt->name);
					return false;
				}
				if (value.vb_uint64 > INT64_MAX) {
				overflow:
					talloc_free(vpt);
					REDEBUG("Value of &%.*s (%pV) would overflow a signed 64bit integer "
						"(our internal arithmetic type)", (int)vpt->len, vpt->name, &value);
					return false;
				}
				y = (int64_t)value.vb_uint64;

				RINDENT();
				RDEBUG3("&%.*s --> %" PRIu64, (int)vpt->len, vpt->name, y);
				REXDENT();
			} else {
				if (vp->vp_uint64 > INT64_MAX) {
					/*
					 *	So we can print out the correct value
					 *	in the overflow error message.
					 */
					fr_value_box_copy(NULL, &value, &vp->data);
					goto overflow;
				}
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
			REDEBUG("No trailing ')'");
			return false;
		}
		p++;
		goto done;
	}

	if ((*p < '0') || (*p > '9')) {
		REDEBUG("Not a number at \"%s\"", p);
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
			REDEBUG("Division by zero!");
			return false;
		}

		*answer = lhs % rhs;
		break;

	case TOKEN_MULTIPLY:
		*answer = lhs * rhs;
		break;

	case TOKEN_LSHIFT:
		if (rhs > 62) {
			REDEBUG("Shift must be less than 62 (was %lld)", (long long int) rhs);
			return false;
		}

		*answer = lhs << rhs;
		break;

	case TOKEN_RSHIFT:
		if (rhs > 62) {
			REDEBUG("Shift must be less than 62 (was %lld)", (long long int) rhs);
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

	REDEBUG("Expected operator at \"%s\"", p);

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
	fr_skip_whitespace(p);

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

/** Xlat expressions
 *
 * Example (NAS-Port = 1):
@verbatim
"%{expr:2 + 3 + &NAS-Port}" == 6
@endverbatim
 *
 * @ingroup xlat_functions
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
		REDEBUG("Invalid text after expression: %s", p);
		return -1;
	}

	snprintf(*out, outlen, "%lld", (long long int) result);
	return strlen(*out);
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
extern module_t rlm_expr;
module_t rlm_expr = {
	.magic		= RLM_MODULE_INIT,
	.name		= "expr",
	.inst_size	= sizeof(rlm_expr_t),
	.bootstrap	= mod_bootstrap,
};
