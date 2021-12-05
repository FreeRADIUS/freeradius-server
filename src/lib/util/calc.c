/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file src/lib/util/calc.c
 * @brief Functions to perform calculations on leaf values
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/util/strerror.h>
#include <math.h>
#include "calc.h"

#define swap(_a, _b) do { __typeof__ (_a) _tmp = _a; _a = _b; _b = _tmp; } while (0)

#define ERR_OVERFLOW (-3)
#define ERR_INVALID  (-2)

/** Updates type (a,b) -> c
 *
 *  Note that we MUST have a less than b here.  Otherwise there will
 *  be two entries for the same upcast, and the entries may get out of
 *  sync.
 */
static const fr_type_t upcast[FR_TYPE_MAX + 1][FR_TYPE_MAX + 1] = {
	/*
	 *	Prefix + int --> ipaddr
	 */
	[FR_TYPE_IPV4_PREFIX] = {
		[FR_TYPE_UINT8] =   FR_TYPE_IPV4_ADDR,
		[FR_TYPE_UINT16] =  FR_TYPE_IPV4_ADDR,
		[FR_TYPE_UINT32] =  FR_TYPE_IPV4_ADDR,
		[FR_TYPE_UINT64] =  FR_TYPE_IPV4_ADDR,

		[FR_TYPE_SIZE] =    FR_TYPE_IPV4_ADDR,

		[FR_TYPE_INT8] =    FR_TYPE_IPV4_ADDR,
		[FR_TYPE_INT16] =   FR_TYPE_IPV4_ADDR,
		[FR_TYPE_INT32] =   FR_TYPE_IPV4_ADDR,
		[FR_TYPE_INT64] =   FR_TYPE_IPV4_ADDR,

		[FR_TYPE_FLOAT32] = FR_TYPE_IPV4_ADDR,
		[FR_TYPE_FLOAT64] = FR_TYPE_IPV4_ADDR,
	},

	[FR_TYPE_IPV6_PREFIX] = {
		[FR_TYPE_UINT8] =   FR_TYPE_IPV6_ADDR,
		[FR_TYPE_UINT16] =  FR_TYPE_IPV6_ADDR,
		[FR_TYPE_UINT32] =  FR_TYPE_IPV6_ADDR,
		[FR_TYPE_UINT64] =  FR_TYPE_IPV6_ADDR,

		[FR_TYPE_SIZE] =    FR_TYPE_IPV6_ADDR,

		[FR_TYPE_INT8] =    FR_TYPE_IPV6_ADDR,
		[FR_TYPE_INT16] =   FR_TYPE_IPV6_ADDR,
		[FR_TYPE_INT32] =   FR_TYPE_IPV6_ADDR,
		[FR_TYPE_INT64] =   FR_TYPE_IPV6_ADDR,

		[FR_TYPE_FLOAT32] = FR_TYPE_IPV6_ADDR,
		[FR_TYPE_FLOAT64] = FR_TYPE_IPV6_ADDR,
	},

	/*
	 *	Various ints get cast to the next highest size which
	 *	can hold their values.
	 */
	[FR_TYPE_UINT8] = {
		[FR_TYPE_UINT16] = FR_TYPE_UINT16,
		[FR_TYPE_UINT32] = FR_TYPE_UINT32,
		[FR_TYPE_UINT64] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE] =   FR_TYPE_SIZE,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_INT8]   = FR_TYPE_INT16,
		[FR_TYPE_INT16]  = FR_TYPE_INT16,
		[FR_TYPE_INT32]  = FR_TYPE_INT32,
		[FR_TYPE_INT64]  = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_UINT16] = {
		[FR_TYPE_UINT32] = FR_TYPE_UINT32,
		[FR_TYPE_UINT64] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE] =   FR_TYPE_SIZE,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_INT8]   = FR_TYPE_INT32,
		[FR_TYPE_INT16]  = FR_TYPE_INT32,
		[FR_TYPE_INT32]  = FR_TYPE_INT32,
		[FR_TYPE_INT64]  = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_UINT32] = {
		[FR_TYPE_UINT64] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE]   = FR_TYPE_SIZE,

		[FR_TYPE_DATE]   = FR_TYPE_DATE,

		[FR_TYPE_INT8]   = FR_TYPE_INT64,
		[FR_TYPE_INT16]  = FR_TYPE_INT64,
		[FR_TYPE_INT32]  = FR_TYPE_INT64,
		[FR_TYPE_INT64]  = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_UINT64] = {
		[FR_TYPE_SIZE]  = FR_TYPE_SIZE,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_SIZE] = {
		[FR_TYPE_INT8]    = FR_TYPE_INT64,
		[FR_TYPE_INT16]   = FR_TYPE_INT64,
		[FR_TYPE_INT32]   = FR_TYPE_INT64,
		[FR_TYPE_INT64]   = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_DATE] = {
		[FR_TYPE_INT8]	= FR_TYPE_DATE,
		[FR_TYPE_INT16]	= FR_TYPE_DATE,
		[FR_TYPE_INT32] = FR_TYPE_DATE,
		[FR_TYPE_INT64] = FR_TYPE_DATE,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_DATE,

		[FR_TYPE_FLOAT32] = FR_TYPE_DATE,
		[FR_TYPE_FLOAT64] = FR_TYPE_DATE,
	},

	/*
	 *	Signed ints
	 */
	[FR_TYPE_INT8] = {
		[FR_TYPE_INT16] = FR_TYPE_INT32,
		[FR_TYPE_INT32] = FR_TYPE_INT32,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT16] = {
		[FR_TYPE_INT32] = FR_TYPE_INT64,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT32] = {
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT64] = {
		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_TIME_DELTA] = {
		[FR_TYPE_FLOAT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT64] = FR_TYPE_TIME_DELTA,
	},

	[FR_TYPE_FLOAT32] = {
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},
};


static int calc_bool(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	fr_value_box_t one, two;

	fr_assert(dst->type == FR_TYPE_BOOL);

	if (a->type != FR_TYPE_BOOL) {
		if (fr_value_box_cast(NULL, &one, FR_TYPE_BOOL, NULL, a) < 0) return -1;
		a = &one;
	}

	if (a->type != FR_TYPE_BOOL) {
		if (fr_value_box_cast(NULL, &two, FR_TYPE_BOOL, NULL, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_ADD:
		/*
		 *	1+1 = 2, which isn't a valid boolean value.
		 */
		if (a->vb_bool & b->vb_bool) return ERR_OVERFLOW;

		dst->vb_bool = a->vb_bool | b->vb_bool;
		break;

	case T_SUB:
		/*
		 *	0-1 = -1, which isn't a valid boolean value.
		 */
		if (a->vb_bool < b->vb_bool) return ERR_OVERFLOW;

		dst->vb_bool = a->vb_bool - b->vb_bool;
		break;

	case T_MUL:		/* MUL is just AND here! */
	case T_AND:
		dst->vb_bool = a->vb_bool & b->vb_bool;
		break;

	case T_OR:
		dst->vb_bool = a->vb_bool | b->vb_bool;
		break;

	default:
		return ERR_INVALID;
	}

	return 0;
}

static int calc_date(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	fr_value_box_t one, two;
	bool overflow;
	int64_t when;

	fr_assert(dst->type == FR_TYPE_DATE);

	if ((a->type == FR_TYPE_DATE) && (b->type == FR_TYPE_DATE)) {
		fr_strerror_const("Cannot perform operation on two dates");
		return -1;
	}

	fr_assert(!dst->enumv);	/* unix time is always seconds */

	/*
	 *	Cast dates to time delta, do the conversions.
	 */
	if (a->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(NULL, &one, FR_TYPE_TIME_DELTA, NULL, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(NULL, &two, FR_TYPE_TIME_DELTA, NULL, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_ADD:
		if (!fr_add(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_OVERFLOW;

		dst->vb_date = fr_unix_time_from_integer(&overflow, when, FR_TIME_RES_NSEC);
		if (overflow) return ERR_OVERFLOW; /* overflow */
		break;

	case T_SUB:
		if (!fr_sub(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_OVERFLOW;

		dst->vb_date = fr_unix_time_from_integer(&overflow, when, FR_TIME_RES_NSEC);
		if (overflow) return ERR_OVERFLOW; /* overflow */
		break;

	default:
		return ERR_INVALID;	/* invalid operator */
	}

	return 0;
}

static int calc_time_delta(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	fr_value_box_t one, two;
	int64_t when;

	fr_assert(dst->type == FR_TYPE_TIME_DELTA);

	/*
	 *	We can subtract two dates to get a time delta, but we
	 *	cannot add two dates to get a time delta.
	 */
	if ((a->type == FR_TYPE_DATE) && (b->type == FR_TYPE_DATE)) {
		if (op != T_SUB) {
			fr_strerror_const("Cannot perform operation on two dates");
			return -1;
		}
	}

	/*
	 *	Unix times are always converted 1-1 to our internal
	 *	TIME_DELTA.
	 *
	 *	We cast the inputs based on the destination time resolution.  So "5ms + 5" = "10ms".
	 */
	if (a->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(NULL, &one, FR_TYPE_TIME_DELTA, dst->enumv, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(NULL, &two, FR_TYPE_TIME_DELTA, dst->enumv, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_ADD:
		if (!fr_add(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_OVERFLOW;
		dst->vb_time_delta = fr_time_delta_wrap(when);
		break;

	case T_SUB:
		if (!fr_sub(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_OVERFLOW;
		dst->vb_time_delta = fr_time_delta_wrap(when);
		break;

	default:
		return ERR_INVALID;	/* invalid operator */
	}

	return 0;

}

static int calc_octets(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	uint8_t *buf;
	size_t len;
	fr_value_box_t one, two;

	fr_assert(dst->type == FR_TYPE_OCTETS);

	if (a->type != FR_TYPE_OCTETS) {
		if (fr_value_box_cast(ctx, &one, FR_TYPE_OCTETS, dst->enumv, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_OCTETS) {
		if (fr_value_box_cast(ctx, &two, FR_TYPE_OCTETS, dst->enumv, b) < 0) return -1;
		b = &two;
	}

	len = a->length + b->length;

	switch (op) {
	case T_OP_PREPEND:	/* dst = b . a */
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}

		memcpy(buf, b->vb_octets, b->vb_length);
		memcpy(buf + b->vb_length, a->vb_octets, a->vb_length);

		fr_value_box_clear_value(dst);
		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
		break;

	case T_ADD:	/* dst = a . b */
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) goto oom;

		memcpy(buf, a->vb_octets, a->vb_length);
		memcpy(buf + a->vb_length, b->vb_octets, b->vb_length);

		fr_value_box_clear_value(dst);
		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
		break;

	case T_SUB:
		/*
		 *  The inverse of add!
		 */
		if (a->vb_length < b->vb_length) {
			fr_strerror_const("Suffix to remove is longer than input string");
			return -1;
		}

		if (memcmp(a->vb_octets + a->vb_length - b->vb_length, b->vb_strvalue, b->vb_length) != 0) {
			fr_strerror_const("Right side is not a suffix of the input string");
			return -1;
		}

		len = a->vb_length - b->vb_length;
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, len);

		fr_value_box_clear_value(dst);
		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
		break;

	case T_AND:
		if (a->vb_length != b->vb_length) {
		length_error:
			fr_strerror_const("Cannot perform operation on strings of different length");
			return -1;
		}

		buf = talloc_array(ctx, uint8_t, a->vb_length);
		if (!buf) goto oom;

		for (len = 0; len < a->vb_length; len++) {
			buf[len] = a->vb_octets[len] & b->vb_octets[len];
		}

		fr_value_box_clear_value(dst);
		fr_value_box_memdup_shallow(dst, dst->enumv, buf, a->vb_length, a->tainted | b->tainted);
		break;

	case T_OR:
		if (a->vb_length != b->vb_length) goto length_error;

		buf = talloc_array(ctx, uint8_t, a->vb_length);
		if (!buf) goto oom;

		for (len = 0; len < a->vb_length; len++) {
			buf[len] = a->vb_octets[len] | b->vb_octets[len];
		}

		fr_value_box_clear_value(dst);
		fr_value_box_memdup_shallow(dst, dst->enumv, buf, a->vb_length, a->tainted | b->tainted);
		break;

	default:
		return ERR_INVALID;	/* invalid operator */
	}

	if (a == &one) fr_value_box_clear_value(&one);
	if (b == &two) fr_value_box_clear_value(&two);

	return 0;
}

static int calc_string(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	char *buf;
	size_t len;
	fr_value_box_t one, two;

	fr_assert(dst->type == FR_TYPE_STRING);

	if (a->type != FR_TYPE_STRING) {
		if (fr_value_box_cast(ctx, &one, FR_TYPE_STRING, dst->enumv, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_STRING) {
		if (fr_value_box_cast(ctx, &two, FR_TYPE_STRING, dst->enumv, b) < 0) return -1;
		b = &two;
	}

	len = a->length + b->length;

	switch (op) {
	case T_OP_PREPEND:	/* dst = b . a */
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}

		memcpy(buf, b->vb_strvalue, b->vb_length);
		memcpy(buf + b->vb_length, a->vb_strvalue, a->vb_length);
		buf[a->vb_length + b->vb_length] = '\0';

		fr_value_box_clear_value(dst);
		fr_value_box_strdup_shallow(dst, dst->enumv, buf, a->tainted | b->tainted);
		break;

	case T_ADD:
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, a->vb_length);
		memcpy(buf + a->vb_length, b->vb_strvalue, b->vb_length);
		buf[a->vb_length + b->vb_length] = '\0';

		fr_value_box_clear_value(dst);
		fr_value_box_strdup_shallow(dst, dst->enumv, buf, a->tainted | b->tainted);
		break;

	case T_SUB:
		/*
		 *  The inverse of add!
		 */
		if (a->vb_length < b->vb_length) {
			fr_strerror_const("Suffix to remove is longer than input string");
			return -1;
		}

		if (memcmp(a->vb_strvalue + a->vb_length - b->vb_length, b->vb_strvalue, b->vb_length) != 0) {
			fr_strerror_const("Right side is not a suffix of the input string");
			return -1;
		}

		len = a->vb_length - b->vb_length;
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, len);
		buf[len] = '\0';

		fr_value_box_clear_value(dst);
		fr_value_box_strdup_shallow(dst, dst->enumv, buf, a->tainted | b->tainted);
		break;

	default:
		return ERR_INVALID;	/* invalid operator */
	}

	if (a == &one) fr_value_box_clear_value(&one);
	if (b == &two) fr_value_box_clear_value(&two);

	return 0;
}

static int cast_ipv4_addr(fr_value_box_t *out, fr_value_box_t const *in)
{
	switch (in->type) {
	default:
		fr_strerror_printf("Cannot operate on ipaddr and %s",
				   fr_table_str_by_value(fr_value_box_type_table, in->type, "<INVALID>"));
		return -1;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV4_ADDR:
		fr_value_box_copy(NULL, out, in);
		break;

	case FR_TYPE_IPV6_ADDR:
		if (fr_value_box_cast(NULL, out, FR_TYPE_IPV4_ADDR, NULL, in) < 0) return -1;
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (fr_value_box_cast(NULL, out, FR_TYPE_IPV4_PREFIX, NULL, in) < 0) return -1;
		break;

		/*
		 *	All of these get mashed to 32-bits.  The cast
		 *	operation will check bounds (both negative and
		 *	positive) on the run-time values.
		 */
	case FR_TYPE_BOOL:

	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:

	case FR_TYPE_SIZE:

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:

	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
		if (fr_value_box_cast(NULL, out, FR_TYPE_UINT32, NULL, in) < 0) return -1;
		break;
	}

	return 0;
}

static int calc_ipv4_addr(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	fr_value_box_t one, two;
	fr_value_box_t *a, *b;

	fr_assert(dst->type == FR_TYPE_IPV4_ADDR);

	if (cast_ipv4_addr(&one, in1) < 0) return -1;
	a = &one;

	if (cast_ipv4_addr(&two, in2) < 0) return -1;
	b = &two;

	switch (op) {
	case T_ADD:
		/*
		 *	For simplicity, make sure that the prefix is first.
		 */
		if (b->type == FR_TYPE_IPV4_PREFIX) swap(a,b);

		/*
		 *	We can only add something to a prefix, and
		 *	that something has to be a number. The cast
		 *	operation already ensured that the number is
		 *	uint32, and is at least vaguely within the
		 *	allowed range.
		 */
		if (a->type != FR_TYPE_IPV4_PREFIX) return ERR_INVALID;

		if (b->type != FR_TYPE_UINT32) return ERR_INVALID;

		/*
		 *	Trying to add a number outside of the given prefix.  That's not allowed.
		 */
		if (b->vb_uint32 >= (((uint32_t) 1) << a->vb_ip.prefix)) return ERR_OVERFLOW;

		dst->vb_ip.af = AF_INET;
		dst->vb_ip.addr.v4.s_addr = htonl(ntohl(a->vb_ip.addr.v4.s_addr) + b->vb_uint32);
		dst->vb_ip.prefix = 0;
		break;

	case T_SUB:
		/*
		 *	Subtract two addresses to see how far apart
		 *	they are.  If the caller does "0.0.0.0 -
		 *	255.xxxx", well, they deserve what they get.
		 */
		if ((a->type != FR_TYPE_IPV4_ADDR) && (b->type != FR_TYPE_IPV4_ADDR)) {
			fr_strerror_const("Cannot perform operation on two 'ipaddr' types");
			return -1;
		}

		dst->vb_ip.af = AF_INET;
		dst->vb_ip.addr.v4.s_addr = htonl(ntohl(a->vb_ip.addr.v4.s_addr) - ntohl(b->vb_ip.addr.v4.s_addr));
		dst->vb_ip.prefix = 0;
		break;

	default:
		return ERR_INVALID;
	}

	return 0;
}

static int cast_ipv6_addr(fr_value_box_t *out, fr_value_box_t const *in)
{
	switch (in->type) {
	default:
		fr_strerror_printf("Cannot operate on ipv6addr and %s",
				   fr_table_str_by_value(fr_value_box_type_table, in->type, "<INVALID>"));
		return -1;

	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_IPV6_ADDR:
		fr_value_box_copy(NULL, out, in);
		break;

	case FR_TYPE_IPV4_ADDR:
		if (fr_value_box_cast(NULL, out, FR_TYPE_IPV6_ADDR, NULL, in) < 0) return -1;
		break;

	case FR_TYPE_IPV4_PREFIX:
		if (fr_value_box_cast(NULL, out, FR_TYPE_IPV6_PREFIX, NULL, in) < 0) return -1;
		break;

		/*
		 *	All of these get mashed to 64-bits.  The cast
		 *	operation will check bounds (both negative and
		 *	positive) on the run-time values.
		 */
	case FR_TYPE_BOOL:

	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:

	case FR_TYPE_SIZE:

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:

	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
		if (fr_value_box_cast(NULL, out, FR_TYPE_UINT64, NULL, in) < 0) return -1;
		break;
	}

	return 0;
}

static int calc_ipv6_addr(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	fr_value_box_t one, two;
	fr_value_box_t *a, *b;
	int i;
	uint64_t mask;

	fr_assert(dst->type == FR_TYPE_IPV6_ADDR);

	if (cast_ipv6_addr(&one, in1) < 0) return -1;
	a = &one;

	if (cast_ipv6_addr(&two, in2) < 0) return -1;
	b = &two;

	switch (op) {
	case T_ADD:
		/*
		 *	For simplicity, make sure that the prefix is first.
		 */
		if (b->type == FR_TYPE_IPV6_PREFIX) swap(a,b);

		/*
		 *	We can only add something to a prefix, and
		 *	that something has to be a number. The cast
		 *	operation already ensured that the number is
		 *	uint32, and is at least vaguely within the
		 *	allowed range.
		 */
		if (a->type != FR_TYPE_IPV6_PREFIX) return ERR_INVALID;

		if (b->type != FR_TYPE_UINT64) return ERR_INVALID;

		/*
		 *	Trying to add a number outside of the given prefix.  That's not allowed.
		 */
		if (b->vb_uint64 >= (((uint64_t) 1) << a->vb_ip.prefix)) return ERR_OVERFLOW;

		/*
		 *	Add in the relevant low bits.
		 */
		mask = b->vb_uint64;
		for (i = 15; i >= ((a->vb_ip.prefix + 7) >> 3); i--) {
			dst->vb_ip.addr.v6.s6_addr[i] |= mask & 0xff;
			mask >>= 8;
		}

		dst->vb_ip.af = AF_INET6;
		dst->vb_ip.prefix = 0;
		dst->vb_ip.scope_id = a->vb_ip.scope_id;
		break;

	default:
		return ERR_INVALID;
	}

	return 0;
}

static int calc_float32(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	fr_value_box_t one, two;
	fr_value_box_t const *a = in1;
	fr_value_box_t const *b = in2;

	fr_assert(dst->type == FR_TYPE_FLOAT32);

	/*
	 *	Intermediate calculations are done using increased precision.
	 */
	if (a->type != FR_TYPE_FLOAT64) {
		if (fr_value_box_cast(NULL, &one, FR_TYPE_FLOAT64, NULL, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_FLOAT64) {
		if (fr_value_box_cast(NULL, &two, FR_TYPE_FLOAT64, NULL, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_ADD:
		dst->vb_float32 = a->vb_float64 + b->vb_float64;
		break;

	case T_SUB:
		dst->vb_float32 = a->vb_float64 - b->vb_float64;
		break;

	case T_MUL:
		dst->vb_float32 = a->vb_float64 * b->vb_float64;
		break;

	case T_DIV:
		if (fpclassify(b->vb_float64) == FP_ZERO) return ERR_OVERFLOW;

		dst->vb_float32 = a->vb_float64 / b->vb_float64;
		break;

	default:
		return ERR_INVALID;
	}

	return 0;

}

static int calc_float64(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	fr_value_box_t one, two;
	fr_value_box_t const *a = in1;
	fr_value_box_t const *b = in2;

	fr_assert(dst->type == FR_TYPE_FLOAT64);

	if (a->type != FR_TYPE_FLOAT64) {
		if (fr_value_box_cast(NULL, &one, FR_TYPE_FLOAT64, NULL, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_FLOAT64) {
		if (fr_value_box_cast(NULL, &two, FR_TYPE_FLOAT64, NULL, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_ADD:
		dst->vb_float64 = a->vb_float64 + b->vb_float64;
		break;

	case T_SUB:
		dst->vb_float64 = a->vb_float64 - b->vb_float64;
		break;

	case T_MUL:
		dst->vb_float64 = a->vb_float64 * b->vb_float64;
		break;

	case T_DIV:
		if (fpclassify(b->vb_float64) == FP_ZERO) return ERR_OVERFLOW;

		dst->vb_float64 = a->vb_float64 / b->vb_float64;
		break;

	default:
		return ERR_INVALID;
	}

	return 0;

}

#define CALC(_t) static int calc_ ## _t(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2) \
{ \
	switch (op) { \
	case T_ADD: \
		if (!fr_add(&dst->vb_ ## _t, in1->vb_ ## _t, in2->vb_ ## _t)) return ERR_OVERFLOW; \
		break; \
 \
	case T_SUB: \
		if (!fr_sub(&dst->vb_ ## _t, in1->vb_ ## _t, in2->vb_ ## _t)) return ERR_OVERFLOW; \
		break; \
 \
	case T_MUL: \
		if (!fr_multiply(&dst->vb_ ## _t, in1->vb_ ## _t, in2->vb_ ## _t)) return ERR_OVERFLOW; \
		break; \
 \
	case T_DIV: \
		dst->vb_ ## _t = in1->vb_ ## _t /  in2->vb_ ## _t; \
		break; \
 \
	case T_AND: \
		dst->vb_ ## _t = in1->vb_ ## _t &  in2->vb_ ## _t; \
		break; \
 \
	case T_OR: \
		dst->vb_ ## _t = in1->vb_ ## _t |  in2->vb_ ## _t; \
		break; \
 \
	default: \
		return ERR_INVALID; \
	} \
 \
	return 0; \
}

CALC(uint8)
CALC(uint16)
CALC(uint32)
CALC(uint64)

CALC(size)

CALC(int8)
CALC(int16)
CALC(int32)
CALC(int64)

typedef int (*fr_binary_op_t)(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b);

static const fr_binary_op_t calc_integer_type[FR_TYPE_MAX + 1] = {
	[FR_TYPE_UINT8] =  calc_uint8,
	[FR_TYPE_UINT16] = calc_uint16,
	[FR_TYPE_UINT32] = calc_uint32,
	[FR_TYPE_UINT64] = calc_uint64,

	[FR_TYPE_SIZE] = calc_size,

	[FR_TYPE_INT8] =  calc_int8,
	[FR_TYPE_INT16] = calc_int16,
	[FR_TYPE_INT32] = calc_int32,
	[FR_TYPE_INT64] = calc_int64,
};

static int calc_integer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	int rcode;
	fr_type_t type;
	fr_value_box_t const *a = in1;
	fr_value_box_t const *b = in2;
	fr_value_box_t one, two, out;
	fr_binary_op_t calc = NULL;

	/*
	 *	All of the types are the same.  Just do the work.
	 */
	if ((dst->type == in1->type) &&
	    (dst->type == in2->type)) {
		if (!calc_integer_type[dst->type]) goto not_yet;

		return calc_integer_type[dst->type](ctx, dst, in1, op, in2);
	}

	/*
	 *	Upcast to the largest type which will handle the
	 *	calculations.
	 *
	 *	Note that this still won't catch all of the overflow
	 *	cases, just the majority.
	 *
	 *	This will still fail if we do things like
	 *
	 *	    uint64 foo - int64 INT64_MIN -> uint64
	 *
	 *	the RHS should arguably be converted to uint64.
	 *	Perhaps we'll do that as a later step.
	 */
	type = dst->type;
	if (upcast[type][a->type] != FR_TYPE_NULL) {
		type = upcast[type][a->type];

	} else if (upcast[a->type][type] != FR_TYPE_NULL) {
		type = upcast[a->type][type];
	}

	if (upcast[type][b->type] != FR_TYPE_NULL) {
		type = upcast[type][b->type];

	} else if (upcast[b->type][type] != FR_TYPE_NULL) {
		type = upcast[b->type][type];
	}

	if (a->type != type) {
		if (fr_value_box_cast(NULL, &one, type, NULL, a) < 0) return -1;
		a = &one;
	}

	if (b->type != type) {
		if (fr_value_box_cast(NULL, &two, type, NULL, b) < 0) return -1;
		b = &two;
	}

	/*
	 *	Clang scan is too stupid to notice that
	 *	calc_integer_type[] is "const", so if we check
	 *	calc_integer_type[type] for being !NULL, and then call
	 *	a function from calc_integer_type[type], then the
	 *	array entry can't be NULL.
	 *
	 *	Apparently putting the function pointer into an
	 *	intermediate variable shuts it up.
	 */
	calc = calc_integer_type[type];
	if (!calc) {
	not_yet:
		fr_strerror_const("Not yet implemented");
		return -1;
	}

	fr_value_box_init(&out, type, dst->enumv, false);
	rcode = calc(NULL, &out, a, op, b);
	if (rcode < 0) return rcode;

	/*
	 *	Then once we're done, cast the result to the final
	 *	output type.
	 */
	return fr_value_box_cast(NULL, dst, dst->type, dst->enumv, &out);
}

static const fr_binary_op_t calc_type[FR_TYPE_MAX + 1] = {
	[FR_TYPE_BOOL]		= calc_bool,

	[FR_TYPE_OCTETS]	= calc_octets,
	[FR_TYPE_STRING]	= calc_string,

	[FR_TYPE_IPV4_ADDR]	= calc_ipv4_addr,
	[FR_TYPE_IPV6_ADDR]	= calc_ipv6_addr,

	[FR_TYPE_UINT8]		= calc_integer,
	[FR_TYPE_UINT16]       	= calc_integer,
	[FR_TYPE_UINT32]       	= calc_integer,
	[FR_TYPE_UINT64]       	= calc_integer,

	[FR_TYPE_SIZE]       	= calc_integer,

	[FR_TYPE_INT8]		= calc_integer,
	[FR_TYPE_INT16]       	= calc_integer,
	[FR_TYPE_INT32]       	= calc_integer,
	[FR_TYPE_INT64]       	= calc_integer,

	[FR_TYPE_DATE]		= calc_date,
	[FR_TYPE_TIME_DELTA]	= calc_time_delta,

	[FR_TYPE_FLOAT32]	= calc_float32,
	[FR_TYPE_FLOAT64]	= calc_float64,
};

/** Calculate DST = A OP B
 *
 *  The result is written to DST only *after* it has been calculated.
 *  So it's safe to pass DST as either A or B.
 *
 *  This function should arguably not take comparison operators, but
 *  whatever.  The "promote types" code is the same for all of the
 *  binary operations, so we might as well just have one function.
 */
int fr_value_calc_binary_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_type_t hint, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	int rcode = -1;
	fr_value_box_t one, two;

	fr_assert(fr_type_is_leaf(a->type));
	fr_assert(fr_type_is_leaf(b->type));
	fr_assert((hint == FR_TYPE_NULL) || fr_type_is_leaf(hint));

	fr_value_box_init_null(&one);
	fr_value_box_init_null(&two);

	/*
	 *	We don't know what the output type should be.  Try to
	 *	guess based on a variety of factors.
	 */
	if (hint == FR_TYPE_NULL) do {
		switch (op) {
		case T_OP_PREPEND:
			/*
			 *	Pick the existing type if we have a
			 *	variable-sized type.  Otherwise, pick
			 *	octets.
			 */
			if (fr_type_is_variable_size(a->type)) {
				hint = a->type;

			} else if (fr_type_is_variable_size(b->type)) {
				hint = b->type;

			} else {
				hint = FR_TYPE_OCTETS;
			}
			break;

		case T_OP_CMP_EQ:
		case T_OP_NE:
		case T_OP_GE:
		case T_OP_GT:
		case T_OP_LE:
		case T_OP_LT:
			/*
			 *	Comparison operators always return
			 *	"bool".
			 */
			hint = FR_TYPE_BOOL;
			break;

		case T_ADD:
		case T_SUB:
			if (a->type == b->type) {
				hint = a->type;
				break;
			}

			/*
			 *	Non-comparison operators: Strings of different types always
			 *	results in octets.
			 */
			if (fr_type_is_variable_size(a->type) && fr_type_is_variable_size(b->type)) {
				hint = FR_TYPE_OCTETS;
				break;
			}

			/*
			 *	Nothing else set it.  If the input types are
			 *	the same, then that must be the output type.
			 */
			if (a->type == b->type) {
				hint = a->type;
				break;
			}

			/*
			 *	Try to "up-cast" the types.  This is
			 *	so that we can take (for example)
			 *	uint8 + uint16, and have the output as
			 *	uint16.
			 *
			 *	There must be only one entry per [a,b]
			 *	pairing.  That way we're sure that [a,b]==[b,a]
			 */
			hint = upcast[a->type][b->type];
			if (hint == FR_TYPE_NULL) {
				hint = upcast[b->type][a->type];
			} else {
				fr_assert(upcast[b->type][a->type] == FR_TYPE_NULL);
			}

			if (hint != FR_TYPE_NULL) {
				break;
			}

			/*
			 *	No idea what to do. :(
			 */
			fr_strerror_const("Unable to automatically determine output data type");
			goto done;

		default:
			return ERR_INVALID;
		}
	} while (0);

	/*
	 *	If we're doing operations between
	 *	STRING/OCTETS and another type, then cast the
	 *	variable sized type to the fixed size type.
	 *	Doing this casting here makes the rest of the
	 *	code simpler.
	 *
	 *	This isn't always the best thing to do, but it makes
	 *	sense in most situations.  It allows comparisons,
	 *	etc. to operate between strings and integers.
	 */
	if (!fr_type_is_variable_size(hint)) {
		if (fr_type_is_variable_size(a->type) && !fr_type_is_variable_size(b->type)) {
			if (fr_value_box_cast(NULL, &one, b->type, b->enumv, a) < 0) goto done;
			a = &one;

		} else if (!fr_type_is_variable_size(a->type) && fr_type_is_variable_size(b->type)) {
			if (fr_value_box_cast(NULL, &two, a->type, a->enumv, b) < 0) goto done;
			b = &two;
		}
	}

	switch (op) {
	case T_OP_CMP_EQ:
	case T_OP_NE:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
		if (hint != FR_TYPE_BOOL) {
			fr_strerror_printf("Invalid destination type '%s' for comparison operator",
					   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
			goto done;
		}

		fr_value_box_clear_value(dst);
		fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false);	// just force it...

		rcode = fr_value_box_cmp_op(op, a, b);
		if (rcode < 0) {
			goto done;
		}

		dst->vb_bool = (rcode > 0);
		rcode = 0;
		break;

	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_AND:
	case T_OR:
	case T_OP_PREPEND:
		fr_assert(hint != FR_TYPE_NULL);

		/*
		 *	It's OK to use one of the inputs as the
		 *	output.  But if we don't, ensure that the
		 *	output value box is initialized.
		 */
		if ((dst != a) && (dst != b)) {
			fr_value_box_init(dst, hint, NULL, false);
		}

		if (!calc_type[dst->type]) {
			fr_strerror_printf("Cannot perform any operations for destination type %s",
					   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
			rcode = -1;
			break;
		}

		rcode = calc_type[dst->type](ctx, dst, a, op, b);
		break;

	default:
		rcode = ERR_INVALID;
		break;
	}

	if (rcode == ERR_OVERFLOW) {
		fr_strerror_printf("Value overflows/underflows when calculating answer for %s",
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));

	} else if (rcode == ERR_INVALID) {
		fr_strerror_printf("Invalid operator %s for destination type %s",
				   fr_tokens[op],
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
	}

done:
	if (rcode == 0) dst->tainted = a->tainted | b->tainted;

	fr_value_box_clear_value(&one);
	fr_value_box_clear_value(&two);

	return rcode;
}

/** Calculate DST OP SRC
 *
 *  e.g. "foo += bar".
 *
 *  This is done by doing some sanity checks, and then just calling
 *  the "binary operation" function.
 */
int fr_value_calc_assignment_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_token_t op, fr_value_box_t const *src)
{
	int rcode = -1;

	if (!fr_type_is_leaf(dst->type)) {
		fr_strerror_printf("Cannot perform any operations for destination type %s",
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
		return -1;
	}

	if (!fr_assignment_op[op]) goto invalid;

	switch (op) {
		/*
		 *	These operators are included here for testing
		 *	and completeness.  But see comments in
		 *	fr_edit_list_apply_pair_assignment() for what
		 *	the caller should be doing.
		 */
	case T_OP_EQ:
	case T_OP_SET:
		fr_value_box_clear_value(dst);
		fr_value_box_cast(ctx, dst, dst->type, dst->enumv, src); /* cast, as the RHS might not (yet) be the same! */
		rcode = 0;
		break;

		/*
		 *	Just call the binary op function.  It already
		 *	ensures that (a) the inputs are "const", and
		 *	(b) the output is over-written only as the
		 *	final step
		 */
	case T_OP_ADD_EQ:
		rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, T_ADD, src);
		break;

	case T_OP_SUB_EQ:
		rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, T_SUB, src);
		break;

	case T_OP_PREPEND:
		rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, op, src);
		break;

	case T_OP_AND_EQ:
		rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, T_OR, src);
		break;

	case T_OP_OR_EQ:
		rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, T_AND, src);
		break;

	default:
	invalid:
		rcode = ERR_INVALID;
		break;
	}

	if (rcode == ERR_OVERFLOW) {
		fr_strerror_printf("Value overflows/underflows when calculating answer for %s",
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));

	} else if (rcode == ERR_INVALID) {
		fr_strerror_printf("Invalid assignment operator %s for destination type %s",
				   fr_tokens[op],
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
	}

	/*
	 *	Don't bother returning private magic numbers.
	 */
	if (rcode < 0) return -1;

	dst->tainted |= src->tainted;
	return 0;
}

/** Calculate DST OP
 *
 *  e.g. "foo ++".
 *
 *  This is done by doing some sanity checks, and then just calling
 *  the "binary operation" function.
 */
int fr_value_calc_unary_op(TALLOC_CTX *ctx, fr_value_box_t *box, fr_token_t op)
{
	int rcode = -1;
	fr_value_box_t one;
	fr_token_t new_op;

	if (!fr_type_is_leaf(box->type)) {
		fr_strerror_printf("Cannot perform any operations for destination type %s",
				   fr_table_str_by_value(fr_value_box_type_table, box->type, "<INVALID>"));
		return -1;
	}

	if (op != T_OP_INCRM) goto invalid;

	switch (op) {
	case T_OP_INCRM:
		new_op = T_ADD;
		break;

	default:
		rcode = ERR_INVALID;
		goto invalid;
	}

	/*
	 *	Add 1 or subtract 1 means RHS is always 1.
	 */
	fr_value_box_init(&one, box->type, NULL, false);
	switch (box->type) {
	case FR_TYPE_UINT8:
		one.vb_uint8 = 1;
		break;

	case FR_TYPE_UINT16:
		one.vb_uint16 = 1;
		break;

	case FR_TYPE_UINT32:
		one.vb_uint32 = 1;
		break;

	case FR_TYPE_UINT64:
		one.vb_uint64 = 1;
		break;

	case FR_TYPE_SIZE:
		one.vb_size = 1;
		break;

	case FR_TYPE_INT8:
		one.vb_int8 = 1;
		break;

	case FR_TYPE_INT16:
		one.vb_int16 = 1;
		break;

	case FR_TYPE_INT32:
		one.vb_int32 = 1;
		break;

	case FR_TYPE_INT64:
		one.vb_int64 = 1;
		break;

	case FR_TYPE_FLOAT32:
		one.vb_float32 = 1;
		break;

	case FR_TYPE_FLOAT64:
		one.vb_float64 = 1;
		break;

	default:
		goto invalid;
	}

	rcode = fr_value_calc_binary_op(ctx, box, box->type, box, new_op, &one);

	if (rcode == ERR_OVERFLOW) {
		fr_strerror_printf("Value overflows/underflows when calculating answer for %s",
				   fr_table_str_by_value(fr_value_box_type_table, box->type, "<INVALID>"));

	} else if (rcode == ERR_INVALID) {
	invalid:
		fr_strerror_printf("Invalid assignment operator %s for destination type %s",
				   fr_tokens[op],
				   fr_table_str_by_value(fr_value_box_type_table, box->type, "<INVALID>"));
	}

	return rcode;
}

/** Apply a set of operations in order to create an output box.
 *
 */
int fr_value_calc_list_op(TALLOC_CTX *ctx, fr_value_box_t *box, fr_token_t op, fr_value_box_list_t const *list)
{
	/*
	 *	For octets and string and prepend / append, figure out
	 *	first how long the output is, create a string that
	 *	long, and then loop assigning the values.  Doing it
	 *	this way avoids a lot of intermediate garbage.
	 */
	if (fr_type_is_variable_size(box->type)) {
		bool tainted = false;
		int rcode;
		size_t len = 0;
		uint8_t *str, *p;
		fr_value_box_t src;

		fr_dlist_foreach(list,fr_value_box_t const, a) {
			if (a->type != box->type) {
				len = 0;
				break;
			}

			len += a->vb_length;
		}

		if (!len) goto brute_force;

		if (box->type == FR_TYPE_STRING) {
			str = talloc_array(ctx, uint8_t, len);
			if (!str) return -1;
		} else {
			str = talloc_array(ctx, uint8_t, len + 1);
			if (!str) return -1;

			str[len] = '\0';
		}

		p = str;
		fr_dlist_foreach(list,fr_value_box_t const, a) {
			memcpy(p, a->vb_octets, a->vb_length);
			p += a->vb_length;
			tainted |= a->tainted;
		}

		if (box->type == FR_TYPE_STRING) {
			fr_value_box_bstrndup_shallow(&src, NULL, (char const *) str, len, tainted);
		} else {
			fr_value_box_memdup_shallow(&src, NULL, str, len, tainted);
		}

		rcode = fr_value_calc_binary_op(ctx, box, box->type, box, op, &src);
		talloc_free(str);
		return rcode;
	}

brute_force:
	fr_dlist_foreach(list,fr_value_box_t const, a) {
		if (fr_value_calc_binary_op(ctx, box, box->type, box, op, a) < 0) return -1;
	}

	return 0;
}
