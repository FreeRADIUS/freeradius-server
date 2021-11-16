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
#include "calc.h"

#define swap(_a, _b) do { __typeof__ (a) _tmp = _a; _a = _b; _b = _tmp; } while (0)

#define OVERFLOW (-3)
#define INVALID  (-2)

static int calc_date(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	fr_value_box_t one, two;
	bool overflow;

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
		if (fr_value_box_cast(ctx, &one, FR_TYPE_TIME_DELTA, NULL, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(ctx, &two, FR_TYPE_TIME_DELTA, NULL, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_OP_ADD:
		dst->vb_date = fr_unix_time_from_integer(&overflow,
							 fr_time_delta_unwrap(a->vb_time_delta) + fr_time_delta_unwrap(b->vb_time_delta),
							 FR_TIME_RES_NSEC);
		if (overflow) return OVERFLOW; /* overflow */
		break;

	case T_OP_SUB:
		dst->vb_date = fr_unix_time_from_integer(&overflow,
							 fr_time_delta_unwrap(a->vb_time_delta) - fr_time_delta_unwrap(b->vb_time_delta),
							 FR_TIME_RES_NSEC);
		if (overflow) return OVERFLOW; /* overflow */
		break;

	default:
		return INVALID;	/* invalid operator */
	}

	return 0;
}

static int calc_time_delta(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	fr_value_box_t one, two;

	fr_assert(dst->type == FR_TYPE_TIME_DELTA);

	/*
	 *	We can subtract two dates to get a time delta, but we
	 *	cannot add two dates to get a time delta.
	 */
	if ((a->type == FR_TYPE_DATE) && (b->type == FR_TYPE_DATE)) {
		if (op != T_OP_SUB) {
			fr_strerror_const("Cannot perform operation on two dates");
			return -1;
		}
	}

	/*
	 *	Unix times are always converted 1-1 to our internal
	 *	TIME_DELTA.
	 */
	if (a->type == FR_TYPE_DATE) {
		if (fr_value_box_cast(ctx, &one, FR_TYPE_TIME_DELTA, NULL, a) < 0) return -1;
		a = &one;
	}

	if (b->type == FR_TYPE_DATE) {
		if (fr_value_box_cast(ctx, &two, FR_TYPE_TIME_DELTA, NULL, b) < 0) return -1;
		b = &two;
	}

	/*
	 *	We cast the inputs based on the destination time resolution.  So "5ms + 5" = "10ms".
	 */
	if (a->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(ctx, &one, FR_TYPE_TIME_DELTA, dst->enumv, a) < 0) return -1;
		a = &one;
	}

	if (b->type != FR_TYPE_TIME_DELTA) {
		if (fr_value_box_cast(ctx, &two, FR_TYPE_TIME_DELTA, dst->enumv, b) < 0) return -1;
		b = &two;
	}

	switch (op) {
	case T_OP_ADD:
		dst->vb_time_delta = fr_time_delta_wrap(fr_time_delta_unwrap(a->vb_time_delta) + fr_time_delta_unwrap(b->vb_time_delta));
		break;

	case T_OP_SUB:
		dst->vb_time_delta = fr_time_delta_wrap(fr_time_delta_unwrap(a->vb_time_delta) - fr_time_delta_unwrap(b->vb_time_delta));
		break;

	default:
		return INVALID;	/* invalid operator */
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

	case T_OP_ADD:	/* dst = a . b */
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) goto oom;

		memcpy(buf, a->vb_octets, a->vb_length);
		memcpy(buf + a->vb_length, b->vb_octets, b->vb_length);

		fr_value_box_clear_value(dst);
		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
		break;

	default:
		return INVALID;	/* invalid operator */
	}

	if (a != &one) fr_value_box_clear(&one);
	if (b != &two) fr_value_box_clear(&two);

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

	if (b->type != FR_TYPE_OCTETS) {
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

	case T_OP_ADD:
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, a->vb_length);
		memcpy(buf + a->vb_length, b->vb_strvalue, b->vb_length);
		buf[a->vb_length + b->vb_length] = '\0';

		fr_value_box_clear_value(dst);
		fr_value_box_strdup_shallow(dst, dst->enumv, buf, a->tainted | b->tainted);
		break;

	default:
		return INVALID;	/* invalid operator */
	}

	if (a != &one) fr_value_box_clear(&one);
	if (b != &two) fr_value_box_clear(&two);

	return 0;
}

static int cast_ipv4_addr(fr_value_box_t *out, fr_value_box_t const *in, fr_dict_attr_t const *enumv)
{
	switch (in->type) {
	default:
		return -1;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(NULL, out, FR_TYPE_IPV4_ADDR, enumv,
					  in->vb_strvalue, in->vb_length,
					  NULL, in->tainted) < 0) return -1;
		break;

	case FR_TYPE_IPV6_ADDR:
		if (fr_value_box_cast(NULL, out, FR_TYPE_IPV4_ADDR, NULL, in) < 0) return -1;
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (fr_value_box_cast(NULL, out, FR_TYPE_IPV4_PREFIX, NULL, in) < 0) return -1;
		break;

	case FR_TYPE_BOOL:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_SIZE:
		fr_value_box_copy(NULL, out, in);
		break;
	}

	return 0;
}

static int calc_ipv4_addr(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	uint32_t num;
	fr_value_box_t one, two;
	fr_value_box_t *a, *b;

	fr_assert(dst->type == FR_TYPE_IPV4_ADDR);

	if (cast_ipv4_addr(&one, in1, dst->enumv) < 0) return -1;
	a = &one;

	if (cast_ipv4_addr(&two, in2, dst->enumv) < 0) return -1;
	b = &two;

	switch (op) {
	case T_OP_ADD:
		/*
		 *	For simplicity, make sure that the prefix is first.
		 */
		if (b->type == FR_TYPE_IPV4_PREFIX) swap(a,b);

		/*
		 *	We can only add something to a prefix, and
		 *	that something has to be a number.
		 */
		if (a->type != FR_TYPE_IPV4_PREFIX) return INVALID;

		switch (b->type) {
		case FR_TYPE_INT8:
		case FR_TYPE_INT16:
		case FR_TYPE_INT64:
		case FR_TYPE_FLOAT32:
		case FR_TYPE_FLOAT64:
			if (fr_value_box_cast_in_place(ctx, b, FR_TYPE_INT32, NULL) < 0) return -1;
			FALL_THROUGH;

		case FR_TYPE_INT32:
			if (b->vb_int32 < 0) return OVERFLOW;

			num = b->vb_int32;
			break;

		case FR_TYPE_BOOL:
		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT64:
		case FR_TYPE_SIZE:
			if (fr_value_box_cast_in_place(ctx, b, FR_TYPE_UINT32, NULL) < 0) return -1;
			FALL_THROUGH;

		case FR_TYPE_UINT32:
			num = b->vb_uint32;
			break;

		default:
			/*
			 *	Can't add an IP address to a prefix.
			 */
			return INVALID;
		}

		/*
		 *	Trying to add a number outside of the given prefix.  That's not allowed.
		 */
		if (num >= (((uint32_t) 1) << a->vb_ip.prefix)) return OVERFLOW;

		dst->vb_ip.addr.v4.s_addr = a->vb_ip.addr.v4.s_addr + num;
		dst->vb_ip.prefix = 0;
		break;

	default:
		return INVALID;
	}

	return 0;
}

typedef int (*fr_binary_op_t)(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b);

static const fr_binary_op_t calc_type[FR_TYPE_MAX] = {
	[FR_TYPE_OCTETS] = calc_octets,
	[FR_TYPE_STRING] = calc_string,

	[FR_TYPE_DATE] = calc_date,
	[FR_TYPE_TIME_DELTA] = calc_time_delta,

	[FR_TYPE_IPV4_ADDR] = calc_ipv4_addr,
};

int fr_value_calc(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_type_t hint, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	int rcode;

	if (fr_type_is_structural(dst->type)) {
		fr_strerror_const("Cannot calculate results for structural types");
		return -1;
	}

	switch (op) {
	case T_OP_CMP_EQ:
	case T_OP_NE:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
		if ((hint != FR_TYPE_NULL) && (hint != FR_TYPE_BOOL)) {
			fr_strerror_const("Invalid destination type for comparison operator");
			return -1;
		}

		fr_value_box_clear_value(dst);
		fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false);	// just force it...

		rcode = fr_value_box_cmp_op(op, a, b);
		if (rcode < 0) {
			fr_strerror_const("Failed doing comparison");
			return -1;
		}

		dst->vb_bool = (rcode > 0);
		return 0;

	case T_OP_ADD:
	case T_OP_SUB:
	case T_OP_PREPEND:
		if (hint == FR_TYPE_NULL) {
			if (a->type != b->type) {
				fr_strerror_const("not yet implemented");
				return -1;
			}

			fr_value_box_init(dst, hint, NULL, false);

		} else if ((dst != a) && (dst != b)) {
			/*
			 *	It's OK to use one of the inputs as
			 *	the output.  But if we don't, ensure
			 *	that the output value box is
			 *	initialized.
			 */
			fr_value_box_init(dst, hint, NULL, false);
		}

		if (!calc_type[dst->type]) {
			fr_strerror_printf("No handler has been implemented for leaf type %s",
					   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
			rcode = -1;
			break;
		}

		rcode = calc_type[dst->type](ctx, dst, a, op, b);
		break;

	default:
		rcode = INVALID;
		break;
	}

	if (rcode == OVERFLOW) {
		fr_strerror_printf("Value overflows/underflows when calculating answer for %s",
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));

	} else if (rcode == INVALID) {
		fr_strerror_printf("Invalid operator %s for destination type %s",
				   fr_tokens[op],
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
	}

	return rcode;
}
