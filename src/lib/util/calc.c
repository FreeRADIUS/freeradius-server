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

#define ERR_ZERO (-5)
#define ERR_UNDERFLOW (-4)
#define ERR_OVERFLOW (-3)
#define ERR_INVALID  (-2)

#define COERCE(_vb, _box, _type, _enumv) do { \
		if (_vb->type != _type) { \
			if (fr_value_box_cast(NULL, &_box, _type, _enumv, _vb) < 0) return -1; \
			_vb = &_box; \
		} \
	} while (0)

#define COERCE_A(_type, _enumv) COERCE(a, one, _type, _enumv)
#define COERCE_B(_type, _enumv) COERCE(b, two, _type, _enumv)

/** Updates type (a,b) -> c
 *
 *  Note that we MUST have a less than b here.  Otherwise there will
 *  be two entries for the same upcast, and the entries may get out of
 *  sync.
 *
 *  These upcasts are for operations.
 *
 *
 *  If one side is a string and the other isn't, then we try to parse
 *  the string as the type of the other side.
 *
 *  If one side is an octets type and the other isn't, then we try to
 *  parse the octets as the type of the other side.
 */
static const fr_type_t upcast_op[FR_TYPE_MAX + 1][FR_TYPE_MAX + 1] = {
	/*
	 *	string / octets -> octets
	 */
	[FR_TYPE_STRING] = {
		[FR_TYPE_OCTETS] = FR_TYPE_OCTETS,
	},

	[FR_TYPE_IPV4_ADDR] = {
		/*
		 *	ipaddr + int --> prefix (generally only "and")
		 */
		[FR_TYPE_UINT32] =  FR_TYPE_IPV4_PREFIX,

		/*
		 *	192.168.0.255 - 192.168.0.1 -> int64
		 */
		[FR_TYPE_IPV4_ADDR] =  FR_TYPE_INT64,
	},

	/*
	 *	Prefix + int --> ipaddr
	 */
	[FR_TYPE_IPV4_PREFIX] = {
		[FR_TYPE_BOOL] =   FR_TYPE_IPV4_ADDR,

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
		[FR_TYPE_BOOL] =   FR_TYPE_IPV6_ADDR,

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
	 *	Bools and to pretty much any numerical type result in
	 *	the other integer.
	 */
	[FR_TYPE_BOOL] = {
		[FR_TYPE_STRING] = FR_TYPE_BOOL,
		[FR_TYPE_OCTETS] = FR_TYPE_BOOL,

		[FR_TYPE_UINT8] = FR_TYPE_UINT8,
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

	/*
	 *	Various ints get cast to the next highest size which
	 *	can hold their values.
	 */
	[FR_TYPE_UINT8] = {
		[FR_TYPE_STRING] = FR_TYPE_UINT8,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT8,

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
		[FR_TYPE_STRING] = FR_TYPE_UINT16,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT16,

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
		[FR_TYPE_STRING] = FR_TYPE_UINT32,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT32,

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
		[FR_TYPE_STRING] = FR_TYPE_UINT64,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE]  = FR_TYPE_SIZE,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_SIZE] = {
		[FR_TYPE_STRING] = FR_TYPE_SIZE,

		[FR_TYPE_INT8]    = FR_TYPE_INT64,
		[FR_TYPE_INT16]   = FR_TYPE_INT64,
		[FR_TYPE_INT32]   = FR_TYPE_INT64,
		[FR_TYPE_INT64]   = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_DATE] = {
		[FR_TYPE_STRING] = FR_TYPE_DATE,

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
		[FR_TYPE_STRING] = FR_TYPE_INT8,
		[FR_TYPE_OCTETS] = FR_TYPE_INT8,

		[FR_TYPE_INT16] = FR_TYPE_INT32,
		[FR_TYPE_INT32] = FR_TYPE_INT32,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT16] = {
		[FR_TYPE_STRING] = FR_TYPE_INT16,
		[FR_TYPE_OCTETS] = FR_TYPE_INT16,

		[FR_TYPE_INT32] = FR_TYPE_INT64,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT32] = {
		[FR_TYPE_STRING] = FR_TYPE_INT32,
		[FR_TYPE_OCTETS] = FR_TYPE_INT32,

		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT64] = {
		[FR_TYPE_STRING] = FR_TYPE_INT64,
		[FR_TYPE_OCTETS] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_TIME_DELTA] = {
		[FR_TYPE_STRING] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT64] = FR_TYPE_TIME_DELTA,
	},

	[FR_TYPE_FLOAT32] = {
		[FR_TYPE_STRING] = FR_TYPE_FLOAT32,

		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_FLOAT64] = {
		[FR_TYPE_STRING] = FR_TYPE_FLOAT64,
	},
};


/** Updates type (a,b) -> c
 *
 *  Note that we MUST have a less than b here.  Otherwise there will
 *  be two entries for the same upcast, and the entries may get out of
 *  sync.
 *
 *  These upcasts are for comparisons.  In some cases, we can promote
 *  one data type to another, and then compare them.  However, this is
 *  not always possible.
 *
 *  If one side is a string and the other isn't, then we try to parse
 *  the string as the type of the other side.
 *
 *  If one side is an octets type and the other isn't, then we try to
 *  parse the octets as the type of the other side.
 *
 *  @todo - check this table against fr_type_promote()
 */
static const fr_type_t upcast_cmp[FR_TYPE_MAX + 1][FR_TYPE_MAX + 1] = {
	[FR_TYPE_IPV4_ADDR] = {
		[FR_TYPE_STRING] = FR_TYPE_IPV4_ADDR,
		[FR_TYPE_OCTETS] = FR_TYPE_IPV4_ADDR,

		[FR_TYPE_UINT32] =  FR_TYPE_IPV4_ADDR,
	},

	[FR_TYPE_IPV4_PREFIX] = {
		[FR_TYPE_STRING] = FR_TYPE_IPV4_PREFIX,
		[FR_TYPE_OCTETS] = FR_TYPE_IPV4_PREFIX,

		[FR_TYPE_IPV6_PREFIX] = FR_TYPE_IPV6_PREFIX,
	},

	[FR_TYPE_IPV6_ADDR] = {
		[FR_TYPE_STRING] = FR_TYPE_IPV6_ADDR,
		[FR_TYPE_OCTETS] = FR_TYPE_IPV6_ADDR,
	},

	[FR_TYPE_IPV6_PREFIX] = {
		[FR_TYPE_STRING] = FR_TYPE_IPV6_PREFIX,
		[FR_TYPE_OCTETS] = FR_TYPE_IPV6_PREFIX,
	},

	[FR_TYPE_IFID] = {
		[FR_TYPE_STRING] = FR_TYPE_IFID,
		[FR_TYPE_OCTETS] = FR_TYPE_IFID,
	},

	[FR_TYPE_ETHERNET] = {
		[FR_TYPE_STRING] = FR_TYPE_ETHERNET,
		[FR_TYPE_OCTETS] = FR_TYPE_ETHERNET,
	},

	/*
	 *	Bools compared to pretty much any numerical type
	 *	result in the other integer.
	 */
	[FR_TYPE_BOOL] = {
		[FR_TYPE_STRING] = FR_TYPE_BOOL,
		[FR_TYPE_OCTETS] = FR_TYPE_BOOL,

		[FR_TYPE_UINT8] = FR_TYPE_UINT8,
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

	/*
	 *	Integers of the same sign get cast to the larger of
	 *	the data type.  Integers of different signs get cast
	 *	to a *different* data type which can hold all values
	 *	from both sides.
	 */
	[FR_TYPE_UINT8] = {
		[FR_TYPE_STRING] = FR_TYPE_UINT8,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT8,

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
		[FR_TYPE_STRING] = FR_TYPE_UINT16,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT16,

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
		[FR_TYPE_STRING] = FR_TYPE_UINT32,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT32,

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
		[FR_TYPE_STRING] = FR_TYPE_UINT64,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE]  = FR_TYPE_SIZE,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_SIZE] = {
		[FR_TYPE_STRING] = FR_TYPE_SIZE,

		[FR_TYPE_INT8]    = FR_TYPE_INT64,
		[FR_TYPE_INT16]   = FR_TYPE_INT64,
		[FR_TYPE_INT32]   = FR_TYPE_INT64,
		[FR_TYPE_INT64]   = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_DATE] = {
		[FR_TYPE_STRING] = FR_TYPE_DATE,

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
		[FR_TYPE_STRING] = FR_TYPE_INT8,
		[FR_TYPE_OCTETS] = FR_TYPE_INT8,

		[FR_TYPE_INT16] = FR_TYPE_INT32,
		[FR_TYPE_INT32] = FR_TYPE_INT32,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT16] = {
		[FR_TYPE_STRING] = FR_TYPE_INT16,
		[FR_TYPE_OCTETS] = FR_TYPE_INT16,

		[FR_TYPE_INT32] = FR_TYPE_INT64,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT32] = {
		[FR_TYPE_STRING] = FR_TYPE_INT32,
		[FR_TYPE_OCTETS] = FR_TYPE_INT32,

		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT64] = {
		[FR_TYPE_STRING] = FR_TYPE_INT64,
		[FR_TYPE_OCTETS] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,
	},

	[FR_TYPE_TIME_DELTA] = {
		[FR_TYPE_STRING] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT64] = FR_TYPE_TIME_DELTA,
	},

	[FR_TYPE_FLOAT32] = {
		[FR_TYPE_STRING] = FR_TYPE_FLOAT32,

		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_FLOAT64] = {
		[FR_TYPE_STRING] = FR_TYPE_FLOAT64,
	},
};

static int invalid_type(fr_type_t type)
{
	fr_strerror_printf("Cannot perform mathematical operations on data type %s",
			   fr_type_to_str(type));
	return -1;
}

static int handle_result(fr_type_t type, fr_token_t op, int rcode)
{
	if (rcode == ERR_ZERO) {
		fr_strerror_const("Cannot divide by zero.");

	} else if (rcode == ERR_UNDERFLOW) {
		fr_strerror_printf("Value underflows '%s' when calculating result.",
				   fr_type_to_str(type));

	} else if (rcode == ERR_OVERFLOW) {
		fr_strerror_printf("Value overflows '%s' when calculating result.",
				   fr_type_to_str(type));

	} else if (rcode == ERR_INVALID) {
		fr_strerror_printf("Invalid assignment operator '%s' for result type '%s'.",
				   fr_tokens[op],
				   fr_type_to_str(type));
	}

	return rcode;
}

static int calc_bool(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	fr_value_box_t one, two;

	fr_assert(dst->type == FR_TYPE_BOOL);

	COERCE_A(FR_TYPE_BOOL, NULL);
	COERCE_B(FR_TYPE_BOOL, NULL);

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
		if (a->vb_bool < b->vb_bool) return ERR_UNDERFLOW;

		dst->vb_bool = a->vb_bool - b->vb_bool;
		break;

	case T_MUL:		/* MUL is just AND here! */
	case T_AND:
		dst->vb_bool = a->vb_bool & b->vb_bool;
		break;

	case T_OR:
		dst->vb_bool = a->vb_bool | b->vb_bool;
		break;

	case T_XOR:
		dst->vb_bool = a->vb_bool ^ b->vb_bool;
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
		fr_strerror_const("Cannot perform operation on two values of type 'date'.  One value must be a number.");
		return -1;
	}

	fr_assert(!dst->enumv);	/* unix time is always seconds */

	/*
	 *	Cast dates to time delta, do the conversions.
	 */
	COERCE_A(FR_TYPE_TIME_DELTA, NULL);
	COERCE_B(FR_TYPE_TIME_DELTA, NULL);

	switch (op) {
	case T_ADD:
		if (!fr_add(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_OVERFLOW;

		dst->vb_date = fr_unix_time_from_integer(&overflow, when, FR_TIME_RES_NSEC);
		if (overflow) return ERR_OVERFLOW;
		break;

	case T_SUB:
		if (!fr_sub(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_UNDERFLOW;

		dst->vb_date = fr_unix_time_from_integer(&overflow, when, FR_TIME_RES_NSEC);
		if (overflow) return ERR_UNDERFLOW;
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
			fr_strerror_const("Cannot perform operation on two values of type 'date'.");
			return -1;
		}
	}

	/*
	 *	Unix times are always converted 1-1 to our internal
	 *	TIME_DELTA.
	 *
	 *	We cast the inputs based on the destination time resolution.  So "5ms + 5" = "10ms".
	 */
	COERCE_A(FR_TYPE_TIME_DELTA, dst->enumv);

	if ((op == T_RSHIFT) || (op == T_LSHIFT)) {
		/*
		 *	Don't touch the RHS.
		 */
		fr_assert(b->type == FR_TYPE_UINT32);

	} else {
		COERCE_B(FR_TYPE_TIME_DELTA, dst->enumv);
	}

	switch (op) {
	case T_ADD:
		if (!fr_add(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_OVERFLOW;
		dst->vb_time_delta = fr_time_delta_wrap(when);
		break;

	case T_SUB:
		if (!fr_sub(&when, fr_time_delta_unwrap(a->vb_time_delta), fr_time_delta_unwrap(b->vb_time_delta))) return ERR_UNDERFLOW;
		dst->vb_time_delta = fr_time_delta_wrap(when);
		break;

	case T_RSHIFT:
		if (b->vb_uint32 >= 64) return ERR_UNDERFLOW;

		when = fr_time_delta_unwrap(a->vb_time_delta) >> b->vb_uint32;
		dst->vb_time_delta = fr_time_delta_wrap(when);
		break;

	case T_LSHIFT:
		if (b->vb_uint32 >= 64) return ERR_OVERFLOW;

		when = fr_time_delta_unwrap(a->vb_time_delta) << b->vb_uint8;
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

	COERCE_A(FR_TYPE_OCTETS, dst->enumv);

	if ((op == T_RSHIFT) || (op == T_LSHIFT)) {
		/*
		 *	Don't touch the RHS.
		 */
		fr_assert(b->type == FR_TYPE_UINT32);

	} else {
		COERCE_B(FR_TYPE_OCTETS, dst->enumv);
	}

	len = a->length + b->length;

	switch (op) {
	case T_ADD:	/* dst = a . b */
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}

		memcpy(buf, a->vb_octets, a->vb_length);
		memcpy(buf + a->vb_length, b->vb_octets, b->vb_length);

		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
		break;

	case T_SUB:
		/*
		 *  The inverse of add!
		 */
		if (a->vb_length < b->vb_length) {
			fr_strerror_const("Suffix to remove is longer than input string.");
			return -1;
		}

		if (memcmp(a->vb_octets + a->vb_length - b->vb_length, b->vb_strvalue, b->vb_length) != 0) {
			fr_strerror_const("Suffix to remove is not a suffix of the input string.");
			return -1;
		}

		len = a->vb_length - b->vb_length;
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, len);

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

		fr_value_box_memdup_shallow(dst, dst->enumv, buf, a->vb_length, a->tainted | b->tainted);
		break;

	case T_OR:
		if (a->vb_length != b->vb_length) goto length_error;

		buf = talloc_array(ctx, uint8_t, a->vb_length);
		if (!buf) goto oom;

		for (len = 0; len < a->vb_length; len++) {
			buf[len] = a->vb_octets[len] | b->vb_octets[len];
		}

		fr_value_box_memdup_shallow(dst, dst->enumv, buf, a->vb_length, a->tainted | b->tainted);
		break;

	case T_XOR:
		if (a->vb_length != b->vb_length) goto length_error;

		buf = talloc_array(ctx, uint8_t, a->vb_length);
		if (!buf) goto oom;

		for (len = 0; len < a->vb_length; len++) {
			buf[len] = a->vb_octets[len] ^ b->vb_octets[len];
		}

		fr_value_box_memdup_shallow(dst, dst->enumv, buf, a->vb_length, a->tainted | b->tainted);
		break;

	case T_RSHIFT:
		if (b->vb_uint32 > a->vb_length) return ERR_UNDERFLOW;

		len = a->vb_length - b->vb_uint32;
		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) goto oom;

		memcpy(buf, a->vb_octets, len);

		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted);
		break;

	case T_LSHIFT:
		if (b->vb_uint32 > a->vb_length) return ERR_OVERFLOW;

		len = a->vb_length - b->vb_uint32;

		buf = talloc_array(ctx, uint8_t, len);
		if (!buf) goto oom;

		memcpy(buf, a->vb_octets + b->vb_uint32, len);

		fr_value_box_memdup_shallow(dst, dst->enumv, buf, len, a->tainted);
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

	COERCE_A(FR_TYPE_STRING, dst->enumv);

	if ((op == T_RSHIFT) || (op == T_LSHIFT)) {
		/*
		 *	Don't touch the RHS.
		 */
		fr_assert(b->type == FR_TYPE_UINT32);

	} else {
		COERCE_B(FR_TYPE_STRING, dst->enumv);
	}

	len = a->length + b->length;

	switch (op) {
	case T_ADD:
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}

		len = a->vb_length + b->vb_length;
		memcpy(buf, a->vb_strvalue, a->vb_length);
		memcpy(buf + a->vb_length, b->vb_strvalue, b->vb_length);
		buf[len] = '\0';

		fr_value_box_bstrndup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
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
			fr_strerror_const("Suffix to remove is not a suffix of the input string");
			return -1;
		}

		len = a->vb_length - b->vb_length;
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, len);
		buf[len] = '\0';

		fr_value_box_bstrndup_shallow(dst, dst->enumv, buf, len, a->tainted | b->tainted);
		break;

	case T_RSHIFT:
		if (b->vb_uint32 > a->vb_length) return ERR_UNDERFLOW;

		len = a->vb_length - b->vb_uint32;
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue, len);
		buf[len] = '\0';

		fr_value_box_bstrndup_shallow(dst, dst->enumv, buf, len, a->tainted);
		break;

	case T_LSHIFT:
		if (b->vb_uint32 > a->vb_length) return ERR_OVERFLOW;

		len = a->vb_length - b->vb_uint32;

		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		memcpy(buf, a->vb_strvalue + b->vb_uint32, len);
		buf[len] = '\0';

		fr_value_box_bstrndup_shallow(dst, dst->enumv, buf, len, a->tainted);
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
				   fr_type_to_str(in->type));
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
	case T_OR:
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
		dst->vb_ip.addr.v4.s_addr = htonl(ntohl(a->vb_ip.addr.v4.s_addr) | b->vb_uint32);
		dst->vb_ip.prefix = 0;
		break;

	default:
		return ERR_INVALID;
	}

	return 0;
}

static int calc_ipv4_prefix(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	int prefix;
	fr_value_box_t one, two, tmp;

	fr_assert(dst->type == FR_TYPE_IPV4_PREFIX);

	switch (op) {
	case T_AND:
		if (fr_type_is_integer(a->type)) {
			if (fr_value_box_cast(NULL, &one, FR_TYPE_UINT32, NULL, a) < 0) return -1;

			a = &one;
			swap(a,b);

		} else if (fr_type_is_integer(b->type)) {
			if (fr_value_box_cast(NULL, &two, FR_TYPE_UINT32, NULL, b) < 0) return -1;
			b = &two;

		} else {
			fr_strerror_const("Invalid input types for ipv4prefix");
			return -1;
		}

		switch (a->type) {
		case FR_TYPE_IPV6_ADDR:
			if (fr_value_box_cast(NULL, &tmp, FR_TYPE_IPV4_ADDR, NULL, a) < 0) return -1;
			break;

		case FR_TYPE_IPV4_ADDR:
			break;

		default:
			fr_strerror_printf("Invalid input data type '%s' for logical 'and'",
					   fr_type_to_str(a->type));

			return -1;
		}

		if (b->vb_uint32 == 0) { /* set everything to zero */
			dst->vb_ip.addr.v4.s_addr = 0;
			prefix = 0;

		} else if ((~b->vb_uint32) == 0) { /* all 1's */
			dst->vb_ip.addr.v4.s_addr = a->vb_ip.addr.v4.s_addr;
			prefix = 32;

		} else {
			uint32_t mask;

			mask = ~b->vb_uint32;	/* 0xff00 -> 0x00ff */
			mask++;			/* 0x00ff -> 0x0100 */
			if ((mask & b->vb_uint32) != mask) {
				fr_strerror_printf("Invalid network mask '0x%08x'", b->vb_uint32);
				return -1;
			}

			mask = 0xfffffffe;
			prefix = 31;

			while (prefix > 0) {
				if (mask == b->vb_uint32) break;

				prefix--;
				mask <<= 1;
			}
			fr_assert(prefix > 0);

			dst->vb_ip.addr.v4.s_addr = htonl(ntohl(a->vb_ip.addr.v4.s_addr) & b->vb_uint32);
		}

		dst->vb_ip.af = AF_INET;
		dst->vb_ip.prefix = prefix;
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
				   fr_type_to_str(in->type));
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
	COERCE_A(FR_TYPE_FLOAT64, NULL);
	COERCE_B(FR_TYPE_FLOAT64, NULL);

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
		if (fpclassify(b->vb_float64) == FP_ZERO) return ERR_ZERO;

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

	COERCE_A(FR_TYPE_FLOAT64, NULL);
	COERCE_B(FR_TYPE_FLOAT64, NULL);

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
		if (fpclassify(b->vb_float64) == FP_ZERO) return ERR_ZERO;

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
		if (!fr_sub(&dst->vb_ ## _t, in1->vb_ ## _t, in2->vb_ ## _t)) return ERR_UNDERFLOW; \
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
	case T_XOR: \
		dst->vb_ ## _t = in1->vb_ ## _t ^  in2->vb_ ## _t; \
		break; \
 \
	case T_RSHIFT: \
		if (in2->vb_uint32 > (8 * sizeof(in1->vb_ ## _t))) return ERR_UNDERFLOW; \
 \
		dst->vb_ ## _t = in1->vb_ ## _t >>  in2->vb_uint8; \
		break; \
 \
	case T_LSHIFT: \
		if (in2->vb_uint32 >= (8 * sizeof(in1->vb_ ## _t))) return ERR_OVERFLOW; \
 \
		dst->vb_ ## _t = in1->vb_ ## _t <<  in2->vb_uint8; \
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
		if (!calc_integer_type[dst->type]) return invalid_type(dst->type);

		return calc_integer_type[dst->type](ctx, dst, in1, op, in2);
	}

	/*
	 *	We don't do upcasts on shifting.
	 *
	 *	@todo - on left shift, if the RHS shift value is
	 *	larger than the LHS data type, then promote the result
	 *	data type to the next thing which will fit.
	 */
	if ((op == T_RSHIFT) || (op == T_LSHIFT)) {
		type = a->type;
		fr_assert(b->type == FR_TYPE_UINT32);
		goto calc_it;
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
	if (upcast_op[type][a->type] != FR_TYPE_NULL) {
		type = upcast_op[type][a->type];

	} else if (upcast_op[a->type][type] != FR_TYPE_NULL) {
		type = upcast_op[a->type][type];
	}

	if (upcast_op[type][b->type] != FR_TYPE_NULL) {
		type = upcast_op[type][b->type];

	} else if (upcast_op[b->type][type] != FR_TYPE_NULL) {
		type = upcast_op[b->type][type];
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
calc_it:
	calc = calc_integer_type[type];
	if (!calc) return invalid_type(type);

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
	[FR_TYPE_IPV4_PREFIX]	= calc_ipv4_prefix,
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
 *  So it's safe to pass DST as either A or B.  DST should already exist.
 *
 *  This function should arguably not take comparison operators, but
 *  whatever.  The "promote types" code is the same for all of the
 *  binary operations, so we might as well just have one function.
 */
int fr_value_calc_binary_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_type_t hint, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	int rcode = -1;
	fr_value_box_t one, two;
	fr_value_box_t out;
	fr_binary_op_t func;

	if ((hint != FR_TYPE_NULL) && !fr_type_is_leaf(hint)) return invalid_type(hint);

	if (!fr_type_is_leaf(a->type)) return invalid_type(a->type);
	if (!fr_type_is_leaf(b->type)) return invalid_type(b->type);

	fr_value_box_init_null(&one);
	fr_value_box_init_null(&two);

	/*
	 *	We don't know what the output type should be.  Try to
	 *	guess based on a variety of factors.
	 */
	if (hint == FR_TYPE_NULL) do {
		switch (op) {
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
		case T_MUL:
		case T_DIV:
		case T_AND:
		case T_OR:
		case T_XOR:
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
			hint = upcast_op[a->type][b->type];
			if (hint == FR_TYPE_NULL) {
				hint = upcast_op[b->type][a->type];
			} else {
				fr_assert(upcast_op[b->type][a->type] == FR_TYPE_NULL);
			}

			/*
			 *	No idea what to do. :(
			 */
			if (hint == FR_TYPE_NULL) {
				fr_strerror_const("Unable to automatically determine output data type");
				goto done;
			}

			break;

			/*
			 *	The RHS MUST be a numerical type.  We don't need to do any upcasting here.
			 *
			 *	@todo - the output type could be larger than the input type, if the shift is
			 *	more than the input type can handle.  e.g. uint8 << 4 could result in uint16
			 */
		case T_RSHIFT:
		case T_LSHIFT:
			hint = a->type;
			break;

		default:
			return ERR_INVALID;
		}
	} while (0);

	/*
	 *	Now that we've figured out the correct types, perform the operation.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
	case T_OP_NE:
	case T_OP_GE:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_LT:
		if (hint != FR_TYPE_BOOL) {
			fr_strerror_printf("Invalid destination type '%s' for comparison operator",
					   fr_type_to_str(hint));
			goto done;
		}

		/*
		 *	Try to "up-cast" the types.  This is
		 *	so that we can take (for example)
		 *	uint8 < uint16, and have it make
		 *	sense.  uint16.
		 *
		 *	There must be only one entry per [a,b]
		 *	pairing.  That way we're sure that [a,b]==[b,a]
		 */
		if (a->type != b->type) {
			hint = upcast_cmp[a->type][b->type];
			if (hint == FR_TYPE_NULL) {
				hint = upcast_cmp[b->type][a->type];
			} else {
				fr_assert(upcast_cmp[b->type][a->type] == FR_TYPE_NULL);
			}

			if (hint == FR_TYPE_NULL) {
				fr_strerror_printf("Cannot compare incompatible types (%s)... %s (%s)...",
						   fr_type_to_str(a->type),
						   fr_tokens[op],
						   fr_type_to_str(b->type));
				goto done;
			}

			/*
			 *	Cast them to the appropriate type, which may be different from either of the
			 *	inputs.
			 */
			if (a->type != hint) {
				if (fr_value_box_cast(NULL, &one, hint, NULL, a) < 0) goto done;
				a = &one;
			}

			if (b->type != hint) {
				if (fr_value_box_cast(NULL, &two, hint, NULL, b) < 0) goto done;
				b = &two;
			}
		}

		rcode = fr_value_box_cmp_op(op, a, b);
		if (rcode < 0) goto done;

		fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false);
		dst->vb_bool = (rcode > 0);
		break;

		/*
		 *	For shifts, the RHS value MUST be an integer.  There's no reason to have it as
		 *	anything other than an 8-bit field.
		 */
	case T_LSHIFT:
	case T_RSHIFT:
		if (b->type != FR_TYPE_UINT32) {
			if (fr_value_box_cast(ctx, &two, FR_TYPE_UINT32, NULL, b) < 0) {
				fr_strerror_printf("Cannot parse shift value as integer - %s",
						   fr_strerror());
				goto done;
			}
			b = &two;
		}
		FALL_THROUGH;

	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_AND:
	case T_OR:
	case T_XOR:
		fr_assert(hint != FR_TYPE_NULL);

		func = calc_type[hint];
		if (!func) {
			fr_strerror_printf("Cannot perform any operations for destination type %s",
					   fr_type_to_str(hint));
			rcode = -1;
			break;
		}

		/*
		 *	It's OK to use one of the inputs as the
		 *	output.  In order to ensure that nothing bad
		 *	happens, we use an intermediate value-box.
		 */
		fr_value_box_init(&out, hint, NULL, false);

		rcode = func(ctx, &out, a, op, b); /* not calc_type[hint], to shut up clang */
		if (rcode < 0) goto done;

		fr_value_box_copy_shallow(NULL, dst, &out);
		dst->tainted = a->tainted | b->tainted;
		break;

	default:
		rcode = ERR_INVALID;
		break;
	}

done:
	fr_value_box_clear_value(&one);
	fr_value_box_clear_value(&two);

	return handle_result(hint, op, rcode);
}

#define T(_x) [T_OP_ ## _x ## _EQ] = T_ ## _x

static const fr_token_t assignment2op[T_TOKEN_LAST] = {
	T(ADD),
	T(SUB),
	T(MUL),
	T(DIV),
	T(AND),
	T(OR),
	T(XOR),
	T(RSHIFT),
	T(LSHIFT),
};

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

	if (!fr_type_is_leaf(dst->type)) return invalid_type(dst->type);
	if (!fr_type_is_leaf(src->type)) return invalid_type(src->type);

	/*
	 *	These operators are included here for testing and completeness.  But see comments in
	 *	fr_edit_list_apply_pair_assignment() for what the caller should be doing.
	 */
	if ((op == T_OP_EQ) || (op == T_OP_SET)) {
		/*
		 *	Allow for unintentional mistakes.
		 */
		if (src == dst) return 0;

		fr_value_box_clear_value(dst);
		return fr_value_box_cast(ctx, dst, dst->type, dst->enumv, src); /* cast, as the RHS might not (yet) be the same! */
	}

	op = assignment2op[op];
	if (op == T_INVALID) {
		return handle_result(dst->type, op, ERR_INVALID);
	}

	/*
	 *	Just call the binary op function.  It already ensures that (a) the inputs are "const", and (b)
	 *	the output is over-written only at the final step.
	 */
	rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, op, src);

	if (rcode < 0) handle_result(dst->type, op, rcode);

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

	if (!fr_type_is_leaf(box->type)) return invalid_type(box->type);

	if (op != T_OP_INCRM) goto invalid;

	switch (op) {
	case T_OP_INCRM:
		new_op = T_ADD;
		break;

	default:
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
	invalid:
		return handle_result(box->type, op, ERR_INVALID);
	}

	rcode = fr_value_calc_binary_op(ctx, box, box->type, box, new_op, &one);

	return handle_result(box->type, op, rcode);
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
