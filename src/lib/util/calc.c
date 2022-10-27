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
		[FR_TYPE_STRING] = FR_TYPE_STRING,
		[FR_TYPE_OCTETS] = FR_TYPE_OCTETS,
	},

	[FR_TYPE_OCTETS] = {
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
	 *	IPv6 mod IPv6 -> ????
	 */
	[FR_TYPE_IPV6_ADDR] = {
		[FR_TYPE_IPV6_ADDR] = FR_TYPE_OCTETS,
	},

	/*
	 *	Prefix + int --> ipaddr
	 */
	[FR_TYPE_IPV4_PREFIX] = {
		[FR_TYPE_IPV4_PREFIX] = FR_TYPE_IPV4_PREFIX,

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
		[FR_TYPE_IPV6_PREFIX] = FR_TYPE_IPV6_PREFIX,

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
		[FR_TYPE_BOOL] = FR_TYPE_BOOL,

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

		[FR_TYPE_UINT8] = FR_TYPE_UINT64,
		[FR_TYPE_UINT16] = FR_TYPE_UINT64,
		[FR_TYPE_UINT32] = FR_TYPE_UINT64,
		[FR_TYPE_UINT64] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE] =   FR_TYPE_UINT64,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_INT8]   = FR_TYPE_INT64,
		[FR_TYPE_INT16]  = FR_TYPE_INT64,
		[FR_TYPE_INT32]  = FR_TYPE_INT64,
		[FR_TYPE_INT64]  = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_UINT16] = {
		[FR_TYPE_STRING] = FR_TYPE_UINT16,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT16,

		[FR_TYPE_UINT16] = FR_TYPE_UINT64,
		[FR_TYPE_UINT32] = FR_TYPE_UINT64,
		[FR_TYPE_UINT64] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE] =   FR_TYPE_UINT64,

		[FR_TYPE_DATE]  = FR_TYPE_DATE,

		[FR_TYPE_INT8]   = FR_TYPE_INT64,
		[FR_TYPE_INT16]  = FR_TYPE_INT64,
		[FR_TYPE_INT32]  = FR_TYPE_INT64,
		[FR_TYPE_INT64]  = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA]  = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_UINT32] = {
		[FR_TYPE_STRING] = FR_TYPE_UINT32,
		[FR_TYPE_OCTETS] = FR_TYPE_UINT32,

		[FR_TYPE_UINT32] = FR_TYPE_UINT64,
		[FR_TYPE_UINT64] = FR_TYPE_UINT64,

		[FR_TYPE_SIZE]   = FR_TYPE_UINT64,

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

		[FR_TYPE_UINT64]  = FR_TYPE_UINT64,
		[FR_TYPE_INT64]  = FR_TYPE_INT64,

		[FR_TYPE_SIZE]  = FR_TYPE_UINT64,

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

		[FR_TYPE_SIZE]   = FR_TYPE_INT64,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_DATE] = {
		[FR_TYPE_STRING] = FR_TYPE_DATE,

		[FR_TYPE_INT8]	= FR_TYPE_DATE,
		[FR_TYPE_INT16]	= FR_TYPE_DATE,
		[FR_TYPE_INT32] = FR_TYPE_DATE,
		[FR_TYPE_INT64] = FR_TYPE_DATE,

		[FR_TYPE_DATE] = FR_TYPE_DATE,
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

		[FR_TYPE_INT8] = FR_TYPE_INT64,
		[FR_TYPE_INT16] = FR_TYPE_INT64,
		[FR_TYPE_INT32] = FR_TYPE_INT64,
		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_INT16] = {
		[FR_TYPE_STRING] = FR_TYPE_INT16,
		[FR_TYPE_OCTETS] = FR_TYPE_INT16,

		[FR_TYPE_INT16] = FR_TYPE_INT64,
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

		[FR_TYPE_INT64] = FR_TYPE_INT64,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_TIME_DELTA] = {
		[FR_TYPE_STRING] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_TIME_DELTA] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT64] = FR_TYPE_TIME_DELTA,
	},

	[FR_TYPE_FLOAT32] = {
		[FR_TYPE_STRING] = FR_TYPE_FLOAT32,

		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT32,
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
	},

	[FR_TYPE_FLOAT64] = {
		[FR_TYPE_FLOAT64] = FR_TYPE_FLOAT64,
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

		[FR_TYPE_IPV4_PREFIX] = FR_TYPE_IPV4_PREFIX,

		[FR_TYPE_IPV6_ADDR] = FR_TYPE_IPV6_ADDR,
		[FR_TYPE_IPV6_PREFIX] = FR_TYPE_IPV6_PREFIX,

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

		[FR_TYPE_IPV6_PREFIX] = FR_TYPE_IPV6_PREFIX,
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

static const fr_type_t upcast_unsigned[FR_TYPE_MAX + 1] = {
	[FR_TYPE_BOOL] = FR_TYPE_INT8,
	[FR_TYPE_UINT8] = FR_TYPE_INT16,
	[FR_TYPE_UINT16] = FR_TYPE_INT32,
	[FR_TYPE_UINT32] = FR_TYPE_INT64,
	[FR_TYPE_UINT64] = FR_TYPE_INT64,
	[FR_TYPE_SIZE] = FR_TYPE_INT64,
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

		when = fr_time_delta_unwrap(a->vb_time_delta) << b->vb_uint32;
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

	/* coverity[uninit_use_in_call] */
	if (a == &one) fr_value_box_clear_value(&one);
	/* coverity[uninit_use_in_call] */
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

	case T_XOR:		/* is prepend for strings */
		buf = talloc_array(ctx, char, len + 1);
		if (!buf) goto oom;

		len = a->vb_length + b->vb_length;
		memcpy(buf, b->vb_strvalue, b->vb_length);
		memcpy(buf + b->vb_length, a->vb_strvalue, a->vb_length);
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

	/* coverity[uninit_use_in_call] */
	if (a == &one) fr_value_box_clear_value(&one);
	/* coverity[uninit_use_in_call] */
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
		 *	If we're adding a UINT64, the prefix can't be shorter than 64.
		 */
		if (a->vb_ip.prefix <= 64) return ERR_OVERFLOW;

		/*
		 *	Trying to add a number outside of the given prefix.  That's not allowed.
		 */
		if (b->vb_uint64 >= (((uint64_t) 1) << (128 - a->vb_ip.prefix))) return ERR_OVERFLOW;

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

static int get_ipv6_prefix(uint8_t const *in)
{
	int i, j, prefix;

	prefix = 128;
	for (i = 15; i >= 0; i--) {
		if (!in[i]) {
			prefix -= 8;
			continue;
		}

		for (j = 0; j < 8; j++) {
			if ((in[i] & (1 << j)) == 0) {
				prefix--;
				continue;
			}
			return prefix;
		}
	}

	return prefix;
}

static int calc_ipv6_prefix(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b)
{
	int i, prefix = 128;
	uint8_t const *pa, *pb;
	uint8_t *pdst;

	fr_assert(dst->type == FR_TYPE_IPV6_PREFIX);

	if (a->type == FR_TYPE_OCTETS) {
		if (a->vb_length != (128 / 8)) {
			fr_strerror_printf("Invalid length %zu for octets network mask", a->vb_length);
			return -1;
		}
		pa = a->vb_octets;
		prefix = get_ipv6_prefix(pa);

	} else if (a->type == FR_TYPE_IPV6_ADDR) {
		pa = (const uint8_t *) &a->vb_ip.addr.v6.s6_addr;

	} else {
		return ERR_INVALID;
	}

	if (b->type == FR_TYPE_OCTETS) {
		if (b->vb_length != (128 / 8)) {
			fr_strerror_printf("Invalid length %zu for octets network mask", b->vb_length);
			return -1;
		}
		pb = b->vb_octets;
		prefix = get_ipv6_prefix(pb);

	} else if (a->type == FR_TYPE_IPV6_ADDR) {
		pb = (const uint8_t *) &b->vb_ip.addr.v6;

	} else {
		return ERR_INVALID;
	}

	switch (op) {
	case T_AND:
		fr_value_box_init(dst, FR_TYPE_IPV6_PREFIX, NULL, a->tainted | b->tainted);
		pdst = (uint8_t *) &dst->vb_ip.addr.v6;

		for (i = 0; i < 16; i++) {
			pdst[i] = pa[i] & pb[i];
		}

		dst->vb_ip.af = AF_INET6;
		dst->vb_ip.prefix = prefix;
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

	case T_MOD:
		if (fpclassify(b->vb_float64) == FP_ZERO) return ERR_ZERO;

		dst->vb_float32 = fmod(a->vb_float64, b->vb_float64);
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

	case T_MOD:
		if (fpclassify(b->vb_float64) == FP_ZERO) return ERR_ZERO;

		dst->vb_float64 = fmod(a->vb_float64, b->vb_float64);
		break;

	default:
		return ERR_INVALID;
	}

	return 0;

}

/*
 *	Do all intermediate operations on 64-bit numbers.
 */
static int calc_uint64(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	fr_value_box_t one, two, result;
	fr_value_box_t const *a = in1;
	fr_value_box_t const *b = in2;

	fr_value_box_init(&result, FR_TYPE_UINT64, NULL, a->tainted | b->tainted);

	COERCE_A(FR_TYPE_UINT64, NULL);

	if ((op == T_RSHIFT) || (op == T_LSHIFT)) {
		/*
		 *	Don't touch the RHS.
		 */
		fr_assert(b->type == FR_TYPE_UINT32);

	} else {
		COERCE_B(FR_TYPE_UINT64, dst->enumv);
	}

	switch (op) {
	case T_ADD:
		if (!fr_add(&result.vb_uint64, a->vb_uint64, b->vb_uint64)) return ERR_OVERFLOW;
		break;

	case T_SUB:
		if (!fr_sub(&result.vb_uint64, a->vb_uint64, b->vb_uint64)) return ERR_UNDERFLOW;
		break;

	case T_MUL:
		if (!fr_multiply(&result.vb_uint64, a->vb_uint64, b->vb_uint64)) return ERR_OVERFLOW;
		break;

	case T_DIV:
		if (b->vb_uint64 == 0) return ERR_ZERO;

		result.vb_uint64 = a->vb_uint64 / b->vb_uint64;
		break;

	case T_MOD:
		if (b->vb_uint64 == 0) return ERR_ZERO;

		result.vb_uint64 = a->vb_uint64 % in2->vb_uint64;
		break;

	case T_AND:
		result.vb_uint64 = a->vb_uint64 & b->vb_uint64;
		break;

	case T_OR:
		result.vb_uint64 = a->vb_uint64 | b->vb_uint64;
		break;

	case T_XOR:
		result.vb_uint64 = a->vb_uint64 ^ b->vb_uint64;
		break;

	case T_RSHIFT:
		if (b->vb_uint32 >= (8 * sizeof(a->vb_uint64))) return ERR_UNDERFLOW;

		result.vb_uint64 = a->vb_uint64 >> b->vb_uint32;
		break;

	case T_LSHIFT:
		if (b->vb_uint32 >= (8 * sizeof(a->vb_uint64))) return ERR_OVERFLOW;

		result.vb_uint64 = a->vb_uint64 <<  b->vb_uint32;
		break;

	default:
		return ERR_INVALID;
	}

	/*
	 *	Once we're done, cast the result to the final data type.
	 */
	if (fr_value_box_cast(ctx, dst, dst->type, dst->enumv, &result) < 0) return -1;

	return 0;
}

/*
 *	Same as above, except uint64 -> int64.  These functions should be kept in sync!
 */
static int calc_int64(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *in1, fr_token_t op, fr_value_box_t const *in2)
{
	fr_value_box_t one, two, result;
	fr_value_box_t const *a = in1;
	fr_value_box_t const *b = in2;

	fr_value_box_init(&result, FR_TYPE_INT64, NULL, a->tainted | b->tainted);

	COERCE_A(FR_TYPE_INT64, NULL);

	if ((op == T_RSHIFT) || (op == T_LSHIFT)) {
		/*
		 *	Don't touch the RHS.
		 */
		fr_assert(b->type == FR_TYPE_UINT32);

	} else {
		COERCE_B(FR_TYPE_INT64, dst->enumv);
	}

	switch (op) {
	case T_ADD:
		if (!fr_add(&result.vb_int64, a->vb_int64, b->vb_int64)) return ERR_OVERFLOW;
		break;

	case T_SUB:
		if (!fr_sub(&result.vb_int64, a->vb_int64, b->vb_int64)) return ERR_UNDERFLOW;
		break;

	case T_MUL:
		if (!fr_multiply(&result.vb_int64, a->vb_int64, b->vb_int64)) return ERR_OVERFLOW;
		break;

	case T_DIV:
		if (b->vb_int64 == 0) return ERR_ZERO;

		result.vb_int64 = a->vb_int64 / b->vb_int64;
		break;

	case T_MOD:
		if (b->vb_int64 == 0) return ERR_ZERO;

		result.vb_int64 = a->vb_int64 % in2->vb_int64;
		break;

	case T_AND:
		result.vb_int64 = a->vb_int64 & b->vb_int64;
		break;

	case T_OR:
		result.vb_int64 = a->vb_int64 | b->vb_int64;
		break;

	case T_XOR:
		result.vb_int64 = a->vb_int64 ^ b->vb_int64;
		break;

	case T_RSHIFT:
		if (b->vb_uint32 >= (8 * sizeof(a->vb_int64))) return ERR_UNDERFLOW;

		result.vb_int64 = a->vb_int64 >> b->vb_uint32;
		break;

	case T_LSHIFT:
		if (b->vb_uint32 >= (8 * sizeof(a->vb_int64))) return ERR_OVERFLOW;

		result.vb_int64 = a->vb_int64 <<  b->vb_uint32;
		break;

	default:
		return ERR_INVALID;
	}

	/*
	 *	Once we're done, cast the result to the final data type.
	 */
	if (fr_value_box_cast(ctx, dst, dst->type, dst->enumv, &result) < 0) return -1;

	return 0;
}

typedef int (*fr_binary_op_t)(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b);

static const fr_binary_op_t calc_type[FR_TYPE_MAX + 1] = {
	[FR_TYPE_BOOL]		= calc_bool,

	[FR_TYPE_OCTETS]	= calc_octets,
	[FR_TYPE_STRING]	= calc_string,

	[FR_TYPE_IPV4_ADDR]	= calc_ipv4_addr,
	[FR_TYPE_IPV4_PREFIX]	= calc_ipv4_prefix,
	[FR_TYPE_IPV6_ADDR]	= calc_ipv6_addr,
	[FR_TYPE_IPV6_PREFIX]	= calc_ipv6_prefix,

	[FR_TYPE_UINT8]		= calc_uint64,
	[FR_TYPE_UINT16]       	= calc_uint64,
	[FR_TYPE_UINT32]       	= calc_uint64,
	[FR_TYPE_UINT64]       	= calc_uint64,

	[FR_TYPE_SIZE]       	= calc_uint64,

	[FR_TYPE_INT8]		= calc_int64,
	[FR_TYPE_INT16]       	= calc_int64,
	[FR_TYPE_INT32]       	= calc_int64,
	[FR_TYPE_INT64]       	= calc_int64,

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

	/*
	 *	Any operation on NULL types is itself a NULL type.
	 */
	if ((a->type == FR_TYPE_NULL) || (b->type == FR_TYPE_NULL)) {
		fr_value_box_init_null(dst);
		return 0;
	}

	/*
	 *	Casting to structural types should be a parse error,
	 *	and not a run-time calculation error.
	 */
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

		case T_AND:
			/*
			 *	Get mask from IP + number
			 */
			if ((a->type == FR_TYPE_IPV4_ADDR) || (b->type == FR_TYPE_IPV4_ADDR)) {
				hint = FR_TYPE_IPV4_PREFIX;
				break;
			}

			if ((a->type == FR_TYPE_IPV6_ADDR) || (b->type == FR_TYPE_IPV6_ADDR)) {
				hint = FR_TYPE_IPV6_PREFIX;
				break;
			}
			FALL_THROUGH;

		case T_OR:
		case T_ADD:
		case T_SUB:
		case T_MUL:
		case T_DIV:
		case T_MOD:
		case T_XOR:
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
			} else if (a->type != b->type) {
				fr_assert(upcast_op[b->type][a->type] == FR_TYPE_NULL);
			}

			/*
			 *	No idea what to do. :(
			 */
			if (hint == FR_TYPE_NULL) {
				fr_strerror_printf("Unable to automatically determine output data type for inputs %s and %s",
						   fr_type_to_str(a->type), fr_type_to_str(b->type));
				goto done;
			}

			break;

			/*
			 *	The RHS MUST be a numerical type.  We don't need to do any upcasting here.
			 *
			 *	@todo - the output type could be larger than the input type, if the shift is
			 *	more than the input type can handle.  e.g. uint8 << 4 could result in uint16
			 */
		case T_LSHIFT:
			if (!fr_type_is_integer(a->type)) {
				return handle_result(a->type, T_LSHIFT, ERR_INVALID);
			}

			if (fr_type_is_signed(a->type)) {
				hint = FR_TYPE_INT64;
				break;
			}
			hint = FR_TYPE_UINT64;
			break;

		case T_RSHIFT:
			hint = a->type;
			break;

		default:
			return handle_result(a->type, T_LSHIFT, ERR_INVALID);
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
		 *	sense.
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
	case T_MOD:
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
	int rcode;

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
	if (src->type != FR_TYPE_GROUP) {
		rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, op, src);

	} else {
		fr_value_box_t *vb = NULL;

		/*
		 *	If the RHS is a group, then we loop over the group recursively, doing the operation.
		 */
		rcode = 0;	/* in case group is empty */

		while ((vb = fr_dlist_next(&src->vb_group, vb)) != NULL) {
			rcode = fr_value_calc_binary_op(ctx, dst, dst->type, dst, op, vb);
			if (rcode < 0) break;
		}
	}

	if (rcode < 0) handle_result(dst->type, op, rcode);

	return 0;
}

/** Calculate unary operations
 *
 *  e.g. "foo++", or "-foo".
 */
int fr_value_calc_unary_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_token_t op, fr_value_box_t const *src)
{
	int rcode = -1;
	fr_value_box_t one;

	if (!fr_type_is_numeric(src->type)) return invalid_type(src->type);

	if (op == T_OP_INCRM) {
		/*
		 *	Add 1 or subtract 1 means RHS is always 1.
		 */
		fr_value_box_init(&one, src->type, NULL, false);
		switch (src->type) {
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
			fr_assert(0);
			return -1;
		}

		rcode = fr_value_calc_binary_op(ctx, dst, src->type, src, T_ADD, &one);
		return handle_result(dst->type, op, rcode);

	} else if (op == T_COMPLEMENT) {
		if (dst != src) fr_value_box_init(dst, src->type, src->enumv, src->tainted);

#undef COMP
#define COMP(_type, _field) case FR_TYPE_ ## _type: dst->vb_ ##_field = (_field ## _t) ~src->vb_ ##_field; break
		switch (src->type) {
			COMP(UINT8, uint8);
			COMP(UINT16, uint16);
			COMP(UINT32, uint32);
			COMP(UINT64, uint64);
			COMP(SIZE, size);

			COMP(INT8, int8);
			COMP(INT16, int16);
			COMP(INT32, int32);
			COMP(INT64, int64);

		default:
			goto invalid;
		}

		return 0;

	} else if (op == T_SUB) {
		fr_type_t type = src->type;

		if ((dst != src) && !fr_type_is_signed(src->type)) {
			type = upcast_unsigned[src->type];

			if (type == FR_TYPE_NULL) {
				type = src->type; /* hope for the best */
			}
		}

		fr_value_box_init(&one, type, NULL, src->tainted); /* init to zero */
		rcode = fr_value_calc_binary_op(ctx, dst, type, &one, T_SUB, src);

		return handle_result(dst->type, op, rcode);

	} else if (op == T_NOT) {
		bool value = fr_value_box_is_truthy(src);

		fr_value_box_clear(dst);
		fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false); // @todo - add enum!
		dst->vb_bool = !value;

		return 0;

	} else {
	invalid:
		return handle_result(src->type, op, ERR_INVALID);
	}

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


/*
 *	Loop over input lists, calling fr_value_calc_binary_op()
 *
 *	This implementation is arguably wrong... it should be checking individual entries in list1 against individual entries in list2.
 *	Instead, it checks if ANY entry in list1 matches ANY entry in list2.
 */
int fr_value_calc_list_cmp(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_list_t const *list1, fr_token_t op, fr_value_box_list_t const *list2)
{
	int rcode;
	bool invert = false;

	/*
	 *	v3 hack.  != really means !( ... == ... )
	 */
	if (op == T_OP_NE) {
		invert = true;
		op = T_OP_CMP_EQ;
	}

	/*
	 *	Emulate v3.  :(
	 */
	fr_dlist_foreach(list1, fr_value_box_t, a) {
		fr_dlist_foreach(list2, fr_value_box_t, b) {
			rcode = fr_value_calc_binary_op(ctx, dst, FR_TYPE_BOOL, a, op, b);
			if (rcode < 0) return rcode;

			/*
			 *	No match: keep looking for a match.
			 */
			fr_assert(dst->type == FR_TYPE_BOOL);
			if (!dst->vb_bool) continue;

			/*
			 *	Found a match, we're done.
			 */
			dst->vb_bool = !invert;
			return 0;
		}
	}

	/*
	 *	No match.
	 */
	fr_value_box_clear(dst);
	fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false); // @todo - add enum!
	dst->vb_bool = invert;
	return 0;
}
