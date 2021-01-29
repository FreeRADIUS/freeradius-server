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

/** Boxed value structures and functions to manipulate them
 *
 * @file src/lib/util/types.c
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>

#define O(_x) [FR_TYPE_ ## _x] = true

/*
 *	Can we promote [src][dst] -> dst
 *		dst is not octets / string
 *		src and dst are both FR_TYPE_VALUE
 */
static const bool type_cast_table[FR_TYPE_MAX][FR_TYPE_MAX] = {
	[FR_TYPE_IPV4_ADDR] = {
		O(IPV4_PREFIX),
		O(IPV6_ADDR),
		O(IPV6_PREFIX),
		O(UINT32), /* ipv4 addresses are uint32 */
	},
	[FR_TYPE_IPV4_PREFIX] = {
		O(IPV4_ADDR),	/* if the prefix is /32 */
		O(IPV6_ADDR),
		O(IPV6_PREFIX),
	},
	[FR_TYPE_IPV6_ADDR] = {
		O(IPV6_PREFIX),
	},
	[FR_TYPE_IPV6_PREFIX] = {
		O(IPV6_ADDR),	/* if the prefix is /128 */
	},

	[FR_TYPE_ETHERNET] = {
		O(UINT64),
	},

	[FR_TYPE_UINT64] = {
		O(ETHERNET),
	},

	[FR_TYPE_DATE] = {	/* in 2021, dates always have values 2^31 or more */
		O(UINT32),
		O(UINT64),
		O(INT32),
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
	},

	[FR_TYPE_TIME_DELTA] = {
		O(DATE),
	},

	[FR_TYPE_UINT32] = {
		O(IPV4_ADDR),
	},

};

/*
 *	This is different from FR_TYPE_NUMERIC, largely in that it
 *	doesn't include FR_TYPE_DATE.  Because we know that dates
 *	always have values 2^31 or greater, so casts exclude some of
 *	the smaller integer types.
 */
static const bool type_is_number[FR_TYPE_MAX] = {
	O(BOOL),  O(SIZE),   O(FLOAT32), O(FLOAT64),
	O(UINT8), O(UINT16), O(UINT32), O(UINT64),
	O(INT8),  O(INT16),  O(INT32),  O(INT64),
	O(TIME_DELTA),
};

/** Return if we're allowed to cast the types.
 *
 * @param dst	the destination type we wish to cast to
 * @param src	the source type we wish to cast to
 *
 */
bool fr_type_cast(fr_type_t dst, fr_type_t src)
{
	/*
	 *	Invalid casts.
	 */
	switch (dst) {
	case FR_TYPE_NON_VALUES:
		return false;

	default:
		break;
	}

	switch (src) {
	case FR_TYPE_NON_VALUES:
		return false;

	default:
		break;
	}

	if (src == dst) return true;

	/*
	 *	Anything can be converted to octets or strings.
	 */
	if (dst == FR_TYPE_OCTETS) return true;
	if (dst == FR_TYPE_STRING) return true;

	/*
	 *	Strings and octets can be converted to anything.  We
	 *	do run-time checks on the values to see if they fit.
	 */
	if (src == FR_TYPE_OCTETS) return true;
	if (src == FR_TYPE_STRING) return true;

	/*
	 *	Any integer-style thing can be cast to any other
	 *	integer-style thing.  Mostly.  We do run-time checks
	 *	on values to see if they fit.
	 */
	if (type_is_number[src] && type_is_number[dst]) {
		return true;
	}

	/*
	 *	That takes care of the simple cases.  :( Now to the
	 *	complex ones.  Instead of masses of if / then / else,
	 *	we just use a lookup table.
	 */
	return type_cast_table[src][dst];
}

#undef O
#define O(_x) [FR_TYPE_ ## _x] = FR_TYPE_ ## _x

/** promote (a,b) -> a or b
 *		a/b are not octets / string
 *		a and b are both FR_TYPE_VALUE
 *
 *  Note that this table can return a type which is _not_ a or b.
 *
 *  Many lookups of table[a][b] will return b.  Some will return a.
 *  Others will return a type which is compatible with both a and b.
 */
static fr_type_t type_promote_table[FR_TYPE_MAX][FR_TYPE_MAX] = {
	[FR_TYPE_IPV4_ADDR] = {
		O(IPV4_PREFIX),
		O(IPV6_ADDR),
		O(IPV6_PREFIX),
		[FR_TYPE_UINT32] = FR_TYPE_IPV4_ADDR,
	},

	[FR_TYPE_IPV4_PREFIX] = {
		[FR_TYPE_IPV4_ADDR] = FR_TYPE_IPV4_PREFIX,
		O(IPV4_PREFIX),
		[FR_TYPE_IPV6_ADDR] = FR_TYPE_IPV6_PREFIX,
		O(IPV6_PREFIX),
	},

	[FR_TYPE_IPV6_ADDR] = {
		O(IPV6_PREFIX),
	},

	[FR_TYPE_IPV6_PREFIX] = {
		[FR_TYPE_IPV6_ADDR] = FR_TYPE_IPV6_PREFIX,
	},

	/* unsigned integers */

	[FR_TYPE_BOOL] = {
		O(UINT8),
		O(UINT16),
		O(UINT32),
		O(UINT64),
		O(INT8),
		O(INT16),
		O(INT32),
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
	},

	[FR_TYPE_UINT8] = {
		[FR_TYPE_BOOL] = FR_TYPE_UINT8,
		O(UINT16),
		O(UINT32),
		O(UINT64),
		[FR_TYPE_INT8] = FR_TYPE_UINT8,
		O(INT16),
		O(INT32),
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
	},

	[FR_TYPE_UINT16] = {
		[FR_TYPE_BOOL] = FR_TYPE_UINT16,
		[FR_TYPE_UINT8] = FR_TYPE_UINT16,
		O(UINT32),
		O(UINT64),
		[FR_TYPE_INT16] = FR_TYPE_UINT16,
		O(INT32),
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
	},

	[FR_TYPE_UINT32] = {
		[FR_TYPE_BOOL] = FR_TYPE_UINT32,
		O(IPV4_ADDR),
		[FR_TYPE_UINT8] = FR_TYPE_UINT32,
		[FR_TYPE_UINT16] = FR_TYPE_UINT32,
		O(UINT64),
		[FR_TYPE_INT32] = FR_TYPE_UINT32,
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
		O(DATE),
	},

	[FR_TYPE_UINT64] = {
		[FR_TYPE_BOOL] = FR_TYPE_UINT64,
		[FR_TYPE_UINT8] = FR_TYPE_UINT64,
		[FR_TYPE_UINT16] = FR_TYPE_UINT64,
		[FR_TYPE_UINT32] = FR_TYPE_UINT64,

		[FR_TYPE_INT8] = FR_TYPE_UINT64,
		[FR_TYPE_INT16] = FR_TYPE_UINT64,
		[FR_TYPE_INT32] = FR_TYPE_UINT64,
		[FR_TYPE_INT64] = FR_TYPE_UINT64,
		O(SIZE),
		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT64,
		O(FLOAT64),
		O(TIME_DELTA),
		O(DATE),
	},

	/* signed integers */
	[FR_TYPE_INT8] = {
		[FR_TYPE_BOOL] = FR_TYPE_INT8,
		O(UINT8),
		O(UINT16),
		O(UINT32),
		O(UINT64),
		O(INT16),
		O(INT32),
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
	},

	[FR_TYPE_INT16] = {
		[FR_TYPE_BOOL] = FR_TYPE_INT16,
		[FR_TYPE_UINT8] = FR_TYPE_INT16,
		O(UINT16),
		O(UINT32),
		O(UINT64),
		[FR_TYPE_INT8] = FR_TYPE_INT16,
		O(INT32),
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
	},

	[FR_TYPE_INT32] = {
		[FR_TYPE_BOOL] = FR_TYPE_INT32,
		[FR_TYPE_UINT8] = FR_TYPE_INT32,
		[FR_TYPE_UINT16] = FR_TYPE_INT32,
		O(UINT32),
		O(UINT64),
		[FR_TYPE_INT8] = FR_TYPE_INT32,
		[FR_TYPE_INT16] = FR_TYPE_INT32,
		O(INT64),
		O(SIZE),
		O(FLOAT32),
		O(FLOAT64),
		O(TIME_DELTA),
		O(DATE),
	},

	[FR_TYPE_INT64] = {
		[FR_TYPE_UINT8] = FR_TYPE_UINT64,
		[FR_TYPE_UINT16] = FR_TYPE_UINT64,
		[FR_TYPE_UINT32] = FR_TYPE_UINT64,
		O(UINT64),
		O(SIZE),
		[FR_TYPE_INT8] = FR_TYPE_UINT64,
		[FR_TYPE_INT16] = FR_TYPE_UINT64,
		[FR_TYPE_INT32] = FR_TYPE_UINT64,
		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT64,
		O(FLOAT64),
		O(TIME_DELTA),
		O(DATE),
	},

	[FR_TYPE_TIME_DELTA] = {
		[FR_TYPE_BOOL] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_UINT8] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_UINT16] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_UINT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_UINT64] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_SIZE] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_INT8] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_INT16] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_INT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_INT64] = FR_TYPE_TIME_DELTA,

		[FR_TYPE_FLOAT32] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_FLOAT64] = FR_TYPE_TIME_DELTA,
		[FR_TYPE_DATE] = FR_TYPE_TIME_DELTA,
	},

	[FR_TYPE_DATE] = {
		[FR_TYPE_UINT32] = FR_TYPE_DATE,
		[FR_TYPE_UINT64] = FR_TYPE_DATE,
		[FR_TYPE_SIZE] = FR_TYPE_DATE,

		[FR_TYPE_INT32] = FR_TYPE_DATE,
		[FR_TYPE_INT64] = FR_TYPE_DATE,

		[FR_TYPE_FLOAT32] = FR_TYPE_DATE,
		[FR_TYPE_FLOAT64] = FR_TYPE_DATE,
		O(TIME_DELTA),
	},

	[FR_TYPE_SIZE] = {
		[FR_TYPE_BOOL] = FR_TYPE_SIZE,
		[FR_TYPE_UINT8] = FR_TYPE_SIZE,
		[FR_TYPE_UINT16] = FR_TYPE_SIZE,
		[FR_TYPE_UINT32] = FR_TYPE_SIZE,
		[FR_TYPE_UINT64] = FR_TYPE_SIZE,
		[FR_TYPE_INT8] = FR_TYPE_SIZE,
		[FR_TYPE_INT16] = FR_TYPE_SIZE,
		[FR_TYPE_INT32] = FR_TYPE_SIZE,
		[FR_TYPE_INT64] = FR_TYPE_SIZE,
		[FR_TYPE_FLOAT32] = FR_TYPE_FLOAT64,
		O(FLOAT64),
		[FR_TYPE_TIME_DELTA] = FR_TYPE_SIZE,
		O(DATE),
	}
};

/** Return the promoted type
 *
 *  We presume that the two types are compatible, as checked by
 *  calling fr_type_cast().  The main difference here is that the two
 *  types don't have any src / dst relationship.  Instead, we just
 *  pick one which best suits any value-box comparisons
 *
 *  Note that this function can return a type which is _not_ a or b.
 *
 * @param a	type one
 * @param b	type two
 * @return	the promoted type
 */
fr_type_t fr_type_promote(fr_type_t a, fr_type_t b)
{
	/*
	 *	Invalid types
	 */
	switch (a) {
	case FR_TYPE_NON_VALUES:
		return FR_TYPE_INVALID;

	default:
		break;
	}

	switch (b) {
	case FR_TYPE_NON_VALUES:
		return FR_TYPE_INVALID;

	default:
		break;
	}

	if (a == b) return a;

	/*
	 *	string / octets and "type", the un-typed data gets cast to
	 *	"type".
	 *
	 *	We prefer to cast raw data to real types.  We also
	 *	prefer to _parse_ strings, and do the type checking on
	 *	the real types.  That way we have things like:  "000" == 0
	 */
	if (a == FR_TYPE_OCTETS) return b;
	if (b == FR_TYPE_OCTETS) return a;

	/*
	 *	Check for string after octets, because we want to cast
	 *	octets to string, and not vice versa.
	 */
	if (a == FR_TYPE_STRING) return b;
	if (b == FR_TYPE_STRING) return a;

	/*
	 *	Otherwise bad things happen. :(
	 */
	if (unlikely(type_promote_table[a][b] != type_promote_table[b][a])) {
		fr_strerror_printf("Inverse type mapping inconsistent for a = %s, b = %s",
				   fr_table_str_by_value(fr_value_box_type_table, a, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, b, "<INVALID>"));

		return FR_TYPE_INVALID;
	}

	if (unlikely(type_promote_table[a][b] == FR_TYPE_INVALID)) {
		fr_strerror_printf("No type promotions for a = %s, b = %s",
				   fr_table_str_by_value(fr_value_box_type_table, a, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, b, "<INVALID>"));
		return FR_TYPE_INVALID;
	}

	/*
	 *	That takes care of the simple cases.  :( Now to the
	 *	complex ones.  Instead of masses of if / then / else,
	 *	we just use a lookup table.
	 */
	return type_promote_table[a][b];
}
