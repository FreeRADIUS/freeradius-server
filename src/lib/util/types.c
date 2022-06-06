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

/** Map data types to names representing those types
 */
fr_table_num_ordered_t const fr_type_table[] = {
	{ L("null"),		FR_TYPE_NULL		},
	{ L("string"),		FR_TYPE_STRING		},
	{ L("octets"),		FR_TYPE_OCTETS		},

	{ L("ipaddr"),		FR_TYPE_IPV4_ADDR	},
	{ L("ipv4addr"),	FR_TYPE_IPV4_ADDR	},
	{ L("ipv4prefix"),	FR_TYPE_IPV4_PREFIX	},
	{ L("ipv6addr"),	FR_TYPE_IPV6_ADDR	},
	{ L("ipv6prefix"),	FR_TYPE_IPV6_PREFIX	},
	{ L("ifid"),		FR_TYPE_IFID		},
	{ L("combo-ip"),	FR_TYPE_COMBO_IP_ADDR	},
	{ L("combo-prefix"),	FR_TYPE_COMBO_IP_PREFIX	},
	{ L("ether"),		FR_TYPE_ETHERNET	},

	{ L("bool"),		FR_TYPE_BOOL		},

	{ L("uint8"),        	FR_TYPE_UINT8		},
	{ L("uint16"),        	FR_TYPE_UINT16		},
	{ L("uint32"),		FR_TYPE_UINT32		},
	{ L("uint64"),		FR_TYPE_UINT64		},

	{ L("int8"),		FR_TYPE_INT8 		},
	{ L("int16"),		FR_TYPE_INT16		},
	{ L("int32"),         	FR_TYPE_INT32		},
	{ L("int64"),		FR_TYPE_INT64		},

	{ L("float32"),		FR_TYPE_FLOAT32		},
	{ L("float64"),		FR_TYPE_FLOAT64		},

	{ L("date"),		FR_TYPE_DATE		},
	{ L("time_delta"),	FR_TYPE_TIME_DELTA	},

	{ L("size"),		FR_TYPE_SIZE		},

	{ L("tlv"),		FR_TYPE_TLV		},
	{ L("struct"),        	FR_TYPE_STRUCT		},

	{ L("vsa"),          	FR_TYPE_VSA		},
	{ L("vendor"),        	FR_TYPE_VENDOR		},
	{ L("group"),        	FR_TYPE_GROUP		},

	/*
	 *	Alternative names
	 */
	{ L("cidr"),         	FR_TYPE_IPV4_PREFIX	},
	{ L("byte"),		FR_TYPE_UINT8		},
	{ L("short"),		FR_TYPE_UINT16		},
	{ L("integer"),		FR_TYPE_UINT32		},
	{ L("integer64"),	FR_TYPE_UINT64		},
	{ L("decimal"),		FR_TYPE_FLOAT64		},
	{ L("signed"),        	FR_TYPE_INT32		}
};
size_t fr_type_table_len = NUM_ELEMENTS(fr_type_table);

/** Table of all the direct mappings between types and C types
 *
 * Useful for setting talloc types correctly.
 */
static char const *fr_type_to_c_type[] = {
	[FR_TYPE_STRING]			= "char *",
	[FR_TYPE_OCTETS]			= "uint8_t *",

	[FR_TYPE_IPV4_ADDR]			= "fr_ipaddr_t",
	[FR_TYPE_IPV4_PREFIX]			= "fr_ipaddr_t",
	[FR_TYPE_IPV6_ADDR]			= "fr_ipaddr_t",
	[FR_TYPE_IPV6_PREFIX]			= "fr_ipaddr_t",
	[FR_TYPE_COMBO_IP_ADDR]			= "fr_ipaddr_t",
	[FR_TYPE_COMBO_IP_PREFIX]	       	= "fr_ipaddr_t",
	[FR_TYPE_IFID]				= "fr_ifid_t",
	[FR_TYPE_ETHERNET]			= "fr_ethernet_t",

	[FR_TYPE_BOOL]				= "bool",
	[FR_TYPE_UINT8]				= "uint8_t",
	[FR_TYPE_UINT16]			= "uint16_t",
	[FR_TYPE_UINT32]			= "uint32_t",
	[FR_TYPE_UINT64]			= "uint64_t",

	[FR_TYPE_INT8]				= "int8_t",
	[FR_TYPE_INT16]				= "int16_t",
	[FR_TYPE_INT32]				= "int32_t",
	[FR_TYPE_INT64]				= "int64_t",

	[FR_TYPE_FLOAT32]			= "float",
	[FR_TYPE_FLOAT64]			= "double",

	[FR_TYPE_DATE]				= "fr_unix_time_t",

	[FR_TYPE_TIME_DELTA]			= "fr_time_delta_t",
	[FR_TYPE_SIZE]				= "size_t",
	[FR_TYPE_VALUE_BOX]			= "fr_value_box_t",
	[FR_TYPE_VOID]				= "void *",

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

/** Table of all the direct mappings between types and C type sizes
 *
 */
static size_t const fr_type_to_c_size[] = {
	[FR_TYPE_STRING]			= sizeof(char *),
	[FR_TYPE_OCTETS]			= sizeof(uint8_t *),

	[FR_TYPE_IPV4_ADDR]			= sizeof(fr_ipaddr_t),
	[FR_TYPE_IPV4_PREFIX]			= sizeof(fr_ipaddr_t),
	[FR_TYPE_IPV6_ADDR]			= sizeof(fr_ipaddr_t),
	[FR_TYPE_IPV6_PREFIX]			= sizeof(fr_ipaddr_t),
	[FR_TYPE_COMBO_IP_ADDR]			= sizeof(fr_ipaddr_t),
	[FR_TYPE_COMBO_IP_PREFIX]	       	= sizeof(fr_ipaddr_t),
	[FR_TYPE_IFID]				= sizeof(fr_ifid_t),
	[FR_TYPE_ETHERNET]			= sizeof(fr_ethernet_t),

	[FR_TYPE_BOOL]				= sizeof(bool),
	[FR_TYPE_UINT8]				= sizeof(uint8_t),
	[FR_TYPE_UINT16]			= sizeof(uint16_t),
	[FR_TYPE_UINT32]			= sizeof(uint32_t),
	[FR_TYPE_UINT64]			= sizeof(uint64_t),

	[FR_TYPE_INT8]				= sizeof(int8_t),
	[FR_TYPE_INT16]				= sizeof(int16_t),
	[FR_TYPE_INT32]				= sizeof(int32_t),
	[FR_TYPE_INT64]				= sizeof(int64_t),

	[FR_TYPE_FLOAT32]			= sizeof(float),
	[FR_TYPE_FLOAT64]			= sizeof(double),

	[FR_TYPE_DATE]				= sizeof(fr_unix_time_t),

	[FR_TYPE_TIME_DELTA]			= sizeof(fr_time_delta_t),
	[FR_TYPE_SIZE]				= sizeof(size_t),
	[FR_TYPE_VALUE_BOX]			= sizeof(fr_value_box_t),
	[FR_TYPE_VOID]				= sizeof(void *),

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

#define ARRAY_BEG(_type)	{ [_type] = true,
#define ARRAY_MID(_type)	[_type] = true,
#define ARRAY_END(_type)	[_type] = true }

bool const fr_type_integer_except_bool[FR_TYPE_MAX + 1] = FR_TYPE_INTEGER_EXCEPT_BOOL_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_integer[FR_TYPE_MAX + 1] = FR_TYPE_INTEGER_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_numeric[FR_TYPE_MAX + 1] = FR_TYPE_NUMERIC_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_signed[FR_TYPE_MAX + 1] = FR_TYPE_SIGNED_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);

bool const fr_type_ip[FR_TYPE_MAX + 1] = FR_TYPE_IP_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);

bool const fr_type_fixed_size[FR_TYPE_MAX + 1] = FR_TYPE_FIXED_SIZE_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_variable_size[FR_TYPE_MAX + 1] = FR_TYPE_VARIABLE_SIZE_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_quoted[FR_TYPE_MAX + 1] = FR_TYPE_QUOTED_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);

bool const fr_type_structural_except_vsa[FR_TYPE_MAX + 1] = FR_TYPE_STRUCTURAL_EXCEPT_VSA_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_structural[FR_TYPE_MAX + 1] = FR_TYPE_STRUCTURAL_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_leaf[FR_TYPE_MAX + 1] = FR_TYPE_LEAF_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);
bool const fr_type_non_leaf[FR_TYPE_MAX + 1] = FR_TYPE_NON_LEAF_DEF(ARRAY_BEG, ARRAY_MID, ARRAY_END);

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
	case FR_TYPE_NON_LEAF:
		return false;

	default:
		break;
	}

	switch (src) {
	case FR_TYPE_NON_LEAF:
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
	if (!fr_type_is_leaf(a) || !fr_type_is_leaf(b)) return FR_TYPE_NULL;

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
				   fr_type_to_str(a),
				   fr_type_to_str(b));

		return FR_TYPE_NULL;
	}

	if (unlikely(type_promote_table[a][b] == FR_TYPE_NULL)) {
		fr_strerror_printf("No type promotions for a = %s, b = %s",
				   fr_type_to_str(a),
				   fr_type_to_str(b));
		return FR_TYPE_NULL;
	}

	/*
	 *	That takes care of the simple cases.  :( Now to the
	 *	complex ones.  Instead of masses of if / then / else,
	 *	we just use a lookup table.
	 */
	return type_promote_table[a][b];
}

/** Allocate an array of a given type
 *
 * @param[in] ctx	to allocate array in.
 * @param[in] type	array to allocate.
 * @param[in] count	The number of elements to allocate.
 * @return
 *	- NULL on error.
 *	- A new talloc array.
 */
void **fr_type_array_alloc(TALLOC_CTX *ctx, fr_type_t type, size_t count)
{
	char const *c_type;

	c_type = fr_type_to_c_type[type];
	if (c_type == NULL) {
		fr_strerror_printf("Type %s does not have a C type equivalent", fr_type_to_str(type));
		return NULL;
	}

	return _talloc_zero_array(ctx, fr_type_to_c_size[type], count, c_type);
 }
