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
 * @file src/lib/util/value.c
 *
 * There are three notional data formats used in the server:
 *
 * - #fr_value_box_t are the INTERNAL format.  This is usually close to the in-memory representation
 *   of the data, though uint32s and IPs are always converted to/from octets with BIG ENDIAN
 *   uint8 ordering for consistency.
 *   - #fr_value_box_cast is used to convert (cast) #fr_value_box_t between INTERNAL formats.
 *   - #fr_value_box_strdup* is used to ingest nul terminated strings into the INTERNAL format.
 *   - #fr_value_box_memcpy* is used to ingest binary data into the INTERNAL format.
 *
 * - NETWORK format is the format we send/receive on the wire.  It is not a perfect representation
 *   of data packing for all protocols, so you will likely need to overload conversion for some types.
 *   - fr_value_box_to_network is used to covert INTERNAL format data to generic NETWORK format data.
 *     For uint32s, IP addresses etc... This means BIG ENDIAN uint8 ordering.
 *   - fr_value_box_from_network is used to convert packet buffer fragments in NETWORK format to
 *     INTERNAL format.
 *
 * - PRESENTATION format is what we print to the screen, and what we get from the user, databases
 *   and configuration files.
 *   - #fr_value_box_asprint is used to convert from INTERNAL to PRESENTATION format.
 *   - #fr_value_box_from_str is used to convert from PRESENTATION to INTERNAL format.
 *
 * @copyright 2014-2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/ascend.h>
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/net.h>

#include <assert.h>
#include <ctype.h>

/** Sanity checks
 *
 * There should never be an instance where these fail.
 */
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_ip.addr.v4.s_addr) == 4,
	      "in_addr.s_addr has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_ip.addr.v6.s6_addr) == 16,
	      "in6_addr.s6_addr has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_ifid) == 8,
	      "vb_ifid has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_ether) == 6,
	      "vb_ether has unexpected length");

static_assert(SIZEOF_MEMBER(fr_value_box_t, datum.boolean) == 1,
	      "datum.boolean has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_uint8) == 1,
	      "vb_uint8 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_uint16) == 2,
	      "vb_uint16 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_uint32) == 4,
	      "vb_uint32 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_uint64) == 8,
	      "vb_uint64 has unexpected length");

static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_int8) == 1,
	      "vb_int16 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_int16) == 2,
	      "vb_int16 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_int32) == 4,
	      "vb_int32 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_int64) == 8,
	      "vb_int64 has unexpected length");

static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_float32) == 4,
	      "vb_float32 has unexpected length");
static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_float64) == 8,
	      "vb_float64 has unexpected length");


/** Map data types to names representing those types
 */
fr_table_num_ordered_t const fr_value_box_type_table[] = {
	{ "string",		FR_TYPE_STRING		},
	{ "octets",		FR_TYPE_OCTETS		},

	{ "ipaddr",		FR_TYPE_IPV4_ADDR	},
	{ "ipv4addr",		FR_TYPE_IPV4_ADDR	},
	{ "ipv4prefix",		FR_TYPE_IPV4_PREFIX	},
	{ "ipv6addr",		FR_TYPE_IPV6_ADDR	},
	{ "ipv6prefix",		FR_TYPE_IPV6_PREFIX	},
	{ "ifid",		FR_TYPE_IFID		},
	{ "combo-ip",		FR_TYPE_COMBO_IP_ADDR	},
	{ "combo-prefix",	FR_TYPE_COMBO_IP_PREFIX	},
	{ "ether",		FR_TYPE_ETHERNET	},

	{ "bool",		FR_TYPE_BOOL		},

	{ "uint8",        	FR_TYPE_UINT8		},
	{ "uint16",        	FR_TYPE_UINT16		},
	{ "uint32",		FR_TYPE_UINT32		},
	{ "uint64",		FR_TYPE_UINT64		},

	{ "int8",		FR_TYPE_INT8 		},
	{ "int16",		FR_TYPE_INT16		},
	{ "int32",         	FR_TYPE_INT32		},
	{ "int64",		FR_TYPE_INT64		},

	{ "float32",		FR_TYPE_FLOAT32		},
	{ "float64",		FR_TYPE_FLOAT64		},

	{ "time_delta",		FR_TYPE_TIME_DELTA	},
	{ "date",		FR_TYPE_DATE		},

	{ "abinary",		FR_TYPE_ABINARY		},

	{ "size",		FR_TYPE_SIZE		},

	{ "tlv",		FR_TYPE_TLV		},
	{ "struct",        	FR_TYPE_STRUCT		},

	{ "extended",      	FR_TYPE_EXTENDED	},

	{ "vsa",          	FR_TYPE_VSA		},
	{ "vendor",        	FR_TYPE_VENDOR		},
	{ "group",        	FR_TYPE_GROUP		},

	/*
	 *	Alternative names
	 */
	{ "cidr",         	FR_TYPE_IPV4_PREFIX	},
	{ "byte",		FR_TYPE_UINT8		},
	{ "short",		FR_TYPE_UINT16		},
	{ "integer",		FR_TYPE_UINT32		},
	{ "integer64",		FR_TYPE_UINT64		},
	{ "decimal",		FR_TYPE_FLOAT64		},
	{ "signed",        	FR_TYPE_INT32		}
};
size_t fr_value_box_type_table_len = NUM_ELEMENTS(fr_value_box_type_table);

/** How many bytes on-the-wire would a #fr_value_box_t value consume
 *
 * This is for the generic NETWORK format.  For field sizes in the in-memory
 * structure use #fr_value_box_field_sizes.
 *
 * @note Don't use this array directly when determining the length
 *	 that would be consumed by the on-the-wire representation.
 *	 Use #fr_value_box_network_length instead, as that deals with variable
 *	 length attributes too.
 */
static size_t const fr_value_box_network_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]			= {~0, 0},

	[FR_TYPE_STRING]			= {0, ~0},
	[FR_TYPE_OCTETS]			= {0, ~0},

	[FR_TYPE_IPV4_ADDR]			= {4, 4},
	[FR_TYPE_IPV4_PREFIX]			= {5, 5},
	[FR_TYPE_IPV6_ADDR]			= {16, 17},
	[FR_TYPE_IPV6_PREFIX]			= {17, 18},
	[FR_TYPE_IFID]				= {8, 8},
	[FR_TYPE_ETHERNET]			= {6, 6},

	[FR_TYPE_BOOL]				= {1, 1},
	[FR_TYPE_UINT8]				= {1, 1},
	[FR_TYPE_UINT16]			= {2, 2},
	[FR_TYPE_UINT32]			= {4, 4},
	[FR_TYPE_UINT64]			= {8, 8},

	[FR_TYPE_INT8]				= {1, 1},
	[FR_TYPE_INT16]				= {2, 2},
	[FR_TYPE_INT32]				= {4, 4},
	[FR_TYPE_INT64]				= {8, 8},

	[FR_TYPE_FLOAT32]			= {4, 4},
	[FR_TYPE_FLOAT64]			= {8, 8},

	[FR_TYPE_DATE]				= {2, 8},  //!< 2, 4, or 8 only
	[FR_TYPE_TIME_DELTA]   			= {2, 8},  //!< 2, 4, or 8 only

	[FR_TYPE_ABINARY]			= {32, ~0},
	[FR_TYPE_MAX]				= {~0, 0}		//!< Ensure array covers all types.
};

/** How many uint8s wide each of the value data fields are
 *
 * This is useful when copying a value from a fr_value_box_t to a memory
 * location passed as a void *.
 */
size_t const fr_value_box_field_sizes[] = {
	[FR_TYPE_STRING]			= SIZEOF_MEMBER(fr_value_box_t, vb_strvalue),
	[FR_TYPE_OCTETS]			= SIZEOF_MEMBER(fr_value_box_t, vb_octets),

	[FR_TYPE_IPV4_ADDR]			= SIZEOF_MEMBER(fr_value_box_t, vb_ip),
	[FR_TYPE_IPV4_PREFIX]			= SIZEOF_MEMBER(fr_value_box_t, vb_ip),
	[FR_TYPE_IPV6_ADDR]			= SIZEOF_MEMBER(fr_value_box_t, vb_ip),
	[FR_TYPE_IPV6_PREFIX]			= SIZEOF_MEMBER(fr_value_box_t, vb_ip),
	[FR_TYPE_COMBO_IP_ADDR]			= SIZEOF_MEMBER(fr_value_box_t, vb_ip),
	[FR_TYPE_COMBO_IP_PREFIX]	       	= SIZEOF_MEMBER(fr_value_box_t, vb_ip),
	[FR_TYPE_IFID]				= SIZEOF_MEMBER(fr_value_box_t, vb_ifid),
	[FR_TYPE_ETHERNET]			= SIZEOF_MEMBER(fr_value_box_t, vb_ether),

	[FR_TYPE_BOOL]				= SIZEOF_MEMBER(fr_value_box_t, datum.boolean),
	[FR_TYPE_UINT8]				= SIZEOF_MEMBER(fr_value_box_t, vb_uint8),
	[FR_TYPE_UINT16]			= SIZEOF_MEMBER(fr_value_box_t, vb_uint16),
	[FR_TYPE_UINT32]			= SIZEOF_MEMBER(fr_value_box_t, vb_uint32),
	[FR_TYPE_UINT64]			= SIZEOF_MEMBER(fr_value_box_t, vb_uint64),

	[FR_TYPE_INT8]				= SIZEOF_MEMBER(fr_value_box_t, vb_int8),
	[FR_TYPE_INT16]				= SIZEOF_MEMBER(fr_value_box_t, vb_int16),
	[FR_TYPE_INT32]				= SIZEOF_MEMBER(fr_value_box_t, vb_int32),
	[FR_TYPE_INT64]				= SIZEOF_MEMBER(fr_value_box_t, vb_int64),

	[FR_TYPE_FLOAT32]			= SIZEOF_MEMBER(fr_value_box_t, vb_float32),
	[FR_TYPE_FLOAT64]			= SIZEOF_MEMBER(fr_value_box_t, vb_float64),

	[FR_TYPE_DATE]				= SIZEOF_MEMBER(fr_value_box_t, vb_date),

	[FR_TYPE_TIME_DELTA]			= SIZEOF_MEMBER(fr_value_box_t, datum.time_delta),
	[FR_TYPE_SIZE]				= SIZEOF_MEMBER(fr_value_box_t, datum.size),

	[FR_TYPE_ABINARY]			= SIZEOF_MEMBER(fr_value_box_t, datum.filter),

	[FR_TYPE_VALUE_BOX]			= sizeof(fr_value_box_t),

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

/** Where the value starts in the #fr_value_box_t
 *
 */
size_t const fr_value_box_offsets[] = {
	[FR_TYPE_STRING]			= offsetof(fr_value_box_t, vb_strvalue),
	[FR_TYPE_OCTETS]			= offsetof(fr_value_box_t, vb_octets),

	[FR_TYPE_IPV4_ADDR]			= offsetof(fr_value_box_t, vb_ip),
	[FR_TYPE_IPV4_PREFIX]			= offsetof(fr_value_box_t, vb_ip),
	[FR_TYPE_IPV6_ADDR]			= offsetof(fr_value_box_t, vb_ip),
	[FR_TYPE_IPV6_PREFIX]			= offsetof(fr_value_box_t, vb_ip),
	[FR_TYPE_COMBO_IP_ADDR]			= offsetof(fr_value_box_t, vb_ip),
	[FR_TYPE_COMBO_IP_PREFIX]	       	= offsetof(fr_value_box_t, vb_ip),
	[FR_TYPE_IFID]				= offsetof(fr_value_box_t, vb_ifid),
	[FR_TYPE_ETHERNET]			= offsetof(fr_value_box_t, vb_ether),

	[FR_TYPE_BOOL]				= offsetof(fr_value_box_t, vb_bool),
	[FR_TYPE_UINT8]				= offsetof(fr_value_box_t, vb_uint8),
	[FR_TYPE_UINT16]			= offsetof(fr_value_box_t, vb_uint16),
	[FR_TYPE_UINT32]			= offsetof(fr_value_box_t, vb_uint32),
	[FR_TYPE_UINT64]			= offsetof(fr_value_box_t, vb_uint64),

	[FR_TYPE_INT8]				= offsetof(fr_value_box_t, vb_int8),
	[FR_TYPE_INT16]				= offsetof(fr_value_box_t, vb_int16),
	[FR_TYPE_INT32]				= offsetof(fr_value_box_t, vb_int32),
	[FR_TYPE_INT64]				= offsetof(fr_value_box_t, vb_int64),

	[FR_TYPE_FLOAT32]			= offsetof(fr_value_box_t, vb_float32),
	[FR_TYPE_FLOAT64]			= offsetof(fr_value_box_t, vb_float64),

	[FR_TYPE_DATE]				= offsetof(fr_value_box_t, vb_date),

	[FR_TYPE_TIME_DELTA]			= offsetof(fr_value_box_t, vb_time_delta),
	[FR_TYPE_SIZE]				= offsetof(fr_value_box_t, vb_size),

	[FR_TYPE_ABINARY]			= offsetof(fr_value_box_t, datum.filter),

	[FR_TYPE_VALUE_BOX]			= 0,

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

/** Clear/free any existing value
 *
 * @note Do not use on uninitialised memory.
 *
 * @param[in] data to clear.
 */
inline void fr_value_box_clear(fr_value_box_t *data)
{
	switch (data->type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		TALLOC_FREE(data->datum.ptr);
		data->datum.length = 0;
		break;

	case FR_TYPE_STRUCTURAL:
		fr_assert_fail(NULL);
		return;

	case FR_TYPE_INVALID:
		return;

	default:
		memset(&data->datum, 0, dict_attr_sizes[data->type][1]);
		break;
	}

	data->tainted = false;
	data->type = FR_TYPE_INVALID;
}

/** Copy flags and type data from one value box to another
 *
 * @param[in] dst to copy flags to
 * @param[in] src of data.
 */
static inline void fr_value_box_copy_meta(fr_value_box_t *dst, fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_VARIABLE_SIZE:
		dst->datum.length = src->datum.length;
		break;

	default:
		break;
	}

	dst->enumv = src->enumv;
	dst->type = src->type;
	dst->tainted = src->tainted;
	dst->next = NULL;	/* copy one */
}

/** Compare two values
 *
 * @param[in] a Value to compare.
 * @param[in] b Value to compare.
 * @return
 *	- -1 if a is less than b.
 *	- 0 if both are equal.
 *	- 1 if a is more than b.
 *	- < -1 on failure.
 */
int fr_value_box_cmp(fr_value_box_t const *a, fr_value_box_t const *b)
{
	int compare = 0;

	if (!fr_cond_assert(a->type != FR_TYPE_INVALID)) return -1;
	if (!fr_cond_assert(b->type != FR_TYPE_INVALID)) return -1;

	if (a->type != b->type) {
		fr_strerror_printf("%s: Can't compare values of different types", __FUNCTION__);
		return -2;
	}

	/*
	 *	After doing the previous check for special comparisons,
	 *	do the per-type comparison here.
	 */
	switch (a->type) {
	case FR_TYPE_VARIABLE_SIZE:
	{
		size_t length;

		if (a->datum.length < b->datum.length) {
			length = a->datum.length;
		} else {
			length = b->datum.length;
		}

		if (length) {
			compare = memcmp(a->vb_octets, b->vb_octets, length);
			if (compare != 0) break;
		}

		/*
		 *	Contents are the same.  The return code
		 *	is therefore the difference in lengths.
		 *
		 *	i.e. "0x00" is smaller than "0x0000"
		 */
		compare = a->datum.length - b->datum.length;
	}
		break;

		/*
		 *	Short-hand for simplicity.
		 */
#define CHECK(_type) if (a->datum._type < b->datum._type)   { compare = -1; \
		} else if (a->datum._type > b->datum._type) { compare = +1; }

	case FR_TYPE_BOOL:
		CHECK(boolean);
		break;

	case FR_TYPE_DATE:
		CHECK(date);
		break;

	case FR_TYPE_UINT8:
		CHECK(uint8);
		break;

	case FR_TYPE_UINT16:
		CHECK(uint16);
		break;

	case FR_TYPE_UINT32:
		CHECK(int32);
		break;

	case FR_TYPE_UINT64:
		CHECK(uint64);
		break;

	case FR_TYPE_INT8:
		CHECK(int8);
		break;

	case FR_TYPE_INT16:
		CHECK(int16);
		break;

	case FR_TYPE_INT32:
		CHECK(int32);
		break;

	case FR_TYPE_INT64:
		CHECK(int64);
		break;

	case FR_TYPE_SIZE:
		CHECK(size);
		break;

	case FR_TYPE_TIME_DELTA:
		CHECK(time_delta);
		break;

	case FR_TYPE_FLOAT32:
		CHECK(float32);
		break;

	case FR_TYPE_FLOAT64:
		CHECK(float64);
		break;

	case FR_TYPE_ETHERNET:
		compare = memcmp(a->vb_ether, b->vb_ether, sizeof(a->vb_ether));
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		compare = memcmp(&a->vb_ip, &b->vb_ip, sizeof(a->vb_ip));
		break;

	case FR_TYPE_IFID:
		compare = memcmp(a->vb_ifid, b->vb_ifid, sizeof(a->vb_ifid));
		break;

	/*
	 *	These should be handled at some point
	 */
	case FR_TYPE_NON_VALUES:
		(void)fr_cond_assert(0);	/* unknown type */
		return -2;

	/*
	 *	Do NOT add a default here, as new types are added
	 *	static analysis will warn us they're not handled
	 */
	}

	if (compare > 0) return 1;
	if (compare < 0) return -1;
	return 0;
}

/*
 *	We leverage the fact that IPv4 and IPv6 prefixes both
 *	have the same format:
 *
 *	reserved, prefix-len, data...
 */
static int fr_value_box_cidr_cmp_op(fr_token_t op, int uint8s,
				 uint8_t a_net, uint8_t const *a,
				 uint8_t b_net, uint8_t const *b)
{
	int i, common;
	uint32_t mask;

	/*
	 *	Handle the case of netmasks being identical.
	 */
	if (a_net == b_net) {
		int compare;

		compare = memcmp(a, b, uint8s);

		/*
		 *	If they're identical return true for
		 *	identical.
		 */
		if ((compare == 0) &&
		    ((op == T_OP_CMP_EQ) ||
		     (op == T_OP_LE) ||
		     (op == T_OP_GE))) {
			return true;
		}

		/*
		 *	Everything else returns false.
		 *
		 *	10/8 == 24/8  --> false
		 *	10/8 <= 24/8  --> false
		 *	10/8 >= 24/8  --> false
		 */
		return false;
	}

	/*
	 *	Netmasks are different.  That limits the
	 *	possible results, based on the operator.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
		return false;

	case T_OP_NE:
		return true;

	case T_OP_LE:
	case T_OP_LT:	/* 192/8 < 192.168/16 --> false */
		if (a_net < b_net) {
			return false;
		}
		break;

	case T_OP_GE:
	case T_OP_GT:	/* 192/16 > 192.168/8 --> false */
		if (a_net > b_net) {
			return false;
		}
		break;

	default:
		return false;
	}

	if (a_net < b_net) {
		common = a_net;
	} else {
		common = b_net;
	}

	/*
	 *	Do the check uint8 by uint8.  If the uint8s are
	 *	identical, it MAY be a match.  If they're different,
	 *	it is NOT a match.
	 */
	i = 0;
	while (i < uint8s) {
		/*
		 *	All leading uint8s are identical.
		 */
		if (common == 0) return true;

		/*
		 *	Doing bitmasks takes more work.
		 */
		if (common < 8) break;

		if (a[i] != b[i]) return false;

		common -= 8;
		i++;
		continue;
	}

	mask = 1;
	mask <<= (8 - common);
	mask--;
	mask = ~mask;

	if ((a[i] & mask) == ((b[i] & mask))) {
		return true;
	}

	return false;
}

/** Compare two attributes using an operator
 *
 * @param[in] op to use in comparison.
 * @param[in] a Value to compare.
 * @param[in] b Value to compare.
 * @return
 *	- 1 if true
 *	- 0 if false
 *	- -1 on failure.
 */
int fr_value_box_cmp_op(fr_token_t op, fr_value_box_t const *a, fr_value_box_t const *b)
{
	int compare = 0;

	if (!a || !b) return -1;

	if (!fr_cond_assert(a->type != FR_TYPE_INVALID)) return -1;
	if (!fr_cond_assert(b->type != FR_TYPE_INVALID)) return -1;

	switch (a->type) {
	case FR_TYPE_IPV4_ADDR:
		switch (b->type) {
		case FR_TYPE_IPV4_ADDR:		/* IPv4 and IPv4 */
			goto cmp;

		case FR_TYPE_IPV4_PREFIX:	/* IPv4 and IPv4 Prefix */
			return fr_value_box_cidr_cmp_op(op, 4, 32, (uint8_t const *) &a->vb_ip.addr.v4.s_addr,
						     b->vb_ip.prefix, (uint8_t const *) &b->vb_ip.addr.v4.s_addr);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}

	case FR_TYPE_IPV4_PREFIX:		/* IPv4 and IPv4 Prefix */
		switch (b->type) {
		case FR_TYPE_IPV4_ADDR:
			return fr_value_box_cidr_cmp_op(op, 4, a->vb_ip.prefix,
						     (uint8_t const *) &a->vb_ip.addr.v4.s_addr,
						     32, (uint8_t const *) &b->vb_ip.addr.v4);

		case FR_TYPE_IPV4_PREFIX:	/* IPv4 Prefix and IPv4 Prefix */
			return fr_value_box_cidr_cmp_op(op, 4, a->vb_ip.prefix,
						     (uint8_t const *) &a->vb_ip.addr.v4.s_addr,
						     b->vb_ip.prefix, (uint8_t const *) &b->vb_ip.addr.v4.s_addr);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}

	case FR_TYPE_IPV6_ADDR:
		switch (b->type) {
		case FR_TYPE_IPV6_ADDR:		/* IPv6 and IPv6 */
			goto cmp;

		case FR_TYPE_IPV6_PREFIX:	/* IPv6 and IPv6 Preifx */
			return fr_value_box_cidr_cmp_op(op, 16, 128, (uint8_t const *) &a->vb_ip.addr.v6,
						     b->vb_ip.prefix, (uint8_t const *) &b->vb_ip.addr.v6);

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}

	case FR_TYPE_IPV6_PREFIX:
		switch (b->type) {
		case FR_TYPE_IPV6_ADDR:		/* IPv6 Prefix and IPv6 */
			return fr_value_box_cidr_cmp_op(op, 16, a->vb_ip.prefix,
						     (uint8_t const *) &a->vb_ip.addr.v6,
						     128, (uint8_t const *) &b->vb_ip.addr.v6);

		case FR_TYPE_IPV6_PREFIX:	/* IPv6 Prefix and IPv6 */
			return fr_value_box_cidr_cmp_op(op, 16, a->vb_ip.prefix,
						     (uint8_t const *) &a->vb_ip.addr.v6,
						     b->vb_ip.prefix, (uint8_t const *) &b->vb_ip.addr.v6);

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}

	default:
	cmp:
		compare = fr_value_box_cmp(a, b);
		if (compare < -1) {	/* comparison error */
			return -1;
		}
	}

	/*
	 *	Now do the operator comparison.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
		return (compare == 0);

	case T_OP_NE:
		return (compare != 0);

	case T_OP_LT:
		return (compare < 0);

	case T_OP_GT:
		return (compare > 0);

	case T_OP_LE:
		return (compare <= 0);

	case T_OP_GE:
		return (compare >= 0);

	default:
		return 0;
	}
}

static char const hextab[] = "0123456789abcdef";

/** Convert a string value with escape sequences into its binary form
 *
 * The quote character determines the escape sequences recognised.
 *
 * Literal mode ("'" quote char) will unescape:
 @verbatim
   - \\        - Literal backslash.
   - \<quote>  - The quotation char.
 @endverbatim
 *
 * Expanded mode (any other quote char) will also unescape:
 @verbatim
   - \r        - Carriage return.
   - \n        - Newline.
   - \t        - Tab.
   - \<oct>    - An octal escape sequence.
   - \x<hex>   - A hex escape sequence.
 @endverbatim
 *
 * Verbatim mode ("\0") passing \0 as the quote char copies in to out verbatim.
 *
 * @note The resulting string will not be \0 terminated, and may contain embedded \0s.
 * @note Invalid escape sequences will be copied verbatim.
 * @note in and out may point to the same buffer.
 *
 * @param[out] out	Where to write the unescaped string.
 *			Unescaping never introduces additional chars.
 * @param[in] in	The string to unescape.
 * @param[in] inlen	Length of input string.
 * @param[in] quote	Character around the string, determines unescaping mode.
 *
 * @return >= 0 the number of uint8s written to out.
 */
size_t fr_value_str_unescape(uint8_t *out, char const *in, size_t inlen, char quote)
{
	char const	*p = in;
	uint8_t		*out_p = out;
	int		x;

	/*
	 *	No de-quoting.  Just copy the string.
	 */
	if (!quote) {
		memcpy(out, in, inlen);
		return inlen;
	}

	/*
	 *	Do escaping for single quoted strings.  Only
	 *	single quotes get escaped.  Everything else is
	 *	left as-is.
	 */
	if (quote == '\'') {
		while (p < (in + inlen)) {
			/*
			 *	The quotation character is escaped.
			 */
			if ((p[0] == '\\') &&
			    (p[1] == quote)) {
				*(out_p++) = quote;
				p += 2;
				continue;
			}

			/*
			 *	Two backslashes get mangled to one.
			 */
			if ((p[0] == '\\') &&
			    (p[1] == '\\')) {
				*(out_p++) = '\\';
				p += 2;
				continue;
			}

			/*
			 *	Not escaped, just copy it over.
			 */
			*(out_p++) = *(p++);
		}
		return out_p - out;
	}

	/*
	 *	It's "string" or `string`, do all standard
	 *	escaping.
	 */
	while (p < (in + inlen)) {
		uint8_t c = *p++;
		uint8_t *h0, *h1;

		/*
		 *	We copy all invalid escape sequences verbatim,
		 *	even if they occur at the end of sthe string.
		 */
		if ((c == '\\') && (p >= (in + inlen))) {
		invalid_escape:
			*out_p++ = c;
			while (p < (in + inlen)) *out_p++ = *p++;
			return out_p - out;
		}

		/*
		 *	Fix up \[rnt\\] -> ... the binary form of it.
		 */
		if (c == '\\') {
			switch (*p) {
			case 'r':
				c = '\r';
				p++;
				break;

			case 'n':
				c = '\n';
				p++;
				break;

			case 't':
				c = '\t';
				p++;
				break;

			case '\\':
				c = '\\';
				p++;
				break;

			default:
				/*
				 *	\" --> ", but only inside of double quoted strings, etc.
				 */
				if (*p == quote) {
					c = quote;
					p++;
					break;
				}

				/*
				 *	We need at least three chars, for either octal or hex
				 */
				if ((p + 2) >= (in + inlen)) goto invalid_escape;

				/*
				 *	\x00 --> binary zero character
				 */
				if ((p[0] == 'x') &&
				    (h0 = memchr((uint8_t const *)hextab, tolower((int) p[1]), sizeof(hextab))) &&
				    (h1 = memchr((uint8_t const *)hextab, tolower((int) p[2]), sizeof(hextab)))) {
				 	c = ((h0 - (uint8_t const *)hextab) << 4) + (h1 - (uint8_t const *)hextab);
				 	p += 3;
				}

				/*
				 *	\000 --> binary zero character
				 */
				if ((p[0] >= '0') &&
				    (p[0] <= '9') &&
				    (p[1] >= '0') &&
				    (p[1] <= '9') &&
				    (p[2] >= '0') &&
				    (p[2] <= '9') &&
				    (sscanf(p, "%3o", &x) == 1)) {
					c = x;
					p += 3;
				}

				/*
				 *	Else It's not a recognised escape sequence DON'T
				 *	consume the backslash. This is identical
				 *	behaviour to bash and most other things that
				 *	use backslash escaping.
				 */
			}
		}
		*out_p++ = c;
	}

	return out_p - out;
}

/** Performs byte order reversal for types that need it
 *
 * @param[in] dst	Where to write the result.  May be the same as src.
 * @param[in] src	#fr_value_box_t containing an uint32 value.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_hton(fr_value_box_t *dst, fr_value_box_t const *src)
{
	if (!fr_cond_assert(src->type != FR_TYPE_INVALID)) return -1;

	switch (src->type) {
	case FR_TYPE_UINT16:
		dst->vb_uint16 = htons(src->vb_uint16);
		break;

	case FR_TYPE_UINT32:
		dst->vb_uint32 = htonl(src->vb_uint32);
		break;

	case FR_TYPE_UINT64:
		dst->vb_uint64 = htonll(src->vb_uint64);
		break;

	case FR_TYPE_INT16:
		dst->vb_uint16 = htons(src->vb_uint16);
		break;

	case FR_TYPE_INT32:
		dst->vb_uint32 = htonl(src->vb_uint32);
		break;

	case FR_TYPE_DATE:
		dst->vb_date = htonll(src->vb_date);
		break;

	case FR_TYPE_TIME_DELTA:
		dst->vb_time_delta = htonll(src->vb_time_delta);
		break;

	case FR_TYPE_INT64:
		dst->vb_uint64 = htonll(src->vb_uint64);
		break;

	case FR_TYPE_FLOAT32:
		dst->vb_uint32 = htonl(dst->vb_uint32);
		break;

	case FR_TYPE_FLOAT64:
		dst->vb_uint64 = htonll(dst->vb_uint64);
		break;

	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_INT8:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_SIZE:
	case FR_TYPE_ABINARY:
		fr_value_box_copy(NULL, dst, src);
		return 0;

	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	case FR_TYPE_NON_VALUES:
		fr_assert_fail(NULL);
		return -1; /* shouldn't happen */
	}

	if (dst != src) fr_value_box_copy_meta(dst, src);

	return 0;
}
/** Get the size of the value held by the fr_value_box_t
 *
 * This is the length of the NETWORK presentation
 */
size_t fr_value_box_network_length(fr_value_box_t *value)
{
	switch (value->type) {
	case FR_TYPE_VARIABLE_SIZE:
	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		return value->datum.length;

	default:
		return fr_value_box_network_sizes[value->type][0];
	}
}

/** Encode a single value box, serializing its contents in generic network format
 *
 * The serialized form of #fr_value_box_t may not match the requirements of your protocol
 * completely.  In cases where they do not, you should overload specific types in the
 * function calling #fr_value_box_to_network.
 *
 * The general serialization rules are:
 *
 * - Octets are encoded in binary form (not hex).
 * - Strings are encoded without the trailing \0 byte.
 * - Integers are encoded big-endian.
 * - Bools are encoded using one byte, with value 0x00 (false) or 0x01 (true).
 * - Signed integers are encoded two's complement, with the MSB as the sign bit.
 *   Byte order is big-endian.
 * - Network addresses are encoded big-endian.
 * - IPv4 prefixes are encoded with 1 byte for the prefix, then 4 bytes of address.
 * - IPv6 prefixes are encoded with 1 byte for the scope_id, 1 byte for the prefix,
 *   and 16 bytes of address.
 * - Floats are encoded in IEEE-754 format with a big-endian byte order.  We rely
 *   on the fact that the C standards require floats to be represented in IEEE-754
 *   format in memory.
 * - Dates are encoded as 16/32/64-bit unsigned UNIX timestamps.
 * - time_deltas are encoded as 16/32/64-bit signed integers.
 *
 * #FR_TYPE_SIZE is not encodable, as it is system specific.
 * #FR_TYPE_ABINARY is RADIUS specific and should be encoded by the RADIUS encoder.
 *
 * This function will not encode complex types (TLVs, VSAs etc...).  These are usually
 * specific to the protocol anyway.
 *
 * @param[out] need	if not NULL, how many bytes are required to serialize
 *			the remainder of the boxed data.
 *			Note: Only variable length types will be partially
 *			encoded. Fixed length types will not be partially encoded.
 * @param[out] dst	Where to write serialized data.
 * @param[in] dst_len	The length of the output buffer, or maximum value fragment
 *			size.
 * @param[in] value	to encode.
 * @return
 *	- 0 no bytes were written, see need value to determine if it was because
 *	  the fr_value_box_t was #FR_TYPE_OCTETS/#FR_TYPE_STRING and was
 *	  NULL (which is unfortunately valid)
 *	- >0 the number of bytes written to out.
 *	- <0 on error.
 */
ssize_t fr_value_box_to_network(size_t *need, uint8_t *dst, size_t dst_len, fr_value_box_t const *value)
{
	return fr_value_box_to_network_dbuff(need, &FR_DBUFF_TMP(dst, dst_len), value);
}

ssize_t fr_value_box_to_network_dbuff(size_t *need, fr_dbuff_t *dbuff, fr_value_box_t const *value)
{
	size_t min, max;

	/*
	 *	Variable length types
	 */
	switch (value->type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	{
		size_t len;

		/*
		 *	Figure dst if we'd overflow
		 */
		if (value->datum.length > fr_dbuff_remaining(dbuff)) {
			if (need) *need = value->datum.length;
			len = fr_dbuff_remaining(dbuff);
		} else {
			if (need) *need = 0;
			len = value->datum.length;
		}

		if (value->datum.length > 0) fr_dbuff_memcpy_in(dbuff, value->datum.ptr, len);

		return len;
	}

	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (value->enumv) {
			min = max = value->enumv->flags.length;
		} else {
			min = max = 4;
		}
		break;

	default:
		min = fr_value_box_network_sizes[value->type][0];
		max = fr_value_box_network_sizes[value->type][1];
		break;
	}

	/*
	 *	It's an unsupported type
	 */
	if ((min == 0) && (max == 0)) {
	unsupported:
		fr_strerror_printf("%s: Cannot encode type \"%s\"",
				   __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, value->type, "<INVALID>"));
		return FR_VALUE_BOX_NET_ERROR;
	}

	/*
	 *	Fixed type would overflow output buffer
	 */
	if (max > fr_dbuff_remaining(dbuff)) {
		if (need) *need = max;
		return 0;
	}

	switch (value->type) {
	case FR_TYPE_IPV4_ADDR:
		fr_dbuff_memcpy_in(dbuff, (uint8_t const *)&value->vb_ip.addr.v4.s_addr,
				   sizeof(value->vb_ip.addr.v4.s_addr));
		break;
	/*
	 *	Needs special mangling
	 */
	case FR_TYPE_IPV4_PREFIX:
		fr_dbuff_memcpy_in(dbuff, &value->vb_ip.prefix, sizeof(value->vb_ip.prefix));
		fr_dbuff_memcpy_in(dbuff, (uint8_t const *)&value->vb_ip.addr.v4.s_addr,
				   sizeof(value->vb_ip.addr.v4.s_addr));
		break;

	case FR_TYPE_IPV6_ADDR:
		if (value->vb_ip.scope_id > 0) fr_dbuff_bytes_in(dbuff, value->vb_ip.scope_id);
		fr_dbuff_memcpy_in(dbuff, value->vb_ip.addr.v6.s6_addr, sizeof(value->vb_ip.addr.v6.s6_addr));
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (value->vb_ip.scope_id > 0) fr_dbuff_bytes_in(dbuff, value->vb_ip.scope_id);
		fr_dbuff_memcpy_in(dbuff, &value->vb_ip.prefix, sizeof(value->vb_ip.prefix));
		fr_dbuff_memcpy_in(dbuff, value->vb_ip.addr.v6.s6_addr, sizeof(value->vb_ip.addr.v6.s6_addr));
		break;

	case FR_TYPE_BOOL:
		fr_dbuff_bytes_in(dbuff, value->datum.boolean);
		break;

	/*
	 *	Already in network byte-order
	 */

	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_UINT8:
	case FR_TYPE_INT8:
		if (!fr_cond_assert(fr_value_box_field_sizes[value->type] == min)) return -1;
		fr_dbuff_memcpy_in(dbuff, ((uint8_t const *)&value->datum) + fr_value_box_offsets[value->type], min);
		break;

	/*
	 *	Needs a bytesex operation
	 */
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	{
		fr_value_box_t tmp;

		if (!fr_cond_assert(fr_value_box_field_sizes[value->type] == min)) return -1;

		fr_value_box_hton(&tmp, value);
		fr_dbuff_memcpy_in(dbuff, ((uint8_t const *)&tmp.datum) + fr_value_box_offsets[value->type], min);
	}
		break;

		/*
		 *	Dates and deltas are stored internally as
		 *	64-bit nanoseconds.  We have to convert to the
		 *	network format.  First by resolution (ns, us,
		 *	ms, s), and then by size (16/32/64-bit).
		 */
	case FR_TYPE_DATE:
	{
		uint64_t date;

		if (!value->enumv) {
			goto date_seconds;

		} else switch (value->enumv->flags.type_size) {
		date_seconds:
		case FR_TIME_RES_SEC:
			date = fr_unix_time_to_sec(value->vb_date);
			break;

		case FR_TIME_RES_MSEC:
			date = fr_unix_time_to_msec(value->vb_date);
			break;

		case FR_TIME_RES_USEC:
			date = fr_unix_time_to_usec(value->vb_date);
			break;

		case FR_TIME_RES_NSEC:
			date = fr_unix_time_to_usec(value->vb_date);
			break;

		default:
			goto unsupported;
		}

		if (!value->enumv) {
			goto date_size4;

		} else switch (value->enumv->flags.length) {
		case 2:
			if (date > UINT16_MAX) date = UINT16_MAX;
			fr_dbuff_net_from_uint16(dbuff, date);
			break;

		date_size4:
		case 4:
			if (date > UINT32_MAX) date = UINT32_MAX;
			fr_dbuff_net_from_uint32(dbuff, date);
			break;

		case 8:
			fr_dbuff_net_from_uint64(dbuff, date);
			break;

		default:
			goto unsupported;
		}

	}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		int64_t date;	/* may be negative */

		if (!value->enumv) {
			goto delta_seconds;

		} else switch (value->enumv->flags.type_size) {
		delta_seconds:
		case FR_TIME_RES_SEC:
			date = fr_time_delta_to_sec(value->vb_time_delta);
			break;

		case FR_TIME_RES_MSEC:
			date = fr_time_delta_to_msec(value->vb_time_delta);
			break;

		case FR_TIME_RES_USEC:
			date = fr_time_delta_to_usec(value->vb_time_delta);
			break;

		case FR_TIME_RES_NSEC:
			date = value->vb_time_delta;
			break;

		default:
			goto unsupported;
		}

		if (!value->enumv) {
			goto delta_size4;

		} else switch (value->enumv->flags.length) {
		case 2:
			if (date < INT16_MIN) {
				date = INT16_MIN;
			} else if (date > INT16_MAX) {
				date = INT16_MAX;
			}
			fr_dbuff_net_from_uint16(dbuff, (uint16_t)date);
			break;

		delta_size4:
		case 4:
			if (date < INT32_MIN) {
				date = INT32_MIN;
			} else if (date > INT32_MAX) {
				date = INT32_MAX;
			}
			fr_dbuff_net_from_uint32(dbuff, (uint32_t)date);
			break;

		case 8:
			fr_dbuff_net_from_uint64(dbuff, (uint64_t)date);
			break;

		default:
			goto unsupported;
		}

	}
		break;

	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	case FR_TYPE_SIZE:
	case FR_TYPE_ABINARY:
	case FR_TYPE_NON_VALUES:
		goto unsupported;
	}

	if (need) *need = 0;

	return min;
}

/** Decode a #fr_value_box_t from serialized binary data
 *
 * The general deserialization rules are:
 *
 * - Octets are decoded in binary form (not hex).
 * - Strings are decoded without the trailing \0 byte. Strings must consist only of valid UTF8 chars.
 * - Integers are decoded big-endian.
 * - Bools are decoded using one byte, with value 0x00 (false) or 0x01 (true).
 * - Signed integers are decoded two's complement, with the MSB as the sign bit.
 *   Byte order is big-endian.
 * - Network addresses are decoded big-endian.
 * - IPv4 prefixes are decoded with 1 byte for the prefix, then 4 bytes of address.
 * - IPv6 prefixes are decoded with 1 byte for the scope_id, 1 byte for the prefix,
 *   and 16 bytes of address.
 * - Floats are decoded in IEEE-754 format with a big-endian byte order.  We rely
 *   on the fact that the C standards require floats to be represented in IEEE-754
 *   format in memory.
 * - Dates are decoded as 32bit unsigned UNIX timestamps.
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[out] dst	value_box to write the result to.
 * @param[in] type	to decode data to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	Binary data to decode.
 * @param[in] len	Length of data to decode.  For fixed length types we only
 *			decode complete values.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- >= 0 The number of bytes consumed.
 *	- <0 - The negative offset where the error occurred.
 *	- FR_VALUE_BOX_NET_OOM (negative value) - Out of memory.
 */
ssize_t fr_value_box_from_network(TALLOC_CTX *ctx,
				  fr_value_box_t *dst, fr_type_t type, fr_dict_attr_t const *enumv,
				  uint8_t const *src, size_t len,
				  bool tainted)
{
	uint8_t	const *p = src;
	size_t	min, max;

	min = fr_value_box_network_sizes[type][0];
	max = fr_value_box_network_sizes[type][1];

	if (len < min) {
		fr_strerror_printf("Got truncated value parsing type \"%s\". "
				   "Expected length >= %zu bytes, got %zu bytes",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"),
				   min, len);
		return -(len);
	}
	if (len > max) {
		fr_strerror_printf("Found trailing garbage parsing type \"%s\". "
				   "Expected length <= %zu bytes, got %zu bytes",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"),
				   max, len);
		return -(max);
	}

	switch (type) {
	case FR_TYPE_STRING:
		if (fr_value_box_bstrndup(ctx, dst, enumv, (char const *)src, len, tainted) < 0) return FR_VALUE_BOX_NET_OOM;
		return len;

	case FR_TYPE_OCTETS:
		if (fr_value_box_memcpy(ctx, dst, enumv, src, len, tainted) < 0) return FR_VALUE_BOX_NET_OOM;
		return len;

	/*
	 *	Already in network byte order
	 */
	case FR_TYPE_IPV4_ADDR:
		memset(&dst->vb_ip, 0, sizeof(dst->vb_ip));
		memcpy(&dst->vb_ip.addr.v4, src, len);
		dst->vb_ip.af = AF_INET;
		dst->vb_ip.prefix = 32;
		dst->vb_ip.scope_id = 0;	/* init even if it's unused */
		break;

	case FR_TYPE_IPV4_PREFIX:
		memset(&dst->vb_ip, 0, sizeof(dst->vb_ip));
		dst->vb_ip.af = AF_INET;
		dst->vb_ip.prefix = *p++;
		memcpy(&dst->vb_ip.addr.v4, p, sizeof(dst->vb_ip.addr.v4));
		dst->vb_ip.scope_id = 0;	/* init even if it's unused */
		break;

	case FR_TYPE_IPV6_ADDR:
		memset(&dst->vb_ip, 0, sizeof(dst->vb_ip));
		dst->vb_ip.af = AF_INET6;
		dst->vb_ip.scope_id = len == max ? *p++ : 0;		/* optional */
		memcpy(&dst->vb_ip.addr.v6, p, sizeof(dst->vb_ip.addr.v6));
		dst->vb_ip.prefix = 128;
		break;

	case FR_TYPE_IPV6_PREFIX:
		memset(&dst->vb_ip, 0, sizeof(dst->vb_ip));
		dst->vb_ip.af = AF_INET6;
		dst->vb_ip.scope_id = len == max ? *p++ : 0;		/* optional */
		dst->vb_ip.prefix = *p++;
		memcpy(&dst->vb_ip.addr.v6, p, sizeof(dst->vb_ip.addr.v6));
		break;

	case FR_TYPE_BOOL:
		dst->datum.boolean = src[0] > 0 ? true : false;
		break;

	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_UINT8:
	case FR_TYPE_INT8:
		memcpy(((uint8_t *)&dst->datum) + fr_value_box_offsets[type], src, len);
		break;

	/*
	 *	Needs a bytesex operation
	 */
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
		memcpy(((uint8_t *)&dst->datum) + fr_value_box_offsets[type], src, len);
		fr_value_box_hton(dst, dst);	/* Operate in-place */
		break;

		/*
		 *	Dates and deltas are stored internally as
		 *	64-bit nanoseconds.  We have to convert from
		 *	the network format.  First by size
		 *	(16/32/64-bit), and then by resolution (ns,
		 *	us, ms, s).
		 */
	case FR_TYPE_DATE:
	{
		size_t i, length = 4;
		fr_time_res_t precision = FR_TIME_RES_SEC;
		uint64_t date;

		if (enumv) {
			length = enumv->flags.length;
			precision = (fr_time_res_t)enumv->flags.type_size;
		}

		/*
		 *	Input data doesn't match what we were told we
		 *	need.
		 */
		if (len != length) return (len > length) ? -(length) : -(len);

		/*
		 *	Just loop over the input data until we reach
		 *	the end.  Shifting it every time.
		 */
		date = 0;
		dst->enumv = enumv;

		i = 0;
		do {
			date <<= 8;
			date |= *(p++);
			i++;
		} while (i < length);

		switch (precision) {
		default:
		case FR_TIME_RES_SEC: /* external seconds, internal nanoseconds */
			date *= NSEC;
			break;

		case FR_TIME_RES_MSEC:
			date *= 1000000;
			break;

		case FR_TIME_RES_USEC:
			date *= 1000;
			break;

		case FR_TIME_RES_NSEC:
			break;
		}

		dst->vb_date = date;
	}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		size_t i, length = 4;
		fr_time_res_t precision = FR_TIME_RES_SEC;
		uint64_t date;

		if (enumv) {
			length = enumv->flags.length;
			precision = (fr_time_res_t)enumv->flags.type_size;
		}

		/*
		 *	Input data doesn't match what we were told we
		 *	need.
		 */
		if (len != length) return (len > length) ? -(length) : -(len);

		/*
		 *	Just loop over the input data until we reach
		 *	the end.  Shifting it every time.
		 */
		date = 0;
		dst->enumv = enumv;

		i = 0;
		do {
			date <<= 8;
			date |= *(p++);
			i++;
		} while (i < length);

		switch (precision) {
		default:
		case FR_TIME_RES_SEC: /* external seconds, internal nanoseconds */
			dst->vb_time_delta = fr_time_delta_from_sec(date);
			break;

		case FR_TIME_RES_MSEC:
			dst->vb_time_delta = fr_time_delta_from_msec(date);
			break;

		case FR_TIME_RES_USEC:
			dst->vb_time_delta = fr_time_delta_from_usec(date);
			break;

		case FR_TIME_RES_NSEC:
			dst->vb_time_delta = date;
			break;
		}

	}
		break;

	case FR_TYPE_SIZE:
	case FR_TYPE_ABINARY:
	case FR_TYPE_NON_VALUES:
		fr_strerror_printf("Cannot decode type \"%s\" - Is not a value",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"));
		break;
	}

	dst->type = type;
	dst->tainted = tainted;
	dst->enumv = enumv;
	dst->next = NULL;

	return len;
}

/** Convert octets to a fixed size value box value
 *
 * All fixed size types are allowed.
 *
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static int fr_value_box_fixed_size_from_octets(fr_value_box_t *dst,
					      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					      fr_value_box_t const *src)
{
	switch (dst_type) {
	case FR_TYPE_FIXED_SIZE:
		break;

	default:
		if (!fr_cond_assert(false)) return -1;
	}

	if (src->datum.length < fr_value_box_network_sizes[dst_type][0]) {
		fr_strerror_printf("Invalid cast from %s to %s.  Source is length %zd is smaller than "
				   "destination type size %zd",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
				   src->datum.length,
				   fr_value_box_network_sizes[dst_type][0]);
		return -1;
	}

	if (src->datum.length > fr_value_box_network_sizes[dst_type][1]) {
		fr_strerror_printf("Invalid cast from %s to %s.  Source length %zd is greater than "
				   "destination type size %zd",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
				   src->datum.length,
				   fr_value_box_network_sizes[dst_type][1]);
		return -1;
	}

	/*
	 *	Copy the raw octets into the datum of a value_box
	 *	inverting bytesex for uint32s (if LE).
	 */
	memcpy(&dst->datum, src->vb_octets, fr_value_box_field_sizes[dst_type]);
	dst->type = dst_type;
	dst->enumv = dst_enumv;
	fr_value_box_hton(dst, dst);

	return 0;
}

/** v4 to v6 mapping prefix
 *
 * Part of the IPv6 range is allocated to represent IPv4 addresses.
 */
static uint8_t const v4_v6_map[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x00, 0xff, 0xff };


/** Convert any supported type to a string
 *
 * All non-structural types are allowed.
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_strvalue(TALLOC_CTX *ctx, fr_value_box_t *dst,
						fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						fr_value_box_t const *src)
{
	if (!fr_cond_assert(dst_type == FR_TYPE_STRING)) return -1;

	switch (src->type) {
	/*
	 *	The presentation format of octets is hex
	 *	What we actually want here is the raw string
	 */
	case FR_TYPE_OCTETS:
		dst->vb_strvalue = talloc_bstrndup(ctx, (char const *)src->vb_octets, src->datum.length);
		dst->datum.length = src->datum.length;	/* It's the same, even though the buffer is slightly bigger */
		break;

	case FR_TYPE_GROUP:
	{
		fr_cursor_t cursor;
		fr_value_box_t *vb;

		dst->type = FR_TYPE_STRING;
		dst->vb_strvalue = talloc_typed_strdup(ctx, "");
		dst->datum.length = 0;

		fr_cursor_init(&cursor, &src->vb_group);
		while ((vb = fr_cursor_current(&cursor)) != NULL) {
			fr_value_box_t *n = vb;

			if (vb->type != FR_TYPE_STRING) {
				n = talloc_zero(ctx, fr_value_box_t);
				if (!n) return -1;

				if (fr_value_box_cast(n, n, FR_TYPE_STRING, NULL, vb) < 0) {
					return -1;
				}
			}

			if (fr_value_box_append_bstr(dst, n->vb_strvalue, n->vb_length, n->tainted) < 0) return -1;

			if (n != vb) talloc_free(n);
			fr_cursor_next(&cursor);
		}
	}
		break;

	/*
	 *	Get the presentation format
	 */
	default:
		dst->vb_strvalue = fr_value_box_asprint(ctx, src, '\0');
		dst->datum.length = talloc_array_length(dst->vb_strvalue) - 1;
		break;
	}

	if (!dst->vb_strvalue) return -1;
	dst->type = FR_TYPE_STRING;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to octets
 *
 * All non-structural types are allowed.
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_octets(TALLOC_CTX *ctx, fr_value_box_t *dst,
					      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					      fr_value_box_t const *src)
{
	uint8_t *bin;

	if (!fr_cond_assert(dst_type == FR_TYPE_OCTETS)) return -1;

	switch (src->type) {
	/*
	 *	<string> (excluding terminating \0)
	 */
	case FR_TYPE_STRING:
		bin = talloc_memdup(ctx, (uint8_t const *)src->vb_strvalue, src->datum.length);
		break;

	case FR_TYPE_GROUP:
	{
		fr_cursor_t cursor;
		fr_value_box_t *vb;

		dst->type = FR_TYPE_OCTETS;
		dst->vb_octets = talloc_memdup(ctx, "", 0);
		talloc_set_type(dst->vb_octets, uint8_t);
		dst->datum.length = 0;

		fr_cursor_init(&cursor, &src->vb_group);
		while ((vb = fr_cursor_current(&cursor)) != NULL) {
			fr_value_box_t *n = vb;

			if (vb->type != FR_TYPE_OCTETS) {
				n = talloc_zero(ctx, fr_value_box_t);
				if (!n) return -1;

				if (fr_value_box_cast(n, n, FR_TYPE_OCTETS, NULL, vb) < 0) {
					return -1;
				}
			}

			if (fr_value_box_append_mem(dst, n->vb_octets, n->vb_length, n->tainted) < 0) return -1;

			if (n != vb) talloc_free(n);
			fr_cursor_next(&cursor);
		}

		return 0;
	}

	/*
	 *	<4 uint8s address>
	 */
	case FR_TYPE_IPV4_ADDR:
	{
		bin = talloc_memdup(ctx, (uint8_t const *)&src->vb_ip.addr.v4.s_addr,
				    sizeof(src->vb_ip.addr.v4.s_addr));
	}
		break;

	/*
	 *	<1 uint8 prefix> + <4 uint8s address>
	 */
	case FR_TYPE_IPV4_PREFIX:
		bin = talloc_array(ctx, uint8_t, sizeof(src->vb_ip.addr.v4.s_addr) + 1);
		bin[0] = src->vb_ip.prefix;
		memcpy(&bin[1], (uint8_t const *)&src->vb_ip.addr.v4.s_addr, sizeof(src->vb_ip.addr.v4.s_addr));
		break;

	/*
	 *	<16 uint8s address>
	 */
	case FR_TYPE_IPV6_ADDR:
		bin = talloc_memdup(ctx, (uint8_t const *)src->vb_ip.addr.v6.s6_addr,
				    sizeof(src->vb_ip.addr.v6.s6_addr));
		break;

	/*
	 *	<1 uint8 prefix> + <1 uint8 scope> + <16 uint8s address>
	 */
	case FR_TYPE_IPV6_PREFIX:
		bin = talloc_array(ctx, uint8_t, sizeof(src->vb_ip.addr.v6.s6_addr) + 2);
		bin[0] = src->vb_ip.scope_id;
		bin[1] = src->vb_ip.prefix;
		memcpy(&bin[2], src->vb_ip.addr.v6.s6_addr, sizeof(src->vb_ip.addr.v6.s6_addr));
		break;
	/*
	 *	Get the raw binary in memory representation
	 */
	case FR_TYPE_NUMERIC:
		fr_value_box_hton(dst, src);	/* Flip any uint32 representations */
		bin = talloc_memdup(ctx, ((uint8_t const *)&dst->datum) + fr_value_box_offsets[src->type],
				    fr_value_box_field_sizes[src->type]);
		break;

	default:
		/* Not the same talloc_memdup call as above.  The above memdup reads data from the dst */
		bin = talloc_memdup(ctx, ((uint8_t const *)&src->datum) + fr_value_box_offsets[src->type],
				    fr_value_box_field_sizes[src->type]);
		break;
	}

	if (!bin) return -1;

	talloc_set_type(bin, uint8_t);
	fr_value_box_memsteal(ctx, dst, dst_enumv, bin, src->tainted);
	dst->type = FR_TYPE_OCTETS;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to an IPv4 address
 *
 * Allowed input types are:
 * - FR_TYPE_IPV6_ADDR (with v4 prefix).
 * - FR_TYPE_IPV4_PREFIX (with 32bit mask).
 * - FR_TYPE_IPV6_PREFIX (with v4 prefix and 128bit mask).
 * - FR_TYPE_OCTETS (of length 4).
 * - FR_TYPE_UINT32
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_ipv4addr(TALLOC_CTX *ctx, fr_value_box_t *dst,
						fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						fr_value_box_t const *src)
{
	if (!fr_cond_assert(dst_type == FR_TYPE_IPV4_ADDR)) return -1;

	switch (src->type) {
	case FR_TYPE_IPV6_ADDR:
		if (memcmp(src->vb_ip.addr.v6.s6_addr, v4_v6_map, sizeof(v4_v6_map)) != 0) {
		bad_v6_prefix_map:
			fr_strerror_printf("Invalid cast from %s to %s.  No IPv4-IPv6 mapping prefix",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
			return -1;
		}

		memcpy(&dst->vb_ip.addr.v4, &src->vb_ip.addr.v6.s6_addr[sizeof(v4_v6_map)],
		       sizeof(dst->vb_ip.addr.v4));

		break;

	case FR_TYPE_IPV4_PREFIX:
		if (src->vb_ip.prefix != 32) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only /32 (not %i/) prefixes may be "
					   "cast to IP address types",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->vb_ip.prefix);
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v4, &src->vb_ip.addr.v4, sizeof(dst->vb_ip.addr.v4));
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (src->vb_ip.prefix != 128) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only /128 (not /%i) prefixes may be "
					   "cast to IP address types",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->vb_ip.prefix);
			return -1;
		}
		if (memcmp(&src->vb_ip.addr.v6.s6_addr, v4_v6_map, sizeof(v4_v6_map)) != 0) goto bad_v6_prefix_map;
		memcpy(&dst->vb_ip.addr.v4, &src->vb_ip.addr.v6.s6_addr[sizeof(v4_v6_map)],
		       sizeof(dst->vb_ip.addr.v4));
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (src->datum.length != sizeof(dst->vb_ip.addr.v4.s_addr)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only %zu uint8 octet strings "
					   "may be cast to IP address types",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v4.s_addr));
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v4, src->vb_octets, sizeof(dst->vb_ip.addr.v4.s_addr));
		break;

	case FR_TYPE_UINT32:
	{
		uint32_t net;

		net = ntohl(src->vb_uint32);
		memcpy(&dst->vb_ip.addr.v4, (uint8_t *)&net, sizeof(dst->vb_ip.addr.v4.s_addr));
	}
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->vb_ip.af = AF_INET;
	dst->vb_ip.prefix = 32;
	dst->vb_ip.scope_id = 0;
	dst->type = FR_TYPE_IPV4_ADDR;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to an IPv6 address
 *
 * Allowed input types are:
 * - FR_TYPE_IPV4_ADDR
 * - FR_TYPE_IPV4_PREFIX (with 32bit mask).
 * - FR_TYPE_IPV6_PREFIX (with 128bit mask).
 * - FR_TYPE_OCTETS (of length 16).
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_ipv4prefix(TALLOC_CTX *ctx, fr_value_box_t *dst,
						  fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						  fr_value_box_t const *src)
{
	if (!fr_cond_assert(dst_type == FR_TYPE_IPV4_PREFIX)) return -1;

	switch (src->type) {
	case FR_TYPE_IPV4_ADDR:
		memcpy(&dst->vb_ip, &src->vb_ip, sizeof(dst->vb_ip));
		break;

	/*
	 *	Copy the last four uint8s, to make an IPv4prefix
	 */
	case FR_TYPE_IPV6_ADDR:
		if (memcmp(src->vb_ip.addr.v6.s6_addr, v4_v6_map, sizeof(v4_v6_map)) != 0) {
		bad_v6_prefix_map:
			fr_strerror_printf("Invalid cast from %s to %s.  No IPv4-IPv6 mapping prefix",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v4.s_addr, &src->vb_ip.addr.v6.s6_addr[sizeof(v4_v6_map)],
		       sizeof(dst->vb_ip.addr.v4.s_addr));
		dst->vb_ip.prefix = 32;
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (memcmp(src->vb_ip.addr.v6.s6_addr, v4_v6_map, sizeof(v4_v6_map)) != 0) goto bad_v6_prefix_map;

		if (src->vb_ip.prefix < (sizeof(v4_v6_map) << 3)) {
			fr_strerror_printf("Invalid cast from %s to %s. Expected prefix >= %u bits got %u bits",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   (unsigned int)(sizeof(v4_v6_map) << 3), src->vb_ip.prefix);
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v4.s_addr, &src->vb_ip.addr.v6.s6_addr[sizeof(v4_v6_map)],
		       sizeof(dst->vb_ip.addr.v4.s_addr));

		/*
		 *	Subtract the bits used by the v4_v6_map to get the v4 prefix bits
		 */
		dst->vb_ip.prefix = src->vb_ip.prefix - (sizeof(v4_v6_map) << 3);
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;


	case FR_TYPE_OCTETS:
		if (src->datum.length != sizeof(dst->vb_ip.addr.v4.s_addr) + 1) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only %zu uint8 octet strings "
					   "may be cast to IP address types",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v4.s_addr) + 1);
			return -1;
		}
		dst->vb_ip.prefix = src->vb_octets[0];
		memcpy(&dst->vb_ip.addr.v4, &src->vb_octets[1], sizeof(dst->vb_ip.addr.v4.s_addr));
		break;

	case FR_TYPE_UINT32:
	{
		uint32_t net;

		net = ntohl(src->vb_uint32);
		memcpy(&dst->vb_ip.addr.v4, (uint8_t *)&net, sizeof(dst->vb_ip.addr.v4.s_addr));
		dst->vb_ip.prefix = 32;
		break;
	}

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->vb_ip.af = AF_INET;
	dst->vb_ip.scope_id = 0;
	dst->type = FR_TYPE_IPV4_PREFIX;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to an IPv6 address
 *
 * Allowed input types are:
 * - FR_TYPE_IPV4_ADDR
 * - FR_TYPE_IPV4_PREFIX (with 32bit mask).
 * - FR_TYPE_IPV6_PREFIX (with 128bit mask).
 * - FR_TYPE_OCTETS (of length 16).
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_ipv6addr(TALLOC_CTX *ctx, fr_value_box_t *dst,
						fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						fr_value_box_t const *src)
{
	if (!fr_cond_assert(dst_type == FR_TYPE_IPV6_ADDR)) return -1;

	static_assert((sizeof(v4_v6_map) + sizeof(src->vb_ip.addr.v4)) <=
		      sizeof(src->vb_ip.addr.v6), "IPv6 storage too small");

	switch (src->type) {
	case FR_TYPE_IPV4_ADDR:
	{
		uint8_t *p = dst->vb_ip.addr.v6.s6_addr;

		/* Add the v4/v6 mapping prefix */
		memcpy(p, v4_v6_map, sizeof(v4_v6_map));
		p += sizeof(v4_v6_map);
		memcpy(p, (uint8_t const *)&src->vb_ip.addr.v4.s_addr, sizeof(src->vb_ip.addr.v4.s_addr));
		dst->vb_ip.scope_id = 0;
	}
		break;

	case FR_TYPE_IPV4_PREFIX:
	{
		uint8_t *p = dst->vb_ip.addr.v6.s6_addr;

		if (src->vb_ip.prefix != 32) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only /32 (not /%i) prefixes may be "
			   		   "cast to IP address types",
			   		   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->vb_ip.prefix);
			return -1;
		}

		/* Add the v4/v6 mapping prefix */
		memcpy(p, v4_v6_map, sizeof(v4_v6_map));
		p += sizeof(v4_v6_map);
		memcpy(p, (uint8_t const *)&src->vb_ip.addr.v4.s_addr, sizeof(src->vb_ip.addr.v4.s_addr));
		dst->vb_ip.scope_id = 0;
	}
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (src->vb_ip.prefix != 128) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only /128 (not /%i) prefixes may be "
			   		   "cast to IP address types",
			   		   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->vb_ip.prefix);
			return -1;
		}
		memcpy(dst->vb_ip.addr.v6.s6_addr, src->vb_ip.addr.v6.s6_addr,
		       sizeof(dst->vb_ip.addr.v6.s6_addr));
		dst->vb_ip.scope_id = src->vb_ip.scope_id;
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (src->datum.length != sizeof(dst->vb_ip.addr.v6.s6_addr)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only %zu uint8 octet strings "
					   "may be cast to IP address types",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v6.s6_addr));
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v6.s6_addr, src->vb_octets, sizeof(dst->vb_ip.addr.v6.s6_addr));
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		break;
	}

	dst->vb_ip.af = AF_INET6;
	dst->vb_ip.prefix = 128;
	dst->type = FR_TYPE_IPV6_ADDR;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to an IPv6 address
 *
 * Allowed input types are:
 * - FR_TYPE_IPV4_ADDR
 * - FR_TYPE_IPV4_PREFIX (with 32bit mask).
 * - FR_TYPE_IPV6_PREFIX (with 128bit mask).
 * - FR_TYPE_OCTETS (of length 16).
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_ipv6prefix(TALLOC_CTX *ctx, fr_value_box_t *dst,
						  fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						  fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_IPV4_ADDR:
	{
		uint8_t *p = dst->vb_ip.addr.v6.s6_addr;

		/* Add the v4/v6 mapping prefix */
		memcpy(p, v4_v6_map, sizeof(v4_v6_map));
		p += sizeof(v4_v6_map);
		memcpy(p, (uint8_t const *)&src->vb_ip.addr.v4.s_addr, sizeof(src->vb_ip.addr.v4.s_addr));
		dst->vb_ip.prefix = 128;
		dst->vb_ip.scope_id = 0;
	}
		break;

	case FR_TYPE_IPV4_PREFIX:
	{
		uint8_t *p = dst->vb_ip.addr.v6.s6_addr;

		/* Add the v4/v6 mapping prefix */
		memcpy(p, v4_v6_map, sizeof(v4_v6_map));
		p += sizeof(v4_v6_map);
		memcpy(p, (uint8_t const *)&src->vb_ip.addr.v4.s_addr, sizeof(src->vb_ip.addr.v4.s_addr));
		dst->vb_ip.prefix = (sizeof(v4_v6_map) << 3) + src->vb_ip.prefix;
		dst->vb_ip.scope_id = 0;
	}
		break;

	case FR_TYPE_IPV6_ADDR:
		memcpy(dst->vb_ip.addr.v6.s6_addr, src->vb_ip.addr.v6.s6_addr,
		       sizeof(dst->vb_ip.addr.v6.s6_addr));
		dst->vb_ip.prefix = 128;
		dst->vb_ip.scope_id = src->vb_ip.scope_id;
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (src->datum.length != (sizeof(dst->vb_ip.addr.v6.s6_addr) + 2)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only %zu uint8 octet strings "
					   "may be cast to IP address types",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v6.s6_addr) + 2);
			return -1;
		}
		dst->vb_ip.scope_id = src->vb_octets[0];
		dst->vb_ip.prefix = src->vb_octets[1];
		memcpy(&dst->vb_ip.addr.v6.s6_addr, src->vb_octets, sizeof(dst->vb_ip.addr.v6.s6_addr));
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->vb_ip.af = AF_INET6;
	dst->type = FR_TYPE_IPV6_PREFIX;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to an ethernet address
 *
 * Allowed input types are:
 * - FR_TYPE_STRING ("00:11:22:33:44:55")
 * - FR_TYPE_OCTETS (0x001122334455)
 *
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_ethernet(TALLOC_CTX *ctx, fr_value_box_t *dst,
						fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src) < 0) return -1;
		break;

	case FR_TYPE_UINT64: {
		uint8_t array[8];

		fr_net_from_uint64(array, src->vb_uint64);

		/*
		 *	For OUIs in the DB.
		 */
		if ((array[0] != 0) || (array[1] != 0)) return -1;

		memcpy(dst->vb_ether, &array[2], 6);
		break;
	}

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->type = FR_TYPE_ETHERNET;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to a bool
 *
 * Allowed input types are:
 * - FR_TYPE_STRING ("yes", "true", "no", "false")
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_bool(TALLOC_CTX *ctx, fr_value_box_t *dst,
					    fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					    fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->type = FR_TYPE_BOOL;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to a uint8
 *
 * Allowed input types are:
 * - FR_TYPE_BOOL
 * - FR_TYPE_INT8 (if positive)
 * - FR_TYPE_STRING
 * - FR_TYPE_OCTETS
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_uint8(TALLOC_CTX *ctx, fr_value_box_t *dst,
					     fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					     fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_BOOL:
		dst->vb_uint8 = (src->vb_bool == true) ? 1 : 0;
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src) < 0) return -1;
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->type = FR_TYPE_UINT8;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to a uint16
 *
 * Allowed input types are:
 * - FR_TYPE_BOOL
 * - FR_TYPE_UINT8
 * - FR_TYPE_STRING
 * - FR_TYPE_OCTETS
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_uint16(TALLOC_CTX *ctx, fr_value_box_t *dst,
					      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					      fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_BOOL:
		dst->vb_uint16 = (src->vb_bool == true) ? 1 : 0;
		break;

	case FR_TYPE_UINT8:
		dst->vb_uint16 = src->vb_uint8;
		break;

	case FR_TYPE_INT8:
		if (src->vb_int8 < 0 ) {
			fr_strerror_printf("Invalid cast: From int8 to uint8.  "
					   "signed value %d is negative ", src->vb_int8);
			return -1;
		}
		dst->vb_uint16 = (uint8_t)src->vb_int8;
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src) < 0) return -1;
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->type = FR_TYPE_UINT16;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to a uint32
 *
 * Allowed input types are:
 * - FR_TYPE_BOOL
 * - FR_TYPE_UINT8
 * - FR_TYPE_UINT16
 * - FR_TYPE_STRING
 * - FR_TYPE_OCTETS
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_uint32(TALLOC_CTX *ctx, fr_value_box_t *dst,
					      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					      fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_BOOL:
		dst->vb_uint32 = (src->vb_bool == true) ? 1 : 0;
		break;

	case FR_TYPE_UINT8:
		dst->vb_uint32 = src->vb_uint8;
		break;

	case FR_TYPE_UINT16:
		dst->vb_uint32 = src->vb_uint16;
		break;

	case FR_TYPE_INT8:
		if (src->vb_int8 < 0 ) {
			fr_strerror_printf("Invalid cast: From int8 to uint8.  "
					   "signed value %d is negative ", src->vb_int8);
			return -1;
		}
		dst->vb_uint32 = (uint8_t)src->vb_int8;
		break;

	case FR_TYPE_INT16:
		if (src->vb_int16 < 0 ) {
			fr_strerror_printf("Invalid cast: From int16 to uint16.  "
					   "signed value %d is negative ", src->vb_int16);
			return -1;
		}
		dst->vb_uint32 = (uint16_t)src->vb_int16;
		break;

	case FR_TYPE_DATE:
		/*
		 *	Dates are represented internally as int64_t
		 *	nanoseconds since the server started.  But we
		 *	note that dates can't be negative.
		 */

		if (!dst->enumv) {
			goto date_seconds;

		} else {
			fr_unix_time_t cast;

			switch (dst->enumv->flags.type_size) {

			date_seconds:
			default:
			case FR_TIME_RES_SEC:
				cast = fr_unix_time_to_sec(src->vb_date);
				if (cast >= ((uint64_t) 1) << 32) {
				invalid_cast:
					fr_strerror_printf("Invalid cast: result cannot fit into uint32");
					return -1;
				}
				dst->vb_uint32 = cast;
				break;

			case FR_TIME_RES_USEC:
				cast = fr_unix_time_to_usec(src->vb_date);
				if (cast >= ((uint64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;

			case FR_TIME_RES_MSEC:
				cast = fr_unix_time_to_msec(src->vb_date);
				if (cast >= ((uint64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;

			case FR_TIME_RES_NSEC:
				cast = src->vb_date;
				if (cast >= ((uint64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;
			}
		}
		break;

	case FR_TYPE_TIME_DELTA:
		if (src->vb_time_delta < 0) goto invalid_cast;

		if (!dst->enumv) {
			goto delta_seconds;

		} else {
			int64_t cast;

			switch (dst->enumv->flags.type_size) {

			delta_seconds:
			default:
			case FR_TIME_RES_SEC:
				cast = fr_time_delta_to_sec(src->vb_time_delta);
				if (cast >= ((int64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;

			case FR_TIME_RES_USEC:
				cast = fr_time_delta_to_usec(src->vb_time_delta);
				if (cast >= ((int64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;

			case FR_TIME_RES_MSEC:
				cast = fr_time_delta_to_msec(src->vb_time_delta);
				if (cast >= ((int64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;

			case FR_TIME_RES_NSEC:
				cast = src->vb_time_delta;
				if (cast >= ((int64_t) 1) << 32) goto invalid_cast;

				dst->vb_uint32 = cast;
				break;
			}
		}
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src) < 0) return -1;
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->type = FR_TYPE_UINT32;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert any supported type to a uint64
 *
 * Allowed input types are:
 * - FR_TYPE_BOOL
 * - FR_TYPE_UINT8
 * - FR_TYPE_UINT16
 * - FR_TYPE_UINT32
 * - FR_TYPE_STRING
 * - FR_TYPE_OCTETS
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_uint64(TALLOC_CTX *ctx, fr_value_box_t *dst,
					      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					      fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_BOOL:
		dst->vb_uint64 = (src->vb_bool == true) ? 1 : 0;
		break;

	case FR_TYPE_UINT8:
		dst->vb_uint64 = src->vb_uint8;
		break;

	case FR_TYPE_UINT16:
		dst->vb_uint64 = src->vb_uint16;
		break;

	case FR_TYPE_UINT32:
		dst->vb_uint64 = src->vb_uint32;
		break;

	case FR_TYPE_INT8:
		if (src->vb_int8 < 0 ) {
			fr_strerror_printf("Invalid cast: From int8 to uint8.  "
					   "signed value %d is negative ", src->vb_int8);
			return -1;
		}
		dst->vb_uint64 = (uint8_t)src->vb_int8;
		break;

	case FR_TYPE_INT16:
		if (src->vb_int16 < 0 ) {
			fr_strerror_printf("Invalid cast: From int16 to uint16.  "
					   "signed value %d is negative ", src->vb_int16);
			return -1;
		}
		dst->vb_uint64 = (uint16_t)src->vb_int16;
		break;

	case FR_TYPE_INT32:
		if (src->vb_int32 < 0 ) {
			fr_strerror_printf("Invalid cast: From int32 to uint32.  "
					   "signed value %d is negative ", src->vb_int32);
			return -1;
		}
		dst->vb_uint64 = (uint32_t)src->vb_int32;
		break;

	case FR_TYPE_DATE:
		if (!dst->enumv) {
			goto date_seconds;

		} else switch (dst->enumv->flags.type_size) {
		date_seconds:
		default:
		case FR_TIME_RES_SEC:
			dst->vb_uint64 = fr_unix_time_to_sec(src->vb_date);
			break;

		case FR_TIME_RES_USEC:
			dst->vb_uint64 = fr_unix_time_to_usec(src->vb_date);
			break;

		case FR_TIME_RES_MSEC:
			dst->vb_uint64 = fr_unix_time_to_msec(src->vb_date);
			break;

		case FR_TIME_RES_NSEC:
			dst->vb_uint64 = src->vb_date;
			break;
		}
		break;

	case FR_TYPE_TIME_DELTA:
		/*
		 *	uint64 can't hold all of int64
		 */
		if (src->vb_time_delta < 0) {
			fr_strerror_printf("Invalid cast: result cannot fit into uint64");
			return -1;
		}

		if (!dst->enumv) {
			goto delta_seconds;

		} else switch (dst->enumv->flags.type_size) {
		delta_seconds:
		default:
		case FR_TIME_RES_SEC:
			dst->vb_uint64 = fr_time_delta_to_sec(src->vb_time_delta);
			break;

		case FR_TIME_RES_USEC:
			dst->vb_uint64 = fr_time_delta_to_usec(src->vb_time_delta);
			break;

		case FR_TIME_RES_MSEC:
			dst->vb_uint64 = fr_time_delta_to_msec(src->vb_time_delta);
			break;

		case FR_TIME_RES_NSEC:
			dst->vb_uint64 = src->vb_time_delta;
			break;
		}
		break;

	case FR_TYPE_STRING:
		if (fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				          src->vb_strvalue, src->datum.length, '\0', src->tainted) < 0) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src) < 0) return -1;
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	dst->type = FR_TYPE_UINT64;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert one type of fr_value_box_t to another
 *
 * This should be the canonical function used to convert between INTERNAL data formats.
 *
 * If you want to convert from PRESENTATION format, use #fr_value_box_from_str.
 *
 * @note src and dst must not be the same box.  We do not support casting in place.
 *
 * @param ctx		to allocate buffers in (usually the same as dst)
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	Aliases for values contained within this fr_value_box_t.
 *			If #fr_value_box_t is passed to #fr_value_box_asprint
 *			names will be printed instead of actual value.
 * @param src		Input data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_cast(TALLOC_CTX *ctx, fr_value_box_t *dst,
		      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
		      fr_value_box_t const *src)
{
	if (!fr_cond_assert(dst_type != FR_TYPE_INVALID)) return -1;
	if (!fr_cond_assert(src->type != FR_TYPE_INVALID)) return -1;
	if (!fr_cond_assert(src != dst)) return -1;

	if (fr_dict_non_data_types[dst_type]) {
		fr_strerror_printf("Invalid cast from %s to %s.  Can only cast simple data types.",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	/*
	 *	If it's the same type, copy, but set the enumv
	 *	in the destination box to be the one provided.
	 *
	 *	The theory here is that the attribute value isn't
	 *	being converted into its presentation format and
	 *	re-parsed, and the enumv names only get applied
	 *	when converting internal values to/from strings,
	 *	so it's OK just to swap out the enumv.
	 *
	 *	If there's a compelling case in the future we
	 *	might revisit this, but it'd likely mean fixing
	 *	all the casting functions to treat any value
	 *	with an enumv as a string, which seems weird.
	 */
	if (dst_type == src->type) {
		int ret;

		ret = fr_value_box_copy(ctx, dst, src);
		if (ret < 0) return ret;

		dst->enumv = dst_enumv;

		return ret;
	}

	/*
	 *	Initialise dst
	 */
	memset(dst, 0, sizeof(*dst));

	/*
	 *	Dispatch to specialised cast functions
	 */
	switch (dst_type) {
	case FR_TYPE_STRING:
		return fr_value_box_cast_to_strvalue(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_OCTETS:
		return fr_value_box_cast_to_octets(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_IPV4_ADDR:
		return fr_value_box_cast_to_ipv4addr(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_IPV4_PREFIX:
		return fr_value_box_cast_to_ipv4prefix(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_IPV6_ADDR:
		return fr_value_box_cast_to_ipv6addr(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_IPV6_PREFIX:
		return fr_value_box_cast_to_ipv6prefix(ctx, dst, dst_type, dst_enumv, src);

	/*
	 *	Need func
	 */
	case FR_TYPE_IFID:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
		break;

	case FR_TYPE_ETHERNET:
		return fr_value_box_cast_to_ethernet(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_BOOL:
		return fr_value_box_cast_to_bool(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_UINT8:
		return fr_value_box_cast_to_uint8(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_UINT16:
		return fr_value_box_cast_to_uint16(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_UINT32:
		return fr_value_box_cast_to_uint32(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_UINT64:
		return fr_value_box_cast_to_uint64(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_DATE:
	case FR_TYPE_SIZE:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_ABINARY:
		break;

	/*
	 *	Invalid types for casting (should have been caught earlier)
	 */
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_STRUCTURAL:
	case FR_TYPE_INVALID:
	case FR_TYPE_MAX:
	invalid_cast:
		fr_strerror_printf("Invalid cast from %s to %s",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Deserialise a fr_value_box_t
	 */
	if (src->type == FR_TYPE_STRING) return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
								      src->vb_strvalue,
								      src->datum.length, '\0', src->tainted);

	if ((src->type == FR_TYPE_IFID) &&
	    (dst_type == FR_TYPE_UINT64)) {
		dst->vb_uint64 = fr_net_to_uint64(&src->vb_ifid[0]);

	fixed_length:
		dst->type = dst_type;
		dst->enumv = dst_enumv;

		return 0;
	}

	/*
	 *	We can cast uint32s less that < INT_MAX to signed
	 */
	if (dst_type == FR_TYPE_INT32) {
		switch (src->type) {
		case FR_TYPE_UINT8:
			dst->vb_int32 = src->vb_uint8;
			break;

		case FR_TYPE_UINT16:
			dst->vb_int32 = src->vb_uint16;
			break;

		case FR_TYPE_UINT32:
			if (src->vb_uint32 > INT_MAX) {
				fr_strerror_printf("Invalid cast: From uint32 to signed.  uint32 value %u is larger "
						   "than max signed int and would overflow", src->vb_uint32);
				return -1;
			}
			dst->vb_int32 = (int)src->vb_uint32;
			break;

		case FR_TYPE_UINT64:
			if (src->vb_uint32 > INT_MAX) {
				fr_strerror_printf("Invalid cast: From uint64 to signed.  uint64 value %" PRIu64
						   " is larger than max signed int and would overflow", src->vb_uint64);
				return -1;
			}
			dst->vb_int32 = (int)src->vb_uint64;
			break;

		case FR_TYPE_OCTETS:
			goto do_octets;

		default:
			goto invalid_cast;
		}
		goto fixed_length;
	}

	if (dst_type == FR_TYPE_TIME_DELTA) {
		switch (src->type) {
		case FR_TYPE_UINT8:
			dst->datum.time_delta = src->vb_uint8;
			break;

		case FR_TYPE_UINT16:
			dst->datum.time_delta = src->vb_uint16;
			break;

		case FR_TYPE_UINT32:
			dst->datum.time_delta = src->vb_uint32;
			break;

		case FR_TYPE_UINT64:
			dst->datum.time_delta = src->vb_uint64;
			break;

		default:
			goto invalid_cast;
		}
	}

	if (src->type == FR_TYPE_OCTETS) {
		fr_value_box_t tmp;

	do_octets:
		if (src->datum.length < fr_value_box_network_sizes[dst_type][0]) {
			fr_strerror_printf("Invalid cast from %s to %s.  Source is length %zd is smaller than "
					   "destination type size %zd",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->datum.length,
					   fr_value_box_network_sizes[dst_type][0]);
			return -1;
		}

		if (src->datum.length > fr_value_box_network_sizes[dst_type][1]) {
			fr_strerror_printf("Invalid cast from %s to %s.  Source length %zd is greater than "
					   "destination type size %zd",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->datum.length,
					   fr_value_box_network_sizes[dst_type][1]);
			return -1;
		}

		memset(&tmp, 0, sizeof(tmp));

		/*
		 *	Copy the raw octets into the datum of a value_box
		 *	inverting bytesex for uint32s (if LE).
		 */
		memcpy(&tmp.datum, src->vb_octets, fr_value_box_field_sizes[dst_type]);
		tmp.type = dst_type;
		dst->enumv = dst_enumv;

		fr_value_box_hton(dst, &tmp);

		/*
		 *	Fixup IP addresses.
		 */
		switch (dst->type) {
		case FR_TYPE_IPV4_ADDR:
			dst->vb_ip.af = AF_INET;
			dst->vb_ip.prefix = 128;
			dst->vb_ip.scope_id = 0;
			break;

		case FR_TYPE_IPV6_ADDR:
			dst->vb_ip.af = AF_INET6;
			dst->vb_ip.prefix = 128;
			dst->vb_ip.scope_id = 0;
			break;

		default:
			break;
		}

		return 0;
	}

	if ((src->type == FR_TYPE_IPV4_ADDR) &&
		   ((dst_type == FR_TYPE_UINT32) ||
		    (dst_type == FR_TYPE_DATE) ||
		    (dst_type == FR_TYPE_TIME_DELTA) ||
		    (dst_type == FR_TYPE_INT32))) {
		dst->vb_uint32 = htonl(src->vb_ip.addr.v4.s_addr);

	} else {		/* they're of the same uint8 order */
		memcpy(&dst->datum, &src->datum, fr_value_box_field_sizes[src->type]);
	}

	dst->type = dst_type;
	dst->enumv = dst_enumv;

	return 0;
}

/** Convert one type of fr_value_box_t to another in place
 *
 * This should be the canonical function used to convert between INTERNAL data formats.
 *
 * If you want to convert from PRESENTATION format, use #fr_value_box_from_str.
 *
 * @param ctx		to allocate buffers in (usually the same as dst)
 * @param vb		to cast.
 * @param dst_type	to cast to.
 * @param dst_enumv	Aliases for values contained within this fr_value_box_t.
 *			If #fr_value_box_t is passed to #fr_value_box_asprint
 *			names will be printed instead of actual value.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_cast_in_place(TALLOC_CTX *ctx, fr_value_box_t *vb,
			       fr_type_t dst_type, fr_dict_attr_t const *dst_enumv)
{
	fr_value_box_t tmp;

	/*
	 *	Simple case, destination type and current
	 *	type are the same.
	 */
	if (vb->type == dst_type) {
		vb->enumv = dst_enumv;	/* Update the enumv as this may be different */
		return 0;
	}

	/*
	 *	Copy meta data and any existing buffers to
	 *	a temporary box.  We then clear that value
	 *	box after the cast has been completed,
	 *	freeing any old buffers.
	 */
	fr_value_box_copy_shallow(ctx, &tmp, vb, false);

	if (fr_value_box_cast(vb, vb, dst_type, dst_enumv, &tmp) < 0) return -1;

	fr_value_box_clear(&tmp);	/* Clear out any old buffers */

	return 0;
}

/** Assign a #fr_value_box_t value from an #fr_ipaddr_t
 *
 * Automatically determines the type of the value box from the ipaddr address family
 * and the length of the prefix field.
 *
 * @param[in] dst	to assign ipaddr to.
 * @param[in] enumv	Aliases for values.
 * @param[in] ipaddr	to copy address from.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_ipaddr(fr_value_box_t *dst, fr_dict_attr_t const *enumv, fr_ipaddr_t const *ipaddr, bool tainted)
{
	fr_type_t type;

	switch (ipaddr->af) {
	case AF_INET:
		type = (fr_ipaddr_is_prefix(ipaddr) == 1) ? FR_TYPE_IPV4_PREFIX : FR_TYPE_IPV4_ADDR;
		break;

	case AF_INET6:
		type = (fr_ipaddr_is_prefix(ipaddr) == 1) ? FR_TYPE_IPV6_PREFIX : FR_TYPE_IPV6_ADDR;
		break;

	default:
		fr_strerror_printf("Invalid address family %i", ipaddr->af);
		return -1;
	}

	fr_value_box_init(dst, type, enumv, tainted);
	memcpy(&dst->vb_ip, ipaddr, sizeof(dst->vb_ip));

	return 0;
}

/** Unbox an IP address performing a type check
 *
 * @param[out] dst	Where to copy the IP address to.
 * @param[in] src	Where to copy the IP address from.
 * @return
 *	- 0 on success.
 *	- -1 on type mismatch.
 */
int fr_value_unbox_ipaddr(fr_ipaddr_t *dst, fr_value_box_t *src)
{
	switch (src->type) {
	case FR_TYPE_IP:
		break;

	default:
		fr_strerror_printf("Unboxing failed.  Needed IPv4/6 addr/prefix, had type %s",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "?Unknown?"));
		return -1;
	}

	memcpy(dst, &src->vb_ip, sizeof(*dst));

	return 0;
}

/** Copy value data verbatim duplicating any buffers
 *
 * @note Will free any exiting buffers associated with the dst #fr_value_box_t.
 *
 * @param ctx To allocate buffers in.
 * @param dst Where to copy value_box to.
 * @param src Where to copy value_box from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_copy(TALLOC_CTX *ctx, fr_value_box_t *dst, const fr_value_box_t *src)
{
	if (!fr_cond_assert(src->type != FR_TYPE_INVALID)) return -1;

	switch (src->type) {
	default:
		memcpy(((uint8_t *)dst) + fr_value_box_offsets[src->type],
		       ((uint8_t const *)src) + fr_value_box_offsets[src->type],
		       fr_value_box_field_sizes[src->type]);
		break;

	case FR_TYPE_STRING:
	{
		char *str = NULL;

		/*
		 *	Zero length strings still have a one uint8 buffer
		 */
		str = talloc_bstrndup(ctx, src->vb_strvalue, src->datum.length);
		if (!str) {
			fr_strerror_printf("Failed allocating string buffer");
			return -1;
		}
		dst->vb_strvalue = str;
	}
		break;

	case FR_TYPE_OCTETS:
	{
		uint8_t *bin = NULL;

		if (src->datum.length) {
			bin = talloc_memdup(ctx, src->vb_octets, src->datum.length);
			if (!bin) {
				fr_strerror_printf("Failed allocating octets buffer");
				return -1;
			}
			talloc_set_type(bin, uint8_t);
		}
		dst->vb_octets = bin;
	}
		break;
	}

	fr_value_box_copy_meta(dst, src);

	return 0;
}

/** Perform a shallow copy of a value_box
 *
 * Like #fr_value_box_copy, but does not duplicate the buffers of the src value_box.
 *
 * For #FR_TYPE_STRING and #FR_TYPE_OCTETS adds a reference from ctx so that the
 * buffer cannot be freed until the ctx is freed.
 *
 * @param[in] ctx	to add reference from.  If NULL no reference will be added.
 * @param[in] dst	to copy value to.
 * @param[in] src	to copy value from.
 * @param[in] incr_ref	Increment the reference count on the src buffer.
 *			Only do this if you KNOW the src box/buffer was allocated by
 *			this thread and will only ever be used by this thread.
 */
void fr_value_box_copy_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *src, bool incr_ref)
{
	switch (src->type) {
	default:
		fr_value_box_copy(ctx, dst, src);
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		dst->datum.ptr = ctx && incr_ref ? talloc_reference(ctx, src->datum.ptr) : src->datum.ptr;
		fr_value_box_copy_meta(dst, src);
		break;
	}
}

/** Copy value data verbatim moving any buffers to the specified context
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst	to copy value to.
 * @param[in] src	to copy value from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_steal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *src)
{
	if (!fr_cond_assert(src->type != FR_TYPE_INVALID)) return -1;

	switch (src->type) {
	default:
		return fr_value_box_copy(ctx, dst, src);

	case FR_TYPE_STRING:
	{
		char const *str;

		str = talloc_steal(ctx, src->vb_strvalue);
		if (!str) {
			fr_strerror_printf("Failed stealing string buffer");
			return -1;
		}
		dst->vb_strvalue = str;
		fr_value_box_copy_meta(dst, src);
	}
		return 0;

	case FR_TYPE_OCTETS:
	{
		uint8_t const *bin;

 		bin = talloc_steal(ctx, src->vb_octets);
		if (!bin) {
			fr_strerror_printf("Failed stealing octets buffer");
			return -1;
		}
		dst->vb_octets = bin;
		fr_value_box_copy_meta(dst, src);
	}
		return 0;
	}
}

/** Print a formatted string using our internal printf wrapper and assign it to a value box
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] fmt	The printf format string to process.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @param[in] ap	Substitution arguments.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_vasprintf(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv, bool tainted,
			   char const *fmt, va_list ap)
{
	va_list aq;
	char *str;

	va_copy(aq, ap);	/* See vlog_module_failure_msg for why */
	str = fr_vasprintf(ctx, fmt, aq);
	va_end(aq);

	if (!str) return -1;

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = str;
	dst->datum.length = talloc_array_length(str) - 1;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Print a formatted string using our internal printf wrapper and assign it to a value box
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @param[in] fmt	The printf format string to process.
 * @param[in] ...	Substitution arguments.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_asprintf(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv, bool tainted,
			  char const *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = fr_value_box_vasprintf(ctx, dst, enumv, tainted, fmt, ap);
	va_end(ap);

	return ret;
}

/** Copy a nul terminated string to a #fr_value_box_t
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
int fr_value_box_strdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			char const *src, bool tainted)
{
	char const	*str;

	str = talloc_typed_strdup(ctx, src);
	if (!str) {
		fr_strerror_printf("Failed allocating string buffer");
		return -1;
	}

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = str;
	dst->datum.length = talloc_array_length(str) - 1;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Copy a string to to a #fr_value_box_t
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a string.
 * @param[in] len	of src.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
int fr_value_box_bstrndup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			  char const *src, size_t len, bool tainted)
{
	char const	*str;

	str = talloc_bstrndup(ctx, src, len);
	if (!str) {
		fr_strerror_printf("Failed allocating string buffer");
		return -1;
	}

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = str;
	dst->datum.length = len;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Assign a string to to a #fr_value_box_t
 *
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a string.
 * @param[in] len	of src.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
void fr_value_box_bstrndup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				   char const *src, size_t len, bool tainted)
{
	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = src;
	dst->datum.length = len;
	dst->enumv = enumv;
	dst->next = NULL;
}

/** Copy a nul terminated talloced buffer to a #fr_value_box_t
 *
 * Copy a talloced nul terminated buffer, setting fields in the dst value box appropriately.
 *
 * The buffer must be \0 terminated, or an error will be returned.
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a talloced nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_strdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			       char const *src, bool tainted)
{
	char	*str;
	size_t	len;

	len = talloc_array_length(src);
	if ((len == 1) || (src[len - 1] != '\0')) {
		fr_strerror_printf("Input buffer not \\0 terminated");
		return -1;
	}

	str = talloc_bstrndup(ctx, src, len - 1);
	if (!str) {
		fr_strerror_printf("Failed allocating string buffer");
		return -1;
	}

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = str;
	dst->datum.length = talloc_array_length(str) - 1;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Steal a nul terminated talloced buffer into a specified ctx, and assign to a #fr_value_box_t
 *
 * Steal a talloced nul terminated buffer, setting fields in the dst value box appropriately.
 *
 * The buffer must be \0 terminated, or an error will be returned.
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a talloced nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_bstrsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			  char *src, bool tainted)
{
	size_t	len;
	char	*str;

	len = talloc_array_length(src);
	if ((len == 0) || (src[len - 1] != '\0')) {
		fr_strerror_printf("Input buffer empty or not \\0 terminated");
		return -1;
	}

	str = talloc_steal(ctx, src);
	if (!str) {
		fr_strerror_printf("Failed stealing string buffer");
		return -1;
	}

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = str;
	dst->datum.length = len - 1;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Steal a talloced string buffer into a specified ctx, reallocing if necessary
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a talloced buffer.
 * @param[in] inlen	length of data in the buffer.  Buffer will be realloced if necessary.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_bstrsnteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			    char **src, size_t inlen, bool tainted)
{
	size_t	len;
	char	*str;

	str = talloc_steal(ctx, *src);
	if (!str) {
		fr_strerror_printf("Failed stealing string buffer");
		return -1;
	}

	len = talloc_array_length(*src);
	if (len != (inlen + 1)) {	/* +1 for \0 */
		str = talloc_realloc_size(ctx, *src, inlen + 1);
		if (!str) {
			fr_strerror_printf("Failed reallocing string buffer");
			return -1;
		}
		str[inlen] = '\0';
		*src = str;
	}

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = str;
	dst->datum.length = inlen;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Append a buffer to an existing fr_value_box_t
 *
 * @param[in] dst	value box to append to.
 * @param[in] src	octets data to append.
 * @param[in] len	length of octets data.
 * @param[in] tainted	Whether src is tainted.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_value_box_append_bstr(fr_value_box_t *dst, char const *src, size_t len, bool tainted)
{
	char *ptr, *nptr;
	size_t nlen;

	if (len == 0) return 0;

	if (dst->type != FR_TYPE_STRING) {
		fr_strerror_printf("%s: Expected boxed value of type %s, got type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_STRING, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
		return -1;
	}

	memcpy(&ptr, &dst->datum.ptr, sizeof(ptr));	/* defeat const */
	if (!fr_cond_assert(ptr)) return -1;

	if (talloc_reference_count(ptr) > 0) {
		fr_strerror_printf("%s: Boxed value has two many references", __FUNCTION__);
		return -1;
	}

	nlen = dst->vb_length + len + 1;
	nptr = talloc_realloc(talloc_parent(ptr), ptr, char, dst->vb_length + len + 1);
	if (!nptr) {
		fr_strerror_printf("%s: Realloc of %s array from %zu to %zu bytes failed",
				   __FUNCTION__, talloc_get_name(ptr), talloc_array_length(ptr), nlen);
		return -1;
	}
	ptr = nptr;

	memcpy(ptr + dst->vb_length, src, len);	/* Copy data into the realloced buffer */

	dst->tainted = tainted;
	dst->datum.ptr = ptr;
	dst->vb_length += len;

	ptr[dst->vb_length] = '\0';

	return 0;
}

/** Assign a buffer containing a nul terminated string to a box, but don't copy it
 *
 * @param[in] dst	to assign string to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	to copy string to.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
void fr_value_box_strdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				 char const *src, bool tainted)
{
	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = src;
	dst->datum.length = strlen(src);
	dst->enumv = enumv;
	dst->next = NULL;
}

/** Assign a talloced buffer containing a nul terminated string to a box, but don't copy it
 *
 * Adds a reference to the src buffer so that it cannot be freed until the ctx is freed.
 *
 * @param[in] ctx	to add reference from.  If NULL no reference will be added.
 * @param[in] dst	to assign string to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	to copy string to.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_strdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				       char const *src, bool tainted)
{
	size_t	len;

	(void) talloc_get_type_abort_const(src, char);

	len = talloc_array_length(src);
	if ((len == 0) || (src[len - 1] != '\0')) {
		fr_strerror_printf("Input buffer not \\0 terminated");
		return -1;
	}

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->vb_strvalue = ctx ? talloc_reference(ctx, src) : src;
	dst->datum.length = len - 1;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Copy a buffer to a fr_value_box_t
 *
 * Copy a buffer containing binary data, setting fields in the dst value box appropriately.
 *
 * @param[in] ctx	to allocate any new buffers in.
 * @param[in] dst	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	a buffer.
 * @param[in] len	of data in the buffer. If 0, a zero length
 *			talloc buffer will be alloced. dst->vb_octets
 *			will *NOT* be NULL.  You should use the length
 *			field of the box to determine if any value
 *      		is assigned.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_memcpy(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			uint8_t const *src, size_t len, bool tainted)
{
	uint8_t *bin;

	bin = talloc_memdup(ctx, src, len);
	if (!bin) {
		fr_strerror_printf("Failed allocating octets buffer");
		return -1;
	}
	talloc_set_type(bin, uint8_t);

	dst->type = FR_TYPE_OCTETS;
	dst->tainted = tainted;
	dst->vb_octets = bin;
	dst->datum.length = len;
	dst->enumv = enumv;
	dst->next = NULL;

	return 0;
}

/** Append a buffer to an existing fr_value_box_t
 *
 * @param[in] dst	value box to append to.
 * @param[in] src	octets data to append.
 * @param[in] len	length of octets data.
 * @param[in] tainted	Whether src is tainted.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_value_box_append_mem(fr_value_box_t *dst, uint8_t const *src, size_t len, bool tainted)
{
	uint8_t *ptr, *nptr;
	size_t nlen;

	if (len == 0) return 0;

	if (dst->type != FR_TYPE_OCTETS) {
		fr_strerror_printf("%s: Expected boxed value of type %s, got type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_OCTETS, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
		return -1;
	}

	memcpy(&ptr, &dst->datum.ptr, sizeof(ptr));	/* defeat const */
	if (!fr_cond_assert(ptr)) return -1;

	if (talloc_reference_count(ptr) > 0) {
		fr_strerror_printf("%s: Boxed value has two many references", __FUNCTION__);
		return -1;
	}

	nlen = dst->vb_length + len;
	nptr = talloc_realloc(talloc_parent(ptr), ptr, uint8_t, dst->vb_length + len);
	if (!nptr) {
		fr_strerror_printf("%s: Realloc of %s array from %zu to %zu bytes failed",
				   __FUNCTION__, talloc_get_name(ptr), talloc_array_length(ptr), nlen);
		return -1;
	}
	ptr = nptr;

	memcpy(ptr + dst->vb_length, src, len);	/* Copy data into the realloced buffer */

	dst->tainted = tainted;
	dst->datum.ptr = ptr;
	dst->vb_length += len;

	return 0;
}

/** Copy a talloced buffer to a fr_value_box_t
 *
 * Copy a buffer containing binary data, setting fields in the dst value box appropriately.
 *
 * @param[in] ctx	to allocate any new buffers in.
 * @param[in] dst	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	a buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_memcpy_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			       uint8_t *src, bool tainted)
{
	(void) talloc_get_type_abort(src, uint8_t);

	return fr_value_box_memcpy(ctx, dst, enumv, src, talloc_array_length(src), tainted);
}

/** Steal a talloced buffer into a specified ctx, and assign to a #fr_value_box_t
 *
 * Steal a talloced buffer, setting fields in the dst value box appropriately.
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a talloced nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
void fr_value_box_memsteal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			   uint8_t const *src, bool tainted)
{
	(void) talloc_get_type_abort_const(src, uint8_t);

	(void) talloc_steal(ctx, src);	/* steal can never fail according to talloc docs */

	dst->type = FR_TYPE_OCTETS;
	dst->tainted = tainted;
	dst->vb_octets = src;
	dst->datum.length = talloc_array_length(src);
	dst->enumv = enumv;
	dst->next = NULL;
}

/** Assign a buffer to a box, but don't copy it
 *
 * Adds a reference to the src buffer so that it cannot be freed until the ctx is freed.
 *
 * Caller should set dst->taint = true, where the value was acquired from an untrusted source.
 *
 * @note Will free any exiting buffers associated with the value box.
 *
 * @param[in] dst 	to assign buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	a talloced buffer.
 * @param[in] len	of buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
void fr_value_box_memcpy_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				 uint8_t *src, size_t len, bool tainted)
{
	dst->type = FR_TYPE_OCTETS;
	dst->tainted = tainted;
	dst->vb_octets = src;
	dst->datum.length = len;
	dst->enumv = enumv;
	dst->next = NULL;
}

/** Assign a talloced buffer to a box, but don't copy it
 *
 * Adds a reference to the src buffer so that it cannot be freed until the ctx is freed.
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	a talloced buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
void fr_value_box_memcpy_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				        uint8_t *src, bool tainted)
{
	(void) talloc_get_type_abort(src, uint8_t);

	dst->type = FR_TYPE_OCTETS;
	dst->tainted = tainted;
	dst->vb_octets = ctx ? talloc_reference(ctx, src) : src;
	dst->datum.length = talloc_array_length(src);
	dst->enumv = enumv;
	dst->next = NULL;
}

/** Increment a boxed value
 *
 * Implements safe integer overflow.
 *
 * @param[in] vb	to increment.
 */
void fr_value_box_increment(fr_value_box_t *vb)
{
	switch (vb->type) {
	case FR_TYPE_UINT8:
		vb->vb_uint8 = vb->vb_uint8 == UINT8_MAX ? 0 : vb->vb_uint8 + 1;
		return;

	case FR_TYPE_UINT16:
		vb->vb_uint16 = vb->vb_uint16 == UINT16_MAX ? 0 : vb->vb_uint16 + 1;
		return;

	case FR_TYPE_UINT32:
		vb->vb_uint32 = vb->vb_uint32 == UINT32_MAX ? 0 : vb->vb_uint32 + 1;
		return;

	case FR_TYPE_UINT64:
		vb->vb_uint64 = vb->vb_uint64 == UINT64_MAX ? 0 : vb->vb_uint64 + 1;
		return;

	case FR_TYPE_INT8:
		vb->vb_int8 = vb->vb_int8 == INT8_MAX ? INT8_MIN : vb->vb_int8 + 1;
		return;

	case FR_TYPE_INT16:
		vb->vb_int16 = vb->vb_int16 == INT16_MAX ? INT16_MIN : vb->vb_int16 + 1;
		return;

	case FR_TYPE_INT32:
		vb->vb_int32 = vb->vb_int32 == INT32_MAX ? INT32_MIN : vb->vb_int32 + 1;
		return;

	case FR_TYPE_INT64:
		vb->vb_int64 = vb->vb_int64 == INT64_MAX ? INT64_MIN : vb->vb_int64 + 1;
		return;

	default:
		return;
	}
}

/** Convert integer encoded as string to a fr_value_box_t type
 *
 * @param[out] dst		where to write parsed value.
 * @param[in] dst_type		type of integer to convert string to.
 * @param[in] in		String to convert to integer.
 * @return
 *	- 0 on success.
 *	- -1 on parse error.
 */
static int fr_value_box_from_integer_str(fr_value_box_t *dst, fr_type_t dst_type, char const *in)
{
	uint64_t	uinteger = 0;
	int64_t		sinteger = 0;
	char 		*p = NULL;

	switch (dst_type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
		fr_skip_whitespace(in);

		if (*in == '-') {
			fr_strerror_printf("Invalid negative value \"%s\" for unsigned integer", in);
			return -1;
		}

		/*
		 *	fr_strtoull checks for overflows and calls
		 *	fr_strerror_printf to set an error.
		 */
		if (fr_strtoull(&uinteger, &p, in) < 0) return -1;
		if (*p != '\0') {
			fr_strerror_printf("Invalid integer value \"%s\"", in);

			return -1;
		}
		if (errno == ERANGE) {


			return -1;
		}
		break;

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
		/*
		 *	fr_strtoll checks for overflows and calls
		 *	fr_strerror_printf to set an error.
		 */
		if (fr_strtoll(&sinteger, &p, in) < 0) return -1;
		if (*p != '\0') {
			fr_strerror_printf("Invalid integer value \"%s\"", in);

			return -1;
		}
		break;

	default:
		fr_assert_fail(NULL);
		return -1;
	}

#define IN_RANGE_UNSIGNED(_type) \
	do { \
		if (uinteger > _type ## _MAX) { \
			fr_strerror_printf("Value %" PRIu64 " is invalid for type %s (must be in range " \
					   "0...%" PRIu64 ")",		\
					   uinteger, fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"), \
					   (uint64_t) _type ## _MAX); \
			return -1; \
		} \
	} while (0)

#define IN_RANGE_SIGNED(_type) \
	do { \
		if ((sinteger > _type ## _MAX) || (sinteger < _type ## _MIN)) { \
			fr_strerror_printf("Value %" PRId64 " is invalid for type %s (must be in range " \
					   "%" PRId64 "...%" PRId64 ")", \
					   sinteger, fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"), \
					   (int64_t) _type ## _MIN, (int64_t) _type ## _MAX); \
			return -1; \
		} \
	} while (0)

	switch (dst_type) {
	case FR_TYPE_UINT8:
		IN_RANGE_UNSIGNED(UINT8);
		dst->vb_uint8 = (uint8_t)uinteger;
		break;

	case FR_TYPE_UINT16:
		IN_RANGE_UNSIGNED(UINT16);
		dst->vb_uint16 = (uint16_t)uinteger;
		break;

	case FR_TYPE_UINT32:
		IN_RANGE_UNSIGNED(UINT32);
		dst->vb_uint32 = (uint32_t)uinteger;
		break;

	case FR_TYPE_UINT64:
		/* IN_RANGE_UNSIGNED doesn't work here */
		dst->vb_uint64 = (uint64_t)uinteger;
		break;

	case FR_TYPE_INT8:
		IN_RANGE_SIGNED(INT8);
		dst->vb_int8 = (int8_t)sinteger;
		break;

	case FR_TYPE_INT16:
		IN_RANGE_SIGNED(INT16);
		dst->vb_int16 = (int16_t)sinteger;
		break;

	case FR_TYPE_INT32:
		IN_RANGE_SIGNED(INT32);
		dst->vb_int32 = (int32_t)sinteger;
		break;

	case FR_TYPE_INT64:
		/* IN_RANGE_SIGNED doesn't work here */
		dst->vb_int64 = (int64_t)sinteger;
		break;

	default:
		fr_assert_fail(NULL);
		return -1;
	}

	return 0;
}

/** Convert string value to a fr_value_box_t type
 *
 * @param[in] ctx		to alloc strings in.
 * @param[out] dst		where to write parsed value.
 * @param[in,out] dst_type	of value data to create/dst_type of value created.
 * @param[in] dst_enumv		fr_dict_attr_t with string names for uint32 values.
 * @param[in] in		String to convert. Binary safe for variable length values
 *				if len is provided.
 * @param[in] inlen		may be < 0 in which case strlen(len) is used to determine
 *				length, else inlen should be the length of the string or
 *				sub string to parse.
 * @param[in] quote		character used set unescape mode.  @see fr_value_str_unescape.
 * @param[in] tainted		Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on parse error.
 */
int fr_value_box_from_str(TALLOC_CTX *ctx, fr_value_box_t *dst,
			  fr_type_t *dst_type, fr_dict_attr_t const *dst_enumv,
			  char const *in, ssize_t inlen, char quote, bool tainted)
{
	size_t		len;
	ssize_t		ret;
	char		buffer[256];

	if (!fr_cond_assert(*dst_type != FR_TYPE_INVALID)) return -1;

	if (!in) return -1;

	len = (inlen < 0) ? strlen(in) : (size_t)inlen;

	/*
	 *	Set size for all fixed length attributes.
	 */
	ret = dict_attr_sizes[*dst_type][1];	/* Max length */

	/*
	 *	Lookup any names before continuing
	 */
	if (dst_enumv) {
		char		*tmp = NULL;
		char		*name;
		size_t		name_len;
		fr_dict_enum_t	*enumv;

		if (len > (sizeof(buffer) - 1)) {
			tmp = talloc_array(NULL, char, len + 1);
			if (!tmp) return -1;

			name_len = fr_value_str_unescape((uint8_t *)tmp, in, len, quote);
			name = tmp;
		} else {
			name_len = fr_value_str_unescape((uint8_t *)buffer, in, len, quote);
			name = buffer;
		}
		name[name_len] = '\0';

		/*
		 *	Check the name name is valid first before bothering
		 *	to look it up.
		 *
		 *	Catches any embedded \0 bytes that might cause
		 *	incorrect results.
		 */
		if (fr_dict_valid_name(name, name_len) <= 0) {
			if (tmp) talloc_free(tmp);
			goto parse;
		}

		enumv = fr_dict_enum_by_name(dst_enumv, name, name_len);
		if (tmp) talloc_free(tmp);
		if (!enumv) goto parse;

		fr_value_box_copy(ctx, dst, enumv->value);
		dst->enumv = dst_enumv;

		return 0;
	}

parse:
	/*
	 *	It's a variable ret src->dst_type so we just alloc a new buffer
	 *	of size len and copy.
	 */
	switch (*dst_type) {
	case FR_TYPE_STRING:
	{
		char *buff, *p;

		buff = talloc_bstrndup(ctx, in, len);

		/*
		 *	No de-quoting.  Just copy the string.
		 */
		if (!quote) {
			ret = len;
			dst->vb_strvalue = buff;
			goto finish;
		}

		len = fr_value_str_unescape((uint8_t *)buff, in, len, quote);

		/*
		 *	Shrink the buffer to the correct size
		 *	and \0 terminate it.  There is a significant
		 *	amount of legacy code that assumes the string
		 *	buffer in value pairs is a C string.
		 *
		 *	It's better for the server to print partial
		 *	strings, instead of SEGV.
		 */
		dst->vb_strvalue = p = talloc_realloc(ctx, buff, char, len + 1);
		p[len] = '\0';
		ret = len;
	}
		goto finish;

	case FR_TYPE_VSA:
		fr_strerror_printf("Must use 'Attr-26 = ...' instead of 'Vendor-Specific = ...'");
		return -1;

	/* raw octets: 0x01020304... */
	case FR_TYPE_OCTETS:
	{
		uint8_t	*p;

		/*
		 *	No 0x prefix, just copy verbatim.
		 */
		if ((len < 2) || (strncasecmp(in, "0x", 2) != 0)) {
			dst->vb_octets = talloc_memdup(ctx, (uint8_t const *)in, len);
			talloc_set_type(dst->vb_octets, uint8_t);
			ret = len;
			goto finish;
		}

		len -= 2;

		/*
		 *	Invalid.
		 */
		if ((len & 0x01) != 0) {
			fr_strerror_printf("Length of Hex String is not even, got %zu uint8s", len);
			return -1;
		}

		ret = len >> 1;
		p = talloc_array(ctx, uint8_t, ret);
		if (fr_hex2bin(p, ret, in + 2, len) != (size_t)ret) {
			talloc_free(p);
			fr_strerror_printf("Invalid hex data");
			return -1;
		}

		dst->vb_octets = p;
	}
		goto finish;

	case FR_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		if ((len > 1) && (strncasecmp(in, "0x", 2) == 0)) {
			ssize_t bin;

			if (len > ((sizeof(dst->datum.filter) + 1) * 2)) {
				fr_strerror_printf("Hex data is too large for ascend filter");
				return -1;
			}

			bin = fr_hex2bin((uint8_t *) &dst->datum.filter, ret, in + 2, len - 2);
			if (bin < ret) {
				memset(((uint8_t *) &dst->datum.filter) + bin, 0, ret - bin);
			}
		} else {
			if (ascend_parse_filter(dst, in, len) < 0 ) {
				/* Allow ascend_parse_filter's strerror to bubble up */
				return -1;
			}
		}

		ret = sizeof(dst->datum.filter);
		goto finish;
#else
		/*
		 *	If Ascend binary is NOT defined,
		 *	then fall through to raw octets, so that
		 *	the user can at least make them by hand...
		 */
	 	goto do_octets;
#endif

	case FR_TYPE_IPV4_ADDR:
	{
		fr_ipaddr_t addr;

		if (fr_inet_pton4(&addr, in, inlen, fr_hostname_lookups, false, true) < 0) return -1;

		/*
		 *	We allow v4 addresses to have a /32 suffix as some databases (PostgreSQL)
		 *	print them this way.
		 */
		if (addr.prefix != 32) {
			fr_strerror_printf("Invalid IPv4 mask length \"/%i\".  Only \"/32\" permitted "
					   "for non-prefix types", addr.prefix);
			return -1;
		}

		memcpy(&dst->vb_ip, &addr, sizeof(dst->vb_ip));
	}
		goto finish;

	case FR_TYPE_IPV4_PREFIX:
		if (fr_inet_pton4(&dst->vb_ip, in, inlen, fr_hostname_lookups, false, true) < 0) return -1;
		goto finish;

	case FR_TYPE_IPV6_ADDR:
	{
		fr_ipaddr_t addr;

		if (fr_inet_pton6(&addr, in, inlen, fr_hostname_lookups, false, true) < 0) return -1;

		/*
		 *	We allow v6 addresses to have a /128 suffix as some databases (PostgreSQL)
		 *	print them this way.
		 */
		if (addr.prefix != 128) {
			fr_strerror_printf("Invalid IPv6 mask length \"/%i\".  Only \"/128\" permitted "
					   "for non-prefix types", addr.prefix);
			return -1;
		}

		memcpy(&dst->vb_ip, &addr, sizeof(dst->vb_ip));
	}
		goto finish;

	case FR_TYPE_IPV6_PREFIX:
		if (fr_inet_pton6(&dst->vb_ip, in, inlen, fr_hostname_lookups, false, true) < 0) return -1;
		goto finish;

	/*
	 *	Dealt with below
	 */
	default:
		break;

	case FR_TYPE_STRUCTURAL_EXCEPT_VSA:
	case FR_TYPE_VENDOR:
	case FR_TYPE_BAD:
		fr_strerror_printf("Invalid dst_type %s",
				   fr_table_str_by_value(fr_value_box_type_table, *dst_type, "<INVALID>"));
		return -1;
	}

	/*
	 *	It's a fixed size src->dst_type, copy to a temporary buffer and
	 *	\0 terminate if insize >= 0.
	 */
	if (inlen > 0) {
		if (len >= sizeof(buffer)) {
			fr_strerror_printf("Temporary buffer too small");
			return -1;
		}

		memcpy(buffer, in, inlen);
		buffer[inlen] = '\0';
		in = buffer;
	}

	switch (*dst_type) {
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		break;

	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
		if (fr_value_box_from_integer_str(dst, *dst_type, in) < 0) return -1;
		break;

	case FR_TYPE_SIZE:
		if (fr_size_from_str(&dst->datum.size, in) < 0) return -1;
		break;

	case FR_TYPE_TIME_DELTA:
		if (dst_enumv) {
			if (fr_time_delta_from_str(&dst->datum.time_delta, in, dst_enumv->flags.type_size) < 0) return -1;
		} else {
			if (fr_time_delta_from_str(&dst->datum.time_delta, in, FR_TIME_RES_SEC) < 0) return -1;
		}
		break;

	case FR_TYPE_FLOAT32:
	{
		float f;

		if (sscanf(in, "%f", &f) != 1) {
			fr_strerror_printf("Failed parsing \"%s\" as a float32", in);
			return -1;
		}
		dst->vb_float32 = f;
	}
		break;

	case FR_TYPE_FLOAT64:
	{
		double d;

		if (sscanf(in, "%lf", &d) != 1) {
			fr_strerror_printf("Failed parsing \"%s\" as a float64", in);
			return -1;
		}
		dst->vb_float64 = d;
	}
		break;

	case FR_TYPE_DATE:
	{
		if (fr_unix_time_from_str(&dst->vb_date, in) < 0) return -1;

		dst->enumv = dst_enumv;
	}
		break;

	case FR_TYPE_IFID:
		if (fr_inet_ifid_pton((void *) dst->vb_ifid, in) == NULL) {
			fr_strerror_printf("Failed to parse interface-id string \"%s\"", in);
			return -1;
		}
		break;

	case FR_TYPE_ETHERNET:
	{
		char const *c1, *c2, *cp;
		size_t p_len = 0;

		/*
		 *	Convert things which are obviously integers to Ethernet addresses
		 *
		 *	We assume the number is the decimal
		 *	representation of the ethernet address.
		 *	i.e. the ethernet address converted to a
		 *	number, and printed.
		 *
		 *	The string gets converted to a network-order
		 *	8-byte number, and then the lower bytes of
		 *	that get copied to the ethernet address.
		 */
		if (is_integer(in)) {
			uint64_t lvalue = htonll(atoll(in));

			memcpy(dst->vb_ether, ((uint8_t *) &lvalue) + 2, sizeof(dst->vb_ether));
			break;
		}

		cp = in;
		while (*cp) {
			if (cp[1] == ':') {
				c1 = hextab;
				c2 = memchr(hextab, tolower((int) cp[0]), 16);
				cp += 2;
			} else if ((cp[1] != '\0') && ((cp[2] == ':') || (cp[2] == '\0'))) {
				c1 = memchr(hextab, tolower((int) cp[0]), 16);
				c2 = memchr(hextab, tolower((int) cp[1]), 16);
				cp += 2;
				if (*cp == ':') cp++;
			} else {
				c1 = c2 = NULL;
			}
			if (!c1 || !c2 || (p_len >= sizeof(dst->vb_ether))) {
				fr_strerror_printf("failed to parse Ethernet address \"%s\"", in);
				return -1;
			}
			dst->vb_ether[p_len] = ((c1-hextab)<<4) + (c2-hextab);
			p_len++;
		}
	}
		break;

	/*
	 *	Crazy polymorphic (IPv4/IPv6) attribute src->dst_type for WiMAX.
	 *
	 *	We try and make is saner by replacing the original
	 *	da, with either an IPv4 or IPv6 da src->dst_type.
	 *
	 *	These are not dynamic da, and will have the same vendor
	 *	and attribute as the original.
	 */
	case FR_TYPE_COMBO_IP_ADDR:
	{
		if (fr_inet_pton(&dst->vb_ip, in, inlen, AF_UNSPEC, fr_hostname_lookups, true) < 0) return -1;
		switch (dst->vb_ip.af) {
		case AF_INET:
			ret = dict_attr_sizes[FR_TYPE_COMBO_IP_ADDR][0]; /* size of IPv4 address */
			*dst_type = FR_TYPE_IPV4_ADDR;
			break;

		case AF_INET6:
			*dst_type = FR_TYPE_IPV6_ADDR;
			ret = dict_attr_sizes[FR_TYPE_COMBO_IP_ADDR][1]; /* size of IPv6 address */
			break;

		default:
			fr_strerror_printf("Bad address family %i", dst->vb_ip.af);
			return -1;
		}
	}
		break;

	case FR_TYPE_BOOL:
		if ((strcmp(in, "yes") == 0) || strcmp(in, "true") == 0) {
			dst->datum.boolean = true;
		} else if ((strcmp(in, "no") == 0) || (strcmp(in, "false") == 0)) {
			dst->datum.boolean = false;
		} else {
			fr_strerror_printf("\"%s\" is not a valid boolean value", in);
			return -1;
		}
		break;

	case FR_TYPE_COMBO_IP_PREFIX:
		break;

	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_VARIABLE_SIZE:	/* Should have been dealt with above */
	case FR_TYPE_STRUCTURAL:	/* Listed again to suppress compiler warnings */
	case FR_TYPE_BAD:
		fr_strerror_printf("Unknown attribute dst_type %d", *dst_type);
		return -1;
	}

finish:
	dst->datum.length = ret;
	dst->type = *dst_type;
	dst->tainted = tainted;

	/*
	 *	Fixup enumv
	 */
	dst->enumv = dst_enumv;
	dst->next = NULL;

	return 0;
}

/** Print one attribute value to a string
 *
 */
char *fr_value_box_asprint(TALLOC_CTX *ctx, fr_value_box_t const *data, char quote)
{
	char *p = NULL;

	if (!fr_cond_assert(data->type != FR_TYPE_INVALID)) return NULL;

	/*
	 *	_fr_box_with_da() uses in-line enumv's, and we don't
	 *	want to do dictionary lookups based on that.
	 */
	if (data->enumv && data->enumv->name) {
		fr_dict_enum_t const	*dv;

		dv = fr_dict_enum_by_value(data->enumv, data);
		if (dv) return talloc_typed_strdup(ctx, dv->name);
	}

	switch (data->type) {
	case FR_TYPE_STRING:
	{
		size_t len, ret;

		if (!quote) {
			p = talloc_bstrndup(ctx, data->vb_strvalue, data->datum.length);
			if (!p) return NULL;
			talloc_set_type(p, char);
			return p;
		}

		/* Gets us the size of the buffer we need to alloc */
		len = fr_snprint_len(data->vb_strvalue, data->datum.length, quote);
		p = talloc_array(ctx, char, len);
		if (!p) return NULL;

		ret = fr_snprint(p, len, data->vb_strvalue, data->datum.length, quote);
		if (!fr_cond_assert(ret == (len - 1))) {
			talloc_free(p);
			return NULL;
		}
		break;
	}

	case FR_TYPE_OCTETS:
		p = talloc_array(ctx, char, 2 + 1 + data->datum.length * 2);
		if (!p) return NULL;
		p[0] = '0';
		p[1] = 'x';

		if (data->vb_octets) {
			fr_bin2hex(p + 2, data->vb_octets, data->datum.length);
			p[2 + (data->datum.length * 2)] = '\0';
		} else {
			p[2] = '\0';
		}
		break;

	/*
	 *	We need to use the proper inet_ntop functions for IP
	 *	addresses, else the output might not match output of
	 *	other functions, which makes testing difficult.
	 *
	 *	An example is tunneled ipv4 in ipv6 addresses.
	 */
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	{
		char buff[INET_ADDRSTRLEN  + 4]; // + /prefix

		buff[0] = '\0';
		fr_value_box_snprint(buff, sizeof(buff), data, '\0');

		p = talloc_typed_strdup(ctx, buff);
	}
	break;

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	{
		char buff[INET6_ADDRSTRLEN + 4]; // + /prefix

		buff[0] = '\0';
		fr_value_box_snprint(buff, sizeof(buff), data, '\0');

		p = talloc_typed_strdup(ctx, buff);
	}
	break;

	case FR_TYPE_IFID:
		p = talloc_typed_asprintf(ctx, "%x:%x:%x:%x",
					  (data->vb_ifid[0] << 8) | data->vb_ifid[1],
					  (data->vb_ifid[2] << 8) | data->vb_ifid[3],
					  (data->vb_ifid[4] << 8) | data->vb_ifid[5],
					  (data->vb_ifid[6] << 8) | data->vb_ifid[7]);
		break;

	case FR_TYPE_ETHERNET:
		p = talloc_typed_asprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
					  data->vb_ether[0], data->vb_ether[1],
					  data->vb_ether[2], data->vb_ether[3],
					  data->vb_ether[4], data->vb_ether[5]);
		break;

	case FR_TYPE_BOOL:
		p = talloc_typed_strdup(ctx, data->vb_uint8 ? "yes" : "no");
		break;

	case FR_TYPE_UINT8:
		p = talloc_typed_asprintf(ctx, "%u", data->vb_uint8);
		break;

	case FR_TYPE_UINT16:
		p = talloc_typed_asprintf(ctx, "%u", data->vb_uint16);
		break;

	case FR_TYPE_UINT32:
		p = talloc_typed_asprintf(ctx, "%u", data->vb_uint32);
		break;

	case FR_TYPE_UINT64:
		p = talloc_typed_asprintf(ctx, "%" PRIu64, data->vb_uint64);
		break;

	case FR_TYPE_INT8:
		p = talloc_typed_asprintf(ctx, "%d", data->vb_int8);
		break;

	case FR_TYPE_INT16:
		p = talloc_typed_asprintf(ctx, "%d", data->vb_int16);
		break;

	case FR_TYPE_INT32:
		p = talloc_typed_asprintf(ctx, "%d", data->vb_int32);
		break;

	case FR_TYPE_INT64:
		p = talloc_typed_asprintf(ctx, "%" PRId64, data->vb_int64);
		break;

	case FR_TYPE_FLOAT32:
		p = talloc_typed_asprintf(ctx, "%f", (double) data->vb_float32);
		break;

	case FR_TYPE_FLOAT64:
		p = talloc_typed_asprintf(ctx, "%g", data->vb_float64);
		break;

	case FR_TYPE_DATE:
	{
		char buff[128];

		/*
		 *	This is complex, so call another function to
		 *	do the work.
		 */
		(void) fr_value_box_snprint(buff, sizeof(buff), data, quote);
		p = talloc_typed_strdup(ctx, buff);
		break;
	}

	case FR_TYPE_SIZE:
		p = talloc_typed_asprintf(ctx, "%zu", data->datum.size);
		break;

	case FR_TYPE_TIME_DELTA:
	{
		char *q;
		uint64_t lhs, rhs;
		fr_time_res_t res = FR_TIME_RES_SEC;

		if (data->enumv) res = data->enumv->flags.type_size;

		switch (res) {
		default:
		case FR_TIME_RES_SEC:
			lhs = data->datum.time_delta / NSEC;
			rhs = data->datum.time_delta % NSEC;
			break;

		case FR_TIME_RES_MSEC:
			lhs = data->datum.time_delta / 1000000;
			rhs = data->datum.time_delta % 1000000;
			break;

		case FR_TIME_RES_USEC:
			lhs = data->datum.time_delta / 1000;
			rhs = data->datum.time_delta % 1000;
			break;

		case FR_TIME_RES_NSEC:
			lhs = data->datum.time_delta;
			rhs = 0;
			break;
		}

		p = talloc_typed_asprintf(ctx, "%" PRIu64 ".%09" PRIu64, lhs, rhs);

		/*
		 *	Truncate trailing zeros.
		 */
		q = p + strlen(p) - 1;
		while (*q == '0') {
			*(q--) = '\0';
		}

		/*
		 *	If there's nothing after the decimal point,
		 *	trunctate the decimal point.  i.e. Don't print
		 *	"5."
		 */
		if (*q == '.') {
			*q = '\0';
		} else {
			q++;	/* to account for q-- above */
		}

		p = talloc_bstr_realloc(ctx, p, q - p);
	}
		break;

	case FR_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		p = talloc_array(ctx, char, 128);
		if (!p) return NULL;
		print_abinary(NULL, p, 128, (uint8_t const *) &data->datum.filter, data->datum.length, 0);
		break;
#else
		  /* FALL THROUGH */
#endif

	case FR_TYPE_GROUP:
	{
		fr_value_box_t vb;

		memset(&vb, 0, sizeof(vb));

		/*
		 *	Be lazy by just converting it to a string, and then printing the string.
		 */
		if (fr_value_box_cast_to_strvalue(NULL, &vb, FR_TYPE_STRING, NULL, data->vb_group) < 0) return NULL;
		p = fr_value_box_asprint(ctx, &vb, quote);
		fr_value_box_clear(&vb);
	}
		break;

	/*
	 *	Don't add default here
	 */
	case FR_TYPE_TLV:		/* Not a box type */
	case FR_TYPE_STRUCT:		/* Not a box type */
	case FR_TYPE_VSA:		/* Not a box type */
	case FR_TYPE_VENDOR:		/* Not a box type */
	case FR_TYPE_EXTENDED:		/* Not a box type */
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_BAD:
		(void)fr_cond_assert(0);
		return NULL;
	}

	return p;
}

/** Concatenate a list of value boxes
 *
 * @note Will automatically cast all #fr_value_box_t to type specified.
 *
 * @param[in] ctx		to allocate new value buffer in.
 * @param[out] out		Where to write the resulting box.
 * @param[in] list		to concatenate together.
 * @param[in] type		May be #FR_TYPE_STRING or #FR_TYPE_OCTETS, no other types are
 *				supported.
 * @param[in] free_input	If true, free the input boxes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_list_concat(TALLOC_CTX *ctx,
			     fr_value_box_t *out, fr_value_box_t **list, fr_type_t type, bool free_input)
{
	TALLOC_CTX		*pool;
	fr_cursor_t		cursor;
	fr_value_box_t const	*vb;

	if (!list || !*list) {
		fr_strerror_printf("Invalid arguments.  List was NULL");
		return -1;
	}

	switch (type) {
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		break;

	default:
		fr_strerror_printf("Invalid argument.  Can't concatenate boxes to type %s",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"));
		return -1;
	}

	fr_cursor_init(&cursor, list);

	/*
	 *	Allow concatenating in place
	 */
	if (out == *list) {
		if ((*list)->type != type) {
			fr_value_box_t from_cast;
			fr_value_box_t *next = out->next;

			/*
			 *	Two phase, as the casting code doesn't
			 *	allow 'cast-in-place'.
			 */
			if (fr_value_box_cast(ctx, &from_cast, type, NULL, out) < 0) return -1;
			if (fr_value_box_copy(ctx, out, &from_cast) < 0) return -1;
			out->next = next;			/* Restore the next pointer */
		}
		fr_cursor_next(&cursor);
	} else {
		if (fr_value_box_cast(ctx, out, type, NULL, *list) < 0) return -1;	/* Decomposes to copy */

		if (free_input) {
			fr_cursor_free_item(&cursor);		/* Advances cursor */
		} else {
			fr_cursor_next(&cursor);
		}
	}

	/*
	 *	Imploding a one element list.
	 */
	if (!fr_cursor_current(&cursor)) return 0;

	pool = talloc_pool(NULL, 255);	/* To absorb the temporary strings */

	/*
	 *	Join the remaining values
	 */
	while ((vb = fr_cursor_current(&cursor))) {
	     	fr_value_box_t from_cast;
	     	fr_value_box_t const *n;

		if (vb->type != type) {
			talloc_free_children(pool);		/* Clear out previous buffers */
			memset(&from_cast, 0, sizeof(from_cast));

			if (fr_value_box_cast(pool, &from_cast, type, NULL, vb) < 0) {
			error:
				talloc_free(pool);
				return -1;
			}

			n = &from_cast;
		} else {
			n = vb;
		}

		/*
		 *	Append the next value
		 */
		if (type == FR_TYPE_STRING) {
			if (fr_value_box_append_bstr(out, n->vb_strvalue, n->vb_length, n->tainted) < 0) goto error;
		} else {
			if (fr_value_box_append_mem(out, n->vb_octets, n->vb_length, n->tainted) < 0) goto error;
		}

		if (free_input) {
			fr_cursor_free_item(&cursor);		/* Advances cursor */
		} else {
			fr_cursor_next(&cursor);
		}
	}

	talloc_free(pool);

	return 0;
}

/** Concatenate the string representations of a list of value boxes together
 *
 * @param[in] ctx	to allocate the buffer in.
 * @param[in] head	of the list of value boxes.
 * @param[in] delim	to insert between value box values.
 * @param[in] quote	character used set unescape mode.  @see fr_value_str_unescape.
 * @return
 *	- NULL on error.
 *	- The concatenation of the string values of the value box list on success.
 */
char *fr_value_box_list_asprint(TALLOC_CTX *ctx, fr_value_box_t const *head, char const *delim, char quote)
{
	fr_value_box_t const	*vb = head;
	char			*aggr, *td = NULL;
	TALLOC_CTX		*pool = NULL;

	if (!head) return NULL;

	aggr = fr_value_box_asprint(ctx, vb, quote);
	if (!aggr) return NULL;
	if (!vb->next) return aggr;

	/*
	 *	If we're aggregating more values,
	 *	allocate a temporary pool.
	 */
	pool = talloc_pool(NULL, 255);
	if (delim) td = talloc_typed_strdup(pool, delim);

	while ((vb = vb->next)) {
		char *str, *new_aggr;

		str = fr_value_box_asprint(pool, vb, quote);
		if (!str) continue;

		new_aggr = talloc_buffer_append_variadic_buffer(ctx, aggr, 2, td, str);
		if (unlikely(!new_aggr)) {
			talloc_free(aggr);
			talloc_free(pool);
			return NULL;
		}
		aggr = new_aggr;
		talloc_free(str);
	}
	talloc_free(pool);

	return aggr;
}

/** Flatten a list into individual "char *" argv-style array
 *
 * @param[in] ctx	to allocate boxes in.
 * @param[out] argv_p	where output strings go
 * @param[in] in	boxes to flatten
 * @return
 *	- >= 0 number of array elements in argv
 *	- <0 on error
 */
int fr_value_box_list_flatten_argv(TALLOC_CTX *ctx, char ***argv_p, fr_value_box_t const *in)
{
	int i, argc;
	char **argv;

	if (in->type != FR_TYPE_GROUP) {
		argc = 1;

	} else {
		argc = fr_value_box_list_len(in);
	}

	argv = talloc_zero_array(ctx, char *, argc + 1);
	if (!argv) return -1;

	if (in->type != FR_TYPE_GROUP) {
		argv[0] = fr_value_box_asprint(argv, in, 0);

	} else {
		fr_value_box_t const *in_p;

		/*
		 *	Print the children of each group into the argv array.
		 */
		for (in_p = in, i = 0;
		     in_p;
		     in_p = in_p->next) {
			argv[i] = fr_value_box_asprint(argv, in_p->vb_group, '\0');
			if (!argv[i]) {
				talloc_free(argv);
				return -1;
			}

			/*
			 *	Unescape quoted strings, so that the
			 *	programs get passed the unquoted
			 *	results.
			 */
			if ((argv[i][0] == '"') || (argv[i][0] == '\'')) {
				size_t inlen, outlen;

				inlen = talloc_array_length(argv[i]) - 3;
				outlen = fr_value_str_unescape((uint8_t *) argv[i], argv[i] + 1, inlen, *argv[i]);
				fr_assert(outlen <= inlen);
				argv[i][outlen] = '\0';
			}

			i++;
		}
	}

	*argv_p = argv;
	return argc;
}

/** Do a full copy of a list of value boxes
 *
 * @param[in] ctx	to allocate boxes in.
 * @param[out] out	Where to write the head of the new list.
 * @param[in] in	boxes to copy.
 * @return
 *	- A duplicate list of value boxes, allocated in the context of 'ctx'
 *	- NULL on error, or empty input list.
 */
int fr_value_box_list_acopy(TALLOC_CTX *ctx, fr_value_box_t **out, fr_value_box_t const *in)
{
	fr_value_box_t const *in_p;
	fr_cursor_t cursor;

	*out = NULL;

	fr_cursor_init(&cursor, out);

	for (in_p = in;
	     in_p;
	     in_p = in_p->next) {
	     	fr_value_box_t *n = NULL;

		n = fr_value_box_alloc_null(ctx);
		if (!n) {
		error:
			fr_cursor_head(&cursor);
			fr_cursor_free_list(&cursor);
			return -1;
		}

		if (fr_value_box_copy(n, n, in_p) < 0) goto error;
		fr_cursor_append(&cursor, n);
	}

	return 0;
}

/** Check to see if any list members are tainted
 *
 * @param[in] head	of list to check.
 * @return
 *	- true if a list member is tainted.
 *	- false if no list members are tainted.
 */
bool fr_value_box_list_tainted(fr_value_box_t const *head)
{
	if (!head) return false;

	do {
		if (head->tainted) return true;
	} while ((head = head->next));

	return false;
}

/** Get list member at a given index
 *
 * @param[in] head	of list.
 * @param[in] index	of member to return.
 * @return
 *	- NULL if there is no member at given index
 *	- member if it exists
 */
fr_value_box_t * fr_value_box_list_get(fr_value_box_t *head, int index)
{
	int i = 0;

	while (i < index && head) {
		head = head->next;
		i++;
	}

	return head;
}

/** Print the value of an attribute to a string
 *
 * @note return value should be checked with is_truncated.
 * @note Will always \0 terminate unless outlen == 0.
 *
 * @param out Where to write the printed version of the attribute value.
 * @param outlen Length of the output buffer.
 * @param data to print.
 * @param quote char to escape in string output.
 * @return
 *	- The number of uint8s written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
size_t fr_value_box_snprint(char *out, size_t outlen, fr_value_box_t const *data, char quote)
{
	char		buf[1024];	/* Interim buffer to use with poorly behaved printing functions */
	char const	*a = NULL;
	char		*p = out, *end = p + outlen;
	time_t		t;
	struct tm	s_tm;

	size_t		len = 0;

	if (!data) return 0;

	if (!fr_cond_assert(data->type != FR_TYPE_INVALID)) return -1;

	if (outlen == 0) return data->datum.length;

	*out = '\0';

	p = out;

	if (data->enumv && data->enumv->name) {
		fr_dict_enum_t const	*dv;

		dv = fr_dict_enum_by_value(data->enumv, data);
		if (dv) return strlcpy(out, dv->name, outlen);
	}

	switch (data->type) {
	case FR_TYPE_STRING:

		/*
		 *	Ensure that WE add the quotation marks around the string.
		 */
		if (quote) {
			if ((end - p) < 3) return data->datum.length + 2;

			*p++ = quote;

			len = fr_snprint(p, (end - p), data->vb_strvalue, data->datum.length, quote);
			/* always terminate the quoted string with another quote */
			if ((len + 1) >= (size_t)(end - p)) {
				/* Use out not p as we're operating on the entire buffer */
				out[outlen - 2] = (char) quote;
				out[outlen - 1] = '\0';
				return len + 2;
			}
			p += len;

			*p++ = (char) quote;
			*p = '\0';

			return len + 2;
		}

		return fr_snprint(out, outlen, data->vb_strvalue, data->datum.length, quote);

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
		a = fr_inet_ntop(buf, sizeof(buf), &data->vb_ip);
		len = strlen(buf);
		break;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
		a = fr_inet_ntop_prefix(buf, sizeof(buf), &data->vb_ip);
		len = strlen(buf);
		break;

	case FR_TYPE_IFID:
		a = fr_inet_ifid_ntop(buf, sizeof(buf), data->vb_ifid);
		len = strlen(buf);
		break;

	case FR_TYPE_ETHERNET:
		return snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
				data->vb_ether[0], data->vb_ether[1],
				data->vb_ether[2], data->vb_ether[3],
				data->vb_ether[4], data->vb_ether[5]);

	case FR_TYPE_BOOL:
		return snprintf(out, outlen, "%s", data->vb_bool ? "yes" : "no");

	case FR_TYPE_UINT8:
		return snprintf(out, outlen, "%u", data->vb_uint8);

	case FR_TYPE_UINT16:
		return snprintf(out, outlen, "%u", data->vb_uint16);

	case FR_TYPE_UINT32:
		return snprintf(out, outlen, "%u", data->vb_uint32);

	case FR_TYPE_UINT64:
		return snprintf(out, outlen, "%" PRIu64, data->vb_uint64);

	case FR_TYPE_INT8:
		return snprintf(out, outlen, "%d", data->vb_int8);

	case FR_TYPE_INT16:
		return snprintf(out, outlen, "%d", data->vb_int16);

	case FR_TYPE_INT32:
		return snprintf(out, outlen, "%d", data->vb_int32);

	case FR_TYPE_INT64:
		return snprintf(out, outlen, "%" PRId64, data->vb_int64);

	case FR_TYPE_FLOAT32:
		return snprintf(out, outlen, "%f", (double) data->vb_float32);

	case FR_TYPE_FLOAT64:
		return snprintf(out, outlen, "%g", data->vb_float64);

	case FR_TYPE_DATE:
		t = fr_unix_time_to_sec(data->vb_date);
		(void) gmtime_r(&t, &s_tm);

		if (!data->enumv || (data->enumv->flags.type_size == FR_TIME_RES_SEC)) {
			if (quote > 0) {
				len = strftime(buf, sizeof(buf) - 1, "%%%b %e %Y %H:%M:%S UTC", &s_tm);
			} else {
				len = strftime(buf, sizeof(buf), "%b %e %Y %H:%M:%S UTC", &s_tm);
			}

		} else {
			int64_t subseconds;

			/*
			 *	Print this out first, as it's always the same
			 */
			if (quote > 0) {
				len = strftime(buf, sizeof(buf) - 1, "%%%Y-%m-%dT%H:%M:%S", &s_tm);
			} else {
				len = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &s_tm);
			}

			subseconds = data->vb_date % NSEC;

			/*
			 *	Use RFC 3339 format, which is a
			 *	profile of ISO8601.  The ISO standard
			 *	allows a much more complex set of date
			 *	formats.  The RFC is much stricter.
			 */
			switch (data->enumv->flags.type_size) {
			default:
				break;

			case FR_TIME_RES_MSEC:
				subseconds /= 1000000;
				len += snprintf(buf + len, sizeof(buf) - len - 1, ".%03" PRIi64, subseconds);
				break;

			case FR_TIME_RES_USEC:
				subseconds /= 1000;
				len += snprintf(buf + len, sizeof(buf) - len - 1, ".%06" PRIi64, subseconds);
				break;

			case FR_TIME_RES_NSEC:
				len += snprintf(buf + len, sizeof(buf) - len - 1, ".%09" PRIi64, subseconds);
				break;
			}

			/*
			 *	And time zone.
			 */
			if (s_tm.tm_gmtoff != 0) {
				int hours, minutes;

				hours = s_tm.tm_gmtoff / 3600;
				minutes = (s_tm.tm_gmtoff / 60) % 60;

				len += snprintf(buf + len, sizeof(buf) - len - 1, "%+03d:%02u", hours, minutes);
			} else {
				buf[len] = 'Z';
				len++;
			}
		}

		if (quote > 0) {
			buf[0] = (char) quote;
			buf[len] = (char) quote;
			buf[len + 1] = '\0';
			len++;	/* Account for trailing quote */
		}
		a = buf;
		break;

	case FR_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		len = print_abinary(NULL, buf, sizeof(buf),
				    (uint8_t const *) data->datum.filter, data->datum.length, quote);
		a = buf;
		break;
#else
	/* FALL THROUGH */
#endif
	case FR_TYPE_OCTETS:
	case FR_TYPE_TLV:
	{
		size_t max;

		/* Return the number of uint8s we would have written */
		len = (data->datum.length * 2) + 2;
		if ((end - p) <= 1) return len;


		*p++ = '0';
		if ((end - p) <= 1) {
			*p = '\0';
			return len;
		}

		*p++ = 'x';
		if ((end - p) <= 2) {
			*p = '\0';
			return len;
		}

		/* Get maximum number of uint8s we can encode given (end - p) */
		if (data->vb_octets) {
			max = (((end - p) % 2) ? (end - p) - 1 : (end - p) - 2) / 2;
			fr_bin2hex(p, data->vb_octets,
				   ((size_t)data->datum.length > max) ? max : (size_t)data->datum.length);
		} else {
			*p = '\0';
		}
	}
		return len;



	case FR_TYPE_SIZE:
		return snprintf(out, outlen, "%zu", data->datum.size);

	case FR_TYPE_TIME_DELTA:
	{
		char		*q;
		uint64_t	lhs, rhs;
		fr_time_res_t	res = FR_TIME_RES_SEC;

		if (data->enumv) res = data->enumv->flags.type_size;

		switch (res) {
		default:
		case FR_TIME_RES_SEC:
			lhs = data->datum.time_delta / NSEC;
			rhs = data->datum.time_delta % NSEC;
			break;

		case FR_TIME_RES_MSEC:
			lhs = data->datum.time_delta / 1000000;
			rhs = data->datum.time_delta % 1000000;
			break;

		case FR_TIME_RES_USEC:
			lhs = data->datum.time_delta / 1000;
			rhs = data->datum.time_delta % 1000;
			break;

		case FR_TIME_RES_NSEC:
			lhs = data->datum.time_delta;
			rhs = 0;
			break;
		}

		len = snprintf(buf, sizeof(buf), "%" PRIu64 ".%09" PRIu64, lhs, rhs);
		a = buf;

		/*
		 *	Truncate trailing zeros.
		 */
		q = buf + len - 1;
		while (*q == '0') {
			*(q--) = '\0';
			len--;
		}

		/*
		 *	If there's nothing after the decimal point,
		 *	trunctate the decimal point.  i.e. Don't print
		 *	"5."
		 */
		if (*q == '.') {
			*q = '\0';
			len--;
		}
	}
		break;

	case FR_TYPE_GROUP:
	{
		fr_cursor_t cursor;
		fr_value_box_t *vb;

		fr_cursor_init(&cursor, &data->vb_group);
		while ((vb = fr_cursor_current(&cursor)) != NULL) {
			len = fr_value_box_snprint(p, end - p, vb, quote);
			p += len;
			if (p >= end) break;
			fr_cursor_next(&cursor);
		}
	}
		break;

	/*
	 *	Don't add default here
	 */
	case FR_TYPE_INVALID:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_EXTENDED:
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
	case FR_TYPE_STRUCT:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_MAX:
		(void)fr_cond_assert_msg(0, "%s: Can't print box of type \"%s\"", __FUNCTION__,
					 fr_table_str_by_value(fr_value_box_type_table, data->type, "?Unknown?"));
		*out = '\0';
		return 0;
	}

	if (a) strlcpy(out, a, outlen);

	return len;	/* Return the number of uint8s we would of written (for truncation detection) */
}
