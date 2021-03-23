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
 *   - #fr_value_box_memdup* is used to ingest binary data into the INTERNAL format.
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
 *   - #fr_value_box_aprint is used to convert from INTERNAL to PRESENTATION format.
 *   - #fr_value_box_from_str is used to convert from PRESENTATION to INTERNAL format.
 *
 * @copyright 2014-2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#define _VALUE_PRIVATE
#include <freeradius-devel/util/value.h>
#undef _VALUE_PRIVATE

#include <freeradius-devel/util/ascend.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>

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

	{ L("time_delta"),	FR_TYPE_TIME_DELTA	},
	{ L("date"),		FR_TYPE_DATE		},

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
#define network_min_size(_x) (fr_value_box_network_sizes[_x][0])
#define network_max_size(_x) (fr_value_box_network_sizes[_x][1])
static size_t const fr_value_box_network_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_NULL]			= {~0, 0},

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

	[FR_TYPE_MAX]				= {~0, 0}		//!< Ensure array covers all types.
};

/** How many bytes wide each of the value data fields are
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

	[FR_TYPE_VALUE_BOX]			= 0,

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

static uint64_t const fr_value_box_integer_max[] = {
	[FR_TYPE_BOOL]				= true,
	[FR_TYPE_UINT8]				= UINT8_MAX,
	[FR_TYPE_UINT16]			= UINT16_MAX,
	[FR_TYPE_UINT32]			= UINT32_MAX,
	[FR_TYPE_UINT64]			= UINT64_MAX,

	[FR_TYPE_INT8]				= INT8_MAX,
	[FR_TYPE_INT16]				= INT16_MAX,
	[FR_TYPE_INT32]				= INT32_MAX,
	[FR_TYPE_INT64]				= INT64_MAX,

	[FR_TYPE_DATE]				= UINT64_MAX,
	[FR_TYPE_TIME_DELTA]			= INT64_MAX,

	[FR_TYPE_SIZE]				= SIZE_MAX,

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

static int64_t const fr_value_box_integer_min[] = {
	[FR_TYPE_BOOL]				= false,
	[FR_TYPE_UINT8]				= 0,
	[FR_TYPE_UINT16]			= 0,
	[FR_TYPE_UINT32]			= 0,
	[FR_TYPE_UINT64]			= 0,

	[FR_TYPE_INT8]				= INT8_MIN,
	[FR_TYPE_INT16]				= INT16_MIN,
	[FR_TYPE_INT32]				= INT32_MIN,
	[FR_TYPE_INT64]				= INT64_MIN,

	[FR_TYPE_DATE]				= 0,
	[FR_TYPE_TIME_DELTA]			= INT64_MIN,

	[FR_TYPE_SIZE]				= 0,

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

fr_sbuff_unescape_rules_t fr_value_unescape_double = {
	.name = "double",
	.chr = '\\',
	.subs = {
		['"'] = '"',	/* Quoting char */
		['%'] = '%',	/* xlat expansions */
		['\\'] = '\\',
		['a'] = '\a',
		['b'] = '\b',
		['e'] = '\\',
		['n'] = '\n',
		['r'] = '\r',
		['t'] = '\t',
		['v'] = '\v'
	},
	.do_hex = true,
	.do_oct = true
};

fr_sbuff_unescape_rules_t fr_value_unescape_single = {
	.name = "single",
	.chr = '\\',
	.subs = {
		['\''] = '\'',	/* Quoting char */
		['\\'] = '\\'
	},
	.do_hex = false,
	.do_oct = false
};

fr_sbuff_unescape_rules_t fr_value_unescape_solidus = {
	.name = "solidus",
	.chr = '\\',
	.subs = {
		['%'] = '%',	/* xlat expansions */
		['/'] = '/',	/* Quoting char */
		['a'] = '\a',
		['b'] = '\b',
		['e'] = '\\',
		['n'] = '\n',
		['r'] = '\r',
		['t'] = '\t',
		['v'] = '\v'
	},
	.skip = {
		['\\'] = '\\'	/* Leave this for the regex library */
	},
	.do_hex = true,
	.do_oct = true
};

fr_sbuff_unescape_rules_t fr_value_unescape_backtick = {
	.name = "backtick",
	.chr = '\\',
	.subs = {
		['%'] = '%',	/* xlat expansions */
		['\\'] = '\\',
		['`'] = '`',	/* Quoting char */
		['a'] = '\a',
		['b'] = '\b',
		['e'] = '\\',
		['n'] = '\n',
		['r'] = '\r',
		['t'] = '\t',
		['v'] = '\v'
	},
	.do_hex = true,
	.do_oct = true
};

fr_sbuff_unescape_rules_t *fr_value_unescape_by_quote[T_TOKEN_LAST] = {
	[T_DOUBLE_QUOTED_STRING]	= &fr_value_unescape_double,
	[T_SINGLE_QUOTED_STRING]	= &fr_value_unescape_single,
	[T_SOLIDUS_QUOTED_STRING]	= &fr_value_unescape_solidus,
	[T_BACK_QUOTED_STRING]		= &fr_value_unescape_backtick,
};

fr_sbuff_escape_rules_t fr_value_escape_double = {
	.name = "double",
	.chr = '\\',
	.subs = {
		['"'] = '"',	/* Quoting char */
		['%'] = '%',	/* xlat expansions */
		['\\'] = '\\',
		['\a'] = 'a',
		['\b'] = 'b',
		['\n'] = 'n',
		['\r'] = 'r',
		['\t'] = 't',
		['\v'] = 'v'
	},
	.esc = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	},
	.do_utf8 = true,
	.do_oct = true
};

fr_sbuff_escape_rules_t fr_value_escape_single = {
	.name = "single",
	.chr = '\\',
	.subs = {
		['\''] = '\'',	/* Quoting char */
		['\\'] = '\\'
	},
	.do_utf8 = true,
};

fr_sbuff_escape_rules_t fr_value_escape_solidus = {
	.name = "solidus",
	.chr = '\\',
	.subs = {
		['%'] = '%',	/* xlat expansions */
		['/'] = '/',	/* Quoting char */
		['\a'] = 'a',
		['\b'] = 'b',
		['\n'] = 'n',
		['\r'] = 'r',
		['\t'] = 't',
		['\v'] = 'v'
	},
	.esc = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	},
	.do_utf8 = true,
	.do_oct = true
};

fr_sbuff_escape_rules_t fr_value_escape_backtick = {
	.name = "backtick",
	.chr = '\\',
	.subs = {
		['%'] = '%',	/* xlat expansions */
		['\\'] = '\\',
		['`'] = '`',	/* Quoting char */
		['\a'] = 'a',
		['\b'] = 'b',
		['\n'] = 'n',
		['\r'] = 'r',
		['\t'] = 't',
		['\v'] = 'v'
	},
	.esc = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	},
	.do_utf8 = true,
	.do_oct = true
};

fr_sbuff_escape_rules_t *fr_value_escape_by_quote[T_TOKEN_LAST] = {
	[T_DOUBLE_QUOTED_STRING]	= &fr_value_escape_double,
	[T_SINGLE_QUOTED_STRING]	= &fr_value_escape_single,
	[T_SOLIDUS_QUOTED_STRING]	= &fr_value_escape_solidus,
	[T_BACK_QUOTED_STRING]		= &fr_value_escape_backtick,
};

/** Copy flags and type data from one value box to another
 *
 * @param[in] dst to copy flags to
 * @param[in] src of data.
 */
static inline void fr_value_box_copy_meta(fr_value_box_t *dst, fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_VARIABLE_SIZE:
		dst->vb_length = src->vb_length;
		break;
	/*
	 *	Not 100% sure this should be done here
	 *	but if the intent is to make a null
	 *	box usable, then we need to do this
	 *	somewhere.
	 */
	case FR_TYPE_GROUP:
		fr_value_box_list_init(&dst->vb_group);
		break;

	default:
		break;
	}

	dst->enumv = src->enumv;
	dst->type = src->type;
	dst->tainted = src->tainted;
	fr_dlist_entry_init(&dst->entry);
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

	if (!fr_cond_assert(a->type != FR_TYPE_NULL)) return -1;
	if (!fr_cond_assert(b->type != FR_TYPE_NULL)) return -1;

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

		if (a->vb_length < b->vb_length) {
			length = a->vb_length;
		} else {
			length = b->vb_length;
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
		compare = a->vb_length - b->vb_length;
	}
		break;

		/*
		 *	Short-hand for simplicity.
		 */
#define CHECK(_type) do { \
			if (a->datum._type < b->datum._type)   { compare = -1; \
			} else if (a->datum._type > b->datum._type) { compare = +1; } \
		     } while (0)

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
static int fr_value_box_cidr_cmp_op(fr_token_t op, int bytes,
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

		compare = memcmp(a, b, bytes);

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
	 *	Do the check uint8 by uint8.  If the bytes are
	 *	identical, it MAY be a match.  If they're different,
	 *	it is NOT a match.
	 */
	i = 0;
	while (i < bytes) {
		/*
		 *	All leading bytes are identical.
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

	if (!fr_cond_assert(a->type != FR_TYPE_NULL)) return -1;
	if (!fr_cond_assert(b->type != FR_TYPE_NULL)) return -1;

	switch (a->type) {
	case FR_TYPE_IPV4_ADDR:
		switch (b->type) {
		case FR_TYPE_IPV4_ADDR:		/* IPv4 and IPv4 */
			goto cmp;

		case FR_TYPE_IPV4_PREFIX:	/* IPv4 and IPv4 Prefix */
			return fr_value_box_cidr_cmp_op(op, 4, 32, (uint8_t const *) &a->vb_ip.addr.v4.s_addr,
						     b->vb_ip.prefix, (uint8_t const *) &b->vb_ip.addr.v4.s_addr);

		default:
			fr_strerror_const("Cannot compare IPv4 with IPv6 address");
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
			fr_strerror_const("Cannot compare IPv4 with IPv6 address");
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
			fr_strerror_const("Cannot compare IPv6 with IPv4 address");
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
			fr_strerror_const("Cannot compare IPv6 with IPv4 address");
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
 * - Literal mode ("'" quote char) will unescape:
 @verbatim
   - \\        - Literal backslash.
   - \<quote>  - The quotation char.
 @endverbatim
 * - Expanded mode ('"' quote char) will also unescape:
 @verbatim
   - \a        - Alert.
   - \b        - Backspace.
   - \e        - Escape character i.e. (\)
   - \r        - Carriage return.
   - \n        - Newline.
   - \t        - Tab.
   - \v        - Vertical tab
   - \<oct>    - An octal escape sequence.
   - \x<hex>   - A hex escape sequence.
 @endverbatim
 * - Backtick mode ('`' quote char) identical to expanded mode.
 * - Regex mode ('/') identical to expanded mode but two successive
 * backslashes will be interpreted as an escape sequence, but not
 * unescaped, so that they will be passed to the underlying regex
 * library.
 * - Verbatim mode ('\0' quote char) copies in to out verbatim.
 *
 * @note The resulting output may contain embedded \0s.
 * @note Unrecognised escape sequences will be copied verbatim.
 * @note In and out may point to the same underlying buffer.
 * @note Copying will stop early if an unescaped instance of the
 *	 quoting char is found in the input buffer.
 *
 * @param[out] out	Where to write the unescaped string.
 * @param[in] in	The string to unescape.
 * @param[in] inlen	Length of input string.  Pass SIZE_MAX to copy all data
 *			in the input buffer.
 * @param[in] quote	Character around the string, determines unescaping mode.
 *
 * @return
 *	- 0 if input string was empty.
 *	- >0 the number of bytes written to out.
 */
size_t fr_value_str_unescape(fr_sbuff_t *out, fr_sbuff_t *in, size_t inlen, char quote)
{
	switch (quote) {
	default:
		break;

	case '"':
	{
		return fr_sbuff_out_unescape_until(out, in, inlen, NULL, &fr_value_unescape_double);
	}
	case '\'':
	{
		return fr_sbuff_out_unescape_until(out, in, inlen, NULL, &fr_value_unescape_single);
	}

	case '`':
	{
		return fr_sbuff_out_unescape_until(out, in, inlen, NULL, &fr_value_unescape_backtick);
	}

	case '/':
	{
		return fr_sbuff_out_unescape_until(out, in, inlen, NULL, &fr_value_unescape_solidus);
	}
	}

	return fr_sbuff_out_bstrncpy(out, in, inlen);
}

/** Convert a string value with escape sequences into its binary form
 *
 * The quote character determines the escape sequences recognised.
 *
 * - Literal mode ("'" quote char) will unescape:
 @verbatim
   - \\        - Literal backslash.
   - \<quote>  - The quotation char.
 @endverbatim
 * - Expanded mode ('"' quote char) will also unescape:
 @verbatim
   - \a        - Alert.
   - \b        - Backspace.
   - \e        - Escape character i.e. (\)
   - \r        - Carriage return.
   - \n        - Newline.
   - \t        - Tab.
   - \v        - Vertical tab
   - \<oct>    - An octal escape sequence.
   - \x<hex>   - A hex escape sequence.
 @endverbatim
 * - Backtick mode ('`' quote char) identical to expanded mode.
 * - Regex mode ('/') identical to expanded mode but two successive
 * backslashes will be interpreted as an escape sequence, but not
 * unescaped, so that they will be passed to the underlying regex
 * library.
 * - Verbatim mode ('\0' quote char) copies in to out verbatim.
 *
 * @note The resulting output may contain embedded \0s.
 * @note Unrecognised escape sequences will be copied verbatim.
 * @note In and out may point to the same underlying buffer.
 * @note Copying will stop early if an unescaped instance of the
 *	 quoting char is found in the input buffer.
 *
 * @param[out] out	Where to write the unescaped string.
 * @param[in] in	The string to unescape.
 * @param[in] inlen	Length of input string.  Pass SIZE_MAX to copy all data
 *			in the input buffer.
 * @param[in] quote	Character around the string, determines unescaping mode.
 *
 * @return
 *	- 0 if input string was empty.
 *	- >0 the number of bytes written to out.
 */
size_t fr_value_substr_unescape(fr_sbuff_t *out, fr_sbuff_t *in, size_t inlen, char quote)
{
	switch (quote) {
	default:
		break;

	case '"':
		return fr_sbuff_out_unescape_until(out, in, inlen, &FR_SBUFF_TERM("\""), &fr_value_unescape_double);

	case '\'':
		return fr_sbuff_out_unescape_until(out, in, inlen, &FR_SBUFF_TERM("'"), &fr_value_unescape_single);

	case '`':
		return fr_sbuff_out_unescape_until(out, in, inlen, &FR_SBUFF_TERM("`"), &fr_value_unescape_backtick);

	case '/':
		return fr_sbuff_out_unescape_until(out, in, inlen, &FR_SBUFF_TERM("/"), &fr_value_unescape_solidus);
	}

	return fr_sbuff_out_bstrncpy(out, in, inlen);
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
	if (!fr_cond_assert(src->type != FR_TYPE_NULL)) return -1;

	switch (src->type) {
	default:
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
		fr_value_box_copy(NULL, dst, src);
		return 0;

	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	case FR_TYPE_NON_VALUES:
		fr_assert_fail(NULL);
		return -1; /* shouldn't happen */
	}

	/*
	 *	If we're not just flipping in place
	 *	initialise the destination box
	 *	with similar meta data as the src.
	 *
	 *	Don't use the copy meta data function
	 *	here as that doesn't initialise the
	 *	destination box.
	 */
	if (dst != src) fr_value_box_init(dst, src->type, src->enumv, src->tainted);

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
		dst->vb_float32 = htonl((uint32_t)src->vb_float32);
		break;

	case FR_TYPE_FLOAT64:
		dst->vb_float64 = htonll((uint64_t)src->vb_float64);
		break;

	default:
		fr_assert_fail(NULL);
		return -1; /* shouldn't happen */
	}

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
		return value->vb_length;

	default:
		return network_min_size(value->type);
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
 *
 * This function will not encode complex types (TLVs, VSAs etc...).  These are usually
 * specific to the protocol anyway.
 *
 * @param[out] dbuff	Where to write serialized data.
 * @param[in] value	to encode.
 * @return
 *	- 0 no bytes were written.
 *	- >0 the number of bytes written to out.
 *	- <0 the number of bytes we'd need in dbuff to complete the operation.
 */
ssize_t fr_value_box_to_network(fr_dbuff_t *dbuff, fr_value_box_t const *value)
{
	size_t		min, max;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	/*
	 *	Variable length types
	 */
	switch (value->type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		max = value->vb_length;

		/*
		 *	Sometimes variable length *inside* the server
		 *	has maximum length on the wire.
		 */
		if (value->enumv && value->enumv->flags.length) {
			if (max < value->enumv->flags.length) {
				FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)value->datum.ptr, max);
				FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, value->enumv->flags.length - max);
				return fr_dbuff_set(dbuff, &work_dbuff);
			}

			/*
			 *	Truncate the input to the maximum allowed length.
			 */
			max = value->enumv->flags.length;
		}

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)value->datum.ptr, max);
		return fr_dbuff_set(dbuff, &work_dbuff);

	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (value->enumv) {
			min = max = value->enumv->flags.length;
		} else {
			min = max = 4;
		}
		break;

	default:
		min = network_min_size(value->type);
		max = network_max_size(value->type);
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

	switch (value->type) {
	case FR_TYPE_IPV4_ADDR:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff,
					  (uint8_t const *)&value->vb_ip.addr.v4.s_addr,
					  sizeof(value->vb_ip.addr.v4.s_addr));
		break;
	/*
	 *	Needs special mangling
	 */
	case FR_TYPE_IPV4_PREFIX:
		FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff,
					  (uint8_t const *)&value->vb_ip.addr.v4.s_addr,
					  sizeof(value->vb_ip.addr.v4.s_addr));
		break;

	case FR_TYPE_IPV6_ADDR:
		if (value->vb_ip.scope_id > 0) FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.scope_id);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value->vb_ip.addr.v6.s6_addr, sizeof(value->vb_ip.addr.v6.s6_addr));
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (value->vb_ip.scope_id > 0) FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.scope_id);
		FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value->vb_ip.addr.v6.s6_addr, sizeof(value->vb_ip.addr.v6.s6_addr));
		break;

	case FR_TYPE_BOOL:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, value->datum.boolean);
		break;

	/*
	 *	Already in network byte-order
	 */
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_UINT8:
	case FR_TYPE_INT8:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, ((uint8_t const *)&value->datum) + fr_value_box_offsets[value->type], min);
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

		fr_value_box_hton(&tmp, value);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, ((uint8_t const *)&tmp.datum) + fr_value_box_offsets[value->type], min);
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
			FR_DBUFF_IN_RETURN(&work_dbuff, (int16_t) date);
			break;

		date_size4:
		case 4:
			if (date > UINT32_MAX) date = UINT32_MAX;
			FR_DBUFF_IN_RETURN(&work_dbuff, (int32_t) date);
			break;

		case 8:
			FR_DBUFF_IN_RETURN(&work_dbuff, date);
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
			FR_DBUFF_IN_RETURN(&work_dbuff, (int16_t)date);
			break;

		delta_size4:
		case 4:
			if (date < INT32_MIN) {
				date = INT32_MIN;
			} else if (date > INT32_MAX) {
				date = INT32_MAX;
			}
			FR_DBUFF_IN_RETURN(&work_dbuff, (int32_t)date);
			break;

		case 8:
			FR_DBUFF_IN_RETURN(&work_dbuff, (int64_t)date);
			break;

		default:
			goto unsupported;
		}

	}
		break;

	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	case FR_TYPE_SIZE:
	case FR_TYPE_NON_VALUES:
		goto unsupported;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
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
	return fr_value_box_from_network_dbuff(ctx, dst, type, enumv, &FR_DBUFF_TMP(src, len), len, tainted);
}

ssize_t fr_value_box_from_network_dbuff(TALLOC_CTX *ctx,
					fr_value_box_t *dst, fr_type_t type, fr_dict_attr_t const *enumv,
					fr_dbuff_t *dbuff, size_t len,
					bool tainted)
{
	size_t		min, max;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	min = network_min_size(type);
	max = network_max_size(type);

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
		if (fr_value_box_bstrndup_dbuff(ctx, dst, enumv, &work_dbuff, len, tainted) < 0) {
			return FR_VALUE_BOX_NET_OOM;
		}
		return fr_dbuff_set(dbuff, &work_dbuff);

	case FR_TYPE_OCTETS:
		if (fr_value_box_memdup_dbuff(ctx, dst, enumv, &work_dbuff, len, tainted) < 0) {
			return FR_VALUE_BOX_NET_OOM;
		}
		return fr_dbuff_set(dbuff, &work_dbuff);
	default:
		break;
	}

	/*
	 *	Pre-Initialise box for non-variable types
	 */
	fr_value_box_init(dst, type, enumv, tainted);
	switch (type) {
	/*
	 *	Already in network byte order
	 */
	case FR_TYPE_IPV4_ADDR:
		dst->vb_ip = (fr_ipaddr_t){
			.af = AF_INET,
			.prefix = 32,
		};
		FR_DBUFF_OUT_MEMCPY_RETURN((uint8_t *)&dst->vb_ip.addr.v4, &work_dbuff, len);
		break;

	case FR_TYPE_IPV4_PREFIX:
		dst->vb_ip = (fr_ipaddr_t){
			.af = AF_INET,
		};
		FR_DBUFF_OUT_RETURN(&dst->vb_ip.prefix, &work_dbuff);
		FR_DBUFF_OUT_MEMCPY_RETURN((uint8_t *)&dst->vb_ip.addr.v4, &work_dbuff, len - 1);
		break;

	case FR_TYPE_IPV6_ADDR:
		dst->vb_ip = (fr_ipaddr_t){
			.af = AF_INET6,
			.scope_id = 0,
			.prefix = 128
		};
		if (len == max) {
			uint8_t	scope_id = 0;

			FR_DBUFF_OUT_RETURN(&scope_id, &work_dbuff);
			dst->vb_ip.scope_id = scope_id;
			len--;
		}
		FR_DBUFF_OUT_MEMCPY_RETURN((uint8_t *)&dst->vb_ip.addr.v6, &work_dbuff, len);
		break;

	case FR_TYPE_IPV6_PREFIX:
		dst->vb_ip = (fr_ipaddr_t){
			.af = AF_INET6,
			.scope_id = 0,
		};
		if (len == max) {
			uint8_t	scope_id = 0;

			FR_DBUFF_OUT_RETURN(&scope_id, &work_dbuff);
			dst->vb_ip.scope_id = scope_id;
			len--;
		}
		FR_DBUFF_OUT_RETURN(&dst->vb_ip.prefix, &work_dbuff);
		FR_DBUFF_OUT_MEMCPY_RETURN((uint8_t *)&dst->vb_ip.addr.v6, &work_dbuff, len - 1);
		break;

	case FR_TYPE_BOOL:
		{
			uint8_t	val = 0;

			FR_DBUFF_OUT_RETURN(&val, &work_dbuff);
			dst->datum.boolean = (val != 0);
		}
		break;

	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
		FR_DBUFF_OUT_MEMCPY_RETURN(((uint8_t *)&dst->datum) + fr_value_box_offsets[type], &work_dbuff, len);
		break;

	case FR_TYPE_INT8:
		FR_DBUFF_OUT_RETURN(&dst->vb_int8, &work_dbuff);
		break;

	case FR_TYPE_UINT8:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint8, &work_dbuff);
		break;

	case FR_TYPE_INT16:
		FR_DBUFF_OUT_RETURN(&dst->vb_int16, &work_dbuff);
		break;

	case FR_TYPE_UINT16:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint16, &work_dbuff);
		break;

	case FR_TYPE_INT32:
		FR_DBUFF_OUT_RETURN(&dst->vb_int32, &work_dbuff);
		break;

	case FR_TYPE_UINT32:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint32, &work_dbuff);
		break;

	case FR_TYPE_INT64:
		FR_DBUFF_OUT_RETURN(&dst->vb_int64, &work_dbuff);
		break;

	case FR_TYPE_UINT64:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint64, &work_dbuff);
		break;

	case FR_TYPE_FLOAT32:
		FR_DBUFF_OUT_RETURN(&dst->vb_float32, &work_dbuff);
		break;

	case FR_TYPE_FLOAT64:
		FR_DBUFF_OUT_RETURN(&dst->vb_float64, &work_dbuff);
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
		size_t length = 4;
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
		if (len > length) return -(length);

		dst->enumv = enumv;

		FR_DBUFF_OUT_UINT64V_RETURN(&date, &work_dbuff, length);

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
		size_t length = 4;
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
		if (len > length) return -(length);

		dst->enumv = enumv;

		FR_DBUFF_OUT_UINT64V_RETURN(&date, &work_dbuff, length);

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

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		break;		/* Already dealt with */

	case FR_TYPE_SIZE:
	case FR_TYPE_NON_VALUES:
		fr_strerror_printf("Cannot decode type \"%s\" - Is not a value",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"));
		break;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
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

	if (src->vb_length < network_min_size(dst_type)) {
		fr_strerror_printf("Invalid cast from %s to %s.  Source is length %zd is smaller than "
				   "destination type size %zd",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
				   src->vb_length,
				   network_min_size(dst_type));
		return -1;
	}

	if (src->vb_length > network_max_size(dst_type)) {
		fr_strerror_printf("Invalid cast from %s to %s.  Source length %zd is greater than "
				   "destination type size %zd",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
				   src->vb_length,
				   network_max_size(dst_type));
		return -1;
	}

	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);

	/*
	 *	Copy the raw octets into the datum of a value_box
	 *	inverting bytesex for uint32s (if LE).
	 */
	memcpy(&dst->datum, src->vb_octets, fr_value_box_field_sizes[dst_type]);
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
		return fr_value_box_bstrndup(ctx, dst, dst_enumv,
					     (char const *)src->vb_octets, src->vb_length, src->tainted);

	case FR_TYPE_GROUP:
	{
		fr_value_box_t *vb = NULL;

		/*
		 *	Initialise an empty buffer we can
		 *	append to.
		 */
		if (fr_value_box_bstrndup(ctx, dst, dst_enumv, NULL, 0, src->tainted) < 0) return -1;

		while ((vb = fr_dlist_next(&src->vb_group, vb))) {
			/*
			 *	Attempt to cast to a string so
			 *	we can append.
			 */
			if (vb->type != FR_TYPE_STRING) {
				fr_value_box_t	tmp;
				int		ret;

				if (fr_value_box_cast(ctx, &tmp, FR_TYPE_STRING, NULL, vb) < 0) return -1;

				/*
				 *	Append and continue
				 */
				ret = fr_value_box_bstr_append_buffer(ctx, dst, tmp.vb_strvalue, tmp.tainted);
				fr_value_box_clear(&tmp);
				if (ret < 0) {
				error:
					fr_value_box_clear(dst);
					return -1;
				}
				continue;
			}

			if (fr_value_box_bstr_append_buffer(ctx, dst, vb->vb_strvalue, vb->tainted) < 0) goto error;
		}
	}
		return 0;

	/*
	 *	Get the presentation format
	 */
	default:
	{
		char *str;

		fr_value_box_aprint(ctx, &str, src, NULL);
		if (unlikely(!str)) return -1;

		return fr_value_box_bstrdup_buffer_shallow(NULL, dst, dst_enumv, str, src->tainted);
	}
	}
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
	if (!fr_cond_assert(dst_type == FR_TYPE_OCTETS)) return -1;

	switch (src->type) {
	/*
	 *	<string> (excluding terminating \0)
	 */
	case FR_TYPE_STRING:
		if (fr_value_box_memdup(ctx, dst, dst_enumv,
					(uint8_t const *)src->vb_strvalue, src->vb_length, src->tainted) < 0) {
			return -1;
		}
		return 0;

	case FR_TYPE_GROUP:
	{
		fr_value_box_t *vb = NULL;

		/*
		 *	Initialise an empty buffer we can
		 *	append to.
		 */
		if (fr_value_box_memdup(ctx, dst, dst_enumv, NULL, 0, src->tainted) < 0) return -1;

		while ((vb = fr_dlist_next(&src->vb_group, vb))) {
			/*
			 *	Attempt to cast to octets so
			 *	we can append;
			 */
			if (vb->type != FR_TYPE_OCTETS) {
				fr_value_box_t	tmp;
				int		ret;

				if (fr_value_box_cast(ctx, &tmp, FR_TYPE_OCTETS, NULL, vb) < 0) return -1;

				/*
				 *	Append and continue
				 */
				ret = fr_value_box_mem_append_buffer(ctx, dst, tmp.vb_octets, tmp.tainted);
				fr_value_box_clear(&tmp);
				if (ret < 0) {
				error:
					fr_value_box_clear(dst);
					return -1;
				}
				continue;
			}

			if (fr_value_box_mem_append_buffer(ctx, dst, vb->vb_octets, vb->tainted) < 0) goto error;
		}
		return 0;
	}

	/*
	 *	<4 bytes address>
	 */
	case FR_TYPE_IPV4_ADDR:
		return fr_value_box_memdup(ctx, dst, dst_enumv,
					   (uint8_t const *)&src->vb_ip.addr.v4.s_addr,
					   sizeof(src->vb_ip.addr.v4.s_addr), src->tainted);

	/*
	 *	<1 uint8 prefix> + <4 bytes address>
	 */
	case FR_TYPE_IPV4_PREFIX:
	{
		uint8_t *bin;

		if (fr_value_box_mem_alloc(ctx, &bin, dst, dst_enumv,
					   sizeof(src->vb_ip.addr.v4.s_addr) + 1, src->tainted) < 0) return -1;

		bin[0] = src->vb_ip.prefix;
		memcpy(&bin[1], (uint8_t const *)&src->vb_ip.addr.v4.s_addr, sizeof(src->vb_ip.addr.v4.s_addr));
	}
		return 0;

	/*
	 *	<16 bytes address>
	 */
	case FR_TYPE_IPV6_ADDR:
		return fr_value_box_memdup(ctx, dst, dst_enumv,
					   (uint8_t const *)src->vb_ip.addr.v6.s6_addr,
					   sizeof(src->vb_ip.addr.v6.s6_addr), src->tainted);

	/*
	 *	<1 uint8 prefix> + <1 uint8 scope> + <16 bytes address>
	 */
	case FR_TYPE_IPV6_PREFIX:
	{
		uint8_t *bin;

		if (fr_value_box_mem_alloc(ctx, &bin, dst, dst_enumv,
					   sizeof(src->vb_ip.addr.v6.s6_addr) + 2, src->tainted) < 0) return -1;
		bin[0] = src->vb_ip.scope_id;
		bin[1] = src->vb_ip.prefix;
		memcpy(&bin[2], src->vb_ip.addr.v6.s6_addr, sizeof(src->vb_ip.addr.v6.s6_addr));
	}
		return 0;

	/*
	 *	Get the raw binary in memory representation
	 */
	case FR_TYPE_NUMERIC:
	{
		fr_value_box_t tmp;

		fr_value_box_hton(&tmp, src);	/* Flip any numeric representations */
		return fr_value_box_memdup(ctx, dst, dst_enumv,
					   ((uint8_t const *)&tmp.datum) + fr_value_box_offsets[src->type],
					   fr_value_box_field_sizes[src->type], src->tainted);
	}

	default:
		/* Not the same talloc_memdup call as above.  The above memdup reads data from the dst */
		return fr_value_box_memdup(ctx, dst, dst_enumv,
					   ((uint8_t const *)&src->datum) + fr_value_box_offsets[src->type],
					   fr_value_box_field_sizes[src->type], src->tainted);
	}
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
	fr_assert(dst_type == FR_TYPE_IPV4_ADDR);

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length, '\0', src->tainted);

	default:
		break;
	}

	/*
	 *	Pre-initialise box for non-variable types
	 */
	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
	dst->vb_ip.af = AF_INET;
	dst->vb_ip.prefix = 32;
	dst->vb_ip.scope_id = 0;

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

	case FR_TYPE_OCTETS:
		if (src->vb_length != sizeof(dst->vb_ip.addr.v4.s_addr)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Needed octet string of length %zu, got %zu",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v4.s_addr), src->vb_length);
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
	fr_assert(dst_type == FR_TYPE_IPV4_PREFIX);

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				             src->vb_strvalue, src->vb_length, '\0', src->tainted);

	default:
		break;
	}

	/*
	 *	Pre-initialise box for non-variable types
	 */
	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
	dst->vb_ip.af = AF_INET;
	dst->vb_ip.scope_id = 0;

	switch (src->type) {
	case FR_TYPE_IPV4_ADDR:
		memcpy(&dst->vb_ip, &src->vb_ip, sizeof(dst->vb_ip));
		break;

	/*
	 *	Copy the last four bytes, to make an IPv4prefix
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

	case FR_TYPE_OCTETS:
		if (src->vb_length != sizeof(dst->vb_ip.addr.v4.s_addr) + 1) {
			fr_strerror_printf("Invalid cast from %s to %s.  Needed octet string of length %zu, got %zu",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v4.s_addr) + 1, src->vb_length);
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
	fr_assert(dst_type == FR_TYPE_IPV6_ADDR);

	static_assert((sizeof(v4_v6_map) + sizeof(src->vb_ip.addr.v4)) <=
		      sizeof(src->vb_ip.addr.v6), "IPv6 storage too small");

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length, '\0', src->tainted);

	default:
		break;
	}

	/*
	 *	Pre-initialise box for non-variable types
	 */
	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
	dst->vb_ip.af = AF_INET6;
	dst->vb_ip.prefix = 128;

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

	case FR_TYPE_OCTETS:
		if (src->vb_length != sizeof(dst->vb_ip.addr.v6.s6_addr)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Needed octet string of length %zu, got %zu",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v6.s6_addr), src->vb_length);
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
	fr_assert(dst_type == FR_TYPE_IPV6_PREFIX);

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length, '\0', src->tainted);

	default:
		break;
	}

	/*
	 *	Pre-initialise box for non-variable types
	 */
	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
	dst->vb_ip.af = AF_INET6;

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

	case FR_TYPE_OCTETS:
		if (src->vb_length != (sizeof(dst->vb_ip.addr.v6.s6_addr) + 2)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Needed octet string of length %zu, got %zu",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   sizeof(dst->vb_ip.addr.v6.s6_addr) + 2, src->vb_length);
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
	fr_assert(dst_type == FR_TYPE_ETHERNET);

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length, '\0', src->tainted);

	case FR_TYPE_OCTETS:
		return fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src);

	default:
		break;
	}

	/*
	 *	Pre-initialise box for non-variable types
	 */
	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);

	switch (src->type) {
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
	fr_assert(dst_type == FR_TYPE_BOOL);

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length, '\0', src->tainted);

	case FR_TYPE_OCTETS:
		return fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src);

	default:
		break;
	}

	/*
	 *	Pre-initialise box for non-variable types
	 */
	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);

	switch (src->type) {
	case FR_TYPE_INT8:
		dst->vb_bool = (src->vb_int8 != 0);
		break;

	case FR_TYPE_UINT8:
		dst->vb_bool = (src->vb_uint8 != 0);
		break;

	case FR_TYPE_INT16:
		dst->vb_bool = (src->vb_int16 != 0);
		break;

	case FR_TYPE_UINT16:
		dst->vb_bool = (src->vb_uint16 != 0);
		break;

	case FR_TYPE_INT32:
		dst->vb_bool = (src->vb_int32 != 0);
		break;

	case FR_TYPE_UINT32:
		dst->vb_bool = (src->vb_uint32 != 0);
		break;

	case FR_TYPE_INT64:
		dst->vb_bool = (src->vb_int64 != 0);
		break;

	case FR_TYPE_UINT64:
		dst->vb_bool = (src->vb_uint64 != 0);
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	return 0;
}

/** Convert any signed or unsigned integer type to any other signed or unsigned integer type
 *
 */
static inline int fr_value_box_cast_integer_to_integer(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst,
						       fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
						       fr_value_box_t const *src)
{
	uint64_t		tmp = 0;
	size_t			len = fr_value_box_field_sizes[src->type];
	int64_t			min;

#define SIGN_BIT_HIGH(_int, _len)	((((uint64_t)1) << (((_len) << 3) - 1)) & (_int))
#define SIGN_PROMOTE(_int, _len)	((_len) < sizeof(_int) ? \
					(_int) | (~((__typeof__(_int))0)) << ((_len) << 3) : (_int))

#if !defined(NDEBUG) || defined(__clang_analyzer__)
	/*
	 *	Helps catch invalid fr_value_box_field_sizes
	 *	entries, and shuts up clang analyzer.
	 */
	if (!fr_cond_assert_msg(len > 0, "Invalid cast from %s to %s. "
			        "invalid source type len, expected > 0, got %zu",
			        fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
			        fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
			        len)) return -1;

	if (!fr_cond_assert_msg(len <= sizeof(uint64_t),
				"Invalid cast from %s to %s. "
				"invalid source type len, expected <= %zu, got %zu",
				fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
				sizeof(uint64_t), len)) return -1;
#endif

	switch (src->type) {
	/*
	 *	Dates are always represented in nanoseconds
	 *	internally, but when we convert to another
	 *	integer type, we scale appropriately.
	 *
	 *	i.e. if the attribute value resolution is
	 *	seconds, then the integer value is
	 *	nanoseconds -> seconds.
	 */
	case FR_TYPE_DATE:
		if (dst->enumv) {
			switch (dst->enumv->flags.type_size) {
			date_src_seconds:
			default:
			case FR_TIME_RES_SEC:
				tmp = fr_unix_time_to_sec(src->vb_date);
				break;

			case FR_TIME_RES_USEC:
				tmp = fr_unix_time_to_usec(src->vb_date);
				break;

			case FR_TIME_RES_MSEC:
				tmp = fr_unix_time_to_msec(src->vb_date);
				break;

			case FR_TIME_RES_NSEC:
				tmp = src->vb_date;
				break;
			}
		} else goto date_src_seconds;
		break;

	/*
	 *	Same deal with time deltas.  Note that
	 *	even though we store the value as an
	 *	unsigned integer, it'll be cast to a
	 *	signed integer for comparisons.
	 */
	case FR_TYPE_TIME_DELTA:
		if (dst->enumv) {
			switch (dst->enumv->flags.type_size) {
			delta_src_seconds:
			default:
			case FR_TIME_RES_SEC:
				tmp = (uint64_t)fr_time_delta_to_sec(src->vb_time_delta);
				break;

			case FR_TIME_RES_USEC:
				tmp = (uint64_t)fr_time_delta_to_usec(src->vb_time_delta);
				break;

			case FR_TIME_RES_MSEC:
				tmp = (uint64_t)fr_time_delta_to_msec(src->vb_time_delta);
				break;

			case FR_TIME_RES_NSEC:
				tmp = (uint64_t)src->vb_time_delta;
				break;
			}
		} else goto delta_src_seconds;
		break;

	default:
#ifdef WORDS_BIGENDIAN
		memcpy(((uint8_t *)&tmp) + (sizeof(tmp) - len),
		       ((uint8_t const *)src) + fr_value_box_offsets[src->type], len);
#else
		memcpy(&tmp, src, len);
#endif
		break;
	}

	min = fr_value_box_integer_min[dst_type];
	if ((min < 0) && SIGN_BIT_HIGH(tmp, len)) {
		tmp = SIGN_PROMOTE(tmp, len);
		if (((int64_t)tmp < min)) {
			fr_strerror_printf("Invalid cast from %s to %s.  %"PRId64" "
					   "outside value range %"PRId64"-%"PRIu64,
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   (int64_t)tmp,
					   min, fr_value_box_integer_max[dst_type]);
			return -1;
		}
	} else if (tmp > fr_value_box_integer_max[dst_type]) {
		fr_strerror_printf("Invalid cast from %s to %s.  %"PRIu64" "
				   "outside value range 0-%"PRIu64,
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
				   tmp, fr_value_box_integer_max[dst_type]);
		return -1;
	}

	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
	switch (dst_type) {
	case FR_TYPE_DATE:
		if (dst->enumv) {
			switch (dst->enumv->flags.type_size) {
			date_dst_seconds:
			default:
			case FR_TIME_RES_SEC:
				dst->vb_date = fr_unix_time_from_sec((fr_unix_time_t)tmp);
				break;

			case FR_TIME_RES_USEC:
				dst->vb_date = fr_unix_time_from_usec((fr_unix_time_t)tmp);
				break;

			case FR_TIME_RES_MSEC:
				dst->vb_date = fr_unix_time_from_msec((fr_unix_time_t)tmp);
				break;

			case FR_TIME_RES_NSEC:
				dst->vb_date = fr_unix_time_from_nsec((fr_unix_time_t)tmp);
				break;
			}
		} else goto date_dst_seconds;
		break;

	case FR_TYPE_TIME_DELTA:
		if (dst->enumv) {
			switch (dst->enumv->flags.type_size) {
			delta_dst_seconds:
			default:
			case FR_TIME_RES_SEC:
				dst->vb_time_delta = fr_time_delta_from_sec((fr_time_delta_t)tmp);
				break;

			case FR_TIME_RES_USEC:
				dst->vb_time_delta = fr_time_delta_from_usec((fr_time_delta_t)tmp);
				break;

			case FR_TIME_RES_MSEC:
				dst->vb_time_delta = fr_time_delta_from_msec((fr_time_delta_t)tmp);
				break;

			case FR_TIME_RES_NSEC:
				dst->vb_time_delta = fr_time_delta_from_nsec((fr_time_delta_t)tmp);
				break;
			}
		 } else goto delta_dst_seconds;
		 break;

	default:
#ifdef WORDS_BIGENDIAN
		memcpy(((uint8_t *)dst) + fr_value_box_offsets[dst_type],
		       ((uint8_t *)&tmp) + (sizeof(tmp) - len), fr_value_box_field_sizes[dst_type]);
#else
		memcpy(((uint8_t *)dst) + fr_value_box_offsets[dst_type],
		       &tmp, fr_value_box_field_sizes[dst_type]);
#endif
		break;
	}

	return 0;
}

/** Convert any value to a signed or unsigned integer
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_integer(TALLOC_CTX *ctx, fr_value_box_t *dst,
					       fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					       fr_value_box_t const *src)
{
	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
				             src->vb_strvalue, src->vb_length, '\0', src->tainted);

	case FR_TYPE_OCTETS:
		return fr_value_box_fixed_size_from_octets(dst, dst_type, dst_enumv, src);

	case FR_TYPE_INTEGER:
		return fr_value_box_cast_integer_to_integer(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	{
		fr_value_box_t	tmp;

		switch (dst_type) {
		case FR_TYPE_UINT32:
		case FR_TYPE_INT64:
		case FR_TYPE_UINT64:
		case FR_TYPE_DATE:
		case FR_TYPE_TIME_DELTA:
			break;

		default:
			goto bad_cast;
		}

		fr_value_box_init(&tmp, FR_TYPE_UINT32, src->enumv, src->tainted);
		memcpy(&tmp.vb_uint32, &src->vb_ip.addr.v4, sizeof(tmp.vb_uint32));
		fr_value_box_hton(&tmp, &tmp);
		return fr_value_box_cast_integer_to_integer(ctx, dst, dst_type, dst_enumv, &tmp);
	}

	case FR_TYPE_ETHERNET:
	{
		fr_value_box_t	tmp;

		switch (dst_type) {
		case FR_TYPE_INT64:
		case FR_TYPE_UINT64:
		case FR_TYPE_DATE:
		case FR_TYPE_TIME_DELTA:
			break;

		default:
			goto bad_cast;
		}

		fr_value_box_init(&tmp, FR_TYPE_UINT64, src->enumv, src->tainted);
		memcpy(((uint8_t *)&tmp.vb_uint64) + (sizeof(tmp.vb_uint64) - sizeof(src->vb_ether)),
		       &src->vb_ether, sizeof(src->vb_ether));
#ifndef WORDS_BIGENDIAN
		/*
		 *	Ethernet addresses are always stored bigendian,
		 *	convert to native on little endian systems
		 */
		fr_value_box_hton(&tmp, &tmp);
#endif
		return fr_value_box_cast_integer_to_integer(ctx, dst, dst_type, dst_enumv, &tmp);
	}

	case FR_TYPE_IFID:
	{
		switch (dst_type) {
		case FR_TYPE_UINT64:
			break;

		default:
			goto bad_cast;
		}

		fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
		dst->vb_uint64 = fr_net_to_uint64(&src->vb_ifid[0]);
		return 0;
	}

	default:
		break;
	}

bad_cast:
	fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
			   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
			   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
	return -1;
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
 *			If #fr_value_box_t is passed to #fr_value_box_aprint
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
	if (!fr_cond_assert(dst_type != FR_TYPE_NULL)) return -1;
	if (!fr_cond_assert(src != dst)) return -1;
	if (!fr_cond_assert(src->type != FR_TYPE_NULL)) return -1;

	if (fr_dict_non_data_types[dst_type]) {
		fr_strerror_printf("Invalid cast from %s to %s.  Can only cast simple data types",
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

	case FR_TYPE_INTEGER_EXCEPT_BOOL:
		return fr_value_box_cast_to_integer(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
		break;

	/*
	 *	Invalid types for casting (should have been caught earlier)
	 */
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_STRUCTURAL:
	case FR_TYPE_NULL:
	case FR_TYPE_VOID:
	case FR_TYPE_MAX:
		fr_strerror_printf("Invalid cast from %s to %s.  Invalid destination type",
				   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Deserialise a fr_value_box_t
	 */
	if (src->type == FR_TYPE_STRING) return fr_value_box_from_str(ctx, dst, &dst_type, dst_enumv,
								      src->vb_strvalue,
								      src->vb_length, '\0', src->tainted);

	if (src->type == FR_TYPE_OCTETS) {
		fr_value_box_t tmp;

		if (src->vb_length < network_min_size(dst_type)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Source is length %zd is smaller than "
					   "destination type size %zd",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->vb_length,
					   network_min_size(dst_type));
			return -1;
		}

		if (src->vb_length > network_max_size(dst_type)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Source length %zd is greater than "
					   "destination type size %zd",
					   fr_table_str_by_value(fr_value_box_type_table, src->type, "<INVALID>"),
					   fr_table_str_by_value(fr_value_box_type_table, dst_type, "<INVALID>"),
					   src->vb_length,
					   network_max_size(dst_type));
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
		return 0;
	}

	memcpy(&dst->datum, &src->datum, fr_value_box_field_sizes[src->type]);

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
 *			If #fr_value_box_t is passed to #fr_value_box_aprint
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
	 *	Store list poiters to restore later - fr_value_box_cast clears them
	 */
	fr_dlist_t entry = {
		.next = vb->entry.next,
		.prev = vb->entry.prev
	};

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
	fr_value_box_copy_shallow(NULL, &tmp, vb);

	if (fr_value_box_cast(ctx, vb, dst_type, dst_enumv, &tmp) < 0) return -1;

	fr_value_box_clear(&tmp);	/* Clear out any old buffers */

	/*
	 *	Restore list pointers
	 */
	vb->entry.next = entry.next;
	vb->entry.prev = entry.prev;

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

/** Clear/free any existing value
 *
 * @note Do not use on uninitialised memory.
 *
 * @param[in] data to clear.
 */
void fr_value_box_clear_value(fr_value_box_t *data)
{
	switch (data->type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		talloc_free(data->datum.ptr);
		break;

	case FR_TYPE_GROUP:
		/*
		 *	Depth first freeing of children
		 *
		 *	This ensures orderly freeing, regardless
		 *	of talloc hierarchy.
		 */
		{
			fr_value_box_t	*vb = NULL;

			while ((vb = fr_dlist_next(&data->vb_group, vb))) {
				fr_value_box_clear_value(vb);
				talloc_free(vb);
			}
		}
		return;

	case FR_TYPE_NULL:
		return;

	default:
		break;
	}

	memset(&data->datum, 0, sizeof(data->datum));
}

/** Clear/free any existing value and metadata
 *
 * @note Do not use on uninitialised memory.
 *
 * @param[in] data to clear.
 */
void fr_value_box_clear(fr_value_box_t *data)
{
	fr_value_box_clear_value(data);
	fr_value_box_init(data, FR_TYPE_NULL, NULL, false);
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
	if (!fr_cond_assert(src->type != FR_TYPE_NULL)) return -1;

	switch (src->type) {
	default:
		memcpy(((uint8_t *)dst) + fr_value_box_offsets[src->type],
		       ((uint8_t const *)src) + fr_value_box_offsets[src->type],
		       fr_value_box_field_sizes[src->type]);
		fr_value_box_copy_meta(dst, src);
		break;

	case FR_TYPE_STRING:
	{
		char *str = NULL;

		/*
		 *	Zero length strings still have a one uint8 buffer
		 */
		str = talloc_bstrndup(ctx, src->vb_strvalue, src->vb_length);
		if (!str) {
			fr_strerror_const("Failed allocating string buffer");
			return -1;
		}
		dst->vb_strvalue = str;
		fr_value_box_copy_meta(dst, src);
	}
		break;

	case FR_TYPE_OCTETS:
	{
		uint8_t *bin = NULL;

		if (src->vb_length) {
			bin = talloc_memdup(ctx, src->vb_octets, src->vb_length);
			if (!bin) {
				fr_strerror_const("Failed allocating octets buffer");
				return -1;
			}
			talloc_set_type(bin, uint8_t);
		}
		dst->vb_octets = bin;
		fr_value_box_copy_meta(dst, src);
	}
		break;

	case FR_TYPE_GROUP:
	{
		fr_value_box_t *child = NULL;

		fr_value_box_copy_meta(dst, src);	/* Initialises group child dlist */

		while ((child = fr_dlist_next(&src->vb_group, child))) {
			fr_value_box_t *new;

			/*
			 *	Build out the child
			 */
			new = fr_value_box_alloc_null(ctx);
			if (unlikely(!new)) {
			group_error:
				fr_strerror_const("Failed duplicating group child");
				fr_dlist_talloc_free(&dst->vb_group);
				return -1;
			}

			/*
			 *	Populate it with the
			 *      data from the original
			 *	child.
			 */
			if (unlikely(fr_value_box_copy(new, new, child) < 0)) goto group_error;
			fr_dlist_insert_tail(&dst->vb_group, new);
		}
	}
		break;
	}

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
 */
void fr_value_box_copy_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t const *src)
{
	switch (src->type) {
	default:
		fr_value_box_copy(NULL, dst, src);
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		dst->datum.ptr = ctx ? talloc_reference(ctx, src->datum.ptr) : src->datum.ptr;
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
int fr_value_box_steal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t *src)
{
	if (!fr_cond_assert(src->type != FR_TYPE_NULL)) return -1;

	switch (src->type) {
	default:
		return fr_value_box_copy(ctx, dst, src);

	case FR_TYPE_STRING:
	{
		char const *str;

		str = talloc_steal(ctx, src->vb_strvalue);
		if (!str) {
			fr_strerror_const("Failed stealing string buffer");
			return -1;
		}
		talloc_set_type(str, char);
		dst->vb_strvalue = str;
		fr_value_box_copy_meta(dst, src);
		memset(&src->datum, 0, sizeof(src->datum));
	}
		return 0;

	case FR_TYPE_OCTETS:
	{
		uint8_t const *bin;

 		bin = talloc_steal(ctx, src->vb_octets);
		if (!bin) {
			fr_strerror_const("Failed stealing octets buffer");
			return -1;
		}
		talloc_set_type(bin, uint8_t);

		dst->vb_octets = bin;
		fr_value_box_copy_meta(dst, src);
		memset(&src->datum, 0, sizeof(src->datum));
	}
		return 0;

	case FR_TYPE_GROUP:
	{
		fr_value_box_t *child;

		while ((child = fr_dlist_pop_head(&src->vb_group))) {
			child = talloc_steal(ctx, child);
			if (unlikely(!child)) {
				fr_strerror_const("Failed stealing child");
				return -1;
			}
			fr_dlist_insert_tail(&dst->vb_group, child);
		}
	}
		return 0;
	}
}

/** Copy a nul terminated string to a #fr_value_box_t
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src 	a nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_strdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			char const *src, bool tainted)
{
	char const	*str;

	str = talloc_typed_strdup(ctx, src);
	if (!str) {
		fr_strerror_const("Failed allocating string buffer");
		return -1;
	}

	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = str;
	dst->vb_length = talloc_array_length(str) - 1;

	return 0;
}

/** Trim the length of the string buffer to match the length of the C string
 *
 * @param[in] ctx	to re-alloc the buffer in.
 * @param[in,out] vb	to trim.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_strtrim(TALLOC_CTX *ctx, fr_value_box_t *vb)
{
	size_t	len;
	char	*str;

	if (!fr_cond_assert(vb->type == FR_TYPE_STRING)) return -1;

	len = strlen(vb->vb_strvalue);
	str = talloc_realloc(ctx, UNCONST(char *, vb->vb_strvalue), char, len + 1);
	if (!str) {
		fr_strerror_const("Failed re-allocing string buffer");
		return -1;
	}
	vb->vb_length = len;

	return 0;
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

	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = str;
	dst->vb_length = talloc_array_length(str) - 1;

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

/** Assign a buffer containing a nul terminated string to a box, but don't copy it
 *
 * @param[in] dst	to assign string to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	to copy string from.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
void fr_value_box_strdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				 char const *src, bool tainted)
{
	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = src;
	dst->vb_length = strlen(src);
}

/** Alloc and assign an empty \0 terminated string to a #fr_value_box_t
 *
 * @param[in] ctx 	to allocate any new buffers in.
 * @param[out] out	if non-null where to write a pointer to the new buffer.
 * @param[in] dst 	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
 * @param[in] len	of buffer to allocate.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_bstr_alloc(TALLOC_CTX *ctx, char **out, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			   size_t len, bool tainted)
{
	char	*str;

	str = talloc_zero_array(ctx, char, len + 1);
	if (!str) {
		fr_strerror_const("Failed allocating string buffer");
		return -1;
	}
	str[len] = '\0';

	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = str;
	dst->vb_length = talloc_array_length(str) - 1;

	if (out) *out = str;

	return 0;
}

/** Change the length of a buffer already allocated to a value box
 *
 * @note Do not use on an uninitialised box.
 *
 * @param[in] ctx	to realloc buffer in.
 * @param[out] out	if non-null where to write a pointer to the new buffer.
 * @param[in] dst 	to realloc buffer for.
 * @param[in] len	to realloc to (don't include nul byte).
 * @return
 *	- 0 on success.
 *	 - -1 on failure.
 */
int fr_value_box_bstr_realloc(TALLOC_CTX *ctx, char **out, fr_value_box_t *dst, size_t len)
{
	size_t	clen;
	char	*cstr;
	char	*str;

	fr_assert(dst->type == FR_TYPE_STRING);

	memcpy(&cstr, &dst->vb_strvalue, sizeof(cstr));

	clen = talloc_array_length(dst->vb_strvalue) - 1;
	if (clen == len) return 0;	/* No change */

	str = talloc_realloc(ctx, cstr, char, len + 1);
	if (!str) {
		fr_strerror_printf("Failed reallocing value box buffer to %zu bytes", len + 1);
		return -1;
	}

	/*
	 *	Zero out the additional bytes
	 */
	if (clen < len) {
		memset(str + clen, '\0', (len - clen) + 1);
	} else {
		cstr[len] = '\0';
	}
	dst->vb_strvalue = str;
	dst->vb_length = len;

	if (out) *out = str;

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
		fr_strerror_const("Failed allocating string buffer");
		return -1;
	}

	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = str;
	dst->vb_length = len;

	return 0;
}

int fr_value_box_bstrndup_dbuff(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				fr_dbuff_t *dbuff, size_t len, bool tainted)
{
	char	*str;

	str = talloc_array(ctx, char, len + 1);
	if (!str) {
		fr_strerror_printf("Failed allocating string buffer");
		return -1;
	}

	if (fr_dbuff_out_memcpy((uint8_t *)str, dbuff, len) < 0) return -1;
	str[len] = '\0';

	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = str;
	dst->vb_length = len;

	return 0;
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
int fr_value_box_bstrdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			        char const *src, bool tainted)
{
	size_t	len;

	(void)talloc_get_type_abort_const(src, char);

	len = talloc_array_length(src);
	if ((len == 0) || (src[len - 1] != '\0')) {
		fr_strerror_const("Input buffer not \\0 terminated");
		return -1;
	}

	return fr_value_box_bstrndup(ctx, dst, enumv, src, len - 1, tainted);
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
	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = src;
	dst->vb_length = len;
}

/** Assign a talloced buffer containing a nul terminated string to a box, but don't copy it
 *
 * Adds a reference to the src buffer so that it cannot be freed until the ctx is freed.
 *
 * @param[in] ctx	to add reference from.  If NULL no reference will be added.
 * @param[in] dst	to assign string to.
 * @param[in] enumv	Aliases for values.
 * @param[in] src	to copy string from.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_bstrdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				        char const *src, bool tainted)
{
	size_t	len;

	(void) talloc_get_type_abort_const(src, char);

	len = talloc_array_length(src);
	if ((len == 0) || (src[len - 1] != '\0')) {
		fr_strerror_const("Input buffer not \\0 terminated");
		return -1;
	}

	fr_value_box_init(dst, FR_TYPE_STRING, enumv, tainted);
	dst->vb_strvalue = ctx ? talloc_reference(ctx, src) : src;
	dst->vb_length = len - 1;

	return 0;
}

/** Append bytes from a buffer to an existing #fr_value_box_t
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[in] dst	value box to append to.
 * @param[in] src	octets data to append.
 * @param[in] len	length of octets data.
 * @param[in] tainted	Whether src is tainted.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_value_box_bstrn_append(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, size_t len, bool tainted)
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

	ptr = dst->datum.ptr;
	if (!fr_cond_assert(ptr)) return -1;

	if (talloc_reference_count(ptr) > 0) {
		fr_strerror_printf("%s: Boxed value has too many references", __FUNCTION__);
		return -1;
	}

	nlen = dst->vb_length + len + 1;
	nptr = talloc_realloc(ctx, ptr, char, dst->vb_length + len + 1);
	if (!nptr) {
		fr_strerror_printf("%s: Realloc of %s array from %zu to %zu bytes failed",
				   __FUNCTION__, talloc_get_name(ptr), talloc_array_length(ptr), nlen);
		return -1;
	}
	talloc_set_type(nptr, char);
	ptr = nptr;

	memcpy(ptr + dst->vb_length, src, len);	/* Copy data into the realloced buffer */

	dst->tainted = dst->tainted || tainted;
	dst->datum.ptr = ptr;
	dst->vb_length += len;

	ptr[dst->vb_length] = '\0';

	return 0;
}

/** Append a talloced buffer to an existing fr_value_box_t
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[in] dst	value box to append to.
 * @param[in] src	string data to append.
 * @param[in] tainted	Whether src is tainted.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_value_box_bstr_append_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, bool tainted)
{
	size_t len;

	(void) talloc_get_type_abort_const(src, char);

	len = talloc_array_length(src);
	if ((len == 0) || (src[len - 1] != '\0')) {
		fr_strerror_const("Input buffer not \\0 terminated");
		return -1;
	}

	return fr_value_box_bstrn_append(ctx, dst, src, len - 1, tainted);
}

/** Pre-allocate an octets buffer for filling by the caller
 *
 * @note Buffer will not be zeroed, as it's assumed the caller will be filling it.
 *
 * @param[in] ctx	to allocate any new buffers in.
 * @param[out] out	If non-null will be filled with a pointer to the
 *			new buffer.
 * @param[in] dst	to assign new buffer to.
 * @param[in] enumv	Aliases for values.
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
int fr_value_box_mem_alloc(TALLOC_CTX *ctx, uint8_t **out, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			   size_t len, bool tainted)
{
	uint8_t *bin;

	bin = talloc_array(ctx, uint8_t, len);
	if (!bin) {
		fr_strerror_const("Failed allocating octets buffer");
		return -1;
	}
	talloc_set_type(bin, uint8_t);

	fr_value_box_init(dst, FR_TYPE_OCTETS, enumv, tainted);
	dst->vb_octets = bin;
	dst->vb_length = len;

	if (out) *out = bin;

	return 0;
}

/** Change the length of a buffer already allocated to a value box
 *
 * @note Do not use on an uninitialised box.
 *
 * @param[in] ctx	to realloc buffer in.
 * @param[out] out	if non-null where to write a pointer to the new buffer.
 * @param[in] dst 	to realloc buffer for.
 * @param[in] len	to realloc to.
 * @return
 *	- 0 on success.
 *	 - -1 on failure.
 */
int fr_value_box_mem_realloc(TALLOC_CTX *ctx, uint8_t **out, fr_value_box_t *dst, size_t len)
{
	size_t	clen;
	uint8_t	*cbin;
	uint8_t	*bin;

	fr_assert(dst->type == FR_TYPE_OCTETS);

	memcpy(&cbin, &dst->vb_octets, sizeof(cbin));

	clen = talloc_array_length(dst->vb_octets);
	if (clen == len) return 0;	/* No change */

	bin = talloc_realloc(ctx, cbin, uint8_t, len);
	if (!bin) {
		fr_strerror_printf("Failed reallocing value box buffer to %zu bytes", len);
		return -1;
	}

	/*
	 *	Zero out the additional bytes
	 */
	if (clen < len) memset(bin + clen, 0x00, len - clen);
	dst->vb_octets = bin;
	dst->vb_length = len;

	if (out) *out = bin;

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
int fr_value_box_memdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			uint8_t const *src, size_t len, bool tainted)
{
	uint8_t *bin;

	bin = talloc_memdup(ctx, src, len);
	if (!bin) {
		fr_strerror_const("Failed allocating octets buffer");
		return -1;
	}
	talloc_set_type(bin, uint8_t);

	fr_value_box_init(dst, FR_TYPE_OCTETS, enumv, tainted);
	dst->vb_octets = bin;
	dst->vb_length = len;

	return 0;
}

int fr_value_box_memdup_dbuff(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			      fr_dbuff_t *dbuff, size_t len, bool tainted)
{
	uint8_t *bin;

	bin = talloc_size(ctx, len);
	if (!bin) {
		fr_strerror_printf("Failed allocating octets buffer");
		return -1;
	}
	if (fr_dbuff_out_memcpy(bin, dbuff, len) < (ssize_t) len) return -1;
	talloc_set_type(bin, uint8_t);

	fr_value_box_init(dst, FR_TYPE_OCTETS, enumv, tainted);
	dst->vb_octets = bin;
	dst->vb_length = len;

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
int fr_value_box_memdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			       uint8_t const *src, bool tainted)
{
	(void) talloc_get_type_abort_const(src, uint8_t);

	return fr_value_box_memdup(ctx, dst, enumv, src, talloc_array_length(src), tainted);
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
void fr_value_box_memdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				 uint8_t const *src, size_t len, bool tainted)
{
	fr_value_box_init(dst, FR_TYPE_OCTETS, enumv, tainted);
	dst->vb_octets = src;
	dst->vb_length = len;
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
void fr_value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				        uint8_t const *src, bool tainted)
{
	(void) talloc_get_type_abort_const(src, uint8_t);

	fr_value_box_init(dst, FR_TYPE_OCTETS, enumv, tainted);
	dst->vb_octets = ctx ? talloc_reference(ctx, src) : src;
	dst->vb_length = talloc_array_length(src);
}

/** Append data to an existing fr_value_box_t
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[in] dst	value box to append to.
 * @param[in] src	octets data to append.
 * @param[in] len	length of octets data.
 * @param[in] tainted	Whether src is tainted.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_value_box_mem_append(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t const *src, size_t len, bool tainted)
{
	uint8_t *nptr;
	size_t nlen;

	if (len == 0) return 0;

	if (dst->type != FR_TYPE_OCTETS) {
		fr_strerror_printf("%s: Expected boxed value of type %s, got type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_OCTETS, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, dst->type, "<INVALID>"));
		return -1;
	}

	if (!fr_cond_assert(dst->datum.ptr)) return -1;

	if (talloc_reference_count(dst->datum.ptr) > 0) {
		fr_strerror_printf("%s: Boxed value has too many references", __FUNCTION__);
		return -1;
	}

	nlen = dst->vb_length + len;
	nptr = talloc_realloc(ctx, dst->datum.ptr, uint8_t, dst->vb_length + len);
	if (!nptr) {
		fr_strerror_printf("%s: Realloc of %s array from %zu to %zu bytes failed",
				   __FUNCTION__,
				   talloc_get_name(dst->datum.ptr),
				   talloc_array_length((uint8_t const *)dst->datum.ptr), nlen);
		return -1;
	}

	memcpy(nptr + dst->vb_length, src, len);	/* Copy data into the realloced buffer */

	dst->tainted = dst->tainted || tainted;
	dst->datum.ptr = nptr;
	dst->vb_length += len;

	return 0;
}

/** Append a talloc buffer to an existing fr_value_box_t
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[in] dst	value box to append to.
 * @param[in] src	octets data to append.
 * @param[in] tainted	Whether src is tainted.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_value_box_mem_append_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t const *src, bool tainted)
{
	return fr_value_box_mem_append(ctx, dst, src, talloc_array_length(src), tainted);
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

	if (!fr_cond_assert(*dst_type != FR_TYPE_NULL)) return -1;

	len = (inlen < 0) ? strlen(in) : (size_t)inlen;

	/*
	 *	Set size for all fixed length attributes.
	 */
	ret = network_max_size(*dst_type);

	/*
	 *	Lookup any names before continuing
	 */
	if (dst_enumv) {
		char		*tmp = NULL;
		char		*name;
		size_t		name_len;
		fr_dict_enum_t	*enumv;

		if (len > (sizeof(buffer) - 1)) {
			name_len = fr_value_str_aunescape(NULL, &tmp,
							  &FR_SBUFF_IN(in, len), SIZE_MAX, quote);
			name = tmp;
		} else {
			name_len = fr_value_str_unescape(&FR_SBUFF_OUT(buffer, sizeof(buffer)),
							 &FR_SBUFF_IN(in, len), SIZE_MAX, quote);
			name = buffer;
		}
		fr_assert(name);

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
		char *buff;

		ret = fr_value_str_aunescape(ctx, &buff, &FR_SBUFF_IN(in, len), SIZE_MAX, quote);
		talloc_get_type_abort(buff, char);
		dst->vb_strvalue = buff;
	}
		goto finish;

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
			fr_strerror_printf("Length of hex string is not even, got %zu bytes", len);
			return -1;
		}

		ret = len >> 1;
		p = talloc_array(ctx, uint8_t, ret);
		if (fr_hex2bin(NULL, &FR_DBUFF_TMP(p, ret), &FR_SBUFF_IN(in + 2, len), false) != (ssize_t)ret) {
			talloc_free(p);
			fr_strerror_const("Invalid hex data");
			return -1;
		}

		dst->vb_octets = p;
	}
		goto finish;

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

	case FR_TYPE_STRUCTURAL:
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
			fr_strerror_const("Temporary buffer too small");
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
			*dst_type = FR_TYPE_IPV4_ADDR;
			ret = network_min_size(*dst_type);
			break;

		case AF_INET6:
			*dst_type = FR_TYPE_IPV6_ADDR;
			ret = network_max_size(*dst_type);
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
	case FR_TYPE_VOID:
	case FR_TYPE_BAD:
		fr_strerror_printf("Unknown attribute dst_type %d", *dst_type);
		return -1;
	}

finish:
	dst->vb_length = ret;
	dst->type = *dst_type;
	dst->tainted = tainted;

	/*
	 *	Fixup enumvs
	 */
	dst->enumv = dst_enumv;
	fr_dlist_entry_init(&dst->entry);

	return 0;
}

/** Print one boxed value to a string
 *
 * This function should primarily be used when a #fr_value_box_t is being
 * serialized in some non-standard way, i.e. as a value for a field
 * in a database, in all other instances it's better to use
 * #fr_value_box_print_quoted.
 *
 * @param[in] out	Where to write the printed string.
 * @param[in] data	Value box to print.
 * @param[in] e_rules	To apply to FR_TYPE_STRING types.
 *			Is not currently applied to any other box type.
 */
ssize_t fr_value_box_print(fr_sbuff_t *out, fr_value_box_t const *data, fr_sbuff_escape_rules_t const *e_rules)
{
	fr_sbuff_t	our_out = FR_SBUFF_NO_ADVANCE(out);

	char		buf[1024];	/* Interim buffer to use with poorly behaved printing functions */

	if (!fr_cond_assert(data->type != FR_TYPE_NULL)) return 0;

	if (data->enumv && data->enumv->name) {
		char const *name;

		name = fr_dict_enum_name_by_value(data->enumv, data);
		if (name) {
			FR_SBUFF_IN_ESCAPE_BUFFER_RETURN(&our_out, name, NULL);
			goto done;
		}
	}

	switch (data->type) {
	case FR_TYPE_STRING:
		if (data->vb_length) FR_SBUFF_IN_ESCAPE_RETURN(&our_out,
								  data->vb_strvalue, data->vb_length, e_rules);
		break;

	case FR_TYPE_OCTETS:
		FR_SBUFF_IN_CHAR_RETURN(&our_out, '0', 'x');
		if (data->vb_length) FR_SBUFF_RETURN(fr_bin2hex, &our_out,
							&FR_DBUFF_TMP(data->vb_octets, data->vb_length), SIZE_MAX);
		break;

	/*
	 *	We need to use the proper inet_ntop functions for IP
	 *	addresses, else the output might not match output of
	 *	other functions, which makes testing difficult.
	 *
	 *	An example is tunneled ipv4 in ipv6 addresses.
	 */
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
		if (!fr_inet_ntop(buf, sizeof(buf), &data->vb_ip)) return 0;
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, buf);
		break;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
		if (!fr_inet_ntop_prefix(buf, sizeof(buf), &data->vb_ip)) return 0;
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, buf);
		break;

	case FR_TYPE_IFID:
		if (!fr_inet_ifid_ntop(buf, sizeof(buf), data->vb_ifid)) return 0;
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, buf);
		break;

	case FR_TYPE_ETHERNET:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%02x:%02x:%02x:%02x:%02x:%02x",
					   data->vb_ether[0], data->vb_ether[1],
					   data->vb_ether[2], data->vb_ether[3],
					   data->vb_ether[4], data->vb_ether[5]);
		break;

	case FR_TYPE_BOOL:
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, data->vb_uint8 ? "yes" : "no");
		break;

	case FR_TYPE_UINT8:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", data->vb_uint8);
		break;

	case FR_TYPE_UINT16:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", data->vb_uint16);
		break;

	case FR_TYPE_UINT32:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%u", data->vb_uint32);
		break;

	case FR_TYPE_UINT64:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%" PRIu64, data->vb_uint64);
		break;

	case FR_TYPE_INT8:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%d", data->vb_int8);
		break;

	case FR_TYPE_INT16:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%d", data->vb_int16);
		break;

	case FR_TYPE_INT32:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%d", data->vb_int32);
		break;

	case FR_TYPE_INT64:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%" PRId64, data->vb_int64);
		break;

	case FR_TYPE_FLOAT32:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%f", (double) data->vb_float32);
		break;

	case FR_TYPE_FLOAT64:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%g", data->vb_float64);
		break;

	case FR_TYPE_DATE:
	{
		int64_t 	subseconds;
		time_t		t;
		struct tm	s_tm;
		size_t		len;

		t = fr_unix_time_to_sec(data->vb_date);
		(void) gmtime_r(&t, &s_tm);

		if (!data->enumv || (data->enumv->flags.type_size == FR_TIME_RES_SEC)) {
			len = strftime(buf, sizeof(buf), "%b %e %Y %H:%M:%S UTC", &s_tm);
			FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, buf, len);
			goto done;
		}

		len = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &s_tm);
		FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, buf, len);
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
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%03" PRIi64, subseconds);
			break;

		case FR_TIME_RES_USEC:
			subseconds /= 1000;
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%06" PRIi64, subseconds);
			break;

		case FR_TIME_RES_NSEC:
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%09" PRIi64, subseconds);
			break;
		}

		/*
		 *	And time zone.
		 */
		if (s_tm.tm_gmtoff != 0) {
			int hours, minutes;

			hours = s_tm.tm_gmtoff / 3600;
			minutes = (s_tm.tm_gmtoff / 60) % 60;

			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%+03d:%02u", hours, minutes);
		} else {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, 'Z');
		}
		break;
	}

	case FR_TYPE_SIZE:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zu", data->datum.size);
		break;

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

		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%" PRIu64 ".%09" PRIu64, lhs, rhs);
		q = fr_sbuff_current(&our_out) - 1;

		/*
		 *	Truncate trailing zeros.
		 */
		while (*q == '0') *(q--) = '\0';

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
		fr_sbuff_set(&our_out, q);
	}
		break;

	case FR_TYPE_GROUP:
	{
		fr_value_box_t	*child = NULL;
		ssize_t		slen;

		FR_SBUFF_IN_CHAR_RETURN(&our_out, '{');

		while ((child = fr_dlist_next(&data->vb_group, child))) {
			slen = fr_value_box_print(&our_out, child, e_rules);
			if (slen < 0) return slen;

			if (fr_dlist_next(&data->vb_group, child)) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, ", ");
		}

		FR_SBUFF_IN_CHAR_RETURN(&our_out, '}');
	}
		break;

	/*
	 *	Don't add default here
	 */
	case FR_TYPE_TLV:		/* Not a box type */
	case FR_TYPE_STRUCT:		/* Not a box type */
	case FR_TYPE_VSA:		/* Not a box type */
	case FR_TYPE_VENDOR:		/* Not a box type */
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_VOID:
	case FR_TYPE_BAD:
		(void)fr_cond_assert(0);
		return 0;
	}

done:
	return fr_sbuff_set(out, &our_out);
}

/** Print one boxed value to a string with quotes (where needed)
 *
 * @param[in] out	Where to write the printed string.
 * @param[in] data	Value box to print.
 * @param[in] quote	To apply to FR_TYPE_STRING types.
 *			Is not currently applied to any
 *			other box type.
 */
ssize_t fr_value_box_print_quoted(fr_sbuff_t *out, fr_value_box_t const *data, fr_token_t quote)
{
	fr_sbuff_t	our_out = FR_SBUFF_NO_ADVANCE(out);

	if (quote == T_BARE_WORD) return fr_value_box_print(out, data, NULL);

	switch (data->type) {
	case FR_TYPE_QUOTED:
		FR_SBUFF_IN_CHAR_RETURN(&our_out, fr_token_quote[quote]);
		FR_SBUFF_RETURN(fr_value_box_print, &our_out, data, fr_value_escape_by_quote[quote]);
		FR_SBUFF_IN_CHAR_RETURN(&our_out, fr_token_quote[quote]);
		break;

	default:
		return fr_value_box_print(out, data, NULL);
	}

	return fr_sbuff_set(out, &our_out);
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
			     fr_value_box_t *out, fr_value_box_list_t *list, fr_type_t type, bool free_input)
{
	TALLOC_CTX		*pool;
	fr_dcursor_t		cursor;
	fr_value_box_t const	*vb;
	fr_value_box_t		*head_vb;

	if (!list || fr_dlist_empty(list)) {
		fr_strerror_const("Invalid arguments.  List was NULL");
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

	head_vb = fr_dlist_head(list);
	fr_dcursor_init(&cursor, list);

	/*
	 *	Allow concatenating in place
	 */
	if (out == head_vb) {
		if (head_vb->type != type) {
			fr_value_box_t from_cast;
			fr_dlist_t entry = {
				.next = out->entry.next,
				.prev = out->entry.prev
			};

			/*
			 *	Two phase, as the casting code doesn't
			 *	allow 'cast-in-place'.
			 */
			if (fr_value_box_cast(ctx, &from_cast, type, NULL, out) < 0) return -1;
			if (fr_value_box_copy(ctx, out, &from_cast) < 0) return -1;

			out->entry.next = entry.next;		/* Restore the list pointers */
			out->entry.prev = entry.prev;

		}
		fr_dcursor_next(&cursor);
	} else {
		if (fr_value_box_cast(ctx, out, type, NULL, head_vb) < 0) return -1;	/* Decomposes to copy */

		if (free_input) {
			fr_dcursor_free_item(&cursor);		/* Advances cursor */
		} else {
			fr_dcursor_next(&cursor);
		}
	}

	/*
	 *	Imploding a one element list.
	 */
	if (!fr_dcursor_current(&cursor)) return 0;

	pool = talloc_pool(NULL, 255);	/* To absorb the temporary strings */

	/*
	 *	Join the remaining values
	 */
	while ((vb = fr_dcursor_current(&cursor))) {
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
			if (fr_value_box_bstrn_append(ctx, out, n->vb_strvalue, n->vb_length, n->tainted) < 0) goto error;
		} else {
			if (fr_value_box_mem_append(ctx, out, n->vb_octets, n->vb_length, n->tainted) < 0) goto error;
		}

		if (free_input) {
			fr_dcursor_free_item(&cursor);		/* Advances cursor */
		} else {
			fr_dcursor_next(&cursor);
		}
	}

	talloc_free(pool);

	return 0;
}

/** Concatenate the string representations of a list of value boxes together
 *
 * @param[in] ctx	to allocate the buffer in.
 * @param[in] list	of value boxes.
 * @param[in] delim	to insert between value box values.
 * @param[in] e_rules	to control escaping of the concatenated elements.
 * @return
 *	- NULL on error.
 *	- The concatenation of the string values of the value box list on success.
 */
char *fr_value_box_list_aprint(TALLOC_CTX *ctx, fr_value_box_list_t const *list, char const *delim,
			       fr_sbuff_escape_rules_t const *e_rules)
{
	fr_value_box_t const	*vb = fr_dlist_head(list);
	char			*aggr, *td = NULL;
	TALLOC_CTX		*pool = NULL;

	if (!vb) return NULL;

	fr_value_box_aprint(ctx, &aggr, vb, e_rules);
	if (!aggr) return NULL;
	if (!fr_dlist_next(list, vb)) return aggr;

	/*
	 *	If we're aggregating more values,
	 *	allocate a temporary pool.
	 */
	pool = talloc_pool(NULL, 255);
	if (delim) td = talloc_typed_strdup(pool, delim);

	while ((vb = fr_dlist_next(list, vb))) {
		char *str, *new_aggr;

		fr_value_box_aprint(pool, &str, vb, e_rules);
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

/** Hash the contents of a value box
 *
 */
uint32_t fr_value_box_hash_update(fr_value_box_t const *vb, uint32_t hash)
{
	switch (vb->type) {
	case FR_TYPE_FIXED_SIZE:
		return fr_hash_update(((uint8_t const *)vb) + fr_value_box_offsets[vb->type],
				      fr_value_box_field_sizes[vb->type], hash);

	case FR_TYPE_STRING:
		return fr_hash_update(vb->vb_strvalue, vb->vb_length, hash);

	case FR_TYPE_OCTETS:
		return fr_hash_update(vb->vb_octets, vb->vb_length, hash);

	default:
		break;
	}
	return hash;
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
int fr_value_box_list_acopy(TALLOC_CTX *ctx, fr_value_box_list_t *out, fr_value_box_list_t const *in)
{
	fr_value_box_t const *in_p = NULL;

	while ((in_p = fr_dlist_next(in, in_p))) {
	     	fr_value_box_t *n = NULL;

		n = fr_value_box_alloc_null(ctx);
		if (!n) {
		error:
			fr_dlist_talloc_free(out);
			return -1;
		}

		if (fr_value_box_copy(n, n, in_p) < 0) goto error;
		fr_dlist_insert_tail(out, n);
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
bool fr_value_box_list_tainted(fr_value_box_list_t const *head)
{
	fr_value_box_t *vb = NULL;

	if (fr_dlist_empty(head)) return false;

	while ((vb = fr_dlist_next(head, vb))) {
		if (vb->tainted) return true;
	}

	return false;
}

/** Validation function to check that a fr_value_box_t is correctly initialised
 *
 */
void value_box_verify(char const *file, int line, fr_value_box_t const *vb, bool talloced)
{
	fr_fatal_assert_msg(vb, "CONSISTENCY CHECK FAILED %s[%i]: fr_value_box_t pointer was NULL", file, line);

	if (talloced) vb = talloc_get_type_abort_const(vb, fr_value_box_t);

	switch (vb->type) {
	case FR_TYPE_STRING:
		fr_fatal_assert_msg(vb->vb_strvalue, "CONSISTENCY CHECK FAILED %s[%i]: fr_value_box_t strvalue field "
				    "was NULL", file, line);
		fr_fatal_assert_msg(vb->vb_strvalue[vb->vb_length] == '\0',
				    "CONSISTENCY CHECK FAILED %s[%i]: fr_value_box_t strvalue field "
				    "not null terminated", file, line);
		break;

	case FR_TYPE_OCTETS:
		fr_fatal_assert_msg(vb->vb_octets, "CONSISTENCY CHECK FAILED %s[%i]: fr_value_box_t octets field "
				    "was NULL", file, line);
		break;

	case FR_TYPE_VOID:
		fr_fatal_assert_msg(vb->vb_void, "CONSISTENCY CHECK FAILED %s[%i]: fr_value_box_t ptr field "
				    "was NULL", file, line);
		break;

	case FR_TYPE_GROUP:
		value_box_list_verify(file, line, &vb->vb_group, talloced);
		break;

	default:
		break;
	}
}

void value_box_list_verify(char const *file, int line, fr_value_box_list_t const *list, bool talloced)
{
	fr_value_box_t const *vb = NULL;

	while ((vb = fr_dlist_next(list, vb))) value_box_verify(file, line, vb, talloced);
}
