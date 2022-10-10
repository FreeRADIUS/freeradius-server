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
 *   - #fr_value_box_from_substr is used to convert from PRESENTATION to INTERNAL format.
 *
 * @copyright 2014-2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#define _VALUE_PRIVATE
#include <freeradius-devel/util/value.h>
#undef _VALUE_PRIVATE

#include <freeradius-devel/util/ascend.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/size.h>
#include <freeradius-devel/util/time.h>

#include <math.h>

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
	[FR_TYPE_NULL]				= {~0, 0},

	[FR_TYPE_STRING]			= {0, ~0},
	[FR_TYPE_OCTETS]			= {0, ~0},

	[FR_TYPE_IPV4_ADDR]			= {4, 4},
	[FR_TYPE_IPV4_PREFIX]			= {5, 5},
	[FR_TYPE_IPV6_ADDR]			= {16, 17},
	[FR_TYPE_IPV6_PREFIX]			= {17, 18},
	[FR_TYPE_COMBO_IP_ADDR]			= {4, 17},
	[FR_TYPE_COMBO_IP_PREFIX]		= {16, 18},
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

fr_sbuff_unescape_rules_t *fr_value_unescape_by_char[UINT8_MAX + 1] = {
	['"']	= &fr_value_unescape_double,
	['\'']	= &fr_value_unescape_single,
	['/']	= &fr_value_unescape_solidus,
	['`']	= &fr_value_unescape_backtick,
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

fr_sbuff_escape_rules_t *fr_value_escape_by_char[UINT8_MAX + 1] = {
	['"']	= &fr_value_escape_double,
	['\'']	= &fr_value_escape_single,
	['/']	= &fr_value_escape_solidus,
	['`']	= &fr_value_escape_backtick,
};

fr_sbuff_escape_rules_t fr_value_escape_unprintables = {
	.name = "unprintables",
	.chr = '\\',
	.subs = {
		['\\'] = '\\',
	},
	.esc = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	},
	.do_utf8 = true,
	.do_oct = true
};


/** @name Produce a #tmpl_t from a string or substring
 *
 * @{
 */

/* clang-format off */
/** Default formatting rules
 *
 * Control token termination, escaping and how the tmpl is printed.
 */
fr_sbuff_parse_rules_t const value_parse_rules_bareword_unquoted = {

};

fr_sbuff_parse_rules_t const value_parse_rules_double_unquoted = {
	.escapes = &fr_value_unescape_double
};

fr_sbuff_parse_rules_t const value_parse_rules_single_unquoted = {
	.escapes = &fr_value_unescape_single
};

fr_sbuff_parse_rules_t const value_parse_rules_solidus_unquoted = {
	.escapes = &fr_value_unescape_solidus
};

fr_sbuff_parse_rules_t const value_parse_rules_backtick_unquoted = {
	.escapes = &fr_value_unescape_backtick
};

/** Parse rules for non-quoted strings
 *
 * These parse rules should be used for processing escape sequences in
 * data from external data sources like SQL databases and REST APIs.
 *
 * They do not include terminals to stop parsing as it assumes the values
 * are discreet, and not wrapped in quotes.
 */
fr_sbuff_parse_rules_t const *value_parse_rules_unquoted[T_TOKEN_LAST] = {
	[T_BARE_WORD]			= &value_parse_rules_bareword_unquoted,
	[T_DOUBLE_QUOTED_STRING]	= &value_parse_rules_double_unquoted,
	[T_SINGLE_QUOTED_STRING]	= &value_parse_rules_single_unquoted,
	[T_SOLIDUS_QUOTED_STRING]	= &value_parse_rules_solidus_unquoted,
	[T_BACK_QUOTED_STRING]		= &value_parse_rules_backtick_unquoted
};

fr_sbuff_parse_rules_t const *value_parse_rules_unquoted_char[UINT8_MAX] = {
	['\0']				= &value_parse_rules_bareword_unquoted,
	['"']				= &value_parse_rules_double_unquoted,
	['\'']				= &value_parse_rules_single_unquoted,
	['/']				= &value_parse_rules_solidus_unquoted,
	['`']				= &value_parse_rules_backtick_unquoted
};

fr_sbuff_parse_rules_t const value_parse_rules_bareword_quoted = {
	.escapes = &(fr_sbuff_unescape_rules_t){
		.chr = '\\',
		/*
		 *	Allow barewords to contain whitespace
		 *	if they're escaped.
		 */
		.subs = {
			['\t'] = '\t',
			['\n'] = '\n',
			[' '] = ' '
		},
		.do_hex = false,
		.do_oct = false
	},
	.terminals = &FR_SBUFF_TERMS(
		L("\t"),
		L("\n"),
		L(" ")
	)
};

fr_sbuff_parse_rules_t const value_parse_rules_double_quoted = {
	.escapes = &fr_value_unescape_double,
	.terminals = &FR_SBUFF_TERM("\"")
};

fr_sbuff_parse_rules_t const value_parse_rules_single_quoted = {
	.escapes = &fr_value_unescape_single,
	.terminals = &FR_SBUFF_TERM("'")
};

fr_sbuff_parse_rules_t const value_parse_rules_solidus_quoted = {
	.escapes = &fr_value_unescape_solidus,
	.terminals = &FR_SBUFF_TERM("/")
};

fr_sbuff_parse_rules_t const value_parse_rules_backtick_quoted = {
	.escapes = &fr_value_unescape_backtick,
	.terminals = &FR_SBUFF_TERM("`")
};

/** Parse rules for quoted strings
 *
 * These parse rules should be used for internal parsing functions that
 * are working with configuration files.
 *
 * They include appropriate quote terminals to force functions parsing
 * quoted strings to return when they reach a quote character.
 */
fr_sbuff_parse_rules_t const *value_parse_rules_quoted[T_TOKEN_LAST] = {
	[T_BARE_WORD]			= &value_parse_rules_bareword_quoted,
	[T_DOUBLE_QUOTED_STRING]	= &value_parse_rules_double_quoted,
	[T_SINGLE_QUOTED_STRING]	= &value_parse_rules_single_quoted,
	[T_SOLIDUS_QUOTED_STRING]	= &value_parse_rules_solidus_quoted,
	[T_BACK_QUOTED_STRING]		= &value_parse_rules_backtick_quoted
};

fr_sbuff_parse_rules_t const *value_parse_rules_quoted_char[UINT8_MAX] = {
	['\0']				= &value_parse_rules_bareword_quoted,
	['"']				= &value_parse_rules_double_quoted,
	['\'']				= &value_parse_rules_single_quoted,
	['/']				= &value_parse_rules_solidus_quoted,
	['`']				= &value_parse_rules_backtick_quoted
};
/* clang-format on */
/** @} */

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
	dst->safe = src->safe;
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
int8_t fr_value_box_cmp(fr_value_box_t const *a, fr_value_box_t const *b)
{
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
			int cmp = memcmp(a->datum.ptr, b->datum.ptr, length);
			if (cmp != 0) return CMP(cmp, 0);
		}

		/*
		 *	Contents are the same.  The return code
		 *	is therefore the difference in lengths.
		 *
		 *	i.e. "0x00" is smaller than "0x0000"
		 */
		return CMP(a->vb_length, b->vb_length);
	}

	/*
	 *	Short-hand for simplicity.
	 */
#define RETURN(_type) return CMP(a->datum._type, b->datum._type)
#define COMPARE(_type) return CMP(memcmp(&a->datum._type, &b->datum._type, sizeof(a->datum._type)), 0);

	case FR_TYPE_BOOL:
		RETURN(boolean);

	case FR_TYPE_DATE:
		return fr_unix_time_cmp(a->datum.date, b->datum.date);

	case FR_TYPE_UINT8:
		RETURN(uint8);

	case FR_TYPE_UINT16:
		RETURN(uint16);

	case FR_TYPE_UINT32:
		RETURN(uint32);

	case FR_TYPE_UINT64:
		RETURN(uint64);

	case FR_TYPE_INT8:
		RETURN(int8);

	case FR_TYPE_INT16:
		RETURN(int16);

	case FR_TYPE_INT32:
		RETURN(int32);

	case FR_TYPE_INT64:
		RETURN(int64);

	case FR_TYPE_SIZE:
		RETURN(size);

	case FR_TYPE_TIME_DELTA:
		return fr_time_delta_cmp(a->datum.time_delta, b->datum.time_delta);

	case FR_TYPE_FLOAT32:
		RETURN(float32);

	case FR_TYPE_FLOAT64:
		RETURN(float64);

	case FR_TYPE_ETHERNET:
		COMPARE(ether);

	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		return fr_ipaddr_cmp(&a->vb_ip, &b->vb_ip);

	case FR_TYPE_IFID:
		COMPARE(ifid);

	/*
	 *	These should be handled at some point
	 */
	case FR_TYPE_NON_LEAF:
		(void)fr_cond_assert(0);	/* unknown type */
		return -2;

	/*
	 *	Do NOT add a default here, as new types are added
	 *	static analysis will warn us they're not handled
	 */
	}
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
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_SIZE:
		fr_value_box_copy(NULL, dst, src);
		return 0;

	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	case FR_TYPE_NON_LEAF:
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
		dst->vb_int16 = htons(src->vb_int16);
		break;

	case FR_TYPE_INT32:
		dst->vb_int32 = htonl(src->vb_int32);
		break;

	case FR_TYPE_INT64:
		dst->vb_int64 = htonll(src->vb_int64);
		break;

	case FR_TYPE_DATE:
		dst->vb_date = fr_unix_time_wrap(htonll(fr_unix_time_unwrap(src->vb_date)));
		break;

	case FR_TYPE_TIME_DELTA:
		dst->vb_time_delta = fr_time_delta_wrap(htonll(fr_time_delta_unwrap(src->vb_time_delta)));
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
size_t fr_value_box_network_length(fr_value_box_t const *value)
{
	switch (value->type) {
	case FR_TYPE_VARIABLE_SIZE:
		if (value->enumv) {
			/*
			 *	Fixed-width fields.
			 */
			if (value->enumv->flags.length) {
				return value->enumv->flags.length;
			}

			/*
			 *	Clamp length at maximum we're allowed to encode.
			 */
			if (da_is_length_field(value->enumv)) {
				if (value->enumv->flags.subtype == FLAG_LENGTH_UINT8) {
					if (value->vb_length > 255) return 255;

				} else if (value->enumv->flags.subtype == FLAG_LENGTH_UINT16) {
					if (value->vb_length > 65535) return 65535;
				}
			}
		}
		return value->vb_length;

		/*
		 *	These can have different encodings, depending on the underlying protocol.
		 */
	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (value->enumv) return value->enumv->flags.length;

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
 * This function will not encode stuctural types (TLVs, VSAs etc...).  These are usually
 * specific to the protocol anyway.
 *
 *  All of the dictionary rules are respected.  string/octets can have
 *  a fixed length (which is zero-padded if necessary), or can have an
 *  8/16-bit "length" prefix.
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
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	/*
	 *	We cannot encode structural types here.
	 */
	if (!fr_type_is_leaf(value->type)) {
	unsupported:
		fr_strerror_printf("%s: Cannot encode type \"%s\"",
				   __FUNCTION__,
				   fr_type_to_str(value->type));
		return FR_VALUE_BOX_NET_ERROR;
	}

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
		if (value->enumv) {
			if (value->enumv->flags.length) {
				/*
				 *	The field is fixed size, and the data is smaller than that,  We zero-pad the field.
				 */
				if (max < value->enumv->flags.length) {
					FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)value->datum.ptr, max);
					FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, value->enumv->flags.length - max);
					return fr_dbuff_set(dbuff, &work_dbuff);

				} else if (max > value->enumv->flags.length) {
					/*
					 *	Truncate the input to the maximum allowed length.
					 */
					max = value->enumv->flags.length;
				}

			} else if (da_is_length_field(value->enumv)) {
				/*
				 *	Truncate the output to the max allowed for this field and encode the length.
				 */
				if (value->enumv->flags.subtype == FLAG_LENGTH_UINT8) {
					if (max > 255) max = 255;
					fr_dbuff_in(&work_dbuff, (uint8_t) max);

				} else if (value->enumv->flags.subtype == FLAG_LENGTH_UINT16) {
					if (max > 65536) max = 65535;
					fr_dbuff_in(&work_dbuff, (uint16_t) max);

				} else {
					return -1;
				}
			}
		}

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)value->datum.ptr, max);
		return fr_dbuff_set(dbuff, &work_dbuff);

		/*
		 *	The data can be encoded in a variety of widths.
		 */
	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (value->enumv) {
			min = value->enumv->flags.length;
		} else {
			min = 4;
		}
		break;

	default:
		min = network_min_size(value->type);
		break;
	}

	/*
	 *	We have to encode actual data here.
	 */
	fr_assert(min > 0);

	switch (value->type) {
	case FR_TYPE_IPV4_ADDR:
	ipv4addr:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff,
					  (uint8_t const *)&value->vb_ip.addr.v4.s_addr,
					  sizeof(value->vb_ip.addr.v4.s_addr));
		break;
	/*
	 *	Needs special mangling
	 */
	case FR_TYPE_IPV4_PREFIX:
	ipv4prefix:
		FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff,
					  (uint8_t const *)&value->vb_ip.addr.v4.s_addr,
					  sizeof(value->vb_ip.addr.v4.s_addr));
		break;

	case FR_TYPE_IPV6_ADDR:
	ipv6addr:
		if (value->vb_ip.scope_id > 0) FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.scope_id);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value->vb_ip.addr.v6.s6_addr, sizeof(value->vb_ip.addr.v6.s6_addr));
		break;

	case FR_TYPE_IPV6_PREFIX:
	ipv6prefix:
		if (value->vb_ip.scope_id > 0) FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.scope_id);
		FR_DBUFF_IN_RETURN(&work_dbuff, value->vb_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, value->vb_ip.addr.v6.s6_addr, sizeof(value->vb_ip.addr.v6.s6_addr));
		break;

	case FR_TYPE_BOOL:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, value->datum.boolean);
		break;

	case FR_TYPE_COMBO_IP_ADDR:
		switch (value->vb_ip.af) {
		case AF_INET:
			goto ipv4addr;

		case AF_INET6:
			goto ipv6addr;

		default:
			break;
		}

		fr_strerror_const("Combo IP value missing af");
		return 0;

	case FR_TYPE_COMBO_IP_PREFIX:
		switch (value->vb_ip.af) {
		case AF_INET:
			goto ipv4prefix;

		case AF_INET6:
			goto ipv6prefix;

		default:
			break;
		}

		fr_strerror_const("Combo IP value missing af");
		return 0;

	/*
	 *	Already in network byte-order
	 */
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_UINT8:
	case FR_TYPE_INT8:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, fr_value_box_raw(value, value->type), min);
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

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, fr_value_box_raw(&tmp, value->type), min);
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
		uint64_t date = 0;
		fr_time_res_t res;

		if (!value->enumv) {
			res = FR_TIME_RES_SEC;
		} else {
			res = value->enumv->flags.flag_time_res;
		}
		date = fr_unix_time_to_integer(value->vb_date, res);

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
		int64_t date = 0;	/* may be negative */
		fr_time_res_t res = FR_TIME_RES_SEC;
		if (value->enumv) res = value->enumv->flags.flag_time_res;

		date = fr_time_delta_to_integer(value->vb_time_delta, res);

		if (!value->enumv) {
			goto delta_size4;

		} else if (!value->enumv->flags.is_unsigned) {
			switch (value->enumv->flags.length) {
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
		} else {	/* time delta is unsigned! */
			switch (value->enumv->flags.length) {
			case 2:
				if (date < 0) {
					date = 0;
				} else if (date > UINT16_MAX) {
					date = UINT16_MAX;
				}
				FR_DBUFF_IN_RETURN(&work_dbuff, (uint16_t)date);
				break;

			case 4:
				if (date < 0) {
					date = 0;
				} else if (date > UINT32_MAX) {
					date = UINT32_MAX;
				}
				FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t)date);
				break;

			case 8:
				FR_DBUFF_IN_RETURN(&work_dbuff, (uint64_t)date);
				break;

			default:
				goto unsupported;
			}
		}
	}
		break;

	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
	case FR_TYPE_SIZE:
	case FR_TYPE_NON_LEAF:
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
 *  All of the dictionary rules are respected.  string/octets can have
 *  a fixed length, or can have an 8/16-bit "length" prefix.  If the
 *  enumv is not an array, then the input # len MUST be the correct size
 *  (not too large or small), otherwise an error is returned.
 *
 *  If the enumv is an array, then the input must have the minimum
 *  length, and the number of bytes decoded is capped at the maximum
 *  length allowed to be decoded.  This behavior allows the caller to
 *  decode an array of values simply by calling this function in a
 *  loop.
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[out] dst	value_box to write the result to.
 * @param[in] type	to decode data to.
 * @param[in] enumv	Aliases for values.
 * @param[in] dbuff	Binary data to decode.
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
				  fr_dbuff_t *dbuff, size_t len,
				  bool tainted)
{
	size_t		min, max;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	min = network_min_size(type);
	max = network_max_size(type);

	if (len < min) {
		fr_strerror_printf("Got truncated value parsing type \"%s\". "
				   "Expected length >= %zu bytes, got %zu bytes",
				   fr_type_to_str(type),
				   min, len);
		return -(len);
	}

	/*
	 *	For array entries, we only decode one value at a time.
	 */
	if (len > max) {
		if (enumv && !enumv->flags.array) {
			fr_strerror_printf("Found trailing garbage parsing type \"%s\". "
					   "Expected length <= %zu bytes, got %zu bytes",
					   fr_type_to_str(type),
				   max, len);
			return -(max);
		}

		len = max;
	}

	/*
	 *	String / octets are special.
	 */
	if (fr_type_is_variable_size(type)) {
		size_t newlen = len;
		size_t offset = 0;

		/*
		 *	Decode fixed-width fields.
		 */
		if (enumv) {
			if (enumv->flags.length) {
				newlen = enumv->flags.length;

			} else if (da_is_length_field(enumv)) {
				/*
				 *	Or fields with a length prefix.
				 */
				if (enumv->flags.subtype == FLAG_LENGTH_UINT8) {
					uint8_t num = 0;

					FR_DBUFF_OUT_RETURN(&num, &work_dbuff);
					newlen = num;
					offset = 1;

				} else if (enumv->flags.subtype == FLAG_LENGTH_UINT16) {
					uint16_t num = 0;

					FR_DBUFF_OUT_RETURN(&num, &work_dbuff);
					newlen = num;
					offset = 2;

				} else {
					return -1;
				}
			}
		}

		/*
		 *	If we need more data than exists, that's an error.
		 *
		 *	Otherwise, bound the decoding to the count we found.
		 */
		if (newlen > len) return -(newlen + offset);
		len = newlen;

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
			return -1;
		}
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
	ipv4addr:
		dst->vb_ip = (fr_ipaddr_t){
			.af = AF_INET,
			.prefix = 32,
		};
		FR_DBUFF_OUT_MEMCPY_RETURN((uint8_t *)&dst->vb_ip.addr.v4, &work_dbuff, len);
		break;

	case FR_TYPE_IPV4_PREFIX:
	ipv4prefix:
		dst->vb_ip = (fr_ipaddr_t){
			.af = AF_INET,
		};
		FR_DBUFF_OUT_RETURN(&dst->vb_ip.prefix, &work_dbuff);
		FR_DBUFF_OUT_MEMCPY_RETURN((uint8_t *)&dst->vb_ip.addr.v4, &work_dbuff, len - 1);
		break;

	case FR_TYPE_IPV6_ADDR:
	ipv6addr:
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
	ipv6prefix:
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

	case FR_TYPE_COMBO_IP_ADDR:
		if ((len >= network_min_size(FR_TYPE_IPV6_ADDR)) &&
		    (len <= network_max_size(FR_TYPE_IPV6_ADDR))) goto ipv6addr;	/* scope is optional */
		else if ((len >= network_min_size(FR_TYPE_IPV4_ADDR)) &&
		    	 (len <= network_max_size(FR_TYPE_IPV4_ADDR))) goto ipv4addr;
		fr_strerror_const("Invalid combo ip address value");
		return 0;

	case FR_TYPE_COMBO_IP_PREFIX:
		if ((len >= network_min_size(FR_TYPE_IPV6_PREFIX)) &&
		    (len <= network_max_size(FR_TYPE_IPV6_PREFIX))) goto ipv6prefix;	/* scope is optional */
		else if ((len >= network_min_size(FR_TYPE_IPV4_PREFIX)) &&
		    	 (len <= network_max_size(FR_TYPE_IPV4_PREFIX))) goto ipv4prefix;
		fr_strerror_const("Invalid combo ip prefix value");
		return 0;

	case FR_TYPE_BOOL:
		{
			uint8_t	val = 0;

			FR_DBUFF_OUT_RETURN(&val, &work_dbuff);
			dst->datum.boolean = (val != 0);
		}
		break;

	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
		FR_DBUFF_OUT_MEMCPY_RETURN(fr_value_box_raw(dst, type), &work_dbuff, len);
		break;

	case FR_TYPE_UINT8:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint8, &work_dbuff);
		break;

	case FR_TYPE_UINT16:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint16, &work_dbuff);
		break;

	case FR_TYPE_UINT32:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint32, &work_dbuff);
		break;

	case FR_TYPE_UINT64:
		FR_DBUFF_OUT_RETURN(&dst->vb_uint64, &work_dbuff);
		break;

	case FR_TYPE_INT8:
		FR_DBUFF_OUT_RETURN(&dst->vb_int8, &work_dbuff);
		break;

	case FR_TYPE_INT16:
		FR_DBUFF_OUT_RETURN(&dst->vb_int16, &work_dbuff);
		break;

	case FR_TYPE_INT32:
		FR_DBUFF_OUT_RETURN(&dst->vb_int32, &work_dbuff);
		break;

	case FR_TYPE_INT64:
		FR_DBUFF_OUT_RETURN(&dst->vb_int64, &work_dbuff);
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
			precision = (fr_time_res_t)enumv->flags.flag_time_res;
		}

		/*
		 *	Input data doesn't match what we were told we
		 *	need.
		 */
		if (len > length) return -(length);

		dst->enumv = enumv;

		FR_DBUFF_OUT_UINT64V_RETURN(&date, &work_dbuff, length);

		if (!fr_multiply(&date, date, fr_time_multiplier_by_res[precision])) {
			fr_strerror_const("date would overflow");
			return 0;
		}

		dst->vb_date = fr_unix_time_wrap(date);
	}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		size_t length = 4;
		fr_time_res_t precision = FR_TIME_RES_SEC;
		int64_t date;

		if (enumv) {
			length = enumv->flags.length;
			precision = (fr_time_res_t)enumv->flags.flag_time_res;
		}

		/*
		 *	Input data doesn't match what we were told we
		 *	need.
		 */
		if (len > length) return -(length);

		dst->enumv = enumv;

		if (!enumv || !enumv->flags.is_unsigned) {
			FR_DBUFF_OUT_INT64V_RETURN(&date, &work_dbuff, length);
		} else {
			uint64_t tmp;

			/*
			 *	Else it's an unsigned time delta, but
			 *	we do have to clamp it at the max
			 *	value for a signed 64-bit integer.
			 */
			FR_DBUFF_OUT_UINT64V_RETURN(&tmp, &work_dbuff, length);

			if (tmp > INT64_MAX) tmp = INT64_MAX;

			date = tmp;
		}

		dst->vb_time_delta = fr_time_delta_wrap(fr_time_scale(date, precision));
	}
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		break;		/* Already dealt with */

	case FR_TYPE_SIZE:
	case FR_TYPE_NON_LEAF:
		fr_strerror_printf("Cannot decode type \"%s\" - Is not a value",
				   fr_type_to_str(type));
		break;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Get a key from a value box
 *
 * @param[in,out] out - set to a small buffer on input.  If the callback has more data
 *		  than is available here, the callback can update "out" to point elsewhere
 * @param[in,out] outlen The number of bits available in the initial buffer.  On output,
 *		  the number of bits available in the key
 * @param[in] value the value box which contains the key
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_value_box_to_key(uint8_t **out, size_t *outlen, fr_value_box_t const *value)
{
	ssize_t slen;
	fr_dbuff_t dbuff;

	switch (value->type) {
	case FR_TYPE_BOOL:
		if (*outlen < 8) return -1;

		*out[0] = (value->vb_bool) << 7;
		*outlen = 1;
		break;

	case FR_TYPE_INTEGER_EXCEPT_BOOL:
		if (*outlen < (value->vb_length * 8)) return -1;

		/*
		 *	Integers are put into network byte order.
		 */
		fr_dbuff_init(&dbuff, *out, *outlen >> 3);

		slen = fr_value_box_to_network(&dbuff, value);
		if (slen < 0) return slen;
		*outlen = slen * 8; /* bits not bytes */
		break;

	case FR_TYPE_IP:
		/*
		 *	IPs are already in network byte order.
		 */
		*out = UNCONST(uint8_t *, &value->vb_ip.addr);
		*outlen = value->vb_ip.prefix;
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		*out = value->datum.ptr;
		*outlen = value->vb_length * 8;
		break;

	case FR_TYPE_ETHERNET:
		*out = UNCONST(uint8_t *, &value->vb_ether[0]);
		*outlen = sizeof(value->vb_ether) * 8;
		break;

	default:
		fr_strerror_printf("Invalid data type '%s' for getting key",
				   fr_type_to_str(value->type));
		return -1;
	}

	return 0;
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
	if (!fr_type_is_fixed_size(dst_type)) if (!fr_cond_assert(false)) return -1;

	if (src->vb_length < network_min_size(dst_type)) {
		fr_strerror_printf("Invalid cast from %s to %s.  Source is length %zd is smaller than "
				   "destination type size %zd",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type),
				   src->vb_length,
				   network_min_size(dst_type));
		return -1;
	}

	if (src->vb_length > network_max_size(dst_type)) {
		fr_strerror_printf("Invalid cast from %s to %s.  Source length %zd is greater than "
				   "destination type size %zd",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type),
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
		return fr_value_box_list_concat_in_place(ctx,
							 dst, UNCONST(fr_value_box_list_t *, &src->vb_group),
							 FR_TYPE_STRING,
							 FR_VALUE_BOX_LIST_NONE, false,
							 SIZE_MAX);

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
		return fr_value_box_list_concat_in_place(ctx,
							 dst, UNCONST(fr_value_box_list_t *, &src->vb_group),
							 FR_TYPE_OCTETS,
							 FR_VALUE_BOX_LIST_NONE, false,
							 SIZE_MAX);
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
					   fr_value_box_raw(&tmp, src->type),
					   fr_value_box_field_sizes[src->type], src->tainted);
	}

	default:
		/* Not the same talloc_memdup call as above.  The above memdup reads data from the dst */
		return fr_value_box_memdup(ctx, dst, dst_enumv,
					   fr_value_box_raw(src, src->type),
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
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type));
			return -1;
		}

		memcpy(&dst->vb_ip.addr.v4, &src->vb_ip.addr.v6.s6_addr[sizeof(v4_v6_map)],
		       sizeof(dst->vb_ip.addr.v4));

		break;

	case FR_TYPE_IPV4_PREFIX:
		if (src->vb_ip.prefix != 32) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only /32 (not %i/) prefixes may be "
					   "cast to IP address types",
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
					   src->vb_ip.prefix);
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v4, &src->vb_ip.addr.v4, sizeof(dst->vb_ip.addr.v4));
		break;

	case FR_TYPE_IPV6_PREFIX:
		if (src->vb_ip.prefix != 128) {
			fr_strerror_printf("Invalid cast from %s to %s.  Only /128 (not /%i) prefixes may be "
					   "cast to IP address types",
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type));
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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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
	static_assert((sizeof(v4_v6_map) + sizeof(src->vb_ip.addr.v4)) <=
		      sizeof(src->vb_ip.addr.v6), "IPv6 storage too small");
	fr_assert(dst_type == FR_TYPE_IPV6_ADDR);

	switch (src->type) {
	case FR_TYPE_STRING:
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

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
			   		   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
			   		   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
					   sizeof(dst->vb_ip.addr.v6.s6_addr), src->vb_length);
			return -1;
		}
		memcpy(&dst->vb_ip.addr.v6.s6_addr, src->vb_octets, sizeof(dst->vb_ip.addr.v6.s6_addr));
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

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
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
					   sizeof(dst->vb_ip.addr.v6.s6_addr) + 2, src->vb_length);
			return -1;
		}
		dst->vb_ip.scope_id = src->vb_octets[0];
		dst->vb_ip.prefix = src->vb_octets[1];
		memcpy(&dst->vb_ip.addr.v6.s6_addr, src->vb_octets, sizeof(dst->vb_ip.addr.v6.s6_addr));
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

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

		fr_nbo_from_uint64(array, src->vb_uint64);

		/*
		 *	For OUIs in the DB.
		 */
		if ((array[0] != 0) || (array[1] != 0)) return -1;

		memcpy(dst->vb_ether, &array[2], 6);
		break;
	}

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

	case FR_TYPE_OCTETS:
		/*
		 *	This is really "bool from network"
		 */
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

	case FR_TYPE_SIZE:
		dst->vb_bool = (src->vb_size != 0);
		break;

	case FR_TYPE_TIME_DELTA:
		dst->vb_bool = (fr_time_delta_unwrap(src->vb_time_delta) != 0);
		break;

	case FR_TYPE_FLOAT32:
		dst->vb_bool = (fpclassify(src->vb_float32) == FP_ZERO);
		break;

	case FR_TYPE_FLOAT64:
		dst->vb_bool = (fpclassify(src->vb_float64) == FP_ZERO);
		break;

	default:
		fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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

#if !defined(NDEBUG) || defined(STATIC_ANALYZER)
	/*
	 *	Helps catch invalid fr_value_box_field_sizes
	 *	entries, and shuts up clang analyzer.
	 */
	if (!fr_cond_assert_msg(len > 0, "Invalid cast from %s to %s. "
			        "invalid source type len, expected > 0, got %zu",
			        fr_type_to_str(src->type),
			        fr_type_to_str(dst_type),
			        len)) return -1;

	if (!fr_cond_assert_msg(len <= sizeof(uint64_t),
				"Invalid cast from %s to %s. "
				"invalid source type len, expected <= %zu, got %zu",
				fr_type_to_str(src->type),
				fr_type_to_str(dst_type),
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
	{
		fr_time_res_t res = FR_TIME_RES_SEC;
		if (dst->enumv) res = dst->enumv->flags.flag_time_res;

		tmp = fr_unix_time_to_integer(src->vb_date, res);
	}
		break;

	/*
	 *	Same deal with time deltas.  Note that
	 *	even though we store the value as an
	 *	unsigned integer, it'll be cast to a
	 *	signed integer for comparisons.
	 */
	case FR_TYPE_TIME_DELTA:
	{
		fr_time_res_t res = FR_TIME_RES_SEC;

		if (dst->enumv) res = dst->enumv->flags.flag_time_res;

		tmp = (uint64_t)fr_time_delta_to_integer(src->vb_time_delta, res);
	}
		break;

	default:
#ifdef WORDS_BIGENDIAN
		memcpy(((uint8_t *)&tmp) + (sizeof(tmp) - len),
		       fr_value_box_raw(src, src->type), len);
#else
		memcpy(&tmp, fr_value_box_raw(src, src->type), len);
#endif
		break;
	}

	min = fr_value_box_integer_min[dst_type];

	/*
	 *	Sign promote the input if the source type is
	 *	signed, and the high bit is set.
	 */
	if (fr_value_box_integer_min[src->type] < 0) {
		if (SIGN_BIT_HIGH(tmp, len)) tmp = SIGN_PROMOTE(tmp, len);

		if ((int64_t)tmp < min) {
			fr_strerror_printf("Invalid cast from %s to %s.  %"PRId64" "
					   "outside value range %"PRId64"-%"PRIu64,
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
					   (int64_t)tmp,
					   min, fr_value_box_integer_max[dst_type]);
			return -1;
		}
	} else if (tmp > fr_value_box_integer_max[dst_type]) {
		fr_strerror_printf("Invalid cast from %s to %s.  %"PRIu64" "
				   "outside value range 0-%"PRIu64,
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type),
				   tmp, fr_value_box_integer_max[dst_type]);
		return -1;
	}

	fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
	switch (dst_type) {
	case FR_TYPE_DATE:
	{
		bool overflow;
		fr_time_res_t res = FR_TIME_RES_SEC;
		if (dst->enumv) res = dst->enumv->flags.flag_time_res;

		dst->vb_date = fr_unix_time_from_integer(&overflow, tmp, res);
		if (overflow) {
			fr_strerror_const("Input to data type would overflow");
			return -1;
		}
	}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		bool overflow;
		fr_time_res_t res = FR_TIME_RES_SEC;
		if (dst->enumv) res = dst->enumv->flags.flag_time_res;

		dst->vb_time_delta = fr_time_delta_from_integer(&overflow, tmp, res);
		if (overflow) {
			fr_strerror_const("Input to time_delta type would overflow");
			return -1;
		}
	}
		break;

	default:
#ifdef WORDS_BIGENDIAN
		memcpy(fr_value_box_raw(dst, dst->type),
		       ((uint8_t *)&tmp) + (sizeof(tmp) - len), fr_value_box_field_sizes[dst_type]);
#else
		memcpy(fr_value_box_raw(dst, dst->type),
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
		return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
					     src->vb_strvalue, src->vb_length,
					     NULL, src->tainted);

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
		dst->vb_uint64 = fr_nbo_to_uint64(&src->vb_ifid[0]);
		return 0;
	}

	default:
		break;
	}

bad_cast:
	fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
			   fr_type_to_str(src->type),
			   fr_type_to_str(dst_type));
	return -1;
}

/** Convert any value to a floating point value
 *
 * @param ctx		unused.
 * @param dst		Where to write result of casting.
 * @param dst_type	to cast to.
 * @param dst_enumv	enumeration values.
 * @param src		Input data.
 */
static inline int fr_value_box_cast_to_float(UNUSED TALLOC_CTX *ctx, fr_value_box_t *dst,
					     fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					     fr_value_box_t const *src)
{
	double num;

	switch (src->type) {
	case FR_TYPE_FLOAT32:
		if (dst_type == FR_TYPE_FLOAT64) {
			num = (double) src->vb_float32;
			goto good_cast;
		}

		goto bad_cast;

	case FR_TYPE_FLOAT64:
		if (dst_type == FR_TYPE_FLOAT32) {
			num = src->vb_float64;
			goto good_cast;
		}

		goto bad_cast;

	case FR_TYPE_BOOL:
		num = src->vb_bool;
		goto good_cast;

	case FR_TYPE_INT8:
		num = src->vb_int8;
		goto good_cast;

	case FR_TYPE_INT16:
		num = src->vb_int16;
		goto good_cast;

	case FR_TYPE_INT32:
		num = src->vb_int32;
		goto good_cast;

	case FR_TYPE_INT64:
		num = src->vb_int64;
		goto good_cast;

	case FR_TYPE_UINT8:
		num = src->vb_uint8;
		goto good_cast;

	case FR_TYPE_UINT16:
		num = src->vb_uint16;
		goto good_cast;

	case FR_TYPE_UINT32:
		num = src->vb_uint32;
		goto good_cast;

	case FR_TYPE_UINT64:
		num = src->vb_uint64;
		goto good_cast;

	case FR_TYPE_DATE:
		/*
		 *	Unix times are in nanoseconds
		 */
		num = fr_unix_time_unwrap(src->vb_date);
		num /= NSEC;
		goto good_cast;

	case FR_TYPE_TIME_DELTA:
		/*
		 *	Time deltas are in nanoseconds, but scaled.
		 */
		num = fr_time_delta_unwrap(src->vb_time_delta);
		if (src->enumv) {
			num /= fr_time_multiplier_by_res[src->enumv->flags.flag_time_res];
		}
		goto good_cast;

	case FR_TYPE_SIZE:
		num = src->vb_size;

	good_cast:
		fr_value_box_init(dst, dst_type, dst_enumv, src->tainted);
		if (dst_type == FR_TYPE_FLOAT32) {
			dst->vb_float32 = num;
		} else {
			dst->vb_float64 = num;
		}
		return 0;

	default:
		break;
	}

bad_cast:
	fr_strerror_printf("Invalid cast from %s to %s.  Unsupported",
			   fr_type_to_str(src->type),
			   fr_type_to_str(dst_type));
	return -1;
}


/** Convert one type of fr_value_box_t to another
 *
 * This should be the canonical function used to convert between INTERNAL data formats.
 *
 * If you want to convert from PRESENTATION format, use #fr_value_box_from_substr.
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

	if (fr_type_is_non_leaf(dst_type)) {
		fr_strerror_printf("Invalid cast from %s to %s.  Can only cast simple data types",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
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

	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
		break;
	/*
	 *	Need func
	 */
	case FR_TYPE_IFID:
		break;

	case FR_TYPE_ETHERNET:
		return fr_value_box_cast_to_ethernet(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_BOOL:
		return fr_value_box_cast_to_bool(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_INTEGER_EXCEPT_BOOL:
		return fr_value_box_cast_to_integer(ctx, dst, dst_type, dst_enumv, src);

	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
		if (fr_type_is_fixed_size(src->type)) {
			return fr_value_box_cast_to_float(ctx, dst, dst_type, dst_enumv, src);
		}
		break;		/* use generic string/octets stuff below */

	/*
	 *	Invalid types for casting (should have been caught earlier)
	 */
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_STRUCTURAL:
	case FR_TYPE_NULL:
	case FR_TYPE_VOID:
	case FR_TYPE_MAX:
		fr_strerror_printf("Invalid cast from %s to %s.  Invalid destination type",
				   fr_type_to_str(src->type),
				   fr_type_to_str(dst_type));
		return -1;
	}

	/*
	 *	Deserialise a fr_value_box_t
	 */
	if (src->type == FR_TYPE_STRING) return fr_value_box_from_str(ctx, dst, dst_type, dst_enumv,
								      src->vb_strvalue, src->vb_length,
								      NULL, src->tainted);

	if (src->type == FR_TYPE_OCTETS) {
		fr_value_box_t tmp;

		if (src->vb_length < network_min_size(dst_type)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Source is length %zd is smaller than "
					   "destination type size %zd",
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
					   src->vb_length,
					   network_min_size(dst_type));
			return -1;
		}

		if (src->vb_length > network_max_size(dst_type)) {
			fr_strerror_printf("Invalid cast from %s to %s.  Source length %zd is greater than "
					   "destination type size %zd",
					   fr_type_to_str(src->type),
					   fr_type_to_str(dst_type),
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
 * If you want to convert from PRESENTATION format, use #fr_value_box_from_substr.
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
	fr_dlist_t entry = vb->entry;

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

	if (fr_value_box_cast(ctx, vb, dst_type, dst_enumv, &tmp) < 0) {
		/*
		 *	On error, make sure the original
		 *	box is left in a consistent state.
		 */
		fr_value_box_copy_shallow(NULL, vb, &tmp);
		vb->entry.next = entry.next;
		vb->entry.prev = entry.prev;
		return -1;
	}
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
	if (!fr_type_is_ip(src->type)) {
		fr_strerror_printf("Unboxing failed.  Needed IPv4/6 addr/prefix, had type %s",
				   fr_type_to_str(src->type));
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
	switch (src->type) {
	default:
		fr_value_box_memcpy_out(fr_value_box_raw(dst, src->type), src);
		fr_value_box_copy_meta(dst, src);
		break;

	case FR_TYPE_NULL:
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
		uint8_t *bin;

		if (src->vb_length) {
			bin = talloc_memdup(ctx, src->vb_octets, src->vb_length);
			if (!bin) {
				fr_strerror_const("Failed allocating octets buffer");
				return -1;
			}
			talloc_set_type(bin, uint8_t);
		} else {
			bin = talloc_array(ctx, uint8_t, 0);
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
 * @param[in] src 	a string.  May be NULL only if len == 0.
 * @param[in] len	of src.
 * @param[in] tainted	Whether the value came from a trusted source.
 */
int fr_value_box_bstrndup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
			  char const *src, size_t len, bool tainted)
{
	char const	*str;

	if (unlikely((len > 0) && !src)) {
		fr_strerror_printf("Invalid arguments to %s.  Len > 0 (%zu) but src string was NULL",
				   __FUNCTION__, len);
		return -1;
	}

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
				   fr_type_to_str(FR_TYPE_STRING),
				   fr_type_to_str(dst->type));
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

	if (unlikely((len > 0) && !src)) {
		fr_strerror_printf("Invalid arguments to %s.  Len > 0 (%zu) but src was NULL",
				   __FUNCTION__, len);
		return -1;
	}

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
				   fr_type_to_str(FR_TYPE_OCTETS),
				   fr_type_to_str(dst->type));
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
 * @param[in] tainted		Whether the value came from a trusted source.
 * @return
 *	- >= 0 on success (number of bytes parsed).
 *	- < 0 on error (where the parse error ocurred).
 */
static inline CC_HINT(always_inline)
fr_slen_t fr_value_box_from_numeric_substr(fr_value_box_t *dst, fr_type_t dst_type,
					   fr_dict_attr_t const *dst_enumv,
					   fr_sbuff_t *in, fr_sbuff_parse_rules_t const *rules, bool tainted)
{
	fr_slen_t		slen;
	fr_sbuff_parse_error_t	err;

	fr_value_box_init(dst, dst_type, dst_enumv, tainted);

	switch (dst_type) {
	case FR_TYPE_UINT8:
		slen = fr_sbuff_out(&err, &dst->vb_uint8, in);
		break;

	case FR_TYPE_UINT16:
		slen = fr_sbuff_out(&err, &dst->vb_uint16, in);
		break;

	case FR_TYPE_UINT32:
		slen = fr_sbuff_out(&err, &dst->vb_uint32, in);
		break;

	case FR_TYPE_UINT64:
		slen = fr_sbuff_out(&err, &dst->vb_uint64, in);
		break;

	case FR_TYPE_INT8:
		slen = fr_sbuff_out(&err, &dst->vb_int8, in);
		break;

	case FR_TYPE_INT16:
		slen = fr_sbuff_out(&err, &dst->vb_int16, in);
		break;

	case FR_TYPE_INT32:
		slen = fr_sbuff_out(&err, &dst->vb_int32, in);
		break;

	case FR_TYPE_INT64:
		slen = fr_sbuff_out(&err, &dst->vb_int64, in);
		break;

	case FR_TYPE_SIZE:
		slen = fr_sbuff_out(&err, &dst->vb_size, in);
		break;

	case FR_TYPE_FLOAT32:
		slen = fr_sbuff_out(&err, &dst->vb_float32, in);
		break;

	case FR_TYPE_FLOAT64:
		slen = fr_sbuff_out(&err, &dst->vb_float64, in);
		break;

	default:
		fr_assert_fail(NULL);
		return -1;
	}

	if (slen < 0) {
		/*
		 *	If an enumeration attribute is provided and we
		 *      don't find an integer, assume this is an enumv
		 *      lookup fail, and produce a better error.
		 */
		if (dst_enumv && dst_enumv->flags.has_value && (err == FR_SBUFF_PARSE_ERROR_NOT_FOUND)) {
			fr_sbuff_t our_in = FR_SBUFF(in);
			fr_sbuff_adv_until(&our_in, SIZE_MAX, rules->terminals,
					   rules->escapes ? rules->escapes->chr : '\0');

			fr_strerror_printf("Invalid enumeration value \"%pV\" for attribute %s",
					   fr_box_strvalue_len(fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)),
					   dst_enumv->name);
			return -1;
		}

		if (err == FR_SBUFF_PARSE_ERROR_NOT_FOUND) {
			fr_strerror_printf("Failed parsing string as type '%s'",
					   fr_type_to_str(dst_type));
		} else {
			fr_sbuff_parse_error_to_strerror(err);
		}
	}


	return slen;
}

/** Convert string value to a fr_value_box_t type
 *
 * @param[in] ctx		to alloc strings in.
 * @param[out] dst		where to write parsed value.
 * @param[in,out] dst_type	of value data to create/dst_type of value created.
 * @param[in] dst_enumv		fr_dict_attr_t with string names for uint32 values.
 * @param[in] in		sbuff to read data from.
 * @param[in] rules		unescape and termination rules.
 * @param[in] tainted		Whether the value came from a trusted source.
 * @return
 *	- >0 on success.
 *	- <= 0 on parse error.
 */
ssize_t fr_value_box_from_substr(TALLOC_CTX *ctx, fr_value_box_t *dst,
				 fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				 fr_sbuff_t *in, fr_sbuff_parse_rules_t const *rules, bool tainted)
{
	static fr_sbuff_parse_rules_t	default_rules;
	fr_sbuff_t			*unescaped = NULL;
	fr_sbuff_t			our_in = FR_SBUFF(in);
	ssize_t				ret;
	char				buffer[256];
	fr_slen_t			slen;

	if (!rules) rules = &default_rules;

	fr_strerror_clear();

	/*
	 *	Set size for all fixed length attributes.
	 */
	ret = network_max_size(dst_type);

	/*
	 *	Lookup any names before continuing
	 */
	if (dst_enumv) {
		size_t			name_len;
		fr_dict_enum_value_t	*enumv;

		/*
		 *	Create a thread-local extensible buffer to
		 *	store unescaped data.
		 *
		 *	This is created once per-thread (the first time
		 *	this function is called), and freed when the
		 *	thread exits.
		 */
		FR_SBUFF_TALLOC_THREAD_LOCAL(&unescaped, 256, 4096);

		name_len = fr_sbuff_out_unescape_until(unescaped, &our_in, SIZE_MAX,
						       rules->terminals, rules->escapes);
		if (!name_len) {
			fr_sbuff_set_to_start(&our_in);
			goto parse;	/* Zero length name can't match enum */
		}

		enumv = fr_dict_enum_by_name(dst_enumv, fr_sbuff_start(unescaped), fr_sbuff_used(unescaped));
		if (!enumv) {
			fr_sbuff_set_to_start(&our_in);
			goto parse;	/* No enumeration matches escaped string */
		}

		/*
		 *	dst_type may not match enumv type
		 */
		if (fr_value_box_cast(ctx, dst, dst_type, dst_enumv, enumv->value) < 0) return -1;

		FR_SBUFF_SET_RETURN(in, &our_in);
	}

parse:
	/*
	 *	It's a variable ret src->dst_type so we just alloc a new buffer
	 *	of size len and copy.
	 */
	switch (dst_type) {
	case FR_TYPE_STRING:
		/*
		 *	We've not unescaped the string yet, produce an unescaped version
		 */
		if (!dst_enumv) {
			char *buff;

			if (unlikely(fr_sbuff_out_aunescape_until(ctx, &buff, &our_in, SIZE_MAX,
								  rules->terminals, rules->escapes) < 0)) {
				return -1;
			}
			fr_value_box_bstrdup_buffer_shallow(NULL, dst, dst_enumv, buff, tainted);
		/*
		 *	We already have an unescaped version, just use that
		 */
		} else {
			fr_value_box_bstrndup(ctx, dst, dst_enumv,
					      fr_sbuff_start(unescaped), fr_sbuff_used(unescaped), tainted);
		}
		FR_SBUFF_SET_RETURN(in, &our_in);

	/* raw octets: 0x01020304... */
	case FR_TYPE_OCTETS:
	{
		fr_sbuff_marker_t	hex_start;
		size_t			hex_len;
		uint8_t			*bin_buff;

		/*
		 *	If there's escape sequences that need to be processed
		 *	or the string doesn't start with 0x, then assume this
		 *	is literal data, not hex encoded data.
		 */
		if (rules->escapes || !fr_sbuff_adv_past_strcase_literal(&our_in, "0x")) {
			if (!dst_enumv) {
				char	*buff = NULL;
				uint8_t	*bin;

				if (fr_sbuff_extend(&our_in)) {
					fr_sbuff_out_aunescape_until(ctx, &buff, &our_in, SIZE_MAX,
								     rules->terminals, rules->escapes);

					bin = talloc_realloc(ctx, buff, uint8_t, talloc_array_length(buff) - 1);
					if (unlikely(!bin)) {
						fr_strerror_const("Failed trimming string buffer");
						talloc_free(buff);
						return -1;
					}
					talloc_set_type(bin, uint8_t); /* talloc_realloc doesn't do this */
				/*
				 *	Input data is zero
				 *
				 *	talloc realloc will refuse to realloc to
				 *	a zero length buffer.  This is probably
				 *	a bug, because we can create zero length
				 *	arrays normally
				 */
				} else {
					bin = talloc_zero_array(ctx, uint8_t, 0);
				}

				fr_value_box_memdup_buffer_shallow(NULL, dst, dst_enumv, bin, tainted);
			/*
			 *	We already have an unescaped version, just use that
			 */
			} else {
				fr_value_box_memdup(ctx, dst, dst_enumv,
						    (uint8_t *)fr_sbuff_start(unescaped),
						    fr_sbuff_used(unescaped), tainted);
			}
			FR_SBUFF_SET_RETURN(in, &our_in);
		}

		fr_sbuff_marker(&hex_start, &our_in);	/* Record where the hexits start */

		/*
		 *	Find the end of the hex sequence.
		 *
		 *	We don't technically need to do this, fr_base16_decode
		 *	will find the end on its own.
		 *
		 *	We do this so we can alloc the correct sized
		 *	output buffer.
		 */
		hex_len = fr_sbuff_adv_past_allowed(&our_in, SIZE_MAX, sbuff_char_class_hex, rules->terminals);
		if (hex_len == 0) {
			if (fr_value_box_memdup(ctx, dst, dst_enumv, (uint8_t[]){ 0x00 }, 0, tainted) < 0) return -1;
			FR_SBUFF_SET_RETURN(in, &our_in);
		}

		if ((hex_len & 0x01) != 0) {
			fr_strerror_printf("Length of hex string is not even, got %zu bytes", hex_len);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	Pre-allocate the bin buff and initialise the box
		 */
		if (fr_value_box_mem_alloc(ctx, &bin_buff, dst, dst_enumv, (hex_len >> 1), tainted) < 0) return -1;

		/*
		 *	Reset to the start of the hex string
		 */
		fr_sbuff_set(&our_in, &hex_start);

		if (unlikely(fr_base16_decode(NULL, &FR_DBUFF_TMP(bin_buff, hex_len), &our_in, false) < 0)) {
			talloc_free(bin_buff);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		FR_SBUFF_SET_RETURN(in, &our_in);
	}

	case FR_TYPE_IPV4_ADDR:
	{
		fr_ipaddr_t addr;
		size_t name_len = fr_sbuff_adv_past_allowed(&our_in, fr_sbuff_remaining(&our_in), sbuff_char_class_hostname, rules->terminals);
		if (!name_len) return 0;

		if (fr_inet_pton4(&addr, fr_sbuff_current(in), name_len,
				  fr_hostname_lookups, false, true) < 0) return -1;

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
	{
		size_t name_len = fr_sbuff_adv_past_allowed(&our_in, fr_sbuff_remaining(&our_in), sbuff_char_class_hostname, rules->terminals);
		if (!name_len) return 0;

		if (fr_inet_pton4(&dst->vb_ip, fr_sbuff_current(in), name_len,
				  fr_hostname_lookups, false, true) < 0) return -1;
	}
		goto finish;

	case FR_TYPE_IPV6_ADDR:
	{
		fr_ipaddr_t addr;
		size_t name_len = fr_sbuff_adv_past_allowed(&our_in, fr_sbuff_remaining(&our_in), sbuff_char_class_hostname, rules->terminals);
		if (!name_len) return 0;

		/*
		 *	Parse scope, too.
		 */
		if (fr_sbuff_next_if_char(&our_in, '%')) {
			name_len += fr_sbuff_adv_past_allowed(&our_in, fr_sbuff_remaining(&our_in), sbuff_char_class_uint, rules->terminals);
		}

		if (fr_inet_pton6(&addr, fr_sbuff_current(in), name_len,
				  fr_hostname_lookups, false, true) < 0) return -1;

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
	{
		size_t name_len = fr_sbuff_adv_past_allowed(&our_in, fr_sbuff_remaining(&our_in), sbuff_char_class_hostname, rules->terminals);
		if (!name_len) return 0;

		if (fr_inet_pton6(&dst->vb_ip, fr_sbuff_current(in), name_len,
				  fr_hostname_lookups, false, true) < 0) return -1;
	}
		goto finish;

	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
		return fr_value_box_from_numeric_substr(dst, dst_type, dst_enumv, in, rules, tainted);

	case FR_TYPE_SIZE:
		if (fr_size_from_str(&dst->datum.size, &our_in) < 0) return -1;
		goto finish;

	case FR_TYPE_BOOL:
		fr_value_box_init(dst, dst_type, dst_enumv, tainted);

		/*
		 *	Quoted boolean values are "yes", "no", "true", "false"
		 */
		slen = fr_sbuff_out(NULL, &dst->vb_bool, in);
		if (slen >= 0) return slen;

		/*
		 *	For barewords we also allow 0 for false and any other
		 *      integer value for true.
		 */
		if (!rules->escapes) {
			int64_t	stmp;
			uint64_t utmp;

			slen = fr_sbuff_out(NULL, &stmp, in);
			if (slen >= 0) {
				dst->vb_bool = (stmp != 0);
				return slen;
			}

			slen = fr_sbuff_out(NULL, &utmp, in);
			if (slen >= 0) {
				dst->vb_bool = (utmp != 0);
				return slen;
			}
		}

		fr_strerror_const("Invalid boolean value.  Accepted values are "
				 "\"yes\", \"no\", \"true\", \"false\" or any unquoted integer");

		return slen;	/* Just whatever the last error offset was */

	case FR_TYPE_ETHERNET:
	{
		uint64_t 		num;
		fr_ethernet_t		ether;
		fr_dbuff_t		dbuff;
		fr_sbuff_parse_error_t	err;

		fr_dbuff_init(&dbuff, ether.addr, sizeof(ether.addr));

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
		 *
		 *	Note: We need to check for a terminal sequence
		 *	after the number, else we may just end up
		 *	parsing the first hexit and returning.
		 *
		 *	i.e. 1c:00:00:00:00 -> 1
		 */
		if ((fr_sbuff_out(NULL, &num, &our_in) > 0) && fr_sbuff_is_terminal(&our_in, rules->terminals)) {
			num = htonll(num);

			fr_dbuff_in_memcpy(&dbuff, ((uint8_t *) &num) + 2, sizeof(dst->vb_ether));
			fr_value_box_ethernet_addr(dst, dst_enumv, &ether, tainted);

			FR_SBUFF_SET_RETURN(in, &our_in);
		}

		fr_sbuff_set_to_start(&our_in);

		fr_base16_decode(&err, &dbuff, &our_in, true);
		if (err != FR_SBUFF_PARSE_OK) {
		ether_error:
			fr_sbuff_parse_error_to_strerror(err);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (!fr_sbuff_next_if_char(&our_in, ':')) {
		ether_sep_error:
			fr_strerror_const("Missing separator, expected ':'");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		fr_base16_decode(&err, &dbuff, &our_in, true);
		if (err != FR_SBUFF_PARSE_OK) goto ether_error;

		if (!fr_sbuff_next_if_char(&our_in, ':')) goto ether_sep_error;

		fr_base16_decode(&err, &dbuff, &our_in, true);
		if (err != FR_SBUFF_PARSE_OK) goto ether_error;

		if (!fr_sbuff_next_if_char(&our_in, ':')) goto ether_sep_error;

		fr_base16_decode(&err, &dbuff, &our_in, true);
		if (err != FR_SBUFF_PARSE_OK) goto ether_error;

		if (!fr_sbuff_next_if_char(&our_in, ':')) goto ether_sep_error;

		fr_base16_decode(&err, &dbuff, &our_in, true);
		if (err != FR_SBUFF_PARSE_OK) goto ether_error;

		if (!fr_sbuff_next_if_char(&our_in, ':')) goto ether_sep_error;

		fr_base16_decode(&err, &dbuff, &our_in, true);
		if (err != FR_SBUFF_PARSE_OK) goto ether_error;

		/* coverity[uninit_use_in_call] */
		fr_value_box_ethernet_addr(dst, dst_enumv, &ether, tainted);

		FR_SBUFF_SET_RETURN(in, &our_in);
	}

	case FR_TYPE_TIME_DELTA:
		fr_value_box_init(dst, FR_TYPE_TIME_DELTA, dst_enumv, tainted);

		slen = fr_time_delta_from_substr(&dst->datum.time_delta, &our_in,
						 dst_enumv ? dst_enumv->flags.flag_time_res : FR_TIME_RES_SEC,
						 false, rules->terminals);
		if (slen < 0) return slen;
		FR_SBUFF_SET_RETURN(in, &our_in);

	case FR_TYPE_NULL:
		if (!rules->escapes && fr_sbuff_adv_past_str_literal(in, "NULL")) {
			fr_value_box_init(dst, dst_type, dst_enumv, tainted);
			FR_SBUFF_SET_RETURN(in, &our_in);
		}

		fr_strerror_const("String value was not NULL");
		return -1;

	/*
	 *	Dealt with below
	 */
	default:
		break;
	}

	/*
	 *	It's a fixed size src->dst_type, copy to a temporary buffer and
	 *	\0 terminate.
	 */
	if (fr_sbuff_remaining(in) >= sizeof(buffer)) {
		fr_strerror_const("Temporary buffer too small");
		return -1;
	}

	memcpy(buffer, fr_sbuff_current(in), fr_sbuff_remaining(in));
	buffer[fr_sbuff_remaining(in)] = '\0';

	switch (dst_type) {
	case FR_TYPE_DATE:
	{
		if (dst_enumv) {
			if (fr_unix_time_from_str(&dst->vb_date, buffer, dst_enumv->flags.flag_time_res) < 0) return -1;
		} else {
			if (fr_unix_time_from_str(&dst->vb_date, buffer, FR_TIME_RES_SEC) < 0) return -1;
		}

		dst->enumv = dst_enumv;
	}
		break;

	case FR_TYPE_IFID:
		if (fr_inet_ifid_pton((void *) dst->vb_ifid, buffer) == NULL) {
			fr_strerror_printf("Failed to parse interface-id string \"%s\"", buffer);
			return -1;
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
		if (fr_inet_pton(&dst->vb_ip, buffer, strlen(buffer), AF_UNSPEC, fr_hostname_lookups, true) < 0) return -1;
		switch (dst->vb_ip.af) {
		case AF_INET:
			ret = network_max_size(FR_TYPE_IPV4_ADDR);
			break;

		case AF_INET6:
			ret = network_max_size(FR_TYPE_IPV6_ADDR);
			break;

		default:
			fr_strerror_printf("Bad address family %i", dst->vb_ip.af);
			return -1;
		}
		break;

	case FR_TYPE_COMBO_IP_PREFIX:
		if (fr_inet_pton(&dst->vb_ip, buffer, strlen(buffer), AF_UNSPEC, fr_hostname_lookups, true) < 0) return -1;
		switch (dst->vb_ip.af) {
		case AF_INET:
			ret = network_max_size(FR_TYPE_IPV4_PREFIX);
			break;

		case AF_INET6:
			ret = network_max_size(FR_TYPE_IPV6_PREFIX);
			break;

		default:
			fr_strerror_printf("Bad address family %i", dst->vb_ip.af);
			return -1;
		}
		break;

	default:
		fr_strerror_printf("Cannot parse input as data type %s", fr_type_to_str(dst_type));
		return -1;
	}

finish:
	dst->vb_length = ret;
	dst->type = dst_type;
	dst->tainted = tainted;

	/*
	 *	Fixup enumvs
	 */
	dst->enumv = dst_enumv;
	fr_dlist_entry_init(&dst->entry);

	FR_SBUFF_SET_RETURN(in, &our_in);
}

ssize_t fr_value_box_from_str(TALLOC_CTX *ctx, fr_value_box_t *dst,
			      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
			      char const *in, size_t inlen,
			      fr_sbuff_unescape_rules_t const *erules, bool tainted)
{
	ssize_t slen;
	fr_sbuff_parse_rules_t prules = { .escapes = erules };

	slen = fr_value_box_from_substr(ctx, dst, dst_type, dst_enumv, &FR_SBUFF_IN(in, inlen), &prules, tainted);
	if (slen <= 0) return slen;

	if (slen != (ssize_t)inlen) {
		fr_strerror_printf("Failed parsing '%s'.  %zu bytes of trailing data after string value \"%pV\"",
				   fr_type_to_str(dst_type),
				   inlen - slen,
				   fr_box_strvalue_len(in + slen, inlen - slen));
		return (slen - inlen) - 1;
	}

	return slen;
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
	fr_sbuff_t	our_out = FR_SBUFF(out);

	char		buf[1024];	/* Interim buffer to use with poorly behaved printing functions */

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
		if (data->vb_length) FR_SBUFF_RETURN(fr_base16_encode, &our_out,
						     &FR_DBUFF_TMP(data->vb_octets, data->vb_length));
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
	case FR_TYPE_COMBO_IP_ADDR:
		if (!fr_inet_ntop(buf, sizeof(buf), &data->vb_ip)) return 0;
		FR_SBUFF_IN_STRCPY_RETURN(&our_out, buf);
		break;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_PREFIX:
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
		fr_time_res_t	res = FR_TIME_RES_SEC;

		if (data->enumv) res = data->enumv->flags.flag_time_res;

		FR_SBUFF_RETURN(fr_unix_time_to_str, &our_out, data->vb_date, res);
		break;
	}

	case FR_TYPE_SIZE:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zu", data->datum.size);
		break;

	case FR_TYPE_TIME_DELTA:
	{
		fr_time_res_t	res = FR_TIME_RES_SEC;
		bool		is_unsigned = false;

		if (data->enumv) {
			res = data->enumv->flags.flag_time_res;
			is_unsigned = data->enumv->flags.is_unsigned;
		}


		FR_SBUFF_RETURN(fr_time_delta_to_str, &our_out, data->vb_time_delta, res, is_unsigned);
	}
		break;

	case FR_TYPE_GROUP:
		/*
		 *	If the caller didn't ask to escape binary data
		 *	in 'octets' types, then we force that now.
		 *	Otherwise any 'octets' type which is buried
		 *	inside of a 'group' will get copied verbatim
		 *	from input to output, with no escaping!
		 */
		if (!e_rules || (!e_rules->do_oct && !e_rules->do_hex)) {
			e_rules = &fr_value_escape_double;
		}

		/*
		 *	Represent groups as:
		 *
		 *	{ <value0>, <value1>, { <sub-value0>, <sub-value1>, <sub-valueN> }}
		 */
		FR_SBUFF_IN_CHAR_RETURN(&our_out, '{');
		FR_SBUFF_RETURN(fr_value_box_list_concat_as_string,
				NULL, &our_out, UNCONST(fr_value_box_list_t *, &data->vb_group),
				", ", (sizeof(", ") - 1), e_rules,
				0, false, true);
		FR_SBUFF_IN_CHAR_RETURN(&our_out, '}');
		break;

	case FR_TYPE_NULL:
		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "NULL");
		break;
	/*
	 *	Don't add default here
	 */
	case FR_TYPE_TLV:		/* Not a box type */
	case FR_TYPE_STRUCT:		/* Not a box type */
	case FR_TYPE_VSA:		/* Not a box type */
	case FR_TYPE_VENDOR:		/* Not a box type */
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_VOID:
	case FR_TYPE_MAX:
		(void)fr_cond_assert(0);
		return 0;
	}

done:
	FR_SBUFF_SET_RETURN(out, &our_out);
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
	fr_sbuff_t	our_out = FR_SBUFF(out);

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

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Concatenate a list of value boxes together
 *
 * All boxes will be removed from the list.
 *
 * @param[out] tainted		If nonnull, will be set to true if any input boxes are tainted.
 *				bool pointed to must be initialised.
 * @param[out] sbuff		to write the result of the concatenation to.
 * @param[in] list		to concatenate.
 * @param[in] sep		Insert a separator between the values.
 * @param[in] sep_len		Length of the separator.
 * @param[in] e_rules		To apply to FR_TYPE_STRING types.
 *				Is not currently applied to any other box type.
 * @param[in] proc_action	What to do with the boxes in the list once
 *				they've been processed.
 * @param[in] flatten		If true and we encounter a #FR_TYPE_GROUP,
 *				we concat the contents of its children together.
 *      			If false, the contents will be cast to #type.
 * @param[in] printable		Convert 'octets' to printable strings.
 * @return
 *      - >=0 the number of bytes written to the sbuff.
 *	- <0 how many additional bytes we would have needed to
 *	  concat the next box.
 */
ssize_t fr_value_box_list_concat_as_string(bool *tainted, fr_sbuff_t *sbuff, fr_value_box_list_t *list,
					   char const *sep, size_t sep_len, fr_sbuff_escape_rules_t const *e_rules,
					   fr_value_box_list_action_t proc_action, bool flatten, bool printable)
{
	fr_sbuff_t our_sbuff = FR_SBUFF(sbuff);
	ssize_t slen;

	if (fr_dlist_empty(list)) return 0;

	fr_dlist_foreach(list, fr_value_box_t, vb) {
		switch (vb->type) {
		case FR_TYPE_GROUP:
			if (!flatten) goto print;
			slen = fr_value_box_list_concat_as_string(tainted, &our_sbuff, &vb->vb_group,
								  sep, sep_len, e_rules,
								  proc_action, flatten, printable);
			break;

		case FR_TYPE_OCTETS:
			if (printable) goto print; /* even if !tainted */

			/*
			 *	Copy the raw string over, if necessary with escaping.
			 */
			if (e_rules && (vb->tainted || e_rules->do_oct || e_rules->do_hex)) {
				slen = fr_sbuff_in_escape(&our_sbuff, (char const *)vb->vb_strvalue, vb->vb_length, e_rules);
			} else {
				slen = fr_sbuff_in_bstrncpy(&our_sbuff, (char const *)vb->vb_strvalue, vb->vb_length);
			}
			break;

		case FR_TYPE_STRING:
			if (vb->tainted && e_rules) goto print;

			slen = fr_sbuff_in_bstrncpy(&our_sbuff, vb->vb_strvalue, vb->vb_length);
			break;

		default:
		print:
			slen = fr_value_box_print(&our_sbuff, vb, e_rules);
			break;
		}
		if (slen < 0) {
		error:
			return slen;
		}

		if (sep && fr_dlist_next(list, vb)) {
			slen = fr_sbuff_in_bstrncpy(&our_sbuff, sep, sep_len);
			if (slen < 0) goto error;
		}
	}

	/*
	 *	Free the boxes last so if there's
	 *	an issue concating them, everything
	 *	is still in a known state.
	 */
	fr_dlist_foreach_safe(list, fr_value_box_t, vb) {
		if (tainted && vb->tainted) *tainted = true;

		if (vb_should_remove(proc_action)) fr_dlist_remove(list, vb);
		if (vb_should_free_value(proc_action)) fr_value_box_clear(vb);
		if (vb_should_free(proc_action)) talloc_free(vb);
	}}

	FR_SBUFF_SET_RETURN(sbuff, &our_sbuff);
}

/** Concatenate a list of value boxes together
 *
 * All boxes will be removed from the list.
 *
 * @param[out] tainted		If nonnull, will be set to true if any input boxes are tainted.
 *				bool pointed to must be initialised.
 * @param[out] dbuff		to write the result of the concatenation to.
 * @param[in] list		to concatenate.
 * @param[in] sep		Insert a separator between the values.
 * @param[in] sep_len		Length of the separator.
 * @param[in] proc_action	What to do with the boxes in the list once
 *				they've been processed.
 * @param[in] flatten		If true and we encounter a #FR_TYPE_GROUP,
 *				we concat the contents of its children together.
 *      			If false, the contents will be cast to #type.
 * @return
 *      - >=0 the number of bytes written to the sbuff.
 *	- <0 how many additional bytes we would have needed to
 *	  concat the next box.
 */
ssize_t fr_value_box_list_concat_as_octets(bool *tainted, fr_dbuff_t *dbuff, fr_value_box_list_t *list,
					   uint8_t const *sep, size_t sep_len,
					   fr_value_box_list_action_t proc_action, bool flatten)
{
	fr_dbuff_t 	our_dbuff = FR_DBUFF(dbuff);
	TALLOC_CTX	*tmp_ctx = NULL;
	ssize_t		slen;

	if (fr_dlist_empty(list)) return 0;

	fr_dlist_foreach(list, fr_value_box_t, vb) {
		switch (vb->type) {
		case FR_TYPE_GROUP:
			if (!flatten) goto cast;
			slen = fr_value_box_list_concat_as_octets(tainted, &our_dbuff, &vb->vb_group,
								  sep, sep_len,
								  proc_action, flatten);
			break;

		case FR_TYPE_OCTETS:
			slen = fr_dbuff_in_memcpy(&our_dbuff, vb->vb_octets, vb->vb_length);
			break;

		case FR_TYPE_STRING:
			slen = fr_dbuff_in_memcpy(&our_dbuff, (uint8_t const *)vb->vb_strvalue, vb->vb_length);
			break;

		default:
		cast:
			{
				fr_value_box_t tmp_vb;

				if (!tmp_ctx) tmp_ctx = talloc_pool(NULL, 1024);
				/*
				 *	Not equivalent to fr_value_box_to_network
				 */
				if (fr_value_box_cast_to_octets(tmp_ctx, &tmp_vb, FR_TYPE_OCTETS, NULL, vb) < 0) {
					slen = -1;
					goto error;
				}

				slen = fr_dbuff_in_memcpy(&our_dbuff, tmp_vb.vb_octets, tmp_vb.vb_length);
				fr_value_box_clear_value(&tmp_vb);
				break;
			}
		}

		if (slen < 0) {
		error:
			talloc_free(tmp_ctx);
			return slen;
		}

		if (sep && fr_dlist_next(list, vb)) {
			slen = fr_dbuff_in_memcpy(&our_dbuff, sep, sep_len);
			if (slen < 0) goto error;
		}
	}

	talloc_free(tmp_ctx);

	/*
	 *	Free the boxes last so if there's
	 *	an issue concating them, everything
	 *	is still in a known state.
	 */
	fr_dlist_foreach_safe(list, fr_value_box_t, vb) {
		if (tainted && vb->tainted) *tainted = true;

		if (vb_should_remove(proc_action)) fr_dlist_remove(list, vb);
		if (vb_should_free_value(proc_action)) fr_value_box_clear(vb);
		if (vb_should_free(proc_action)) talloc_free(vb);
	}}

	return fr_dbuff_set(dbuff, &our_dbuff);
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
 * @param[in] proc_action	What to do with the boxes in the list once
 *				they've been processed.
 * @param[in] flatten		If true and we encounter a #FR_TYPE_GROUP,
 *				we concat the contents of its children together.
 *      			If false, the contents will be cast to #type.
 * @param[in] max_size		of the value.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_value_box_list_concat_in_place(TALLOC_CTX *ctx,
				      fr_value_box_t *out, fr_value_box_list_t *list, fr_type_t type,
				      fr_value_box_list_action_t proc_action, bool flatten,
				      size_t max_size)
{
	fr_dbuff_t		dbuff;		/* FR_TYPE_OCTETS */
	fr_dbuff_uctx_talloc_t	dbuff_tctx;

	fr_sbuff_t		sbuff;		/* FR_TYPE_STRING */
	fr_sbuff_uctx_talloc_t	sbuff_tctx;

	fr_value_box_t		*head_vb = fr_dlist_head(list);
	bool			tainted = false;

	fr_dlist_t		entry;

	if (fr_dlist_empty(list)) {
		fr_strerror_const("Invalid arguments.  List contains no elements");
		return -1;
	}

	switch (type) {
	case FR_TYPE_STRING:
		if (unlikely(!fr_sbuff_init_talloc(ctx, &sbuff, &sbuff_tctx, 256, max_size))) return -1;
		break;

	case FR_TYPE_OCTETS:
		if (unlikely(!fr_dbuff_init_talloc(ctx, &dbuff, &dbuff_tctx, 256, max_size))) return -1;
		break;

	default:
		fr_strerror_printf("Invalid argument.  Can't concatenate boxes to type %s",
				   fr_type_to_str(type));
		return -1;
	}

	/*
	 *	Merge all siblings into list head.
	 *
	 *	This is where the first element in the
	 *	list is the output box.
	 *
	 *	i.e. we want to merge all its siblings
	 *	into it.
	 */
	if (out == head_vb) {
		out = head_vb;	/* sync up out and head_vb */

		switch (type) {
		case FR_TYPE_STRING:
			/*
			 *	Head gets dealt with specially as we don't
			 *	want to free it, and we don't want to free
			 *	the buffer associated with it (just yet).
			 *
			 *	Note that we don't convert 'octets' to a printable string
			 *	here.  Doing so breaks the keyword tests.
			 */
			if (fr_value_box_list_concat_as_string(&tainted, &sbuff, list,
							       NULL, 0, NULL,
							       FR_VALUE_BOX_LIST_REMOVE, flatten, false) < 0) {
				fr_strerror_printf("Concatenation exceeded max_size (%zu)", max_size);
			error:
				switch (type) {
				case FR_TYPE_STRING:
					talloc_free(fr_sbuff_buff(&sbuff));
					break;

				case FR_TYPE_OCTETS:
					talloc_free(fr_dbuff_buff(&dbuff));
					break;

				default:
					break;
				}
				return -1;
			}

			/*
			 *	Concat the rest of the children...
			 */
			if (fr_value_box_list_concat_as_string(&tainted, &sbuff, list,
							       NULL, 0, NULL,
							       proc_action, flatten, true) < 0) {
				fr_dlist_insert_head(list, head_vb);
				goto error;
			}
			(void)fr_sbuff_trim_talloc(&sbuff, SIZE_MAX);
			if (vb_should_free_value(proc_action)) fr_value_box_clear_value(out);
			fr_value_box_bstrndup_shallow(out, NULL, fr_sbuff_buff(&sbuff), fr_sbuff_used(&sbuff), tainted);
			break;

		case FR_TYPE_OCTETS:
			if (fr_value_box_list_concat_as_octets(&tainted, &dbuff, list,
							       NULL, 0,
							       FR_VALUE_BOX_LIST_REMOVE, flatten) < 0) goto error;

			if (fr_value_box_list_concat_as_octets(&tainted, &dbuff, list,
							       NULL, 0,
							       proc_action, flatten) < 0) {
				fr_dlist_insert_head(list, head_vb);
				goto error;
			}
			(void)fr_dbuff_trim_talloc(&dbuff, SIZE_MAX);
			if (vb_should_free_value(proc_action)) fr_value_box_clear_value(out);
			fr_value_box_memdup_shallow(out, NULL, fr_dbuff_buff(&dbuff), fr_dbuff_used(&dbuff), tainted);
			break;

		default:
			break;
		}
		fr_dlist_insert_head(list, out);
	/*
	 *	Merge all the boxes in the list into
	 *	a single contiguous buffer.
	 *
	 *	This deals with an unrelated out and list
	 *	and also where list is the children of
	 *      out.
	 */
	} else {
		switch (type) {
		case FR_TYPE_STRING:
			if (fr_value_box_list_concat_as_string(&tainted, &sbuff, list,
							       NULL, 0, NULL,
							       proc_action, flatten, true) < 0) goto error;
			(void)fr_sbuff_trim_talloc(&sbuff, SIZE_MAX);

			entry = out->entry;
			fr_value_box_bstrndup_shallow(out, NULL, fr_sbuff_buff(&sbuff), fr_sbuff_used(&sbuff), tainted);
			out->entry = entry;
			break;

		case FR_TYPE_OCTETS:
			if (fr_value_box_list_concat_as_octets(&tainted, &dbuff, list,
							       NULL, 0,
							       proc_action, flatten) < 0) goto error;
			(void)fr_dbuff_trim_talloc(&dbuff, SIZE_MAX);

			entry = out->entry;
			fr_value_box_memdup_shallow(out, NULL, fr_dbuff_buff(&dbuff), fr_dbuff_used(&dbuff), tainted);
			out->entry = entry;
			break;

		default:
			break;
		}
	}

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
uint32_t fr_value_box_hash(fr_value_box_t const *vb)
{
	switch (vb->type) {
	case FR_TYPE_FIXED_SIZE:
		return fr_hash(fr_value_box_raw(vb, vb->type),
			       fr_value_box_field_sizes[vb->type]);

	case FR_TYPE_STRING:
		return fr_hash(vb->vb_strvalue, vb->vb_length);

	case FR_TYPE_OCTETS:
		return fr_hash(vb->vb_octets, vb->vb_length);

	default:
		break;
	}

	return 0;
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

/** Check to see if any list members (or their children) are tainted
 *
 * @param[in] head	of list to check.
 * @return
 *	- true if a list member is tainted.
 *	- false if no list members are tainted.
 */
bool fr_value_box_list_tainted(fr_value_box_list_t const *head)
{
	fr_value_box_t *vb = NULL;

	while ((vb = fr_dlist_next(head, vb))) {
		if (fr_type_is_group(vb->type) && fr_value_box_list_tainted(&vb->vb_group)) return true;
		if (vb->tainted) return true;
	}

	return false;
}

/** Taint every list member (and their children)
 *
 * @param[in] head	of list.
 */
void fr_value_box_list_taint(fr_value_box_list_t *head)
{
	fr_value_box_t *vb = NULL;

	while ((vb = fr_dlist_next(head, vb))) {
		if (fr_type_is_group(vb->type)) fr_value_box_list_taint(&vb->vb_group);
		vb->tainted = true;
	}
}

/** Untaint every list member (and their children)
 *
 * @param[in] head	of list.
 */
void fr_value_box_list_untaint(fr_value_box_list_t *head)
{
	fr_value_box_t *vb = NULL;

	while ((vb = fr_dlist_next(head, vb))) {
		if (fr_type_is_group(vb->type)) fr_value_box_list_untaint(&vb->vb_group);
		vb->tainted = false;
	}
}

/** Validation function to check that a fr_value_box_t is correctly initialised
 *
 */
void value_box_verify(char const *file, int line, fr_value_box_t const *vb, bool talloced)
{
DIAG_OFF(nonnull-compare)
	/*
	 *	nonnull only does something if we're building
	 *	with ubsan...  We still want to assert event
	 *	if we're building without sanitizers.
	 */
	fr_fatal_assert_msg(vb, "CONSISTENCY CHECK FAILED %s[%i]: fr_value_box_t pointer was NULL", file, line);
DIAG_ON(nonnull-compare)

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


/** Mark a value-box as "safe", of a particular type.
 *
 *  Tainted data cannot be marked "safe".  And once data is marked
 *  safe, it cannot be marked as a different type of "safe"
 */
int fr_value_box_mark_safe(fr_value_box_t *box, uint16_t safe)
{
	if (box->tainted) {
		fr_strerror_const("Cannot mark data as 'safe' - it is 'tainted'");
		return -1;
	}

	if (box->safe == safe) return 0;

	if (box->safe != 0) {
		fr_strerror_const("Data was already marked 'safe', of a different type");
		return -1;
	}

	box->safe = safe;
	return 0;
}

/** Mark a value-box as "unsafe"
 *
 *  This always succeeds, and there are no side effects.
 */
void fr_value_box_mark_unsafe(fr_value_box_t *box)
{
	box->safe = 0;
}

/** Check truthiness of values.
 *
 *	The casting rules for expressions / conditions are slightly
 *	different than fr_value_box_cast().  Largely because that
 *	function is used to parse configuration files, and parses "yes
 *	/ no" and "true / false" strings, even if there's no
 *	fr_dict_attr_t passed to it.
 */
bool fr_value_box_is_truthy(fr_value_box_t const *in)
{
	fr_value_box_t box;

	switch (in->type) {
	case FR_TYPE_NULL:
		return false;

	case FR_TYPE_STRUCTURAL:
		if (in->type == FR_TYPE_GROUP) return (fr_value_box_list_len(&in->vb_group) > 0);
		return false;

	case FR_TYPE_BOOL:
		return in->vb_bool;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		return (in->vb_length > 0);

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
		return !fr_ipaddr_is_inaddr_any(&in->vb_ip);

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
		return !((in->vb_ip.prefix == 0) && fr_ipaddr_is_inaddr_any(&in->vb_ip));

	default:
		fr_value_box_init_null(&box);
		(void) fr_value_box_cast(NULL, &box, FR_TYPE_BOOL, NULL, in);
		return box.vb_bool;
	}
}
