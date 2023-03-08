#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Boxed value structures and functions to manipulate them
 *
 * @file src/lib/util/value.h
 *
 * @copyright 2015-2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(value_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define FR_MAX_STRING_LEN	254	/* RFC2138: string 0-253 octets */

typedef struct value_box_s fr_value_box_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/util/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _VALUE_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

extern size_t const fr_value_box_field_sizes[];

extern size_t const fr_value_box_offsets[];

extern fr_sbuff_unescape_rules_t fr_value_unescape_double;
extern fr_sbuff_unescape_rules_t fr_value_unescape_single;
extern fr_sbuff_unescape_rules_t fr_value_unescape_solidus;
extern fr_sbuff_unescape_rules_t fr_value_unescape_backtick;
extern fr_sbuff_unescape_rules_t *fr_value_unescape_by_quote[T_TOKEN_LAST];
extern fr_sbuff_unescape_rules_t *fr_value_unescape_by_char[UINT8_MAX + 1];

extern fr_sbuff_escape_rules_t fr_value_escape_double;
extern fr_sbuff_escape_rules_t fr_value_escape_single;
extern fr_sbuff_escape_rules_t fr_value_escape_solidus;
extern fr_sbuff_escape_rules_t fr_value_escape_backtick;
extern fr_sbuff_escape_rules_t *fr_value_escape_by_quote[T_TOKEN_LAST];
extern fr_sbuff_escape_rules_t *fr_value_escape_by_char[UINT8_MAX + 1];

extern fr_sbuff_escape_rules_t fr_value_escape_unprintables;

/** @name List and cursor type definitions
 */
FR_DLIST_TYPES(fr_value_box_list)
FR_DLIST_TYPEDEFS(fr_value_box_list, fr_value_box_list_t, fr_value_box_entry_t)
FR_DCURSOR_DLIST_TYPES(fr_value_box_dcursor, fr_value_box_list, fr_value_box_t)
/** @{ */

typedef union {
	/*
	*	Variable length values
	*/
	struct {
		union {
			char const 	* _CONST		strvalue;	//!< Pointer to UTF-8 string.
			uint8_t const 	* _CONST 		octets;		//!< Pointer to binary string.
			void 		* _CONST 		ptr;		//!< generic pointer.
		};
		size_t		length;						//!< Only these types are variable length.
	};

	/*
	*	Fixed length values
	*/
	fr_ipaddr_t				ip;			//!< IPv4/6 address/prefix.

	fr_ifid_t				ifid;			//!< IPv6 interface ID.
	fr_ethernet_t				ether;			//!< Ethernet (MAC) address.

	bool					boolean;		//!< A truth value.

	uint8_t					uint8;			//!< 8bit unsigned integer.
	uint16_t				uint16;			//!< 16bit unsigned integer.
	uint32_t				uint32;			//!< 32bit unsigned integer.
	uint64_t				uint64;			//!< 64bit unsigned integer.
	uint128_t				uint128;		//!< 128bit unsigned integer.

	int8_t					int8;			//!< 8bit signed integer.
	int16_t					int16;			//!< 16bit signed integer.
	int32_t					int32;			//!< 32bit signed integer.
	int64_t					int64;			//!< 64bit signed integer;

	float					float32;		//!< Single precision float.
	double					float64;		//!< Double precision float.

	fr_unix_time_t				date;			//!< Date internal format in nanoseconds

	/*
	*	System specific - Used for runtime configuration only.
	*/
	size_t					size;			//!< System specific file/memory size.
	fr_time_delta_t				time_delta;		//!< a delta time in nanoseconds

	fr_value_box_list_t			children;		//!< for groups
} fr_value_box_datum_t;

/** Union containing all data types supported by the server
 *
 * This union contains all data types that can be represented by fr_pair_ts. It may also be used in other parts
 * of the server where values of different types need to be stored.
 *
 * fr_type_t should be an enumeration of the values in this union.
 *
 * Don't change the order of the fields below without checing that the output of radsize doesn't change.
 */
struct value_box_s {
	/** Type and flags should appear together for packing efficiency
	 */
	fr_type_t		_CONST		type;			//!< Type of this value-box, at the start, see pair.h
	bool					tainted;		//!< i.e. did it come from an untrusted source
	uint16_t		_CONST		safe;			//!< more detailed safety

	fr_value_box_entry_t			entry;			//!< Doubly linked list entry.

	fr_dict_attr_t const			*enumv;			//!< Enumeration values.

	fr_value_box_datum_t			datum;			//!< The value held by the value box.  Should appear
									///< last for packing efficiency.
};

/** @name List and cursor function definitions
 */
FR_DLIST_FUNCS(fr_value_box_list, fr_value_box_t, entry)

#define fr_value_box_list_foreach(_list_head, _iter)		fr_dlist_foreach(fr_value_box_list_dlist_head(_list_head), fr_value_box_t, _iter)
#define fr_value_box_list_foreach_safe(_list_head, _iter)	fr_dlist_foreach_safe(fr_value_box_list_dlist_head(_list_head), fr_value_box_t, _iter)

FR_DCURSOR_FUNCS(fr_value_box_dcursor, fr_value_box_list, fr_value_box_t)
/** @} */

/** Actions to perform when we process a box in a list
 *
 */
typedef enum {
	FR_VALUE_BOX_LIST_NONE			= 0x00,			//!< Do nothing to processed boxes.
	FR_VALUE_BOX_LIST_REMOVE		= 0x01,			//!< Remove the box from the input list.
	FR_VALUE_BOX_LIST_FREE_BOX		= (0x02 | FR_VALUE_BOX_LIST_REMOVE), //!< Free each processed box.
	FR_VALUE_BOX_LIST_FREE_BOX_VALUE	= 0x04,			//!< Explicitly free any value buffers associated
									///< with a box.
	FR_VALUE_BOX_LIST_FREE			= (FR_VALUE_BOX_LIST_FREE_BOX | FR_VALUE_BOX_LIST_FREE_BOX_VALUE)
} fr_value_box_list_action_t;

#define vb_should_free(_action)		((_action & FR_VALUE_BOX_LIST_FREE_BOX) == FR_VALUE_BOX_LIST_FREE_BOX)
#define vb_should_free_value(_action)	((_action & FR_VALUE_BOX_LIST_FREE_BOX_VALUE) == FR_VALUE_BOX_LIST_FREE_BOX_VALUE)
#define vb_should_remove(_action)	((_action & FR_VALUE_BOX_LIST_REMOVE) == FR_VALUE_BOX_LIST_REMOVE)

/** @name Field accessors for #fr_value_box_t
 *
 * Use these instead of accessing fields directly to make refactoring
 * easier in future.
 *
 * @{
 */
#define vb_strvalue				datum.strvalue
#define vb_octets				datum.octets
#define vb_void					datum.ptr
#define vb_group				datum.children

#define vb_ip					datum.ip

#define vb_ifid					datum.ifid.addr
#define vb_ether				datum.ether.addr

#define vb_bool					datum.boolean
#define vb_uint8				datum.uint8
#define vb_uint16				datum.uint16
#define vb_uint32				datum.uint32
#define vb_uint64				datum.uint64
#define vb_uint128				datum.uint128

#define vb_int8					datum.int8
#define vb_int16				datum.int16
#define vb_int32				datum.int32
#define vb_int64				datum.int64

#define vb_float32				datum.float32
#define vb_float64				datum.float64

#define vb_date					datum.date

#define vb_size					datum.size
#define vb_timeval				datum.timeval
#define vb_time_delta				datum.time_delta

#define vb_length				datum.length
/** @} */

/** @name Argument boxing macros
 *
 * These macros allow C types to be passed to functions which take
 * boxed arguments, without needing to declare a fr_value_box_t
 * explicitly on the stack.
 *
 * @{
 */
#define _fr_box_with_len(_type, _field, _val, _len) &(fr_value_box_t){ .type = _type, _field = _val, .vb_length = _len }

#define fr_box_strvalue(_val)			_fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, strlen(_val))
#define fr_box_strvalue_len(_val, _len)		_fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, _len)

#define fr_box_octets(_val, _len)		_fr_box_with_len(FR_TYPE_OCTETS, .vb_octets, _val, _len)
#define fr_box_strvalue_buffer(_val)		_fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, talloc_array_length(_val) - 1)
#define fr_box_octets_buffer(_val)		_fr_box_with_len(FR_TYPE_OCTETS, .vb_octets, _val, talloc_array_length(_val))

#define _fr_box(_type, _field, _val) (&(fr_value_box_t){ .type = _type, _field = (_val) })

#define fr_box_ipaddr(_val)			_fr_box((((_val).af == AF_INET) ? \
							(((_val).prefix == 32) ?	FR_TYPE_IPV4_ADDR : \
										FR_TYPE_IPV4_PREFIX) : \
							(((_val).prefix == 128) ?	FR_TYPE_IPV6_ADDR : \
										FR_TYPE_IPV6_PREFIX)), \
						.vb_ip, _val)
#define fr_box_ipv4addr(_val)			_fr_box(FR_TYPE_IPV4_ADDR, .vb_ip, _val)
#define fr_box_ipv4prefix(_val)			_fr_box(FR_TYPE_IPV4_PREFIX, .vb_ip, _val)
#define fr_box_ipv6addr(_val)			_fr_box(FR_TYPE_IPV6_ADDR, .vb_ip, _val)
#define fr_box_ipv6prefix(_val)			_fr_box(FR_TYPE_IPV6_PREFIX, .vb_ip, _val)

#define fr_box_ifid(_val)			_fr_box(FR_TYPE_IFID, .vb_ifid, _val)
#define fr_box_ether(_val)                      &(fr_value_box_t){ .type = FR_TYPE_ETHERNET, .vb_ether = { _val[0], _val[1], _val[2], _val[3], _val[4], _val[5] } }

#define fr_box_bool(_val)			_fr_box(FR_TYPE_BOOL, .vb_bool, _val)

#define fr_box_uint8(_val)			_fr_box(FR_TYPE_UINT8, .vb_uint8, _val)
#define fr_box_uint16(_val)			_fr_box(FR_TYPE_UINT16, .vb_uint16, _val)
#define fr_box_uint32(_val)			_fr_box(FR_TYPE_UINT32, .vb_uint32, _val)
#define fr_box_uint64(_val)			_fr_box(FR_TYPE_UINT64, .vb_uint64, _val)
#define fr_box_uint128(_val)			_fr_box(FR_TYPE_UINT128, .vb_uint128, _val)

#define fr_box_int8(_val)			_fr_box(FR_TYPE_INT8, .vb_int8, _val)
#define fr_box_int16(_val)			_fr_box(FR_TYPE_INT16, .vb_int16, _val)
#define fr_box_int32(_val)			_fr_box(FR_TYPE_INT32, .vb_int32, _val)
#define fr_box_int64(_val)			_fr_box(FR_TYPE_INT64, .vb_int64, _val)

#define fr_box_float32(_val)			_fr_box(FR_TYPE_FLOAT32, .vb_float32, _val)
#define fr_box_float64(_val)			_fr_box(FR_TYPE_FLOAT64, .vb_float64, _val)

#define fr_box_date(_val)			_fr_box(FR_TYPE_DATE, .vb_date, _val)

#define fr_box_time(_val)			_fr_box(FR_TYPE_DATE, .vb_date, fr_time_to_unix_time(_val))

#define fr_box_size(_val)			_fr_box(FR_TYPE_SIZE, .vb_size, _val)

#define _fr_box_with_da(_type, _field, _val, _da) (&(fr_value_box_t){ .type = _type, _field = (_val), .enumv = (_da) })

#define fr_box_time_delta_with_res(_val, _res)	_fr_box_with_da(FR_TYPE_TIME_DELTA, \
								.vb_time_delta, \
								(_val), \
								(&(fr_dict_attr_t){ \
									.name = NULL, \
									.type = FR_TYPE_TIME_DELTA, \
									.flags = { \
										.type_size = _res \
									} \
								}))

#define fr_box_time_delta(_val)			fr_box_time_delta_with_res((_val), FR_TIME_RES_SEC)

#define fr_box_time_delta_sec(_val)		fr_box_time_delta_with_res((_val), FR_TIME_RES_SEC)

#define fr_box_time_delta_msec(_val)		fr_box_time_delta_with_res((_val), FR_TIME_RES_MSEC)

#define fr_box_time_delta_nsec(_val)		fr_box_time_delta_with_res((_val), FR_TIME_RES_NSEC)

#define fr_box_time_delta_usec(_val)		fr_box_time_delta_with_res((_val), FR_TIME_RES_USEC)
/** @} */

/** @name Type checking macros
 *
 * Convenience macros for checking if a box is a
 * specific type.
 *
 * @{
 */
#define fr_box_is_null(_x)			fr_type_is_null((_x)->type)
#define fr_box_is_string(_x)			fr_type_is_string((_x)->type)
#define fr_box_is_octets(_x)			fr_type_is_octets((_x)->type)
#define fr_box_is_ipv4addr(_x)			fr_type_is_ipv4addr((_x)->type)
#define fr_box_is_ipv4prefix(_x)		fr_type_is_ipv4prefix((_x)->type)
#define fr_box_is_ipv6addr(_x)			fr_type_is_ipv6addr((_x)->type)
#define fr_box_is_ipv6prefix(_x)		fr_type_is_ipv6prefix((_x)->type)
#define fr_box_is_ifid(_x)			fr_type_is_ifid((_x)->type)
#define fr_box_is_combo_ipaddr(_x)		fr_type_is_combo_ipaddr((_x)->type)
#define fr_box_is_combo_ipprefix(_x)		fr_type_is_combo_ipprefix((_x)->type)
#define fr_box_is_ethernet(_x)			fr_type_is_ethernet((_x)->type)
#define fr_box_is_bool(_x)			fr_type_is_bool((_x)->type)
#define fr_box_is_uint8(_x)			fr_type_is_uint8((_x)->type)
#define fr_box_is_uint16(_x)			fr_type_is_uint16((_x)->type)
#define fr_box_is_uint32(_x)			fr_type_is_uint32((_x)->type)
#define fr_box_is_uint64(_x)			fr_type_is_uint64((_x)->type)
#define fr_box_is_int8(_x)			fr_type_is_int8((_x)->type)
#define fr_box_is_int16(_x)			fr_type_is_int16((_x)->type)
#define fr_box_is_int32(_x)			fr_type_is_int32((_x)->type)
#define fr_box_is_int64(_x)			fr_type_is_int64((_x)->type)
#define fr_box_is_float32(_x)			fr_type_is_float32((_x)->type)
#define fr_box_is_float64(_x)			fr_type_is_float64((_x)->type)
#define fr_box_is_date(_x)			fr_type_is_date((_x)->type)
#define fr_box_is_time_delta(_x)		fr_type_is_time_delta((_x)->type)
#define fr_box_is_size(_x)			fr_type_is_size((_x)->type)
#define fr_box_is_tlv(_x)			fr_type_is_tlv((_x)->type)
#define fr_box_is_struct(_x)			fr_type_is_struct((_x)->type)
#define fr_box_is_vsa(_x)			fr_type_is_vsa((_x)->type)
#define fr_box_is_vendor(_x)			fr_type_is_vendor((_x)->type)
#define fr_box_is_group(_x)			fr_type_is_group((_x)->type)
#define fr_box_is_value_box(_x)			fr_type_is_value_box((_x)->type)
#define fr_box_is_void(_x)			fr_type_is_void((_x)->type)

#define fr_box_is_integer_except_bool(_x)	fr_type_is_integer_except_bool((_x)->type)
#define fr_box_is_integer(_x)			fr_type_is_integer((_x)->type)
#define fr_box_is_numeric(_x)			fr_type_is_numeric((_x)->type)

#define fr_box_is_ip(_x)			fr_type_is_ip((_x)->type)

#define fr_box_is_fixed_size(_x)		fr_type_is_fixed_size((_x)->type)
#define fr_box_is_variable_size(_x)		fr_type_is_variable_size((_x)->type)
#define fr_box_is_value(_x)			fr_type_is_value((_x)->type)
#define fr_box_is_quoted(_x)			fr_type_is_quoted((_x)->type)

#define fr_box_is_structural_except_vsa(_x)	fr_type_is_structural_except_vsa((_x)->type)
#define fr_box_is_structural(_x)		fr_type_is_structural((_x)->type)
#define fr_box_is_non_value(_x)			fr_type_is_non_value((_x)->type)
/** @} */

/** @name Parsing rules for various types of string
 *
 * @{
 */
extern fr_sbuff_parse_rules_t const value_parse_rules_bareword_unquoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_double_unquoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_single_unquoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_solidus_unquoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_backtick_unquoted;
extern fr_sbuff_parse_rules_t const *value_parse_rules_unquoted[T_TOKEN_LAST];
extern fr_sbuff_parse_rules_t const *value_parse_rules_unquoted_char[UINT8_MAX];

extern fr_sbuff_parse_rules_t const value_parse_rules_bareword_quoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_double_quoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_single_quoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_solidus_quoted;
extern fr_sbuff_parse_rules_t const value_parse_rules_backtick_quoted;
extern fr_sbuff_parse_rules_t const *value_parse_rules_quoted[T_TOKEN_LAST];
extern fr_sbuff_parse_rules_t const *value_parse_rules_quoted_char[UINT8_MAX];
/** @} */

/** @name Convenience functions
 *
 * These macros and inline functions simplify working
 * with lists of value boxes.
 *
 * @{
 */
/** Determines whether a list contains the number of boxes required
 *
 * @param[in] list	of value boxes.
 * @param[in] min	The number of boxes required to return true.
 * @return
 *	- true if the list has at least min boxes.
 *	- false if the list has fewer than min boxes.
 */
static inline CC_HINT(nonnull)
bool fr_value_box_list_len_min(fr_value_box_list_t const *list, unsigned int min)
{
	unsigned int i = fr_value_box_list_num_elements(list);

	return (i >= min);
}
/** @} */

/** @name Box to box copying
 *
 * @{
 */
void		fr_value_box_clear_value(fr_value_box_t *data)
		CC_HINT(nonnull(1));

void		fr_value_box_clear(fr_value_box_t *data)
		CC_HINT(nonnull(1));

int		fr_value_box_copy(TALLOC_CTX *ctx, fr_value_box_t *dst, const fr_value_box_t *src)
		CC_HINT(nonnull(2,3));

void		fr_value_box_copy_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst,
					  const fr_value_box_t *src)
		CC_HINT(nonnull(2,3));

int		fr_value_box_steal(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_t *src)
		CC_HINT(nonnull(2,3));
/** @} */

/** @name Value box assignment functions
 *
 * These functions allow C values to be assigned to value boxes.
 * They will work with uninitialised/stack allocated memory.
 *
 * @{
 */

/** Initialise a fr_value_box_t
 *
 * The value should be set later with one of the fr_value_box_* functions.
 *
 * @param[in] vb	to initialise.
 * @param[in] type	to set.
 * @param[in] enumv	Enumeration values.
 * @param[in] tainted	Whether data will come from an untrusted source.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull(1), always_inline)
void fr_value_box_init(fr_value_box_t *vb, fr_type_t type, fr_dict_attr_t const *enumv, bool tainted)
{
	memcpy(vb, &(fr_value_box_t){
	       		.type = type,
			.enumv = enumv,
			.tainted = tainted
	       }, sizeof(*vb));
	fr_value_box_list_entry_init(vb);

	/*
	 *	The majority of types are fine to initialise to
	 *	all zeros, the following are the exceptions.
	 */
	switch (type) {
	case FR_TYPE_STRUCTURAL:
		fr_value_box_list_init(&vb->vb_group);
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_COMBO_IP_ADDR:	/* Default to the smaller type */
		vb->vb_ip.af = AF_INET;
		vb->vb_ip.prefix = 32;
		break;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_COMBO_IP_PREFIX:	/* Default to the samaller type */
		vb->vb_ip.af = AF_INET;
		break;

	case FR_TYPE_IPV6_ADDR:
		vb->vb_ip.af = AF_INET6;
		vb->vb_ip.prefix = 128;
		break;

	case FR_TYPE_IPV6_PREFIX:
		vb->vb_ip.af = AF_INET6;
		break;

	default:
		break;
	}
}

/** Initialise an empty/null box that will be filled later
 *
 */
static inline CC_HINT(always_inline)
void fr_value_box_init_null(fr_value_box_t *vb)
{
	fr_value_box_init(vb, FR_TYPE_NULL, NULL, false);
}

/** Allocate a value box of a specific type
 *
 * Allocates memory for the box, and sets the length of the value
 * for fixed length types.
 *
 * @param[in] ctx	to allocate the value_box in.
 * @param[in] type	of value.
 * @param[in] enumv	Enumeration values.
 * @param[in] tainted	Whether data will come from an untrusted source.
 * @return
 *	- A new fr_value_box_t.
 *	- NULL on error.
 */
static inline CC_HINT(always_inline)
fr_value_box_t *fr_value_box_alloc(TALLOC_CTX *ctx, fr_type_t type, fr_dict_attr_t const *enumv, bool tainted)
{
	fr_value_box_t *vb;

	vb = talloc(ctx, fr_value_box_t);
	if (unlikely(!vb)) return NULL;

	fr_value_box_init(vb, type, enumv, tainted);

	return vb;
}

/** Allocate a value box for later use with a value assignment function
 *
 * @param[in] ctx	to allocate the value_box in.
 * @return
 *	- A new fr_value_box_t.
 *	- NULL on error.
 *
 *  @hidecallergraph
 */
static inline CC_HINT(always_inline)
fr_value_box_t *fr_value_box_alloc_null(TALLOC_CTX *ctx)
{
	return fr_value_box_alloc(ctx, FR_TYPE_NULL, NULL, false);
}

/** Return a pointer to the "raw" value from a value-box.
 *
 *  This has "const" input and "unconst" output because sometimes it's used
 *  to copy out of, and sometimes in to, a value-box.  We rely on the caller to know
 *  the correct uses of it.
 */
static inline CC_HINT(always_inline)
uint8_t *fr_value_box_raw(fr_value_box_t const *vb, fr_type_t type)
{
	return UNCONST(uint8_t *, vb) + fr_value_box_offsets[type];
}

/** Copy the value of a value box to a field in a C struct
 *
 * This is useful when interacting with 3rd party libraries, and doing configuration parsing
 * as it allows us to use standard parsing and casting functions and then emit the result
 * as a C value.
 *
 * The field pointed to by out must be of the same type as we use to represent the value boxe's
 * value in its datum union, or at least the same size.
 *
 * No checks are done to ensure this is the case, so if you get this wrong it'll lead to silent
 * memory corruption.
 *
 * @param[out] out	Field in struct to write variable to.
 * @param[in] vb	to copy value from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline)
int fr_value_box_memcpy_out(void *out, fr_value_box_t const *vb)
{
	size_t len;

	len = fr_value_box_field_sizes[vb->type];
	if (len == 0) {
		fr_strerror_printf("Type %s not supported for conversion to C type", fr_type_to_str(vb->type));
		return -1;
	}

	memcpy(out, ((uint8_t const *)vb) + fr_value_box_offsets[vb->type], len);

	return 0;
}

/** Copy a C value value to a value box.
 *
 * This is useful when interacting with 3rd party libraries, and doing configuration parsing
 * as it allows us to use standard parsing and casting functions and then emit the result
 * as a C value.
 *
 * The field pointed to by in must be of the same type as we use to represent the value boxe's
 * value in its datum union, or at least the same size.
 *
 * No checks are done to ensure this is the case, so if you get this wrong it'll lead to silent
 * memory corruption.
 *
 * @param[in] vb	destination value box, MUST already be initialized
 * @param[out] in	C variable to read from
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline)
int fr_value_box_memcpy_in(fr_value_box_t *vb, void const *in)
{
	size_t len;

	len = fr_value_box_field_sizes[vb->type];
	if (len == 0) {
		fr_strerror_printf("Type %s not supported for conversion to C type", fr_type_to_str(vb->type));
		return -1;
	}

	memcpy(((uint8_t *)vb) + fr_value_box_offsets[vb->type], in, len);

	return 0;
}


/** Box an ethernet value (6 bytes, network byte order)
 *
 * @param[in] dst	Where to copy the ethernet address to.
 * @param[in] enumv	Enumeration values.
 * @param[in] src	The ethernet address.
 * @param[in] tainted	Whether data will come from an untrusted source.
 * @return 0 (always successful).
 */
static inline CC_HINT(nonnull(1,3), always_inline) \
int fr_value_box_ethernet_addr(fr_value_box_t *dst, fr_dict_attr_t const *enumv, \
			       fr_ethernet_t const *src, bool tainted)
{
	fr_value_box_init(dst, FR_TYPE_ETHERNET, enumv, tainted);
	memcpy(dst->vb_ether, src, sizeof(dst->vb_ether));
	return 0;
}

#define DEF_BOXING_FUNC(_ctype, _field, _type) \
static inline CC_HINT(nonnull(1), always_inline) \
int fr_value_box_##_field(fr_value_box_t *dst, fr_dict_attr_t const *enumv, \
			  _ctype const value, bool tainted) { \
	fr_value_box_init(dst, _type, enumv, tainted); \
	dst->vb_##_field = value; \
	return 0; \
}

DEF_BOXING_FUNC(bool, bool, FR_TYPE_BOOL)

DEF_BOXING_FUNC(uint8_t, uint8, FR_TYPE_UINT8)
DEF_BOXING_FUNC(uint16_t, uint16, FR_TYPE_UINT16)
DEF_BOXING_FUNC(uint32_t, uint32, FR_TYPE_UINT32)
DEF_BOXING_FUNC(uint64_t, uint64, FR_TYPE_UINT64)

DEF_BOXING_FUNC(int8_t, int8, FR_TYPE_INT8)
DEF_BOXING_FUNC(int16_t, int16, FR_TYPE_INT16)
DEF_BOXING_FUNC(int32_t, int32, FR_TYPE_INT32)
DEF_BOXING_FUNC(int64_t, int64, FR_TYPE_INT64)

DEF_BOXING_FUNC(float, float32, FR_TYPE_FLOAT32)
DEF_BOXING_FUNC(double, float64, FR_TYPE_FLOAT64)

DEF_BOXING_FUNC(fr_unix_time_t, date, FR_TYPE_DATE)

/** Automagically fill in a box, determining the value type from the type of the C variable
 *
 * Simplify boxing for simple C types using the _Generic macro to emit code that
 * fills in the value box based on the type of _var provided.
 *
 * @note Will not set the box value to tainted.  You should do this manually if required.
 *
 * @note Will not work for all box types.  Will default to the 'simpler' box type, if the mapping
 *	 between C type and box type is ambiguous.
 *
 * @param[in] _box	to assign value to.
 * @param[in] _var	C variable to assign value from.
 * @param[in] _tainted	Whether the value came from an untrusted source.
 */
#define fr_value_box(_box, _var, _tainted) \
_Generic((_var), \
	fr_ipaddr_t *		: fr_value_box_ipaddr, \
	fr_ipaddr_t const *	: fr_value_box_ipaddr, \
	fr_ethernet_t *		: fr_value_box_ethernet_addr, \
	fr_ethernet_t const *	: fr_value_box_ethernet_addr, \
	bool			: fr_value_box_bool, \
	uint8_t			: fr_value_box_uint8, \
	uint16_t		: fr_value_box_uint16, \
	uint32_t		: fr_value_box_uint32, \
	uint64_t		: fr_value_box_uint64, \
	int8_t			: fr_value_box_int8, \
	int16_t			: fr_value_box_int16, \
	int32_t			: fr_value_box_int32, \
	int64_t			: fr_value_box_int64, \
	float			: fr_value_box_float32, \
	double			: fr_value_box_float64 \
)(_box, NULL, _var, _tainted)

/** Automagically fill in a box, for types with length
 *
 * @param[in] _ctx	to allocate value in.
 * @param[in] _box	to assign value to.
 * @param[in] _var	C variable to assign value from.
 * @param[in] _len	of C variable.
 * @param[in] _tainted	Whether the value came from an untrusted source.
 */
#define fr_value_box_len(_ctx, _box, _var, _len, _tainted) \
_Generic((_var), \
	char *			: fr_value_box_bstrndup, \
	char const *		: fr_value_box_bstrndup, \
	uint8_t *		: fr_value_box_memdup, \
	uint8_t const *		: fr_value_box_memdup \
)(_ctx, _box, NULL, _var, _len, _tainted)

/** Unbox an ethernet value (6 bytes, network byte order)
 *
 * @param[in] dst	Where to copy the ethernet address to.
 * @param[in] src	Where to copy the ethernet address from.
 * @return
 *	- 0 on success.
 *	- -1 on type mismatch.
 */
static inline CC_HINT(nonnull)
int fr_value_unbox_ethernet_addr(fr_ethernet_t *dst, fr_value_box_t *src)
{
	if (unlikely(src->type != FR_TYPE_ETHERNET)) { \
		fr_strerror_printf("Unboxing failed.  Needed type %s, had type %s",
				   fr_type_to_str(FR_TYPE_ETHERNET),
				   fr_type_to_str(src->type));
		return -1; \
	}
	memcpy(dst, src->vb_ether, sizeof(src->vb_ether));	/* Must be src, dst is a pointer */
	return 0;
}

#define DEF_UNBOXING_FUNC(_ctype, _field, _type) \
static inline CC_HINT(nonnull)  \
int fr_value_unbox_##_field(_ctype *var, fr_value_box_t const *src) { \
	if (unlikely(src->type != _type)) { \
		fr_strerror_printf("Unboxing failed.  Needed type %s, had type %s", \
				   fr_type_to_str(_type), \
				   fr_type_to_str(src->type)); \
		return -1; \
	} \
	*var = src->vb_##_field; \
	return 0; \
}

DEF_UNBOXING_FUNC(uint8_t, uint8, FR_TYPE_UINT8)
DEF_UNBOXING_FUNC(uint16_t, uint16, FR_TYPE_UINT16)
DEF_UNBOXING_FUNC(uint32_t, uint32, FR_TYPE_UINT32)
DEF_UNBOXING_FUNC(uint64_t, uint64, FR_TYPE_UINT64)

DEF_UNBOXING_FUNC(int8_t, int8, FR_TYPE_INT8)
DEF_UNBOXING_FUNC(int16_t, int16, FR_TYPE_INT16)
DEF_UNBOXING_FUNC(int32_t, int32, FR_TYPE_INT32)
DEF_UNBOXING_FUNC(int64_t, int64, FR_TYPE_INT64)

DEF_UNBOXING_FUNC(float, float32, FR_TYPE_FLOAT32)
DEF_UNBOXING_FUNC(double, float64, FR_TYPE_FLOAT64)

DEF_UNBOXING_FUNC(fr_unix_time_t, date, FR_TYPE_DATE)

/** Unbox simple types peforming type checks
 *
 * @param[out] _var	to write to.
 * @param[in] _box	to unbox.
 */
#define fr_value_unbox_shallow(_var, _box) \
_Generic((_var), \
	uint8_t	*		: fr_value_unbox_uint8, \
	uint16_t *		: fr_value_unbox_uint16, \
	uint32_t *		: fr_value_unbox_uint32, \
	uint64_t *		: fr_value_unbox_uint64, \
	int8_t *		: fr_value_unbox_int8, \
	int16_t	*		: fr_value_unbox_int16, \
	int32_t	*		: fr_value_unbox_int32, \
	int64_t	*		: fr_value_unbox_int64, \
	float *			: fr_value_unbox_float32, \
	double *		: fr_value_unbox_float64 \
)(_var, _box)

/** @} */

/*
 *	Comparison
 */
int8_t		fr_value_box_cmp(fr_value_box_t const *a, fr_value_box_t const *b)
		CC_HINT(nonnull);

int		fr_value_box_cmp_op(fr_token_t op, fr_value_box_t const *a, fr_value_box_t const *b)
		CC_HINT(nonnull);

/*
 *	Conversion
 */
size_t		fr_value_str_unescape(fr_sbuff_t *out, fr_sbuff_t *in, size_t inlen, char quote)
		CC_HINT(nonnull);

size_t		fr_value_substr_unescape(fr_sbuff_t *out, fr_sbuff_t *in, size_t inlen, char quote)
		CC_HINT(nonnull);

static inline size_t fr_value_str_aunescape(TALLOC_CTX *ctx, char **out, fr_sbuff_t *in, size_t inlen, char quote)
SBUFF_OUT_TALLOC_FUNC_DEF(fr_value_str_unescape, in, inlen, quote)

static inline size_t fr_value_substr_aunescape(TALLOC_CTX *ctx, char **out, fr_sbuff_t *in, size_t inlen, char quote)
SBUFF_OUT_TALLOC_FUNC_DEF(fr_value_substr_unescape, in, inlen, quote)

int		fr_value_box_hton(fr_value_box_t *dst, fr_value_box_t const *src)
		CC_HINT(nonnull);

size_t		fr_value_box_network_length(fr_value_box_t const *value)
		CC_HINT(nonnull);

ssize_t		fr_value_box_to_network(fr_dbuff_t *dbuff, fr_value_box_t const *value);
#define FR_VALUE_BOX_TO_NETWORK_RETURN(_dbuff, _value) FR_DBUFF_RETURN(fr_value_box_to_network, _dbuff, _value)

int		fr_value_box_to_key(uint8_t **out, size_t *outlen, fr_value_box_t const *value)
		CC_HINT(nonnull);

/** Special value to indicate fr_value_box_from_network experienced a general error
 */
#define FR_VALUE_BOX_NET_ERROR	SSIZE_MIN

/** Special value to indicate fr_value_box_from_network hit an out of memory error
 */
#define FR_VALUE_BOX_NET_OOM	(FR_VALUE_BOX_NET_ERROR + 1)

/** Special value to ensure other encoding/decoding errors don't overlap
 */
#define FR_VALUE_BOX_NET_MAX	(FR_VALUE_BOX_NET_OOM + 1)

ssize_t		fr_value_box_from_network(TALLOC_CTX *ctx,
					  fr_value_box_t *dst, fr_type_t type, fr_dict_attr_t const *enumv,
					  fr_dbuff_t *dbuff, size_t len, bool tainted)
		CC_HINT(nonnull(2,5));

int		fr_value_box_cast(TALLOC_CTX *ctx, fr_value_box_t *dst,
				  fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				  fr_value_box_t const *src)
		CC_HINT(nonnull(2,5));

int		fr_value_box_cast_in_place(TALLOC_CTX *ctx, fr_value_box_t *vb,
					   fr_type_t dst_type, fr_dict_attr_t const *dst_enumv)
		CC_HINT(nonnull(1));

bool		fr_value_box_is_truthy(fr_value_box_t const *box)
		CC_HINT(nonnull(1));

int		fr_value_box_ipaddr(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    fr_ipaddr_t const *ipaddr, bool tainted)
		CC_HINT(nonnull(1,3));

int		fr_value_unbox_ipaddr(fr_ipaddr_t *dst, fr_value_box_t *src)
		CC_HINT(nonnull);

static inline CC_HINT(nonnull, always_inline)
bool fr_value_box_is_safe(fr_value_box_t const *box, uint16_t safe)
{
	if (!safe) return false;

	return (box->safe == safe);
}

int		fr_value_box_mark_safe(fr_value_box_t *box, uint16_t safe)
		CC_HINT(nonnull);

void		fr_value_box_mark_unsafe(fr_value_box_t *box)
		CC_HINT(nonnull);



/** @name Assign and manipulate binary-unsafe C strings
 *
 * @{
 */
int		fr_value_box_strdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    char const *src, bool tainted)
		CC_HINT(nonnull(2,4));

int		fr_value_box_strtrim(TALLOC_CTX *ctx, fr_value_box_t *vb)
		CC_HINT(nonnull(1));

int		fr_value_box_vasprintf(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv, bool tainted,
				       char const *fmt, va_list ap)
		CC_HINT(nonnull(2,5), format(printf,5,0));

int		fr_value_box_asprintf(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv, bool tainted,
				      char const *fmt, ...)
		CC_HINT(format(printf,5,6), nonnull(2,5));

void		fr_value_box_strdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    char const *src, bool tainted)
		CC_HINT(nonnull(1,3));
/** @} */

/** @name Assign and manipulate binary-safe strings
 *
 * @{
 */
int		fr_value_box_bstr_alloc(TALLOC_CTX *ctx, char **out, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					size_t len, bool tainted)
		CC_HINT(nonnull(3));

int		fr_value_box_bstr_realloc(TALLOC_CTX *ctx, char **out, fr_value_box_t *dst, size_t len)
		CC_HINT(nonnull(3));

int		fr_value_box_bstrndup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				      char const *src, size_t len, bool tainted)
		CC_HINT(nonnull(2)); /* src may be NULL if len == 0 */

int		fr_value_box_bstrndup_dbuff(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    fr_dbuff_t *dbuff, size_t len, bool tainted)
		CC_HINT(nonnull(2,4));

int		fr_value_box_bstrdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					   char const *src, bool tainted)
		CC_HINT(nonnull(2,4));

void		fr_value_box_bstrndup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					      char const *src, size_t len, bool tainted)
		CC_HINT(nonnull(1,3));

int		fr_value_box_bstrdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
						    char const *src, bool tainted)
		CC_HINT(nonnull(2,4));

int		fr_value_box_bstrn_append(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, size_t len, bool tainted)
		CC_HINT(nonnull(2,3));

int		fr_value_box_bstr_append_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, char const *src, bool tainted)
		CC_HINT(nonnull(2,3));
/** @} */

/** @name Assign and manipulate octets strings
 *
 * @{
 */
int		fr_value_box_mem_alloc(TALLOC_CTX *ctx, uint8_t **out, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				       size_t len, bool tainted)
		CC_HINT(nonnull(3));

int		fr_value_box_mem_realloc(TALLOC_CTX *ctx, uint8_t **out, fr_value_box_t *dst, size_t len)
		CC_HINT(nonnull(3));

int		fr_value_box_memdup(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
				    uint8_t const *src, size_t len, bool tainted)
		CC_HINT(nonnull(2)); /* src may be NULL if len == 0 */

int		fr_value_box_memdup_dbuff(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					  fr_dbuff_t *dbuff, size_t len, bool tainted)
		CC_HINT(nonnull(2,4));

int		fr_value_box_memdup_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					   uint8_t const *src, bool tainted)
		CC_HINT(nonnull(2,4));

void		fr_value_box_memdup_shallow(fr_value_box_t *dst, fr_dict_attr_t const *enumv,
					    uint8_t const *src, size_t len, bool tainted)
		CC_HINT(nonnull(1,3));

void		fr_value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_dict_attr_t const *enumv,
						   uint8_t const *src, bool tainted)
		CC_HINT(nonnull(2,4));

int		fr_value_box_mem_append(TALLOC_CTX *ctx, fr_value_box_t *dst,
				       uint8_t const *src, size_t len, bool tainted)
		CC_HINT(nonnull(2,3));

int		fr_value_box_mem_append_buffer(TALLOC_CTX *ctx, fr_value_box_t *dst, uint8_t const *src, bool tainted)
		CC_HINT(nonnull(2,3));
/** @} */

void		fr_value_box_increment(fr_value_box_t *vb)
		CC_HINT(nonnull);

/** @name Parsing
 *
 * @{
 */
ssize_t		fr_value_box_from_substr(TALLOC_CTX *ctx, fr_value_box_t *dst,
					 fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
					 fr_sbuff_t *in, fr_sbuff_parse_rules_t const *rules, bool tainted)
		CC_HINT(nonnull(2,5));

ssize_t		fr_value_box_from_str(TALLOC_CTX *ctx, fr_value_box_t *dst,
				      fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				      char const *in, size_t inlen,
				      fr_sbuff_unescape_rules_t const *erules, bool tainted)
		CC_HINT(nonnull(2,5));
/** @} */

/** @name Work with lists of boxed values
 *
 * @{
 */
ssize_t 	fr_value_box_list_concat_as_string(bool *tainted, fr_sbuff_t *sbuff, fr_value_box_list_t *list,
					   	  char const *sep, size_t sep_len, fr_sbuff_escape_rules_t const *e_rules,
					   	  fr_value_box_list_action_t proc_action, bool flatten, bool printable)
		CC_HINT(nonnull(2,3));

ssize_t		fr_value_box_list_concat_as_octets(bool *tainted, fr_dbuff_t *dbuff, fr_value_box_list_t *list,
						   uint8_t const *sep, size_t sep_len,
						   fr_value_box_list_action_t proc_action, bool flatten)
		CC_HINT(nonnull(2,3));

int		fr_value_box_list_concat_in_place(TALLOC_CTX *ctx,
						  fr_value_box_t *out, fr_value_box_list_t *list, fr_type_t type,
						  fr_value_box_list_action_t proc_action, bool flatten,
						  size_t max_size)
		CC_HINT(nonnull(2,3));

void		fr_value_box_flatten(TALLOC_CTX *ctx, fr_value_box_list_t *list, bool steal, bool free)
		CC_HINT(nonnull(2));

char		*fr_value_box_list_aprint(TALLOC_CTX *ctx, fr_value_box_list_t const *list, char const *delim,
					  fr_sbuff_escape_rules_t const *e_rules)
		CC_HINT(nonnull(2));

int		fr_value_box_list_acopy(TALLOC_CTX *ctx, fr_value_box_list_t *out, fr_value_box_list_t const *in)
		CC_HINT(nonnull(2,3));

bool		fr_value_box_list_tainted(fr_value_box_list_t const *head)
		CC_HINT(nonnull(1));

void		fr_value_box_list_taint(fr_value_box_list_t *head)
		CC_HINT(nonnull(1));

void		fr_value_box_list_untaint(fr_value_box_list_t *head)
		CC_HINT(nonnull(1));
/** @} */

/** @name Print the value of a value box as a string
 *
 * @{
 */
ssize_t		fr_value_box_print(fr_sbuff_t *out, fr_value_box_t const *data, fr_sbuff_escape_rules_t const *e_rules)
		CC_HINT(nonnull(1,2));

ssize_t		fr_value_box_print_quoted(fr_sbuff_t *out, fr_value_box_t const *data, fr_token_t quote)
		CC_HINT(nonnull);

static inline CC_HINT(nonnull(2,3))
		fr_slen_t fr_value_box_aprint(TALLOC_CTX *ctx, char **out,
					      fr_value_box_t const *data, fr_sbuff_escape_rules_t const *e_rules)
		SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(fr_value_box_print, data, e_rules)

static inline CC_HINT(nonnull(2,3))
		fr_slen_t fr_value_box_aprint_quoted(TALLOC_CTX *ctx, char **out,
						     fr_value_box_t const *data, fr_token_t quote)
		SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(fr_value_box_print_quoted, data, quote)

/** @} */
/** @name Hashing
 *
 * @{
 */
uint32_t	fr_value_box_hash(fr_value_box_t const *vb);

/** @} */

void		fr_value_box_verify(char const *file, int line, fr_value_box_t const *vb, bool talloced)
		CC_HINT(nonnull(3));
void		fr_value_box_list_verify(char const *file, int line, fr_value_box_list_t const *list, bool talloced)
		CC_HINT(nonnull(3));

#ifdef WITH_VERIFY_PTR
#  define VALUE_BOX_VERIFY(_x) fr_value_box_verify(__FILE__, __LINE__, _x, false)
#  define VALUE_BOX_LIST_VERIFY(_x) fr_value_box_list_verify(__FILE__, __LINE__, _x, false)
#  define VALUE_BOX_TALLOC_VERIFY(_x) fr_value_box_verify(__FILE__, __LINE__, _x, true)
#  define VALUE_BOX_TALLOC_LIST_VERIFY(_x) fr_value_box_list_verify(__FILE__, __LINE__, _x, true)
#else
/*
 *  Even if were building without WITH_VERIFY_PTR
 *  the pointer must not be NULL when these various macros are used
 *  so we can add some sneaky asserts.
 */
#  define VALUE_BOX_VERIFY(_x) fr_assert(_x)
#  define VALUE_BOX_LIST_VERIFY(_x) fr_assert(_x)
#  define VALUE_BOX_TALLOC_VERIFY(_x) fr_assert(_x)
#  define VALUE_BOX_TALLOC_LIST_VERIFY(_x) fr_assert(_x)
#endif

/** @name Debug functions
 *
 * @{
 */
void fr_value_box_list_debug(fr_value_box_list_t const *head);
void fr_value_box_debug(fr_value_box_t const *vb);
/** @} */

#undef _CONST

#ifdef __cplusplus
}
#endif
