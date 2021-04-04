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

/** Types of values contained within an #fr_value_box_t
 *
 * @file src/lib/util/types.h
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2017 The FreeRADIUS server project
 */
RCSIDH(types_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/** Internal data types
 */
typedef enum {
	FR_TYPE_NULL = 0,			//!< Invalid (uninitialised) attribute type.

	FR_TYPE_STRING,				//!< String of printable characters.
	FR_TYPE_OCTETS,				//!< Raw octets.

	FR_TYPE_IPV4_ADDR,			//!< 32 Bit IPv4 Address.
	FR_TYPE_IPV4_PREFIX,			//!< IPv4 Prefix.
	FR_TYPE_IPV6_ADDR,			//!< 128 Bit IPv6 Address.
	FR_TYPE_IPV6_PREFIX,			//!< IPv6 Prefix.
	FR_TYPE_IFID,				//!< Interface ID.
	FR_TYPE_COMBO_IP_ADDR,			//!< IPv4 or IPv6 address depending on length.
	FR_TYPE_COMBO_IP_PREFIX,		//!< IPv4 or IPv6 address prefix depending on length.
	FR_TYPE_ETHERNET,			//!< 48 Bit Mac-Address.

	FR_TYPE_BOOL,				//!< A truth value.

	FR_TYPE_UINT8,				//!< 8 Bit unsigned integer.
	FR_TYPE_UINT16,				//!< 16 Bit unsigned integer.
	FR_TYPE_UINT32,				//!< 32 Bit unsigned integer.
	FR_TYPE_UINT64,				//!< 64 Bit unsigned integer.


	FR_TYPE_INT8,				//!< 8 Bit signed integer.
	FR_TYPE_INT16,				//!< 16 Bit signed integer.
	FR_TYPE_INT32,				//!< 32 Bit signed integer.
	FR_TYPE_INT64,				//!< 64 Bit signed integer.

	FR_TYPE_FLOAT32,			//!< Single precision floating point.
	FR_TYPE_FLOAT64,			//!< Double precision floating point.

	FR_TYPE_DATE,				//!< Unix time stamp, always has value >2^31

	FR_TYPE_TIME_DELTA,			//!< A period of time measured in nanoseconds.

	FR_TYPE_SIZE,				//!< Unsigned integer capable of representing any memory
						//!< address on the local system.

	FR_TYPE_TLV,				//!< Contains nested attributes.
	FR_TYPE_STRUCT,				//!< like TLV, but without T or L, and fixed-width children

	FR_TYPE_VSA,				//!< Vendor-Specific, for RADIUS attribute 26.
	FR_TYPE_VENDOR,				//!< Attribute that represents a vendor in the attribute tree.

	FR_TYPE_GROUP,				//!< A grouping of other attributes
	FR_TYPE_VALUE_BOX,			//!< A boxed value.

	FR_TYPE_VOID,				//!< User data.  Should be a talloced chunk
						///< assigned to the ptr value of the union.

	FR_TYPE_MAX				//!< Number of defined data types.
} fr_type_t;

/** @name Type grouping macros
 *
 * @{
 */

/** All integer types except bool
 *
 * - Integers
 * - Dates
 * - Delta
 */
#define FR_TYPE_INTEGER_EXCEPT_BOOL_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_UINT8) \
	_mid(FR_TYPE_UINT16) \
	_mid(FR_TYPE_UINT32) \
	_mid(FR_TYPE_UINT64) \
	_mid(FR_TYPE_INT8) \
	_mid(FR_TYPE_INT16) \
	_mid(FR_TYPE_INT32) \
	_mid(FR_TYPE_INT64) \
	_mid(FR_TYPE_DATE) \
	_mid(FR_TYPE_TIME_DELTA) \
	_end(FR_TYPE_SIZE)

/** Signed or unsigned integers
 *
 * - Integers
 * - Dates
 * - Deltas
 * - Bools
 */
#define FR_TYPE_INTEGER_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_BOOL) \
	FR_TYPE_INTEGER_EXCEPT_BOOL_DEF(_mid, _mid, _end)

/** Naturally numeric types
 *
 * - Integers
 * - Dates
 * - Deltas
 * - Bools
 * - Floats
 */
#define FR_TYPE_NUMERIC_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_FLOAT32) \
	_mid(FR_TYPE_FLOAT64) \
	FR_TYPE_INTEGER_DEF(_mid, _mid, _end)

/** Types which can fit in an #fr_ipaddr_t
 *
 * - IPv4 addresses
 * - IPv6 addresses
 * - IPv4 prefix
 * - IPv6 prefix
 */
#define FR_TYPE_IP_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_IPV4_ADDR) \
	_mid(FR_TYPE_IPV4_PREFIX) \
	_mid(FR_TYPE_IPV6_ADDR) \
	_end(FR_TYPE_IPV6_PREFIX)

/** Match all fixed length types
 *
 * - Network addresses
 * - Integers
 * - All other fixed types
 */
#define FR_TYPE_FIXED_SIZE_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_ETHERNET) \
	_mid(FR_TYPE_IFID) \
	FR_TYPE_IP_DEF(_mid, _mid, _mid) \
	FR_TYPE_NUMERIC_DEF(_mid, _mid, _end)

/** Match all variable length types
 *
 * - Strings
 * - Octets
 */
#define FR_TYPE_VARIABLE_SIZE_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_STRING) \
	_end(FR_TYPE_OCTETS)

/** Types which represent concrete values
 *
 * - Network addresses
 * - Strings
 * - Octets
 * - Numbers
 */
#define FR_TYPE_VALUES_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_ETHERNET) \
	_mid(FR_TYPE_IFID) \
	FR_TYPE_IP_DEF(_mid, _mid, _mid) \
	FR_TYPE_VARIABLE_SIZE_DEF(_mid, _mid, _mid) \
	FR_TYPE_NUMERIC_DEF(_mid, _mid, _end)

/** Types which should be wrapped in double quotes when printed
 *
 * - Strings
 * - Dates
 */
#define FR_TYPE_QUOTED_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_STRING) \
	_end(FR_TYPE_DATE)

/** Stupid hack for things which produce special error messages for VSAs
 *
 * - Groups
 * - Structs
 * - TLVs
 * - Vendors
 */
#define FR_TYPE_STRUCTURAL_EXCEPT_VSA_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_GROUP) \
	_mid(FR_TYPE_STRUCT) \
	_mid(FR_TYPE_TLV) \
	_end(FR_TYPE_VENDOR)

/** Match all non value types in case statements
 *
 * - Groups
 * - Structs
 * - TLVs
 * - Vendors
 * - VSAs (i.e. a container of vendors)
 */
#define FR_TYPE_STRUCTURAL_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_VSA) \
	FR_TYPE_STRUCTURAL_EXCEPT_VSA_DEF(_mid, _mid, _end)

/** Types which do not represent concrete values
 *
 * - Combo IPs
 * - Combo prefixes
 * - Structural
 * - Boxes (can represent any type)
 * - Void (opaque types)
 * - Null (lack of value)
 * - Invalid values
 */
#define FR_TYPE_NON_VALUES_DEF(_beg, _mid, _end) \
	_beg(FR_TYPE_COMBO_IP_ADDR) \
	_mid(FR_TYPE_COMBO_IP_PREFIX) \
	_mid(FR_TYPE_VALUE_BOX) \
	_mid(FR_TYPE_VOID) \
	_mid(FR_TYPE_NULL) \
	_mid(FR_TYPE_MAX) \
	FR_TYPE_STRUCTURAL_DEF(_mid, _mid, _end)
/** @} */

/** @name Macros that emit multiple case statements to group types
 *
 * @{
 */
#define CASE_BEG(_type)		_type:
#define CASE_MID(_type)		case _type:
#define CASE_END(_type)		case _type

#define FR_TYPE_INTEGER_EXCEPT_BOOL		FR_TYPE_INTEGER_EXCEPT_BOOL_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_INTEGER				FR_TYPE_INTEGER_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_NUMERIC				FR_TYPE_NUMERIC_DEF(CASE_BEG, CASE_MID, CASE_END)

#define FR_TYPE_IP				FR_TYPE_IP_DEF(CASE_BEG, CASE_MID, CASE_END)

#define FR_TYPE_FIXED_SIZE			FR_TYPE_FIXED_SIZE_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_VARIABLE_SIZE			FR_TYPE_VARIABLE_SIZE_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_VALUES				FR_TYPE_VALUES_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_QUOTED				FR_TYPE_QUOTED_DEF(CASE_BEG, CASE_MID, CASE_END)

#define FR_TYPE_STRUCTURAL_EXCEPT_VSA		FR_TYPE_STRUCTURAL_EXCEPT_VSA_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_STRUCTURAL			FR_TYPE_STRUCTURAL_DEF(CASE_BEG, CASE_MID, CASE_END)
#define FR_TYPE_NON_VALUES			FR_TYPE_NON_VALUES_DEF(CASE_BEG, CASE_MID, CASE_END)
/** @} */

/** @name Bool arrays that group types
 *
 * @{
 */
extern bool const fr_type_integer_except_bool[FR_TYPE_MAX + 1];
extern bool const fr_type_integer[FR_TYPE_MAX + 1];
extern bool const fr_type_numeric[FR_TYPE_MAX + 1];

extern bool const fr_type_ip[FR_TYPE_MAX + 1];

extern bool const fr_type_fixed_size[FR_TYPE_MAX + 1];
extern bool const fr_type_variable_size[FR_TYPE_MAX + 1];
extern bool const fr_type_values[FR_TYPE_MAX + 1];
extern bool const fr_type_quoted[FR_TYPE_MAX + 1];

extern bool const fr_type_structural_except_vsa[FR_TYPE_MAX + 1];
extern bool const fr_type_structural[FR_TYPE_MAX + 1];
extern bool const fr_type_non_values[FR_TYPE_MAX + 1];
/** @} */

/** @name Type checking macros
 *
 * @{
 */
#define fr_type_is_null(_x)			((_x) == FR_TYPE_NULL)
#define fr_type_is_string(_x)			((_x) == FR_TYPE_STRING)
#define fr_type_is_octets(_x)			((_x) == FR_TYPE_OCTETS)
#define fr_type_is_ipv4addr(_x)			((_x) == FR_TYPE_IPV4_ADDR)
#define fr_type_is_ipv4prefix(_x)		((_x) == FR_TYPE_IPV4_PREFIX)
#define fr_type_is_ipv6addr(_x)			((_x) == FR_TYPE_IPV6_ADDR)
#define fr_type_is_ipv6prefix(_x)		((_x) == FR_TYPE_IPV6_PREFIX)
#define fr_type_is_ifid(_x)			((_x) == FR_TYPE_IFID)
#define fr_type_is_combo_ipaddr(_x)		((_x) == FR_TYPE_COMBO_IP_ADDR)
#define fr_type_is_combo_ipprefix(_x)		((_x) == FR_TYPE_COMBO_IP_PREFIX)
#define fr_type_is_ethernet(_x)			((_x) == FR_TYPE_ETHERNET)
#define fr_type_is_bool(_x)			((_x) == FR_TYPE_BOOL)
#define fr_type_is_uint8(_x)			((_x) == FR_TYPE_UINT8)
#define fr_type_is_uint16(_x)			((_x) == FR_TYPE_UINT16)
#define fr_type_is_uint32(_x)			((_x) == FR_TYPE_UINT32)
#define fr_type_is_uint64(_x)			((_x) == FR_TYPE_UINT64)
#define fr_type_is_int8(_x)			((_x) == FR_TYPE_INT8)
#define fr_type_is_int16(_x)			((_x) == FR_TYPE_INT16)
#define fr_type_is_int32(_x)			((_x) == FR_TYPE_INT32)
#define fr_type_is_int64(_x)			((_x) == FR_TYPE_INT64)
#define fr_type_is_float32(_x)			((_x) == FR_TYPE_FLOAT32)
#define fr_type_is_float64(_x)			((_x) == FR_TYPE_FLOAT64)
#define fr_type_is_date(_x)			((_x) == FR_TYPE_DATE)
#define fr_type_is_time_delta(_x)		((_x) == FR_TYPE_TIME_DELTA)
#define fr_type_is_size(_x)			((_x) == FR_TYPE_SIZE)
#define fr_type_is_tlv(_x)			((_x) == FR_TYPE_TLV)
#define fr_type_is_struct(_x)			((_x) == FR_TYPE_STRUCT)
#define fr_type_is_vsa(_x)			((_x) == FR_TYPE_VSA)
#define fr_type_is_vendor(_x)			((_x) == FR_TYPE_VENDOR)
#define fr_type_is_group(_x)			((_x) == FR_TYPE_GROUP)
#define fr_type_is_value_box(_x)		((_x) == FR_TYPE_VALUE_BOX)
#define fr_type_is_void(_x)			((_x) == FR_TYPE_VOID)

#define fr_type_is_integer_except_bool(_x)	(fr_type_integer_except_bool[_x])
#define fr_type_is_integer(_x)			(fr_type_integer[_x])
#define fr_type_is_numeric(_x)			(fr_type_numeric[_x])

#define fr_type_is_ip(_x)			(fr_type_ip[_x])

#define fr_type_is_fixed_size(_x)		(fr_type_fixed_size[_x])
#define fr_type_is_variable_size(_x)		(fr_variable_size[_x])
#define fr_type_is_value(_x)			(fr_type_values[_x])
#define fr_type_is_quoted(_x)			(fr_type_quoted[_x])

#define fr_type_is_structural_except_vsa(_x)	(fr_type_structural_except_vsa[_x])
#define fr_type_is_structural(_x)		(fr_type_structural[_x])
#define fr_type_is_non_value(_x)		(fr_type_non_values[_x])
/** @} */

bool		fr_type_cast(fr_type_t dst, fr_type_t src);
fr_type_t	fr_type_promote(fr_type_t a, fr_type_t b);

#ifdef __cplusplus
}
#endif
