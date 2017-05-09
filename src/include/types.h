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
#ifndef _FR_TYPES_H
#define _FR_TYPES_H
/**
 * $Id$
 *
 * @file include/types.h
 * @brief #value_box_t types
 *
 * @copyright 2017  The FreeRADIUS server project
 */
RCSIDH(types_h, "$Id$")

/** Internal data types used within libfreeradius
 *
 */
typedef enum {
	FR_TYPE_INVALID = 0,			//!< Invalid (uninitialised) attribute type.

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

	FR_TYPE_BOOLEAN,			//!< A truth value.
	FR_TYPE_BYTE,				//!< 8 Bit unsigned integer.
	FR_TYPE_SHORT,				//!< 16 Bit unsigned integer.
	FR_TYPE_INTEGER,			//!< 32 Bit unsigned integer.
	FR_TYPE_INTEGER64,			//!< 64 Bit unsigned integer.
	FR_TYPE_SIZE,				//!< Unsigned integer capable of representing any memory
						//!< address on the local system.
	FR_TYPE_SIGNED,				//!< 32 Bit signed integer.

	FR_TYPE_TIMEVAL,			//!< Time value (struct timeval), only for config items.
	FR_TYPE_DECIMAL,			//!< Double precision floating point.
	FR_TYPE_DATE,				//!< 32 Bit Unix timestamp.

	FR_TYPE_ABINARY,			//!< Ascend binary format a packed data structure.

	FR_TYPE_TLV,				//!< Contains nested attributes.
	FR_TYPE_STRUCT,				//!< like TLV, but without T or L, and fixed-width children

	FR_TYPE_EXTENDED,			//!< Extended attribute space attribute.
	FR_TYPE_LONG_EXTENDED,			//!< Long extended attribute space attribute.

	FR_TYPE_VSA,				//!< Vendor-Specific, for RADIUS attribute 26.
	FR_TYPE_EVS,				//!< Extended attribute, vendor specific.
	FR_TYPE_VENDOR,				//!< Attribute that represents a vendor in the attribute tree.

	FR_TYPE_MAX				//!< Number of defined data types.
} fr_type_t;

/** Match all fixed length types in case statements
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define FR_TYPE_FIXED_SIZE \
	     FR_TYPE_BYTE: \
	case FR_TYPE_SHORT: \
	case FR_TYPE_INTEGER: \
	case FR_TYPE_INTEGER64: \
	case FR_TYPE_SIZE: \
	case FR_TYPE_DATE: \
	case FR_TYPE_IFID: \
	case FR_TYPE_ETHERNET: \
	case FR_TYPE_IPV4_ADDR: \
	case FR_TYPE_IPV4_PREFIX: \
	case FR_TYPE_IPV6_ADDR: \
	case FR_TYPE_IPV6_PREFIX: \
	case FR_TYPE_COMBO_IP_ADDR: \
	case FR_TYPE_COMBO_IP_PREFIX: \
	case FR_TYPE_SIGNED: \
	case FR_TYPE_TIMEVAL: \
	case FR_TYPE_BOOLEAN: \
	case FR_TYPE_DECIMAL

/** Match all variable length types in case statements
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define FR_TYPE_VARIABLE_SIZE \
	     FR_TYPE_STRING: \
	case FR_TYPE_OCTETS: \
	case FR_TYPE_ABINARY \


#define FR_TYPE_BAD \
	     FR_TYPE_MAX: \
	case FR_TYPE_INVALID

/** Stupid hack for things which produce special error messages for VSAs
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define FR_TYPE_STRUCTURAL_EXCEPT_VSA \
	     FR_TYPE_EXTENDED: \
	case FR_TYPE_LONG_EXTENDED: \
	case FR_TYPE_EVS: \
	case FR_TYPE_TLV: \
	case FR_TYPE_STRUCT

/** Match all non value types in case statements
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define FR_TYPE_STRUCTURAL \
	FR_TYPE_STRUCTURAL_EXCEPT_VSA: \
	case FR_TYPE_VSA: \
	case FR_TYPE_VENDOR

/** Naturally numeric types
 *
 */
#define FR_TYPE_NUMERIC \
	FR_TYPE_BOOLEAN: \
	case FR_TYPE_BYTE: \
	case FR_TYPE_SHORT: \
	case FR_TYPE_INTEGER: \
	case FR_TYPE_INTEGER64: \
	case FR_TYPE_SIZE: \
	case FR_TYPE_SIGNED: \
	case FR_TYPE_DATE

#endif /* _FR_TYPES_H */
