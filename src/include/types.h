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
	PW_TYPE_INVALID = 0,			//!< Invalid (uninitialised) attribute type.

	PW_TYPE_STRING,				//!< String of printable characters.
	PW_TYPE_OCTETS,				//!< Raw octets.

	PW_TYPE_IPV4_ADDR,			//!< 32 Bit IPv4 Address.
	PW_TYPE_IPV4_PREFIX,			//!< IPv4 Prefix.
	PW_TYPE_IPV6_ADDR,			//!< 128 Bit IPv6 Address.
	PW_TYPE_IPV6_PREFIX,			//!< IPv6 Prefix.
	PW_TYPE_IFID,				//!< Interface ID.
	PW_TYPE_COMBO_IP_ADDR,			//!< IPv4 or IPv6 address depending on length.
	PW_TYPE_COMBO_IP_PREFIX,		//!< IPv4 or IPv6 address prefix depending on length.
	PW_TYPE_ETHERNET,			//!< 48 Bit Mac-Address.

	PW_TYPE_BOOLEAN,			//!< A truth value.
	PW_TYPE_BYTE,				//!< 8 Bit unsigned integer.
	PW_TYPE_SHORT,				//!< 16 Bit unsigned integer.
	PW_TYPE_INTEGER,			//!< 32 Bit unsigned integer.
	PW_TYPE_INTEGER64,			//!< 64 Bit unsigned integer.
	PW_TYPE_SIZE,				//!< Unsigned integer capable of representing any memory
						//!< address on the local system.
	PW_TYPE_SIGNED,				//!< 32 Bit signed integer.

	PW_TYPE_TIMEVAL,			//!< Time value (struct timeval), only for config items.
	PW_TYPE_DECIMAL,			//!< Double precision floating point.
	PW_TYPE_DATE,				//!< 32 Bit Unix timestamp.

	PW_TYPE_ABINARY,			//!< Ascend binary format a packed data structure.

	PW_TYPE_TLV,				//!< Contains nested attributes.
	PW_TYPE_STRUCT,				//!< like TLV, but without T or L, and fixed-width children

	PW_TYPE_EXTENDED,			//!< Extended attribute space attribute.
	PW_TYPE_LONG_EXTENDED,			//!< Long extended attribute space attribute.

	PW_TYPE_VSA,				//!< Vendor-Specific, for RADIUS attribute 26.
	PW_TYPE_EVS,				//!< Extended attribute, vendor specific.
	PW_TYPE_VENDOR,				//!< Attribute that represents a vendor in the attribute tree.

	PW_TYPE_MAX				//!< Number of defined data types.
} PW_TYPE;

/** Match all fixed length types in case statements
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define PW_TYPE_FIXED_SIZE \
	     PW_TYPE_BYTE: \
	case PW_TYPE_SHORT: \
	case PW_TYPE_INTEGER: \
	case PW_TYPE_INTEGER64: \
	case PW_TYPE_SIZE: \
	case PW_TYPE_DATE: \
	case PW_TYPE_IFID: \
	case PW_TYPE_ETHERNET: \
	case PW_TYPE_IPV4_ADDR: \
	case PW_TYPE_IPV4_PREFIX: \
	case PW_TYPE_IPV6_ADDR: \
	case PW_TYPE_IPV6_PREFIX: \
	case PW_TYPE_COMBO_IP_ADDR: \
	case PW_TYPE_COMBO_IP_PREFIX: \
	case PW_TYPE_SIGNED: \
	case PW_TYPE_TIMEVAL: \
	case PW_TYPE_BOOLEAN: \
	case PW_TYPE_DECIMAL

/** Match all variable length types in case statements
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define PW_TYPE_VARIABLE_SIZE \
	     PW_TYPE_STRING: \
	case PW_TYPE_OCTETS: \
	case PW_TYPE_ABINARY \


#define PW_TYPE_BAD \
	     PW_TYPE_MAX: \
	case PW_TYPE_INVALID

/** Stupid hack for things which produce special error messages for VSAs
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define PW_TYPE_STRUCTURAL_EXCEPT_VSA \
	     PW_TYPE_EXTENDED: \
	case PW_TYPE_LONG_EXTENDED: \
	case PW_TYPE_EVS: \
	case PW_TYPE_TLV: \
	case PW_TYPE_STRUCT

/** Match all non value types in case statements
 *
 * @note This should be used for switch statements in printing and casting
 *	functions that need to deal with all types representing values
 */
#define PW_TYPE_STRUCTURAL \
	PW_TYPE_STRUCTURAL_EXCEPT_VSA: \
	case PW_TYPE_VSA: \
	case PW_TYPE_VENDOR

/** Naturally numeric types
 *
 */
#define PW_TYPE_NUMERIC \
	PW_TYPE_BOOLEAN: \
	case PW_TYPE_BYTE: \
	case PW_TYPE_SHORT: \
	case PW_TYPE_INTEGER: \
	case PW_TYPE_INTEGER64: \
	case PW_TYPE_SIZE: \
	case PW_TYPE_SIGNED: \
	case PW_TYPE_DATE

#endif /* _FR_TYPES_H */
