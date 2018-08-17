#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Protocol encoder/decoder support functions
 *
 * @file src/lib/util/proto.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(proto_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/dict.h>

#define CHECK_FREESPACE(_have, _need) \
do { \
	if (unlikely((size_t)(_have) < (size_t)(_need))) return -((size_t)(_need) - (size_t)(_have)); \
} while (0);

#ifndef NDEBUG
#  define FR_PROTO_TRACE(_x, ...)	if (fr_log_fp && (fr_debug_lvl > 3)) fr_proto_print(__FILE__, __LINE__, _x, ## __VA_ARGS__)
#  define FR_PROTO_HEX_DUMP(_x, _y, _z)	if (fr_log_fp && (fr_debug_lvl > 3)) fr_proto_print_hex_data(__FILE__, __LINE__, _x, _y, _z)
#  define FR_PROTO_STACK_PRINT(_x, _y)	if (fr_log_fp && (fr_debug_lvl > 3)) fr_proto_tlv_stack_print( __FILE__, __LINE__, __FUNCTION__, _x, _y)
#else
#  define FR_PROTO_TRACE(_x, ...)
#  define FR_PROTO_HEX_DUMP(_x, _y, _z)
#  define FR_PROTO_STACK_PRINT(_x, _y)
#endif

void fr_proto_print(char const *file, int line, char const *fmt, ...) CC_HINT(format (printf, 3, 4));

void fr_proto_print_hex_data(char const *file, int line, char const *msg, uint8_t const *data, size_t len);

void fr_proto_tlv_stack_print(char const *file, int line, char const *func, fr_dict_attr_t const **tlv_stack, unsigned int depth);

void fr_proto_tlv_stack_build(fr_dict_attr_t const **tlv_stack, fr_dict_attr_t const *da);

#ifdef __cplusplus
}
#endif
