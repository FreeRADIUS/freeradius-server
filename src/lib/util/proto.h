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
#  define FR_PROTO_TRACE(_fmt, ...)					if (fr_debug_lvl >= L_DBG_LVL_4) fr_proto_print(__FILE__, __LINE__, _fmt, ## __VA_ARGS__)
#  define FR_PROTO_HEX_DUMP(_data, _data_len, _fmt, ...)		if (fr_debug_lvl >= L_DBG_LVL_4) fr_proto_print_hex_data(__FILE__, __LINE__, _data, _data_len, _fmt, ## __VA_ARGS__)
#  define FR_PROTO_HEX_MARKER(_data, _data_len, _slen, _fmt, ...)	if (fr_debug_lvl >= L_DBG_LVL_4) fr_proto_print_hex_marker(__FILE__, __LINE__, _data, _data_len, _slen, _fmt, ## __VA_ARGS__)
#  define FR_PROTO_STACK_PRINT(_stack, _depth)				if (fr_debug_lvl >= L_DBG_LVL_4) fr_proto_da_stack_print(__FILE__, __LINE__, __FUNCTION__, _stack, _depth)
#else
#  define FR_PROTO_TRACE(_fmt, ...)
#  define FR_PROTO_HEX_DUMP(_data, _data_len, _fmt, ...)
#  define FR_PROTO_HEX_MARKER(_data, _data_len, _slen, _fmt, ...)
#  define FR_PROTO_STACK_PRINT(_x, _y)
#endif

/** Structure for holding the stack of dictionary attributes being encoded
 *
 */
typedef struct {
	uint8_t			depth;					//!< Deepest attribute in the stack.
	fr_dict_attr_t const	*da[FR_DICT_MAX_TLV_STACK + 1];		//!< The stack.
} fr_da_stack_t;

void fr_proto_print(char const *file, int line, char const *fmt, ...) CC_HINT(format (printf, 3, 4));

void fr_proto_print_hex_data(char const *file, int line, uint8_t const *data, size_t data_len, char const *fmt, ...);

void fr_proto_print_hex_marker(char const *file, int line, uint8_t const *data, size_t data_len, ssize_t slen, char const *fmt, ...);

void *fr_proto_next_encodable(fr_dlist_head_t *list, void *current, void *uctx);

void fr_proto_da_stack_print(char const *file, int line, char const *func, fr_da_stack_t *da_stack, unsigned int depth);

void fr_proto_da_stack_build(fr_da_stack_t *stack, fr_dict_attr_t const *da);

void fr_proto_da_stack_build_partial(fr_da_stack_t *stack, fr_dict_attr_t const *parent, fr_dict_attr_t const *da);

#ifdef __cplusplus
}
#endif
