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
 * @file src/lib/util/struct.h
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(struct_h, "$Id$")

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef ssize_t (*fr_decode_value_t)(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const data_len, void *decoder_ctx);

ssize_t fr_struct_from_network(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			       fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			       fr_dict_attr_t const **child,
			       fr_decode_value_t decode_value, void *decoder_ctx) CC_HINT(nonnull(2,3,4));

typedef ssize_t (*fr_encode_value_t)(uint8_t *out, size_t outlen, fr_da_stack_t *da_stack, unsigned int depth,
				     fr_cursor_t *cursor, void *encoder_ctx);

ssize_t fr_struct_to_network(uint8_t *out, size_t outlen, fr_da_stack_t *da_stack, unsigned int depth,
			     fr_cursor_t *cursor, void *encoder_ctx,
			     fr_encode_value_t encode_value) CC_HINT(nonnull(1,3,5));

typedef ssize_t (*fr_encode_value_dbuff_t)(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
					   fr_cursor_t *cursor, void *encoder_ctx);

ssize_t fr_struct_to_network_dbuff(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
				   fr_cursor_t *cursor, void *encoder_ctx,
				   fr_encode_value_dbuff_t encode_value) CC_HINT(nonnull(1,2,4));

fr_pair_t *fr_raw_from_network(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t data_len) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
