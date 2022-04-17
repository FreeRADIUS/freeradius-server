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

/** Protocol decoder support functions
 *
 * @file src/lib/util/decode.h
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(decode_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/pair.h>

/** Typedefs for simplifying the use and declaration of protocol decoders.
 *
 */
typedef ssize_t (*fr_pair_decode_value_t)(TALLOC_CTX *ctx, fr_pair_list_t *out,
					   fr_dict_attr_t const *parent,
					   uint8_t const *data, size_t const data_len, void *decode_ctx);

#define PROTO_DECODE_FUNC(_name) static ssize_t _name(TALLOC_CTX *ctx, fr_pair_list_t *out, \
					   fr_dict_attr_t const *parent, \
					   uint8_t const *data, size_t const data_len, fr_proto_decode_ctx_t *decode_ctx); \

ssize_t fr_pair_array_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				   uint8_t const *data, size_t data_len, void *decode_ctx, fr_pair_decode_value_t decode_value) CC_HINT(nonnull(1,2,3,4,6));

fr_pair_t *fr_pair_raw_from_network(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t data_len) CC_HINT(nonnull);


#ifdef __cplusplus
}
#endif
