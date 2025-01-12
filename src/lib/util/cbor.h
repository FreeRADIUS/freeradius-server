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

/** CBOR encoder and decoder
 *
 * @file src/lib/util/cbor.h
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(cbor_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/pair.h>

ssize_t fr_cbor_encode_value_box(fr_dbuff_t *dbuff, fr_value_box_t *vb) CC_HINT(nonnull);

ssize_t fr_cbor_decode_value_box(TALLOC_CTX *ctx, fr_value_box_t *vb, fr_dbuff_t *dbuff,
				 fr_type_t hint, fr_dict_attr_t const *enumv, bool tainted)
				 CC_HINT(nonnull(2,3));

ssize_t fr_cbor_encode_pair(fr_dbuff_t *dbuff, fr_pair_t *vp) CC_HINT(nonnull);

ssize_t fr_cbor_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *dbuff,
			    fr_dict_attr_t const *parent, bool tainted) CC_HINT(nonnull);


#ifdef __cplusplus
}
#endif
