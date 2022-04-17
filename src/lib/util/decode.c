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

/**
 * $Id$
 *
 * @file src/lib/util/decode.c
 * @brief Generic functions for decoding protocols.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/decode.h>

/** Decode an array of values from the network
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[out] out		Where to write the decoded #fr_pair_t
 * @param[in] parent		dictionary entry, must have parent->flags.array set
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] decode_ctx	passed to decode_value
 * @param[in] decode_value	function to decode one value.
 */
ssize_t fr_pair_array_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				   uint8_t const *data, size_t data_len, void *decode_ctx, fr_pair_decode_value_t decode_value)
{
	uint8_t const  		*p = data, *end = p + data_len;
	ssize_t			slen;

	FR_PROTO_HEX_DUMP(data, data_len, "fr_pair_array_from_network");

	if (!fr_cond_assert_msg(parent->flags.array,
				"%s: Internal sanity check failed, attribute \"%s\" does not have array bit set",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

	while (p < end) {
		slen = decode_value(ctx, out, parent, p, (end - p), decode_ctx);
		if (slen < 0) return slen - (p - data);

		p += slen;
	}

	return data_len;
}

/** Create a "raw" pair from the network data
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[in] parent		dictionary entry
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 */
fr_pair_t *fr_pair_raw_from_network(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	fr_pair_t *vp;
	fr_dict_attr_t *unknown;
	fr_dict_attr_t const *child;

#if defined(__clang_analyzer__) || !defined(NDEBUG)
	if (!parent->parent) return NULL; /* stupid static analyzers */
#endif

	/*
	 *	Build an unknown attr of the entire data.
	 */
	unknown = fr_dict_unknown_attr_afrom_da(ctx, parent);
	if (!unknown) return NULL;
	unknown->flags.is_raw = 1;

	vp = fr_pair_afrom_da(ctx, unknown); /* makes a copy of 'child' */
	child = unknown;
	fr_dict_unknown_free(&child);
	if (!vp) return NULL;

	if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
				      &FR_DBUFF_TMP(data, data_len), data_len, true) < 0) {
		talloc_free(vp);
		return NULL;
	}

	return vp;
}
