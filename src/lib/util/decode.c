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
				   uint8_t const *data, size_t data_len,
				   void *decode_ctx, fr_pair_decode_value_t decode_value)
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
 * @param[out] out		Where to write the decoded #fr_pair_t
 * @param[in] parent		dictionary entry
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 */
ssize_t fr_pair_raw_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t data_len)
{
	ssize_t slen;
	fr_pair_t *vp;
	fr_dict_attr_t *unknown;
	fr_dict_attr_t const *child;

#if defined(__clang_analyzer__) || !defined(NDEBUG)
	if (!parent->parent) return -1; /* stupid static analyzers */
#endif

	/*
	 *	Build an unknown attr of the entire data.
	 */
	unknown = fr_dict_unknown_attr_afrom_da(ctx, parent);
	if (!unknown) return -1;
	unknown->flags.is_raw = 1;

	vp = fr_pair_afrom_da(ctx, unknown); /* makes a copy of 'unknown' */
	child = unknown;
	fr_dict_unknown_free(&child); /* const issues */
	if (!vp) return -1;

	slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					 &FR_DBUFF_TMP(data, data_len), data_len, true);
	if (slen < 0) {
		talloc_free(vp);
		return slen;
	}

	/*
	 *	Raw VPs are always tainted.
	 */
	vp->vp_tainted = true;
	fr_pair_append(out, vp);

	return data_len;
}


/** Decode a list of pairs from the network
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[out] out		Where to write the decoded #fr_pair_t
 * @param[in] parent		dictionary entry, must have parent->flags.array set
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] decode_ctx	passed to decode_value
 * @param[in] decode_tlv	function to decode one attribute / option / tlv
 * @param[in] nested		whether or not we create nested VPs.
 *
 *  The decode_tlv function should return an error if the option is
 *  malformed.  In that case, the entire list of pairs is thrown away,
 *  and a "raw" attribute is created which contains the entire
 *  data_len.
 *
 *  If the value is malformed, then the decode_tlv function should call
 *  fr_pair_raw_from_network() on the value, and return a positive value.
 */
ssize_t fr_pair_tlvs_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out,
				  fr_dict_attr_t const *parent,
				  uint8_t const *data, size_t const data_len,
				  void *decode_ctx, fr_pair_decode_value_t decode_tlv, bool nested)
{
	uint8_t const *p, *end;
	fr_pair_list_t tlvs, *list;
	fr_pair_t *vp = NULL;
	TALLOC_CTX *child_ctx;

	FR_PROTO_HEX_DUMP(data, data_len, "fr_pair_tlvs_from_network");

	if (!fr_cond_assert_msg((parent->type == FR_TYPE_TLV || (parent->type == FR_TYPE_VENDOR)),
				"%s: Internal sanity check failed, attribute \"%s\" is not of type 'tlv'",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;
	p = data;
	end = data + data_len;

	if (!nested) {
		fr_pair_list_init(&tlvs);
		list = &tlvs;
		child_ctx = ctx;
	} else {
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		list = &vp->vp_group;
		child_ctx = vp;
	}

	while (p < end) {
		ssize_t slen;

		slen = decode_tlv(child_ctx, list, parent, p, (end - p), decode_ctx);
		if (slen <= 0) {
			fr_pair_list_free(list);
			talloc_free(vp);
			return fr_pair_raw_from_network(ctx, out, parent, data, data_len);
		}

		p += slen;
	}

	if (!nested) {
		fr_pair_list_append(out, &tlvs);
	} else {
		fr_pair_append(out, vp);
	}

	return data_len;
}
