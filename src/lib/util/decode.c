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
 *	<0 on error - decode error, or OOM
 *	data_len on success
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

	/*
	 *	Catch stupidities.
	 */
	if (data_len == 0) return data_len;

	while (p < end) {
		slen = decode_value(ctx, out, parent, p, (end - p), decode_ctx);
		if (slen <= 0) return slen - (p - data);

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
 *	<0 on error - decode error, or OOM
 *	data_len on success
 */
ssize_t fr_pair_raw_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t data_len)
{
	ssize_t slen;
	fr_pair_t *vp;
	fr_dict_attr_t *unknown;
	fr_dict_attr_t const *child;

#if defined(STATIC_ANALYZER) || !defined(NDEBUG)
	if (!parent->parent) return -1; /* stupid static analyzers */
#endif

	FR_PROTO_HEX_DUMP(data, data_len, "fr_pair_raw_from_network");

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

	/*
	 *	Don't bother getting data from the network if there's no data.
	 */
	if (data_len > 0) {
		slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
						 &FR_DBUFF_TMP(data, data_len), data_len, true);
		if (slen < 0) {
			talloc_free(vp);
			return slen;
		}
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
 * @param[in] decode_ctx	passed to decode_tlv
 * @param[in] decode_tlv	function to decode one attribute / option / tlv
 * @param[in] verify_tlvs	simple function to see if the TLVs are even vaguely well-formed
 * @param[in] nested		whether or not we create nested VPs.
 *	<0 on error - decode error, or OOM
 *	data_len on success
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
				  void *decode_ctx, fr_pair_decode_value_t decode_tlv,
				  fr_pair_tlvs_verify_t verify_tlvs,
				  bool nested)
{
	uint8_t const *p, *end;
	fr_pair_list_t tlvs, *list;
	fr_pair_t *vp = NULL;
	TALLOC_CTX *child_ctx;

	FR_PROTO_HEX_DUMP(data, data_len, "fr_pair_tlvs_from_network");

	if (!fr_cond_assert_msg((parent->type == FR_TYPE_TLV || (parent->type == FR_TYPE_VENDOR)),
				"%s: Internal sanity check failed, attribute \"%s\" is not of type 'tlv'",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

	/*
	 *	Do a quick sanity check to see if the TLVs are at all OK.
	 */
	if (verify_tlvs && !verify_tlvs(data, data_len)) return fr_pair_raw_from_network(ctx, out, parent, data, data_len);

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
			FR_PROTO_TRACE("    tlv decode failed at offset %zu - converting to raw", (size_t) (p - data));
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


/** Decode a DNS label or a list of DNS labels from the network
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[out] out		Where to write the decoded #fr_pair_t
 * @param[in] parent		dictionary entry, must have parent->flags.array set
 * @param[in] start		of the DNS labels to decode
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] lb		struct to help with decoding packets.
 * @param[in] exact		whether the labels should entirely fill the buffer.
 * @return
 *	<0 on error - decode error, or OOM
 *	data_len on success
 *
 *  DNS labels exist in many protocols, and we also have src/lib/dns.c, so we might
 *  as well put a common function here, too.
 *
 *  This function assumes that the DNS label or labels take up all of the
 *  input.  If they do not, then the decoded DNS labels are freed, and
 *  a raw attribute is returned instead.
 */
ssize_t fr_pair_dns_labels_from_network(TALLOC_CTX *ctx, fr_pair_list_t *out,
					fr_dict_attr_t const *parent, uint8_t const *start,
					uint8_t const *data, size_t const data_len, fr_dns_labels_t *lb, bool exact)
{
	ssize_t slen;
	size_t total, labels_len;
	fr_pair_t *vp;
	uint8_t const *next = data;
	fr_pair_list_t tmp;

	FR_PROTO_HEX_DUMP(data, data_len, "fr_pair_dns_labels_from_network");

	fr_pair_list_init(&tmp);

	/*
	 *	This function handles both single-valued and array
	 *	types.  It's just easier that way.
	 */
	if (!parent->flags.array) {
		/*
		 *	Decode starting at "NEXT", but allowing decodes from the start of the packet.
		 */
		slen = fr_dns_label_uncompressed_length(start, data, data_len, &next, lb);
		if (slen <= 0) {
			FR_PROTO_TRACE("ERROR - uncompressed length failed");
			goto raw;
		}

		labels_len = next - data; /* decode only what we've found */
	} else {
		/*
		 *	Get the length of the entire set of labels, up
		 *	to (and including) the final 0x00.
		 *
		 *	If any of the labels point outside of this
		 *	area, OR they are otherwise invalid, then that's an error.
		 */
		slen = fr_dns_labels_network_verify(start, data, data_len, data, lb);
		if (slen <= 0) {
			FR_PROTO_TRACE("ERROR - network verify failed");
			goto raw;
		}

		labels_len = slen;
	}

	/*
	 *	The labels MUST fill the entire buffer.
	 */
	if (exact && (labels_len != data_len)) {
		FR_PROTO_TRACE("ERROR - labels_len %zu != data_len %zu", labels_len, data_len);
	raw:
		return fr_pair_raw_from_network(ctx, out, parent, data, data_len);
	}

	/*
	 *	Loop over the input buffer, decoding the labels one by
	 *	one.
	 *
	 *	@todo - put the labels into a child cursor, and then
	 *	merge them only if it succeeds.  That doesn't seem to
	 *	work for some reason, and I don't have time to debug
	 *	it right now.  So... let's leave it.
	 */
	for (total = 0; total < labels_len; total += slen) {
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		/*
		 *	Having verified the input above, this next
		 *	function should never fail unless there's a
		 *	bug in the code.
		 */
		slen = fr_dns_label_to_value_box(vp, &vp->data, data, labels_len, data + total, true, lb);
		if (slen <= 0) {
			FR_PROTO_TRACE("ERROR - failed decoding DNS label at with %zu error %zd", total, slen);
			talloc_free(vp);
			fr_pair_list_free(&tmp);
			goto raw;
		}

		fr_pair_append(&tmp, vp);
	}

	fr_pair_list_append(out, &tmp);
	return labels_len;
}
