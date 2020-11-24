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
 * Because what we need is yet *ANOTHER* serialisation scheme.
 *
 * @file protocols/internal/decode.c
 * @brief Functions to decode data in our internal structure.
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>

#include <talloc.h>

static ssize_t internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				    uint8_t const *start, uint8_t const *end, void *decoder_ctx);

/** Decodes the value of an attribute, potentially producing a pair (added to the cursor)
 *
 */
static ssize_t internal_decode_pair_value(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
					  uint8_t const *start, uint8_t const *end,
					  bool tainted, UNUSED void *decoder_ctx)
{
	fr_pair_t	*vp;
	ssize_t		slen;

	vp = fr_pair_afrom_da(ctx, parent_da);
	if (!vp) return PAIR_DECODE_OOM;

	/*
	 *	Zero length is fine here
	 */
	slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, start, end - start, tainted);
	if (slen < 0) {
		talloc_free(vp);
		return slen;
	}
	fr_pair_add(head, vp);

	return slen;
}

/** Decode a TLV as a group type attribute
 *
 */
static ssize_t internal_decode_tlv(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				   uint8_t const *start, uint8_t const *end, void *decoder_ctx)
{

	ssize_t		slen;
	fr_pair_list_t	children;
	fr_cursor_t	cursor;
	uint8_t	const	*p = start;

	FR_PROTO_TRACE("Decoding TLV - %s (%zu bytes)", parent_da->name, end - start);

	fr_pair_list_init(&children);

	/*
	 *	Decode all the children of this TLV
	 */
	while (p < end) {
		FR_PROTO_HEX_MARKER(start, end - start, p - start, "Decoding child");

		slen = internal_decode_pair(ctx, &children, parent_da, p, end, decoder_ctx);
		if (slen <= 0) return slen;

		p += slen;
	}

	/*
	 *	If decoding produced more than one child
	 *	we need to do an intermediary TLV
	 *	VP to retain the nesting structure.
	 */
	if (fr_cursor_init(&cursor, &children) && fr_cursor_next(&cursor)) {
		fr_pair_t	*tlv;

		tlv = fr_pair_afrom_da(ctx, parent_da);
		if (!tlv) return PAIR_DECODE_OOM;

		while (fr_cursor_head(&cursor)) {
		     	FR_PROTO_TRACE("Moving %s into %s",
		     		       ((fr_pair_t *)fr_cursor_head(&cursor))->da->name, tlv->da->name);
			fr_pair_add(&tlv->vp_group, talloc_reparent(ctx, tlv, fr_cursor_remove(&cursor)));
		}

		fr_pair_add(head, tlv);
	} else {
		fr_pair_add(head, fr_cursor_head(&cursor));
	}

	return p - start;
}

/** Decode a group
 *
 */
static ssize_t internal_decode_group(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				     uint8_t const *start, uint8_t const *end, void *decoder_ctx)
{
	fr_pair_t	*vp;
	ssize_t		slen;
	uint8_t	const	*p = start;

	FR_PROTO_TRACE("Decoding group - %s", parent_da->name);

	vp = fr_pair_afrom_da(ctx, parent_da);
	if (!vp) return PAIR_DECODE_OOM;

	/*
	 *	Decode all the children of this group
	 */
	while (p < end) {
		FR_PROTO_HEX_MARKER(start, end - start, p - start, "Decoding child");

		slen = internal_decode_pair(vp, &vp->vp_group, parent_da, p, end, decoder_ctx);
		if (slen <= 0) {
			talloc_free(vp);
			return slen;
		}

		p += slen;
	}
	fr_pair_add(head, vp);

	return p - start;
}

static ssize_t internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				    uint8_t const *start, uint8_t const *end, void *decoder_ctx)
{
	ssize_t			slen = 0;
	fr_dict_attr_t const	*da;
	uint8_t			type_field_size, len_field_size;
	uint8_t	const		*len_field = NULL, *enc_field = NULL, *ext_field = NULL;
	uint64_t		type = 0;
	size_t			len = 0;
	bool			tainted, extended, unknown = false;
	uint8_t	const		*p = start;

	/*
	 * The first byte of each attribute describes the encoding format.
	 *
	 * tlen (type field len)   - Describes how many byte(s) were used to encode the type.
	 * llen (length field len) - Describes how many byte(s) were used to encode the length.
	 * t (tainted)             - This attribute was tainted when it was encoded,
	 *			     so should be marked tainted now.
	 * e (extended)            - Process the next byte as an extension of the encoding
	 *                           field (allows for future extensions).
	 *
	 * 0                   1                   2                   3
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |tlen |llen |t|e|   Type (min)  |  Length (min) | value...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */
	if ((p + 3) > end) {
		fr_strerror_printf("%s: Insufficient data.  Need %zu additional byte(s)",
				   __FUNCTION__, 3 - (end - p));
		return -(end - start);
	}

	enc_field = p;
	type_field_size = ((enc_field[0] & FR_INTERNAL_MASK_TYPE) >> 5) + 1;		/* bits 0-2 */
	len_field_size = ((enc_field[0] & FR_INTERNAL_MASK_LEN) >> 2) + 1;		/* bits 3-5 */

	tainted = (enc_field[0] & FR_INTERNAL_FLAG_TAINTED) != 0;			/* bit 6 */
	extended = (enc_field[0] & FR_INTERNAL_FLAG_EXTENDED) != 0;			/* bit 7 */

	p++;	/* Processed first encoding byte */

	if ((p + (type_field_size + len_field_size + extended)) > end) {
		fr_strerror_printf("%s: Encoding byte invalid, fields overrun input data. "
				   "%zu byte(s) remaining, need %zu byte(s)",
				   __FUNCTION__, end - p,
				   (size_t)type_field_size + (size_t)len_field_size + (size_t)extended);
		return 0;
	}

	/*
	 * The second (optional) extension byte carries more flag information from the attribute.
	 *
	 * u (unknown attribute)   - When this pair was converted from network to internal
	 *			     format, it was found to be badly formatted, or not
	 *			     match an existing dictionary definition.
	 *			     A new unknown DA should be allocated for this attribute
	 *			     and it should be treated as raw octets.
	 * - (currently unused)    - Unused flag.
	 * e (extended)		   - Encoding definitions continue to a third byte.
	 *
	 * 0                   1
	 * 0 1 2 3 4 5 6 7 8 9 0
	 * +-+-+-+-+-+-+-+-+-+-+
	 * |u|-|-|-|-|-|-|e|
	 * +-+-+-+-+-+-+-+-+-+-+
	 *
	 */
	if (extended) {
		ext_field = p;
		unknown = (ext_field[0] & 0x80) != 0;
		if (ext_field[0] & 0x01) {
			fr_strerror_printf("%s: Third extension byte not in use", __FUNCTION__);
			return PAIR_DECODE_FATAL_ERROR;
		}
		p++;
	}

	type = fr_net_to_uint64v(p, type_field_size);
	p += type_field_size;

	/*
	 *	This is the length of the start *after* the flags and
	 *	type/length fields.
	 */
	len_field = p;
	len = fr_net_to_uint64v(len_field, len_field_size);
	p += len_field_size;

	if ((p + len) > end) {
		fr_strerror_printf("%s: Length field value overruns input data. "
				   "%zu byte(s) remaining, need %zu byte(s)",
				   __FUNCTION__, end - p, len);
		return -(len_field - start);
	}

	if (unknown || parent_da->flags.is_unknown) {
	unknown:
		FR_PROTO_TRACE("Unknown attribute %" PRIu64, type);
		da = fr_dict_unknown_attr_afrom_num(ctx, parent_da, type);
	} else {
		da = fr_dict_attr_child_by_num(parent_da, type);
		if (!da) {
			unknown = true;	/* Be kind, someone may have messed with the dictionaries */
			goto unknown;
		}
	}

	FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

	switch (da->type) {
	/*
	 *	This just changes the lookup context, we don't
	 *	actually need to allocate anything for it.
	 */
	case FR_TYPE_VSA:		/* An attribute holding vendor definitions */
		if (unlikely(unknown)) {
			fr_strerror_printf("%s: %s can't be marked as unknown", __FUNCTION__,
					   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
			p = ext_field;
			goto error;
		}
	FALL_THROUGH;

	case FR_TYPE_VENDOR:		/* A vendor definition */
		if (unlikely(tainted)) {
		bad_tainted:
			fr_strerror_printf("%s: %s can't be marked as tainted", __FUNCTION__,
					   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
			p = enc_field;
		error:
			if (unknown) fr_dict_unknown_free(&da);
			return fr_pair_decode_slen(slen, start, p);
		}

		FR_PROTO_TRACE("Decoding %s - %s", da->name,
			       fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));

		slen = internal_decode_pair(ctx, head, parent_da, p, p + len, decoder_ctx);
		if (slen <= 0) goto error;
		break;

	/*
	 *	Structural types
	 */
	case FR_TYPE_TLV:
		if (unlikely(tainted)) goto bad_tainted;

		slen = internal_decode_tlv(ctx, head, da, p, p + len, decoder_ctx);
		if (slen <= 0) goto error;
		break;

	case FR_TYPE_GROUP:
		slen = internal_decode_group(ctx, head, da, p, p + len, decoder_ctx);
		if (slen <= 0) goto error;
		break;

	default:
		/*
		 *	It's ok for this function to return 0
		 *	we can have zero length strings.
		 */
		slen = internal_decode_pair_value(ctx, head, da, p, p + len, tainted, decoder_ctx);
		if (slen < 0) goto error;
	}

	return (p - start) + slen;
}

/** Create a single fr_pair_t and all its nesting
 *
 */
ssize_t fr_internal_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	fr_pair_list_t	list;
	fr_cursor_t	tmp_cursor;
	ssize_t		slen;

	fr_pair_list_init(&list);

	slen = internal_decode_pair(ctx, &list, fr_dict_root(dict), data, data + data_len, decoder_ctx);
	if (slen <= 0) return slen;

	fr_cursor_init(&tmp_cursor, &list);
	fr_cursor_merge(cursor, &tmp_cursor);

	return slen;
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t internal_tp_decode_pair;
fr_test_point_pair_decode_t internal_tp_decode_pair = {
	.test_ctx	= NULL,
	.func		= fr_internal_decode_pair
};
