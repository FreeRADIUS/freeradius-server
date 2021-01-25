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
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/dbuff.h>

#include <talloc.h>

static ssize_t internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				    fr_dbuff_t *dbuff, void *decoder_ctx);

/** Decodes the value of an attribute, potentially producing a pair (added to the cursor)
 *
 */
static ssize_t internal_decode_pair_value_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
						fr_dbuff_t *dbuff,
						bool tainted, UNUSED void *decoder_ctx)
{
	fr_pair_t	*vp;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	vp = fr_pair_afrom_da(ctx, parent_da);
	if (!vp) return PAIR_DECODE_OOM;

	/*
	 *	Zero length is fine here
	 */
	slen = fr_value_box_from_network_dbuff(vp, &vp->data, vp->da->type, vp->da,
					       &work_dbuff, fr_dbuff_len(&work_dbuff), tainted);
	if (slen < 0) {
		talloc_free(vp);
		return slen;
	}
	fr_pair_add(head, vp);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Decode a TLV as a group type attribute
 *
 */
static ssize_t internal_decode_tlv(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				   fr_dbuff_t *dbuff, void *decoder_ctx)
{

	ssize_t		slen;
	fr_pair_list_t	children;
	fr_dcursor_t	cursor;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	FR_PROTO_TRACE("Decoding TLV - %s (%zu bytes)", parent_da->name, fr_dbuff_len(&work_dbuff));

	fr_pair_list_init(&children);

	/*
	 *	Decode all the children of this TLV
	 */
	while (fr_dbuff_extend(&work_dbuff)) {
		FR_PROTO_HEX_MARKER(fr_dbuff_start(&work_dbuff), fr_dbuff_len(&work_dbuff),
				    fr_dbuff_remaining(&work_dbuff), "Decoding child");

		slen = internal_decode_pair(ctx, &children, parent_da, &work_dbuff, decoder_ctx);
		if (slen <= 0) return slen;
	}

	/*
	 *	If decoding produced more than one child
	 *	we need to do an intermediary TLV
	 *	VP to retain the nesting structure.
	 */
	if (fr_dcursor_init(&cursor, &children) && fr_dcursor_next(&cursor)) {
		fr_pair_t	*tlv;

		tlv = fr_pair_afrom_da(ctx, parent_da);
		if (!tlv) return PAIR_DECODE_OOM;

		while (fr_dcursor_head(&cursor)) {
		     	FR_PROTO_TRACE("Moving %s into %s",
		     		       ((fr_pair_t *)fr_dcursor_head(&cursor))->da->name, tlv->da->name);
			fr_pair_add(&tlv->vp_group, talloc_reparent(ctx, tlv, fr_dcursor_remove(&cursor)));
		}

		fr_pair_add(head, tlv);
	} else {
		fr_pair_add(head, fr_dcursor_head(&cursor));
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Decode a group
 *
 */
static ssize_t internal_decode_group(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				     fr_dbuff_t *dbuff, void *decoder_ctx)
{
	fr_pair_t	*vp;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	FR_PROTO_TRACE("Decoding group - %s", parent_da->name);

	vp = fr_pair_afrom_da(ctx, parent_da);
	if (!vp) return PAIR_DECODE_OOM;

	/*
	 *	Decode all the children of this group
	 */
	while (fr_dbuff_extend(&work_dbuff)) {
		FR_PROTO_HEX_MARKER(fr_dbuff_current(dbuff), fr_dbuff_remaining(dbuff), fr_dbuff_used(&work_dbuff),
				    "Decoding child");

		slen = internal_decode_pair(vp, &vp->vp_group, parent_da, &work_dbuff, decoder_ctx);
		if (slen <= 0) {
			talloc_free(vp);
			return slen;
		}
	}
	fr_pair_add(head, vp);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				    fr_dbuff_t *dbuff, void *decoder_ctx)
{
	ssize_t			slen = 0;
	fr_dict_attr_t const	*da;
	uint8_t			enc_byte = 0, ext_byte = 0, type_field_size, len_field_size;
	fr_dbuff_marker_t	len_field, enc_field, ext_field;
	uint64_t		len = 0, type = 0;
	size_t			remaining, needed;
	bool			tainted, extended, unknown = false;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

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
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1kk
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |tlen |llen |t|e|   Type (min)  |  Length (min) | value...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */
	remaining = fr_dbuff_extend_lowat(NULL, &work_dbuff, 3);
	if (remaining < 3) {
		fr_strerror_printf("%s: Insufficient data.  Need %zu additional byte(s)",
				   __FUNCTION__, 3 - remaining);
		return -fr_dbuff_len(&work_dbuff);
	}

	fr_dbuff_marker(&enc_field, &work_dbuff);
	fr_dbuff_marker(&ext_field, &work_dbuff);	/* Placed here to make static analysis happy */
	FR_DBUFF_OUT_RETURN(&enc_byte, &work_dbuff);
	type_field_size = ((enc_byte & FR_INTERNAL_MASK_TYPE) >> 5) + 1;	/* bits 0-2 */
	len_field_size = ((enc_byte & FR_INTERNAL_MASK_LEN) >> 2) + 1;		/* bits 3-5 */

	tainted = (enc_byte & FR_INTERNAL_FLAG_TAINTED) != 0;			/* bit 6 */
	extended = (enc_byte & FR_INTERNAL_FLAG_EXTENDED) != 0;			/* bit 7 */

	/* Processed first encoding byte */

	needed = type_field_size + len_field_size + extended;
	remaining = fr_dbuff_extend_lowat(NULL, &work_dbuff, needed);
	if (remaining < needed) {
		fr_strerror_printf("%s: Encoding byte invalid, fields overrun input data. "
				   "%zu byte(s) remaining, need %zu byte(s)",
				   __FUNCTION__, remaining, needed);
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
		fr_dbuff_set(&ext_field, &work_dbuff);
		FR_DBUFF_OUT_RETURN(&ext_byte, &work_dbuff);
		unknown = (ext_byte & 0x80) != 0;
		if (ext_byte & 0x01) {
			fr_strerror_printf("%s: Third extension byte not in use", __FUNCTION__);
			return PAIR_DECODE_FATAL_ERROR;
		}
	}

	FR_DBUFF_OUT_UINT64V_RETURN(&type, &work_dbuff, type_field_size);

	/*
	 *	This is the length of the start *after* the flags and
	 *	type/length fields.
	 */
	fr_dbuff_marker(&len_field, &work_dbuff);
	FR_DBUFF_OUT_UINT64V_RETURN(&len, &work_dbuff, len_field_size);

	remaining = fr_dbuff_extend_lowat(NULL, &work_dbuff, len);
	if (remaining < len) {
		fr_strerror_printf("%s: Length field value overruns input data. "
				   "%zu byte(s) remaining, need %zu byte(s)",
				   __FUNCTION__, remaining, (size_t) len);
		return -(fr_dbuff_current(&len_field) - fr_dbuff_start(&work_dbuff));
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
			fr_dbuff_set(&work_dbuff, &ext_field);
			goto error;
		}
	FALL_THROUGH;

	case FR_TYPE_VENDOR:		/* A vendor definition */
		if (unlikely(tainted)) {
		bad_tainted:
			fr_strerror_printf("%s: %s can't be marked as tainted", __FUNCTION__,
					   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
			fr_dbuff_set(&work_dbuff, &enc_field);
		error:
			if (unknown) fr_dict_unknown_free(&da);
			return fr_pair_decode_slen(slen, fr_dbuff_start(&work_dbuff), fr_dbuff_current(&work_dbuff));
		}

		FR_PROTO_TRACE("Decoding %s - %s", da->name,
			       fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));

		slen = internal_decode_pair(ctx, head, parent_da, &work_dbuff, decoder_ctx);
		if (slen <= 0) goto error;
		break;

	/*
	 *	Structural types
	 */
	case FR_TYPE_TLV:
		if (unlikely(tainted)) goto bad_tainted;

		slen = internal_decode_tlv(ctx, head, da, &work_dbuff, decoder_ctx);
		if (slen <= 0) goto error;
		break;

	case FR_TYPE_GROUP:
		slen = internal_decode_group(ctx, head, da, &work_dbuff, decoder_ctx);
		if (slen <= 0) goto error;
		break;

	default:
		/*
		 *	It's ok for this function to return 0
		 *	we can have zero length strings.
		 */
		slen = internal_decode_pair_value_dbuff(ctx, head, da, &work_dbuff, tainted, decoder_ctx);
		if (slen < 0) goto error;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Create a single fr_pair_t and all its nesting
 *
 */
ssize_t fr_internal_decode_pair(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
				uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	return fr_internal_decode_pair_dbuff(ctx, cursor, dict, &FR_DBUFF_TMP(data, data_len), decoder_ctx);
}

ssize_t fr_internal_decode_pair_dbuff(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
				fr_dbuff_t *dbuff, void *decoder_ctx)
{
	fr_pair_list_t	list;
	fr_dcursor_t	tmp_cursor;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	fr_pair_list_init(&list);

	slen = internal_decode_pair(ctx, &list, fr_dict_root(dict), &work_dbuff, decoder_ctx);
	if (slen <= 0) return slen;

	fr_dcursor_init(&tmp_cursor, &list);
	fr_dcursor_merge(cursor, &tmp_cursor);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t internal_tp_decode_pair;
fr_test_point_pair_decode_t internal_tp_decode_pair = {
	.test_ctx	= NULL,
	.func		= fr_internal_decode_pair
};
