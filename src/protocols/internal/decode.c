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
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/types.h>

static ssize_t internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
				    fr_dbuff_t *dbuff, void *decode_ctx);

/** Decodes the value of an attribute, potentially producing a pair (added to the cursor)
 *
 */
static ssize_t internal_decode_pair_value(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
					  fr_dbuff_t *dbuff,
					  bool tainted, UNUSED void *decode_ctx)
{
	fr_pair_t	*vp;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	vp = fr_pair_afrom_da(ctx, parent_da);
	if (!vp) return PAIR_DECODE_OOM;
	PAIR_ALLOCED(vp);

	/*
	 *	Zero length is fine here
	 */
	slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
					 &work_dbuff, fr_dbuff_len(&work_dbuff), tainted);
	if (slen < 0) {
		talloc_free(vp);
		return slen;
	}
	fr_pair_append(head, vp);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Decode a group
 *
 */
static ssize_t internal_decode_structural(TALLOC_CTX *ctx, fr_pair_list_t *head, fr_dict_attr_t const *parent_da,
					  fr_dbuff_t *dbuff, void *decode_ctx)
{
	fr_pair_t	*vp;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	FR_PROTO_TRACE("Decoding group - %s", parent_da->name);

	vp = fr_pair_afrom_da(ctx, parent_da);
	if (!vp) return PAIR_DECODE_OOM;
	PAIR_ALLOCED(vp);

	/*
	 *	Decode all the children of this group
	 */
	while (fr_dbuff_extend(&work_dbuff)) {
		FR_PROTO_HEX_MARKER(fr_dbuff_current(dbuff), fr_dbuff_remaining(dbuff), fr_dbuff_used(&work_dbuff),
				    "Decoding child");

		slen = internal_decode_pair(vp, &vp->vp_group, parent_da, &work_dbuff, decode_ctx);
		if (slen <= 0) {
			talloc_free(vp);
			return slen;
		}
	}
	fr_pair_append(head, vp);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent_da,
				    fr_dbuff_t *dbuff, void *decode_ctx)
{
	ssize_t			slen = 0;
	fr_dict_attr_t const	*da;
	uint8_t			enc_byte = 0, ext_byte = 0, type_field_size, len_field_size;
	fr_dbuff_marker_t	len_field, enc_field, ext_field;
	uint64_t		len = 0, type = 0;
	size_t			remaining, needed;
	bool			tainted, extended, unknown = false, internal = false;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

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
	 * i (internal attribute)  - Resolve this attribute in the internal dictionary.
	 * - (currently unused)    - Unused flag.
	 * e (extended)		   - Encoding definitions continue to a third byte.
	 *
	 * 0                   1
	 * 0 1 2 3 4 5 6 7 8 9 0
	 * +-+-+-+-+-+-+-+-+-+-+
	 * |u|i|-|-|-|-|-|e|
	 * +-+-+-+-+-+-+-+-+-+-+
	 *
	 */
	if (extended) {
		fr_dbuff_set(&ext_field, &work_dbuff);
		FR_DBUFF_OUT_RETURN(&ext_byte, &work_dbuff);
		unknown = (ext_byte & FR_INTERNAL_FLAG_UNKNOWN) != 0;
		internal = (ext_byte & FR_INTERNAL_FLAG_INTERNAL) != 0;
		if (ext_byte & FR_INTERNAL_FLAG_EXTENDED) {
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

	/*
	 *	Internal flag is only set on the outer attribute
	 *	so it's fine to swap the parent_da.
	 */
	if (internal) {
		if (!parent_da->flags.is_root && !(parent_da->type == FR_TYPE_GROUP)) {
			fr_strerror_printf("%s: Internal flag can only be set on top level attribute", __FUNCTION__);
			return PAIR_DECODE_FATAL_ERROR;
		}
		parent_da = fr_dict_root(fr_dict_internal());
	}

	if (unknown || parent_da->flags.is_unknown) {
	unknown:
		FR_PROTO_TRACE("Unknown attribute %" PRIu64, type);
		da = fr_dict_attr_unknown_raw_afrom_num(ctx, parent_da, type);
		if (!da) return PAIR_DECODE_FATAL_ERROR;
	} else {
		da = fr_dict_attr_child_by_num(parent_da, type);
		if (!da) {
			unknown = true;	/* Be kind, someone may have messed with the dictionaries */
			goto unknown;
		}
	}

	FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

	/*
	 *	Set the end of our dbuff to match the length
	 *	of the attribute.
	 */
	fr_dbuff_set_end(&work_dbuff, fr_dbuff_current(&work_dbuff) + len);

	switch (da->type) {
	/*
	 *	Structural types
	 *
	 *	STRUCTs are encoded as TLVs, because the struct
	 *	packing only applies to the original protocol, and not
	 *	to our internal encoding.
	 */
	 case FR_TYPE_STRUCTURAL:
	 	if (fr_type_is_vsa(da->type)) {
			if (unlikely(unknown)) {
				fr_strerror_printf("%s: %s can't be marked as unknown", __FUNCTION__,
						fr_type_to_str(da->type));
				fr_dbuff_set(&work_dbuff, &ext_field);
			error:
				if (unknown) fr_dict_attr_unknown_free(&da);
				return fr_pair_decode_slen(slen, fr_dbuff_start(&work_dbuff), fr_dbuff_current(&work_dbuff));
			}
		}
		/*
		 *	It's ok for this function to return 0
		 *	we can have empty groups (i.e. groups
		 *	with no children)
		 */
		slen = internal_decode_structural(ctx, out, da, &work_dbuff, decode_ctx);
		if (slen < 0) goto error;
		break;

	default:
		/*
		 *	It's ok for this function to return 0
		 *	we can have zero length strings.
		 */
		slen = internal_decode_pair_value(ctx, out, da, &work_dbuff, tainted, decode_ctx);
		if (slen < 0) goto error;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Create a single fr_pair_t and all its nesting
 *
 */
ssize_t fr_internal_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *list, fr_dict_attr_t const *parent,
				uint8_t const *data, size_t data_len, void *decode_ctx)
{
	return fr_internal_decode_pair_dbuff(ctx, list, parent, &FR_DBUFF_TMP(data, data_len), decode_ctx);
}

ssize_t fr_internal_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				fr_dbuff_t *dbuff, void *decode_ctx)
{
	fr_pair_list_t	tmp;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	fr_pair_list_init(&tmp);

	slen = internal_decode_pair(ctx, &tmp, parent, &work_dbuff, decode_ctx);
	if (slen <= 0) {
		fr_pair_list_free(&tmp);
		return slen;
	}

	fr_pair_list_append(out, &tmp);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Retrieve all pairs from the dbuff
 *
 * @param ctx		to create new pairs in
 * @param out		list to append pairs to
 * @param parent	attribute within which which to decode
 * @param dbuff		to parse
 * @param decode_ctx	to pass to decoder function
 * @return
 *	- bytes of dbuff consumed
 *	- < 0 on error
 */
ssize_t fr_internal_decode_list_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					  fr_dbuff_t *dbuff, void *decode_ctx)
{
	ssize_t		ret, len = 0;

	while (fr_dbuff_remaining(dbuff)) {
		ret = fr_internal_decode_pair_dbuff(ctx, out, parent, dbuff, decode_ctx);
		if (ret < 0) return ret;
		if (ret == 0) break;
		len += ret;
	}

	return len;
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t internal_tp_decode_pair;
fr_test_point_pair_decode_t internal_tp_decode_pair = {
	.test_ctx	= NULL,
	.func		= fr_internal_decode_pair
};
