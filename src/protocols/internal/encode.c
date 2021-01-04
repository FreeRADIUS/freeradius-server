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
 * @file protocols/internal/encode.c
 * @brief Functions to encode data in our internal structure.
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/dbuff.h>

#include <talloc.h>

/** We use the same header for all types
 *
 */

/** Encode the value of the value pair the cursor currently points at.
 *
 * @param dbuff		data buffer to place the encoded data in
 * @param da_stack	da stack corresponding to the value pair
 * @param depth		in da_stack
 * @param cursor	cursor whose current value is the one to be encoded
 * @param encoder_ctx	encoder context
 *
 * @return	either a negative number, indicating an error
 * 		or the number of bytes used to encode the value
 */
static ssize_t internal_encode(fr_dbuff_t *dbuff,
			       fr_da_stack_t *da_stack, unsigned int depth,
			       fr_cursor_t *cursor, void *encoder_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	enc_field, len_field, value_field;
	fr_dbuff_t		value_dbuff;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_pair_t		*vp = fr_cursor_current(cursor);

	ssize_t			slen;
	size_t			flen, vlen;

	uint8_t			buff[sizeof(uint64_t)];

	FR_PROTO_STACK_PRINT(da_stack, depth);

	fr_dbuff_marker(&enc_field, &work_dbuff);

	/*
	 *	Zero out first encoding byte
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x00);

	switch (da->type) {
	/*
	 *	Only leaf attributes can be tainted
	 */
	case FR_TYPE_VALUE:
		if (vp->vp_tainted) fr_dbuff_current(&enc_field)[0] |= FR_INTERNAL_FLAG_TAINTED;
		break;

	default:
		break;
	}

	/*
	 *	Need to use the second encoding byte
	 */
	if (da->flags.is_unknown) {
		fr_dbuff_current(&enc_field)[0] |= FR_INTERNAL_FLAG_EXTENDED;
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_INTERNAL_FLAG_INTERNAL);
	}

	/*
	 *	Encode the type and write the width of the
	 *	integer to the encoding byte.
	 */
	flen = fr_dbuff_in_uint64v(&work_dbuff, da->attr);
	if (flen <= 0) return flen;
	fr_dbuff_current(&enc_field)[0] |= ((flen - 1) << 5);

	/*
	 *	Leave one byte in hopes that the length will fit
	 *	so we needn't move the encoded data.
	 */
	fr_dbuff_marker(&len_field, &work_dbuff);
	FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 1);

	/*
	 *	Create dbuff to hold encoded data that assures space
	 *	for the length.
	 */
	value_dbuff = FR_DBUFF_RESERVE(&work_dbuff, sizeof(uint64_t) - 1);
	fr_dbuff_marker(&value_field, &value_dbuff);

	switch (da->type) {
	case FR_TYPE_VALUE:
		slen = fr_value_box_to_network(&value_dbuff, &vp->data);
		if (slen < 0) return PAIR_ENCODE_FATAL_ERROR;
		FR_PROTO_HEX_DUMP(fr_dbuff_start(&value_dbuff), slen, "value %s",
				  fr_table_str_by_value(fr_value_box_type_table, vp->vp_type, "<UNKNOWN>"));
		fr_cursor_next(cursor);
		break;

	/*
	 *	This is the vendor container.
	 *	For RADIUS it'd be something like attr 26.
	 *
	 *	Inside the VSA you then have the vendor
	 *	which is just encoded as another TLVish
	 *	type attribute.
	 *
	 *	For small vendor PENs <= 255 this
	 *	encoding is 6 bytes, the same as RADIUS.
	 *
	 *	For larger vendor PENs it's more bytes
	 *	but we really don't care.
	 */
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
		slen = internal_encode(&value_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		if (slen < 0) return slen;
		break;

	/*
	 *	Children of TLVs are encoded in the context
	 *	of the TLV.
	 */
	case FR_TYPE_TLV:
		/*
		 *	We've done the complete stack.
		 *	Hopefully this TLV has some
		 *	children to encode...
		 */
		if (da == vp->da) {
			fr_cursor_t	children;
			fr_pair_t	*child;

			for (child = fr_cursor_talloc_init(&children, &vp->vp_group, fr_pair_t);
			     child;
			     child = fr_cursor_current(&children)) {

				FR_PROTO_TRACE("encode ctx changed %s -> %s", da->name, child->da->name);

				fr_proto_da_stack_build_partial(da_stack, da_stack->da[depth], child->da);
				FR_PROTO_STACK_PRINT(da_stack, depth);

				slen = internal_encode(&value_dbuff, da_stack, depth + 1, &children, encoder_ctx);
				if (slen < 0) return slen;
			}
			fr_cursor_next(cursor);
			break;
		}

		/*
		 *	Still encoding intermediary TLVs...
		 */
		slen = internal_encode(&value_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		if (slen < 0) return slen;
		break;

	/*
	 *	Each child of a group encodes from the
	 *	dictionary root to the leaf da.
	 *
	 *	Re-enter the encoder at the start.
	 *	We do this, because the child may
	 *      have a completely different da_stack.
	 */
	case FR_TYPE_GROUP:
	{
		fr_cursor_t	children;

		for (vp = fr_cursor_talloc_init(&children, &vp->vp_group, fr_pair_t);
		     vp;
		     vp = fr_cursor_current(&children)) {
		     	FR_PROTO_TRACE("encode ctx changed %s -> %s", da->name, vp->da->name);

			slen = fr_internal_encode_pair(&value_dbuff, &children, encoder_ctx);
			if (slen < 0) return slen;
		}
		fr_cursor_next(cursor);
	}
		break;

	default:
		fr_strerror_printf("%s: Unexpected attribute type \"%s\"",
				   __FUNCTION__, fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Encode the total length, and write the width
	 *	of the integer to the encoding byte.
	 *
	 *	Already did length checks at the start of
	 *	the function.
	 */
	vlen = fr_dbuff_used(&value_dbuff);
	flen = (ssize_t) fr_net_from_uint64v(buff, vlen);

	/*
	 *	Ugh, it's a long one, need to move the data.
	 */
	if (flen > 1) {
		fr_dbuff_advance(&value_field, flen - 1);
		fr_dbuff_set_to_start(&value_dbuff);
		fr_dbuff_move(&value_field, &value_dbuff, vlen);
	}

	fr_dbuff_in_memcpy(&len_field, buff, flen);
	fr_dbuff_current(&enc_field)[0] |= ((flen - 1) << 2);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff) - vlen, "header");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a data structure into an internal attribute
 *
 * This will become the main entry point when we switch fully to dbuff.
 *
 * @param[in,out] dbuff		Where to write encoded data and how much one can write.
 * @param[in] cursor		Specifying attribute to encode.
 * @param[in] encoder_ctx	Additional data such as the shared secret to use.
 * @return
 *	- >0 The number of bytes written to out.
 *	- 0 Nothing to encode (or attribute skipped).
 *	- <0 an error occurred.
 */
ssize_t fr_internal_encode_pair(fr_dbuff_t *dbuff, fr_cursor_t *cursor, void *encoder_ctx)
{
	fr_pair_t		*vp;
	fr_da_stack_t		da_stack;

	vp = fr_cursor_current(cursor);
	if (!vp) return 0;

	fr_proto_da_stack_build(&da_stack, vp->da);

	return internal_encode(dbuff, &da_stack, 0, cursor, encoder_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t internal_tp_encode_pair;
fr_test_point_pair_encode_t internal_tp_encode_pair = {
	.test_ctx	= NULL,
	.func		= fr_internal_encode_pair
};
