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
 * @file protocols/dhcpv4/encode.c
 * @brief Functions to encode DHCP options.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 * @copyright 2015,2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <stdint.h>
#include <stddef.h>

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>
#include "dhcpv4.h"
#include "attrs.h"

/** Write DHCP option value into buffer
 *
 * Does not include DHCP option length or number.
 *
 * @param[out] dbuff		buffer to write the option to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encoder_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- The length of data written.
 *	< 0 if there's not enough space or option type is unsupported
 */
static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, UNUSED fr_dhcpv4_ctx_t *encoder_ctx)
{
	fr_pair_t	*vp = fr_dcursor_current(cursor);
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	ssize_t		slen;

	FR_PROTO_STACK_PRINT(da_stack, depth);
	FR_PROTO_TRACE("%zu byte(s) available for value", fr_dbuff_remaining(dbuff));

	switch (da_stack->da[depth]->type) {
	case FR_TYPE_IPV6_PREFIX:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, vp->vp_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	case FR_TYPE_IPV6_ADDR:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	default:
		slen = fr_value_box_to_network(&work_dbuff, &vp->data);
		if (slen < 0) return slen;
		break;
	}
	vp = fr_dcursor_next(cursor);	/* We encoded a leaf, advance the cursor */
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	FR_PROTO_STACK_PRINT(da_stack, depth);
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), "Value");

	return fr_dbuff_set(dbuff, &work_dbuff);
}


/** Extend an encoded option in-place.
 *
 * @param[in] dbuff	buffer containing the option
 * @param[in] hdr	marker (with dbuff as parent) set to where the option starts
 * @param[in] len	length of the data being written
 * @return
 *	- false if we can't extend the option
 *	- true  if we can, with hdr set to where the next option should start
 * @note	The option starts with a two-byte (type, length) header, where
 *		the length does *not* include the two bytes for the header.
 *		The starting length may be non-zero, hence its counting towards
 *		the header_byte calculation and its inclusion in sublen calculation.
 *		(All those following start out empty, hence the initialization
 *		of their lengths to zero.)
 */
static bool extend_option(fr_dbuff_t *dbuff, fr_dbuff_marker_t *hdr, int len)
{
	size_t header_bytes;
	uint8_t			type, option_len = 0;
	fr_dbuff_marker_t	src, dest, hdr_io;

	/*
	 *	This can't follow the convention of operating on
	 *	a chlld dbuff because it must work on and amidst
	 *	already-written data.
	 */

	fr_dbuff_marker(&src, dbuff);
	fr_dbuff_marker(&dest, dbuff);
	fr_dbuff_marker(&hdr_io, dbuff);

	fr_dbuff_set(&hdr_io, hdr);
	fr_dbuff_out(&type, &hdr_io);
	fr_dbuff_out(&option_len, &hdr_io);

	/*
	 *	How many bytes we will need to add for headers.
	 */
	header_bytes = ((option_len + len) / 255) * 2;

	/*
	 *	No room for the new headers and data, we're done.
	 */
	if (fr_dbuff_extend_lowat(NULL, dbuff, header_bytes) < header_bytes) {
		fr_dbuff_marker_release(&dest);
		fr_dbuff_marker_release(&src);
		fr_dbuff_marker_release(&hdr_io);
		return false;
	}
	fr_dbuff_advance(dbuff, header_bytes);

	/*
	 *	Moving the same data repeatedly in a loop is simpler
	 *	and less error-prone than anything smarter.
	 */
	while (len > 0) {
		int sublen;

		/*
		 *	Figure out how much data goes into this
		 *	option, and how much data we have to move out
		 *	of the way.
		 */
		sublen = 255 - option_len;
		if (sublen > len) sublen = len;

		/*
		 *	Add in the data left at the current pointer.
		 */
		option_len += sublen;
		len -= sublen;
		fr_dbuff_set(&hdr_io, fr_dbuff_current(hdr) + 1);
		fr_dbuff_in(&hdr_io, option_len);

		/*
		 *	Nothing more to do?  Exit.
		 */
		if (!len) break;

		/*
		 *	The current option is full.  So move the
		 *	trailing data up by 2 bytes, making room
		 *	for a new header.
		 */
		fr_dbuff_advance(hdr, option_len + 2);
		fr_dbuff_set(&src, hdr);
		fr_dbuff_set(&dest, fr_dbuff_current(hdr) + 2);
		fr_dbuff_move(&dest, &src, len);

		/*
		 *	Initialize the new header.
		 */
		option_len = 0;
		fr_dbuff_set(&hdr_io, hdr);
		fr_dbuff_in_bytes(&hdr_io, type, option_len);
	}

	fr_dbuff_marker_release(&dest);
	fr_dbuff_marker_release(&src);
	fr_dbuff_marker_release(&hdr_io);
	return true;
}


/** Write out an RFC option header and option data
 *
 * @note May coalesce options with fixed width values
 *
 * @param[out] dbuff		buffer to write the TLV to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in the da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encoder_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
static ssize_t encode_rfc_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, fr_dhcpv4_ctx_t *encoder_ctx)
{
	ssize_t			len;
	uint8_t			option_len = 0;
	fr_dbuff_marker_t	hdr, hdr_io;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_pair_t		*vp = fr_dcursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Write out the option number and length (which, unlike RADIUS,
	 *	is just the length of the value and hence starts out as zero).
	 */
	fr_dbuff_marker(&hdr, &work_dbuff);
	fr_dbuff_marker(&hdr_io, &work_dbuff);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da->attr, option_len);

	/*
	 *	DHCP options with the same number (and array flag set)
	 *	get coalesced into a single option.
	 *
	 *	Note: This only works with fixed length attributes,
	 *	because there's no separate length fields.
	 */
	do {
		fr_pair_t *next;

		/*
		 *	As a quick hack, check if there's enough room
		 *	for fixed-size attributes.  If we're encoding
		 *	the second or later value into this option,
		 *	AND we're encoding fixed size values, AND
		 *	there's no room for the next fixed-size value,
		 *	then don't encode this VP.
		 */
		if (vp->da->flags.array &&
		    ((len = fr_value_box_network_length(&vp->data)) > 0) &&
		    (option_len + len) > 255) {
			break;
		}

		len = encode_value(&work_dbuff, da_stack, depth, cursor, encoder_ctx);
		if (len < -1) return len;
		if (len == -1) {
			FR_PROTO_TRACE("No more space in option");
			if (option_len == 0) {
				/*
				 * Couldn't encode anything: don't leave behind these two octets,
				 * or rather, don't include them when advancing dbuff.
				 */
				fr_dbuff_set(&work_dbuff, &hdr);
			}
			break; /* Packed as much as we can */
		}

		FR_PROTO_STACK_PRINT(da_stack, depth);
		FR_PROTO_TRACE("Encoded value is %zu byte(s)", len);
		FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), NULL);

		if ((option_len + len) <= 255) {
			option_len += len;
			fr_dbuff_set(&hdr_io, fr_dbuff_current(&hdr) + 1);
			fr_dbuff_in(&hdr_io, option_len);
			FR_PROTO_TRACE("%u byte(s) available in option", 255 - option_len);
		} else {
			if (!extend_option(&work_dbuff, &hdr, len)) break;
			fr_dbuff_set(&hdr_io, fr_dbuff_current(&hdr) + 1);
			fr_dbuff_out(&option_len, &hdr_io);
		}

		next = fr_dcursor_current(cursor);
		if (!next || (vp->da != next->da)) break;
		vp = next;
	} while (vp->da->flags.array);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Write out a TLV header (and any sub TLVs or values)
 *
 * @param[out] dbuff		buffer to write the TLV to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in the da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encoder_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
static ssize_t encode_tlv_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, fr_dhcpv4_ctx_t *encoder_ctx)
{
	ssize_t			len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr, next_hdr, dest, hdr_io;
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	uint8_t			option_number, option_len;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	fr_dbuff_marker(&hdr, &work_dbuff);
	/*
	 *	These are set before use; their initial value doesn't matter.
	 */
	fr_dbuff_marker(&next_hdr, &work_dbuff);
	fr_dbuff_marker(&dest, &work_dbuff);
	fr_dbuff_marker(&hdr_io, &work_dbuff);

	/*
	 *	Write out the option number and length (which, unlike RADIUS,
	 *	is just the length of the value and hence starts out as zero).
	 */
	option_number = (uint8_t)da->attr;
	option_len = 0;
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, option_number, option_len);

	/*
	 *	Encode any sub TLVs or values
	 */
	while (fr_dbuff_extend_lowat(NULL, &work_dbuff, 3) >= 3) {
		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (da_stack->da[depth + 1]->type == FR_TYPE_TLV) {
			len = encode_tlv_hdr(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		} else {
			len = encode_rfc_hdr(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		}
		if (len < 0) return len;
		if (len == 0) break;		/* Insufficient space */

		/*
		 *	If the newly added data fits within the current option, then
		 *	update the header, and go to the next option.
		 */
		if (option_len + len <= 255) {
			option_len += len;
			fr_dbuff_set(&hdr_io, fr_dbuff_current(&hdr) + 1);
			fr_dbuff_in_bytes(&hdr_io, option_len);
		} else {
			/*
			 *	If there was data before the new data, create a new header
			 *	and advance to it.
			 */
			if (option_len > 0) {
				if (fr_dbuff_extend_lowat(NULL, &work_dbuff, 2) < 2) break;
				fr_dbuff_advance(&work_dbuff, 2);

				fr_dbuff_set(&next_hdr, fr_dbuff_current(&hdr) + (option_len + 2));
				fr_dbuff_set(&hdr, &next_hdr);

				fr_dbuff_set(&dest, fr_dbuff_current(&next_hdr) + 2);
				fr_dbuff_move(&dest, &next_hdr, len);

				option_len = 0;
				fr_dbuff_set(&hdr_io, &hdr);
				fr_dbuff_in_bytes(&hdr_io, option_number, option_len);
			}

			/*
			 *	If the new data fits entirely within the (possibly new,
			 *	but definitely unused) option, just use it. Otherwise,
			 *	it must be split across multiple options.
			 */
			if (len <= 255) {
				option_len += len;
				fr_dbuff_set(&hdr_io, fr_dbuff_current(&hdr) + 1);
				fr_dbuff_in_bytes(&hdr_io, option_len);
			} else {
				if (!extend_option(&work_dbuff, &hdr, len)) break;
				fr_dbuff_set(&hdr_io, fr_dbuff_current(&hdr) + 1);
				fr_dbuff_out(&option_len, &hdr_io);
			}
		}

		FR_PROTO_STACK_PRINT(da_stack, depth);
		FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "TLV header and sub TLVs");

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_dcursor_current(cursor) || (vp == fr_dcursor_current(cursor))) break;

		/*
	 	 *	We can encode multiple sub TLVs, if after
	 	 *	rebuilding the TLV Stack, the attribute
	 	 *	at this depth is the same.
	 	 */
		if ((da != da_stack->da[depth]) || (da_stack->depth < da->depth)) break;
		vp = fr_dcursor_current(cursor);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

#define DHCPV6_OPT_HDR_LEN (2)

static ssize_t encode_vsio_hdr(fr_dbuff_t *dbuff,
			       fr_da_stack_t *da_stack, unsigned int depth,
			       fr_dcursor_t *cursor, void *encoder_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, 255 - 4 - 1 - 2);
	fr_dbuff_marker_t	hdr;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_dict_attr_t const	*dv;
	ssize_t			len;
	fr_pair_t		*vp;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	DA should be a VSA type with the value of OPTION_VENDOR_OPTS.
	 */
	if (da->type != FR_TYPE_VSA) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Check if we have enough for an option header plus the
	 *	enterprise-number, plus the data length, plus at least
	 *	one option header.
	 */
	FR_DBUFF_REMAINING_RETURN(&work_dbuff, DHCPV6_OPT_HDR_LEN + sizeof(uint32_t) + 3);

	/*
	 *	Now process the vendor ID part (which is one attribute deeper)
	 */
	dv = da_stack->da[++depth];
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, dv->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Copy in the 32bit PEN (Private Enterprise Number)
	 *
	 *	And leave room for data-len1
	 */
	fr_dbuff_in_bytes(&work_dbuff, (uint8_t) da->attr, 0x00);
	fr_dbuff_in(&work_dbuff, dv->attr);
	fr_dbuff_in_bytes(&work_dbuff, (uint8_t) 0x00);

	/*
	 *	https://tools.ietf.org/html/rfc3925#section-4
	 *
	 *                         1 1 1 1 1 1
	 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |  option-code  |  option-len   |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |      enterprise-number1       |
	 *    |                               |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |   data-len1   |               |
	 *    +-+-+-+-+-+-+-+-+ option-data1  |
	 *    /                               /
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	da = da_stack->da[depth + 1];

	while (true) {
		/*
		 *	Encode the different data types
		 *
		 *	@todo - encode all options which have the same parent vendor.
		 */
		if (da->type == FR_TYPE_TLV) {
			len = encode_tlv_hdr(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		} else {
			/*
			 *	Normal vendor option
			 */
			len = encode_rfc_hdr(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		}
		if (len < 0) return len;

		vp = fr_dcursor_current(cursor);
		if (!vp) break;

		/*
		 *	Encode all attributes which match this vendor.
		 */
		if (vp->da->parent != da->parent) break;
	}

	fr_dbuff_advance(&hdr, 1);
	fr_dbuff_in(&hdr, (uint8_t)(fr_dbuff_used(&work_dbuff) - DHCPV6_OPT_HDR_LEN));
	fr_dbuff_advance(&hdr, 4);
	fr_dbuff_in(&hdr, (uint8_t)(fr_dbuff_used(&work_dbuff) - DHCPV6_OPT_HDR_LEN - 4 - 1));

#ifndef NDEBUG
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), "Done VSIO header");
#endif

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a DHCP option and any sub-options.
 *
 * @param[out] dbuff		Where to write encoded DHCP attributes.
 * @param[in] cursor		with current VP set to the option to be encoded.
 *				Will be advanced to the next option to encode.
 * @param[in] encoder_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 *	- 0 not valid option for DHCP (skipping).
 */
ssize_t fr_dhcpv4_encode_option(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encoder_ctx)
{
	fr_pair_t		*vp;
	unsigned int		depth = 0;
	fr_da_stack_t		da_stack;
	ssize_t			len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	vp = fr_dcursor_current(cursor);
	if (!vp) return -1;

	if (vp->da == attr_dhcp_message_type) goto next; /* already done */
	if ((vp->da->attr > 255) && (vp->da->attr != FR_DHCP_OPTION_82)) {
	next:
		fr_strerror_printf("Attribute \"%s\" is not a DHCP option", vp->da->name);
		(void)fr_dcursor_next(cursor);
		return 0;
	}

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, depth);

	/*
	 *	We only have two types of options in DHCPv4
	 */
	switch (da_stack.da[depth]->type) {
	case FR_TYPE_VSA:
		len = encode_vsio_hdr(&work_dbuff, &da_stack, depth, cursor, encoder_ctx);
		break;

	case FR_TYPE_TLV:
		len = encode_tlv_hdr(&work_dbuff, &da_stack, depth, cursor, encoder_ctx);
		break;

	default:
		len = encode_rfc_hdr(&work_dbuff, &da_stack, depth, cursor, encoder_ctx);
		break;
	}

	if (len <= 0) return len;

	FR_PROTO_TRACE("Complete option is %zu byte(s)", fr_dbuff_used(&work_dbuff));
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t fr_dhcpv4_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_dhcpv4_encode_dbuff(&FR_DBUFF_TMP(data, data_len), NULL, 0, 0, vps);
}

static int _encode_test_ctx(UNUSED fr_dhcpv4_ctx_t *test_ctx)
{
	fr_dhcpv4_global_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_dhcpv4_ctx_t *test_ctx;

	if (fr_dhcpv4_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_dhcpv4_ctx_t);
	if (!test_ctx) return -1;
	test_ctx->root = fr_dict_root(dict_dhcpv4);
	talloc_set_destructor(test_ctx, _encode_test_ctx);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t dhcpv4_tp_encode_pair;
fr_test_point_pair_encode_t dhcpv4_tp_encode_pair = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dhcpv4_encode_option
};



extern fr_test_point_proto_encode_t dhcpv4_tp_encode_proto;
fr_test_point_proto_encode_t dhcpv4_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dhcpv4_encode_proto
};
