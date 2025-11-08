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
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/encode.h>

#include "dhcpv4.h"
#include "attrs.h"

static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_child(fr_dbuff_t *dbuff,
				  fr_da_stack_t *da_stack, unsigned int depth,
				  fr_dcursor_t *cursor, void *encode_ctx);

/** Write DHCP option value into buffer
 *
 * Does not include DHCP option length or number.
 *
 * @param[out] dbuff		buffer to write the option to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encode_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- The length of data written, may return 0 for bools
 *	< 0 if there's not enough space or option type is unsupported
 */
static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t	*vp = fr_dcursor_current(cursor);
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	ssize_t		slen;


	FR_PROTO_STACK_PRINT(da_stack, depth);
	FR_PROTO_TRACE("%zu byte(s) available for value", fr_dbuff_remaining(dbuff));

	/*
	 *	Structures are special.
	 */
	if ((vp->vp_type == FR_TYPE_STRUCT) || (da->type == FR_TYPE_STRUCT)) {
		slen = fr_struct_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_value, encode_child);
		if (slen <= 0) return slen;

		/*
		 *	Rebuild the da_stack for the next option.
		 */
		vp = fr_dcursor_current(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	switch (da_stack->da[depth]->type) {
	case FR_TYPE_ATTR:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) vp->vp_attr->attr);
		break;

	case FR_TYPE_IPV6_PREFIX:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, vp->vp_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	case FR_TYPE_IPV6_ADDR:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

		/*
		 *	"option exists" == true.
		 *	"option does not exist" == false
		 *
		 *	fr_dhcpv4_next_encodable() takes care of skipping bools which are false.
		 *
		 *	Rapid-Commit does this.  Options 19/20 require encoding as one byte of 0/1.
		 */
	case FR_TYPE_BOOL:
		if (fr_dhcpv4_flag_exists(vp->da)) {
			break;
		}
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t) (vp->vp_bool == true));
		break;

	case FR_TYPE_IPV4_PREFIX:
		if (fr_dhcpv4_flag_prefix_split(vp->da)) {
			uint32_t mask;

			mask = ~((~(uint32_t) 0) >> vp->vp_ip.prefix);

			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff,
						  (uint8_t const *)&vp->vp_ipv4addr,
						  sizeof(vp->vp_ipv4addr));
			FR_DBUFF_IN_RETURN(&work_dbuff, mask);
			break;
		}

		if (fr_dhcpv4_flag_prefix_bits(vp->da)) {
			size_t num_bytes = (vp->vp_ip.prefix + 0x07) >> 3;

			FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t) vp->vp_ip.prefix);

			if (num_bytes) {
				FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff,
							  (uint8_t const *)&vp->vp_ipv4addr,
							  num_bytes);
			}

			break;
		}

		goto from_network;

	case FR_TYPE_STRING:
		/*
		 *	DNS labels get a special encoder.  DNS labels
		 *	MUST NOT be compressed in DHCP.
		 *
		 *	https://tools.ietf.org/html/rfc8415#section-10
		 */
		if (fr_dhcpv4_flag_dns_label(da)) {
			fr_dbuff_marker_t	last_byte, src;

			fr_dbuff_marker(&last_byte, &work_dbuff);
			fr_dbuff_marker(&src, &work_dbuff);
			slen = fr_dns_label_from_value_box_dbuff(&work_dbuff, false, &vp->data, NULL);
			if (slen < 0) return slen;
			break;
		}
		FALL_THROUGH;

	default:
	from_network:
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
 * @param[in] len        length of the data being written
 * @return
 *	- <0 if we can't extend the option
 *	- >0  if we can, with hdr set to where the next option should start
 * @note	The option starts with a two-byte (type, length) header, where
 *		the length does *not* include the two bytes for the header.
 *		The starting length may be non-zero, hence its counting towards
 *		the header_byte calculation and its inclusion in sublen calculation.
 *		(All those following start out empty, hence the initialization
 *		of their lengths to zero.)
 */
static ssize_t extend_option(fr_dbuff_t *dbuff, fr_dbuff_marker_t *hdr, size_t len)
{
	size_t 			header_bytes;
	uint8_t			type = 0, option_len = 0;
	fr_dbuff_marker_t	dst, tmp;

	/*
	 *	This can't follow the convention of operating on
	 *	a chlld dbuff because it must work on and amidst
	 *	already-written data.
	 */

	fr_dbuff_marker(&dst, dbuff);
	fr_dbuff_marker(&tmp, dbuff);

	fr_dbuff_set(&tmp, hdr);

	/*
	 *	Read the current header.
	 */
	if (fr_dbuff_out(&type, &tmp) < 0 || fr_dbuff_out(&option_len, &tmp) < 0) {
	error:
		fr_dbuff_marker_release(&dst);
		fr_dbuff_marker_release(&tmp);
		return -1;
	}

	len += option_len;

	/*
	 *	How many bytes we will need to add for all headers.
	 */
	header_bytes = (option_len / 255) * 2;

	/*
	 *	No room for the new headers and data, we're done.
	 */
	if (fr_dbuff_extend_lowat(NULL, dbuff, header_bytes) < header_bytes) goto error;

	/*
	 *	Moving the same data repeatedly in a loop is simpler
	 *	and less error-prone than anything smarter.
	 */
	while (true) {
		uint8_t sublen;

		sublen = (len > 255) ? 255 : len;

		/*
		 *	Write the new header, including the (possibly partial) length.
		 */
		fr_dbuff_set(&tmp, fr_dbuff_current(hdr));
		FR_DBUFF_IN_BYTES_RETURN(&tmp, type, sublen);

		/*
		 *	The data is already where it's supposed to be, and the length is in the header, and
		 *	the length is small.  We're done.
		 */
		len -= sublen;
		if (!len) {
			fr_dbuff_set(dbuff, fr_dbuff_current(hdr) + sublen + 2);
			len = sublen;
			break;
		}

		/*
		 *	Take the current header, skip it, and then skip the data we just encoded.  That is the
		 *	location of the "next" header.
		 */
		fr_dbuff_set(&tmp, fr_dbuff_current(hdr) + 2 + 255);
		fr_dbuff_set(hdr, &tmp);

		/*
		 *	The data is currently overlapping with the next header.  We have to move it two bytes forward to
		 *	make room for the header.
		 */
		fr_dbuff_set(&dst, fr_dbuff_current(&tmp) + 2);
		fr_dbuff_move(&dst, &tmp, len);
	}

	fr_dbuff_marker_release(&dst);
	fr_dbuff_marker_release(&tmp);
	return len;
}

#define DHCPV4_OPT_HDR_LEN (2)

/** Write out an RFC option header and option data
 *
 * @note May coalesce options with fixed width values
 *
 * @param[out] dbuff		buffer to write the TLV to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in the da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encode_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
static ssize_t encode_rfc(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			len;
	fr_dbuff_marker_t	hdr;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Write out the option number and length (which, unlike RADIUS,
	 *	is just the length of the value and hence starts out as zero).
	 */
	fr_dbuff_marker(&hdr, &work_dbuff);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da->attr, (uint8_t) 0);

	/*
	 *	Write out the option's value
	 */
	if (da->flags.array) {
		len = fr_pair_array_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_value);
		if (len < 0) return -1;

	} else if (da->parent && (da->parent->type != FR_TYPE_VENDOR)) {
		fr_pair_t *vp;

		do {
			len = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
			if (len < 0) return len; /* @todo return the correct offset, but whatever */

			vp = fr_dcursor_current(cursor);
		} while (vp && (vp->da == da));

	} else {
		/*
		 *	For VSAs, each vendor value is prefixed by an 8-bit length, so we don't loop over the
		 *	input pairs.
		 */
		len = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
		if (len < 0) return len; /* @todo return the correct offset, but whatever */
	}

	len = fr_dbuff_used(&work_dbuff) - 2;

	if (len <= UINT8_MAX) {
		fr_dbuff_advance(&hdr, 1);
		FR_DBUFF_IN_RETURN(&hdr, (uint8_t) len);

	} else if (extend_option(&work_dbuff, &hdr, len) < 0) {
		return PAIR_ENCODE_FATAL_ERROR;
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done RFC header");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_vsio(fr_dbuff_t *dbuff,
			       fr_da_stack_t *da_stack, unsigned int depth,
			       fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_tlv(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_child(fr_dbuff_t *dbuff,
				  fr_da_stack_t *da_stack, unsigned int depth,
				  fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t len;
	fr_pair_t *vp = fr_dcursor_current(cursor);
	fr_dcursor_t child_cursor;
	fr_dbuff_t work_dbuff;

	if (da_stack->da[depth]) {
		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		switch (da_stack->da[depth]->type) {
		case FR_TYPE_TLV:
			if (!da_stack->da[depth + 1]) break;

			return encode_tlv(dbuff, da_stack, depth, cursor, encode_ctx);

		case FR_TYPE_VSA:
			if (!da_stack->da[depth + 1]) break;

			return encode_vsio(dbuff, da_stack, depth, cursor, encode_ctx);

		default:
			return encode_rfc(dbuff, da_stack, depth, cursor, encode_ctx);
		}
	}

	fr_assert(fr_type_is_structural(vp->vp_type));

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->vp_group, cursor);
	work_dbuff = FR_DBUFF(dbuff);

	while ((vp = fr_dcursor_current(&child_cursor)) != NULL) {
		fr_proto_da_stack_build(da_stack, vp->da);

		switch (da_stack->da[depth]->type) {
		case FR_TYPE_VSA:
			len = encode_vsio(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx);
			break;

		case FR_TYPE_TLV:
			len = encode_tlv(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx);
			break;

		default:
			len = encode_rfc(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx);
			break;
		}

		if (len <= 0) return len;
	}

	/*
	 *	Skip over the attribute we just encoded.
	 */
	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}



/** Write out a TLV header (and any sub TLVs or values)
 *
 * @param[out] dbuff		buffer to write the TLV to.
 * @param[in] da_stack		Describing nesting of options.
 * @param[in] depth		in the da_stack.
 * @param[in,out] cursor	Current attribute we're encoding.
 * @param[in] encode_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- >0 length of data encoded.
 *	- 0 if we ran out of space.
 *	- < 0 on error.
 */
static ssize_t encode_tlv(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			len, option_len;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t	hdr, dst, tmp;
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	uint8_t			option_number;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Where the TLV header starts.
	 */
	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	These are set before use; their initial value doesn't matter.
	 */
	fr_dbuff_marker(&dst, &work_dbuff);
	fr_dbuff_marker(&tmp, &work_dbuff);

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
		len = encode_child(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
		if (len < 0) return len;
		if (len == 0) break;		/* Insufficient space */

		/*
		 *	If the newly added data fits within the current option, then
		 *	update the header, and go to the next option.
		 */
		if ((option_len + len) <= 255) {
			option_len += len;

			fr_dbuff_set(&tmp, fr_dbuff_current(&hdr) + 1);
			FR_DBUFF_IN_BYTES_RETURN(&tmp, (uint8_t) option_len);

		} else if ((len = extend_option(&work_dbuff, &hdr, len)) < 0) {
			return PAIR_ENCODE_FATAL_ERROR;

		} else {
			option_len = len;
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

static ssize_t encode_vsio_data(fr_dbuff_t *dbuff,
				fr_da_stack_t *da_stack, unsigned int depth,
				fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX(dbuff, 255 - 4 - 1 - 2);
	fr_dbuff_marker_t	hdr;
	fr_dict_attr_t const	*da;
	fr_dict_attr_t const	*dv = da_stack->da[depth - 1];
	ssize_t			len;
	fr_pair_t		*vp;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("%s: Expected type \"vendor\" got \"%s\"", __FUNCTION__,
				   fr_type_to_str(dv->type));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Check if we have enough the enterprise-number,
	 *	plus the data length, plus at least one option header.
	 */
	FR_DBUFF_REMAINING_RETURN(&work_dbuff, sizeof(uint32_t) + 3);

	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	Copy in the 32bit PEN (Private Enterprise Number)
	 *
	 *	And leave room for data-len1
	 */
	FR_DBUFF_IN_RETURN(&work_dbuff, dv->attr);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) 0x00);

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
	da = da_stack->da[depth];

	/*
	 *	RFC 3925 Section 4 says:
	 *
	 *	Multiple instances of this option may be present and MUST be concatenated in accordance with
	 *	RFC 3396.
	 *
	 *	@todo - we don't currently allow encoding more data as per extend_option() or encode_tlv().
	 *	We probably want to do that.  We probably also want to update the decoder so that it
	 *	concatenates options before decoding, too.
	 */
	while (true) {
		len = encode_child(&work_dbuff, da_stack, depth, cursor, encode_ctx);
		if (len == 0) break; /* insufficient space */
		if (len < 0) return len;

		vp = fr_dcursor_current(cursor);
		if (!vp) break;

		/*
		 *	Encode all attributes which match this vendor.
		 */
		if (vp->da->parent != da->parent) break;
	}

	/*
	 *	Write out "data-len1" for this vendor
	 */
	fr_dbuff_advance(&hdr, 4);
	FR_DBUFF_IN_RETURN(&hdr, (uint8_t)(fr_dbuff_used(&work_dbuff) - 4 - 1));

#ifndef NDEBUG
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), "Done VSIO Data");
#endif

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_vsio(fr_dbuff_t *dbuff,
			       fr_da_stack_t *da_stack, unsigned int depth,
			       fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_pair_t		*vp;
	fr_dcursor_t		vendor_cursor;
	fr_dbuff_t		work_dbuff;
	fr_dbuff_marker_t	hdr;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	DA should be a VSA type with the value of OPTION_VENDOR_OPTS.
	 */
	if (da->type != FR_TYPE_VSA) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_type_to_str(da->type));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	work_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	Copy in the option code
	 *	And leave room for data-len1
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) da->attr, 0x00);

	/*
	 *	We are at the VSA.  The next entry in the stack is the vendor.  The entry after that is the vendor data.
	 */
	if (da_stack->da[depth + 1]) {
		ssize_t len;
		fr_dcursor_t vsa_cursor;

		if (da_stack->da[depth + 2]) {
			len = encode_vsio_data(&work_dbuff, da_stack, depth + 2, cursor, encode_ctx);
			if (len <= 0) return len;
			goto done;
		}

		vp = fr_dcursor_current(cursor);
		fr_assert(vp->vp_type == FR_TYPE_VENDOR);

		/*
		 *	Copied from below.
		 */
		fr_pair_dcursor_init(&vsa_cursor, &vp->vp_group);
		work_dbuff = FR_DBUFF(dbuff);

		while ((vp = fr_dcursor_current(&vsa_cursor)) != NULL) {
			fr_proto_da_stack_build(da_stack, vp->da);
			len = encode_vsio_data(&work_dbuff, da_stack, depth + 2, &vsa_cursor, encode_ctx);
			if (len <= 0) return len;
		}
		goto done;
	}

	vp = fr_dcursor_current(cursor);
	fr_assert(vp->da == da);

	fr_pair_dcursor_init(&vendor_cursor, &vp->vp_group);

	/*
	 *	Loop over all vendors, and inside of that, loop over all VSA attributes.
	 */
	while ((vp = fr_dcursor_current(&vendor_cursor)) != NULL) {
		ssize_t len;
		fr_dcursor_t vsa_cursor;

		if (vp->vp_type != FR_TYPE_VENDOR) continue;

		fr_pair_dcursor_init(&vsa_cursor, &vp->vp_group);

		while ((vp = fr_dcursor_current(&vsa_cursor)) != NULL) {
			/*
			 *	RFC 3925 Section 4 says:
			 *
			 *	"An Enterprise Number SHOULD only occur once
			 *	among all instances of this option.  Behavior
			 *	is undefined if an Enterprise Number occurs
			 *	multiple times."
			 *
			 *	The function encode_vsio_data() builds
			 *	one header, and then loops over all
			 *	children of the vsa_cursor.
			 */
			fr_proto_da_stack_build(da_stack, vp->da);
			len = encode_vsio_data(&work_dbuff, da_stack, depth + 2, &vsa_cursor, encode_ctx);
			if (len <= 0) return len;
		}

		(void) fr_dcursor_next(&vendor_cursor);
	}

	/*
	 *	Write out length for whole option
	 */
done:
	fr_dbuff_advance(&hdr, 1);
	FR_DBUFF_IN_RETURN(&hdr, (uint8_t)(fr_dbuff_used(&work_dbuff) - DHCPV4_OPT_HDR_LEN));

	/*
	 *	Skip over the attribute we just encoded.
	 */
	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a DHCP option and any sub-options.
 *
 * @param[out] dbuff		Where to write encoded DHCP attributes.
 * @param[in] cursor		with current VP set to the option to be encoded.
 *				Will be advanced to the next option to encode.
 * @param[in] encode_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 *	- 0 not valid option for DHCP (skipping).
 */
ssize_t fr_dhcpv4_encode_option(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t		*vp;
	fr_dhcpv4_ctx_t		*enc_ctx = encode_ctx;
	unsigned int		depth = enc_ctx->root->depth;
	fr_da_stack_t		da_stack;
	ssize_t			len;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	vp = fr_dcursor_current(cursor);
	if (!vp) return -1;

	fr_assert_msg(vp->da->attr <= 255, "Cursor provided unencodable attribute to enecoder");

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, depth);

	/*
	 *	We only have two types of options in DHCPv4
	 */
	switch (da_stack.da[depth]->type) {
	case FR_TYPE_VSA:
		len = encode_vsio(&work_dbuff, &da_stack, depth, cursor, encode_ctx);
		break;

	case FR_TYPE_TLV:
		len = encode_tlv(&work_dbuff, &da_stack, depth, cursor, encode_ctx);
		break;

	default:
		len = encode_rfc(&work_dbuff, &da_stack, depth, cursor, encode_ctx);
		break;
	}

	if (len <= 0) return len;

	FR_PROTO_TRACE("Complete option is %zu byte(s)", fr_dbuff_used(&work_dbuff));
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

ssize_t	fr_dhcpv4_encode_foreign(fr_dbuff_t *dbuff, fr_pair_list_t const *list)
{
	ssize_t		slen;
	fr_dcursor_t	cursor;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

	fr_assert(dict_dhcpv4 != NULL);

	fr_pair_dcursor_iter_init(&cursor, list, fr_dhcpv4_next_encodable, dict_dhcpv4);

	/*
	 *	Loop over all DHCPv4 options.
	 *
	 *	Unlike fr_dhcpv4_encode_dbuff(), we don't sort the options.  If that causes problems, we will
	 *	deal with it later.
	 */
	while (fr_dcursor_current(&cursor) != NULL) {
		slen = fr_dhcpv4_encode_option(&work_dbuff, &cursor, &(fr_dhcpv4_ctx_t){ .root = fr_dict_root(dict_dhcpv4) });
		if (slen < 0) return slen;
	}

	FR_PROTO_TRACE("Foreign option is %zu byte(s)", fr_dbuff_used(&work_dbuff));
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t fr_dhcpv4_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_dhcpv4_encode_dbuff(&FR_DBUFF_TMP(data, data_len), NULL, 0, 0, vps);
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   fr_dict_attr_t const *root_da)
{
	fr_dhcpv4_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_dhcpv4_ctx_t);
	if (!test_ctx) return -1;
	test_ctx->root = root_da ? root_da : fr_dict_root(dict_dhcpv4);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t dhcpv4_tp_encode_pair;
fr_test_point_pair_encode_t dhcpv4_tp_encode_pair = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dhcpv4_encode_option,
	.next_encodable	= fr_dhcpv4_next_encodable,
};



extern fr_test_point_proto_encode_t dhcpv4_tp_encode_proto;
fr_test_point_proto_encode_t dhcpv4_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dhcpv4_encode_proto
};
