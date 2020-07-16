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
#include <talloc.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/io/test_point.h>
#include "dhcpv4.h"
#include "attrs.h"

static ssize_t encode_option_dbuff(fr_dbuff_t *dbuff, fr_cursor_t *cursor, void *encoder_ctx);

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
			    fr_cursor_t *cursor, UNUSED fr_dhcpv4_ctx_t *encoder_ctx)
{
	VALUE_PAIR	*vp = fr_cursor_current(cursor);
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	size_t		need = 0;

	FR_PROTO_STACK_PRINT(da_stack, depth);
	FR_PROTO_TRACE("%zu byte(s) available for value", fr_dbuff_remaining(dbuff));

	switch (da_stack->da[depth]->type) {
	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		if (fr_value_box_to_network_dbuff(&need, &work_dbuff, &vp->data) < 0) return -2;
		if (need > 0) return -((ssize_t) need);
		break;

	case FR_TYPE_IPV6_PREFIX:
		FR_DBUFF_BYTES_IN_RETURN(&work_dbuff, vp->vp_ip.prefix);
		FR_DBUFF_MEMCPY_IN_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	case FR_TYPE_IPV6_ADDR:
		FR_DBUFF_MEMCPY_IN_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	default:
		fr_strerror_printf("Unsupported option type %d", vp->vp_type);
		(void)fr_cursor_next(cursor);
		return -2;
	}
	vp = fr_cursor_next(cursor);	/* We encoded a leaf, advance the cursor */
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	FR_PROTO_STACK_PRINT(da_stack, depth);
	FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), "Value");

	return fr_dbuff_advance(dbuff, fr_dbuff_used(&work_dbuff));
}


/** Extend an encoded option in-place.
 *
 * @param[in] dbuff	buffer containing the option
 * @param[in] hdr	where the option starts
 * @param[in] len	length of the data being written
 * @return
 *	- NULL if we can't extend the option
 *	- !NULL which is the start of the next option
 */
static uint8_t *extend_option(fr_dbuff_t *dbuff, uint8_t *hdr, int len)
{
	size_t header_bytes;
	uint8_t *next_hdr = NULL;

	/*
	 *	How many bytes we will need to add for headers.
	 */
	header_bytes = ((hdr[1] + len) / 255) * 2;

	/*
	 *	No room for the new headers and data, we're done.
	 */
	if (fr_dbuff_advance(dbuff, header_bytes) < 0) {
		return NULL;
	}

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
		sublen = 255 - hdr[1];
		if (sublen > len) sublen = len;

		/*
		 *	Add in the data left at the current pointer.
		 */
		hdr[1] += sublen;
		len -= sublen;

		/*
		 *	Nothing more to do?  Exit.
		 */
		if (!len) {
			break;
		}

		/*
		 *	The current option is full.  So move the
		 *	trailing data up by 2 bytes.  Then add a new
		 *	header, and keep looping in order to process
		 *	the next chunk.
		 */
		next_hdr = hdr + (hdr[1] + 2);
		memmove(next_hdr + 2, next_hdr, len);

		/*
		 *	Build the new header, then jump to it and use it.
		 */
		next_hdr[0] = hdr[0];
		next_hdr[1] = 0;
		hdr = next_hdr;
	}

	return next_hdr;
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
			      fr_cursor_t *cursor, fr_dhcpv4_ctx_t *encoder_ctx)
{
	ssize_t			len;
	uint8_t			*hdr;
	size_t			deduct = 0;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	VALUE_PAIR		*vp = fr_cursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	if (fr_dbuff_remaining(&work_dbuff) < 3) return 0;	/* No space */

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Write out the option number and length (which, unlike RADIUS,
	 *	is just the length of the value and hence starts out as zero).
	 */
	hdr = work_dbuff.p;
	fr_dbuff_bytes_in(&work_dbuff, (uint8_t)da->attr, 0);

	/*
	 *	DHCP options with the same number (and array flag set)
	 *	get coalesced into a single option.
	 *
	 *	Note: This only works with fixed length attributes,
	 *	because there's no separate length fields.
	 */
	do {
		VALUE_PAIR *next;

		/*
		 *	As a quick hack, check if there's enough room
		 *	for fixed-size attributes.  If we're encoding
		 *	the second or later value into this option,
		 *	AND we're encoding fixed size values, AND
		 *	there's no room for the next fixed-size value,
		 *	then don't encode this VP.
		 */
		if (hdr[1] && vp->da->flags.array &&
		    (dict_attr_sizes[vp->da->type][0] == dict_attr_sizes[vp->da->type][1]) &&
		    (hdr[1] + dict_attr_sizes[vp->da->type][0]) > 255) {
			break;
		}

		len = encode_value(&work_dbuff, da_stack, depth, cursor, encoder_ctx);
		if (len < -1) return len;
		if (len == -1) {
			FR_PROTO_TRACE("No more space in option");
			if (hdr[1] == 0) {
				/*
				 * Couldn't encode anything: don't leave behind these two octets,
				 * or rather, don't include them when advancing dbuff.
				 */
				deduct = 2;
			}
			break; /* Packed as much as we can */
		}

		FR_PROTO_STACK_PRINT(da_stack, depth);
		FR_PROTO_TRACE("Encoded value is %zu byte(s)", len);
		FR_PROTO_HEX_DUMP(dbuff->p, fr_dbuff_used(&work_dbuff), NULL);

		if ((hdr[1] + len) <= 255) {
			hdr[1] += len;
			FR_PROTO_TRACE("%u byte(s) available in option", 255 - hdr[1]);
		} else {
			hdr = extend_option(&work_dbuff, hdr, len);
			if (!hdr) break;
		}

		next = fr_cursor_current(cursor);
		if (!next || (vp->da != next->da)) break;
		vp = next;
	} while (vp->da->flags.array);

	return fr_dbuff_advance(dbuff, fr_dbuff_used(&work_dbuff) - deduct);
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
			      fr_cursor_t *cursor, fr_dhcpv4_ctx_t *encoder_ctx)
{
	ssize_t			len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	uint8_t			*hdr, *next_hdr, *start;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];

	if (fr_dbuff_remaining(&work_dbuff) < 5) return 0;	/* No space */

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Write out the option number and length (which, unlike RADIUS,
	 *	is just the length of the value and hence starts out as zero).
	 */
	start = hdr = dbuff->p;
	fr_dbuff_bytes_in(&work_dbuff, (uint8_t)da->attr, 0);

	/*
	 *	Encode any sub TLVs or values
	 */
	while (fr_dbuff_remaining(&work_dbuff) >= 3) {
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
		 *	If the newly added data fits within the
		 *	current option, then update the header, and go
		 *	to the next option.
		 */
		if ((hdr[1] + len) <= 255) {
			hdr[1] += len;

		} else {
			/*
			 *	The data doesn't fit within the
			 *	current option.  Maybe start a new
			 *	option.
			 */

			/*
			 *	Move the data up and start a new
			 *	option if necessary.
			 */
			if (hdr[1] > 0) {
				/*
				 *	Not enough space for another 2 byte
				 *	header.
				 */
				if (fr_dbuff_advance(&work_dbuff, 2) < 2) break;
				next_hdr = hdr + hdr[1] + 2;
				memmove(next_hdr + 2, next_hdr, len);
				next_hdr[0] = start[0];
				next_hdr[1] = 0;
				hdr = next_hdr;
			}

			/*
			 *	The data fits entirely within the new
			 *	option.  Just use that.
			 */
			if (len <= 255) {
				hdr[1] = len;

			} else {
				/*
				 *	The data has to be split
				 *	across multiple options.
				 */
				hdr = extend_option(&work_dbuff, hdr, len);
				if (!hdr) break;
			}
		}

		FR_PROTO_STACK_PRINT(da_stack, depth);
		FR_PROTO_HEX_DUMP(start, fr_dbuff_used(&work_dbuff), "TLV header and sub TLVs");

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_cursor_current(cursor) || (vp == fr_cursor_current(cursor))) break;

		/*
	 	 *	We can encode multiple sub TLVs, if after
	 	 *	rebuilding the TLV Stack, the attribute
	 	 *	at this depth is the same.
	 	 */
		if ((da != da_stack->da[depth]) || (da_stack->depth < da->depth)) break;
		vp = fr_cursor_current(cursor);
	}

	return fr_dbuff_advance(dbuff, fr_dbuff_used(&work_dbuff));
}

/** Encode a DHCP option and any sub-options.
 *
 * @param[out] out		Where to write encoded DHCP attributes.
 * @param[in] outlen		Length of out buffer.
 * @param[in] cursor		with current VP set to the option to be encoded.
 *				Will be advanced to the next option to encode.
 * @param[in] encoder_ctx	Containing DHCPv4 dictionary.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 *	- 0 not valid option for DHCP (skipping).
 */
ssize_t fr_dhcpv4_encode_option(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx)
{
	return encode_option_dbuff(&FR_DBUFF_TMP(out, outlen), cursor, encoder_ctx);
}

static ssize_t encode_option_dbuff(fr_dbuff_t *dbuff, fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	unsigned int		depth = 0;
	fr_da_stack_t		da_stack;
	ssize_t			len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	vp = fr_cursor_current(cursor);
	if (!vp) return -1;

	if (vp->da == attr_dhcp_message_type) goto next; /* already done */
	if ((vp->da->attr > 255) && (vp->da->attr != FR_DHCP_OPTION_82)) {
	next:
		fr_strerror_printf("Attribute \"%s\" is not a DHCP option", vp->da->name);
		(void)fr_cursor_next(cursor);
		return 0;
	}

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, depth);

	/*
	 *	We only have two types of options in DHCPv4
	 */
	switch (da_stack.da[depth]->type) {
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

	return fr_dbuff_advance(dbuff, fr_dbuff_used(&work_dbuff));
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
