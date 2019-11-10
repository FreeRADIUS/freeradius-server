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
 * @file protocols/dhcpv6/encode.c
 * @brief Functions to encode DHCP options.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2018 The freeradius server project
 * @copyright 2018 NetworkRADIUS SARL (legal@networkradius.com)
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/io/test_point.h>

#include "dhcpv6.h"
#include "attrs.h"

static ssize_t encode_value(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, unsigned int depth,
			    fr_cursor_t *cursor, void *encoder_ctx);

static ssize_t encode_rfc_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx);

static ssize_t encode_tlv_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx);

static inline bool is_encodable(fr_dict_attr_t const *root, VALUE_PAIR *vp)
{
	if (!vp) return false;
	if (vp->da->flags.internal) return false;
	if (!fr_dict_parent_common(root, vp->da, true)) return false;

	/*
	 *	False bools are represented by the absence of
	 *	an option, i.e. only bool attributes which are
	 *	true get encoded.
	 */
	if ((vp->da->type == FR_TYPE_BOOL) && !vp->vp_bool) return false;

	return true;
}

/** Find the next attribute to encode
 *
 * @param cursor to iterate over.
 * @param encoder_ctx the context for the encoder
 * @return encodable VALUE_PAIR, or NULL if none available.
 */
static inline VALUE_PAIR *next_encodable(fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	fr_dhcpv6_encode_ctx_t	*packet_ctx = encoder_ctx;

	while ((vp = fr_cursor_next(cursor))) if (is_encodable(packet_ctx->root, vp)) break;
	return fr_cursor_current(cursor);
}

/** Determine if the current attribute is encodable, or find the first one that is
 *
 * @param cursor to iterate over.
 * @param encoder_ctx the context for the encoder
 * @return encodable VALUE_PAIR, or NULL if none available.
 */
static inline VALUE_PAIR *first_encodable(fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	fr_dhcpv6_encode_ctx_t	*packet_ctx = encoder_ctx;

	vp = fr_cursor_current(cursor);
	if (is_encodable(packet_ctx->root, vp)) return vp;

	return next_encodable(cursor, encoder_ctx);
}

/** Macro-like function for encoding an option header
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          option-code          |           option-len          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @param[out] out		Where to write the 4 byte option header.
 * @param[in] outlen		Length of the output buffer.
 * @param[in] option		The option number (host byte order).
 * @param[in] data_len		The length of the option (host byte order).
 * @return
 *	- <0	How much data would have been required as a negative value.
 *	- 4	The length of data written.
 */
static inline ssize_t encode_option_hdr(uint8_t *out, size_t outlen, uint16_t option, size_t data_len)
{
	uint16_t	opt, len;
	uint8_t		*p = out;

	CHECK_FREESPACE(outlen, OPT_HDR_LEN);

	opt = htons(option);
	len = htons(data_len);

	memcpy(p, &opt, sizeof(opt));
	p += sizeof(opt);
	memcpy(p, &len, sizeof(len));
	p += sizeof(len);

	return p - out;
}

static ssize_t encode_struct(uint8_t *out, size_t outlen,
			     fr_dict_attr_t const **tlv_stack, unsigned int depth,
			     fr_cursor_t *cursor, UNUSED void *encoder_ctx)
{
	VP_VERIFY(fr_cursor_current(cursor));
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (tlv_stack[depth]->type != FR_TYPE_STRUCT) {
		fr_strerror_printf("%s: Expected type \"struct\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, tlv_stack[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_ERROR;
	}

	if (!tlv_stack[depth + 1]) {
		fr_strerror_printf("%s: Can't encode empty struct", __FUNCTION__);
		return PAIR_ENCODE_ERROR;
	}

	return fr_struct_to_network(out, outlen, tlv_stack[depth], cursor);
}

static ssize_t encode_value(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, unsigned int depth,
			    fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	uint8_t			*p = out, *end = p + outlen;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Pack multiple attributes into into a single option
	 */
	if (da->type == FR_TYPE_STRUCT) {
		slen = encode_struct(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
		if (slen < 0) return slen;

		vp = next_encodable(cursor, encoder_ctx);
		fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);
		return slen;
	}

	/*
	 *	If it's not a TLV, it should be a value type RFC
	 *	attribute make sure that it is.
	 */
	if (tlv_stack[depth + 1] != NULL) {
		fr_strerror_printf("%s: Encoding value but not at top of stack", __FUNCTION__);
		return PAIR_ENCODE_ERROR;
	}

	if (vp->da != da) {
		fr_strerror_printf("%s: Top of stack does not match vp->da", __FUNCTION__);
		return PAIR_ENCODE_ERROR;
	}

	switch (da->type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_ERROR;

	default:
		break;
	}


	switch (da->type) {
	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |          option-len           |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   .                            String                             .
	 *   |                              ...                              |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_STRING:
		/*
		 *	DNS labels get a special encoder.  DNS labels
		 *	MUST NOT be compressed in DHCP.
		 *
		 *	https://tools.ietf.org/html/rfc8415#section-10
		 */
		if (da->flags.subtype == FLAG_ENCODE_DNS_LABEL) {
			slen = fr_dns_label_from_value_box(NULL, p, outlen, p, false, &vp->data);

			/*
			 *	@todo - check for free space, etc.
			 */
			if (slen <= 0) return PAIR_ENCODE_ERROR;

			p += slen;
			break;
		}
		/* FALL-THROUGH */

	case FR_TYPE_OCTETS:
		/*
		 *	If asked to encode more data than allowed,
		 *	we encode only the allowed data.
		 */
		slen = fr_dhcpv6_option_len(vp);
		CHECK_FREESPACE(outlen, slen);

		if (vp->vp_length < (size_t)slen) {
			memcpy(p, vp->vp_ptr, vp->vp_length);
			memset(p + vp->vp_length, 0, slen - vp->vp_length);
		} else {
			memcpy(p, vp->vp_ptr, slen);
		}
		p += slen;
		break;

	/*
	 * Common encoder might add scope byte, so we just copy the address portion
	 *
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |           option-len          |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |                                                               |
	 *   |                         ipv6-address                          |
	 *   |                                                               |
	 *   |                                                               |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_IPV6_ADDR:
		CHECK_FREESPACE(outlen, sizeof(vp->vp_ipv6addr));

		memcpy(out, vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		p += sizeof(vp->vp_ipv6addr);
		break;

	/*
	 *	Common encoder doesn't add a reserved byte after prefix, but it also
	 *	doesn't do the variable length encoding required.
	 *
	 *      0                   1                   2                   3
	 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |          option-code          |         option-length         |
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *     |  prefix6len   |              ipv6-prefix                      |
	 *     +-+-+-+-+-+-+-+-+           (variable length)                   |
	 *     .                                                               .
	 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_IPV6_PREFIX:
	{
		uint8_t	prefix_len;

		prefix_len = vp->vp_ip.prefix >> 3;		/* Convert bits to whole bytes */
		CHECK_FREESPACE(outlen, prefix_len + 1);

		*p++ = vp->vp_ip.prefix;
		memcpy(p, &vp->vp_ipv6addr, prefix_len);	/* Only copy the minimum address bytes required */
		p += prefix_len;
	}
		break;

	/*
	 *	Not actually specified by the DHCPv6 RFC, but will probably come
	 *	in handy at some point if we need to have the DHCPv6 server
	 *	hand out v4 prefixes.
	 */
	case FR_TYPE_IPV4_PREFIX:
	{
		uint8_t prefix_len;

		prefix_len = vp->vp_ip.prefix >> 3;		/* Convert bits to whole bytes */
		CHECK_FREESPACE(outlen, prefix_len + 1);

		*p++ = vp->vp_ip.prefix;
		memcpy(p, &vp->vp_ipv4addr, prefix_len);	/* Only copy the minimum address bytes required */
		p += prefix_len;
	}
		break;

	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |           option-len          |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_BOOL:
		break;

	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |          option-len           |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   | 8-bit-integer |
	 *   +-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_UINT8:

	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |           option-len          |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |         16-bit-integer        |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_UINT16:
	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |          option-code          |           option-len          |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |                         32-bit-integer                        |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
		CHECK_FREESPACE(outlen, fr_dhcpv6_option_len(vp));
		slen = fr_value_box_to_network(NULL, p, end - p, &vp->data);
		if (slen < 0) return PAIR_ENCODE_ERROR;
		p += slen;
		break;

	/*
	 *	A standard 32bit integer, but unlike normal UNIX timestamps
	 *	starts from the 1st of January 2000.
	 *
	 *	In the decoder we add 946,080,000 seconds (30 years) to any
	 *	values, so here we need to subtract 946,080,000 seconds, or
	 *	if the value is less than 946,080,000 seconds, just encode
	 *	a 0x0000000000 value.
	 */
	case FR_TYPE_DATE:
	{
		uint32_t adj_date;
		fr_time_t date = fr_time_to_sec(vp->vp_date);

		CHECK_FREESPACE(outlen, fr_dhcpv6_option_len(vp));

		if (date < 946080000) {	/* 30 years */
			memset(p, 0, sizeof(uint32_t));
			p += sizeof(uint32_t);
			break;
		}

		adj_date = htonl(date - 946080000);
		memcpy(p, &adj_date, sizeof(adj_date));
		p += sizeof(adj_date);
	}
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_EXTENDED:
	case FR_TYPE_COMBO_IP_ADDR:	/* Should have been converted to concrete equivalent */
	case FR_TYPE_COMBO_IP_PREFIX:	/* Should have been converted to concrete equivalent */
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
	case FR_TYPE_TLV:
	case FR_TYPE_STRUCT:
	case FR_TYPE_SIZE:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_ABINARY:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_GROUP:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_MAX:
		fr_strerror_printf("Unsupported attribute type %d", da->type);
		return PAIR_ENCODE_ERROR;
	}

	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = next_encodable(cursor, encoder_ctx);
	fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);

	return p - out;
}

static inline ssize_t encode_array(uint8_t *out, size_t outlen,
				   fr_dict_attr_t const **tlv_stack, int depth,
				   fr_cursor_t *cursor, void *encoder_ctx)
{
	uint8_t			*p = out, *end = p + outlen;
	ssize_t			slen;
	size_t			element_len;
	VALUE_PAIR		*vp;
	fr_dict_attr_t const	*da = tlv_stack[depth];

	if (!fr_cond_assert_msg(da->flags.array,
				"%s: Internal sanity check failed, attribute \"%s\" does not have array bit set",
				__FUNCTION__, da->name)) return PAIR_ENCODE_ERROR;

	/*
	 *	DNS labels have internalized length, so we don't need
	 *	length headers.
	 */
	if ((da->type == FR_TYPE_STRING) && da->flags.subtype){
		while (p < end) {
			vp = fr_cursor_current(cursor);

			/*
			 *	DNS labels get a special encoder.  DNS labels
			 *	MUST NOT be compressed in DHCP.
			 *
			 *	https://tools.ietf.org/html/rfc8415#section-10
			 */
			slen = fr_dns_label_from_value_box(NULL, out, outlen, p, false, &vp->data);
			if (slen <= 0) return PAIR_ENCODE_ERROR;

			p += slen;
			vp = next_encodable(cursor, encoder_ctx);
			if (!vp || (vp->da != da)) break;		/* Stop if we have an attribute of a different type */
		}

		return p - out;
	}

	while (p < end) {
		uint16_t 	*len_field = NULL;	/* GCC is dumb */

		element_len = fr_dhcpv6_option_len(fr_cursor_current(cursor));

		/*
		 *	If the data is variable length i.e. strings or octets
		 *	we need to include a length field before each element.
		 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
		 *   |       text-len                |        String                 |
		 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
		 */
		if (!da->flags.length) {
			CHECK_FREESPACE(end - p, sizeof(uint16_t) + element_len);
			len_field = (uint16_t *)p;
			p += sizeof(uint16_t);			/* Make room for the length field */
		}

		slen = encode_value(p, end - p, tlv_stack, depth, cursor, encoder_ctx);
		if (slen < 0) return slen;
		if (!fr_cond_assert(slen < UINT16_MAX)) return PAIR_ENCODE_ERROR;

		/*
		 *	Ensure we always create elements of the correct length.
		 *	This is mainly for fixed length octets type attributes
		 *	containing one or more keys.
		 */
		if (da->flags.length) {
			if ((size_t)slen < element_len) {
				memset(p + slen, 0, element_len - slen);
				slen = element_len;
			} else if ((size_t)slen > element_len){
				slen = element_len;
			}
		}

		p += slen;

		/*
		 *	Populate the length field
		 */
		if (len_field) *len_field = htons((uint16_t) slen);
		
		vp = fr_cursor_current(cursor);
		if (!vp || (vp->da != da)) break;		/* Stop if we have an attribute of a different type */
	}

	return p - out;
}

static ssize_t encode_tlv(uint8_t *out, size_t outlen,
			  fr_dict_attr_t const **tlv_stack, unsigned int depth,
			  fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	uint8_t			*p = out, *end = p + outlen;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];

	CHECK_FREESPACE(outlen, OPT_HDR_LEN);

	while ((size_t)(end - p) > OPT_HDR_LEN) {
		FR_PROTO_STACK_PRINT(tlv_stack, depth);

		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (tlv_stack[depth + 1]->type == FR_TYPE_TLV) {
			slen = encode_tlv_hdr(p, end - p, tlv_stack, depth + 1, cursor, encoder_ctx);
		} else {
			slen = encode_rfc_hdr(p, end - p, tlv_stack, depth + 1, cursor, encoder_ctx);
		}
		if (slen < 0) return slen;

		p += slen;

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_cursor_current(cursor) || (vp == fr_cursor_current(cursor))) break;

		/*
		 *	We can encode multiple sub TLVs, if after
		 *	rebuilding the TLV Stack, the attribute
		 *	at this depth is the same.
		 */
		if (da != tlv_stack[depth]) break;
		vp = fr_cursor_current(cursor);
	}

#ifndef NDEBUG
	FR_PROTO_HEX_DUMP(out, p - out, "Done TLV body");
#endif

	return p - out;
}

/** Encode an RFC format TLV.
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_rfc_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx)
{
	uint8_t			*p = out, *end = p + outlen;
	ssize_t			slen;
	fr_dict_attr_t const	*da = tlv_stack[depth];

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	CHECK_FREESPACE(outlen, OPT_HDR_LEN);

	/*
	 *	Make space for the header...
	 */
	p += OPT_HDR_LEN;

	/*
	 *	Write out the option's value
	 */
	if (da->flags.array) {
		slen = encode_array(p, end - p, tlv_stack, depth, cursor, encoder_ctx);
	} else {
		slen = encode_value(p, end - p, tlv_stack, depth, cursor, encoder_ctx);
	}
	if (slen < 0) return slen;
	p += slen;

	/*
	 *	Write out the option number and length (before the value we jus wrote)
	 */
	slen = encode_option_hdr(out, outlen, (uint16_t)da->attr, (uint16_t)slen);
	if (slen < 0) return slen;

#ifndef NDEBUG
	FR_PROTO_HEX_DUMP(out, p - out, "Done RFC header");
#endif

	return p - out;
}

static ssize_t encode_tlv_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	uint8_t			*p = out, *end = p + outlen;
	fr_dict_attr_t const	*da = tlv_stack[depth];

	VP_VERIFY(fr_cursor_current(cursor));
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (tlv_stack[depth]->type != FR_TYPE_TLV) {
		fr_strerror_printf("%s: Expected type \"tlv\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, tlv_stack[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_ERROR;
	}

	if (!tlv_stack[depth + 1]) {
		fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
		return PAIR_ENCODE_ERROR;
	}

	CHECK_FREESPACE(outlen, OPT_HDR_LEN);

	p += OPT_HDR_LEN;	/* Make room for option header */
	slen = encode_tlv(p, end - p, tlv_stack, depth, cursor, encoder_ctx);
	if (slen < 0) return slen;
	p += slen;

	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |           option-len          |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	slen = encode_option_hdr(out, outlen, (uint16_t)da->attr, (uint16_t)slen);
	if (slen < 0) return slen;

#ifndef NDEBUG
	FR_PROTO_HEX_DUMP(out, p - out, "Done TLV header");
#endif

	return p - out;
}


/** Encode a Vendor-Specific Information Option
 *
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      OPTION_VENDOR_OPTS       |           option-len          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       enterprise-number                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     .                                                               .
 *     .                          option-data                          .
 *     .                                                               .
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static ssize_t encode_vsio_hdr(uint8_t *out, size_t outlen,
			       fr_dict_attr_t const **tlv_stack, unsigned int depth,
			       fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	uint32_t		pen;
	uint8_t			*p = out, *end = p + outlen;
	fr_dict_attr_t const	*da = tlv_stack[depth];
	fr_dict_attr_t const	*dv;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	DA should be a VSA type with the value of OPTION_VENDOR_OPTS.
	 */
	if (da->type != FR_TYPE_VSA) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_ERROR;
	}

	/*
	 *	Check if we have enough for an option header plus the
	 *	enterprise-number.
	 */
	CHECK_FREESPACE(outlen, OPT_HDR_LEN + sizeof(uint32_t));

	/*
	 *	Now process the vendor ID part (which is one attribute deeper)
	 */
	dv = tlv_stack[++depth];
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, dv->type, "?Unknown?"));
		return PAIR_ENCODE_ERROR;
	}

	/*
	 *	Copy in the 32bit PEN (Private Enterprise Number)
	 */
	p += OPT_HDR_LEN;
	pen = htonl(dv->attr);
	memcpy(p, &pen, sizeof(pen));
	p += 4;

	/*
	 *	https://tools.ietf.org/html/rfc8415#section-21.17 says:
	 *
	 *   The vendor-option-data field MUST be encoded as a sequence of
	 *   code/length/value fields of format identical to the DHCP options (see
	 *   Section 21.1).  The sub-option codes are defined by the vendor
	 *   identified in the enterprise-number field and are not managed by
	 *   IANA.  Each of the sub-options is formatted as follows:
	 *
	 *       0                   1                   2                   3
	 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |          sub-opt-code         |         sub-option-len        |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      .                                                               .
	 *      .                        sub-option-data                        .
	 *      .                                                               .
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	/*
	 *	Encode the different data types
	 */
	if (da->type == FR_TYPE_TLV) {
		slen = encode_tlv_hdr(p, end - p, tlv_stack, depth + 1, cursor, encoder_ctx);

	} else {
		/*
		 *	Normal vendor option
		 */
		slen = encode_rfc_hdr(p, end - p, tlv_stack, depth + 1, cursor, encoder_ctx);
	}

	if (slen < 0) return slen;
	p += slen;

	encode_option_hdr(out, outlen, da->attr, p - (out + 4));

#ifndef NDEBUG
	FR_PROTO_HEX_DUMP(out, p - out, "Done VSIO header");
#endif

	return p - out;
}

/** Encode a DHCPv6 option and any sub-options.
 *
 * @param[out] out		Where to write encoded DHCP attributes.
 * @param[in] outlen		Length of out buffer.
 * @param[in] cursor		with current VP set to the option to be encoded.
 *				Will be advanced to the next option to encode.
 * @param[in] encoder_ctx	containing parameters for the encoder.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 */
ssize_t fr_dhcpv6_encode_option(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	unsigned int		depth = 0;
	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	ssize_t			slen;

	vp = first_encodable(cursor, encoder_ctx);
	if (!vp) return 0;

	if (vp->da->flags.internal) {
		fr_strerror_printf("Attribute \"%s\" is not a DHCPv6 option", vp->da->name);
		fr_cursor_next(cursor);
		return PAIR_ENCODE_SKIP;
	}

	fr_proto_tlv_stack_build(tlv_stack, vp->da);

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Trim output buffer size for sanity
	 */
	if (outlen > (OPT_HDR_LEN + UINT16_MAX)) outlen = (OPT_HDR_LEN + UINT16_MAX);

	/*
	 *	Deal with nested options
	 */
	switch (tlv_stack[depth]->type) {
	case FR_TYPE_TLV:
		slen = encode_tlv_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
		break;

	case FR_TYPE_VSA:
		slen = encode_vsio_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
		break;

	default:
		slen = encode_rfc_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
		break;
	}

	if (slen <= 0) return slen;

	FR_PROTO_TRACE("Complete option is %zu byte(s)", slen);
	FR_PROTO_HEX_DUMP(out, slen, NULL);

	return slen;
}

static int _test_ctx_free(UNUSED fr_dhcpv6_encode_ctx_t *ctx)
{
	fr_dhcpv6_global_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_dhcpv6_encode_ctx_t	*test_ctx;

	if (fr_dhcpv6_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_dhcpv6_encode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_dhcpv6);
	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_dhcpv6_encode_proto(UNUSED TALLOC_CTX *ctx, VALUE_PAIR *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
//	fr_dhcpv6_decode_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_dhcpv6_decode_ctx_t);


	return fr_dhcpv6_encode(data, data_len, NULL, 0, vps);
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t dhcpv6_tp_encode_pair;
fr_test_point_pair_encode_t dhcpv6_tp_encode_pair = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dhcpv6_encode_option
};

extern fr_test_point_proto_encode_t dhcpv6_tp_encode_proto;
fr_test_point_proto_encode_t dhcpv6_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dhcpv6_encode_proto
};
