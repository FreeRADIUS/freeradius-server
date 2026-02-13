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
 * @file protocols/dns/encode.c
 * @brief Functions to encode DNS packets
 *
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2021 NetworkRADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/encode.h>

#include "dns.h"
#include "attrs.h"

#define DNS_OPT_HDR_LEN (4)

static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_rfc(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_tlv(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_child(fr_dbuff_t *dbuff,
			     fr_da_stack_t *da_stack, unsigned int depth,
			     fr_dcursor_t *cursor, void *encode_ctx);

/** Macro-like function for encoding an option header
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          option-code          |           option-len          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @param[out] m		Where to write the 4 byte option header.
 * @param[in] option		The option number (host byte order).
 * @param[in] data_len		The length of the option (host byte order).
 * @return
 *	- <0	How much data would have been required as a negative value.
 *	- 4	The length of data written.
 */
static inline ssize_t encode_option_hdr(fr_dbuff_marker_t *m, uint16_t option, size_t data_len)
{
	FR_DBUFF_IN_RETURN(m, option);
	FR_DBUFF_IN_RETURN(m, (uint16_t) data_len);

	return sizeof(option) + sizeof(uint16_t);
}


static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_dns_ctx_t	*packet_ctx = encode_ctx;

	PAIR_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Nested structs
	 */
	if (vp->vp_type == FR_TYPE_STRUCT) {
		fr_dcursor_t child_cursor;

		fr_pair_dcursor_child_iter_init(&child_cursor, &vp->vp_group, cursor);

		slen = fr_struct_to_network(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx, encode_value, encode_child);
		if (slen < 0) return slen;

		/*
		 *	Rebuild the da_stack for the next option.
		 */
		vp = fr_dcursor_next(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	/*
	 *	Flat-list
	 */
	if (da->type == FR_TYPE_STRUCT) {
		slen = fr_struct_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_value, encode_child);
		if (slen <= 0) return slen;

		/*
		 *	Rebuild the da_stack for the next option.
		 */
		vp = fr_dcursor_current(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return fr_dbuff_set(dbuff, &work_dbuff);
	}
	/*
	 *	If it's not a TLV, it should be a value type RFC
	 *	attribute make sure that it is.
	 */
	if (da_stack->da[depth + 1] != NULL) {
		fr_strerror_printf("%s: Encoding value but not at top of stack", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (vp->da != da) {
		fr_strerror_printf("%s: Top of stack does not match vp->da", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	switch (vp->vp_type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VENDOR:
	case FR_TYPE_VSA:
	case FR_TYPE_GROUP:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_type_to_str(da->type));
		return PAIR_ENCODE_FATAL_ERROR;

	case FR_TYPE_STRING:
		/*
		 *	DNS labels get a special encoder.
		 */
		if (fr_dns_flag_dns_label_any(da)) {
			fr_dbuff_marker_t	last_byte, src;

			fr_dbuff_marker(&last_byte, &work_dbuff);
			fr_dbuff_marker(&src, &work_dbuff);
			FR_PROTO_TRACE("encode DNS label %s", vp->vp_strvalue);
			slen = fr_dns_label_from_value_box_dbuff(&work_dbuff, fr_dns_flag_dns_label(da),
								 &vp->data, packet_ctx->lb);
			if (slen < 0) return slen;
			break;
		}
		goto to_network;

	/*
	 *	Common encoder might add scope byte, so we just copy the address portion
	 */
	case FR_TYPE_IPV6_ADDR:
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	case FR_TYPE_IPV4_PREFIX:
		fr_strerror_const("invalid data type - ipv4prefix");
		return PAIR_ENCODE_FATAL_ERROR;

	case FR_TYPE_IPV6_PREFIX:
		fr_strerror_const("invalid data type - ipv6prefix");
		return PAIR_ENCODE_FATAL_ERROR;

	case FR_TYPE_BOOL:
		/*
		 *	Don't encode anything!  The mere existence of
		 *	the attribute signifies a "true" value.
		 */
		break;

	/*
	 *	The value_box functions will take care of fixed-width
	 *	"string" and "octets" options.
	 */
	to_network:
	case FR_TYPE_OCTETS:
		/*
		 *	Hack until we find all places that don't set data.enumv
		 */
		if (vp->da->flags.length && (vp->data.enumv != vp->da)) {
			fr_dict_attr_t const * const *c = &vp->data.enumv;
			fr_dict_attr_t **u;

			memcpy(&u, &c, sizeof(c)); /* const issues */
			memcpy(u, &vp->da, sizeof(vp->da));
		}
		FALL_THROUGH;

	default:
		slen = fr_value_box_to_network(&work_dbuff, &vp->data);
		if (slen < 0) return PAIR_ENCODE_FATAL_ERROR;
		break;
	}

	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "done value");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

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

		case FR_TYPE_GROUP:
			if (!da_stack->da[depth + 1]) break;
			FALL_THROUGH;

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

/** Encode an RFC format TLV.
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_rfc(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t	hdr;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	ssize_t			len;

	FR_PROTO_STACK_PRINT(da_stack, depth);
	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	Make space for the header...
	 */
	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, DNS_OPT_HDR_LEN);
	fr_dbuff_advance(&work_dbuff, DNS_OPT_HDR_LEN);

	/*
	 *	Write out the option's value
	 */
	if (da->flags.array) {
		len = fr_pair_array_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_value);
	} else {
		len = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
	}
	if (len < 0) return len;

	/*
	 *	Write out the option number and length (before the value we just wrote)
	 */
	(void) encode_option_hdr(&hdr, (uint16_t)da->attr, (uint16_t) (fr_dbuff_used(&work_dbuff) - DNS_OPT_HDR_LEN));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done RFC header");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_tlv(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t	hdr;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	ssize_t			len;

	fr_dbuff_marker(&hdr, &work_dbuff);
	PAIR_VERIFY(fr_dcursor_current(cursor));
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da_stack->da[depth]->type != FR_TYPE_TLV) {
		fr_strerror_printf("%s: Expected type \"tlv\" got \"%s\"", __FUNCTION__,
				   fr_type_to_str(da_stack->da[depth]->type));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (!da_stack->da[depth + 1]) {
		fr_assert(0);
		fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	FR_DBUFF_ADVANCE_RETURN(&work_dbuff, DNS_OPT_HDR_LEN);	/* Make room for option header */

	len = fr_pair_cursor_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_child);
	if (len < 0) return len;

	/*
	 *    0                   1                   2                   3
	 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *   |          option-code          |           option-len          |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	(void) encode_option_hdr(&hdr, (uint16_t)da->attr, (uint16_t) (fr_dbuff_used(&work_dbuff) - DNS_OPT_HDR_LEN));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done TLV header");

	return fr_dbuff_set(dbuff, &work_dbuff);
}


/** Encode a Dns option and any sub-options.
 *
 *  This function is only used by the test harness.
 *
 * @param[out] dbuff		Where to write encoded DHCP attributes.
 * @param[in] cursor		with current VP set to the option to be encoded.
 *				Will be advanced to the next option to encode.
 * @param[in] encode_ctx	containing parameters for the encoder.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 */
static ssize_t fr_dns_encode_rr(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	fr_pair_t		*vp;
	fr_dcursor_t		child_cursor;
	fr_da_stack_t		da_stack;
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX(dbuff, UINT16_MAX);

	fr_proto_da_stack_build(&da_stack, attr_dns_rr);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	FR_PROTO_TRACE("encode_rr -- remaining %zd", fr_dbuff_remaining(&work_dbuff));

	vp = fr_dcursor_current(cursor);
	if (!vp) return 0;

	fr_assert(vp->vp_type == FR_TYPE_STRUCT);

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->vp_group, cursor);

	slen = fr_struct_to_network(&work_dbuff, &da_stack, 0, &child_cursor, encode_ctx, encode_value, encode_child);
	if (slen <= 0) return slen;
	(void) fr_dcursor_next(cursor);

	FR_PROTO_TRACE("Complete rr is %zu byte(s)", fr_dbuff_used(&work_dbuff));
	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_record(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, fr_pair_list_t *vps,
			     fr_dict_attr_t const *attr, fr_dns_ctx_t *packet_ctx, uint8_t *counter)
{
	int		count;
	fr_pair_t	*vp;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);
	fr_dcursor_t	cursor;

	vp = fr_pair_dcursor_by_da_init(&cursor, vps, attr);
	if (!vp) {
		FR_PROTO_TRACE("      %s not found in list", attr->name);
		counter[0] = counter[1] = 0;
		return 0;
	}

	fr_proto_da_stack_build(da_stack, attr);

	count = 0;
	while (count < 65535) {
		ssize_t slen;
		fr_dcursor_t child_cursor;

		fr_pair_dcursor_init(&child_cursor, &vp->vp_group);
		slen = fr_struct_to_network(&work_dbuff, da_stack, 0, &child_cursor, packet_ctx, encode_value, encode_child);
		if (slen <= 0) return slen;

		count++;
		vp = fr_dcursor_next(&cursor);
		if (!vp) break;
	}

	fr_nbo_from_uint16(counter, count);
	FR_PROTO_TRACE("      %s encoded %d records", attr->name, count);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a DNS packet
 *
 */
ssize_t fr_dns_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_dns_ctx_t *packet_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	ssize_t			slen;
	uint8_t			*packet;
	fr_pair_t		*vp;
	fr_dcursor_t		cursor;
	fr_da_stack_t		da_stack;

	packet = fr_dbuff_current(&work_dbuff);
	fr_assert(packet == packet_ctx->packet);

	/*
	 *	@todo - find maximum packet length, and limit work_dbuff to that.
	 */
	vp = fr_pair_dcursor_by_da_init(&cursor, vps, attr_dns_packet);
	if (!vp) {
		fr_pair_list_log(&default_log, 0, vps);

		fr_strerror_const("attribute list does not include DNS packet header");
		return -1;
	}

	/*
	 *	Encode the header.
	 */
	fr_proto_da_stack_build(&da_stack, attr_dns_packet);

	slen = fr_struct_to_network(&work_dbuff, &da_stack, 0, &cursor, packet_ctx, encode_value, NULL);
	if (slen <= 0) return slen;

	fr_assert(slen == DNS_HDR_LEN);

	/*
	 *	Encode questions
	 */
	slen = encode_record(&work_dbuff, &da_stack, vps, attr_dns_question, packet_ctx, packet + 4);
	if (slen < 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff));

	/*
	 *	Encode answers
	 */
	slen = encode_record(&work_dbuff, &da_stack, vps, attr_dns_rr, packet_ctx, packet + 6);
	if (slen < 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff));

	/*
	 *	Encode NS records
	 */
	slen = encode_record(&work_dbuff, &da_stack, vps, attr_dns_ns, packet_ctx, packet + 8);
	if (slen < 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff));

	/*
	 *	Encode additional records
	 */
	slen = encode_record(&work_dbuff, &da_stack, vps, attr_dns_ar, packet_ctx, packet + 10);
	if (slen < 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff));

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_dns_ctx_t	*test_ctx;

	test_ctx = talloc_zero(ctx, fr_dns_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_dns_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, void *proto_ctx)
{
	ssize_t slen;
	fr_dns_ctx_t *packet_ctx = (fr_dns_ctx_t *) proto_ctx;

	packet_ctx->packet = data;
	packet_ctx->packet_len = data_len;
	packet_ctx->lb = fr_dns_labels_get(data, data_len, false);
	fr_assert(packet_ctx->lb != NULL);

	slen = fr_dns_encode(&FR_DBUFF_TMP(data, data_len), vps, packet_ctx);

#ifndef NDEBUG
	if (slen <= 0) return slen;

	if (fr_debug_lvl > 2) {
//		fr_dns_print_hex(stdout, data, slen);
	}
#endif

	return slen;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t dns_tp_encode_pair;
fr_test_point_pair_encode_t dns_tp_encode_pair = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dns_encode_rr,
};

extern fr_test_point_proto_encode_t dns_tp_encode_proto;
fr_test_point_proto_encode_t dns_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_dns_encode_proto
};
