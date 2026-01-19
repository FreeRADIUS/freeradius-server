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
 * @file protocols/dhcpv6/decode.c
 * @brief Functions to decode DHCP options.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 NetworkRADIUS SARL (legal@networkradius.com)
 */
#include <stdint.h>
#include <stddef.h>

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>

#include "dhcpv6.h"
#include "attrs.h"

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			     fr_dict_attr_t const *parent,
			     uint8_t const *data, size_t const data_len, void *decode_ctx);

static ssize_t decode_tlv_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	return fr_pair_tlvs_from_network(ctx, out, parent, data, data_len, decode_ctx, decode_option, NULL, true);
}

static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx);

/** Handle arrays of DNS labels for fr_struct_from_network()
 *
 */
static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				       fr_dict_attr_t const *parent,
				       uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	if ((parent->type == FR_TYPE_STRING) && fr_dhcpv6_flag_any_dns_label(parent)) {
		return fr_pair_dns_labels_from_network(ctx, out, parent, data, data, data_len, NULL, false);
	}

	return decode_value(ctx, out, parent, data, data_len, decode_ctx);
}


static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t			slen;
	fr_pair_t		*vp = NULL;
	fr_dict_attr_t const	*ref;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_value");

	switch (parent->type) {
	case FR_TYPE_ATTR:
		/*
		 *	Force the length of the data to be two,
		 *	otherwise the "from network" call complains.
		 *	Because we pass in the enumv as the _parent_
		 *	and not the da.  The da is marked as "array",
		 *	but the parent is not.
		 */
		if (data_len < 2) goto raw;

		fr_assert(parent->parent->flags.is_root);

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, parent->parent,
						 &FR_DBUFF_TMP(data, 2), 2, true);
		if (slen <= 0) {
			TALLOC_FREE(vp);
			goto raw;
		}

		vp->vp_tainted = true;
		fr_pair_append(out, vp);
		return 2;

	/*
	 *	Address MAY be shorter than 16 bytes.
	 */
	case FR_TYPE_IPV6_PREFIX:
		if (data_len == 0) {
		raw:
			return fr_pair_raw_from_network(ctx, out, parent, data, data_len);

		}

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		slen = fr_value_box_ipaddr_from_network(&vp->data, parent->type, parent,
							data[0], data + 1, data_len - 1,
							(parent->parent->type == FR_TYPE_STRUCT), true);
		if (slen < 0) goto raw_free;

		slen++;		/* account for the prefix */
		break;

	/*
	 *	A bool is encoded as an empty option if it's
	 *	true.  A bool is omitted entirely if it's
	 *	false.
	 */
	case FR_TYPE_BOOL:
		if (data_len != 0) goto raw;
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		vp->vp_bool = true;
		slen = 0;
		break;

	/*
	 *	A standard 32bit integer, but unlike normal UNIX timestamps
	 *	starts from the 1st of January 2000.
	 *
	 *	In the encoder we subtract 30 years to any values, so
	 *	here we need to add that to the time here.
	 */
	case FR_TYPE_DATE:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
						 &FR_DBUFF_TMP(data, data_len), data_len, true);
		if (slen < 0) {
			talloc_free(vp);
			goto raw;
		}
		vp->vp_date = fr_unix_time_add(vp->vp_date, fr_time_delta_from_sec(DHCPV6_DATE_OFFSET));
		break;

	case FR_TYPE_STRUCT:
		slen = fr_struct_from_network(ctx, out, parent, data, data_len,
					      decode_ctx, decode_value_trampoline, decode_tlv_trampoline);
		if (slen < 0) goto raw;

		if (parent->flags.array) return slen;
		return data_len;

	case FR_TYPE_GROUP:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		ref = fr_dict_attr_ref(parent);
		if (ref && (ref->dict != dict_dhcpv6)) {
			fr_dict_protocol_t const *proto;

			proto = fr_dict_protocol(ref->dict);
			fr_assert(proto != NULL);

			if (!proto->decode) {
			raw_free:
				talloc_free(vp);
				goto raw;
			}

			slen = proto->decode(vp, &vp->vp_group, data, data_len);
			if (slen < 0) goto raw_free;

			vp->vp_tainted = true;

		} else {
			if (!ref) ref = fr_dict_root(dict_dhcpv6);

			/*
			 *	Child VPs go into the child group, not in the main parent list.  BUT, we start
			 *	decoding attributes from the ref, and not from the group parent.
			 */
			slen = fr_pair_tlvs_from_network(vp, &vp->vp_group, ref, data, data_len, decode_ctx, decode_option, NULL, false);
			if (slen < 0) goto raw_free;
		}

		fr_pair_append(out, vp);
		return data_len;

	case FR_TYPE_IPV6_ADDR:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		slen = fr_value_box_ipaddr_from_network(&vp->data, parent->type, parent,
							128, data, data_len,
							true, true);
		if (slen < 0) goto raw_free;
		break;

	default:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
						 &FR_DBUFF_TMP(data, data_len), data_len, true);
		if (slen < 0) goto raw_free;
		break;
	}

	/*
	 *	The input is larger than the decoded value, re-do it as a raw attribute.
	 */
	if (!parent->flags.array && ((size_t) slen < data_len)) {
		talloc_free(vp);
		goto raw;
	}

	fr_assert(vp != NULL);

	vp->vp_tainted = true;
	fr_pair_append(out, vp);

	if (parent->flags.array) return slen;

	return data_len;
}


static ssize_t decode_vsa(TALLOC_CTX *ctx, fr_pair_list_t *out,
			  fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	uint32_t		pen;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	fr_dhcpv6_decode_ctx_t	*packet_ctx = decode_ctx;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_vsa");

	if (!fr_cond_assert_msg(parent->type == FR_TYPE_VSA,
				"%s: Internal sanity check failed, attribute \"%s\" is not of type 'vsa'",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

	/*
	 *	Enterprise code plus at least one option header
	 */
	if (data_len < 8) return fr_pair_raw_from_network(ctx, out, parent, data, data_len);

	memcpy(&pen, data, sizeof(pen));
	pen = htonl(pen);

	/*
	 *	Verify that the parent (which should be a VSA)
	 *	contains a fake attribute representing the vendor.
	 *
	 *	If it doesn't then this vendor is unknown, but we know
	 *	vendor attributes have a standard format, so we can
	 *	decode the data anyway.
	 */
	da = fr_dict_attr_child_by_num(parent, pen);
	if (!da) {
		fr_dict_attr_t *n;

		n = fr_dict_attr_unknown_vendor_afrom_num(packet_ctx->tmp_ctx, parent, pen);
		if (!n) return PAIR_DECODE_OOM;
		da = n;
	}

	FR_PROTO_TRACE("decode context %s -> %s", parent->name, da->name);

	vp = fr_pair_find_by_da(out, NULL, da);
	if (vp) {
		return fr_pair_tlvs_from_network(vp, &vp->vp_group, da, data + 4, data_len - 4, decode_ctx, decode_option, NULL, false);
	}

	return fr_pair_tlvs_from_network(ctx, out, da, data + 4, data_len - 4, decode_ctx, decode_option, NULL, true);
}

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	unsigned int   		option;
	size_t			len;
	ssize_t			slen;
	fr_dict_attr_t const	*da;
	fr_dhcpv6_decode_ctx_t	*packet_ctx = decode_ctx;

#ifdef STATIC_ANALYZER
	if (!packet_ctx || !packet_ctx->tmp_ctx) return PAIR_DECODE_FATAL_ERROR;
#endif

	/*
	 *	Must have at least an option header.
	 */
	if (data_len < 4) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -(data_len);
	}

	option = DHCPV6_GET_OPTION_NUM(data);
	len = DHCPV6_GET_OPTION_LEN(data);
	if (len > (data_len - 4)) {
		fr_strerror_printf("%s: Option overflows input.  "
				   "Optional length must be less than %zu bytes, got %zu bytes",
				   __FUNCTION__, data_len - 4, len);
		return PAIR_DECODE_FATAL_ERROR;
	}

	da = fr_dict_attr_child_by_num(parent, option);
	if (!da) {
		da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, option);
		if (!da) return PAIR_DECODE_FATAL_ERROR;
	}
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	/*
	 *	Relay messages are weird, and contain complete DHCPv6
	 *	packets, copied verbatim from the DHCPv6 client.
	 */
	if (da == attr_relay_message) {
		fr_pair_t *vp;

		vp = fr_pair_afrom_da(ctx, attr_relay_message);
		if (!vp) return PAIR_DECODE_FATAL_ERROR;
		PAIR_ALLOCED(vp);

		slen = fr_dhcpv6_decode(vp, &vp->vp_group, data + 4, len);
		if (slen < 0) {
			talloc_free(vp);
		raw:
			slen = fr_pair_raw_from_network(ctx, out, da, data + 4, len);
			if (slen < 0) return slen;
			return 4 + slen;
		}

		fr_pair_append(out, vp);

	} else if ((da->type == FR_TYPE_STRING) && fr_dhcpv6_flag_any_dns_label(da)) {
		slen = fr_pair_dns_labels_from_network(ctx, out, da, data + 4, data + 4, len, NULL, true);
		if (slen < 0) return slen;

	} else if (da->flags.array) {
		slen = fr_pair_array_from_network(ctx, out, da, data + 4, len, decode_ctx, decode_value);

	} else if (da->type == FR_TYPE_VSA) {
		bool append = false;
		fr_pair_t *vp;

		vp = fr_pair_find_by_da(out, NULL, da);
		if (!vp) {
			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) return PAIR_DECODE_FATAL_ERROR;
			PAIR_ALLOCED(vp);

			append = true;
		}

		slen = decode_vsa(vp, &vp->vp_group, da, data + 4, len, decode_ctx);
		if (append) {
			if (slen < 0) {
				TALLOC_FREE(vp);
			} else {
				fr_pair_append(out, vp);
			}
		}

	} else if (da->type == FR_TYPE_TLV) {
		slen = fr_pair_tlvs_from_network(ctx, out, da, data + 4, len, decode_ctx, decode_option, NULL, true);

	} else {
		slen = decode_value(ctx, out, da, data + 4, len, decode_ctx);
	}

	if (slen < 0) goto raw;

	return len + 4;
}


/** Create a "normal" fr_pair_t from the given data
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          option-code          |           option-len          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
ssize_t fr_dhcpv6_decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
				uint8_t const *data, size_t data_len, void *decode_ctx)
{
	FR_PROTO_HEX_DUMP(data, data_len, "fr_dhcpv6_decode_pair");

	/*
	 *	The API changes, so we just bounce directly to the
	 *	decode_option() function.
	 *
	 *	All options including VSAs in DHCPv6 MUST follow the
	 *	standard format.
	 */
	return decode_option(ctx, out, fr_dict_root(dict_dhcpv6), data, data_len, decode_ctx);
}

ssize_t	fr_dhcpv6_decode_foreign(TALLOC_CTX *ctx, fr_pair_list_t *out,
				 uint8_t const *data, size_t data_len)
{
	ssize_t slen;
	uint8_t const *attr, *end;

	fr_dhcpv6_decode_ctx_t decode_ctx = {};

	fr_assert(dict_dhcpv6 != NULL);

	decode_ctx.tmp_ctx = talloc(ctx, uint8_t);

	attr = data;
	end = data + data_len;

	while (attr < end) {
		slen = fr_dhcpv6_decode_option(ctx, out, attr, (end - attr), &decode_ctx);
		if (slen < 0) {
			talloc_free(decode_ctx.tmp_ctx);
			return slen;
		}

		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - attr))) {
			talloc_free(decode_ctx.tmp_ctx);
			 return -slen - (attr - data);
		 }

		attr += slen;
		talloc_free_children(decode_ctx.tmp_ctx);
	}

	talloc_free(decode_ctx.tmp_ctx);
	return data_len;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_dhcpv6_decode_ctx_t	*test_ctx;

	test_ctx = talloc_zero(ctx, fr_dhcpv6_decode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_dhcpv6_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	size_t packet_len = data_len;
//	fr_dhcpv6_decode_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_dhcpv6_decode_ctx_t);

	if (!fr_dhcpv6_ok(data, packet_len, 200)) return -1;

	return fr_dhcpv6_decode(ctx, out, data, packet_len);
}


static ssize_t decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, NDEBUG_UNUSED fr_dict_attr_t const *parent,
			   uint8_t const *data, size_t data_len, void *decode_ctx)
{
	fr_assert(parent == fr_dict_root(dict_dhcpv6));

	return decode_option(ctx, out, fr_dict_root(dict_dhcpv6), data, data_len, decode_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dhcpv6_tp_decode_pair;
fr_test_point_pair_decode_t dhcpv6_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_pair,
};

extern fr_test_point_proto_decode_t dhcpv6_tp_decode_proto;
fr_test_point_proto_decode_t dhcpv6_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv6_decode_proto
};
