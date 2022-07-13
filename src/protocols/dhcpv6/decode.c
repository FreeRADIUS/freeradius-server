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
	if ((parent->type == FR_TYPE_STRING) && da_is_dns_label(parent)) {
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
	uint8_t			prefix_len;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_value");

	switch (parent->type) {
	/*
	 *	Address MAY be shorter than 16 bytes.
	 */
	case FR_TYPE_IPV6_PREFIX:
		if (data_len == 0) {
		raw:
			return fr_pair_raw_from_network(ctx, out, parent, data, data_len);

		};

		/*
		 *	Structs used fixed length IPv6 addressews.
		 */
		if (parent->parent->type == FR_TYPE_STRUCT) {
			if (data_len != (1 + sizeof(vp->vp_ipv6addr))) {
				goto raw;
			}

			vp = fr_pair_afrom_da(ctx, parent);
			if (!vp) return PAIR_DECODE_OOM;

			vp->vp_ip.af = AF_INET6;
			vp->vp_ip.scope_id = 0;
			vp->vp_ip.prefix = data[0];
			memcpy(&vp->vp_ipv6addr, data + 1, sizeof(vp->vp_ipv6addr));
			slen = 1 + sizeof(vp->vp_ipv6addr);
			break;
		}

		/*
		 *	No address, the prefix length MUST be zero.
		 */
		if (data_len == 1) {
			if (data[0] != 0) goto raw;

			vp = fr_pair_afrom_da(ctx, parent);
			if (!vp) return PAIR_DECODE_OOM;

			vp->vp_ip.af = AF_INET6;
			slen = 1;
			break;
		}

		prefix_len = data[0];

		/*
		 *	If we have a /64 prefix but only 7 bytes of
		 *	address, that's an error.
		 */
		slen = fr_bytes_from_bits(prefix_len);
		if ((size_t) slen > (data_len - 1)) {
			goto raw;
		}

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.prefix = prefix_len;
		memcpy(&vp->vp_ipv6addr, data + 1, slen);

		slen++;
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

		slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
						 &FR_DBUFF_TMP(data, data_len), data_len, true);
		if (slen < 0) {
			talloc_free(vp);
			goto raw;
		}
		vp->vp_date = fr_unix_time_add(vp->vp_date, fr_time_delta_from_sec(DHCPV6_DATE_OFFSET));
		break;

	case FR_TYPE_STRUCT:
		slen = fr_struct_from_network(ctx, out, parent, data, data_len, false,
					      decode_ctx, decode_value_trampoline, decode_tlv_trampoline);
		if (slen < 0) goto raw;

		if (parent->flags.array) return slen;
		return data_len;

	case FR_TYPE_GROUP:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		/*
		 *	Child VPs go into the child group, not in the
		 *	main parent list.  We start decoding
		 *	attributes from the dictionary root, not from
		 *	this parent.  We also don't decode an option
		 *	header, as we're just decoding the values
		 *	here.
		 */
		slen = fr_pair_tlvs_from_network(vp, &vp->vp_group, fr_dict_root(dict_dhcpv6), data, data_len, decode_ctx, decode_option, NULL, false);
		if (slen < 0) {
			talloc_free(vp);
			return slen;
		}
		break;

	case FR_TYPE_IPV6_ADDR:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		/*
		 *	Limit the IPv6 address to 16 octets, with no scope.
		 */
		if (data_len < sizeof(vp->vp_ipv6addr)) goto raw;

		slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
						 &FR_DBUFF_TMP(data,  sizeof(vp->vp_ipv6addr)),  sizeof(vp->vp_ipv6addr), true);
		if (slen < 0) {
			talloc_free(vp);
			goto raw;
		}
		break;

	default:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
						 &FR_DBUFF_TMP(data, data_len), data_len, true);
		if (slen < 0) {
			talloc_free(vp);
			goto raw;
		}
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

		n = fr_dict_unknown_vendor_afrom_num(packet_ctx->tmp_ctx, parent, pen);
		if (!n) return PAIR_DECODE_OOM;
		da = n;
	}

	FR_PROTO_TRACE("decode context %s -> %s", parent->name, da->name);

	return fr_pair_tlvs_from_network(ctx, out, da, data + 4, data_len - 4, decode_ctx, decode_option, NULL, false);
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
		da = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, option);
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

		slen = fr_dhcpv6_decode(vp, &vp->vp_group, data + 4, len);
		if (slen < 0) {
			talloc_free(vp);
		raw:
			slen = fr_pair_raw_from_network(ctx, out, da, data + 4, len);
			if (slen < 0) return slen;
			return 4 + slen;
		}

		fr_pair_append(out, vp);

	} else if ((da->type == FR_TYPE_STRING) && da_is_dns_label(da)) {
		slen = fr_pair_dns_labels_from_network(ctx, out, da, data + 4, data + 4, len, NULL, true);
		if (slen < 0) return slen;

	} else if (da->flags.array) {
		slen = fr_pair_array_from_network(ctx, out, da, data + 4, len, decode_ctx, decode_value);

	} else if (da->type == FR_TYPE_VSA) {
		slen = decode_vsa(ctx, out, da, data + 4, len, decode_ctx);

	} else if (da->type == FR_TYPE_TLV) {
		slen = fr_pair_tlvs_from_network(ctx, out, da, data + 4, len, decode_ctx, decode_option, NULL, false);

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

/*
 *	Stub functions to enable test context
 */
static int _test_ctx_free(UNUSED fr_dhcpv6_decode_ctx_t *ctx)
{
	fr_dhcpv6_global_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_dhcpv6_decode_ctx_t	*test_ctx;

	if (fr_dhcpv6_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_dhcpv6_decode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);
	talloc_set_destructor(test_ctx, _test_ctx_free);

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
