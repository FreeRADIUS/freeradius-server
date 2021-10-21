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
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>

#include "dhcpv6.h"
#include "attrs.h"

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			     fr_dict_attr_t const *parent,
			     uint8_t const *data, size_t const data_len, void *decode_ctx);
static ssize_t decode_tlvs(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			   fr_dict_attr_t const *parent,
			   uint8_t const *data, size_t const data_len, void *decode_ctx, bool do_raw);

static ssize_t decode_tlv_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	return decode_tlvs(ctx, out, dict, parent, data, data_len, decode_ctx, true);
}


static ssize_t decode_raw(TALLOC_CTX *ctx, fr_pair_list_t *out, UNUSED fr_dict_t const *dict,
			  fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	fr_pair_t		*vp;
	fr_dict_attr_t		*unknown;
	fr_dict_attr_t const	*da;
	fr_dhcpv6_decode_ctx_t	*packet_ctx = decode_ctx;
	ssize_t			slen;

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx || !parent->parent) return PAIR_DECODE_FATAL_ERROR;
#endif

	FR_PROTO_HEX_DUMP(data, data_len, "decode_raw");

	/*
	 *	Re-write the attribute to be "raw".  It is
	 *	therefore of type "octets", and will be
	 *	handled below.
	 */
	unknown = fr_dict_unknown_attr_afrom_da(packet_ctx->tmp_ctx, parent);
	if (!unknown) {
		fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
		return PAIR_DECODE_OOM;
	}
	unknown->flags.is_raw = 1;

	vp = fr_pair_afrom_da(ctx, unknown);
	if (!vp) return PAIR_DECODE_OOM;

	slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					 &FR_DBUFF_TMP(data, data_len), data_len, true);
	if (slen < 0) {
		talloc_free(vp);
		da = unknown;
		fr_dict_unknown_free(&da);
		return slen;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_pair_append(out, vp);
	return data_len;
}

static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx);
static ssize_t decode_array(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx);
static ssize_t decode_dns_labels(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
				 fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t const data_len, void *decode_ctx);

/** Handle arrays of DNS lavels for fr_struct_from_network()
 *
 */
static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
				       fr_dict_attr_t const *parent,
				       uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	/*
	 *	@todo - we might need to limit this to only one DNS label.
	 */
	if ((parent->type == FR_TYPE_STRING) && !parent->flags.extra && parent->flags.subtype) {
		return decode_dns_labels(ctx, out, dict, parent, data, data_len, decode_ctx);
	}

	if (parent->flags.array) return decode_array(ctx, out, dict, parent, data, data_len, decode_ctx);

	return decode_value(ctx, out, dict, parent, data, data_len, decode_ctx);
}


static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t			slen;
	fr_pair_t		*vp;
	uint8_t			prefix_len;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_value");

	switch (parent->type) {
	/*
	 *	Address MAY be shorter than 16 bytes.
	 */
	case FR_TYPE_IPV6_PREFIX:
		if ((data_len == 0) || (data_len > (1 + sizeof(vp->vp_ipv6addr)))) {
		raw:
			return decode_raw(ctx, out, dict, parent, data, data_len, decode_ctx);

		};

		/*
		 *	Structs used fixed length fields
		 */
		if (parent->parent->type == FR_TYPE_STRUCT) {
			if (data_len != (1 + sizeof(vp->vp_ipv6addr))) goto raw;

			vp = fr_pair_afrom_da(ctx, parent);
			if (!vp) return PAIR_DECODE_OOM;

			vp->vp_ip.af = AF_INET6;
			vp->vp_ip.scope_id = 0;
			vp->vp_ip.prefix = data[0];
			memcpy(&vp->vp_ipv6addr, data + 1, data_len - 1);
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
			vp->vp_ip.scope_id = 0;
			vp->vp_ip.prefix = 0;
			memset(&vp->vp_ipv6addr, 0, sizeof(vp->vp_ipv6addr));
			break;
		}

		prefix_len = data[0];

		/*
		 *	If we have a /64 prefix but only 7 bytes of
		 *	address, that's an error.
		 */
		if (fr_bytes_from_bits(prefix_len) > (data_len - 1)) goto raw;

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = prefix_len;
		memset(&vp->vp_ipv6addr, 0, sizeof(vp->vp_ipv6addr));
		memcpy(&vp->vp_ipv6addr, data + 1, data_len - 1);
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

		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					      &FR_DBUFF_TMP(data, data_len), data_len, true) < 0) {
			talloc_free(vp);
			goto raw;
		}
		vp->vp_date = fr_unix_time_add(vp->vp_date, fr_time_delta_from_sec(DHCPV6_DATE_OFFSET));
		break;

	case FR_TYPE_STRUCT:
		slen = fr_struct_from_network(ctx, out, parent, data, data_len, false,
					      decode_ctx, decode_value_trampoline, decode_tlv_trampoline);
		if (slen < 0) return slen;
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
		slen = decode_tlvs(vp, &vp->vp_group, dict, fr_dict_root(dict_dhcpv6), data, data_len, decode_ctx, false);
		if (slen < 0) {
			talloc_free(vp);
			goto raw;
		}
		break;

	default:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					      &FR_DBUFF_TMP(data, data_len), data_len, true) < 0) {
			talloc_free(vp);
			goto raw;
		}
		break;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_pair_append(out, vp);
	return data_len;
}


static ssize_t decode_array(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	uint8_t const  		*p = data, *end = p + data_len;
	ssize_t			slen;
	size_t			element_len;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_array");

	if (!fr_cond_assert_msg(parent->flags.array,
				"%s: Internal sanity check failed, attribute \"%s\" does not have array bit set",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

	/*
	 *	Fixed-size fields get decoded with a simple decoder.
	 */
	element_len = fr_dhcpv6_attr_sizes[parent->type][0];
	if (element_len > 0) {
		while (p < end) {
			/*
			 *	Not enough room for one more element,
			 *	decode the last bit as raw data.
			 */
			if ((size_t) (end - p) < element_len) {
				slen = decode_raw(ctx, out, dict, parent, p, end - p , decode_ctx);
				if (slen < 0) return slen;
				break;
			}

			slen = decode_value(ctx, out, dict, parent, p, element_len, decode_ctx);
			if (slen < 0) return slen;
			if (!fr_cond_assert((size_t) slen == element_len)) return -(p - data);

			p += slen;
		}

		/*
		 *	We MUST have decoded the entire input.  If
		 *	not, we ignore the extra bits.
		 */
		return data_len;
	}

	/*
	 *	If the data is variable length i.e. strings or octets
	 *	there is a length field before each element.
	 *
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
	 *   |       text-len                |        String                 |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
	 */
	while (p < end) {
		if ((end - p) < 2) {
		raw:
			slen = decode_raw(ctx, out, dict, parent, p, end - p , decode_ctx);
			if (slen < 0) return slen;
			break;
		}

		element_len = fr_net_to_uint16(p);
		if ((p + 2 + element_len) > end) {
			goto raw;
		}

		p += 2;
		slen = decode_value(ctx, out, dict, parent, p, element_len, decode_ctx);
		if (slen < 0) return slen;
		p += slen;
	}

	return data_len;
}

static ssize_t decode_dns_labels(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
				 fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t slen;
	size_t total, labels_len;
	fr_pair_t *vp;
	uint8_t const *next = data;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_dns_labels");

	/*
	 *	This function handles both single-valued and array
	 *	types.  It's just easier that way.
	 */
	if (!parent->flags.array) {
		slen = fr_dns_label_uncompressed_length(data, data, data_len, &next, NULL);
		if (slen <= 0) goto raw;

		/*
		 *	If the DNS label doesn't exactly fill the option, it's an error.
		 *
		 *	@todo - we may want to remove this check.
		 */
		if (next != (data + data_len)) goto raw;

		labels_len = next - data; /* decode only what we've found */
	} else {
		/*
		 *	Get the length of the entire set of labels, up
		 *	to (and including) the final 0x00.
		 *
		 *	If any of the labels point outside of this
		 *	area, OR they are otherwise invalid, then that's an error.
		 */
		slen = fr_dns_labels_network_verify(data, data, data_len, data, NULL);
		if (slen < 0) {
		raw:
			return decode_raw(ctx, out, dict, parent, data, data_len, decode_ctx);
		}

		labels_len = slen;
	}

	/*
	 *	Loop over the input buffer, decoding the labels one by
	 *	one.
	 */
	for (total = 0; total < labels_len; total += slen) {
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		/*
		 *	Having verified the input above, this next
		 *	function should never fail unless there's a
		 *	bug in the code.
		 */
		slen = fr_dns_label_to_value_box(vp, &vp->data, data, labels_len, data + total, true, NULL);
		if (slen <= 0) {
			talloc_free(vp);
			goto raw;
		}

		vp->type = VT_DATA;
		fr_pair_append(out, vp);
	}

	return labels_len;
}


/** Like decode_option(), but decodes *all* of the options.
 *
 */
static ssize_t decode_tlvs(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			   fr_dict_attr_t const *parent,
			   uint8_t const *data, size_t const data_len, void *decode_ctx, bool do_raw)
{
	uint8_t const *p, *end;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_tlvs");

	if (!fr_cond_assert_msg((parent->type == FR_TYPE_TLV || (parent->type == FR_TYPE_VENDOR)),
				"%s: Internal sanity check failed, attribute \"%s\" is not of type 'tlv'",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;
	p = data;
	end = data + data_len;

	while (p < end) {
		ssize_t slen;

		slen = decode_option(ctx, out, dict, parent, p, (end - p), decode_ctx);
		if (slen <= 0) {
			if (!do_raw) return slen;

			slen = decode_raw(ctx, out, dict, parent, p, (end - p), decode_ctx);
			if (slen <= 0) return slen;
			break;
		}

		p += slen;
	}

	return data_len;
}


static ssize_t decode_vsa(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
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
	if (data_len < 8) return decode_raw(ctx, out, dict, parent, data, data_len, decode_ctx);

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

	return decode_tlvs(ctx, out, dict, da, data + 4, data_len - 4, decode_ctx, true);
}

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	unsigned int   		option;
	size_t			len;
	ssize_t			slen;
	fr_dict_attr_t const	*da;
	fr_dhcpv6_decode_ctx_t	*packet_ctx = decode_ctx;

#ifdef __clang_analyzer__
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
			return slen;
		}

		fr_pair_append(out, vp);
	} else if ((da->type == FR_TYPE_STRING) && !da->flags.extra && da->flags.subtype) {
		slen = decode_dns_labels(ctx, out, dict, da, data + 4, len, decode_ctx);
		if (slen < 0) return slen;

		/*
		 *	The DNS labels may only partially fill the
		 *	option.  If so, that's an error.  Point to the
		 *	byte which caused the error, accounting for
		 *	the option header.
		 */
		if ((size_t) slen != len) return -(4 + slen);

	} else if (da->flags.array) {
		slen = decode_array(ctx, out, dict, da, data + 4, len, decode_ctx);

	} else if (da->type == FR_TYPE_VSA) {
		slen = decode_vsa(ctx, out, dict, da, data + 4, len, decode_ctx);

	} else if (da->type == FR_TYPE_TLV) {
		slen = decode_tlvs(ctx, out, dict, da, data + 4, len, decode_ctx, true);

	} else {
		slen = decode_value(ctx, out, dict, da, data + 4, len, decode_ctx);
	}

	if (slen < 0) return slen;

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
ssize_t fr_dhcpv6_decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
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
	return decode_option(ctx, out, dict, fr_dict_root(dict), data, data_len, decode_ctx);
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

	test_ctx->tmp_ctx = talloc(ctx, uint8_t);
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


/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dhcpv6_tp_decode_pair;
fr_test_point_pair_decode_t dhcpv6_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv6_decode_option
};

extern fr_test_point_proto_decode_t dhcpv6_tp_decode_proto;
fr_test_point_proto_decode_t dhcpv6_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv6_decode_proto
};
