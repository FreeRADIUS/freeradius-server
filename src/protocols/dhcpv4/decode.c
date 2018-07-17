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
 * @file protocols/dhcpv4/decode.c
 * @brief Functions to decode DHCP options.
 *
 * @copyright 2008,2017 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok <aland@deployingradius.com>
 * @copyright 2015,2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/rfc2865.h>
#include <freeradius-devel/io/test_point.h>

static ssize_t decode_tlv(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t data_len);

static ssize_t decode_value(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			    fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len);

/** Returns the number of array members for arrays with fixed element sizes
 *
 */
static int fr_dhcpv4_array_members(size_t *out, size_t len, fr_dict_attr_t const *da)
{
	int num_entries = 1;

	*out = len;

	/*
	 *	Could be an array of bytes, integers, etc.
	 */
	if (da->flags.array) switch (da->type) {
	case FR_TYPE_UINT8:
		num_entries = len;
		*out = 1;
		break;

	case FR_TYPE_UINT16: /* ignore any trailing data */
		num_entries = len >> 1;
		*out = 2;
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_UINT32:
	case FR_TYPE_DATE: /* ignore any trailing data */
		num_entries = len >> 2;
		*out = 4;
		break;

	case FR_TYPE_IPV6_ADDR:
		num_entries = len >> 4;
		*out = 16;
		break;

	default:
		break;
	}

	return num_entries;
}

/*
 *	Decode ONE value into a VP
 */
static ssize_t decode_value_internal(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *da,
				     uint8_t const *data, size_t data_len)
{
	VALUE_PAIR *vp;
	uint8_t const *p = data;

	FR_PROTO_TRACE("%s called to parse %zu bytes", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return -1;

	/*
	 *	Unknown attributes always get converted to
	 *	octet types, so there's no way there could
	 *	be multiple attributes, so its safe to
	 *	steal the unknown attribute into the context
	 *	of the pair.
	 */
	if (da->flags.is_unknown) talloc_steal(vp, da);

	if (vp->da->type == FR_TYPE_STRING) {
		uint8_t const *q, *end;

		q = end = data + data_len;

		/*
		 *	Not allowed to be an array, copy the whole value
		 */
		if (!vp->da->flags.array) {
			fr_pair_value_bstrncpy(vp, (char const *)p, end - p);
			p = end;
			goto finish;
		}

		for (;;) {
			q = memchr(p, '\0', q - p);

			/* Malformed but recoverable */
			if (!q) q = end;

			fr_pair_value_bstrncpy(vp, (char const *)p, q - p);
			p = q + 1;
			vp->vp_tainted = true;

			/* Need another VP for the next round */
			if (p < end) {
				fr_cursor_append(cursor, vp);

				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) return -1;
				continue;
			}
			break;
		}
		goto finish;
	}

	switch (vp->da->type) {
	/*
	 *	Doesn't include scope, whereas the generic format can
	 */
	case FR_TYPE_IPV6_ADDR:
		memcpy(&vp->vp_ipv6addr, p, sizeof(vp->vp_ipv6addr));
		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = 128;
		vp->vp_tainted = true;
		p += sizeof(vp->vp_ipv6addr);
		break;

	case FR_TYPE_IPV6_PREFIX:
		memcpy(&vp->vp_ipv6addr, p + 1, sizeof(vp->vp_ipv6addr));
		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = p[0];
		vp->vp_tainted = true;
		p += sizeof(vp->vp_ipv6addr) + 1;
		break;

	default:
	{
		ssize_t ret;

		ret = fr_value_box_from_network(vp, &vp->data, vp->da->type, da, p, data_len, true);
		if (ret < 0) {
			FR_PROTO_TRACE("decoding as unknown type");
			if (fr_pair_to_unknown(vp) < 0) return -1;
			fr_pair_value_memcpy(vp, p, data_len);
		}
		p += (size_t) ret;
	}
	}

finish:
	FR_PROTO_TRACE("decoding value complete, adding new pair and returning %zu byte(s)", p - data);
	fr_cursor_append(cursor, vp);

	return p - data;
}

/** RFC 4243 Vendor Specific Suboptions
 *
 * Vendor specific suboptions are in the format.
 @verbatim
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Enterprise Number 0                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Len 0      |                                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                      Suboption Data 0                         /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Enterprise Number n                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Len n      |                                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                      Suboption Data n                         /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 @endverbatim
 *
 * So although the vendor is identified, the format of the data isn't
 * specified so we can't actually resolve the suboption to an
 * attribute.  For now, we just convert it to an attribute of
 * DHCP-Vendor-Specific-Information with raw octets contents.
 */

/** Decode DHCP suboptions
 *
 * @param[in] ctx context to alloc new attributes in.
 * @param[in,out] cursor Where to write the decoded options.
 * @param[in] parent of sub TLVs.
 * @param[in] data to parse.
 * @param[in] data_len of data parsed.
 */
static ssize_t decode_tlv(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t data_len)
{
	uint8_t const		*p = data;
	uint8_t const		*end = data + data_len;
	fr_dict_attr_t const	*child;

	if (data_len < 3) return -1; /* type, length, value */

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	/*
	 *	Each TLV may contain multiple children
	 */
	while (p < end) {
		ssize_t tlv_len;

		if (p[0] == 0) {
			p++;
			continue;
		}

		/*
		 *	RFC 3046 is very specific about not allowing termination
		 *	with a 255 sub-option. But it's required for decoding
		 *	option 43, and vendors will probably screw it up
		 *	anyway.
		 */
		if (p[0] == 255) {
			p++;
			return p - data;
		}

		/*
		 *	Everything else should be real options
		 */
		if ((end - p) < 2) {
			fr_strerror_printf("%s: Insufficient data: Needed at least 2 bytes, got %zu",
					   __FUNCTION__, (end - p));
			return -1;
		}

		if (p[1] > (end - p)) {
			fr_strerror_printf("%s: Suboption would overflow option.  Remaining option data %zu byte(s) "
					   "(from %zu), Suboption length %u", __FUNCTION__, (end - p), data_len, p[1]);
			return -1;
		}

		child = fr_dict_attr_child_by_num(parent, p[0]);
		if (!child) {
			fr_dict_attr_t const *unknown_child;

			FR_PROTO_TRACE("failed to find child %u of TLV %s", p[0], parent->name);

			/*
			 *	Build an unknown attr
			 */
			unknown_child = fr_dict_unknown_afrom_fields(ctx, parent,
								     fr_dict_vendor_num_by_da(parent), p[0]);
			if (!unknown_child) return -1;
			child = unknown_child;
		}
		FR_PROTO_TRACE("decode context changed %s:%s -> %s:%s",
			       fr_int2str(dict_attr_types, parent->type, "<invalid>"), parent->name,
			       fr_int2str(dict_attr_types, child->type, "<invalid>"), child->name);

		tlv_len = decode_value(ctx, cursor, child, p + 2, p[1]);
		if (tlv_len <= 0) {
			fr_dict_unknown_free(&child);
			return tlv_len;
		}
		p += tlv_len + 2;
		FR_PROTO_TRACE("decode_value returned %zu, adding 2 (for header)", tlv_len);
		FR_PROTO_TRACE("remaining TLV data %zu byte(s)" , end - p);
	}
	FR_PROTO_TRACE("tlv parsing complete, returning %zu byte(s)", p - data);

	return p - data;
}

static ssize_t decode_value(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			    fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	unsigned int	values, i;		/* How many values we need to decode */
	uint8_t const	*p = data;
	size_t		value_len;
	ssize_t		len;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	/*
	 *	TLVs can't be coalesced as they're variable length
	 */
	if (parent->type == FR_TYPE_TLV) return decode_tlv(ctx, cursor, parent, data, data_len);

	/*
	 *	Values with a fixed length may be coalesced into a single option
	 */
	values = fr_dhcpv4_array_members(&value_len, data_len, parent);
	if (values) {
		FR_PROTO_TRACE("found %u coalesced values (%zu bytes each)", values, value_len);

		if ((values * value_len) != data_len) {
			fr_strerror_printf("Option length not divisible by its fixed value "
					  "length (probably trailing garbage)");
			return -1;
		}
	}

	/*
	 *	Decode each of the (maybe) coalesced values as its own
	 *	attribute.
	 */
	for (i = 0, p = data; i < values; i++) {
		len = decode_value_internal(ctx, cursor, parent, p, value_len);
		if (len <= 0) return len;
		if (len != (ssize_t)value_len) {
			fr_strerror_printf("Failed decoding complete option value");
			return -1;
		}
		p += len;
	}

	return p - data;
}

/** Decode DHCP option
 *
 * @param[in] ctx context to alloc new attributes in.
 * @param[in,out] cursor Where to write the decoded options.
 * @param[in] data to parse.
 * @param[in] data_len of data to parse.
 * @param[in] decoder_ctx Unused.
 */
ssize_t fr_dhcpv4_decode_option(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			        uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	ssize_t			ret;
	uint8_t const		*p = data;
	fr_dict_attr_t const	*child;
	fr_dhcp_ctx_t	*packet_ctx = decoder_ctx;
	fr_dict_attr_t const	*parent;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);

	if (data_len == 0) return 0;

	FR_PROTO_HEX_DUMP(NULL, data, data_len);

	/*
	 *	Stupid hacks until we have protocol specific dictionaries
	 */
	parent = fr_dict_attr_child_by_num(packet_ctx->root, FR_VENDOR_SPECIFIC);
	if (!parent) {
		fr_strerror_printf("Can't find Vendor-Specific (26)");
		return -1;
	}

	parent = fr_dict_attr_child_by_num(parent, DHCP_MAGIC_VENDOR);
	if (!parent) {
		fr_strerror_printf("Can't find DHCP vendor");
		return -1;
	}

	/*
	 *	Padding / End of options
	 */
	if (p[0] == 0) return 1;		/* 0x00 - Padding option */
	if (p[0] == 255) {			/* 0xff - End of options signifier */
		size_t i;

		for (i = 1; i < data_len; i++) {
			if (p[i] != 0) {
				FR_PROTO_HEX_DUMP("ignoring trailing junk at end of packet", p + i, data_len - i);
				break;
			}
		}
		return data_len;
	}

	/*
	 *	Everything else should be real options
	 */
	if ((data_len < 2) || (data[1] > data_len)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	child = fr_dict_attr_child_by_num(parent, p[0]);
	if (!child) {
		/*
		 *	Unknown attribute, create an octets type
		 *	attribute with the contents of the sub-option.
		 */
		child = fr_dict_unknown_afrom_fields(ctx, parent, DHCP_MAGIC_VENDOR, p[0]);
		if (!child) return -1;
	}
	FR_PROTO_TRACE("decode context changed %s:%s -> %s:%s",
		       fr_int2str(dict_attr_types, parent->type, "<invalid>"), parent->name,
		       fr_int2str(dict_attr_types, child->type, "<invalid>"), child->name);

	ret = decode_value(ctx, cursor, child, data + 2, data[1]);
	if (ret < 0) {
		fr_dict_unknown_free(&child);
		return ret;
	}
	ret += 2; /* For header */
	FR_PROTO_TRACE("decoding option complete, returning %zu byte(s)", ret);
	return ret;
}

static int _decode_test_ctx(UNUSED fr_dhcp_ctx_t *test_ctx)
{
	fr_dhcpv4_free();

	return 0;
}

static void *decode_test_ctx(TALLOC_CTX *ctx)
{
	fr_dhcp_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_dhcp_ctx_t);
	test_ctx->root = fr_dict_root(fr_dict_internal);
	talloc_set_destructor(test_ctx, _decode_test_ctx);

	fr_dhcpv4_init();

	return test_ctx;
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dhcpv4_tp_decode;
fr_test_point_pair_decode_t dhcpv4_tp_decode = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv4_decode_option
};
