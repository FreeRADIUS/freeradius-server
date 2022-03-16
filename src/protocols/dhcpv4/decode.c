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
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 * @copyright 2015,2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>

#include "dhcpv4.h"
#include "attrs.h"

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx);

static ssize_t decode_tlv(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t data_len, void *decode_ctx);

static ssize_t decode_array(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decode_ctx);

static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decode_ctx, bool exact);

/** Handle arrays of DNS labels for fr_struct_from_network()
 *
 */
static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				       fr_dict_attr_t const *parent,
				       uint8_t const *data, size_t const data_len, void *decode_ctx)
{
#if 0
	/*
	 *	@todo - we might need to limit this to only one DNS label.
	 */
	if ((parent->type == FR_TYPE_STRING) && !parent->flags.extra && parent->flags.subtype) {
		return decode_dns_labels(ctx, out, parent, data, data_len, decode_ctx);
	}
#endif

	if (parent->flags.array) return decode_array(ctx, out, parent, data, data_len, decode_ctx);

	return decode_value(ctx, out, parent, data, data_len, decode_ctx, true);
}

/*
 *	Decode ONE value into a VP
 */
static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *da,
			    uint8_t const *data, size_t data_len, UNUSED void *decode_ctx, bool exact)
{
	fr_pair_t *vp;
	uint8_t const *p = data;
	uint8_t const *end = data + data_len;

	FR_PROTO_TRACE("%s called to parse %zu bytes", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(data, data_len, NULL);

	/*
	 *	Structs create their own VP wrapper.
	 */
	if (da->type == FR_TYPE_STRUCT) {
		ssize_t slen;

		slen = fr_struct_from_network(ctx, out, da, data, data_len, true,
					      decode_ctx, decode_value_trampoline, decode_tlv);
		if (slen < 0) return slen;

		return data_len;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return -1;

	/*
	 *	string / octets / bool can be empty.  Other data types are
	 *	incorrect if they're empty.
	 */
	if (data_len == 0) {
		if (da->type == FR_TYPE_BOOL) {
			vp->vp_bool = true;
			goto finish;
		}

		if (!((da->type == FR_TYPE_OCTETS) || (da->type == FR_TYPE_STRING))) goto raw;
		goto finish;
	}

	/*
	 *	Unknown attributes always get converted to
	 *	octet types, so there's no way there could
	 *	be multiple attributes, so its safe to
	 *	steal the unknown attribute into the context
	 *	of the pair.
	 *
	 *	Note that we *cannot* do talloc_steal here, because
	 *	this function is called in a loop from decode_array().
	 *	And we cannot steal the same da into multiple parent
	 *	VPs.  As a result, we have to copy it, and rely in the
	 *	caller to clean up the unknown da.
	 */
	if (da->flags.is_unknown) {
		fr_pair_reinit_from_da(NULL, vp, fr_dict_unknown_attr_afrom_da(vp, da));
		da = vp->da;
	}

	switch (vp->da->type) {
	/*
	 *	Doesn't include scope, whereas the generic format can
	 */
	case FR_TYPE_IPV6_ADDR:
		if ((size_t) (end - p) < sizeof(vp->vp_ipv6addr)) goto raw;

		if (exact && ((size_t) (end - p) > sizeof(vp->vp_ipv6addr))) goto raw;

		memcpy(&vp->vp_ipv6addr, p, sizeof(vp->vp_ipv6addr));
		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = 128;
		vp->vp_tainted = true;
		p += sizeof(vp->vp_ipv6addr);
		break;

	case FR_TYPE_IPV6_PREFIX:
		if ((size_t) (end - (p + 1)) < sizeof(vp->vp_ipv6addr)) goto raw;

		if (exact && ((size_t) (end - p) > sizeof(vp->vp_ipv6addr))) goto raw;

		memcpy(&vp->vp_ipv6addr, p + 1, sizeof(vp->vp_ipv6addr));
		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = p[0];
		vp->vp_tainted = true;
		p += sizeof(vp->vp_ipv6addr) + 1;
		break;

	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("Cannot decode type '%s' as value", fr_type_to_str(vp->da->type));
		talloc_free(vp);
		return 0;

	default:
	{
		ssize_t ret;

		ret = fr_value_box_from_network(vp, &vp->data, vp->da->type, da,
						&FR_DBUFF_TMP(p, end - p), end - p, true);
		if (ret < 0) {
		raw:
			FR_PROTO_TRACE("decoding as unknown type");
			if (fr_pair_to_unknown(vp) < 0) return -1;
			fr_pair_value_memdup(vp, p, end - p, true);
			p = end;
			break;
		}

		if (exact && (ret != (end - p))) {
			talloc_free(vp);
			goto raw;
		}

		p += (size_t) ret;
	}
	}

finish:
	FR_PROTO_TRACE("decoding value complete, adding new pair and returning %zu byte(s)", p - data);
	fr_pair_append(out, vp);

	return p - data;
}

static ssize_t decode_raw(TALLOC_CTX *ctx, fr_pair_list_t *out,
			  fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	fr_pair_t		*vp;
	fr_dict_attr_t		*unknown;
	fr_dict_attr_t const	*da;
	fr_dhcpv4_ctx_t		*packet_ctx = decode_ctx;
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

	vp->vp_tainted = true;
	fr_pair_append(out, vp);
	return data_len;
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
 * Vendor-Specific-Information with raw octets contents.
 */

/** Decode DHCP suboptions
 *
 * @param[in] ctx		context to alloc new attributes in.
 * @param[out] out		Where to write the decoded options.
 * @param[in] parent		of sub TLVs.
 * @param[in] data		to parse.
 * @param[in] data_len		of the data to parse
 * @return
 *	<= 0 on error
 *	data_len on success.
 */
static ssize_t decode_tlv(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t data_len, void *decode_ctx)
{
	uint8_t const		*p = data;
	uint8_t const		*end = data + data_len;

	/*
	 *	Type, length, data.  If that doesn't exist, we decode
	 *	the data as "raw" in the parents context/
	 */
	if (data_len < 3) {
		fr_pair_t *vp;

		vp = fr_raw_from_network(ctx, parent, data, data_len);
		if (!vp) return -1;
		fr_pair_append(out, vp);
		return data_len;
	}

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);
	FR_PROTO_HEX_DUMP(data, data_len, NULL);

	/*
	 *	Each TLV may contain multiple children
	 */
	while (p < end) {
		ssize_t slen;

		/*
		 *	RFC 3046 is very specific about not allowing termination
		 *	with a 255 sub-option. But it's required for decoding
		 *	option 43, and vendors will probably screw it up
		 *	anyway.
		 *
		 *	Similarly, option 0 is sometimes treated as
		 *	"end of options".
		 */
		if ((p[0] == 0) || (p[0] == 255)) {
			if ((p + 1) == end) return data_len;

			/*
			 *	There's stuff after the "end of
			 *	options" option.  Return it as random crap.
			 */
		raw:
			/*
			 *	@todo - the "goto raw" can leave partially decoded VPs in the output.  we'll
			 *	need a temporary cursor / pair_list to fix that.
			 */
			slen = decode_raw(ctx, out, parent, p, end - p, decode_ctx);
			if (slen < 0) return slen - (p - data);

			return data_len;
		}

		/*
		 *      Everything else should be real options
		 */
		if ((end - p) < 2) goto raw;

		if ((p[1] + 2) > (end - p)) goto raw;

		slen = decode_option(ctx, out, parent, p, p[1] + 2, decode_ctx);
		if (slen <= 0) {
			return slen - (p - data);
		}
		fr_assert(slen <= (2 + p[1]));

		p += 2 + p[1];
		FR_PROTO_TRACE("remaining TLV data %zu byte(s)" , end - p);
	}
	FR_PROTO_TRACE("tlv parsing complete, returning %zu byte(s)", p - data);

	return data_len;
}

static ssize_t decode_array(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decode_ctx)
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
	element_len = fr_dhcpv4_attr_sizes[parent->type][0];
	if (!element_len) element_len = parent->flags.length;

	if (element_len > 0) {
		size_t num_elements = (end - p) / element_len;

		FR_PROTO_TRACE("decode_array %zu input expected %zd total (%zu elements * %zu size)",
			       (size_t) (end - p), num_elements * element_len, num_elements, element_len);

		if ((num_elements * element_len) != (size_t) (end - p)) {
		raw:
			slen = decode_raw(ctx, out, parent, p, end - p , decode_ctx);
			if (slen < 0) return slen;
			return data_len;
		}

		while (p < end) {
			/*
			 *	Not enough room for one more element,
			 *	decode the last bit as raw data.
			 */
			if ((size_t) (end - p) < element_len) goto raw;

			slen = decode_value(ctx, out, parent, p, element_len, decode_ctx, false);
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
	 *	Note that we don't bother checking if the data type is
	 *	string or octets.  There will only be issues if
	 *	someone edited the dictionaries and broke them.
	 */
	while (p < end) {
		if ((end - p) < 1) goto raw;

		element_len = *p;

		if ((size_t) (end - p) < (((size_t) element_len) + 1)) goto raw;

		p += 1;
		slen = decode_value(ctx, out, parent, p, element_len, decode_ctx, false);
		if (slen < 0) return slen;
		p += slen;
	}

	return data_len;
}

/*
 *  One VSA option may contain multiple vendors, each vendor
 *  may contain one or more sub-options.
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  option-code  |  option-len   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      enterprise-number1       |
 *  |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   data-len1   |               |
 *  +-+-+-+-+-+-+-+-+ option-data1  |
 *  /                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 *  |      enterprise-number2       |   ^
 *  |                               |   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
 *  |   data-len2   |               | optional
 *  +-+-+-+-+-+-+-+-+ option-data2  |   |
 *  /                               /   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
 *  ~            ...                ~   V
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 */
static ssize_t decode_vsa(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t			len;
	uint8_t			option_len;
	uint32_t		pen;
	fr_dict_attr_t const	*vendor;
	uint8_t const		*end = data + data_len;
	uint8_t const		*p = data;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_vsa");

	if (!fr_cond_assert_msg(parent->type == FR_TYPE_VSA,
				"%s: Internal sanity check failed, attribute \"%s\" is not of type 'vsa'",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

next:
	/*
	 *	We need at least 4 (PEN) + 1 (data-len) + 1 (vendor option num)
	 *	to be able to decode vendor specific
	 *	attributes.
	 */
	if ((size_t)(end - p) < (sizeof(uint32_t) + 1 + 1)) {
		len = decode_raw(ctx, out, parent, p, end - p, decode_ctx);
		if (len < 0) return len;

		return data_len + 2; /* decoded the whole thing */
	}

	pen = fr_net_to_uint32(p);

	/*
	 *	Verify that the parent (which should be a VSA)
	 *	contains a fake attribute representing the vendor.
	 *
	 *	If it doesn't then this vendor is unknown, but we know
	 *	vendor attributes have a standard format, so we can
	 *	decode the data anyway.
	 */
	vendor = fr_dict_attr_child_by_num(parent, pen);
	if (!vendor) {
		fr_dict_attr_t *n;

		n = fr_dict_unknown_vendor_afrom_num(ctx, parent, pen);
		if (!n) return PAIR_DECODE_OOM;
		vendor = n;
	}
	p += sizeof(uint32_t);

	FR_PROTO_TRACE("decode context %s -> %s", parent->name, vendor->name);

	option_len = p[0];
	if ((p + 1 + option_len) > end) {
		len = decode_raw(ctx, out, vendor, p, end - p, decode_ctx);
		if (len < 0) return len;

		return data_len + 2; /* decoded the whole thing */
	}
	p++;

	len = decode_tlv(ctx, out, vendor, p, option_len, decode_ctx);
	if (len <= 0) return len;

	p += len;
	if (p < end) goto next;

	/*
	 *	Tell the caller we read all of it, even if we didn't.
	 */
	return data_len + 2;
}


static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	unsigned int   		option;
	size_t			len;
	ssize_t			slen;
	fr_dict_attr_t const	*da;
	fr_dhcpv4_ctx_t		*packet_ctx = decode_ctx;

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return PAIR_DECODE_FATAL_ERROR;
#endif

	fr_assert(parent != NULL);

	/*
	 *	Must have at least an option header.
	 */
	if (data_len < 2) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -(data_len);
	}

	option = data[0];
	len = data[1];
	if (len > (data_len - 2)) {
		fr_strerror_printf("%s: Option overflows input.  "
				   "Optional length must be less than %zu bytes, got %zu bytes",
				   __FUNCTION__, data_len - 2, len);
		return PAIR_DECODE_FATAL_ERROR;
	}

	da = fr_dict_attr_child_by_num(parent, option);
	if (!da) {
		da = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, option);
		if (!da) return PAIR_DECODE_FATAL_ERROR;
	}
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

#if 0
	if ((da->type == FR_TYPE_STRING) && !da->flags.extra && da->flags.subtype) {
		fr_pair_list_t tmp;

		fr_pair_list_init(&tmp);

		slen = decode_dns_labels(ctx, &tmp, da, data + 2, len, decode_ctx);
		if (slen < 0) goto raw;

		/*
		 *	The DNS labels may only partially fill the
		 *	option.  If so, then it's a decode error.
		 */
		if ((size_t) slen != len) {
			fr_pair_list_free(&tmp);
			goto raw;
		}

		fr_pair_list_append(out, &tmp);

	} else
#endif
	if (da->flags.array) {
		slen = decode_array(ctx, out, da, data + 2, len, decode_ctx);

	} else if (da->type == FR_TYPE_VSA) {
		slen = decode_vsa(ctx, out, da, data + 2, len, decode_ctx);

	} else if (da->type == FR_TYPE_TLV) {
		slen = decode_tlv(ctx, out, da, data + 2, len, decode_ctx);

	} else {
		slen = decode_value(ctx, out, da, data + 2, len, decode_ctx, true);
	}

	if (slen < 0) {
		slen = decode_raw(ctx, out, da, data + 2, len, decode_ctx);
		if (slen <= 0) return slen;
	}

	return len + 2;
}

/** Decode DHCP option
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[out] out		Where to write the decoded options.
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] decode_ctx	Unused.
 */
ssize_t fr_dhcpv4_decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			        uint8_t const *data, size_t data_len, void *decode_ctx)
{
	ssize_t			slen;
	uint8_t const		*p = data, *end = data + data_len;
	uint8_t const		*next;
	fr_dhcpv4_ctx_t		*packet_ctx = decode_ctx;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);

	if (data_len == 0) return 0;

	FR_PROTO_HEX_DUMP(data, data_len, NULL);

	/*
	 *	Padding / End of options
	 */
	if (p[0] == 0) return data_len;		/* 0x00 - Padding option */
	if (p[0] == 255) return data_len;	/* 0xff - End of options signifier */

	/*
	 *	Everything else should be real options
	 */
	if ((data_len < 2) || ((size_t) (data[1] + 2) > data_len)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	/*
	 *	Check for multiple options of the same type, and concatenate their values together.
	 *
	 *	RFC 2131 Section 4.1 says:
	 *
	 *	  The client concatenates the values of multiple
	 *	  instances of the same option into a single parameter
	 *	  list for configuration.
	 *
	 *	which presumably also means the same for the server on reception.
	 *
	 *	We therefore peek ahead, and concatenate the values into a temporary buffer.  The buffer is
	 *	allocated only if necessary, and is re-used for the entire packet.
	 *
	 *	If the options are *not* consecutive, then we don't concatenate them.  Too bad for you!
	 *
	 *	Note that we don't (yet) do this for TLVs.
	 */
	next = data + 2 + data[1];
	if ((data[1] > 0) && (next < end) && (next[0] == data[0])) {
		uint8_t *q;
		fr_dict_attr_t const *da;

		if (!packet_ctx->buffer) {
			packet_ctx->buffer = talloc_array(packet_ctx, uint8_t, data_len);
			if (!packet_ctx->buffer) return -1;

		} else if (talloc_array_length(packet_ctx->buffer) < data_len) {
			/*
			 *	We're called in a loop from fr_dhcpv4_decode(), with the full packet, so the
			 *	needed size should only go down as we decode the packet.
			 */
			return -1;
		}
		q = packet_ctx->buffer;

		for (next = data; next < end; next += 2 + next[1]) {
			if ((end - next) < 2) return -1;
			if (next[0] != data[0]) break;
			if ((next + 2 + next[1]) > end) return -1;

			memcpy(q, next + 2, next[1]);
			q += next[1];
		}

		da = fr_dict_attr_child_by_num(fr_dict_root(dict_dhcpv4), p[0]);
		if (!da) {
			da = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, fr_dict_root(dict_dhcpv4), p[0]);
			if (!da) return -1;

			slen = decode_raw(ctx, out, da, packet_ctx->buffer, q - packet_ctx->buffer, packet_ctx);

		} else if (da->type == FR_TYPE_VSA) {
			slen = decode_vsa(ctx, out, da, packet_ctx->buffer, q - packet_ctx->buffer, packet_ctx);

		} else if (da->type == FR_TYPE_TLV) {
			slen = decode_tlv(ctx, out, da, packet_ctx->buffer, q - packet_ctx->buffer, packet_ctx);

		} else if (da->flags.array) {
			slen = decode_array(ctx, out, da, packet_ctx->buffer, q - packet_ctx->buffer, packet_ctx);

		} else {
			slen = decode_value(ctx, out, da, packet_ctx->buffer, q - packet_ctx->buffer, packet_ctx, true);
		}
		if (slen <= 0) return slen;

		/*
		 *	The actual amount of data we decoded, including the various headers.
		 */
		FR_PROTO_TRACE("decoding option complete, %zu decoded, returning %zu byte(s)", slen, (size_t) (next - data));
		return next - data;
	}

	slen = decode_option(ctx, out, fr_dict_root(dict_dhcpv4), data, data[1] + 2, decode_ctx);
	if (slen < 0) return slen;

	FR_PROTO_TRACE("decoding option complete, %zu decoded, returning %u byte(s)", slen, data[1] + 2);
	return data[1] + 2;
}

static int _decode_test_ctx(UNUSED fr_dhcpv4_ctx_t *test_ctx)
{
	fr_dhcpv4_global_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_dhcpv4_ctx_t *test_ctx;

	if (fr_dhcpv4_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_dhcpv4_ctx_t);
	talloc_set_destructor(test_ctx, _decode_test_ctx);
	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}


static ssize_t fr_dhcpv4_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
				      uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	unsigned int	code;

	if (!fr_dhcpv4_ok(data, data_len, NULL, NULL)) return -1;

	if (fr_dhcpv4_decode(ctx, out, data, data_len, &code) < 0) return -1;

	return data_len;
}

static ssize_t decode_option_wrapper(TALLOC_CTX *ctx, fr_pair_list_t *out, NDEBUG_UNUSED fr_dict_attr_t const *parent,
			        uint8_t const *data, size_t data_len, void *decode_ctx)
{
	fr_assert(parent == fr_dict_root(dict_dhcpv4));

	return fr_dhcpv4_decode_option(ctx, out, data, data_len, decode_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dhcpv4_tp_decode_pair;
fr_test_point_pair_decode_t dhcpv4_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_option_wrapper
};

extern fr_test_point_proto_decode_t dhcpv4_tp_decode_proto;
fr_test_point_proto_decode_t dhcpv4_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv4_decode_proto
};
