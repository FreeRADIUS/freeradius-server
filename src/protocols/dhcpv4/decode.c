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
#include <freeradius-devel/util/dns.h>

#include "dhcpv4.h"
#include "attrs.h"

static _Thread_local uint8_t	concat_buffer[1500]; /* ethernet max */

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx);

static bool verify_tlvs(uint8_t const *data, size_t data_len)
{
	uint8_t const *p = data;
	uint8_t const *end = data + data_len;

	while (p < end) {
		if ((end - p) < 2) return false;

		if ((p + 2 + p[1]) > end) return false;

		p += 2 + p[1];
	}

	return true;
}

static ssize_t decode_tlv_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	return fr_pair_tlvs_from_network(ctx, out, parent, data, data_len, decode_ctx, decode_option, verify_tlvs, true);
}

static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decode_ctx);

/** Handle arrays of DNS labels for fr_struct_from_network()
 *
 */
static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				       fr_dict_attr_t const *parent,
				       uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	FR_PROTO_TRACE("decode_value_trampoline of %s with %zu bytes", parent->name, data_len);

	/*
	 *	@todo - we might need to limit this to only one DNS label.
	 */
	if ((parent->type == FR_TYPE_STRING) && fr_dhcpv4_flag_dns_label(parent)) {
		return fr_pair_dns_labels_from_network(ctx, out, parent, data, data, data_len, NULL, false);
	}

	return decode_value(ctx, out, parent, data, data_len, decode_ctx);
}

/*
 *	Decode ONE value into a VP
 */
static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *da,
			    uint8_t const *data, size_t data_len, void *decode_ctx)
{
	ssize_t slen;
	fr_pair_t *vp;
	uint8_t const *p = data;
	uint8_t const *end = data + data_len;
	bool exact = !da->flags.array;

	FR_PROTO_TRACE("%s called to parse %zu bytes from %s", __FUNCTION__, data_len, da->name);
	FR_PROTO_HEX_DUMP(data, data_len, NULL);

	/*
	 *	Structs create their own VP wrapper.
	 */
	if (da->type == FR_TYPE_STRUCT) {
		slen = fr_struct_from_network(ctx, out, da, data, data_len,
					      decode_ctx, decode_value_trampoline, decode_tlv_trampoline);
		if (slen < 0) return slen;

		if (!exact) return slen;

		return data_len;
	}

	/*
	 *	These are always raw.
	 */
	if (da->flags.is_unknown) {
		return fr_pair_raw_from_network(ctx, out, da, data, data_len);
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return PAIR_DECODE_OOM;
	PAIR_ALLOCED(vp);

	/*
	 *	string / octets / bool can be empty.  Other data types are
	 *	raw if they're empty.
	 */
	if (data_len == 0) {
		if (da->type == FR_TYPE_BOOL) {
			vp->vp_bool = true;
			goto finish;
		}

		if ((da->type == FR_TYPE_OCTETS) || (da->type == FR_TYPE_STRING)) {
			goto finish;
		}

		talloc_free(vp);
		return fr_pair_raw_from_network(ctx, out, da, data, 0);
	}

	switch (vp->vp_type) {
	case FR_TYPE_ATTR:
		/*
		 *	Force the length of the data to be one,
		 *	otherwise the "from network" call complains.
		 *	Because we pass in the enumv as the _parent_
		 *	and not the da.  The da is marked as "array",
		 *	but the parent is not.
		 */
		end = p + 1;

		fr_assert(da->parent->flags.is_root);

		slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, da->parent,
						 &FR_DBUFF_TMP(p, end - p), end - p, true);
		if (slen <= 0) goto raw;

		p++;
		break;

	/*
	 *	Doesn't include scope, whereas the generic format can.
	 */
	case FR_TYPE_IPV6_ADDR:
		slen = fr_value_box_ipaddr_from_network(&vp->data, da->type, da,
							128, p, (size_t) (end - p),
							exact, true);
		if (slen < 0) goto raw;
		fr_assert(slen == sizeof(vp->vp_ipv6addr));

		p += sizeof(vp->vp_ipv6addr);
		break;

	case FR_TYPE_IPV6_PREFIX:
		/*
		 *	Not enough room for the prefix length, that's an issue.
		 *
		 *	Note that there's actually no standard for IPv6 prefixes inside of DHCPv4.
		 */
		if ((end - p) < 1) goto raw;

		slen = fr_value_box_ipaddr_from_network(&vp->data, da->type, da,
							p[0], p + 1, ((size_t) (end - p)) - 1,
							exact, true);
		if (slen < 0) goto raw;

		p += slen + 1;
		break;

	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("Cannot decode type '%s' as value", fr_type_to_str(vp->vp_type));
		talloc_free(vp);
		return 0;

	case FR_TYPE_IPV4_PREFIX:
		fr_value_box_init(&vp->data, FR_TYPE_IPV4_PREFIX, vp->da, true);
		vp->vp_ip.af = AF_INET;

		/*
		 *	4 octets of address
		 *	4 octets of mask
		 */
		if (fr_dhcpv4_flag_prefix_split(da)) {
			uint32_t ipaddr, mask;

			if (data_len < 8) goto raw;

			ipaddr = fr_nbo_to_uint32(p);
			mask = fr_nbo_to_uint32(p + 4);
			p += 8;

			/*
			 *	0/0 means a prefix of 0, too.
			 */
			if (!mask) {
				break;
			}

			/*
			 *	Try to figure out the prefix value from the mask.
			 */
			while (mask) {
				vp->vp_ip.prefix++;
				mask <<= 1;
			}

			/*
			 *	Mash the IP based on the calculated mask.  We don't really care if the mask
			 *	has holes, or if the IP address overlaps with the mask.  We just fix it all up
			 *	so it's sane.
			 */
			mask = ~(uint32_t) 0;
			mask <<= (32 - vp->vp_ip.prefix);

			vp->vp_ipv4addr = htonl(ipaddr & mask);
			break;
		}

		if (fr_dhcpv4_flag_prefix_bits(vp->da)) {
			size_t needs;

			if ((data_len == 0) || (*p > 32)) goto raw;

			needs = 1 + ((*p + 0x07) >> 3);
			if (data_len < needs) goto raw;

			/*
			 *	Don't do exact checks here, as the content is variable-sized.
			 */

			vp->vp_ip.prefix = *p;

			/*
			 *	If the IP address is longer than necessary, then only grab the pieces we need.
			 */
			if (vp->vp_ip.prefix) {
				uint32_t ipaddr, mask;

				mask = ~(uint32_t) 0;
				mask <<= (32 - vp->vp_ip.prefix);

				if (*p > 24) {
					ipaddr = fr_nbo_to_uint32(p + 1);

				} else if (*p > 16) {
					ipaddr = fr_nbo_to_uint24(p + 1);
					ipaddr <<= 8;

				} else if (*p > 8) {
					ipaddr = fr_nbo_to_uint16(p + 1);
					ipaddr <<= 16;

				} else { /* 1..8 */
					ipaddr = p[1];
					ipaddr <<= 24;
				}

				vp->vp_ipv4addr = htonl(ipaddr & mask);
			} /* else *p==0, and we leave ipaddr set to zero */

			p += needs;
			break;
		}

		FALL_THROUGH;

	default:
		slen = fr_value_box_from_network(vp, &vp->data, vp->vp_type, da,
						 &FR_DBUFF_TMP(p, end - p), end - p, true);
		if (slen < 0) {
		raw:
			FR_PROTO_TRACE("decoding as unknown type");
			if (fr_pair_raw_afrom_pair(vp, p, (end - p)) < 0) {
				return -1;
			}
			p = end;
			break;
		}

		if (exact && (slen != (end - p))) {
			goto raw;
		}

		p += (size_t) slen;
		break;
	}

finish:
	FR_PROTO_TRACE("decoding value complete, adding new pair and returning %zu byte(s)", (size_t) (p - data));
	fr_pair_append(out, vp);

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
 * Vendor-Specific-Information with raw octets contents.
 */


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
	fr_pair_t		*vp;
	fr_dict_attr_t const	*vendor;
	uint8_t const		*end = data + data_len;
	uint8_t const		*p = data;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_vsa");

	if (!fr_cond_assert_msg(parent->type == FR_TYPE_VSA,
				"%s: Internal sanity check failed, attribute \"%s\" is not of type 'vsa'",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

next:
	/*
	 *	We need at least 4 (PEN) + 1 (data-len) + 1 (vendor option num) to be able to decode vendor
	 *	specific attributes.  If we don't have that, then we return an error.  The caller will free
	 *	the VSA, and create a "raw.VSA" attribute.
	 */
	if ((size_t)(end - p) < (sizeof(uint32_t) + 1 + 1)) {
		return -1;
	}

	pen = fr_nbo_to_uint32(p);

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

		n = fr_dict_attr_unknown_vendor_afrom_num(ctx, parent, pen);
		if (!n) return PAIR_DECODE_OOM;
		vendor = n;
	}
	p += sizeof(uint32_t);

	FR_PROTO_TRACE("decode context %s -> %s", parent->name, vendor->name);

	option_len = p[0];
	if ((p + 1 + option_len) > end) {
		len = fr_pair_raw_from_network(ctx, out, vendor, p, end - p);
		if (len < 0) return len;

		return data_len + 2; /* decoded the whole thing */
	}
	p++;

	/*
	 *	Pathological case of no data.
	 */
	if (option_len == 0) goto next;

	vp = fr_pair_find_by_da(out, NULL, vendor);
	if (!vp) {
		vp = fr_pair_afrom_da(ctx, vendor);
		if (!vp) return PAIR_DECODE_FATAL_ERROR;
		PAIR_ALLOCED(vp);

		fr_pair_append(out, vp);
	}

	len = fr_pair_tlvs_from_network(vp, &vp->vp_group, vendor, p, option_len, decode_ctx, decode_option, verify_tlvs, false);
	if (len < 0) return len;

	p += option_len;
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

#ifdef STATIC_ANALYZER
	if (!packet_ctx || !packet_ctx->tmp_ctx) return PAIR_DECODE_FATAL_ERROR;
#endif

	fr_assert(parent != NULL);

	/*
	 *      RFC 3046 is very specific about not allowing termination
	 *      with a 255 sub-option. But it's required for decoding
	 *      option 43, and vendors will probably screw it up
	 *      anyway.
	 *
	 *      Similarly, option 0 is sometimes treated as
	 *      "end of options".
	 *
	 *	@todo - this check is likely correct only when at the
	 *	dhcpv4 root, OR inside of option 43.  It could be
	 *	argued that it's wrong for all other TLVs.
	 */
	if ((data_len == 1) && ((data[0] == 0) || (data[0] == 255))) return data_len;

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
		da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, option);
		if (!da) return PAIR_DECODE_OOM;

		slen = fr_pair_raw_from_network(ctx, out, da, data + 2, len);

	} else if ((da->type == FR_TYPE_STRING) && fr_dhcpv4_flag_dns_label(da)) {
		slen = fr_pair_dns_labels_from_network(ctx, out, da, data + 2, data + 2, len, NULL, true);

	} else if (da->flags.array) {
		slen = fr_pair_array_from_network(ctx, out, da, data + 2, len, decode_ctx, decode_value);

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

		slen = decode_vsa(vp, &vp->vp_group, da, data + 2, len, decode_ctx);
		if (append) {
			if (slen < 0) {
				TALLOC_FREE(vp);
			} else {
				fr_pair_append(out, vp);
			}
		}

	} else if (da->type == FR_TYPE_TLV) {
		slen = fr_pair_tlvs_from_network(ctx, out, da, data + 2, len, decode_ctx, decode_option, verify_tlvs, true);

	} else {
		slen = decode_value(ctx, out, da, data + 2, len, decode_ctx);
	}

	if (slen < 0) {
		slen = fr_pair_raw_from_network(ctx, out, da, data + 2, len);
		if (slen < 0) return slen;
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
	if (p[0] == 0) {			/* 0x00 - Padding option	  */
		data_len = 1;			/* Walk over any consecutive 0x00 */
		p++;				/* for efficiency		  */
		while ((p < end) && (p[0] == 0)) {
			p++;
			data_len ++;
		}
		return data_len;
	}
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

		q = concat_buffer;

		for (next = data; next < end; next += 2 + next[1]) {
			if (next >= end) return -1;
			if (next[0] != data[0]) break;
			if ((end - next) < 2) return -1;
			if ((next + 2 + next[1]) > end) return -1;

			if ((size_t) (q + next[1] - concat_buffer) > sizeof(concat_buffer)) return -1;

			memcpy(q, next + 2, next[1]);
			q += next[1];
		}

		if (q == concat_buffer) return 0;

		da = fr_dict_attr_child_by_num(packet_ctx->root, p[0]);
		if (!da) {
			da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, packet_ctx->root, p[0]);
			if (!da) return -1;

			slen = fr_pair_raw_from_network(ctx, out, da, concat_buffer, q - concat_buffer);

		} else if (da->type == FR_TYPE_VSA) {
			slen = decode_vsa(ctx, out, da, concat_buffer, q - concat_buffer, packet_ctx);

		} else if (da->type == FR_TYPE_TLV) {
			slen = fr_pair_tlvs_from_network(ctx, out, da, concat_buffer, q - concat_buffer,
							 packet_ctx, decode_option, verify_tlvs, true);

		} else if (da->flags.array) {
			slen = fr_pair_array_from_network(ctx, out, da, concat_buffer, q - concat_buffer, packet_ctx, decode_value);

		} else {
			slen = decode_value(ctx, out, da, concat_buffer, q - concat_buffer, packet_ctx);
		}
		if (slen < 0) return slen;

		/*
		 *	The actual amount of data we decoded, including the various headers.
		 */
		FR_PROTO_TRACE("decoding option complete, %zd decoded, returning %zu byte(s)", slen, (size_t) (next - data));
		return next - data;
	}

	slen = decode_option(ctx, out, packet_ctx->root, data, data[1] + 2, decode_ctx);
	if (slen < 0) return slen;

	FR_PROTO_TRACE("decoding option complete, %zd decoded, returning %u byte(s)", slen, (unsigned int) data[1] + 2);
	return data[1] + 2;
}

ssize_t	fr_dhcpv4_decode_foreign(TALLOC_CTX *ctx, fr_pair_list_t *out,
				 uint8_t const *data, size_t data_len)
{
	ssize_t slen;
	uint8_t const *attr, *end;

	fr_dhcpv4_ctx_t decode_ctx = {
		.root = fr_dict_root(dict_dhcpv4)
	};

	fr_assert(dict_dhcpv4 != NULL);

	decode_ctx.tmp_ctx = talloc(ctx, uint8_t);

	attr = data;
	end = data + data_len;

	while (attr < end) {
		slen = fr_dhcpv4_decode_option(ctx, out, attr, (end - attr), &decode_ctx);
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
			   fr_dict_attr_t const *root_da)
{
	fr_dhcpv4_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_dhcpv4_ctx_t);
	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);
	test_ctx->root = root_da ? root_da : fr_dict_root(dict_dhcpv4);

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
