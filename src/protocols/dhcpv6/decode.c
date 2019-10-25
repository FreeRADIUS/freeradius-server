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
 * @copyright 2018 NetworkRADIUS SARL (info@networkradius.com)
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/io/test_point.h>

#include "dhcpv6.h"
#include "attrs.h"

typedef struct {
	TALLOC_CTX		*tmp_ctx;		//!< for temporary things cleaned up during decoding
} fr_dhcpv6_decode_ctx_t;

static ssize_t decode_raw(TALLOC_CTX *ctx, fr_cursor_t *cursor, UNUSED fr_dict_t const *dict,
			  fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t const data_len, void *decoder_ctx)
{
	VALUE_PAIR		*vp;
	fr_dict_attr_t const	*da;
	fr_dhcpv6_decode_ctx_t	*packet_ctx = decoder_ctx;

	/*
	 *	Re-write the attribute to be "raw".  It is
	 *	therefore of type "octets", and will be
	 *	handled below.
	 */
	da = fr_dict_unknown_afrom_fields(packet_ctx->tmp_ctx, parent->parent,
					  fr_dict_vendor_num_by_da(parent), parent->attr);
	if (!da) {
		fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return -1;

	if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, data, data_len, true) < 0) {
		fr_pair_list_free(&vp);
		fr_dict_unknown_free(&da);
		return -1;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_cursor_append(cursor, vp);
	return data_len;
}


static ssize_t decode_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decoder_ctx)
{
	VALUE_PAIR		*vp;

	switch (parent->type) {
	default:
	raw:
		return decode_raw(ctx, cursor, dict, parent, data, data_len, decoder_ctx);

	case FR_TYPE_FIXED_SIZE:
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return -1;

		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, data, data_len, true) < 0) {
			fr_pair_list_free(&vp);
			goto raw;
		}
		break;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_cursor_append(cursor, vp);
	return data_len;
}


static ssize_t decode_array(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				 fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t const data_len, void *decoder_ctx)
{
	uint8_t const  		*p = data, *end = p + data_len;
	ssize_t			slen;
	size_t			element_len;

	if (!fr_cond_assert_msg(parent->flags.array,
				"%s: Internal sanity check failed, attribute \"%s\" does not have array bit set",
				__FUNCTION__, parent->name)) return PAIR_ENCODE_ERROR;

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
				slen = decode_raw(ctx, cursor, dict, parent, p, end - p , decoder_ctx);
				if (slen < 0) return slen;
				break;
			}

			slen = decode_value(ctx, cursor, dict, parent, p, element_len, decoder_ctx);
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
		if ((end - p) <= 2) {
		raw:
			slen = decode_raw(ctx, cursor, dict, parent, p, end - p , decoder_ctx);
			if (slen < 0) return slen;
			
			p += slen;
			break;
		}

		element_len = (p[0] << 8) | p[1];
		if ((p + 2 + element_len) > end) {
			goto raw;
		}

		p += 2;
		slen = decode_value(ctx, cursor, dict, parent, p, element_len , decoder_ctx);
		if (slen < 0) return slen;
		p += slen;		
	}

	return data_len;
}

static ssize_t decode_dns_labels(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				 fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t const data_len, void *decoder_ctx)
{
	ssize_t rcode;
	size_t total;
	VALUE_PAIR *vp;
	uint8_t const *next;

	/*
	 *	This function handles both single-valued and array
	 *	types.  It's just easier that way.
	 */
	if (!parent->flags.array) {
		rcode = fr_dns_label_length(data, data_len, &next);
		if (rcode < 0) goto raw;

		/*
		 *	If the DNS label doesn't exactly fill the option, it's an error.
		 */
		if (next != (data + data_len)) goto raw;

	} else {
		/*
		 *	If any one of the labels are invalid, then treat the
		 *	entire set as invalid.
		 */
		rcode = fr_dns_labels_network_verify(data, data_len);
		if (rcode < 0) {
		raw:
			return decode_raw(ctx, cursor, dict, parent, data, data_len, decoder_ctx);
		}
	}

	/*
	 *	Loop over the input buffer, decoding the labels one by
	 *	one.
	 */
	for (total = 0; total < data_len; total += rcode) {
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return -1;

		/*
		 *	Having verified the input above, this next
		 *	function should never fail unless there's a
		 *	bug in the code.
		 */
		rcode = fr_dns_label_to_value_box(vp, &vp->data, data, data_len, data + total, true);
		if (rcode < 0) {
			fr_pair_list_free(&vp);
			goto raw;
		}

		vp->type = VT_DATA;
		fr_cursor_append(cursor, vp);
	}

	return data_len;
}


/** Create a "normal" VALUE_PAIR from the given data
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          option-code          |           option-len          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static ssize_t fr_dhcpv6_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				     uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	unsigned int   		option;
	size_t			len;
	ssize_t			rcode;
	fr_dict_attr_t const	*da;
	fr_dhcpv6_decode_ctx_t	*packet_ctx = decoder_ctx;

	/*
	 *	Must have at least an option header.
	 */
	if (data_len < 4) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return -1;
#endif

	option = (data[0] << 8) | data[1];
	len = (data[2] << 8) | data[3];
	if ((len + 4) > data_len) {
		fr_strerror_printf("%s: Option overflows input", __FUNCTION__);
		return -1;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict), option);
	if (!da) {
		FR_PROTO_TRACE("Unknown attribute %u", option);
		da = fr_dict_unknown_afrom_fields(packet_ctx->tmp_ctx, fr_dict_root(dict), 0, option);
	}
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	if ((da->type == FR_TYPE_STRING) && da->flags.subtype) {
		rcode = decode_dns_labels(ctx, cursor, dict, da, data + 4, len, decoder_ctx);
	} else if (da->flags.array) {
		rcode = decode_array(ctx, cursor, dict, da, data + 4, len, decoder_ctx);
	} else {
		rcode = decode_value(ctx, cursor, dict, da, data + 4, len, decoder_ctx);
	}
	if (rcode < 0) return rcode;

	return data_len;
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

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dhcpv6_tp_decode_pair;
fr_test_point_pair_decode_t dhcpv6_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv6_decode_pair
};
