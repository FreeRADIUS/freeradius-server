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
#include <freeradius-devel/io/test_point.h>

#include "dhcpv6.h"
#include "attrs.h"


typedef struct {
	uint8_t		stuff;	/* TBD */
} fr_dhcpv6_decode_ctx_t;


/** Create a "normal" VALUE_PAIR from the given data
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          option-code          |           option-len          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static ssize_t fr_dhcpv6_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				     uint8_t const *data, size_t data_len, UNUSED void *decoder_ctx)
{
	unsigned int   		option;
	size_t			len;
	fr_dict_attr_t const	*da;
	VALUE_PAIR		*vp;

	/*
	 *	Must have at least an option header.
	 */
	if (data_len < 4) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	option = (data[0] << 8) | data[1];
	len = (data[2] << 8) | data[3];
	if ((len + 4) > data_len) {
		fr_strerror_printf("%s: Option overflows input", __FUNCTION__);
		return -1;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict), option);
	if (!da) {
		FR_PROTO_TRACE("Unknown attribute %u", option);
		da = fr_dict_unknown_afrom_fields(ctx, fr_dict_root(dict), 0, option);
	}
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	switch (da->type) {
	default:
	raw:

#ifdef __clang_analyzer__
		if (!ctx || !da->parent) return -1;
#endif

		/*
		 *	Re-write the attribute to be "raw".  It is
		 *	therefore of type "octets", and will be
		 *	handled below.
		 */
		da = fr_dict_unknown_afrom_fields(ctx, da->parent,
						      fr_dict_vendor_num_by_da(da), da->attr);
		if (!da) {
			fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
			return -1;
		}
#ifndef NDEBUG
		/*
		 *	Fix for Coverity.
		 */
		if (da->type != FR_TYPE_OCTETS) {
			fr_dict_unknown_free(&da);
			return -1;
		}
#endif
		/* FALL-THROUGH */

	case FR_TYPE_FIXED_SIZE:
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) return -1;

		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, data + 4, len, true) < 0) {
			/*
			 *	Paranoid loop prevention
			 */
			if (vp->da->flags.is_unknown) {
				talloc_free(vp);
				return -1;
			}
			goto raw;
		}
		break;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_cursor_append(cursor, vp);

	return len + 4;
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

	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dhcpv6_tp_decode;
fr_test_point_pair_decode_t dhcpv6_tp_decode = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dhcpv6_decode_pair
};
