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
 * @file protocols/bfd/decode.c
 * @brief Functions to decode BFD packets
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

#include "attrs.h"

static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, UNUSED void *decode_ctx)
{
	ssize_t slen;
	fr_pair_t *vp;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_value");

	vp = fr_pair_afrom_da(ctx, parent);
	if (!vp) return PAIR_DECODE_OOM;

	slen =  fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					  &FR_DBUFF_TMP(data, data_len), data_len, true);
	if (slen < 0) {
		talloc_free(vp);
		return slen;
	}

	fr_assert(vp != NULL);

	vp->vp_tainted = true;
	fr_pair_append(out, vp);

	return data_len;
}


/** Decode a raw BFD packet into VPs.
 *
 */
ssize_t fr_bfd_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
		      uint8_t const *packet, size_t packet_len,
		      char const *secret, UNUSED size_t secret_len)
{
	ssize_t			slen;
	fr_bfd_ctx_t		packet_ctx;

	packet_ctx.secret = secret;

	slen = fr_struct_from_network(ctx, out, attr_bfd_packet, packet, packet_len, true,
				      &packet_ctx, decode_value, NULL);
	if (slen < 0) return slen;

	return slen;
}

static int _test_ctx_free(UNUSED fr_bfd_ctx_t *ctx)
{
	fr_bfd_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_bfd_ctx_t	*test_ctx;

	if (fr_bfd_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_bfd_ctx_t);
	test_ctx->secret = talloc_strdup(test_ctx, "testing123");
	test_ctx->tmp_ctx = talloc_zero(test_ctx, uint8_t);
	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_bfd_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
				   uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_pair_t	*vp;
	bfd_packet_t const *packet;
	fr_bfd_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_bfd_ctx_t);

	if (data_len < FR_BFD_HEADER_LENGTH) {
		fr_strerror_const("Packet is too small for BFD");
		return -1;
	}

	packet = (bfd_packet_t const *) data;

	if (packet->length > data_len) {
		fr_strerror_const("Packet.lenth is larger than received data");
		return -1;
	}

	/*
	 *	Get the packet type.
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) {
		fr_strerror_const("Failed creating Packet-Type");
		return -1;
	}

	vp->vp_uint32 = packet->state;
	fr_pair_append(out, vp);

#if 0
	/*
	 *	We always decode the packet as a nested VP.
	 */
	vp = fr_pair_afrom_da(ctx, attr_bfd_packet);
	if (!vp) {
		fr_strerror_const("Failed creating Packet");
		return -1;
	}
	fr_pair_append(out, vp);
#endif

	/* coverity[tainted_data] */
	return fr_bfd_decode(ctx, out, data, data_len,
			     test_ctx->secret, talloc_array_length(test_ctx->secret) - 1);
}

/*
 *	Test points
 */
extern fr_test_point_proto_decode_t bfd_tp_decode_proto;
fr_test_point_proto_decode_t bfd_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_bfd_decode_proto
};
