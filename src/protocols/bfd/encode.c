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
 * @file protocols/bfd/encode.c
 * @brief Functions to encode BFD packets
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/internal/internal.h>

#include "attrs.h"

/** Encodes the data portion of an attribute
 *
 * @return
 *	> 0, Length of the data portion.
 *      = 0, we could not encode anything, skip this attribute (and don't encode the header)
 *	  unless it's one of a list of exceptions.
 *	< 0, How many additional bytes we'd need as a negative integer.
 *	PAIR_ENCODE_FATAL_ERROR - Abort encoding the packet.
 */
static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
//	fr_bfd_ctx_t		*packet_ctx = encode_ctx;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	PAIR_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	This has special requirements.
	 */
	if ((vp->vp_type == FR_TYPE_STRUCT) || (da->type == FR_TYPE_STRUCT)) {
		slen = fr_struct_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_value, NULL);
		goto done;
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

	if (fr_type_is_structural(da->type)) {
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_type_to_str(da_stack->da[depth]->type));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	slen = fr_value_box_to_network(&work_dbuff, &vp->data);

done:
	if (slen < 0) return slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "%pP", vp);

	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode VPS into a BFD packet.
 *
 */
ssize_t fr_bfd_encode(uint8_t *out, size_t outlen, UNUSED uint8_t const *original,
		      char const *secret, size_t secret_len, fr_pair_list_t *vps)
{
	ssize_t			slen;
	fr_bfd_ctx_t		packet_ctx;
	bfd_packet_t		*packet;
	fr_dcursor_t		cursor;
	fr_dbuff_t		work_dbuff = FR_DBUFF_TMP(out, outlen);
	fr_da_stack_t		da_stack;

	if (!fr_pair_dcursor_by_ancestor_init(&cursor, vps, attr_bfd_packet)) {
		fr_strerror_const("No BFD attributes found in the list");
		return -1;
	}

	packet_ctx.secret = secret;

	fr_proto_da_stack_build(&da_stack, attr_bfd_packet);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	slen = fr_struct_to_network(&work_dbuff, &da_stack, 0, &cursor, &packet_ctx, encode_value, NULL);
	if (slen < 0) return slen;

	/*
	 *	The length is only 8 bits.  :(
	 */
	if (slen > UINT8_MAX) {
		fr_strerror_const("Packet is larger than 255 octets");
		return -1;
	}

	/*
	 *	For various reasons the base BFD struct has "auth-type" as the last MEMBER, even if it's not
	 *	always used.  The struct encoder will fill it in with zeros, so we have to check for
	 *	"auth_present" and then remove the last byte if there's no authentication stuff present.
	 */
	packet = (bfd_packet_t *) out;

	if (!packet->auth_present) {
		if (slen > FR_BFD_HEADER_LENGTH) slen = FR_BFD_HEADER_LENGTH;

	} else if (!secret || secret_len == 0) {
		fr_strerror_const("Cannot sign packets without a secret");
		return -1;

	} else {

#if 0
		/*
		 *	@todo - sign the packet with the chosen auth type
		 */
		if (fr_bfd_sign(data, NULL, (uint8_t const *) secret, secret_len - 1) < 0) {
			return -1;
		}
#endif
	}

	packet->length = slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), slen, "BFD Packet");

	return slen;
}


static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict)
{
	fr_bfd_ctx_t	*test_ctx;

	test_ctx = talloc_zero(ctx, fr_bfd_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->secret = talloc_strdup(test_ctx, "testing123");

	*out = test_ctx;

	return 0;
}

static ssize_t fr_bfd_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, void *proto_ctx)
{
	fr_bfd_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_bfd_ctx_t);
	ssize_t		slen, alen;
	fr_pair_t	*vp;
	fr_dbuff_t	dbuff;

	/*
	 *	@todo - pass in test_ctx to this function, so that we
	 *	can leverage a consistent random number generator.
	 */
	slen = fr_bfd_encode(data, data_len, NULL, test_ctx->secret, talloc_array_length(test_ctx->secret) - 1, vps);
	if (slen <= 0) return slen;

	vp = fr_pair_find_by_da(vps, NULL, attr_bfd_additional_data);
	if (!vp) return slen;

	fr_dbuff_init(&dbuff, data + slen, data_len - slen);
	alen = fr_internal_encode_list(&dbuff, &vp->vp_group, NULL);
	if (alen <= 0) return slen;

	return slen + alen;
}

/*
 *	No one else should be using this.
 */
extern void *fr_bfd_next_encodable(fr_dlist_head_t *list, void *to_eval, void *uctx);

/*
 *	Test points
 */
extern fr_test_point_proto_encode_t bfd_tp_encode_proto;
fr_test_point_proto_encode_t bfd_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_bfd_encode_proto
};
