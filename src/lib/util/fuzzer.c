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

/** Functions to manipulate DNS labels
 *
 * @file src/lib/util/fuzzer.c
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/value.h>

static int decode_test_ctx(void **out, UNUSED TALLOC_CTX *ctx)
{
	*out = NULL;
	return 0;
}

/*
 *	Try to parse the input as a (mostly text) string.
 *
 *	This isn't perfect, but it allows simple fuzzing of the parsers for all of the data types.
 */
static ssize_t util_decode_proto(TALLOC_CTX *ctx, UNUSED fr_pair_list_t *out, uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	ssize_t rcode;
	fr_type_t type;
	fr_value_box_t *box;
	uint8_t *copy;

	if (data_len == 1) return data_len;

	type = data[0];
	switch (type) {
	case FR_TYPE_LEAF:
		break;

	default:
		return data_len;
	}

	box = fr_value_box_alloc(ctx, type, NULL, true);
	if (!box) return -1;

	/*
	 *	Copy the input, and ensure that it's zero terminated.
	 */
	copy = talloc_zero_array(box, uint8_t, data_len);
	if (!copy) {
		talloc_free(box);
		return -1;
	}
	memcpy(copy, data + 1, data_len - 1);


	/*
	 *	Some things in value_box_from_str() don't yet respect
	 *	data_len.  This means that if there's no zero
	 *	termination, we _know_ there will be buffer over-runs.
	 */
	rcode = fr_value_box_from_str(box, box, type, NULL, (char const *) copy, data_len - 1, 0, true);
	talloc_free(box);
	return rcode;
}

extern fr_test_point_proto_decode_t util_tp_decode_proto;
fr_test_point_proto_decode_t util_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= util_decode_proto
};
