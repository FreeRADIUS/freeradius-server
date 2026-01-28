/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @brief Protocol agnostic encode/decoders
 * @file unlang/xlat_pair.c
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/unlang/xlat_priv.h>

/** Keep decoding pairs until all of the data has been used.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] out		the cursor to update
 * @param[in] parent		to use as the root
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decode_ctx	Any decode specific data such as secrets or configurable.
 * @param[in] decode		the function used to decode one specific pair.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
static ssize_t fr_pair_decode_multi(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t data_len, void *decode_ctx, fr_pair_decode_t decode)
{
	uint8_t const *p, *end;
	fr_pair_list_t tmp;

	/*
	 *	Catch idiocies.
	 */
	if (data_len == 0) return 0;

	fr_pair_list_init(&tmp);

	p = data;
	end = data + data_len;

	while (p < end) {
		ssize_t len;

		len = decode(ctx, &tmp, parent, p, end - p, decode_ctx);
		if (len <= 0) {
			fr_pair_list_free(&tmp);
			return len - (p - data);
		}
		p += len;
	}

	/*
	 *	Add the pairs to the cursor
	 */
	fr_pair_list_append(out, &tmp);

	return data_len;
}


/** Decode all of the value boxes into the output cursor
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] out		the cursor to update
 * @param[in] request		the request
 * @param[in] decode_ctx	Any decode specific data such as secrets or configurable.
 * @param[in] decode		the function used to decode one specific pair.
 * @param[in] in		the list of value boxes to decode
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many value boxes were decoded
 */
int xlat_decode_value_box_list(TALLOC_CTX *ctx, fr_pair_list_t *out,
			       request_t *request, void *decode_ctx, fr_pair_decode_t decode,
			       fr_value_box_list_t *in)
{
	int		decoded = 0;
	fr_pair_t	*vp = NULL;
	fr_dict_attr_t const *parent = fr_dict_root(request->proto_dict);
	fr_pair_list_t	head;

	fr_pair_list_init(&head);

	fr_value_box_list_foreach(in, vb) {
		ssize_t		len;

		if (vb->type != FR_TYPE_OCTETS) {
			RWDEBUG("Skipping value \"%pR\", expected value of type %s, got type %s",
				vb,
				fr_type_to_str(FR_TYPE_OCTETS),
				fr_type_to_str(vb->type));
			continue;
		}

		len = fr_pair_decode_multi(ctx, &head, parent,
					   vb->vb_octets, vb->vb_length, decode_ctx, decode);
		if (len <= 0) {
			fr_pair_list_free(&head);
			return -decoded;
		}
		decoded++;	/* one more VB, but there may be many pairs in the decoded vps. */
	}

	if (RDEBUG_ENABLED2) {
		char const *name = parent->name;

		while ((vp = fr_pair_list_next(&head, vp))) {
			RDEBUG2("decode %s: %pP", name, vp);
		}
	}

	decoded = fr_pair_list_num_elements(&head);

	fr_pair_list_append(out, &head);

	return decoded;
}
