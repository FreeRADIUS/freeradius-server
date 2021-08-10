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
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/io/pair.h>

/** Keep decoding pairs until all of the data has been used.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] out		the cursor to update
 * @param[in] dict		to use to lookup attributes.
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decode_ctx	Any decode specific data such as secrets or configurable.
 * @param[in] decode		the function used to decode one specific pair.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
static ssize_t fr_pair_decode_multi(TALLOC_CTX *ctx, fr_dcursor_t *out, fr_dict_t const *dict,
				    uint8_t const *data, size_t data_len, void *decode_ctx, fr_pair_decode_t decode)
{
	uint8_t const *p, *end;
	fr_pair_list_t head;
	fr_dcursor_t cursor;

	/*
	 *	Catch idiocies.
	 */
	if (data_len == 0) return 0;

	fr_pair_list_init(&head);
	fr_dcursor_init(&cursor, &head);

	p = data;
	end = data + data_len;

	while (p < end) {
		ssize_t len;

		len = decode(ctx, &cursor, dict, p, end - p, decode_ctx);
		if (len <= 0) {
			fr_pair_list_free(&head);
			return len - (p - data);
		}
		p += len;
	}

	/*
	 *	Add the pairs to the cursor
	 */
	fr_dcursor_head(&cursor);
	fr_dcursor_merge(out, &cursor);

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
int fr_pair_decode_value_box_list(TALLOC_CTX *ctx, fr_dcursor_t *out,
				  request_t *request, void *decode_ctx, fr_pair_decode_t decode,
				  fr_value_box_list_t *in)
{
	int		decoded = 0;
	fr_value_box_t	*vb = NULL;
	fr_pair_t	*vp = NULL;
	fr_pair_list_t	head;
	fr_dcursor_t	cursor;

	fr_pair_list_init(&head);

	while ((vb = fr_dlist_next(in, vb))) {
		ssize_t		len;
		fr_pair_list_t	vps;

		if (vb->type != FR_TYPE_OCTETS) {
			RWDEBUG("Skipping value \"%pV\", expected value of type %s, got type %s",
				vb,
				fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_OCTETS, "<INVALID>"),
				fr_table_str_by_value(fr_value_box_type_table, vb->type, "<INVALID>"));
			continue;
		}

		fr_pair_list_init(&vps);
		fr_dcursor_init(&cursor, &vps);

		len = fr_pair_decode_multi(ctx, &cursor, request->dict,
					   vb->vb_octets, vb->vb_length, decode_ctx, decode);
		if (len <= 0) {
			fr_pair_list_free(&head);
			return -decoded;
		}
		fr_pair_list_append(&head, &vps);
		decoded++;	/* one more VB, but there may be many pairs in the decoded vps. */
	}

	if (RDEBUG_ENABLED2) {
		char const *name = fr_dict_root(request->dict)->name;

		while ((vp = fr_pair_list_next(&head, vp))) {
			RDEBUG2("decode %s: &%pP", name, vp);
		}
	}

	decoded = fr_dlist_num_elements(&head.head);

	fr_dcursor_init(&cursor, &head);
	fr_dcursor_merge(out, &cursor);

	return decoded;
}
