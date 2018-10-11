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

/** Functions to encode / decode structures on the wire
 *
 * @file src/lib/util/struct.c
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include "struct.h"

#include <freeradius-devel/util/pair.h>

/** Convert a STRUCT to one or more VPs
 *
 */
ssize_t fr_struct_from_network(TALLOC_CTX *ctx, fr_cursor_t *cursor,
				     fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	unsigned int		child_num;
	uint8_t const		*p = data, *end = data + data_len;
	fr_dict_attr_t const	*child;
	VALUE_PAIR		*head = NULL;
	fr_cursor_t		child_cursor;

	if (data_len < 1) return -1; /* at least one byte of data */

	/*
	 *	Data is too small for the structure, ignore it.
	 */
	if (data_len < parent->flags.length) goto raw;

	/*
	 *  Record where we were in the list when this function was called
	 */
	fr_cursor_init(&child_cursor, &head);

	child_num = 1;
	while (p < end) {
		size_t child_length;
		VALUE_PAIR *vp;

		/*
		 *	Go to the next child.  If it doesn't exist, we're done.
		 */
		child = fr_dict_attr_child_by_num(parent, child_num);
		if (!child) break;

		child_length = child->flags.length;
		if (!child_length) child_length = (end - p);

		vp = fr_pair_afrom_da(ctx, child);
		if (!vp) return -1;

		/*
		 *	We only allow a limited number of data types
		 *	inside of a struct.
		 */
		switch (child->type) {
		default:
			fr_strerror_printf("Invalid data type passed to decode_struct");
			return -1;

		case FR_TYPE_VALUES:
		case FR_TYPE_STRUCT:
			break;
		}

		/*
		 *	No protocol-specific magic here.
		 *
		 *	@todo - allow it, if necessary
		 */
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, p, child_length, true) < 0) {
			TALLOC_FREE(vp);

			fr_pair_list_free(&head);

		raw:
			fr_cursor_init(&child_cursor, &head);

			/*
			 *	Build an unknown attr of the entire STRUCT.
			 */
			child = fr_dict_unknown_afrom_fields(ctx, parent->parent,
							     fr_dict_vendor_num_by_da(parent), parent->attr);
			if (!child) return -1;

			vp = fr_pair_afrom_da(ctx, child);
			if (!vp) return -1;

			if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, data, data_len, true) < 0) {
				TALLOC_FREE(vp);
				return -1;
			}

			vp->type = VT_DATA;
			vp->vp_tainted = true;
			fr_cursor_append(&child_cursor, vp);
			break;
		}

		vp->type = VT_DATA;
		vp->vp_tainted = true;
		fr_cursor_append(&child_cursor, vp);

		/*
		 *	Note that we're decoding fixed fields here.
		 *	So we skip the input based on the *known*
		 *	length, and not on the *decoded* length.
		 */
		p += child_length;
		child_num++;	/* go to the next child */
	}

	fr_cursor_head(&child_cursor);
	fr_cursor_tail(cursor);
	fr_cursor_merge(cursor, &child_cursor);	/* Wind to the end of the new pairs */

	return data_len;
}

