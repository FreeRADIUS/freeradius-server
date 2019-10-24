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
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/struct.h>

VALUE_PAIR *fr_unknown_from_network(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len)
{
	VALUE_PAIR *vp;
	fr_dict_attr_t const *child;

#if defined(__clang_analyzer__) || !defined(NDEBUG)
	if (!parent->parent) return NULL; /* stupid static analyzers */
#endif

	/*
	 *	Build an unknown attr of the entire STRUCT.
	 */
	child = fr_dict_unknown_afrom_fields(ctx, parent->parent,
					     fr_dict_vendor_num_by_da(parent), parent->attr);
	if (!child) return NULL;

	vp = fr_pair_afrom_da(ctx, child); /* makes a copy of 'child' */
	fr_dict_unknown_free(&child);
	if (!vp) return NULL;

	if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, data, data_len, true) < 0) {
		fr_pair_list_free(&vp);
		return NULL;
	}

	vp->type = VT_DATA;
	return vp;
}



/** Convert a STRUCT to one or more VPs
 *
 */
ssize_t fr_struct_from_network(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			       fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			       fr_dict_attr_t const **child_p)
{
	unsigned int		child_num;
	uint8_t const		*p = data, *end = data + data_len;
	fr_dict_attr_t const	*child;
	VALUE_PAIR		*head = NULL;
	fr_cursor_t		child_cursor;
	VALUE_PAIR		*vp, *key_vp;

	if (data_len < 1) return -1; /* at least one byte of data */

	/*
	 *  Record where we were in the list when this function was called
	 */
	fr_cursor_init(&child_cursor, &head);
	*child_p = NULL;
	child_num = 1;
	key_vp = NULL;

	while (p < end) {
		size_t child_length;

		/*
		 *	Go to the next child.  If it doesn't exist, we're done.
		 */
		child = fr_dict_attr_child_by_num(parent, child_num);
		if (!child) break;

		/*
		 *	Decode child TLVs, according to the parent attribute.
		 *
		 *	Return only PARTIALLY decoded data.  Let the
		 *	caller decode the rest.
		 */
		if (child->type == FR_TYPE_TLV) {
			*child_p = child;

			fr_cursor_head(&child_cursor);
			fr_cursor_tail(cursor);
			fr_cursor_merge(cursor, &child_cursor);	/* Wind to the end of the new pairs */
			return (p - data);
		}

		child_length = child->flags.length;

		/*
		 *	If this field overflows the input, then *all*
		 *	of the input is suspect.
		 */
		if ((p + child_length) > end) goto unknown;

		if (!child_length) child_length = (end - p);

		/*
		 *	We only allow a limited number of data types
		 *	inside of a struct.
		 */
		switch (child->type) {
		default:
			goto unknown;

		case FR_TYPE_VALUES:
			break;
		}

		vp = fr_pair_afrom_da(ctx, child);
		if (!vp) goto unknown;

		/*
		 *	No protocol-specific data types here (yet).
		 *
		 *	If we can't decode this field, then the entire
		 *	structure is treated as a raw blob.
		 */
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, p, child_length, true) < 0) {
			fr_pair_list_free(&vp);
		unknown:
			fr_pair_list_free(&head);

			vp = fr_unknown_from_network(ctx, parent, data, data_len);
			if (!vp) return -1;

			/*
			 *	And append this one VP to the output cursor.
			 */
			fr_cursor_append(cursor, vp);
			return data_len;
		}

		vp->type = VT_DATA;
		vp->vp_tainted = true;
		fr_cursor_append(&child_cursor, vp);

		if (vp->da->flags.extra) key_vp = vp;

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

	/*
	 *	Is there a substructure after this one?  If so, go
	 *	decode it.
	 */
	if (key_vp) {
		ssize_t sublen;

		switch (key_vp->da->type) {
		default:
			return data_len;

		case FR_TYPE_UINT8:
			child_num = key_vp->vp_uint8;
			break;

		case FR_TYPE_UINT16:
			child_num = key_vp->vp_uint16;
			break;

		case FR_TYPE_UINT32:
			child_num = key_vp->vp_uint32;
			break;
		}

		child = fr_dict_attr_child_by_num(key_vp->da, child_num);
		if (!child || (child->type != FR_TYPE_STRUCT)) {
			return data_len;
		}

		sublen = fr_struct_from_network(ctx, cursor, child, p, end - p, child_p);
		if (sublen < 0) goto unknown;

		/*
		 *	Else return whatever we decoded.  Note that if
		 *	the substruct ends in a TLV, we only decode
		 *	the fixed-length portion of the structure.
		 */
		return (end - p) + sublen;
	}

	return data_len;
}


ssize_t fr_struct_to_network(uint8_t *out, size_t outlen,
			     fr_dict_attr_t const *parent, fr_cursor_t *cursor)
{
	ssize_t			len;
	unsigned int		child_num = 1;
	uint8_t			*p = out;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const   	*key_da;

	VP_VERIFY(fr_cursor_current(cursor));

	if (parent->type != FR_TYPE_STRUCT) {
		fr_strerror_printf("%s: Expected type \"struct\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"));
		return -1;
	}

	if (!vp || (vp->da->parent != parent)) {
		fr_strerror_printf("%s: Can't encode empty struct", __FUNCTION__);
		return -1;
	}

	key_da = NULL;

	while (outlen) {
		fr_dict_attr_t const *child;

		/*
		 *	The child attributes should be in order.  If
		 *	they're not, we fill the struct with zeroes.
		 */
		child = vp->da;
		if (child->attr != child_num) {
			child = fr_dict_attr_child_by_num(parent, child_num);

			if (!child) break;

			if (child->flags.extra) {
				key_da = child;
			}

			if (child->flags.length > outlen) {
				len = outlen;
			} else {
				len = child->flags.length;
			}

			memset(p, 0, len);
			p += len;
			outlen -= len;
			child_num++;
			continue;
		}

		/*
		 *	Encode fixed-size octets fields so that they
		 *	are exactly the fixed size, UNLESS the entire
		 *	output is truncated.
		 */
		if ((vp->da->type == FR_TYPE_OCTETS) && vp->da->flags.length) {
			size_t mylen = vp->da->flags.length;

			if (mylen > outlen) mylen = outlen;

			if (vp->vp_length < mylen) {
				memcpy(p, vp->vp_ptr, vp->vp_length);
				memset(p + vp->vp_length, 0, mylen - vp->vp_length);
			} else {
				memcpy(p, vp->vp_ptr, mylen);
			}
			len = mylen;

		} else {
			/*
			 *	Determine the nested type and call the appropriate encoder
			 */
			len = fr_value_box_to_network(NULL, p, outlen, &vp->data);
			if (len <= 0) return -1;
		}

		if (child->flags.extra) {
			key_da = child;
		}

		p += len;
		outlen -= len;				/* Subtract from the buffer we have available */
		child_num++;

		do {
			vp = fr_cursor_next(cursor);
			if (!vp || !vp->da->flags.internal) break;
		} while (vp != NULL);

		/*
		 *	Nothing more to do, or we've done all of the
		 *	entries in this structure, stop.
		 */
		if (!vp || (vp->da->parent != parent)) break;
	}

	if (!vp || !outlen) return p - out;

	/*
	 *	If our parent is a struct, AND it's parent is
	 *	the key_da, then we have a keyed struct for
	 *	the child.  Go encode it.
	 */
	if (key_da &&
	    (vp->da->parent->type == FR_TYPE_STRUCT) &&
	    (vp->da->parent->parent == key_da)) {
		len = fr_struct_to_network(p, outlen,
					   vp->da->parent, cursor);
		if (len < 0) return len;
		return (p - out) + len;
	}
	/*
	 *	Else we have a key_da with no child struct.
	 *	Oh well.  Assume that the caller knows WTF
	 *	he's doing, and encode things as best we can.
	 */

	return p - out;
}
