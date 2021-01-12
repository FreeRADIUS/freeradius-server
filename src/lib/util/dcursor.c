/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
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

/** Functions to iterate over a sets and subsets of items in dlists
 *
 * @file src/lib/util/dcursor.c
 *
 * @note Do not modify collections of items pointed to by a cursor
 *	 with non fr_dcursor_* functions over the lifetime of that cursor.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2016 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include <talloc.h>
#include <string.h>
#include <stdint.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/dpair.h>

/** Return the first item matching the iterator in cursor a and cursor b
 *
 * If a and b are not currently set to the same item, b will be reset,
 * and wound to the item before a's current item.
 *
 * @note Both cursors must operate on the same list of items.
 *
 * @param[in] a		First cursor.
 * @param[in] b		Second cursor.
 * @return item at the start of the list.
 *
 * @hidecallergraph
 */
void *fr_dcursor_intersect_head(fr_dcursor_t *a, fr_dcursor_t *b)
{
	void *a_item, *b_item;

	if (unlikely(a->dlist != b->dlist)) return NULL;

	a_item = fr_dcursor_head(a);
	b_item = fr_dcursor_head(b);

	if (a_item == b_item) return a_item;

	return fr_dcursor_intersect_next(a, b);
}

/** Return the next item matching the iterator in cursor a and cursor b
 *
 * If a and b are not currently set to the same item, b will be reset,
 * and wound to the item before a's current item.
 *
 * @note Both cursors must operate on the same list of items.
 *
 * @param[in] a		First cursor.
 * @param[in] b		Second cursor.
 * @return next item in the list.
 *
 * @hidecallergraph
 */
void *fr_dcursor_intersect_next(fr_dcursor_t *a, fr_dcursor_t *b)
{
	fr_dcursor_iter_t	b_iter;
	void			*b_uctx;

	if (unlikely(a->dlist != b->dlist)) return NULL;

	/*
	 *	If either of the iterators lack an iterator
	 *	just use cursor_next...
	 */
	if (!a->iter) return fr_dcursor_next(b);
	if (!b->iter) return fr_dcursor_next(a);

	/*
	 *	Both have iterators...
	 */
	b_iter = b->iter;
	b_uctx = b->uctx;

	/*
	 *	Deal with the case where the two iterators
	 *	are out of sync.
	 */
	if (a->current != b->current) {
		fr_dcursor_head(b);	/* reset */
	} else {
		a->current = dcursor_next(a, a->current);
		a->prev = fr_dlist_prev(a->dlist, a->current);
	}

	/*
	 *	Use a's iterator to select the item to
	 *	check.
	 */
	do {
		void *a_prev = fr_dcursor_list_prev_peek(a);
		b->iter = NULL;		/* Disable b's iterator */

		/*
		 *	Find a in b (the slow way *sigh*)
		 */
		while ((b->current = dcursor_next(b, b->current)) && (b->current != a_prev));

		/*
		 *	No more items...
		 */
		if (!b->current) {
			fr_dcursor_copy(a, b);
			return NULL;
		}

		/*
		 *	We're now one item before the item
		 *	returned by a, see if b's iterator
		 *	returns the same item as a's.
		 */
		 b->iter = b_iter;
		 b->current = dcursor_next(b, b->current);

		/*
		 *	Matched, we're done...
		 */
		if (a->current == b->current) return a->current;

		/*
		 *	Reset b's position to a's and try again.
		 */
		fr_dcursor_copy(b, a);
		b->iter = b_iter;
		b->uctx = b_uctx;
	} while ((a->current = dcursor_next(a, a->current)));

	return NULL;
}
