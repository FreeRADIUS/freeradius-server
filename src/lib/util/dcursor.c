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

#include <string.h>
#include <stdint.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/pair.h>

static void *fr_dcursor_intersect_next(fr_dcursor_t *a, fr_dcursor_t *b);

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
static void *fr_dcursor_intersect_head(fr_dcursor_t *a, fr_dcursor_t *b)
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
 * The purpose of this function is to return items that match both iterators.
 *
 * @note Both cursors must operate on the same list of items.
 *
 * @param[in] a		First cursor.
 * @param[in] b		Second cursor.
 * @return next item in the list.
 *
 * @hidecallergraph
 */
static void *fr_dcursor_intersect_next(fr_dcursor_t *a, fr_dcursor_t *b)
{
	void *a_next, *b_next;

	if (unlikely(a->dlist != b->dlist)) return NULL;

	/*
	 *	If either of the cursors lack an iterator
	 *	just use cursor_next... i.e. return items
	 *	from the list that's actually filtered.
	 */
	if (!a->iter) return fr_dcursor_next(b);
	if (!b->iter) return fr_dcursor_next(a);

	/*
	 *	Deal with the case where the two iterators
	 *	are out of sync.
	 */
	if (a->current == b->current) {
		a_next = fr_dcursor_next(a);
		b_next = fr_dcursor_next(b);

		/*
		 *	Fast path...
		 */
		if (a_next == b_next) return a_next;
	} else {
		a_next = fr_dcursor_next(a);
	}

	if (!a_next) return NULL;

	/*
	 *	b_next doesn't match a_next, we don't know
	 *	if b is ahead or behind a, so we rewind
	 *	b, and compare every item to see if it
	 *	matches a.
	 *
	 *	This is slow and inefficient, but there's
	 *	nothing else we can do for stateful
	 *      iterators.
	 */
	do {
		for (b_next = fr_dcursor_head(b);
		     b_next;
		     b_next = fr_dcursor_next(b)) if (a_next == b_next) return b_next;
	} while ((a_next = fr_dcursor_next(a)));

	return NULL;
}
