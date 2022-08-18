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

/** AVP privately inlineable manipulation and search API
 *
 * @file src/lib/util/pair_inline.c
 *
 * @copyright 2022 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#ifndef _PAIR_INLINE
RCSID("$Id$")
#  define _PAIR_PRIVATE 1
#  include <freeradius-devel/util/pair.h>
#  include <freeradius-devel/util/tlist.h>
#  define _INLINE
FR_TLIST_FUNCS(fr_pair_order_list, fr_pair_t, order_entry)
#else
#  define _INLINE CC_HINT(always_inline) static inline
#endif

/** Get the head of a valuepair list
 *
 * @param[in] list	to return the head of
 *
 * @return
 *	- NULL if the list is empty
 *	- pointer to the first item in the list.
 * @hidecallergraph
 */
_INLINE fr_pair_t *fr_pair_list_head(fr_pair_list_t const *list)
{
	return fr_pair_order_list_head(&list->order);
}

/** Get the tail of a valuepair list
 *
 * @param[in] list	to return the tail of
 *
 * @return
 *	- NULL if the list is empty
 *	- pointer to the last item in the list.
 */
_INLINE fr_pair_t *fr_pair_list_tail(fr_pair_list_t const *list)
{
	return fr_pair_order_list_tail(&list->order);
}

/** Get the next item in a valuepair list after a specific entry
 *
 * @param[in] list	to walk
 * @param[in] item	whose "next" item to return
 * @return
 *	- NULL if the end of the list has been reached
 *	- pointer to the next item
 * @hidecallergraph
 */
_INLINE fr_pair_t *fr_pair_list_next(fr_pair_list_t const *list, fr_pair_t const *item)
{
	return fr_pair_order_list_next(&list->order, item);
}

/** Get the previous item in a valuepair list before a specific entry
 *
 * @param[in] list	to walk
 * @param[in] item	whose "prev" item to return
 * @return
 *	- NULL if the head of the list has been reached
 *	- pointer to the previous item
 */
_INLINE fr_pair_t *fr_pair_list_prev(fr_pair_list_t const *list, fr_pair_t const *item)
{
	return fr_pair_order_list_prev(&list->order, item);
}

/** Remove fr_pair_t from a list without freeing
 *
 * @param[in] list	of value pairs to remove VP from.
 * @param[in] vp	to remove
 * @return previous item in the list to the one being removed.
 */
_INLINE fr_pair_t *fr_pair_remove(fr_pair_list_t *list, fr_pair_t *vp)
{
	return fr_pair_order_list_remove(&list->order, vp);
}

/** Free memory used by a valuepair list.
 *
 * @hidecallergraph
 */
_INLINE void fr_pair_list_free(fr_pair_list_t *list)
{
	fr_pair_order_list_talloc_free(&list->order);
}

/** Is a valuepair list empty
 *
 * @param[in] list to check
 * @return true if empty
 *
 * @hidecallergraph
 */
_INLINE bool fr_pair_list_empty(fr_pair_list_t const *list)
{
	return fr_pair_order_list_empty(&list->order);
}

/** Sort a doubly linked list of fr_pair_ts using merge sort
 *
 * @note We use a merge sort (which is a stable sort), making this
 *	suitable for use on lists with things like EAP-Message
 *	fragments where the order of EAP-Message attributes needs to
 *	be maintained.
 *
 * @param[in,out] list head of dlinked fr_pair_ts to sort.
 * @param[in] cmp to sort with
 */
_INLINE void fr_pair_list_sort(fr_pair_list_t *list, fr_cmp_t cmp)
{
	fr_pair_order_list_sort(&list->order, cmp);
}

/** Get the length of a list of fr_pair_t
 *
 * @param[in] list to return the length of
 *
 * @return number of entries in the list
 */
_INLINE size_t fr_pair_list_num_elements(fr_pair_list_t const *list)
{
	return fr_pair_order_list_num_elements(&list->order);
}

/** Get the dlist head from a pair list
 *
 * @param[in] list to get the head from
 *
 * @return the pointer to the dlist wihin the pair list.
 */
_INLINE fr_dlist_head_t *fr_pair_list_to_dlist(fr_pair_list_t const *list)
{
	return fr_pair_order_list_dlist_head(&list->order);
}

/** Get the pair list head from a dlist
 *
 * @param[in] list	The order list from a pair list.
 * @return The pair list head.
 */
_INLINE fr_pair_list_t *fr_pair_list_from_dlist(fr_dlist_head_t const *list)
{
	return (fr_pair_list_t *)((uintptr_t)list - offsetof(fr_pair_list_t, order));
}

/** Appends a list of fr_pair_t from a temporary list to a destination list
 *
 * @param dst list to move pairs into
 * @param src list from which to take pairs
 */
_INLINE void fr_pair_list_append(fr_pair_list_t *dst, fr_pair_list_t *src)
{
	fr_pair_order_list_move(&dst->order, &src->order);
}

/** Move a list of fr_pair_t from a temporary list to the head of a destination list
 *
 * @param dst list to move pairs into
 * @param src from which to take pairs
 */
_INLINE void fr_pair_list_prepend(fr_pair_list_t *dst, fr_pair_list_t *src)
{
	fr_pair_order_list_move_head(&dst->order, &src->order);
}
