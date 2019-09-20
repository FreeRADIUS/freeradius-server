#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, cursor 2 of the
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

/** Functions to iterate over a sets and subsets of items
 *
 * @file src/lib/util/cursor.h
 *
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(cursor_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stddef.h>
#include <talloc.h>

/** Callback for implementing custom iterators
 *
 * @param[in,out] prev	the attribute to the one passed as to_eval.
 *			Must be updated to the previous attribute to the one
 *			returned.
 * @param[in] to_eval	the next item in the list.  Iterator should check to
 *			see if it matches the iterator's filter, and if it doesn't
 *			iterate over the items until one is found that does.
 * @param[in] uctx	passed to #fr_cursor_init.
 * @return
 *	- to_eval if to_eval matched, or a subsequent attribute if that matched.
 *	- NULL if no more matching attributes were found.
 */
typedef void *(*fr_cursor_iter_t)(void **prev, void *to_eval, void *uctx);

typedef struct {
	void			**head;		//!< First item in the list.
	void			*tail;		//!< Used for efficient fr_cursor_append.
	void			*current;	//!< The current item in the linked list.
	void			*prev;		//!< The previous item in the linked list.

	size_t			offset;		//!< Where the next ptr is in the item struct.
	fr_cursor_iter_t	iter;		//!< Iterator function.
	void			*ctx;		//!< to pass to iterator function.
	char const		*type;		//!< If set, used for explicit runtime type safety checks.
} fr_cursor_t;

void fr_cursor_copy(fr_cursor_t *out, fr_cursor_t const *in) CC_HINT(nonnull);

void *fr_cursor_head(fr_cursor_t *cursor);

void *fr_cursor_tail(fr_cursor_t *cursor);

void *fr_cursor_next(fr_cursor_t *cursor);

void *fr_cursor_next_peek(fr_cursor_t *cursor);

void *fr_cursor_list_next_peek(fr_cursor_t *cursor);

void *fr_cursor_list_prev_peek(fr_cursor_t *cursor);

void *fr_cursor_current(fr_cursor_t *cursor);

void fr_cursor_prepend(fr_cursor_t *cursor, void *v) CC_HINT(nonnull);

void fr_cursor_append(fr_cursor_t *cursor, void *v) CC_HINT(nonnull);

void fr_cursor_insert(fr_cursor_t *cursor, void *v) CC_HINT(nonnull);

void fr_cursor_merge(fr_cursor_t *cursor, fr_cursor_t *to_append) CC_HINT(nonnull);

void *fr_cursor_remove(fr_cursor_t *cursor) CC_HINT(nonnull);

void *fr_cursor_replace(fr_cursor_t *cursor, void *r) CC_HINT(nonnull);

void fr_cursor_free_list(fr_cursor_t *cursor) CC_HINT(nonnull);

/** Initialise a cursor with runtime talloc type safety checks and a custom iterator
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _iter	function.
 * @param[in] _ctx	_iter function _ctx.
 * @param[in] _type	Talloc type i.e. VALUE_PAIR or fr_value_box_t.
 * @return
 *	- NULL if _head does not point to any items, or the iterator matches no items
 *	  in the current list.
 *	- The first item returned by the iterator.
 */
#define fr_cursor_talloc_iter_init(_cursor, _head, _iter, _ctx, _type) \
	_fr_cursor_init(_cursor, (void **)_head, offsetof(__typeof__(**(_head)), next), _iter, _ctx, #_type)

/** Initialise a cursor with a custom iterator
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _iter	function.
 * @param[in] _ctx	_iter function _ctx.
 * @return
 *	- NULL if _head does not point to any items, or the iterator matches no items
 *	  in the current list.
 *	- The first item returned by the iterator.
 */
#define fr_cursor_iter_init(_cursor, _head, _iter, _ctx) \
	_fr_cursor_init(_cursor, (void **)_head, offsetof(__typeof__(**(_head)), next), _iter, _ctx, NULL)

/** Initialise a cursor with runtime talloc type safety checks
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _type	Talloc type i.e. VALUE_PAIR or fr_value_box_t.
 * @return
 *	- NULL if _head does not point to any items.
 *	- The first item in the list.
 */
#define fr_cursor_talloc_init(_cursor, _head, _type) \
	_fr_cursor_init(_cursor, (void **)_head, offsetof(__typeof__(**(_head)), next), NULL, NULL, #_type)

/** Initialise a cursor
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @return
 *	- NULL if _head does not point to any items.
 *	- The first item in the list.
 */
#define fr_cursor_init(_cursor, _head) \
	_fr_cursor_init(_cursor, (void * const *)_head, offsetof(__typeof__(**(_head)), next), NULL, NULL, NULL)

void *_fr_cursor_init(fr_cursor_t *cursor, void * const *head, size_t offset,
		      fr_cursor_iter_t iter, void const *ctx, char const *type);

/** talloc_free the current item
 *
 * @param[in] cursor	to free items from.
 */
static inline void fr_cursor_free_item(fr_cursor_t *cursor)
{
	if (!cursor) return;

	talloc_free(fr_cursor_remove(cursor));
}

#ifdef __cplusplus
}
#endif
