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

/** Functions to iterate over a sets and subsets of items stored in dlists
 *
 * @file src/lib/util/dcursor.h
 *
 * @copyright 2020 The FreeRADIUS server project
 */
RCSIDH(dcursor_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/dlist.h>

#include <stddef.h>
#include <stdbool.h>
#include <talloc.h>

/** Callback for implementing custom iterators
 *
 * @param[in] list	head of the dlist.
 * @param[in] to_eval	the next item in the list.  Iterator should check to
 *			see if it matches the iterator's filter, and if it doesn't
 *			iterate over the items until one is found that does.
 * @param[in] uctx	passed to #fr_dcursor_init.
 * @return
 *	- to_eval if to_eval matched, or a subsequent attribute if that matched.
 *	- NULL if no more matching attributes were found.
 */
typedef void *(*fr_dcursor_iter_t)(fr_dlist_head_t *list, void *to_eval, void *uctx);
/** Callback for performing additional actions on insert
 *
 * @param[in] list	head of the dlist.
 * @param[in] to_insert	The item being inserted into the cursor.
 * @param[in] uctx	passed to #fr_dcursor_init.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_dcursor_insert_t)(fr_dlist_head_t *list, void *to_insert, void *uctx);
/** Callback for performing additional actions on removal
 *
 * @param[in] list	head of the dlist.
 * @param[in] to_delete	The item being removed from the cursor.
 * @param[in] uctx	passed to #fr_dcursor_init.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_dcursor_delete_t)(fr_dlist_head_t *list, void *to_delete, void *uctx);
/** Type of evaluation functions to pass to the fr_dcursor_filter_*() functions.
 *
 * @param[in] item	the item to be evaluated
 * @param[in] uctx	context that may assist with evaluation
 * @return
 * 	- true if the evaluation function is satisfied.
 * 	- false if the evaluation function is not satisfied.
 */
typedef bool (*fr_dcursor_eval_t)(void const *item, void const *uctx);
typedef struct {
	fr_dlist_head_t		*dlist;		//!< Head of the doubly linked list being iterated over.
	void			*current;	//!< The current item in the dlist.
	void			*prev;		//!< The previous item in the dlist.
	fr_dcursor_iter_t	iter;		//!< Iterator function.
	fr_dcursor_insert_t	insert;		//!< Callback function on insert.
	fr_dcursor_delete_t	delete;		//!< Callback function on delete.
	void			*uctx;		//!< to pass to iterator function.
} fr_dcursor_t;

typedef struct {
	uint8_t			depth;		//!< Which cursor is currently in use.
	fr_dcursor_t		cursor[];	//!< Stack of cursors.
} fr_dcursor_stack_t;

/** Internal function to get the next item
 *
 * @param[in] cursor	to operate on.
 * @param[in] current	attribute.
 * @return
 *	- The next attribute.
 *	- NULL if no more attributes.
 */
static inline void *dcursor_next(fr_dcursor_t *cursor, void *current)
{
	void *next;

	/*
	 *	First time next has been called
	 */
	if (!current) {
		if (fr_dlist_empty(cursor->dlist)) return NULL;
		if (cursor->prev) return NULL;					/* At tail of the list */
		if (!cursor->iter) return (fr_dlist_head(cursor->dlist));	/* Fast path without custom iter */

		current = fr_dlist_head(cursor->dlist);
		return cursor->iter(cursor->dlist, current, cursor->uctx);
	}

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->dlist->type) _talloc_get_type_abort(current, cursor->dlist->type, __location__);
#endif

	if (!cursor->iter) {
		return fr_dlist_next(cursor->dlist, current);			/* Fast path without custom iter */
	}

	/*
	 *	Pre-advance current
	 */
	next = fr_dlist_next(cursor->dlist, current);

	/*
	 *	The iterator can just return what it was passed for curr
	 *	if it just wants to advance by one.
	 */
	return cursor->iter(cursor->dlist, next, cursor->uctx);
}

/** Copy cursor parameters and state.
 *
 * @param[out] out	Where to copy the cursor to.
 * @param[in] in	cursor to copy.
 *
 * @hidecallergraph
 */
static inline void fr_dcursor_copy(fr_dcursor_t *out, fr_dcursor_t const *in)
{
	memcpy(out, in, sizeof(*out));
}

/** Rewind cursor to the start of the list
 *
 * @param[in] cursor	to operate on.
 * @return item at the start of the list.
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_head(fr_dcursor_t *cursor)
{
	if (unlikely(!cursor)) return NULL;

	cursor->prev = NULL;
	/*
	 *	If we have a custom iterator, the dlist attribute
	 *	may not be in the subset the iterator would
	 *	return, so set everything to NULL and have
	 *	dcursor_next figure it out.
	 */
	if (cursor->iter) {
		cursor->current = dcursor_next(cursor, NULL);
		return cursor->current;
	}

	cursor->current = fr_dlist_head(cursor->dlist);

	return cursor->current;
}

/** Wind cursor to the tail item in the list
 *
 * @param[in] cursor	to operate on.
 * @return item at the end of the list.
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_tail(fr_dcursor_t *cursor)
{
	if (!cursor || fr_dlist_empty(cursor->dlist)) return NULL;

	cursor->current = fr_dlist_tail(cursor->dlist);
	if (cursor->current) {
		cursor->prev = fr_dlist_prev(cursor->dlist, cursor->current);
	} else {
		cursor->prev = NULL;
	}

	return cursor->current;
}

/** Advanced the cursor to the next item
 *
 * @param[in] cursor to operate on.
 * @return
 *	- Next item.
 *	- NULL if the list is empty, or the cursor has advanced past the end of the list.
 *
 * @hidecallergraph
 */
static inline void * CC_HINT(hot) fr_dcursor_next(fr_dcursor_t *cursor)
{
	if (!cursor || fr_dlist_empty(cursor->dlist)) return NULL;
	cursor->current = dcursor_next(cursor, cursor->current);

	cursor->prev = fr_dlist_prev(cursor->dlist, cursor->current);
	return cursor->current;
}

/** Return the next iterator item without advancing the cursor
 *
 * @param[in] cursor to operate on.
 * @return
 *	- Next item.
 *	- NULL if the list is empty, or the cursor has advanced past the end of the list.
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_next_peek(fr_dcursor_t *cursor)
{
	return dcursor_next(cursor, cursor->current);
}

/** Returns the next list item without advancing the cursor
 *
 * @note This returns the next item in the list, which may not match the
 *	next iterator value.  It's mostly used for debugging.  You probably
 *	want #fr_dcursor_next_peek.
 *
 * @param[in] cursor to operator on.
 * @return
 *	- Next item in list.
 *	- NULL if the list is empty, or the cursor has advanced past the end of the list.
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_list_next_peek(fr_dcursor_t *cursor)
{
	if (!cursor || !cursor->current) return NULL;

	return fr_dlist_next(cursor->dlist, cursor->current);
}

/** Returns the previous list item without rewinding the cursor
 *
 * @note This returns the previous item in the list, which may not be the
 *	 previous 'current' value.
 *
 * @param[in] cursor to operator on.
 * @return
 *	- Previous item.
 *	- NULL if no previous item available.
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_list_prev_peek(fr_dcursor_t *cursor)
{
	if (unlikely(!cursor)) return NULL;

	/*
	 *	If cursor->current is not set then there's no prev.
	 *	fr_dlist_prev would return the tail
	 */
	if (!cursor->prev) return NULL;

	return fr_dlist_prev(cursor->dlist, cursor->current);
}

/** Return the item the cursor current points to
 *
 * @param[in] cursor to operate on.
 * @return
 *	- The item the cursor currently points to.
 *	- NULL if the list is empty, or the cursor has advanced past the end of the list.
 *
 * @hidecallergraph
 */
static inline void * CC_HINT(hot) fr_dcursor_current(fr_dcursor_t *cursor)
{
	if (unlikely(!cursor)) return NULL;

	return cursor->current;
}

/** Set the cursor to a specified item
 *
 * @param[in] cursor to operate on.
 * @param[in] item to point the cursor at
 * @return
 *	- item cursor points at.
 *	- NULL if the list is empty.
 *
 * @hidecallergraph
 */
static inline void * CC_HINT(hot) fr_dcursor_set_current(fr_dcursor_t *cursor, void *item)
{
	if (!cursor || fr_dlist_empty(cursor->dlist)) return NULL;
	if (!item) return NULL;

	cursor->current = item;
	cursor->prev = fr_dlist_prev(cursor->dlist, item);

	return cursor->current;
}

/** Insert a single item at the start of the list
 *
 * @note Will not advance cursor position to r attribute, but will set cursor
 *	 to this attribute, if it's the head one in the list.
 *
 * Insert a void at the start of the list.
 *
 * @param cursor to operate on.
 * @param v to insert.
 *
 * @hidecallergraph
 */
static inline void CC_HINT(hot) fr_dcursor_prepend(fr_dcursor_t *cursor, void *v)
{
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->dlist->type) _talloc_get_type_abort(v, cursor->dlist->type, __location__);
#endif

	/*
	 *	Insert at the head of the list
	 */
	fr_dlist_insert_head(cursor->dlist, v);

	/*
	 *	Set previous if the cursor was already set but not
	 *	prev - this will be if there was only one item in the
	 *	list
	 */
	if (cursor->current && !cursor->prev) {
		cursor->prev = v;
	}
}

/** Insert a single item at the end of the list
 *
 * @note Does not change the current pointer.
 *
 * @param[in] cursor to operate on.
 * @param[in] v to insert.
 *
 * @hidecallergraph
 */
static inline void CC_HINT(hot) fr_dcursor_append(fr_dcursor_t *cursor, void *v)
{
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->dlist->type) _talloc_get_type_abort(v, cursor->dlist->type, __location__);
#endif

	fr_dlist_insert_tail(cursor->dlist, v);
}

/** Insert directly after the current item
 *
 * @note Does not change the current pointer.
 *
 * @param[in] cursor	to operate on.
 * @param[in] v		Item to insert.
 *
 * @hidecallergraph
 */
static inline void fr_dcursor_insert(fr_dcursor_t *cursor, void *v)
{
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->dlist->type) _talloc_get_type_abort(v, cursor->dlist->type, __location__);
#endif

	if (!cursor->current) {
		fr_dcursor_append(cursor, v);
		return;
	}
	fr_dlist_insert_after(cursor->dlist, cursor->current, v);
}

/** Remove the current item
 *
 * The current item will be set to the one after the item
 * being removed. An example check and remove loop:
 *
 @code {.c}
   for (v = fr_dcursor_init(&cursor, head);
        v;
        v = fr_dcursor_current(&cursor) {
        if (<condition>) {
            v = fr_dcursor_remove(&cursor);
            talloc_free(v);
            continue;
        }
        v = fr_dcursor_next(&cursor);
   }
 @endcode
 *
 * @param[in] cursor to remove the current item from.
 * @return
 *	- item we just removed.
 *	- NULL on error.
 *
 * @hidecallergraph
 */
static inline void * CC_HINT(hot) fr_dcursor_remove(fr_dcursor_t *cursor)
{
	void *v, *p;

	if (!cursor->current) return NULL;			/* don't do anything fancy, it's just a noop */

	v = cursor->current;
	p = fr_dcursor_list_prev_peek(cursor);
	fr_dlist_remove(cursor->dlist, v);

	if (fr_dlist_head(cursor->dlist) == v) {
		cursor->current = NULL;
		cursor->prev = NULL;
	} else {
		cursor->current = p;
		cursor->prev = p;
	}

	/*
	 *	Advance the cursor to the next item after the one which we just removed.
	 */
	cursor->current = dcursor_next(cursor, cursor->current);
	return v;
}

/** Moves items from one cursor to another.
 *
 * Move multiple items from one cursor to another.
 *
 * @note Will only move items from the current position of to_append
 *	up to the end of to_append. Items will be removed from the original
 *	cursor.  Items will be inserted after the current position of the
 *	destination cursor (which will not be changed).
 *
 * @param[in] cursor		to operate on.
 * @param[in] to_append		Items to append.
 *
 * @hidecallergraph
 */
static inline void fr_dcursor_merge(fr_dcursor_t *cursor, fr_dcursor_t *to_append)
{
	void		*v, *p;

	p = cursor->current;
	while ((v = fr_dcursor_remove(to_append))) {
		fr_dcursor_insert(cursor, v);
		cursor->current = v;
	}
	cursor->current = p;
}

/** Return the next item, skipping the current item, that satisfies an evaluation function.
 *
 * @param[in] cursor	to operate on
 * @param[in] eval	evaluation function
 * @param[in] uctx	context for the evaluation function
 * @return the next item satisfying eval, or NULL if no such item exists
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_filter_next(fr_dcursor_t *cursor, fr_dcursor_eval_t eval, void const *uctx)
{
	void *item;

	do {
		item = fr_dcursor_next(cursor);
	} while (item && !eval(item, uctx));

	return item;
}

/** Return the first item that satisfies an evaluation function.
 *
 * @param[in] cursor	to operate on
 * @param[in] eval	evaluation function
 * @param[in] uctx	context for the evaluation function
 * @return the first item satisfying eval, or NULL if no such item exists
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_filter_head(fr_dcursor_t *cursor, fr_dcursor_eval_t eval, void const *uctx)
{
	void *item;

	item = fr_dcursor_head(cursor);
	if (eval(item, uctx)) return item;

	return fr_dcursor_filter_next(cursor, eval, uctx);
}

/** Return the next item, starting with the current item, that satisfies an evaluation function.
 *
 * @param[in] cursor    to operate on
 * @param[in] eval      evaluation function
 * @param[in] uctx	context for the evaluation function
 * @return the next item satisfying eval, or NULL if no such item exists
 *
 * @hidecallergraph
 */
static inline void *fr_dcursor_filter_current(fr_dcursor_t *cursor, fr_dcursor_eval_t eval, void const *uctx)
{
        void *item;

        while ((item = fr_dcursor_current(cursor)) && !eval(item, uctx)) {
		fr_dcursor_next(cursor);
	}

        return item;
}

/** @hidecallergraph */
void *fr_dcursor_intersect_head(fr_dcursor_t *a, fr_dcursor_t *b) CC_HINT(nonnull);

/** @hidecallergraph */
void *fr_dcursor_intersect_next(fr_dcursor_t *a, fr_dcursor_t *b) CC_HINT(nonnull);

/** Replace the current item
 *
 * After replacing the current item, the cursor will be rewound,
 * and the next item selected by the iterator function will become current.
 *
 * @param[in] cursor	to replace the current item in.
 * @param[in] r		item to insert.
 * @return
 *	- item we just replaced.
 *	- NULL on error.
 *
 * @hidecallergraph
 */
static inline void * CC_HINT(hot) fr_dcursor_replace(fr_dcursor_t *cursor, void *r)
{
	void *v, *p;

	/*
	 *	Correct behaviour here is debatable
	 */
	if (fr_dlist_empty(cursor->dlist)) {
		fr_dcursor_prepend(cursor, r);
		return NULL;
	}

	/*
	 *	If there's a head, but no current,
	 *	we've iterated off the end of the list,
	 *	so the replace becomes an append.
	 */
	v = cursor->current;
	if (!v) {
		fr_dcursor_append(cursor, r);
		return NULL;
	}
	p = fr_dcursor_list_prev_peek(cursor);

	fr_dlist_replace(cursor->dlist, cursor->current, r);
	
	/*
	 *	Fixup current pointer.
	 */
	cursor->current = p;

	/*
	 *	re-advance the cursor.
	 *
	 *	This ensures if the iterator skips the item
	 *	we just replaced, it doesn't become current.
	 */
	fr_dcursor_next(cursor);

	return v;
}

/** Free the current item and all items after it
 *
 * @note Use fr_dcursor_remove and talloc_free to free single items.
 *
 * Current should be the item *after* the one freed.
 *
 * @param[in] cursor to free items in.
 *
 * @hidecallergraph
 */
static inline void fr_dcursor_free_list(fr_dcursor_t *cursor)
{
	void *v;

	if (fr_dlist_empty(cursor->dlist)) return;	/* noop */

	do {
		v = fr_dcursor_remove(cursor);
		talloc_free(v);
	} while (v);
}

/** Initialise a cursor with runtime talloc type safety checks and a custom iterator
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _iter	function.
 * @param[in] _uctx	_iter function _uctx.
 * @param[in] _type	Talloc type i.e. fr_pair_t or fr_value_box_t.
 * @return
 *	- NULL if _head does not point to any items, or the iterator matches no items
 *	  in the current list.
 *	- The first item returned by the iterator.
 */
#define fr_dcursor_talloc_iter_init(_cursor, _head, _iter, _uctx, _type) \
	_fr_dcursor_init(_cursor, (fr_dlist_head_t const *)_head, _iter, NULL, NULL, _uctx)

/** Initialise a cursor with a custom iterator
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _iter	function.
 * @param[in] _uctx	_iter function _uctx.
 * @return
 *	- NULL if _head does not point to any items, or the iterator matches no items
 *	  in the current list.
 *	- The first item returned by the iterator.
 */
#define fr_dcursor_iter_init(_cursor, _head, _iter, _uctx) \
	_fr_dcursor_init(_cursor, (fr_dlist_head_t *)_head, _iter, NULL, NULL, _uctx)

/** Initialise a cursor with runtime talloc type safety checks
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _type	Talloc type i.e. fr_pair_t or fr_value_box_t.
 * @return
 *	- NULL if _head does not point to any items.
 *	- The first item in the list.
 */
#define fr_dcursor_talloc_init(_cursor, _head, _type) \
	_fr_dcursor_init(_cursor, (fr_dlist_head_t const *)_head, NULL, NULL, NULL, NULL)

/** Initialise a cursor
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @return
 *	- NULL if _head does not point to any items.
 *	- The first item in the list.
 */
#define fr_dcursor_init(_cursor, _head) \
	_fr_dcursor_init(_cursor, (fr_dlist_head_t const *)_head, NULL, NULL, NULL, NULL)

/** Setup a cursor to iterate over attribute items in dlists
 *
 * @param[in] cursor	Where to initialise the cursor (uses existing structure).
 * @param[in] head	of dlist.
 * @param[in] iter	Iterator callback.
 * @param[in] insert	Callback for inserts.
 * @param[in] delete	Callback for removals.
 * @param[in] uctx	to pass to iterator function.
 * @return the attribute pointed to by v.
 *
 * @hidecallergraph
 */
static inline void * CC_HINT(hot) _fr_dcursor_init(fr_dcursor_t *cursor, fr_dlist_head_t const *head,
				     fr_dcursor_iter_t iter, fr_dcursor_insert_t insert,
				     fr_dcursor_delete_t delete, void const *uctx)
{
	fr_dlist_head_t *v;

	memcpy(&v, &head, sizeof(v));			/* stupid const hacks */
	*cursor = (fr_dcursor_t){
		.dlist = v,
		.iter = iter,
		.insert = insert,
		.delete = delete,
		.prev = NULL
	};
	memcpy(&cursor->uctx, &uctx, sizeof(cursor->uctx));
	if (!fr_dlist_empty(cursor->dlist)) return fr_dcursor_next(cursor);	/* Initialise current */

	return NULL;
}

/** talloc_free the current item
 *
 * @param[in] cursor	to free items from.
 */
static inline void fr_dcursor_free_item(fr_dcursor_t *cursor)
{
	if (!cursor) return;

	talloc_free(fr_dcursor_remove(cursor));
}

/** Allocate a stack of cursors for traversing trees
 *
 * @param[in] ctx	to allocate the cursor stack in.
 * @param[in] depth	Maximum depth of the cursor stack.
 * @return
 *	- A new cursor stack.
 *	- NULL on error.
 */
static inline fr_dcursor_stack_t *fr_dcursor_stack_alloc(TALLOC_CTX *ctx, uint8_t depth)
{
	fr_dcursor_stack_t *stack;

	stack = talloc_array_size(ctx, sizeof(fr_dcursor_stack_t) + (sizeof(fr_dcursor_t) * depth), 1);
	if (unlikely(!stack)) return NULL;

	talloc_set_name_const(stack, "fr_dcursor_stack_t");

	return stack;
}

#ifdef __cplusplus
}
#endif
