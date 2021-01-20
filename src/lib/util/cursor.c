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

/** Functions to iterate over a sets and subsets of items
 *
 * @file src/lib/util/cursor.c
 *
 * @note Do not modify collections of items pointed to by a cursor
 *	 with none fr_cursor_* functions over the lifetime of that cursor.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2016 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include <talloc.h>
#include <string.h>
#include <stdint.h>
#include <freeradius-devel/util/cursor.h>

#define NEXT_PTR(_v) ((void **)(((uint8_t *)(_v)) + cursor->offset))

/** Internal function to get the next item
 *
 * @param[in,out] prev	attribute to the one we returned.  May be NULL.
 * @param[in] cursor	to operate on.
 * @param[in] current	attribute.
 * @return
 *	- The next attribute.
 *	- NULL if no more attributes.
 */
static inline void *cursor_next(void **prev, fr_cursor_t *cursor, void *current)
{
	void *unused = NULL;
	void *next;

	if (!prev) prev = &unused;

	/*
	 *	First time next has been called
	 */
	if (!current) {
		if (!*(cursor->head)) return NULL;
		if (cursor->prev) return NULL;				/* At tail of the list */
		if (!cursor->iter) return (*cursor->head);		/* Fast path without custom iter */

		current = *cursor->head;
		return cursor->iter(prev, current, cursor->uctx);
	}

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->type) _talloc_get_type_abort(current, cursor->type, __location__);
#endif

	if (!cursor->iter) {
		next = *NEXT_PTR(current);				/* Fast path without custom iter */
		if (prev) *prev = current;

		return next;
	}

	/*
	 *	Pre-advance prev and current
	 */
	*prev = current;
	next = *NEXT_PTR(current);

	/*
	 *	The iterator can just return what it was passed for curr
	 *	and leave prev untouched if it just wants to advance by one.
	 */
	next = cursor->iter(prev, next, cursor->uctx);
	return next;
}

/** Internal function to get the last attribute
 *
 * @param[in,out] prev	attribute to the one we returned.  May be NULL.
 * @param[in] cursor	to operate on.
 * @param[in] current	attribute.
 * @return the last attribute.
 */
static inline void *cursor_tail(void **prev, fr_cursor_t *cursor, void *current)
{
	void *v, *nv, *p, *np;
	void *unused = NULL;

	if (!prev) prev = &unused;
	if (current) {
		nv = v = current;
		np = p = *prev;
	/*
	 *	When hunting for the tail we're allowed
	 *	to wrap around to the start of the list.
	 */
	} else {
		nv = v = *cursor->head;
		np = p = NULL;
	}

	while ((nv = cursor_next(&np, cursor, nv))) {
		v = nv;		/* Wind to the end */
		p = np;
	}

	*prev = p;

	return v;
}

/** Copy cursor parameters and state.
 *
 * @param[out] out	Where to copy the cursor to.
 * @param[in] in	cursor to copy.
 *
 * @hidecallergraph
 */
void fr_cursor_copy(fr_cursor_t *out, fr_cursor_t const *in)
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
void *fr_cursor_head(fr_cursor_t *cursor)
{
	if (unlikely(!cursor)) return NULL;

	/*
	 *	If we have a custom iterator, the head attribute
	 *	may not be in the subset the iterator would
	 *	return, so set everything to NULL and have
	 *	cursor_next figure it out.
	 */
	if (cursor->iter) {
		cursor->prev = NULL;
		cursor->current = cursor_next(&cursor->prev, cursor, NULL);
		return cursor->current;
	}

	cursor->current = *cursor->head;
	cursor->prev = NULL;

	return cursor->current;
}

/** Wind cursor to the tail item in the list
 *
 * @param[in] cursor	to operate on.
 * @return item at the end of the list.
 *
 * @hidecallergraph
 */
void *fr_cursor_tail(fr_cursor_t *cursor)
{
	if (!cursor || !*cursor->head) return NULL;

	cursor->current = cursor_tail(&cursor->prev, cursor, cursor->current);
	cursor->tail = cursor->current;				/* my as well update our insertion tail */

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
void * CC_HINT(hot) fr_cursor_next(fr_cursor_t *cursor)
{
	if (!cursor || !*cursor->head) return NULL;

	cursor->current = cursor_next(&cursor->prev, cursor, cursor->current);

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
void *fr_cursor_next_peek(fr_cursor_t *cursor)
{
	return cursor_next(NULL, cursor, cursor->current);
}

/** Returns the next list item without advancing the cursor
 *
 * @note This returns the next item in the list, which may not match the
 *	next iterator value.  It's mostly used for debugging.  You probably
 *	want #fr_cursor_next_peek.
 *
 * @param[in] cursor to operator on.
 * @return
 *	- Next item in list.
 *	- NULL if the list is empty, or the cursor has advanced past the end of the list.
 *
 * @hidecallergraph
 */
 void *fr_cursor_list_next_peek(fr_cursor_t *cursor)
{
	if (!cursor || !cursor->current) return NULL;

	return *NEXT_PTR(cursor->current);
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
void *fr_cursor_list_prev_peek(fr_cursor_t *cursor)
{
	if (unlikely(!cursor)) return NULL;

	return cursor->prev;
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
void * CC_HINT(hot) fr_cursor_current(fr_cursor_t *cursor)
{
	if (unlikely(!cursor)) return NULL;

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
void CC_HINT(hot) fr_cursor_prepend(fr_cursor_t *cursor, void *v)
{
	void *old;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->type) _talloc_get_type_abort(v, cursor->type, __location__);
#endif

	/*
	 *	Cursor was initialised with a pointer to a NULL item
	 */
	if (!*(cursor->head)) {
		*cursor->head = v;
		cursor->tail = *cursor->head;

		*NEXT_PTR(v) = NULL;				/* Only insert one at a time */

		return;
	}

	/*
	 *	Insert at the head of the list
	 */
	old = *(cursor->head);
	*cursor->head = v;
	*NEXT_PTR(v) = old;

	if (!cursor->prev) cursor->prev = v;
}

/** Insert a single item at the end of the list
 *
 * @param[in] cursor to operate on.
 * @param[in] v to insert.
 *
 * @hidecallergraph
 */
void CC_HINT(hot) fr_cursor_append(fr_cursor_t *cursor, void *v)
{
	void *old;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->type) _talloc_get_type_abort(v, cursor->type, __location__);
#endif

	/*
	 *	Cursor was initialised with a pointer to a NULL item
	 */
	if (!*(cursor->head)) {
		*cursor->head = v;
		*NEXT_PTR(v) = NULL;				/* Only insert one at a time */

		return;
	}

	/*
	 *	Wind to the end (not updating current)
	 */
	cursor->tail = cursor_tail(NULL, cursor, cursor->tail);

	/*
	 *	Some weirdness here... The intent of the iterator functions
	 *	is to iterate over subsets of the list.
	 *
	 *	This means although fr_cursor_tail has wound to the end of
	 *	this subset of the list, there could still be items *after*
	 *	the end of this subset, so we still need to link them in.
	 */
	old = *NEXT_PTR(cursor->tail);
	*NEXT_PTR(cursor->tail) = v;
	*NEXT_PTR(v) = old;

	cursor->tail = v;
}

/** Insert directly after the current item
 *
 * @param[in] cursor	to operate on.
 * @param[in] v		Item to insert.
 *
 * @hidecallergraph
 */
void fr_cursor_insert(fr_cursor_t *cursor, void *v)
{
	void *old;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (cursor->type) _talloc_get_type_abort(v, cursor->type, __location__);
#endif

	if (!cursor->current) {
		fr_cursor_append(cursor, v);
		return;
	}

	old = *NEXT_PTR(cursor->current);
	*NEXT_PTR(cursor->current) = v;
	*NEXT_PTR(v) = old;

	if (cursor->tail == cursor->current) cursor->tail = v;	/* Advance the tail */
}

/** Appends items from one cursor to another.
 *
 * Append multiple items from one cursor to another.
 *
 * @note Will only append items from the current position of to_append
 *	to the end of to_append. Items will be removed from the original
 *	cursor.
 *
 * @param[in] cursor		to operate on.
 * @param[in] to_append		Items to append.
 *
 * @hidecallergraph
 */
void fr_cursor_merge(fr_cursor_t *cursor, fr_cursor_t *to_append)
{
	void		*head = NULL, *next, *v;

	/*
	 *	Build the complete list (in reverse)
	 */
	while ((v = fr_cursor_remove(to_append))) {
		*NEXT_PTR(v) = head;
		head = v;
	}

	if (!head) return;

	/*
	 *	Now insert - The elements end up in
	 *	the correct order without advancing
	 *	the cursor.
	 */
	v = head;
	if (cursor->current) {
		do {
			next = *NEXT_PTR(v);
			fr_cursor_insert(cursor, v);
		} while ((v = next));
	} else {
		do {
			next = *NEXT_PTR(v);
			fr_cursor_prepend(cursor, v);
		} while ((v = next));
	}
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
void *fr_cursor_filter_head(fr_cursor_t *cursor, fr_cursor_eval_t eval, void const *uctx)
{
	void *item;

	item = fr_cursor_head(cursor);
	if (eval(item, uctx)) return item;

	return fr_cursor_filter_next(cursor, eval, uctx);
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
void *fr_cursor_filter_next(fr_cursor_t *cursor, fr_cursor_eval_t eval, void const *uctx)
{
	void *item;

	do {
		item = fr_cursor_next(cursor);
	} while (item && !eval(item, uctx));

	return item;
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
void *fr_cursor_filter_current(fr_cursor_t *cursor, fr_cursor_eval_t eval, void const *uctx)
{
        void *item;

        while ((item = fr_cursor_current(cursor)) && !eval(item, uctx)) {
		fr_cursor_next(cursor);
	}

        return item;
}


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
void *fr_cursor_intersect_head(fr_cursor_t *a, fr_cursor_t *b)
{
	void *a_item, *b_item;

	if (unlikely(a->head != b->head)) return NULL;

	a_item = fr_cursor_head(a);
	b_item = fr_cursor_head(b);

	if (a_item == b_item) return a_item;

	return fr_cursor_intersect_next(a, b);
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
void *fr_cursor_intersect_next(fr_cursor_t *a, fr_cursor_t *b)
{
	fr_cursor_iter_t	b_iter;
	void			*b_uctx;

	if (unlikely(a->head != b->head)) return NULL;

	/*
	 *	If either of the iterators lack an iterator
	 *	just use cursor_next...
	 */
	if (!a->iter) return fr_cursor_next(b);
	if (!b->iter) return fr_cursor_next(a);

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
		fr_cursor_head(b);	/* reset */
	} else {
		a->current = cursor_next(&a->prev, a, a->current);
	}

	/*
	 *	Use a's iterator to select the item to
	 *	check.
	 */
	do {
		b->iter = NULL;		/* Disable b's iterator */

		/*
		 *	Find a in b (the slow way *sigh*)
		 */
		while ((b->current = cursor_next(&b->prev, b, b->current)) && (b->current != a->prev));

		/*
		 *	No more items...
		 */
		if (!b->current) {
			fr_cursor_copy(a, b);
			return NULL;
		}

		/*
		 *	We're now one item before the item
		 *	returned by a, see if b's iterator
		 *	returns the same item as a's.
		 */
		 b->iter = b_iter;
		 b->current = cursor_next(&b->prev, b, b->current);

		/*
		 *	Matched, we're done...
		 */
		if (a->current == b->current) return a->current;

		/*
		 *	Reset b's position to a's and try again.
		 */
		fr_cursor_copy(b, a);
		b->iter = b_iter;
		b->uctx = b_uctx;
	} while ((a->current = cursor_next(&a->prev, a, a->current)));

	return NULL;
}

/** Remove the current item
 *
 * The current item will be set to the one after the item
 * being removed. An example check and remove loop:
 *
 @code {.c}
   for (v = fr_cursor_init(&cursor, head);
        v;
        v = fr_cursor_current(&cursor) {
        if (<condition>) {
            v = fr_cursor_remove(&cursor);
            talloc_free(v);
            continue;
        }
        v = fr_cursor_next(&cursor);
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
void * CC_HINT(hot) fr_cursor_remove(fr_cursor_t *cursor)
{
	void *v, *p;

	if (!cursor->current) return NULL;			/* don't do anything fancy, it's just a noop */

	v = cursor->current;
	p = cursor->prev;

	if (*cursor->head == v) {
		*cursor->head = *NEXT_PTR(v);			/* at the start (make next head)*/
		cursor->current = NULL;
	} else {
		*NEXT_PTR(p) = *NEXT_PTR(v);			/* in the middle/end (unlink) */
		cursor->current = p;
	}
	cursor->prev = NULL;

	/*
	 *	Fixup append pointer.
	 */
	if (cursor->tail == v) {
		void *n;

		n = cursor_next(NULL, cursor, v);
		if (n) {
			cursor->tail = n;			/* advance tail to the one we removed */
		} else if (p) {
			cursor->tail = p;			/* if the one we removed was the end, tail is prev */
		} else {
			cursor->tail = *(cursor->head);		/* if no prev, tail is set to head (wrap) */
		}
	}

	/*
	 *	Advance the cursor to the next item after the one which we just removed.
	 */
	cursor->current = cursor_next(&cursor->prev, cursor, cursor->current);

	/*
	 *	Set v->next to NULL
	 */
	*NEXT_PTR(v) = NULL;

	return v;
}

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
void * CC_HINT(hot) fr_cursor_replace(fr_cursor_t *cursor, void *r)
{
	void *v, *p;

	/*
	 *	Correct behaviour here is debatable
	 */
	if (!*cursor->head) {
		fr_cursor_prepend(cursor, r);
		return NULL;
	}

	/*
	 *	If there's a head, but no current,
	 *	we've iterated off the end of the list,
	 *	so the replace becomes an append.
	 */
	v = cursor->current;
	if (!v) {
		fr_cursor_append(cursor, r);
		return NULL;
	}
	p = cursor->prev;

	/*
	 *	Item at the head of the list.
	 */
	if (*cursor->head == v) {
		*cursor->head = r;
		*NEXT_PTR(r) = *NEXT_PTR(v);
	} else {
		*NEXT_PTR(p) = r;
		*NEXT_PTR(r) = *NEXT_PTR(v);
	}

	/*
	 *	Fixup current pointer.
	 */
	cursor->current = p;
	cursor->prev = NULL;				/* populated on next call to fr_cursor_next */

	/*
	 *	Fixup tail pointer.
	 */
	if (cursor->tail == v) cursor->tail = r;		/* set tail to the replacement */

	/*
	 *	re-advance the cursor.
	 *
	 *	This ensures if the iterator skips the item
	 *	we just replaced, it doesn't become current.
	 */
	fr_cursor_next(cursor);

	/*
	 *	Set v->next to NULL
	 */
	*NEXT_PTR(v) = NULL;

	return v;
}

/** Free the current item and all items after it
 *
 * @note Use fr_cursor_remove and talloc_free to free single items.
 *
 * Current should be the item *after* the one freed.
 *
 * @param[in] cursor to free items in.
 *
 * @hidecallergraph
 */
void fr_cursor_free_list(fr_cursor_t *cursor)
{
	void *v;

	if (!*(cursor->head)) return;	/* noop */

	do {
		v = fr_cursor_remove(cursor);
		talloc_free(v);
	} while (v);
}

/** Setup a cursor to iterate over attribute items
 *
 * @param[in] cursor	Where to initialise the cursor (uses existing structure).
 * @param[in] head	to start from.
 * @param[in] offset	offsetof next ptr in the structure we're iterating over.
 * @param[in] iter	Iterator callback.
 * @param[in] uctx	to pass to iterator function.
 * @param[in] type	if iterating over talloced memory.
 * @return the attribute pointed to by v.
 *
 * @hidecallergraph
 */
void * CC_HINT(hot) _fr_cursor_init(fr_cursor_t *cursor, void * const *head, size_t offset,
				    fr_cursor_iter_t iter, void const *uctx, char const *type)
{
	void **v;

	memcpy(&v, &head, sizeof(v));			/* stupid const hacks */
	*cursor = (fr_cursor_t){
		.head = v,
		.tail = *v,
		.iter = iter,
		.offset = offset,
		.type = type
	};
	memcpy(&cursor->uctx, &uctx, sizeof(cursor->uctx));

	if (*head) return fr_cursor_next(cursor);	/* Initialise current */

	return NULL;
}
