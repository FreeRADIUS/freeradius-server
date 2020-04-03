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
		return cursor->iter(prev, current, cursor->ctx);
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
	next = cursor->iter(prev, next, cursor->ctx);
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
 */
void fr_cursor_copy(fr_cursor_t *out, fr_cursor_t const *in)
{
	memcpy(out, in, sizeof(*out));
}

/** Rewind cursor to the start of the list
 *
 * @param[in] cursor	to operate on.
 * @return item at the start of the list.
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
 */
void *fr_cursor_intersect_next(fr_cursor_t *a, fr_cursor_t *b)
{
	fr_cursor_iter_t b_iter;

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
 * @param[in] ctx	to pass to iterator function.
 * @param[in] type	if iterating over talloced memory.
 * @return the attribute pointed to by v.
 */
void * CC_HINT(hot) _fr_cursor_init(fr_cursor_t *cursor, void * const *head, size_t offset,
				    fr_cursor_iter_t iter, void const *ctx, char const *type)
{
	void **v;

	memcpy(&v, &head, sizeof(v));			/* stupid const hacks */

	cursor->head = v;
	cursor->tail = *v;
	cursor->prev = cursor->current = NULL;
	cursor->iter = iter;
	cursor->offset = offset;
	cursor->type = type;
	memcpy(&cursor->ctx, &ctx, sizeof(cursor->ctx));

	if (*head) return fr_cursor_next(cursor);	/* Initialise current */

	return NULL;
}

#ifdef TESTING_CURSOR
/*
 *  cc cursor.c -g3 -Wall -DTESTING_CURSOR -I../../ -I../ -include ../include/build.h -l talloc -o test_cursor && ./test_cursor
 */
#include <stddef.h>
#include <freeradius-devel/util/acutest.h>

typedef struct {
	char const *name;
	void *next;
} test_item_t;

static void *test_iter(void **prev, void *current, void *ctx)
{
	return current;
}

/** Verify internal state is initialised correctly
 *
 */
void test_init_null_item(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	*head = NULL;

	item_p = fr_cursor_iter_init(&cursor, &head, test_iter, &cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK((*cursor.head) == head);
	TEST_CHECK(!cursor.tail);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor));
	TEST_CHECK(cursor.ctx == &cursor);
}

void test_init_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	item_p = fr_cursor_init(&cursor, &head);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK((*cursor.head) == head);
	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

void test_init_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	item_p = fr_cursor_init(&cursor, &head);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

void test_next(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
}

void test_next_wrap(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
}

void test_cursor_head_tail_null(void)
{
	fr_cursor_t	cursor;
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
}

void test_cursor_head(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

void test_cursor_head_after_next(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

void test_cursor_tail(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
}

void test_cursor_head_after_tail(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_tail(&cursor);
	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

void test_cursor_wrap_after_tail(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_tail(&cursor);
	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);
}

void test_cursor_append_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

void test_cursor_append_empty_3(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item1);
	fr_cursor_append(&cursor, &item2);
	fr_cursor_append(&cursor, &item3);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next(&cursor) == &item2);
	TEST_CHECK(fr_cursor_tail(&cursor) == &item3);
}

void test_cursor_prepend_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_prepend(&cursor, &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

void test_cursor_insert_into_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

void test_cursor_insert_into_empty_3(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item1);
	fr_cursor_insert(&cursor, &item2);
	fr_cursor_insert(&cursor, &item3);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next(&cursor) == &item2);
	TEST_CHECK(fr_cursor_tail(&cursor) == &item3);
}

void test_cursor_replace_in_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	TEST_CHECK(!fr_cursor_replace(&cursor, &item1));

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

void test_cursor_prepend_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_prepend(&cursor, &item2);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);	/* Inserted before item 1 */

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item1);
}

void test_cursor_append_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item2);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

void test_cursor_insert_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item2);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

void test_cursor_replace_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_replace(&cursor, &item2);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item2);

	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

void test_cursor_prepend_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_prepend(&cursor, &item3);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

void test_cursor_append_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item3);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

void test_cursor_insert_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item3);

	/*
	 *	Order should be
	 *
	 *	item1 -	HEAD
	 *	item3
	 *	item2 - TAIL
	 */
	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

void test_cursor_replace_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	/*
	 *	Order should be
	 *
	 *	item3 -	HEAD
	 *	item2 - TAIL
	 */
	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_replace(&cursor, &item3);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item3);

	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

void test_cursor_prepend_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_prepend(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

void test_cursor_append_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_append(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

void test_cursor_insert_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_insert(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item4);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

void test_cursor_replace_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_replace(&cursor, &item4);
	TEST_CHECK(item_p == &item2);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item4);

	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

void test_cursor_prepend_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	fr_cursor_prepend(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

void test_cursor_append_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	fr_cursor_append(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

void test_cursor_insert_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	fr_cursor_insert(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item4);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

void test_cursor_replace_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_replace(&cursor, &item4);
	TEST_CHECK(item_p == &item3);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item4);

	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

void test_cursor_remove_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	*head = NULL;

	item_p = _fr_cursor_init(&cursor, (void **)&head, offsetof(test_item_t, next), test_iter, &cursor, NULL);
	TEST_CHECK(!fr_cursor_remove(&cursor));
}

void test_cursor_remove_1i(void)
{
	fr_cursor_t	cursor;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);

	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
}

void test_cursor_remove_2i(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_remove(&cursor);

	TEST_CHECK(item_p == &item1);
	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next(&cursor));
	TEST_CHECK(fr_cursor_tail(&cursor) == &item2);
	TEST_CHECK(fr_cursor_head(&cursor) == &item2);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);

	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
}

void test_cursor_remove_3i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);

	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
}

void test_cursor_remove_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);

	/*
	 *	We just removed the end of the list
	 *	so current is now NULL.
	 *
	 *	We don't implicitly start moving backwards.
	 */
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(!item_p);

	TEST_CHECK(fr_cursor_tail(&cursor) == &item1);
	TEST_CHECK(fr_cursor_head(&cursor) == &item1);
}

void test_cursor_remove_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_tail(&cursor);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(!item_p);

	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
}

void test_cursor_merge_start_a_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	First item in cursor_a remains unchanged
	 *
	 *	The insertion point into cursor_a is
	 *	directly after the current item.
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next three items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	With the final two from cursor_a
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

void test_cursor_merge_mid_a(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_next(&cursor_a);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	Should be second item in cursor a
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next three items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Final item should be from cursor a
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

void test_cursor_merge_end_a(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_tail(&cursor_a);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	Should be final item in cursor_a
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next three items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Should be no more items...
	 */
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_a));
	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

void test_cursor_merge_mid_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_next(&cursor_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	First item in cursor_a remains unchanged
	 *
	 *	The insertion point into cursor_a is
	 *	directly after the current item.
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next two items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next two items should be from cursor_a
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor_b) == &item1b);
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

void test_cursor_merge_end_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_next(&cursor_b);
	fr_cursor_next(&cursor_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	First item in cursor_a remains unchanged
	 *
	 *	The insertion point into cursor_a is
	 *	directly after the current item.
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next item should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);

	/*
	 *	Next two items should be from cursor_a
	 */
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor_b) == &item2b);
	TEST_CHECK(fr_cursor_head(&cursor_b) == &item1b);
}

void test_cursor_merge_with_empty(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	*head_a = NULL;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(fr_cursor_head(&cursor_a) == &item1b);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

void test_cursor_merge_empty(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = NULL;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(fr_cursor_head(&cursor_a) == &item1a);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
}

void test_cursor_copy(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };

	test_item_t	*head = &item1;

	fr_cursor_init(&cursor_a, &head);
	fr_cursor_copy(&cursor_b, &cursor_a);

	TEST_CHECK(fr_cursor_head(&cursor_b) == &item1);
	TEST_CHECK(fr_cursor_next(&cursor_b) == &item2);
	TEST_CHECK(fr_cursor_next(&cursor_b) == &item3);
}

void test_cursor_free(void)
{
	test_item_t	*item1, *item2, *item3;
	test_item_t	*head = NULL;
	fr_cursor_t	cursor;
	void		*item_p;

	item1 = talloc_zero(NULL, test_item_t);
	item2 = talloc_zero(NULL, test_item_t);
	item3 = talloc_zero(NULL, test_item_t);

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, item1);
	fr_cursor_append(&cursor, item2);
	fr_cursor_append(&cursor, item3);

	fr_cursor_next(&cursor);
	fr_cursor_free_list(&cursor);

	TEST_CHECK(fr_cursor_current(&cursor) == NULL);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));

	item_p = fr_cursor_remove(&cursor);
	talloc_free(item_p);
}

typedef struct {
	int	pos;
	char	val;
} item_filter;

void *iter_name_check(void **prev, void *to_eval, void *uctx)
{
	test_item_t	*c, *p;
	item_filter	*f = uctx;

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		if (c->name[f->pos] == f->val) break;
	}

	*prev = p;

	return c;
}

void test_intersect_differing_lists(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item2 = {"item2", NULL};
	test_item_t	item1 = {"item1", NULL};
	test_item_t	*head_a = &item1;
	test_item_t	*head_b = &item2;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == NULL);
}

void test_intersect_no_iterators(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor_a, &head);
	fr_cursor_init(&cursor_b, &head);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item2);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

void test_intersect_iterator_a(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item4 = { "after", NULL };
	test_item_t	item3 = { "extra", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "actor", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_a = { 0, 'a' };

	fr_cursor_iter_init(&cursor_a, &head, iter_name_check, &filter_a);
	fr_cursor_init(&cursor_b, &head);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item2);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item4);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

void test_intersect_iterator_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item4 = { "bland", NULL };
	test_item_t	item3 = { "basic", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "blink", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_b = { 0, 'b'};

	fr_cursor_init(&cursor_a, &head);
	fr_cursor_iter_init(&cursor_b, &head, iter_name_check, &filter_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item4);
}

void test_intersect_iterator_ab(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item5 = { "bland", NULL };
	test_item_t	item4 = { "cavil", &item5 };
	test_item_t	item3 = { "basic", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "baits", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_a = { 1, 'a' };
	item_filter	filter_b = { 0, 'b' };

	fr_cursor_iter_init(&cursor_a, &head, iter_name_check, &filter_a);
	fr_cursor_iter_init(&cursor_b, &head, iter_name_check, &filter_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

void test_intersect_iterator_disjoint(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item5 = { "bland", NULL };
	test_item_t	item4 = { "cavil", &item5 };
	test_item_t	item3 = { "basic", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "baits", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_a = { 0, 'a' };
	item_filter	filter_b = { 0, 'b' };

	fr_cursor_iter_init(&cursor_a, &head, iter_name_check, &filter_a);
	fr_cursor_iter_init(&cursor_b, &head, iter_name_check, &filter_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == NULL);
}

TEST_LIST = {
	/*
	 *	Initialisation
	 */
	{ "init_null",			test_init_null_item },
	{ "init_one",			test_init_1i_start },
	{ "init_two",			test_init_2i_start },

	/*
	 *	Normal iteration
	 */
	{ "next",			test_next },
	{ "next_wrap",			test_next_wrap },	/* should not wrap */

	/*
	 *	Jump to head/tail
	 */
	{ "head_tail_null",		test_cursor_head_tail_null },
	{ "head",			test_cursor_head },
	{ "head_after_next",		test_cursor_head_after_next },
	{ "tail",			test_cursor_tail },
	{ "head_after_tail",		test_cursor_head_after_tail },
	{ "wrap_after_tail",		test_cursor_wrap_after_tail },

	/*
	 *	Insert with empty list
	 */
	{ "prepend_empty",		test_cursor_prepend_empty },
	{ "append_empty",		test_cursor_append_empty },
	{ "append_empty_3",		test_cursor_append_empty_3 },
	{ "insert_into_empty",		test_cursor_insert_into_empty },
	{ "insert_into_empty_3",	test_cursor_insert_into_empty_3 },
	{ "replace_in_empty",		test_cursor_replace_in_empty },

	/*
	 *	Insert with one item list
	 */
	{ "prepend_1i_start",		test_cursor_prepend_1i_start},
	{ "append_1i_start",		test_cursor_append_1i_start },
	{ "insert_1i_start",		test_cursor_insert_1i_start },
	{ "replace_1i_start",		test_cursor_replace_1i_start },

	/*
	 *	Insert with two item list
	 */
	{ "prepend_2i_start",		test_cursor_prepend_2i_start },
	{ "append_2i_start",		test_cursor_append_2i_start },
	{ "insert_2i_start",		test_cursor_insert_2i_start },
	{ "replace_2i_start",		test_cursor_replace_2i_start },

	/*
	 *	Insert with three item list (with cursor on item2)
	 */
	{ "prepend_3i_mid",		test_cursor_prepend_3i_mid },
	{ "append_3i_mid",		test_cursor_append_3i_mid },
	{ "insert_3i_mid",		test_cursor_insert_3i_mid },
	{ "replace_3i_mid",		test_cursor_replace_3i_mid },

	 /*
	  *	Insert with three item list (with cursor on item3)
	  */
	{ "prepend_3i_end",		test_cursor_prepend_3i_end },
	{ "append_3i_end",		test_cursor_append_3i_end },
	{ "insert_3i_end",		test_cursor_insert_3i_end },
	{ "replace_3i_end",		test_cursor_replace_3i_end },

	/*
	 *	Remove
	 */
	{ "remove_empty",		test_cursor_remove_empty },
	{ "remove_1i",			test_cursor_remove_1i },
	{ "remove_2i",			test_cursor_remove_2i },
	{ "remove_3i_start",		test_cursor_remove_3i_start },
	{ "remove_3i_mid",		test_cursor_remove_3i_mid },
	{ "remove_3i_end",		test_cursor_remove_3i_end },

	/*
	 *	Merge
	 */
	{ "merge_start_a_b",		test_cursor_merge_start_a_b },
	{ "merge_mid_a",		test_cursor_merge_mid_a },
	{ "merge_end_a",		test_cursor_merge_end_a },
	{ "merge_mid_b",		test_cursor_merge_mid_b },
	{ "merge_end_b",		test_cursor_merge_end_b },
	{ "merge_with_empty",		test_cursor_merge_with_empty },
	{ "merge_empty",		test_cursor_merge_empty },

	/*
	 *	Copy
	 */
	{ "copy",			test_cursor_copy },

	/*
	 *	Free
	 */
	{ "free", 			test_cursor_free },
	/*
	 * 	Intersect
	 */
	{ "differing_lists",		test_intersect_differing_lists },
	{ "no_iterators",		test_intersect_no_iterators },
	{ "iterator_a",			test_intersect_iterator_a },
	{ "iterator_b",			test_intersect_iterator_b },
	{ "iterator_ab",		test_intersect_iterator_ab },
	{ "iterator_disjoint",		test_intersect_iterator_disjoint },
	{ 0 }
};
#endif
