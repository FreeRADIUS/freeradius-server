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
#include <freeradius-devel/util/talloc.h>

#include <stddef.h>
#include <stdbool.h>

typedef struct fr_dcursor_s fr_dcursor_t;

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
typedef int (*fr_dcursor_remove_t)(fr_dlist_head_t *list, void *to_delete, void *uctx);

/** Copy callback for duplicating complex dcursor state
 *
 * @param[out] out	dcursor to copy to.
 * @param[in] in	dcursor to copy from.
 */
typedef void (*fr_dcursor_copy_t)(fr_dcursor_t *out, fr_dcursor_t const *in);

/** Type of evaluation functions to pass to the fr_dcursor_filter_*() functions.
 *
 * @param[in] item	the item to be evaluated
 * @param[in] uctx	context that may assist with evaluation
 * @return
 * 	- true if the evaluation function is satisfied.
 * 	- false if the evaluation function is not satisfied.
 */
typedef bool (*fr_dcursor_eval_t)(void const *item, void const *uctx);

struct fr_dcursor_s {
	fr_dlist_head_t		*dlist;		//!< Head of the doubly linked list being iterated over.
	void			*current;	//!< The current item in the dlist.

	fr_dcursor_iter_t	iter;		//!< Iterator function.
	fr_dcursor_iter_t	peek;		//!< Distinct "peek" function.  This is sometimes necessary
						///< for iterators with complex state.
	void			*iter_uctx;	//!< to pass to iterator function.

	fr_dcursor_insert_t	insert;		//!< Callback function on insert.
	fr_dcursor_remove_t	remove;		//!< Callback function on delete.
	void			*mod_uctx;	//!< to pass to modification functions.

	fr_dcursor_copy_t	copy;		//!< Copy dcursor state.

	bool			is_const;	//!< The list we're iterating over is immutable.
	bool			at_end;		//!< We're at the end of the list.
};

typedef struct {
	uint8_t			depth;		//!< Which cursor is currently in use.
	fr_dcursor_t		cursor[];	//!< Stack of cursors.
} fr_dcursor_stack_t;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
#define VALIDATE(_item) if (cursor->dlist->type && (_item)) _talloc_get_type_abort(_item, cursor->dlist->type, __location__);
#else
#define VALIDATE(_item)
#endif

/** If current is set to a NULL pointer, we record that fact
 *
 * This stops us jumping back to the start of the dlist.
 */
static inline void *dcursor_current_set(fr_dcursor_t *cursor, void *current)
{
	VALIDATE(current);

	cursor->at_end = (current == NULL);
	cursor->current = current;

	return current;
}

/** Internal function to get the next item
 *
 * @param[in] cursor	to operate on.
 * @param[in] current	attribute.
 * @return
 *	- The next attribute.
 *	- NULL if no more attributes.
 */
static inline void *dcursor_next(fr_dcursor_t *cursor, fr_dcursor_iter_t iter, void *current)
{
	void *next;

	/*
	 *	Fast path without custom iter
	 */
	if (!iter) {
		if (likely(current != NULL)) return fr_dlist_next(cursor->dlist, current);

		if (cursor->at_end) return NULL;				/* At tail of the list */

		return fr_dlist_head(cursor->dlist);
	}

	/*
	 *	First time next has been called, or potentially
	 *	another call after we hit the end of the list.
	 */
	if (!current) {
		if (cursor->at_end) return NULL;				/* At tail of the list */

		next = iter(cursor->dlist, NULL, cursor->iter_uctx);
		VALIDATE(next);
		return next;
	}
	VALIDATE(current);

	/*
	 *	The iterator will advance to the next matching entry.
	 */
	next = iter(cursor->dlist, current, cursor->iter_uctx);
	VALIDATE(next);

	return next;
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

	if (in->copy) fr_dcursor_copy(out, in);
}

/** Rewind cursor to the start of the list
 *
 * @param[in] cursor	to operate on.
 * @return item at the start of the list.
 *
 * @hidecallergraph
 */
CC_HINT(nonnull)
static inline void *fr_dcursor_head(fr_dcursor_t *cursor)
{
	/*
	 *	If we have a custom iterator, the dlist attribute
	 *	may not be in the subset the iterator would
	 *	return, so set everything to NULL and have
	 *	dcursor_next figure it out.
	 */
	if (cursor->iter) {
		cursor->at_end = false;	/* reset the flag, else next will just return NULL */

		return dcursor_current_set(cursor, dcursor_next(cursor, cursor->iter, NULL));
	}

	return dcursor_current_set(cursor, fr_dlist_head(cursor->dlist));
}

/** Wind cursor to the tail item in the list
 *
 * @param[in] cursor	to operate on.
 * @return item at the end of the list.
 *
 * @hidecallergraph
 */
CC_HINT(nonnull)
static inline void *fr_dcursor_tail(fr_dcursor_t *cursor)
{
	/*
	 *	Keep calling next on the custom iterator
	 *      until we hit the end of the list.
	 */
	if (cursor->iter) {
		void *current = cursor->current;

		while ((cursor->current = dcursor_next(cursor, cursor->iter, cursor->current))) {
			current = cursor->current;
		}

		return dcursor_current_set(cursor, current);
	}

	return dcursor_current_set(cursor, fr_dlist_tail(cursor->dlist));
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
CC_HINT(nonnull)
static inline void *fr_dcursor_next(fr_dcursor_t *cursor)
{
	return dcursor_current_set(cursor, dcursor_next(cursor, cursor->iter, cursor->current));
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
CC_HINT(nonnull)
static inline void *fr_dcursor_next_peek(fr_dcursor_t *cursor)
{
	return dcursor_next(cursor, cursor->peek, cursor->current);
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
CC_HINT(nonnull)
static inline void *fr_dcursor_list_next_peek(fr_dcursor_t *cursor)
{
	return dcursor_next(cursor, NULL, cursor->current);
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
CC_HINT(nonnull)
static inline void *fr_dcursor_current(fr_dcursor_t *cursor)
{
	VALIDATE(cursor->current);
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
static inline void *fr_dcursor_set_current(fr_dcursor_t *cursor, void *item)
{
	if (!fr_cond_assert_msg(!cursor->is_const, "attempting to modify const list")) return NULL;

	if (!item ||
	    !fr_dlist_in_list(cursor->dlist, item) ||
	    (cursor->iter && !cursor->iter(cursor->dlist, item, cursor->iter_uctx))) return NULL;

	return dcursor_current_set(cursor, item);
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
static inline int fr_dcursor_prepend(fr_dcursor_t *cursor, void *v)
{
	int ret;

	if (!fr_cond_assert_msg(!cursor->is_const, "attempting to modify const list")) return -1;

	VALIDATE(v);

	if (cursor->insert) if ((ret = cursor->insert(cursor->dlist, v, cursor->mod_uctx)) < 0) return ret;

	/*
	 *	Insert at the head of the list
	 */
	fr_dlist_insert_head(cursor->dlist, v);

	return 0;
}

/** Insert a single item at the end of the list
 *
 * @note Does not change the current pointer.
 *
 * @param[in] cursor to operate on.
 * @param[in] v to insert.
 * @return
 *	- 0 on success.
 *	- -1 if the insert callback failed or a modification was attempted on a const'd list.
 *
 * @hidecallergraph
 */
static inline int fr_dcursor_append(fr_dcursor_t *cursor, void *v)
{
	int ret;

	if (!fr_cond_assert_msg(!cursor->is_const, "attempting to modify const list")) return -1;

	VALIDATE(v);

	if (cursor->insert) if ((ret = cursor->insert(cursor->dlist, v, cursor->mod_uctx)) < 0) return ret;

	fr_dlist_insert_tail(cursor->dlist, v);

	cursor->at_end = false;	/* Can't be at the end if we just inserted something */

	return 0;
}

/** Insert directly after the current item
 *
 * @note Does not change the current pointer.
 *
 * @param[in] cursor	to operate on.
 * @param[in] v		Item to insert.
 * @return
 *	- 0 on success.
 *	- -1 if the insert callback failed or a modification was attempted on a const'd list.
 *
 * @hidecallergraph
 */
static inline int fr_dcursor_insert(fr_dcursor_t *cursor, void *v)
{
	int ret;

	if (!fr_cond_assert_msg(!cursor->is_const, "attempting to modify const list")) return -1;

	VALIDATE(v);

	if (!cursor->current) {
		if (fr_dcursor_append(cursor, v) < 0) return -1;
		return 0;
	}

	if (cursor->insert) if ((ret = cursor->insert(cursor->dlist, v, cursor->mod_uctx)) < 0) return ret;

	fr_dlist_insert_after(cursor->dlist, cursor->current, v);

	return 0;
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
static inline void *fr_dcursor_remove(fr_dcursor_t *cursor)
{
	void *v;

	if (!fr_cond_assert_msg(!cursor->is_const, "attempting to modify const list")) return NULL;

	if (!cursor->current) return NULL;			/* don't do anything fancy, it's just a noop */

	v = cursor->current;
	VALIDATE(v);

	if (cursor->remove && (cursor->remove(cursor->dlist, v, cursor->mod_uctx) < 0)) return NULL;

	dcursor_current_set(cursor, dcursor_next(cursor, cursor->iter, v));

	fr_dlist_remove(cursor->dlist, v);

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

	if (!fr_cond_assert_msg(!cursor->is_const, "dst list in merge is const")) return;
	if (!fr_cond_assert_msg(!to_append->is_const, "src list in merge is const")) return;

	p = cursor->current;
	while ((v = fr_dcursor_remove(to_append))) {
		fr_dcursor_insert(cursor, v);
		dcursor_current_set(cursor, v);
	}
	dcursor_current_set(cursor, p);
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
static inline void *fr_dcursor_replace(fr_dcursor_t *cursor, void *r)
{
	void *v;

	if (!fr_cond_assert_msg(!cursor->is_const, "attempting to modify const list")) return NULL;

	VALIDATE(r);

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

	if (cursor->remove) if (cursor->remove(cursor->dlist, v, cursor->mod_uctx) < 0) return NULL;

	fr_dlist_replace(cursor->dlist, cursor->current, r);

	/*
	 *	Fixup current pointer.
	 */
	if (cursor->iter) {
		dcursor_current_set(cursor, cursor->iter(cursor->dlist, r, cursor->iter_uctx));	/* Verify r matches */
	} else {
		dcursor_current_set(cursor, r);			/* Current becomes replacement */
	}

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

/** Initialise a cursor with a custom iterator
 *
 * @param[in] _cursor		to initialise.
 * @param[in] _head		of item list.
 * @param[in] _iter		function.
 * @param[in] _peek		function.  If NULL _iter will be used for peeking.
 * @param[in] _iter_uctx	_iter function _uctx.
 * @return
 *	- NULL if _head does not point to any items, or the iterator matches no items
 *	  in the current list.
 *	- The first item returned by the iterator.
 */
#define fr_dcursor_iter_mod_init(_cursor, _list, _iter, _peek, _iter_uctx, _insert, _remove, _mod_uctx) \
	_fr_dcursor_init(_cursor, \
			 _list, \
			 _iter, \
			 _peek, \
			 _iter_uctx, \
			 _insert, \
			 _remove, \
			 _mod_uctx, \
			 IS_CONST(fr_dlist_head_t *, _list))

/** Initialise a cursor with a custom iterator
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @param[in] _iter	function.
 * @param[in] _peek	function.  If NULL _iter will be used for peeking.
 * @param[in] _uctx	_iter function _uctx.
 * @return
 *	- NULL if _head does not point to any items, or the iterator matches no items
 *	  in the current list.
 *	- The first item returned by the iterator.
 */
#define fr_dcursor_iter_init(_cursor, _head, _iter, _peek, _uctx) \
	_fr_dcursor_init(_cursor, \
			 _head, \
			 _iter, \
			 _peek, \
			 _uctx, \
			 NULL, \
			 NULL, \
			 NULL, \
			 IS_CONST(fr_dlist_head_t *, _head))

/** Initialise a cursor
 *
 * @param[in] _cursor	to initialise.
 * @param[in] _head	of item list.
 * @return
 *	- NULL if _head does not point to any items.
 *	- The first item in the list.
 */
#define fr_dcursor_init(_cursor, _head) \
	_fr_dcursor_init(_cursor, \
			 _head, \
			 NULL, \
			 NULL, \
			 NULL, \
			 NULL, \
			 NULL, \
			 NULL, \
			 IS_CONST(fr_dlist_head_t *, _head))

/** Setup a cursor to iterate over attribute items in dlists
 *
 * @param[in] cursor	Where to initialise the cursor (uses existing structure).
 * @param[in] head	of dlist.
 * @param[in] iter	Iterator callback.
 * @param[in] peek	Iterator callback that should not modify iterator state.
 * @param[in] iter_uctx	to pass to iterator function.
 * @param[in] insert	Callback for inserts.
 * @param[in] remove	Callback for removals.
 * @param[in] mod_uctx	to pass to modification functions.
 * @param[in] is_const	Don't allow modification of the underlying list.
 * @return the attribute pointed to by v.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull(1,2))
void *_fr_dcursor_init(fr_dcursor_t *cursor, fr_dlist_head_t const *head,
		       fr_dcursor_iter_t iter, fr_dcursor_iter_t peek, void const *iter_uctx,
		       fr_dcursor_insert_t insert, fr_dcursor_remove_t remove, void const *mod_uctx, bool is_const)
{
	*cursor = (fr_dcursor_t){
		.dlist = UNCONST(fr_dlist_head_t *, head),
		.iter = iter,
		.peek = peek ? peek : iter,
		.iter_uctx = UNCONST(void *, iter_uctx),
		.insert = insert,
		.remove = remove,
		.mod_uctx = UNCONST(void *, mod_uctx),
		.is_const = is_const
	};
	if (!fr_dlist_empty(cursor->dlist)) return fr_dcursor_next(cursor);	/* Initialise current */

	if (iter) return fr_dcursor_next(cursor);	/* An iterator may do something, even on an empty list */

	return NULL;
}

/** re-initialise a cursor, changing its list
 *
 * @param[in] _cursor	to re-initialise.
 * @param[in] _head	of item list.
 * @return
 *	- NULL if _head does not point to any items.
 *	- The first item in the list.
 */
#define fr_dcursor_reinit(_cursor, _head) \
	_fr_dcursor_reinit(_cursor, \
			   _head, \
			   IS_CONST(fr_dlist_head_t *, _head))

static inline CC_HINT(nonnull(1,2))
void _fr_dcursor_list_reinit(fr_dcursor_t *cursor, fr_dlist_head_t const *head, bool is_const)
{
	cursor->dlist = UNCONST(fr_dlist_head_t *, head);
	cursor->current = NULL;
	cursor->is_const = is_const;
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

/** Expands to the type name used for the dcursor wrapper structure
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return <name>_dcursor_t
 */
#define FR_DCURSOR(_name) _name ## _dcursor_t

/** Expands to the type name used for the dcursor iterator type
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return <name>_iter_t
 */
#define FR_DCURSOR_ITER(_name) _name ## _iter_t

/** Expands to the type name used for the dcursor evaluator type
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return <name>_eval_t
 */
#define FR_DCURSOR_EVAL(_name) _name ## _eval_t

/** Expands to the type name used for the dcursor insert function type
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return <name>_insert_t
 */
#define FR_DCURSOR_INSERT(_name) _name ## _insert_t

/** Expands to the type name used for the dcursor remove function type
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return <name>_remove_t
 */
#define FR_DCURSOR_REMOVE(_name) _name ## _remove_t

/** Expands to the type name used for the dcursor copy function type
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return <name>_copy_t
 */
#define FR_DCURSOR_COPY(_name) _name ## _copy_t

/** Define type specific wrapper structs for dcursors
 *
 * @param[in] _name		Prefix we add to type-specific structures.
 * @param[in] _list_name	The identifier used for type qualifying dlists.
 *				Should be the same as that use for
 *				- #FR_DLIST_HEAD
 *				- #FR_DLIST_ENTRY
 *				- #FR_DLIST_TYPES
 *				- #FR_DLIST_FUNCS
 *
 * @note This macro should be used inside the header for the area of code
 * which will use type specific functions.
 */
#define FR_DCURSOR_DLIST_TYPES(_name, _list_name, _element_type) \
	typedef struct { fr_dcursor_t dcursor; } FR_DCURSOR(_name); \
	typedef _element_type *(*FR_DCURSOR_ITER(_name))(FR_DLIST_HEAD(_list_name) *list, _element_type *to_eval, void *uctx); \
	typedef bool (*FR_DCURSOR_EVAL(_name))(_element_type const *item, void const *uctx); \
	typedef int (*FR_DCURSOR_INSERT(_name))(FR_DLIST_HEAD(_list_name) *list, FR_DLIST_ENTRY(_list_name) *to_insert, void *uctx); \
	typedef int (*FR_DCURSOR_REMOVE(_name))(FR_DLIST_HEAD(_list_name) *list, FR_DLIST_ENTRY(_list_name) *to_delete, void *uctx); \
	typedef void (*FR_DCURSOR_COPY(_name))(FR_DCURSOR(_name) *out, FR_DCURSOR(_name) const *in);

/** Define type specific wrapper functions for dcursors
 *
 * @note This macro should be used inside the source file that will use
 * the type specific functions.
 *
 * @param[in] _name		Prefix we add to type-specific dcursor functions.
 * @param[in] _list_name	Prefix for type-specific dlist used by this dcursor.
 * @param[in] _element_type	Type of structure that'll be inserted into the dlist and returned by the dcursor.
 */
#define FR_DCURSOR_FUNCS(_name, _list_name, _element_type) \
DIAG_OFF(unused-function) \
	static inline CC_HINT(nonnull) _element_type *_name ## _init(FR_DCURSOR(_name) *dcursor, \
								     FR_DLIST_HEAD(_list_name) *head) \
		{ return (_element_type *)_fr_dcursor_init(&dcursor->dcursor, &head->head, \
							   NULL, NULL, NULL, NULL, NULL, NULL, \
							   IS_CONST(FR_DLIST_HEAD(_list_name) *, head)); } \
\
	static inline CC_HINT(nonnull(1,2)) _element_type *_name ## _iter_init(FR_DCURSOR(_name) *dcursor, \
									       FR_DLIST_HEAD(_list_name) *head, \
									       FR_DCURSOR_ITER(_name) iter, \
									       FR_DCURSOR_ITER(_name) peek, \
									       void const *iter_uctx) \
		{ return (_element_type *)_fr_dcursor_init(&dcursor->dcursor, &head->head, \
							   (fr_dcursor_iter_t)iter, \
							   (fr_dcursor_iter_t)peek, \
							   iter_uctx, \
							   NULL, NULL, NULL, \
							   IS_CONST(FR_DLIST_HEAD(_list_name) *, head)); } \
\
	static inline CC_HINT(nonnull(1,2)) _element_type *_name ## _iter_mod_init(FR_DCURSOR(_name) *dcursor, \
										   FR_DLIST_HEAD(_list_name) *head, \
										   FR_DCURSOR_ITER(_name) iter, \
										   FR_DCURSOR_ITER(_name) peek, \
										   void const *iter_uctx, \
										   FR_DCURSOR_INSERT(_name) insert, \
										   FR_DCURSOR_REMOVE(_name) remove, \
										   void const *mod_uctx) \
		{ return (_element_type *)_fr_dcursor_init(&dcursor->dcursor, &head->head, \
							   (fr_dcursor_iter_t)iter, \
							   (fr_dcursor_iter_t)peek, \
							   iter_uctx, \
							   (fr_dcursor_insert_t)insert, \
							   (fr_dcursor_remove_t)remove, \
							   mod_uctx, \
							   IS_CONST(FR_DLIST_HEAD(_list_name) *, head)); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _current(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_current(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _next_peek(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_next_peek(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _list_next_peek(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_list_next_peek(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _next(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_next(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _head(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_head(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _tail(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_tail(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _set_current(FR_DCURSOR(_name) *dcursor, \
									   _element_type *v) \
		{ return (_element_type *)fr_dcursor_set_current(&dcursor->dcursor, v); } \
\
	static inline CC_HINT(nonnull) int _name ## _prepend(FR_DCURSOR(_name) *dcursor, \
							     _element_type *v) \
		{ return fr_dcursor_prepend(&dcursor->dcursor, v); } \
\
	static inline CC_HINT(nonnull) int _name ## _append(FR_DCURSOR(_name) *dcursor, \
							    _element_type *v) \
		{ return fr_dcursor_append(&dcursor->dcursor, v); } \
\
	static inline CC_HINT(nonnull) int _name ## _insert(FR_DCURSOR(_name) *dcursor, \
							    _element_type *v) \
		{ return fr_dcursor_insert(&dcursor->dcursor, v); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _replace(FR_DCURSOR(_name) *dcursor, \
									_element_type *v) \
		{ return fr_dcursor_replace(&dcursor->dcursor, v); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _remove(FR_DCURSOR(_name) *dcursor) \
		{ return (_element_type *)fr_dcursor_remove(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) void _name ## _merge(FR_DCURSOR(_name) *cursor, \
							    FR_DCURSOR(_name) *to_append) \
		{ fr_dcursor_merge(&cursor->dcursor, &to_append->dcursor); } \
\
	static inline CC_HINT(nonnull) void _name ## _copy(FR_DCURSOR(_name) *out, \
							   FR_DCURSOR(_name) const *in) \
		{ fr_dcursor_copy(&out->dcursor, &in->dcursor); } \
\
	static inline CC_HINT(nonnull) void _name ## _free_list(FR_DCURSOR(_name) *dcursor) \
		{ fr_dcursor_free_list(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) void _name ## _free_item(FR_DCURSOR(_name) *dcursor) \
		{ fr_dcursor_free_item(&dcursor->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _intersect_head(FR_DCURSOR(_name) *a, \
									       FR_DCURSOR(_name) *b) \
		{ return (_element_type *)fr_dcursor_intersect_head(&a->dcursor, &b->dcursor); } \
\
	static inline CC_HINT(nonnull) _element_type *_name ## _intersect_next(FR_DCURSOR(_name) *a, \
									       FR_DCURSOR(_name) *b) \
		{ return (_element_type *)fr_dcursor_intersect_next(&a->dcursor, &b->dcursor); } \
\
	static inline CC_HINT(nonnull(1,2)) _element_type *_name ## _filter_head(FR_DCURSOR(_name) *dcursor, \
										 FR_DCURSOR_EVAL(_name) eval, \
										 void const *uctx) \
		{ return (_element_type *)fr_dcursor_filter_head(&dcursor->dcursor, (fr_dcursor_eval_t)eval, uctx); } \
\
	static inline CC_HINT(nonnull(1,2)) _element_type *_name ## _filter_next(FR_DCURSOR(_name) *dcursor, \
										 FR_DCURSOR_EVAL(_name) eval, \
										 void const *uctx) \
		{ return (_element_type *)fr_dcursor_filter_next(&dcursor->dcursor, (fr_dcursor_eval_t)eval, uctx); } \
\
	static inline CC_HINT(nonnull(1,2)) _element_type *_name ## _filter_current(FR_DCURSOR(_name) *dcursor, \
										    FR_DCURSOR_EVAL(_name) eval, \
										    void const *uctx) \
		{ return (_element_type *)fr_dcursor_filter_current(&dcursor->dcursor, (fr_dcursor_eval_t)eval, uctx); }

DIAG_ON(unused-function)

#ifdef __cplusplus
}
#endif
