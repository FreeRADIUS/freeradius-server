#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Doubly linked list implementation
 *
 * @file src/lib/util/dlist.h
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(dlist_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <talloc.h>

typedef struct fr_dlist_s fr_dlist_t;

/** Entry in a doubly linked list
 *
 */
struct fr_dlist_s {
	fr_dlist_t *prev;
	fr_dlist_t *next;
};

/** Head of a doubly linked list
 *
 * Holds additional information about the list items,
 * like at which offset the next/prev pointers can be found.
 */
typedef struct {
	size_t		offset;		//!< Positive offset from start of structure to #fr_dlist_t.
	char const	*type;		//!< of items contained within the list.  Used for talloc
					///< validation.
	fr_dlist_t	entry;		//!< Struct holding the head and tail of the list.
	size_t		num_elements;
} fr_dlist_head_t;

/** Initialise a linked list without metadata
 *
 */
static inline void fr_dlist_entry_init(fr_dlist_t *entry)
{
	entry->prev = entry->next = entry;
}

/** Remove an item from the dlist when we don't have access to the head
 *
 */
static inline void fr_dlist_entry_unlink(fr_dlist_t *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
}

/** Initialise the head structure of a doubly linked list
 *
 * @note This variant does not perform talloc validation.
 *
 @code{.c}
   typedef struct {
   	fr_dlist_t	dlist;
   	char const	*field_a;
   	int		*field_b;
   	...
   } my_struct_t;

   int my_func(my_struct_t *a, my_struct_t *b)
   {
   	fr_dlist_head_t	head;

   	fr_dlist_init(&head, my_struct_t, dlist);
   	fr_dlist_insert_head(&head, a);
   	fr_dlist_insert_head(&head, b);
   }
 @endcode
 *
 * @param[in] _head	structure to initialise.
 * @param[in] _type	of item being stored in the list, e.g. fr_value_box_t,
 *			fr_dict_attr_t etc...
 * @param[in] _field	Containing the #fr_dlist_t within item being stored.
 */
#define fr_dlist_init(_head, _type, _field) \
	_Generic((((_type *)0)->_field), fr_dlist_t: _fr_dlist_init(_head, offsetof(_type, _field), NULL))

/** Initialise the head structure of a doubly linked list
 *
 * @note This variant *DOES* perform talloc validation.  All items inserted
 *	 into the list must be allocated with talloc.
 *
 * @copybrief fr_dlist_init
 *
 * @param[in] _head	structure to initialise.
 * @param[in] _type	of item being stored in the list, e.g. fr_value_box_t,
 *			fr_dict_attr_t etc...
 * @param[in] _field	Containing the #fr_dlist_t within item being stored.
 */
#define fr_dlist_talloc_init(_head, _type, _field) \
	_Generic((((_type *)0)->_field), fr_dlist_t: _fr_dlist_init(_head, offsetof(_type, _field), #_type))

static inline void _fr_dlist_init(fr_dlist_head_t *list_head, size_t offset, char const *type)
{
	fr_dlist_entry_init(&list_head->entry);
	list_head->offset = offset;
	list_head->type = type;
	list_head->num_elements = 0;
}

/** Insert an item into the head of a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 */
static inline CC_HINT(nonnull(1)) void fr_dlist_insert_head(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

	if (!ptr) return;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	entry->prev = head;
	entry->next = head->next;
	head->next->prev = entry;
	head->next = entry;

	list_head->num_elements++;
}

/** Insert an item into the tail of a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 */
static inline CC_HINT(nonnull(1)) void fr_dlist_insert_tail(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

	if (!ptr) return;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	entry->next = head;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;

	list_head->num_elements++;
}

/** Return the HEAD item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the HEAD item from.
 * @return
 *	- The HEAD item.
 *	- NULL if no items exist in the list.
 */
static inline CC_HINT(nonnull) void *fr_dlist_head(fr_dlist_head_t const *list_head)
{
	fr_dlist_t const *head = &(list_head->entry);

	if (head->next == head) return NULL;

	return (void *) (((uint8_t *) head->next) - list_head->offset);
}

/** Check whether a list has any items.
 *
 * @return
 *	- True if it does not.
 *	- False if it does.
 */
static inline CC_HINT(nonnull) bool fr_dlist_empty(fr_dlist_head_t const *list_head)
{
	fr_dlist_t const *head = &(list_head->entry);

	return (head->prev == head);
}

/** Return the TAIL item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the TAIL item from.
 * @return
 *	- The TAIL item.
 *	- NULL if no items exist in the list.
 */
static inline CC_HINT(nonnull) void *fr_dlist_tail(fr_dlist_head_t const *list_head)
{
	fr_dlist_t const *head = &(list_head->entry);

	if (head->prev == head) return NULL;

	return (void *) (((uint8_t *) head->prev) - list_head->offset);

}

/** Get the next item in a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head		containing ptr.
 * @param[in] ptr		to retrieve the next item from.
 *				If ptr is NULL, the HEAD of the list will be returned.
 * @return
 *	- The next item in the list if ptr is not NULL.
 *	- The head of the list if ptr is NULL.
 *	- NULL if ptr is the tail of the list (no more items).
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_next(fr_dlist_head_t const *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t const *head;

	if (!ptr) return fr_dlist_head(list_head);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif
	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (entry->next == head) return NULL;
	entry = entry->next;
	return (void *) (((uint8_t *) entry) - list_head->offset);
}

/** Get the previous item in a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head		containing ptr.
 * @param[in] ptr		to retrieve the next item from.
 *				If ptr is NULL, the TAIL of the list will be returned.
 * @return
 *	- The previous item in the list if ptr is not NULL.
 *	- The tail of the list if ptr is NULL.
 *	- NULL if ptr is the head of the list (no more items).
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_prev(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

	if (!ptr) return fr_dlist_tail(list_head);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (entry->prev == head) return NULL;
	entry = entry->prev;
	return (void *) (((uint8_t *) entry) - list_head->offset);
}

/** Remove an item from the list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * When removing items in an iteration loop, the iterator variable must be
 * assigned the item returned by this function.
 *
 * If the iterator variable is not updated, the item removed will be the last item
 * iterated over, as its next/prev pointers are set to point to itself.
 @code{.c}
	my_item_t *item = NULL;

	while ((item = fr_dlist_next(&head, item))) {
		if (item->should_be_removed) {
   			...do things with item
   			item = fr_dlist_remove(&head, item);
   			continue;
   		}
	}
 @endcode
 *
 * @param[in] list_head	to remove ptr from.
 * @param[in] ptr	to remove.
 * @return
 *	- The previous item in the list (makes iteration easier).
 *	- NULL if we just removed the head of the list.
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_remove(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;
	fr_dlist_t *prev;

	if (!ptr) return NULL;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (!fr_cond_assert(entry->next != NULL)) return NULL;
	if (!fr_cond_assert(entry->prev != NULL)) return NULL;

	entry->prev->next = entry->next;
	entry->next->prev = prev = entry->prev;
	entry->prev = entry->next = entry;

	if (prev == head) return NULL;	/* Works with fr_dlist_next so that the next item is the list HEAD */

	list_head->num_elements--;

	return (void *) (((uint8_t *) prev) - list_head->offset);
}

/** Check all items in the list are valid
 *
 * Checks item talloc headers and types to ensure they're consistent
 * with what we expect.
 *
 * Does nothing if the list was not initialised with #fr_dlist_talloc_init.
 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
static inline CC_HINT(nonnull) void fr_dlist_verify(fr_dlist_head_t *list_head)
{
	void *item;

	if (!list_head->type) return;

	for (item = fr_dlist_head(list_head);
	     item;
	     item = fr_dlist_next(list_head, item)) {
	     item = _talloc_get_type_abort(item, list_head->type, __location__);
	}
}
#else
#  define fr_list_verify(_head)
#endif

/** Merge two lists, inserting the tail of one into the other
 *
 */
static inline CC_HINT(nonnull) void fr_dlist_move(fr_dlist_head_t *list_dst, fr_dlist_head_t *list_src)
{
	fr_dlist_t *dst = &(list_dst->entry);
	fr_dlist_t *src = &(list_src->entry);

#ifdef WITH_VERIFY_PTR
	/*
	 *	Must be both talloced or both not
	 */
	if (!fr_cond_assert((list_dst->type && list_src->type) || (!list_dst->type && !list_src->type))) return;

	/*
	 *	Must be of the same type
	 */
	if (!fr_cond_assert(!list_dst->type || (strcmp(list_dst->type, list_src->type) == 0))) return;
#endif

	if (!fr_cond_assert(dst->next != NULL)) return;
	if (!fr_cond_assert(dst->prev != NULL)) return;

	if (fr_dlist_empty(list_src)) return;

	src->prev->next = dst;
	src->next->prev = dst->prev;

	dst->prev->next = src->next;
	dst->prev = src->prev;

	fr_dlist_entry_init(src);
	list_src->num_elements = 0;
}

/** Free all items in a doubly linked list (with talloc)
 *
 * @param[in] head of list to free.
 */
static inline void fr_dlist_talloc_free(fr_dlist_head_t *head)
{
	void *e = NULL, *p;

	while ((e = fr_dlist_next(head, e))) {
		p = fr_dlist_remove(head, e);
		talloc_free(e);
		e = p;
	}
}

/** Return the number of elements in the dlist
 *
 * @param[in] head of list to count elements for.
 */
static inline size_t fr_dlist_num_elements(fr_dlist_head_t *head)
{
	return head->num_elements;
}

#ifdef __cplusplus
}
#endif
