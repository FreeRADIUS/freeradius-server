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

/**
 * $Id$
 *
 * @file util/dlist.h
 * @brief Doubly linked list implementation
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(dlist_h, "$Id$")

/** Entry in a doubly linked list
 *
 */
typedef struct fr_dlist {
	struct fr_dlist *prev;
	struct fr_dlist *next;
} fr_dlist_t;

/** Head of a doubly linked list
 *
 * Holds additional information about the list items,
 * like at which offset the next/prev pointers can be found.
 */
typedef struct {
	size_t		offset;		//!< Positive offset from start of structure to #fr_dlist_t.
	char const	*type;		//!< of items contained within the list.  Used for talloc
					///< validation.
	fr_dlist_t	entry;		//!< Struct holding the head and fail of the list.
} fr_dlist_head_t;

/** Initialise a linked list without metadata
 *
 */
static inline void fr_dlist_entry_init(fr_dlist_t *entry)
{
	entry->prev = entry->next = entry;
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
 * @param[in] _type	of structure being stored in the list,
 *			e.g. fr_value_box_t, fr_dict_attr_t etc...
 * @param[in] _field	Containing the #fr_dlist_t structure within
 *			structure being stored.
 */
#define fr_dlist_init(_head, _type, _field) _fr_dlist_init(_head, offsetof(_type, _field), NULL)

/** Initialise the head structure of a doubly linked list
 *
 * @note This variant *DOES* perform talloc validation.  All items inserted
 *	 into the list must be allocated with talloc.
 *
 * @copybrief fr_dlist_init.
 *
 * @param[in] _head	structure to initialise.
 * @param[in] _type	of structure being stored in the list,
 *			e.g. fr_value_box_t, fr_dict_attr_t etc...
 * @param[in] _field	Containing the #fr_dlist_t within
 *			structure being stored.
 */
#define fr_dlist_talloc_init(_head, _type, _field) _fr_dlist_init(_head, offsetof(_type, _field), STRINGIFY(_type))

static inline void _fr_dlist_init(fr_dlist_head_t *head, size_t offset, char const *type)
{
	fr_dlist_entry_init(&head->entry);
	head->offset = offset;
	head->type = type;
}

/** Insert an item into the head of the list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 */
static inline void fr_dlist_insert_head(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

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
}

/** Insert an item into the tail of the list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 */
static inline void fr_dlist_insert_tail(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

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
}

/** Return the HEAD item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the HEAD item from.
 * @return
 *	- The HEAD item.
 *	- NULL if no items exist in the list.
 */
static inline void *fr_dlist_head(fr_dlist_head_t *list_head)
{
	fr_dlist_t *head = &(list_head->entry);

	if (head->next == head) return NULL;

	return (void *) (((uint8_t *) head->next) - list_head->offset);

}

/** Return the TAIL item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the HEAD item from.
 * @return
 *	- The TAIL item.
 *	- NULL if no items exist in the list.
 */
static inline void *fr_dlist_tail(fr_dlist_head_t *list_head)
{
	fr_dlist_t *head = &(list_head->entry);

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
 */
static inline void *fr_dlist_next(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (entry->next == head) return NULL;
	entry = entry->next;
	return (void *) (((uint8_t *) entry) - list_head->offset);
}

/** Remove an item from the list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to remove ptr from.
 * @param[in] ptr	to remove.
 */
static inline void fr_dlist_remove(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);

	if (!fr_cond_assert(entry->next != NULL)) return;
	if (!fr_cond_assert(entry->prev != NULL)) return;

	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = entry->next = entry;
}

/** Check all items in the list are valid
 *
 * Checks item talloc headers and types to ensure they're consistent
 * with what we expect.
 *
 * Does nothing if the list was not initialised with #fr_dlist_talloc_init.
 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
static inline void fr_dlist_verify(fr_dlist_head_t *list_head)
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
static inline void fr_dlist_insert_tail_list(fr_dlist_head_t *list_head_a, fr_dlist_head_t *list_head_b)
{
	fr_dlist_t *head_a = &(list_head_a->entry);
	fr_dlist_t *head_b = &(list_head_b->entry);

#ifdef WITH_VERIFY_PTR
	/*
	 *	Must be both talloced or both not
	 */
	if (!fr_cond_assert(list_head_a->type == list_head_b->type)) return;

	/*
	 *	Must be of the same type
	 */
	if (!fr_cond_assert(!list_head_a->type) || (strcmp(list_head_a->type, list_head_b->type) == 0)) return;
#endif

	if (!fr_cond_assert(head_a->next != NULL)) return;
	if (!fr_cond_assert(head_a->prev != NULL)) return;

	head_b->prev->next = head_a;
	head_b->next->prev = head_a->prev;

	head_a->prev->next = head_b->next;
	head_a->prev = head_b->prev;

	head_b->prev = head_b->next = head_b;
}
