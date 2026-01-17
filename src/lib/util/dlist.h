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

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/talloc.h>

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
	fr_dlist_t	entry;		//!< Struct holding the head and tail of the list.
					///< First for efficient traversal.

	unsigned int	offset;		//!< Positive offset from start of structure to #fr_dlist_t.
					///< Yes, this should really be size_t, but we shave 8 bytes
					///< off each head structure by making it unsigned int.

	unsigned int	num_elements;	//!< Number of elements contained within the dlist.

	char const	*type;		//!< of items contained within the list.  Used for talloc
					///< validation.
} fr_dlist_head_t;

static_assert(sizeof(unsigned int) >= 4, "Unsigned integer too small on this platform");

/** Static initialiser for entries
 *
 @code {.c}
   fr_dlist_entry_t my_entry = FR_DLIST_INITIALISER(my_entry)
 @endcode
 *
 * @param[in] _entry	what's being initialised.
 */
#define FR_DLIST_ENTRY_INITIALISER(_entry) { .next = &_entry, .prev = &_entry }

/** Static initialiser for list heads
 *
 @code {.c}
   fr_dlist_head_t my_head = FR_DLIST_INITIALISER(my_head)
 @endcode
 *
 * @param[in] _head	what's being initialised.
 */
#define FR_DLIST_HEAD_INITIALISER(_head) { .entry = FR_DLIST_ENTRY_INITIALISER((_head).entry) }

/** Iterate over the contents of a list
 *
 * The macro is "safe", in that the current iterator variable can be deleted.
 *
 * The iterators can be nested, so long as the _iter variable names are different.
 *
 * @param[in] _list_head	to iterate over.
 * @param[in] _type		of item the list contains.
 * @param[in] _iter		Name of iteration variable.
 *				Will be declared in the scope of the loop.
 */
#define fr_dlist_foreach(_list_head, _type, _iter) \
	for (_type *JOIN(_next,_iter), *_iter = fr_dlist_head(_list_head); JOIN(_next,_iter) = fr_dlist_next(_list_head, _iter), _iter != NULL; _iter = JOIN(_next,_iter))

/** Find the dlist pointers within a list item
 *
 */
static inline fr_dlist_t *fr_dlist_item_to_entry(size_t offset, void const *item)
{
	return (fr_dlist_t *)(((uintptr_t) item) + offset);
}

/** Get the item from a fr_dlist_t
 *
 */
static inline void *fr_dlist_entry_to_item(size_t offset, fr_dlist_t const *entry)
{
	return (void *)(((uintptr_t) entry) - offset);
}

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
static inline CC_HINT(nonnull) void fr_dlist_entry_unlink(fr_dlist_t *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = entry->next = entry;
}

/** Check if a list entry is part of a list
 *
 * This works because the fr_dlist_head_t has an entry in the list.
 * So if next and prev both point to the entry for the object being
 * passed in, then it can't be part of a list with a fr_dlist_head_t.
 *
 * @return
 *	- True if in a list.
 *	- False otherwise.
 */
static inline CC_HINT(nonnull) bool fr_dlist_entry_in_list(fr_dlist_t const *entry)
{
	if (((entry->prev == entry) && (entry->next == entry)) ||
	    ((entry->prev == NULL) && (entry->next == NULL))) return false;

	return true;
}

/** Link in a single entry after the current entry
 *
 * @param[in] entry	to link in entry after.
 * @param[in] to_link 	entry to link in after.
 */
static inline CC_HINT(nonnull) void fr_dlist_entry_link_after(fr_dlist_t *entry, fr_dlist_t *to_link)
{
	to_link->prev = entry;
	to_link->next = entry->next;
	entry->next->prev = to_link;
	entry->next = to_link;
}

/** Link in a single entry before the current entry
 *
 * @param[in] entry	to link in entry before.
 * @param[in] to_link 	entry to link in before.
 */
static inline CC_HINT(nonnull) void fr_dlist_entry_link_before(fr_dlist_t *entry, fr_dlist_t *to_link)
{
	to_link->next = entry;
	to_link->prev = entry->prev;
	entry->prev->next = to_link;
	entry->prev = to_link;
}

/** Link in a sublist before the current entry
 *
 * @note This is not suitable for moving elements from a fr_dlist_head_t as
 *	 we need to snip out the head element. This is only suitable if the
 *	 two entries are not part of lists with head elements.
 *
 * @param[in] dst	to link src in before.
 * @param[in] src	to link in before dst.
 */
static inline CC_HINT(nonnull) void fr_dlist_entry_move(fr_dlist_t *dst, fr_dlist_t *src)
{
	fr_dlist_t *src_end = src->prev;

	dst->prev->next = src;
	src->prev->next = dst;
	src->prev = dst->prev;
	dst->prev = src_end;
}

/** Replace one entry with another
 *
 * @param[in] entry		to replace.
 * @param[in] replacement	to link in.
 */
static inline CC_HINT(nonnull) void fr_dlist_entry_replace(fr_dlist_t *entry, fr_dlist_t *replacement)
{
	/* Link replacement item into list */
	entry->prev->next = replacement;
	replacement->prev = entry->prev;
	entry->next->prev = replacement;
	replacement->next = entry->next;

	/* Reset links on replaced item */
	fr_dlist_entry_init(entry);
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

/** Initialise common fields in a dlist
 *
 */
static inline void _fr_dlist_init(fr_dlist_head_t *list_head, size_t offset, char const *type)
{
	fr_assert(offset < (1 << 20)); /* list_head->offset is `unsigned int`, and 1G structs are stupid. */

	fr_dlist_entry_init(&list_head->entry);
	list_head->offset = offset;
	list_head->type = type;
	list_head->num_elements = 0;
}

/** Efficiently remove all elements in a dlist
 *
 * @param[in] list_head	to clear.
 */
static inline void fr_dlist_clear(fr_dlist_head_t *list_head)
{
	fr_dlist_entry_init(&list_head->entry);
	list_head->num_elements = 0;
}

/** Verify we're not going to overflow the element count
 *
 */
#define CHECK_ELEMENT_COUNT(_head, _add) \
	if (unlikely((_head)->num_elements > (UINT_MAX - (_add)))) do { \
		fr_strerror_const("Maximum elements in list"); \
		return -1; \
	} while (0)

/** Check if a list entry is part of a list
 *
 * This works because the fr_dlist_head_t has an entry in the list.
 * So if next and prev both point to the entry for the object being
 * passed in, then it can't be part of a list with a fr_dlist_head_t.
 *
 * @return
 *	- True if in a list.
 *	- False otherwise.
 */
static inline CC_HINT(nonnull) bool fr_dlist_in_list(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry = fr_dlist_item_to_entry(list_head->offset, ptr);

	return fr_dlist_entry_in_list(entry);
}

/** Insert an item into the head of a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_dlist_insert_head(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

	CHECK_ELEMENT_COUNT(list_head, 1);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return -1;
	if (!fr_cond_assert(head->prev != NULL)) return -1;

	entry->prev = head;
	entry->next = head->next;
	head->next->prev = entry;
	head->next = entry;

	list_head->num_elements++;

	return 0;
}

/** Insert an item into the tail of a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) int fr_dlist_insert_tail(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;

	CHECK_ELEMENT_COUNT(list_head, 1);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return -1;
	if (!fr_cond_assert(head->prev != NULL)) return -1;

	entry->next = head;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;

	list_head->num_elements++;

	return 0;
}

/** Insert an item after an item already in the list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] pos	to insert ptr after.
 * @param[in] ptr	to insert.
 */
static inline CC_HINT(nonnull(1,3)) int fr_dlist_insert_after(fr_dlist_head_t *list_head, void *pos, void *ptr)
{
	fr_dlist_t *entry, *pos_entry;

	CHECK_ELEMENT_COUNT(list_head, 1);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	if (!pos) {
		pos_entry = &(list_head->entry);
	} else {
		pos_entry = fr_dlist_item_to_entry(list_head->offset, pos);
	}

	if (!fr_cond_assert(pos_entry->next != NULL)) return -1;
	if (!fr_cond_assert(pos_entry->prev != NULL)) return -1;

	fr_dlist_entry_link_after(pos_entry, entry);

	list_head->num_elements++;

	return 0;
}

/** Insert an item before an item already in the list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] pos	to insert ptr before.
 * @param[in] ptr	to insert.
 */
static inline CC_HINT(nonnull(1,3)) int fr_dlist_insert_before(fr_dlist_head_t *list_head, void *pos, void *ptr)
{
	fr_dlist_t *entry, *pos_entry;

	CHECK_ELEMENT_COUNT(list_head, 1);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	if (!pos) {
		pos_entry = &(list_head->entry);
	} else {
		pos_entry = fr_dlist_item_to_entry(list_head->offset, pos);
	}

	if (!fr_cond_assert(pos_entry->next != NULL)) return -1;
	if (!fr_cond_assert(pos_entry->prev != NULL)) return -1;

	fr_dlist_entry_link_before(pos_entry, entry);

	list_head->num_elements++;

	return 0;
}

/** Return the HEAD item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the HEAD item from.
 * @return
 *	- The HEAD item.
 *	- NULL if no items exist in the list.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) void *fr_dlist_head(fr_dlist_head_t const *list_head)
{
	fr_dlist_t const *head = &(list_head->entry);

	if (head->next == head) return NULL;

	return fr_dlist_entry_to_item(list_head->offset, head->next);
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

/** Check if the list head is initialised
 *
 * Memory must be zeroed out or initialised.
 *
 * @return
 *	- True if dlist initialised.
 *	- False if dlist not initialised
 */
static inline CC_HINT(nonnull) bool fr_dlist_initialised(fr_dlist_head_t const *list_head)
{
	fr_dlist_t const *head = &(list_head->entry);

	if (!head->prev && !head->next) return false;

	return true;
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

	return fr_dlist_entry_to_item(list_head->offset, head->prev);

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
 * @hidecallergraph
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_next(fr_dlist_head_t const *list_head, void const *ptr)
{
	fr_dlist_t const	*entry;
	fr_dlist_t const	*head;

	if (!ptr) return fr_dlist_head(list_head);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif
	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	head = &(list_head->entry);

	if (entry->next == head) return NULL;
	if (!entry->next) return NULL;
	entry = entry->next;

	return fr_dlist_entry_to_item(list_head->offset, entry);
}

/** Get the previous item in a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_dlist_talloc_init.
 *
 * @param[in] list_head		containing ptr.
 * @param[in] ptr		to retrieve the previous item to.
 *				If ptr is NULL, the TAIL of the list will be returned.
 * @return
 *	- The previous item in the list if ptr is not NULL.
 *	- The tail of the list if ptr is NULL.
 *	- NULL if ptr is the head of the list (no more items).
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_prev(fr_dlist_head_t const *list_head, void const *ptr)
{
	fr_dlist_t const	*entry;
	fr_dlist_t const	*head;

	if (!ptr) return fr_dlist_tail(list_head);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	head = &(list_head->entry);

	if (entry->prev == head) return NULL;
	entry = entry->prev;

	return fr_dlist_entry_to_item(list_head->offset, entry);
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
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_remove(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry;
	fr_dlist_t *head;
	fr_dlist_t *prev;

	if (!ptr || fr_dlist_empty(list_head)) return NULL;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) (void)_talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry = fr_dlist_item_to_entry(list_head->offset, ptr);
	if (!fr_dlist_entry_in_list(entry)) return NULL;

	head = &(list_head->entry);
	entry->prev->next = entry->next;
	entry->next->prev = prev = entry->prev;
	entry->prev = entry->next = entry;

	list_head->num_elements--;

	if (prev == head) return NULL;	/* Works with fr_dlist_next so that the next item is the list HEAD */

	return fr_dlist_entry_to_item(list_head->offset, prev);
}

/** Remove the head item in a list
 *
 * @param[in] list_head to remove head item from.
 * @return
 *	- The item removed.
 *	- NULL if not items in dlist.
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_pop_head(fr_dlist_head_t *list_head)
{
	void *item = fr_dlist_head(list_head);

	(void)fr_dlist_remove(list_head, item);

	return item;	/* fr_dlist_remove returns the previous item */
}

/** Remove the tail item in a list
 *
 * @param[in] list_head to remove tail item from.
 * @return
 *	- The item removed.
 *	- NULL if not items in dlist.
 */
static inline CC_HINT(nonnull(1)) void *fr_dlist_pop_tail(fr_dlist_head_t *list_head)
{
	void *item = fr_dlist_tail(list_head);

	(void)fr_dlist_remove(list_head, item);

	return item;	/* fr_dlist_remove returns the previous item */
}

/** Replace an item in a dlist
 *
 * @param list_head in which the original item is.
 * @param item to replace.
 * @param ptr replacement item.
 * @return
 *	- The item replaced
 *	- NULL if nothing replaced
 */
static inline void *fr_dlist_replace(fr_dlist_head_t *list_head, void *item, void *ptr)
{
	fr_dlist_t *item_entry;
	fr_dlist_t *ptr_entry;

	if (!item || !ptr) return NULL;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) (void)_talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	item_entry = fr_dlist_item_to_entry(list_head->offset, item);
	if (!fr_dlist_entry_in_list(item_entry)) return NULL;

	ptr_entry = fr_dlist_item_to_entry(list_head->offset, ptr);

	fr_dlist_entry_replace(item_entry, ptr_entry);

	return item;
}

/** Check all items in the list are valid
 *
 * Checks item talloc headers and types to ensure they're consistent
 * with what we expect.
 *
 * Does nothing if the list was not initialised with #fr_dlist_talloc_init.
 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
static inline CC_HINT(nonnull) void _fr_dlist_verify(char const *file, int line, fr_dlist_head_t const *list_head)
{
	void *item;

	if (!list_head->type) return;

	fr_assert_msg(fr_dlist_initialised(list_head), "CONSISTENCY CHECK FAILED %s[%i]: dlist not initialised", file, line);

	for (item = fr_dlist_head(list_head);
	     item;
	     item = fr_dlist_next(list_head, item)) {
	     item = _talloc_get_type_abort(item, list_head->type, __location__);
	}
}
#else
static inline void _fr_dlist_verify(UNUSED char const *file, UNUSED int line, fr_dlist_head_t const *list_head)
{
	if (!fr_cond_assert(list_head != NULL)) return;
}
#endif
#define fr_dlist_verify(_head) _fr_dlist_verify(__FILE__, __LINE__, _head)

/** Merge two lists, inserting the source at the tail of the destination
 *
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_dlist_move(fr_dlist_head_t *list_dst, fr_dlist_head_t *list_src)
{
	fr_dlist_t *dst = &(list_dst->entry);
	fr_dlist_t *src = &(list_src->entry);

	CHECK_ELEMENT_COUNT(list_dst, list_src->num_elements);

#ifdef WITH_VERIFY_PTR
	/*
	 *	Must be both talloced or both not
	 */
	if (!fr_cond_assert((list_dst->type && list_src->type) || (!list_dst->type && !list_src->type))) return -1;

	/*
	 *	Must be of the same type
	 */
	if (!fr_cond_assert(!list_dst->type || (strcmp(list_dst->type, list_src->type) == 0))) return -1;
#endif

	if (!fr_cond_assert(dst->next != NULL)) return -1;
	if (!fr_cond_assert(dst->prev != NULL)) return -1;

	if (fr_dlist_empty(list_src)) return 0;

	/*
	 *	This is different to fr_dlist_entry_move
	 *	because we need need to snip out the
	 *	list head entry from the src.
	 */
	src->prev->next = dst;
	src->next->prev = dst->prev;

	dst->prev->next = src->next;
	dst->prev = src->prev;

	list_dst->num_elements += list_src->num_elements;

	fr_dlist_entry_init(src);
	list_src->num_elements = 0;

	return 0;
}

/** Merge two lists, inserting the source at the head of the destination
 *
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_dlist_move_head(fr_dlist_head_t *list_dst, fr_dlist_head_t *list_src)
{
	fr_dlist_t *dst = &(list_dst->entry);
	fr_dlist_t *src = &(list_src->entry);

	CHECK_ELEMENT_COUNT(list_dst, list_src->num_elements);

#ifdef WITH_VERIFY_PTR
	/*
	 *	Must be both talloced or both not
	 */
	if (!fr_cond_assert((list_dst->type && list_src->type) || (!list_dst->type && !list_src->type))) return -1;

	/*
	 *	Must be of the same type
	 */
	if (!fr_cond_assert(!list_dst->type || (strcmp(list_dst->type, list_src->type) == 0))) return -1;
#endif

	if (!fr_cond_assert(dst->next != NULL)) return -1;
	if (!fr_cond_assert(dst->prev != NULL)) return -1;

	if (fr_dlist_empty(list_src)) return 0;

	src->next->prev = dst;
	src->prev->next = dst->next;

	dst->next->prev = src->prev;
	dst->next = src->next;

	list_dst->num_elements += list_src->num_elements;

	fr_dlist_entry_init(src);
	list_src->num_elements = 0;

	return 0;
}

/** Free the first item in the list
 *
 * @param[in] list_head		to free head item in.
 */
static inline void fr_dlist_talloc_free_head(fr_dlist_head_t *list_head)
{
	talloc_free(fr_dlist_pop_head(list_head));
}

/** Free the last item in the list
 *
 * @param[in] list_head		to free tail item in.
 */
static inline void fr_dlist_talloc_free_tail(fr_dlist_head_t *list_head)
{
	talloc_free(fr_dlist_pop_head(list_head));
}

/** Free the item specified
 *
 * @param[in] list_head		to free item in.
 * @param[in] ptr		to remove and free.
 * @return
 *	- NULL if no more items in the list.
 *	- Previous item in the list
 */
static inline void *fr_dlist_talloc_free_item(fr_dlist_head_t *list_head, void *ptr)
{
	void *prev;
	prev = fr_dlist_remove(list_head, ptr);
	talloc_free(ptr);
	return prev;
}

/** Free items in a doubly linked list (with talloc)
 *
 * @param[in] head	of list to free.
 * @param[in] ptr	remove and free from this to the tail.
 */
static inline void fr_dlist_talloc_free_to_tail(fr_dlist_head_t *head, void *ptr)
{
	void *e = ptr, *p;

	if (!ptr) return;	/* NULL means don't do anything */

	while (e) {
		p = fr_dlist_next(head, e);
		(void) fr_dlist_remove(head, e);
		talloc_free(e);
		e = p;
	}
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

/** Free all items in a doubly linked list from the tail backwards
 *
 * @param[in] head of list to free.
 */
static inline void fr_dlist_talloc_reverse_free(fr_dlist_head_t *head)
{
	void *e = NULL, *p;

	e = fr_dlist_tail(head);
	do {
		p = fr_dlist_remove(head, e);
		talloc_free(e);
		e = p;
	} while (e);
}

/** Return the number of elements in the dlist
 *
 * @param[in] head of list to count elements for.
 */
static inline unsigned int fr_dlist_num_elements(fr_dlist_head_t const *head)
{
	return head->num_elements;
}

/** Split phase of a merge sort of a dlist
 *
 * @note Only to be used within a merge sort
 *
 * @param[in] head	of the original list being sorted
 * @param[in] source	first item in the section of the list to split
 * @param[out] front	first item of the first half of the split list
 * @param[out] back	first item of the second half of the split list
 */
static inline void fr_dlist_sort_split(fr_dlist_head_t *head, void **source, void **front, void **back)
{
	void *fast = NULL;
	void *slow;
	fr_dlist_t *entry = NULL;

	*front = *source;

	if (*source) entry = fr_dlist_item_to_entry(head->offset, *source);
	/*
	 *	Stopping condition - no more elements left to split
	 */
	if (!*source || !entry->next) {
		*back = NULL;
		return;
	}

	/*
	 *	Fast advances twice as fast as slow, so when it gets to the end,
	 *	slow will point to the middle of the linked list.
	 */
	slow = *source;
	fast = fr_dlist_next(head, slow);
	while (fast) {
		fast = fr_dlist_next(head, fast);
		if (fast) {
			slow = fr_dlist_next(head, slow);
			fast = fr_dlist_next(head, fast);
		}
	}

	*back = fr_dlist_next(head, slow);

	if (slow) {
		entry = fr_dlist_item_to_entry(head->offset, slow);
		entry->next = NULL;
	}
}

/** Merge phase of a merge sort of a dlist
 *
 * @note Only to be used within a merge sort
 *
 * @param[in] head	of the original list being sorted
 * @param[in] a		first element of first list being merged
 * @param[in] b		first element of second list being merged
 * @param[in] cmp	comparison function for the sort
 * @returns pointer to first item in merged list
 */
static inline void *fr_dlist_sort_merge(fr_dlist_head_t *head, void **a, void **b, fr_cmp_t cmp)
{
	void *result = NULL;
	void *next;
	fr_dlist_t *result_entry;
	fr_dlist_t *next_entry;

	if (!*a) return *b;
	if (!*b) return *a;

	/*
	 *	Compare entries in the lists
	 */
	if (cmp(*a, *b) <= 0) {
		result = *a;
		next = fr_dlist_next(head, *a);
		next = fr_dlist_sort_merge(head, &next, b, cmp);
	} else {
		result = *b;
		next = fr_dlist_next(head, *b);
		next = fr_dlist_sort_merge(head, a, &next, cmp);
	}

	result_entry = fr_dlist_item_to_entry(head->offset, result);
	next_entry = fr_dlist_item_to_entry(head->offset, next);
	result_entry->next = next_entry;

	return result;
}

/** Recursive sort routine for dlist
 *
 * @param[in] head	of the list being sorted
 * @param[in,out] ptr	to the first item in the current section of the list being sorted.
 * @param[in] cmp	comparison function to sort with
 */
static inline void fr_dlist_recursive_sort(fr_dlist_head_t *head, void **ptr, fr_cmp_t cmp)
{
	void *a;
	void *b;
	fr_dlist_t *entry = NULL;

	if (*ptr) entry = fr_dlist_item_to_entry(head->offset, *ptr);

	if (!*ptr || (!entry->next)) return;
	fr_dlist_sort_split(head, ptr, &a, &b);		/* Split into sublists */
	fr_dlist_recursive_sort(head, &a, cmp);		/* Traverse left */
	fr_dlist_recursive_sort(head, &b, cmp);		/* Traverse right */

	/*
	 *	merge the two sorted lists together
	 */
	*ptr = fr_dlist_sort_merge(head, &a, &b, cmp);
}

/** Sort a dlist using merge sort
 *
 * @note This routine temporarily breaks the doubly linked nature of the list
 *
 * @param[in,out] list	to sort
 * @param[in] cmp	comparison function to sort with
 */
static inline void fr_dlist_sort(fr_dlist_head_t *list, fr_cmp_t cmp)
{
	void *head;
	fr_dlist_t *entry;

	if (fr_dlist_num_elements(list) <= 1) return;

	head = fr_dlist_head(list);
	/* NULL terminate existing list */
	list->entry.prev->next = NULL;

	/*
	 *	Call the recursive sort routine
	 */
	fr_dlist_recursive_sort(list, &head, cmp);

	/*
	 *	Reset "prev" pointers broken during sort
	 */
	entry = fr_dlist_item_to_entry(list->offset, head);
	list->entry.next = entry;
	entry->prev = &list->entry;

	while (head) {
		entry = fr_dlist_item_to_entry(list->offset, head);
		if (entry->next) {
			/*
			 * There is a "next" entry, point it back to the current one
			 */
			entry->next->prev = entry;
		} else {
			/*
			 * No next entry, this is the tail
			 */
			list->entry.prev = entry;
			entry->next = &list->entry;
		}
		head = fr_dlist_next(list, head);
	}
}

static inline void fr_dlist_noop(void)
{
	return;
}

/** Expands to the type name used for the entry wrapper structure
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return fr_dlist_<name>_entry_t
 */
#define FR_DLIST_ENTRY(_name) _name ## _entry_t

/** Expands to the type name used for the head wrapper structure
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return fr_dlist_<name>_head_t
 */
#define FR_DLIST_HEAD(_name) _name ## _head_t

/** Define type specific wrapper structs for dlists
 *
 * @note This macro should be used inside the header for the area of code
 * which will use type specific functions.
 */
#define FR_DLIST_TYPES(_name) \
	typedef struct { fr_dlist_t entry; } FR_DLIST_ENTRY(_name); \
	typedef struct { fr_dlist_head_t head; } FR_DLIST_HEAD(_name); \

/** Define friendly names for type specific dlist head and entry structures
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @param[in] _head	Name to use for head structure.
 * @param[in] _entry	Name to use for entry structure.
*/
#define FR_DLIST_TYPEDEFS(_name, _head, _entry) \
	typedef FR_DLIST_HEAD(_name) _head; \
	typedef FR_DLIST_ENTRY(_name) _entry;

/** Define type specific wrapper functions for dlists
 *
 * @note This macro should be used inside the source file that will use
 * the type specific functions.
 *
 * @param[in] _name		Prefix we add to type-specific dlist functions.
 * @param[in] _element_type	Type of structure that'll be inserted into the dlist.
 * @param[in] _element_entry	Field in the _element_type that holds the dlist entry information.
 */
#define FR_DLIST_FUNCS(_name, _element_type, _element_entry) \
DIAG_OFF(unused-function) \
	_Static_assert(IS_FIELD_COMPATIBLE(_element_type, _element_entry, FR_DLIST_ENTRY(_name)) == 1, "Bad dlist entry field type");\
	static inline	fr_dlist_head_t *_name ## _dlist_head(FR_DLIST_HEAD(_name) const *list) \
		{ return	UNCONST(fr_dlist_head_t *, &list->head); } \
\
	static inline	fr_dlist_t *_name ## _dlist_entry(FR_DLIST_ENTRY(_name) const *entry) \
		{ return	UNCONST(fr_dlist_t *, &entry->entry ); } \
\
	static inline	void _name ## _entry_init(_element_type *entry) \
		{ \
			_Generic((&entry->_element_entry), \
				 FR_DLIST_ENTRY(_name) *: fr_dlist_entry_init(UNCONST(fr_dlist_t *, &entry->_element_entry.entry)), \
				 FR_DLIST_ENTRY(_name) const *: fr_dlist_noop()\
			); \
		} \
\
	static inline	void _name ## _init(FR_DLIST_HEAD(_name) *list) \
		{		_fr_dlist_init(&list->head, offsetof(_element_type, _element_entry), NULL); } \
\
	static inline	void _name ## _talloc_init(FR_DLIST_HEAD(_name) *list) \
		{		_fr_dlist_init(&list->head, offsetof(_element_type, _element_entry), #_element_type); } \
\
	static inline	void _name ## _clear(FR_DLIST_HEAD(_name) *list) \
		{		fr_dlist_clear(&list->head); } \
\
	static inline	bool _name ## _in_list(FR_DLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_dlist_in_list(&list->head, ptr); } \
\
	static inline	int _name ## _insert_head(FR_DLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_dlist_insert_head(&list->head, ptr); } \
\
	static inline	int _name ## _insert_tail(FR_DLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_dlist_insert_tail(&list->head, ptr); } \
\
	static inline	int _name ## _insert_after(FR_DLIST_HEAD(_name) *list, _element_type *pos, _element_type *ptr) \
		{ return	fr_dlist_insert_after(&list->head, pos, ptr); } \
\
	static inline	int _name ## _insert_before(FR_DLIST_HEAD(_name) *list, _element_type *pos, _element_type *ptr) \
		{ return	fr_dlist_insert_before(&list->head, pos, ptr); } \
\
	static inline	_element_type *_name ## _head(FR_DLIST_HEAD(_name) const *list) \
		{ return	fr_dlist_head(&list->head); } \
\
	static inline	bool _name ## _empty(FR_DLIST_HEAD(_name) const *list) \
		{ return	fr_dlist_empty(&list->head); } \
\
	static inline	bool _name ## _initialised(FR_DLIST_HEAD(_name) const *list) \
		{ return	fr_dlist_initialised(&list->head); } \
\
	static inline	_element_type *_name ## _tail(FR_DLIST_HEAD(_name) const *list) \
		{ return	fr_dlist_tail(&list->head); } \
\
	static inline _element_type *_name ## _next(FR_DLIST_HEAD(_name) const *list, _element_type const *ptr) \
		{ return	fr_dlist_next(&list->head, ptr); } \
\
	static inline	_element_type *_name ## _prev(FR_DLIST_HEAD(_name) const *list, _element_type const *ptr) \
		{ return	fr_dlist_prev(&list->head, ptr); } \
\
	static inline	_element_type *_name ## _remove(FR_DLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_dlist_remove(&list->head, ptr); } \
\
	static inline	_element_type *_name ## _pop_head(FR_DLIST_HEAD(_name) *list) \
		{ return	fr_dlist_pop_head(&list->head); } \
\
	static inline	_element_type *_name ## _pop_tail(FR_DLIST_HEAD(_name) *list) \
		{ return	fr_dlist_pop_tail(&list->head); } \
\
	static inline	_element_type *_name ## _replace(FR_DLIST_HEAD(_name) *list, _element_type *item, _element_type *ptr) \
		{ return	fr_dlist_replace(&list->head, item, ptr); } \
\
	static inline	void _##_name ## _verify(char const *file, int line, FR_DLIST_HEAD(_name) const *list_head) \
		{		_fr_dlist_verify(file, line, UNCONST(fr_dlist_head_t *, &list_head->head)); } \
\
	static inline	int _name ## _move(FR_DLIST_HEAD(_name) *dst, FR_DLIST_HEAD(_name) *src) \
		{ return	fr_dlist_move(&dst->head, &src->head); } \
\
	static inline	int _name ## _move_head(FR_DLIST_HEAD(_name) *dst, FR_DLIST_HEAD(_name) *src) \
		{ return	fr_dlist_move_head(&dst->head, &src->head); } \
\
	static inline	void _name ## _talloc_free_head(FR_DLIST_HEAD(_name) *list) \
		{		fr_dlist_talloc_free_head(&list->head); } \
\
	static inline	void _name ## _talloc_free_tail(FR_DLIST_HEAD(_name) *list) \
		{		fr_dlist_talloc_free_tail(&list->head); } \
\
	static inline	_element_type * _name ## _talloc_free_item(FR_DLIST_HEAD(_name) *list, _element_type *ptr) \
		{return		fr_dlist_talloc_free_item(&list->head, ptr); } \
\
	static inline	void _name ## _talloc_free(FR_DLIST_HEAD(_name) *list) \
		{		fr_dlist_talloc_free(&list->head); } \
\
	static inline	void _name ## _talloc_free_to_tail(FR_DLIST_HEAD(_name) *list, _element_type *ptr) \
		{		fr_dlist_talloc_free_to_tail(&list->head, ptr); } \
\
	static inline	void _name ## _talloc_reverse_free(FR_DLIST_HEAD(_name) *list) \
		{		fr_dlist_talloc_reverse_free(&list->head); } \
\
	static inline	unsigned int _name ## _num_elements(FR_DLIST_HEAD(_name) const *list) \
		{ return	fr_dlist_num_elements(&list->head); } \
\
	static inline	void _name ## _sort(FR_DLIST_HEAD(_name) *list, fr_cmp_t cmp) \
		{		fr_dlist_sort(&list->head, cmp); } \
DIAG_ON(unused-function)

/*
 *  In addition to the above call to FR_DLIST_FUNCS two additional macros should be defined
 *
 *  Unfortunately as there's no way to dynamically define macro names these need to be done manually.
 *
 *  #define <name>_foreach(_list_head, _iter) fr_dlist_foreach(<name>_dlist_head(_list_head), <element_type>, _iter)
 *  #define <name>_verify(_list_head) _<name>_verify(__FILE__, __LINE__, _list_head)
 */

#ifdef __cplusplus
}
#endif
