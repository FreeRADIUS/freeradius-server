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

/** Tree list implementation
 *
 * @file src/lib/util/tlist.h
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(tlist_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dlist.h>

typedef struct fr_tlist_head_s fr_tlist_head_t;
typedef struct fr_tlist_s fr_tlist_t;

struct fr_tlist_head_s {
	fr_tlist_t	*parent;	//!< the parent entry which holds this list.  May be NULL.

	fr_dlist_head_t	dlist_head;
};

#define tlist_type(_list) ((_list)->dlist_head.type)

struct fr_tlist_s {
	fr_tlist_head_t	*list_head;	//!< the list which holds this entry
	fr_tlist_head_t	*children;	//!< any child list
	fr_dlist_t	dlist_entry;	//!< the doubly linked list of entries.
};


/** Find the tlist pointers within a list item
 *
 */
static inline fr_tlist_t *fr_tlist_item_to_entry(fr_tlist_head_t const *list_head, void const *item)
{
	return (fr_tlist_t *)(((uintptr_t) item) + list_head->dlist_head.offset - offsetof(fr_tlist_t, dlist_entry));
}

/** Get the item from a fr_tlist_t
 *
 */
static inline void *fr_tlist_entry_to_item(fr_tlist_head_t const *list_head, fr_tlist_t const *entry)
{
	return (void *)(((uintptr_t) entry) - list_head->dlist_head.offset + offsetof(fr_tlist_t, dlist_entry));
}

/** Get a fr_tlist_head_t from a fr_dlist_head_t
 *
 */
static inline fr_tlist_head_t *fr_tlist_head_from_dlist(fr_dlist_head_t *dlist_head)
{
	return (fr_tlist_head_t *)(((uintptr_t) dlist_head) - offsetof(fr_tlist_head_t, dlist_head));
}

/** Initialise a linked list without metadata
 *
 */
static inline void fr_tlist_entry_init(fr_tlist_t *entry)
{
	fr_dlist_entry_init(&entry->dlist_entry);
	entry->list_head = NULL;
}

static inline CC_HINT(nonnull) void fr_tlist_entry_unlink(fr_tlist_t *entry)
{
	fr_dlist_entry_unlink(&entry->dlist_entry);
	entry->list_head = NULL;
}

/** Check if a list entry is part of a list
 *
 * This works because the fr_tlist_head_t has an entry in the list.
 * So if next and prev both point to the entry for the object being
 * passed in, then it can't be part of a list with a fr_tlist_head_t.
 *
 * @return
 *	- True if in a list.
 *	- False otherwise.
 */
static inline CC_HINT(nonnull) bool fr_tlist_entry_in_a_list(fr_tlist_t const *entry)
{
	return (entry->list_head != NULL);
}


// no fr_tlist_entry_link_after(), fr_tlist_entry_link_before(), fr_tlist_entry_move(), fr_tlist_entry_replace()

/** Initialise the head structure of a tlist
 *
 * @note This variant does not perform talloc validation.
 *
 * This function should only be called for the top level of the list.
 * Please call fr_tlist_add_child() when adding a child list to an
 * existing entry.
 *
 @code{.c}
   typedef struct {
   	fr_tlist_t	tlist;
   	char const	*field_a;
   	int		*field_b;
   	...
   } my_struct_t;

   int my_func(my_struct_t *a, my_struct_t *b)
   {
   	fr_tlist_head_t	head;

   	fr_tlist_init(&head, my_struct_t, tlist);
   	fr_tlist_insert_head(&head, a);
   	fr_tlist_insert_head(&head, b);
   }
 @endcode
 *
 * @param[in] _head	structure to initialise.
 * @param[in] _type	of item being stored in the list, e.g. fr_value_box_t,
 *			fr_dict_attr_t etc...
 * @param[in] _field	Containing the #fr_tlist_t within item being stored.
 */
#define fr_tlist_init(_head, _type, _field) \
	_Generic((((_type *)0)->_field), fr_tlist_t: _fr_tlist_init(_head, offsetof(_type, _field), NULL))

/** Initialise the head structure of a tlist
 *
 * @note This variant *DOES* perform talloc validation.  All items inserted
 *	 into the list must be allocated with talloc.
 *
 * @copybrief fr_tlist_init
 *
 * @param[in] _head	structure to initialise.
 * @param[in] _type	of item being stored in the list, e.g. fr_value_box_t,
 *			fr_dict_attr_t etc...
 * @param[in] _field	Containing the #fr_tlist_t within item being stored.
 */
#define fr_tlist_talloc_init(_head, _type, _field) \
	_Generic((((_type *)0)->_field), fr_tlist_t: _fr_tlist_init(_head, offsetof(_type, _field), #_type))

/** Initialise common fields in a tlist
 *
 *  The dlist entries point to the tlist structure, which then points to the real structure.
 */
static inline void _fr_tlist_init(fr_tlist_head_t *list_head, size_t offset, char const *type)
{
	list_head->parent = NULL;

	/*
	 *	Initialize the dlist, but point to the ENCLOSING data
	 *	structure and type, not to the #fr_tlist_t.
	 */
	fr_dlist_init(&list_head->dlist_head, fr_tlist_t, dlist_entry);
	list_head->dlist_head.offset += offset;
	list_head->dlist_head.type = type;
}

/** Iterate over the contents of a list, only one level
 *
 * @param[in] _list_head	to iterate over.
 * @param[in] _iter		Name of iteration variable.
 *				Will be declared in the scope of the loop.
 */
#define fr_tlist_foreach_entry(_list_head, _iter) \
	for (void *_iter = fr_dlist_head(&_list_head->dlist_head); _iter; _iter = fr_dlist_next(&_list_head->dlist_head, _iter))

/** Remove all elements in a tlist
 *
 * @param[in] list_head	to clear.
 */
static inline void fr_tlist_clear(fr_tlist_head_t *list_head)
{
	fr_tlist_foreach_entry(list_head, item) {
		fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, item);

		entry->list_head = NULL;
	}
	fr_dlist_clear(&list_head->dlist_head);
}

/** Check if a list entry is part of a tlist
 *
 * This works because the fr_tlist_head_t has an entry in the list.
 * So if next and prev both point to the entry for the object being
 * passed in, then it can't be part of a list with a fr_tlist_head_t.
 *
 * @return
 *	- True if in a list.
 *	- False otherwise.
 */
static inline CC_HINT(nonnull) bool fr_tlist_in_list(fr_tlist_head_t *list_head, void *ptr)
{
	fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, ptr);

	return (entry->list_head == list_head);
}

/** Insert an item into the head of a list
 *
 * @note If #fr_tlist_talloc_init was used to initialise #fr_tlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_tlist_insert_head(fr_tlist_head_t *list_head, void *ptr)
{
	fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, ptr);

	if (fr_dlist_insert_head(&list_head->dlist_head, ptr) < 0) return -1;

	entry->list_head = list_head;
	return 0;
}

/** Insert an item into the tail of a list
 *
 * @note If #fr_tlist_talloc_init was used to initialise #fr_tlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] ptr	to insert.
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_tlist_insert_tail(fr_tlist_head_t *list_head, void *ptr)
{
	fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, ptr);

	if (fr_dlist_insert_tail(&list_head->dlist_head, ptr) < 0) return -1;

	entry->list_head = list_head;
	return 0;
}

/** Insert an item after an item already in the list
 *
 * @note If #fr_tlist_talloc_init was used to initialise #fr_tlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] pos	to insert ptr after.
 * @param[in] ptr	to insert.
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull(1,3)) int fr_tlist_insert_after(fr_tlist_head_t *list_head, void *pos, void *ptr)
{
	fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, ptr);

	if (fr_dlist_insert_after(&list_head->dlist_head, pos, ptr) < 0) return -1;

	entry->list_head = list_head;
	return 0;
}

/** Insert an item after an item already in the list
 *
 * @note If #fr_tlist_talloc_init was used to initialise #fr_tlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * @param[in] list_head	to insert ptr into.
 * @param[in] pos	to insert ptr before.
 * @param[in] ptr	to insert.
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull(1,3)) int fr_tlist_insert_before(fr_tlist_head_t *list_head, void *pos, void *ptr)
{
	fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, ptr);

	if (fr_dlist_insert_before(&list_head->dlist_head, pos, ptr) < 0) return -1;

	entry->list_head = list_head;
	return 0;
}

/** Return the HEAD item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the HEAD item from.
 * @return
 *	- The HEAD item.
 *	- NULL if no items exist in the list.
 */
static inline CC_HINT(nonnull) void *fr_tlist_head(fr_tlist_head_t const *list_head)
{
	return fr_dlist_head(&list_head->dlist_head);
}

/** Check whether a list has any items.
 *
 * @return
 *	- True if it does not.
 *	- False if it does.
 */
static inline bool fr_tlist_empty(fr_tlist_head_t const *list_head)
{
	if (!list_head) return true;

	return fr_dlist_empty(&list_head->dlist_head);
}

/** Check if the list head is initialised
 *
 * Memory must be zeroed out or initialised.
 *
 * @return
 *	- True if tlist initialised.
 *	- False if tlist not initialised
 */
static inline CC_HINT(nonnull) bool fr_tlist_initialised(fr_tlist_head_t const *list_head)
{
	return fr_dlist_initialised(&list_head->dlist_head);
}

/** Return the TAIL item of a list or NULL if the list is empty
 *
 * @param[in] list_head		to return the TAIL item from.
 * @return
 *	- The TAIL item.
 *	- NULL if no items exist in the list.
 */
static inline CC_HINT(nonnull) void *fr_tlist_tail(fr_tlist_head_t const *list_head)
{
	return fr_dlist_tail(&list_head->dlist_head);
}

/** Get the next item in a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * @param[in] list_head		containing ptr.
 * @param[in] ptr		to retrieve the next item from.
 *				If ptr is NULL, the HEAD of the list will be returned.
 * @return
 *	- The next item in the list if ptr is not NULL.
 *	- The head of the list if ptr is NULL.
 *	- NULL if ptr is the tail of the list (no more items).
 */
static inline CC_HINT(nonnull(1)) void *fr_tlist_next(fr_tlist_head_t const *list_head, void const *ptr)
{
	return fr_dlist_next(&list_head->dlist_head, ptr);
}

/** Get the previous item in a list
 *
 * @note If #fr_dlist_talloc_init was used to initialise #fr_dlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * @param[in] list_head		containing ptr.
 * @param[in] ptr		to retrieve the prev item from.
 *				If ptr is NULL, the HEAD of the list will be returned.
 * @return
 *	- The prev item in the list if ptr is not NULL.
 *	- The head of the list if ptr is NULL.
 *	- NULL if ptr is the tail of the list (no more items).
 */
static inline CC_HINT(nonnull(1)) void *fr_tlist_prev(fr_tlist_head_t const *list_head, void const *ptr)
{
	return fr_dlist_prev(&list_head->dlist_head, ptr);
}

/** Remove an item from the list
 *
 * @note If #fr_tlist_talloc_init was used to initialise #fr_tlist_head_t
 *	 ptr must be a talloced chunk of the type passed to #fr_tlist_talloc_init.
 *
 * When removing items in an iteration loop, the iterator variable must be
 * assigned the item returned by this function.
 *
 * If the iterator variable is not updated, the item removed will be the last item
 * iterated over, as its prev/prev pointers are set to point to itself.
 @code{.c}
	my_item_t *item = NULL;

	while ((item = fr_tlist_prev(&head, item))) {
		if (item->should_be_removed) {
   			...do things with item
   			item = fr_tlist_remove(&head, item);
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
static inline CC_HINT(nonnull(1)) void *fr_tlist_remove(fr_tlist_head_t *list_head, void *ptr)
{
	fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, ptr);

	entry->list_head = NULL;

	return fr_dlist_remove(&list_head->dlist_head, ptr);
}

/** Remove the head item in a list
 *
 * @param[in] list_head to remove head item from.
 * @return
 *	- The item removed.
 *	- NULL if not items in tlist.
 */
static inline CC_HINT(nonnull(1)) void *fr_tlist_pop_head(fr_tlist_head_t *list_head)
{
	void *item = fr_tlist_head(list_head);

	(void) fr_tlist_remove(list_head, item);

	return item;
}

/** Remove the tail item in a list
 *
 * @param[in] list_head to remove tail item from.
 * @return
 *	- The item removed.
 *	- NULL if not items in tlist.
 */
static inline CC_HINT(nonnull(1)) void *fr_tlist_pop_tail(fr_tlist_head_t *list_head)
{
	void *item = fr_dlist_tail(&list_head->dlist_head);

	(void) fr_dlist_remove(&list_head->dlist_head, item);

	return item;
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
static inline CC_HINT(nonnull) void *fr_tlist_replace(fr_tlist_head_t *list_head, void *item, void *ptr)
{
	fr_tlist_t *item_entry;
	fr_tlist_t *ptr_entry;

	if (!fr_tlist_in_list(list_head, item)) return NULL;

	ptr_entry = fr_tlist_item_to_entry(list_head, ptr);
	fr_dlist_replace(&list_head->dlist_head, item, ptr);
	ptr_entry->list_head = list_head;

	item_entry = fr_tlist_item_to_entry(list_head, item);
	item_entry->list_head = NULL;

	return item;
}


/** Check all items in the list are valid
 *
 * Checks item talloc headers and types to ensure they're consistent
 * with what we expect.
 *
 * Does nothing if the list was not initialised with #fr_tlist_talloc_init.
 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
static inline CC_HINT(nonnull) void fr_tlist_verify(char const *file, int line, fr_tlist_head_t const *list_head)
{
	void *item;

	if (!tlist_type(list_head)) return;

	fr_assert_msg(fr_tlist_initialised(list_head), "CONSISTENCY CHECK FAILED %s[%i]: tlist not initialised",
		      file, line);

	for (item = fr_tlist_head(list_head);
	     item;
	     item = fr_tlist_next(list_head, item)) {
		fr_tlist_t *entry = fr_tlist_item_to_entry(list_head, item);

		fr_assert_msg(entry->list_head == list_head, "CONSISTENCY CHECK FAILED %s[%i]: tlist entry %p has wrong parent",
			      file, line, entry);

		item = _talloc_get_type_abort(item, tlist_type(list_head), __location__);

		if (entry->children) {
			fr_assert_msg(tlist_type(entry->children) != NULL, "CONSISTENCY CHECK FAILED %s[%i]: tlist entry %p has non-talloc'd child list",
				      file, line, entry);

			fr_assert_msg(strcmp(tlist_type(entry->children), tlist_type(list_head)) == 0,
				      "CONSISTENCY CHECK FAILED %s[%i]: tlist entry %p has different child type from parent",
				      file, line, entry);

			fr_tlist_verify(file, line, entry->children);
		}
	}
}
#  define FR_TLIST_VERIFY(_head) fr_tlist_verify(__FILE__, __LINE__, _head)
#elif !defined(NDEBUG)
#  define FR_TLIST_VERIFY(_head) fr_assert(_head)
#else
#  define FR_TLIST_VERIFY(_head)
#endif


/** Merge two lists, inserting the source at the tail of the destination
 *
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_tlist_move(fr_tlist_head_t *list_dst, fr_tlist_head_t *list_src)
{
	void *item;

#ifdef WITH_VERIFY_PTR
	/*
	 *	Must be both talloced or both not
	 */
	if (!fr_cond_assert((tlist_type(list_dst) && tlist_type(list_src)) || (!tlist_type(list_dst) && !tlist_type(list_src)))) return -1;

	/*
	 *	Must be of the same type
	 */
	if (!fr_cond_assert(!tlist_type(list_dst) || (strcmp(tlist_type(list_dst), tlist_type(list_src)) == 0))) return -1;
#endif

	item = fr_dlist_head(&list_src->dlist_head);
	if (!item) return 0;

	if (fr_dlist_move(&list_dst->dlist_head, &list_src->dlist_head) < 0) return -1;

	/*
	 *	Update new parent from the middle of the list to the end.
	 */
	do {
		fr_tlist_t *entry = fr_tlist_item_to_entry(list_src, item);
		entry->list_head = list_dst;
	} while ((item = fr_dlist_next(&list_dst->dlist_head, item)) != NULL);

	return 0;
}

/** Merge two lists, inserting the source at the head of the destination
 *
 * @return
 * 	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(nonnull) int fr_tlist_move_head(fr_tlist_head_t *list_dst, fr_tlist_head_t *list_src)
{
	void *item, *middle;

#ifdef WITH_VERIFY_PTR
	/*
	 *	Must be both talloced or both not
	 */
	if (!fr_cond_assert((tlist_type(list_dst) && tlist_type(list_src)) || (!tlist_type(list_dst) && !tlist_type(list_src)))) return -1;

	/*
	 *	Must be of the same type
	 */
	if (!fr_cond_assert(!tlist_type(list_dst) || (strcmp(tlist_type(list_dst), tlist_type(list_src)) == 0))) return -1;
#endif

	middle = fr_dlist_head(&list_dst->dlist_head);

	if (fr_dlist_move_head(&list_dst->dlist_head, &list_src->dlist_head) < 0) return -1;

	/*
	 *	Update new parent from the start of the list to the middle.
	 */
	for (item = fr_tlist_head(list_dst);
	     item && (item != middle);
	     item = fr_tlist_next(list_dst, item)) {
		fr_tlist_t *entry = fr_tlist_item_to_entry(list_src, item);
		entry->list_head = list_dst;
	}

	return 0;
}

/** Free the first item in the list
 *
 * @param[in] list_head		to free head item in.
 */
static inline void fr_tlist_talloc_free_head(fr_tlist_head_t *list_head)
{
	talloc_free(fr_tlist_pop_head(list_head));
}

/** Free the last item in the list
 *
 * @param[in] list_head		to free tail item in.
 */
static inline void fr_tlist_talloc_free_tail(fr_tlist_head_t *list_head)
{
	talloc_free(fr_tlist_pop_head(list_head));
}

/** Free the item specified
 *
 * @param[in] list_head		to free item in.
 * @param[in] ptr		to remove and free.
 * @return
 *	- NULL if no more items in the list.
 *	- Previous item in the list
 */
static inline void *fr_tlist_talloc_free_item(fr_tlist_head_t *list_head, void *ptr)
{
	void *prev;

	prev = fr_tlist_remove(list_head, ptr);
	talloc_free(ptr);
	return prev;
}

/** Free items in a doubly linked list (with talloc)
 *
 * @param[in] head	of list to free.
 * @param[in] ptr	remove and free from this to the tail.
 */
static inline void fr_tlist_talloc_free_to_tail(fr_tlist_head_t *head, void *ptr)
{
	void *e = ptr, *p;

	if (!ptr) return;	/* uninitialized means don't do anything */

	while (e) {
		p = fr_tlist_next(head, e);
		(void) fr_tlist_remove(head, e);
		talloc_free(e);
		e = p;
	}
}

/** Free all items in a doubly linked list (with talloc)
 *
 * @param[in] head of list to free.
 */
static inline void fr_tlist_talloc_free(fr_tlist_head_t *head)
{
	void *e = NULL, *p;

	while ((e = fr_tlist_next(head, e))) {
		p = fr_tlist_remove(head, e);
		talloc_free(e);
		e = p;
	}
}

/** Free all items in a doubly linked list from the tail backwards
 *
 * @param[in] head of list to free.
 */
static inline void fr_tlist_talloc_reverse_free(fr_tlist_head_t *head)
{
	void *e = NULL, *p;

	e = fr_tlist_tail(head);
	do {
		p = fr_tlist_remove(head, e);
		talloc_free(e);
		e = p;
	} while (e);
}

/** Return the number of elements in the tlist
 *
 * @param[in] list_head of list to count elements for.
 */
static inline unsigned int fr_tlist_num_elements(fr_tlist_head_t const *list_head)
{
	return fr_dlist_num_elements(&list_head->dlist_head);
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
static inline void fr_tlist_sort_split(fr_tlist_head_t *head, void **source, void **front, void **back)
{
	fr_dlist_sort_split(&head->dlist_head, source, front, back);
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
static inline void *fr_tlist_sort_merge(fr_tlist_head_t *head, void **a, void **b, fr_cmp_t cmp)
{
	return fr_dlist_sort_merge(&head->dlist_head, a, b, cmp);
}

/** Recursive sort routine for tlist
 *
 * @param[in] head	of the list being sorted
 * @param[in,out] ptr	to the first item in the current section of the list being sorted.
 * @param[in] cmp	comparison function to sort with
 */
static inline void fr_tlist_recursive_sort(fr_tlist_head_t *head, void **ptr, fr_cmp_t cmp)
{
	fr_dlist_recursive_sort(&head->dlist_head, ptr, cmp);
}

/** Sort a tlist using merge sort
 *
 * @note This routine temporarily breaks the doubly linked nature of the list
 *
 * @param[in,out] list	to sort
 * @param[in] cmp	comparison function to sort with
 */
static inline void fr_tlist_sort(fr_tlist_head_t *list, fr_cmp_t cmp)
{
	fr_dlist_sort(&list->dlist_head, cmp);
}

static inline void fr_tlist_noop(void)
{
	return;
}


/** Expands to the type name used for the entry wrapper structure
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return fr_tlist_<name>_entry_t
 */
#define FR_TLIST_ENTRY(_name) _name ## _entry_t

/** Expands to the type name used for the head wrapper structure
 *
 * @param[in] _name	Prefix we add to type-specific structures.
 * @return fr_tlist_<name>_head_t
 */
#define FR_TLIST_HEAD(_name) _name ## _head_t

/** Define type specific wrapper structs for tlists
 *
 * @note This macro should be used inside the header for the area of code
 * which will use type specific functions.
 */
#define FR_TLIST_TYPES(_name) \
	typedef struct { fr_tlist_t entry; } FR_TLIST_ENTRY(_name); \
	typedef struct { fr_tlist_head_t head; } FR_TLIST_HEAD(_name); \


/** Define type specific wrapper functions for tlists
 *
 * @note This macro should be used inside the source file that will use
 * the type specific functions.
 *
 * @param[in] _name		Prefix we add to type-specific tlist functions.
 * @param[in] _element_type	Type of structure that'll be inserted into the tlist.
 * @param[in] _element_entry	Field in the _element_type that holds the tlist entry information.
 */
#define FR_TLIST_FUNCS(_name, _element_type, _element_entry) \
DIAG_OFF(unused-function) \
	_Static_assert(IS_FIELD_COMPATIBLE(_element_type, _element_entry, FR_TLIST_ENTRY(_name)) == 1, "Bad tlist entry field type");\
	static inline	fr_tlist_head_t *_name ## _list_head(FR_TLIST_HEAD(_name) const *list) \
		{ return	UNCONST(fr_tlist_head_t *, &list->head); } \
\
	static inline	fr_dlist_head_t *_name ## _dlist_head(FR_TLIST_HEAD(_name) const *list) \
		{ return	UNCONST(fr_dlist_head_t *, &list->head.dlist_head); } \
\
	static inline	void _name ## _entry_init(_element_type *entry) \
		{ \
			_Generic((&entry->_element_entry), \
				 FR_TLIST_ENTRY(_name) *: fr_tlist_entry_init(UNCONST(fr_tlist_t *, &entry->_element_entry.entry)), \
				 FR_TLIST_ENTRY(_name) const *: fr_tlist_noop()\
			); \
		} \
\
	static inline	void _name ## _init(FR_TLIST_HEAD(_name) *list) \
		{		_fr_tlist_init(&list->head, offsetof(_element_type, _element_entry), NULL); } \
\
	static inline	void _name ## _talloc_init(FR_TLIST_HEAD(_name) *list) \
		{		_fr_tlist_init(&list->head, offsetof(_element_type, _element_entry), #_element_type); } \
\
	static inline	void _name ## _clear(FR_TLIST_HEAD(_name) *list) \
		{		fr_tlist_clear(&list->head); } \
\
	static inline	bool _name ## _in_list(FR_TLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_tlist_in_list(&list->head, ptr); } \
\
	static inline	bool _name ## _in_a_list(_element_type *ptr) \
		{ return	fr_tlist_entry_in_a_list(&ptr->_element_entry.entry); } \
\
	static inline	int _name ## _insert_head(FR_TLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_tlist_insert_head(&list->head, ptr); } \
\
	static inline	int _name ## _insert_tail(FR_TLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_tlist_insert_tail(&list->head, ptr); } \
\
	static inline	int _name ## _insert_after(FR_TLIST_HEAD(_name) *list, _element_type *pos, _element_type *ptr) \
		{ return	fr_tlist_insert_after(&list->head, pos, ptr); } \
\
	static inline	int _name ## _insert_before(FR_TLIST_HEAD(_name) *list, _element_type *pos, _element_type *ptr) \
		{ return	fr_tlist_insert_before(&list->head, pos, ptr); } \
\
	static inline	_element_type *_name ## _head(FR_TLIST_HEAD(_name) const *list) \
		{ return	fr_tlist_head(&list->head); } \
\
	static inline	bool _name ## _empty(FR_TLIST_HEAD(_name) const *list) \
		{ return	fr_tlist_empty(&list->head); } \
\
	static inline	bool _name ## _initialised(FR_TLIST_HEAD(_name) const *list) \
		{ return	fr_tlist_initialised(&list->head); } \
\
	static inline	_element_type *_name ## _tail(FR_TLIST_HEAD(_name) const *list) \
		{ return	fr_tlist_tail(&list->head); } \
\
	static inline _element_type *_name ## _next(FR_TLIST_HEAD(_name) const *list, _element_type const *ptr) \
		{ return	fr_tlist_next(&list->head, ptr); } \
\
	static inline	_element_type *_name ## _prev(FR_TLIST_HEAD(_name) const *list, _element_type const *ptr) \
		{ return	fr_tlist_prev(&list->head, ptr); } \
\
	static inline	_element_type *_name ## _remove(FR_TLIST_HEAD(_name) *list, _element_type *ptr) \
		{ return	fr_tlist_remove(&list->head, ptr); } \
\
	static inline	_element_type *_name ## _pop_head(FR_TLIST_HEAD(_name) *list) \
		{ return	fr_tlist_pop_head(&list->head); } \
\
	static inline	_element_type *_name ## _pop_tail(FR_TLIST_HEAD(_name) *list) \
		{ return	fr_tlist_pop_tail(&list->head); } \
\
	static inline	_element_type *_name ## _replace(FR_TLIST_HEAD(_name) *list, _element_type *item, _element_type *ptr) \
		{ return	fr_tlist_replace(&list->head, item, ptr); } \
\
	static inline	int _name ## _move(FR_TLIST_HEAD(_name) *dst, FR_TLIST_HEAD(_name) *src) \
		{ return	fr_tlist_move(&dst->head, &src->head); } \
\
	static inline	int _name ## _move_head(FR_TLIST_HEAD(_name) *dst, FR_TLIST_HEAD(_name) *src) \
		{ return	fr_tlist_move_head(&dst->head, &src->head); } \
\
	static inline	void _name ## _talloc_free_head(FR_TLIST_HEAD(_name) *list) \
		{		fr_tlist_talloc_free_head(&list->head); } \
\
	static inline	void _name ## _talloc_free_tail(FR_TLIST_HEAD(_name) *list) \
		{		fr_tlist_talloc_free_tail(&list->head); } \
\
	static inline	void _name ## _talloc_free_item(FR_TLIST_HEAD(_name) *list, _element_type *ptr) \
		{		fr_tlist_talloc_free_item(&list->head, ptr); } \
\
	static inline	void _name ## _talloc_free(FR_TLIST_HEAD(_name) *list) \
		{		fr_tlist_talloc_free(&list->head); } \
\
	static inline	void _name ## _talloc_free_to_tail(FR_TLIST_HEAD(_name) *list, _element_type *ptr) \
		{		fr_tlist_talloc_free_to_tail(&list->head, ptr); } \
\
	static inline	void _name ## _talloc_reverse_free(FR_TLIST_HEAD(_name) *list) \
		{		fr_tlist_talloc_reverse_free(&list->head); } \
\
	static inline	unsigned int _name ## _num_elements(FR_TLIST_HEAD(_name) const *list) \
		{ return	fr_tlist_num_elements(&list->head); } \
\
	static inline	void _name ## _sort(FR_TLIST_HEAD(_name) *list, fr_cmp_t cmp) \
		{		fr_tlist_sort(&list->head, cmp); } \
\
	static inline FR_TLIST_HEAD(_name) *_name ## _parent(const _element_type *ptr) \
		{		return (FR_TLIST_HEAD(_name) *) (ptr->_element_entry.entry.list_head); } \
\
	static inline FR_TLIST_HEAD(_name) *_name ## _children(_element_type *ptr) \
		{		return (FR_TLIST_HEAD(_name) *) (ptr->_element_entry.entry.children); } \
\
	static inline void _name ## _talloc_init_children(_element_type *ptr, FR_TLIST_HEAD(_name) *children) \
		{		_name ## _talloc_init(children); ptr->_element_entry.entry.children = &children->head; } \
\
	static inline void _name ## _add_children(_element_type *ptr, FR_TLIST_HEAD(_name) *children) \
		{		fr_tlist_add_children(&ptr->_element_entry.entry, &children->head); } \
\
	static inline FR_TLIST_HEAD(_name) * _name ## _remove_children(_element_type *ptr) \
		{		return (FR_TLIST_HEAD(_name) *) fr_tlist_remove_children(&ptr->_element_entry.entry); } \
\
	static inline void _name ## _set_head(fr_tlist_head_t *list, _element_type *ptr) \
		{		ptr->_element_entry.entry.list_head = list; }
DIAG_ON(unused-function)

static inline void *fr_tlist_parent(fr_tlist_head_t *list_head, void const *ptr)
{
	fr_tlist_t *entry;

	if (!ptr || !list_head) return NULL;

	entry = fr_tlist_item_to_entry(list_head, ptr);
	if (!entry->list_head) return NULL;

	if (!entry->list_head->parent) return NULL;

	return fr_tlist_entry_to_item(entry->list_head, entry->list_head->parent);
}

/** Initialize a child tlist based on a parent entry
 *
 * @param[in] entry	the entry which will be the parent of the children
 * @param[in] children	structure to initialise.  Usually in the same parent structure as "entry"
 */
static inline void fr_tlist_init_children(fr_tlist_t *entry, fr_tlist_head_t *children)
{
	fr_tlist_head_t *list_head;

	fr_assert(entry->children == NULL);
	fr_assert(entry->list_head != NULL);

	list_head = entry->list_head;

	/*
	 *	Manually re-do fr_tlist_init() here, as we copy offset/type from the parent list.
	 */
	fr_dlist_init(&children->dlist_head, fr_tlist_t, dlist_entry);
	children->dlist_head.offset = list_head->dlist_head.offset;
	children->dlist_head.type = list_head->dlist_head.type;

	children->parent = NULL;

	entry->children = children;
}

/** Add a pre-initialized child tlist to a parent entry.
 *
 * @param[in] entry	the entry which will be the parent of the children
 * @param[in] children	structure to initialise.  Usually in the same parent structure as "entry"
 */
static inline int fr_tlist_add_children(fr_tlist_t *entry, fr_tlist_head_t *children)
{
	if (entry->children) return -1;

	children->parent = entry;

	entry->children = children;

	return 0;
}


/** Remove a child tlist from a parent entry
 *
 * @param[in] entry	the entry which will have the children removed
 */
static inline fr_tlist_head_t *fr_tlist_remove_children(fr_tlist_t *entry)
{
	fr_tlist_head_t *children = entry->children;

	if (!entry->children) return NULL;

	entry->children->parent = NULL;
	entry->children = NULL;

	return children;
}

#ifdef __cplusplus
}
#endif
