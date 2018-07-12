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
 * @file io/dlist.h
 * @brief Doubly linked list implementation
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(dlist_h, "$Id$")

/**
 *  A doubly linked list.
 */
typedef struct fr_dlist_t {
	struct fr_dlist_t *prev;
	struct fr_dlist_t *next;
} fr_dlist_t;

typedef struct fr_dlist_head_t {
	size_t		offset;
	fr_dlist_t	entry;
} fr_dlist_head_t;

/*
 *	Functions to manage a doubly linked list.
 */
static inline void fr_dlist_entry_init(fr_dlist_t *entry)
{
	entry->prev = entry->next = entry;
}

static inline void fr_dlist_init(fr_dlist_head_t *head, size_t offset)
{
	fr_dlist_entry_init(&head->entry);
	head->offset = offset;
}

static inline void fr_dlist_insert_head(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	fr_dlist_t *head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	entry->prev = head;
	entry->next = head->next;
	head->next->prev = entry;
	head->next = entry;
}

static inline void fr_dlist_insert_tail(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	fr_dlist_t *head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	entry->next = head;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;
}

#if 0
/*
 *	Insert one list into the tail of another
 */
static inline void fr_dlist_insert_tail_list(fr_dlist_head_t *list_head, fr_dlist_t *list)
{
	fr_dlist_t *head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	list->prev->next = head;
	list->next->prev = head->prev;

	head->prev->next = list->next;
	head->prev = list->prev;

	list->prev = list->next = &list;
}
#endif

static inline void fr_dlist_remove(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);

	if (!fr_cond_assert(entry->next != NULL)) return;
	if (!fr_cond_assert(entry->prev != NULL)) return;

	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = entry->next = entry;
}

static inline void *fr_dlist_next(fr_dlist_head_t *list_head, void *ptr)
{
	fr_dlist_t *entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	fr_dlist_t *head = &(list_head->entry);

	if (entry->next == head) return NULL;
	entry = entry->next;
	return (void *) (((uint8_t *) entry) - list_head->offset);
}

static inline void *fr_dlist_first(fr_dlist_head_t *list_head)
{
	fr_dlist_t *head = &(list_head->entry);

	if (head->next == head) return NULL;

	return (void *) (((uint8_t *) head->next) - list_head->offset);

}

static inline void *fr_dlist_tail(fr_dlist_head_t *list_head)
{
	fr_dlist_t *head = &(list_head->entry);

	if (head->prev == head) return NULL;

	return (void *) (((uint8_t *) head->prev) - list_head->offset);

}

#if 0
#ifdef WITH_VERIFY_PTR
#  define FR_DLIST_VERIFY(_head, _type, _member) \
do { \
	fr_dlist_t *_next; \
	for (_next = FR_DLIST_FIRST(_head); \
	     _next; \
	     _next = FR_DLIST_NEXT(_head, _next)) { \
		(void)talloc_get_type_abort(fr_ptr_to_type(_type, _member, _next), _type); \
	} \
} while(0)
#else
#  define FR_DLIST_VERIFY(_head, _type, _member)
#endif
#endif

/** Convert a pointer to a member into a pointer to the parent structure.
 *
 */
#define fr_ptr_to_type(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))
