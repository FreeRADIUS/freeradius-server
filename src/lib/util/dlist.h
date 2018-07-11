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

/*
 *	Functions to manage a doubly linked list.
 */
#define FR_DLIST_INIT(head) do { head.prev = head.next = &head; } while (0)
static inline void fr_dlist_insert_head(fr_dlist_t *head, fr_dlist_t *entry)
{
	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	entry->prev = head;
	entry->next = head->next;
	head->next->prev = entry;
	head->next = entry;
}

static inline void fr_dlist_insert_tail(fr_dlist_t *head, fr_dlist_t *entry)
{
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
static inline void fr_dlist_insert_tail_list(fr_dlist_t *head, fr_dlist_t *list)
{
	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	list->prev->next = head;
	list->next->prev = head->prev;

	head->prev->next = list->next;
	head->prev = list->prev;

	list->prev = list->next = &list;
}
#endif

static inline void fr_dlist_remove(fr_dlist_t *entry)
{
	if (!fr_cond_assert(entry->next != NULL)) return;
	if (!fr_cond_assert(entry->prev != NULL)) return;

	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = entry->next = entry;
}

#define FR_DLIST_FIRST(head) ((head.next == &head) ? NULL : head.next)
#define FR_DLIST_NEXT(head, p_entry) ((p_entry->next == &head) ? NULL : p_entry->next)
#define FR_DLIST_TAIL(head) ((head.prev == &head) ? NULL : head.prev)

/** Convert a pointer to a member into a pointer to the parent structure.
 *
 */
#define fr_ptr_to_type(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))
