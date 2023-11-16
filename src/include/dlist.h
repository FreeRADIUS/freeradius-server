/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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

/**
 * $Id$
 *
 * @file dlist.h
 * @brief doubly linked lists
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

#ifndef RADIUS_DLIST_H
#define RADIUS_DLIST_H

RCSIDH(dlist_h, "$Id$")

/*
 *	We have an internal cache, keyed by (mac + ssid).
 *
 *	It returns the PMK and PSK for the user.
 */
typedef struct fr_dlist_s fr_dlist_t;

struct fr_dlist_s {
	fr_dlist_t	*prev;
	fr_dlist_t	*next;
};

static inline void fr_dlist_entry_init(fr_dlist_t *entry)
{
	entry->prev = entry->next = entry;
}

static inline CC_HINT(nonnull) void fr_dlist_entry_unlink(fr_dlist_t *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = entry->next = entry;
}

static inline CC_HINT(nonnull) void fr_dlist_insert_tail(fr_dlist_t *head, fr_dlist_t *entry)
{
	entry->next = head;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;
}

#endif	/* RADIUS_DLIST_H */
