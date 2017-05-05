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
#ifndef _FR_TIME_H
#define _FR_TIME_H
/**
 * $Id$
 *
 * @file io/time.h
 * @brief Simple time functions
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(time_h, "$Id$")

/*
 *	For sys/time.h and time.h
 */
#include <freeradius-devel/missing.h>
#include <freeradius-devel/rad_assert.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  A typedef for "server local" time.  This is the time in
 *  nanoseconds since the application started.
 */
typedef uint64_t fr_time_t;

/**
 *  A doubly linked list.
 */
typedef struct fr_dlist_t {
	struct fr_dlist_t *prev;
	struct fr_dlist_t *next;
} fr_dlist_t;

/**
 *  A structure to track the time spent processing a request.
 *
 *  The same structure is used by threads to track when they are
 *  running / waiting.  The functions modifying fr_time_tracking_t all
 *  take an explicit "when" parameter.  This parameter allows the
 *  thread to update a requests tracking structure, and then use that
 *  same fr_time_t to update the threads tracking structure.
 *
 *  While fr_time() is fast, it is also called very often.  We should
 *  therefore be careful to call it only when necessary.
 */
typedef struct fr_time_tracking_t {
	fr_time_t	when;			//!< last time we changed a field
	fr_time_t	start;			//!< time this request started being processed
	fr_time_t	end;			//!< when we stopped processing this request
	fr_time_t	predicted;		//!< predicted processing time for this request
	fr_time_t	yielded;		//!< time this request yielded
	fr_time_t	resumed;		//!< time this request last resumed;
	fr_time_t	running;		//!< total time spent running
	fr_time_t	waiting;		//!< total time spent waiting

	fr_dlist_t	list;			//!< for linking a request to various lists
} fr_time_tracking_t;

#define NANOSEC (1000000000)
#define USEC	(1000000)

/*
 *	Functions to manage a doubly linked list.
 */
#define FR_DLIST_INIT(head) do { head.prev = head.next = &head; } while (0)
static inline void fr_dlist_insert_head(fr_dlist_t *head, fr_dlist_t *entry)
{
	if (!rad_cond_assert(head->next != NULL)) return;
	if (!rad_cond_assert(head->prev != NULL)) return;

	entry->prev = head;
	entry->next = head->next;
	head->next->prev = entry;
	head->next = entry;
}

static inline void fr_dlist_insert_tail(fr_dlist_t *head, fr_dlist_t *entry)
{
	if (!rad_cond_assert(head->next != NULL)) return;
	if (!rad_cond_assert(head->prev != NULL)) return;

	entry->next = head;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;
}

static inline void fr_dlist_remove(fr_dlist_t *entry)
{
	if (!rad_cond_assert(entry->next != NULL)) return;
	if (!rad_cond_assert(entry->prev != NULL)) return;

	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = entry->next = entry;
}

#define FR_DLIST_FIRST(head) (head.next == &head) ? NULL : head.next
#define FR_DLIST_NEXT(head, p_entry) (p_entry->next == &head) ? NULL : p_entry->next
#define FR_DLIST_TAIL(head) (head.prev == &head) ? NULL : head.prev

int fr_time_start(void);
fr_time_t fr_time(void);
void fr_time_to_timeval(struct timeval *tv, fr_time_t when) CC_HINT(nonnull);

void fr_time_tracking_start(fr_time_tracking_t *tt, fr_time_t when) CC_HINT(nonnull);
void fr_time_tracking_end(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_yield(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_resume(fr_time_tracking_t *tt, fr_time_t when) CC_HINT(nonnull);
void fr_time_tracking_debug(fr_time_tracking_t *tt, FILE *fp) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif

#endif /* _FR_TIME_H */
