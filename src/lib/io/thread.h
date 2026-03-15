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
 * @file io/thread.h
 * @brief Common thread instantiation and detach for worker and coordinator threads
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(thread_h, "$Id$")

#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/semaphore.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/dlist.h>

#include <pthread.h>

/**
 *  Track the child thread status.
 */
typedef enum fr_thread_status_t {
	FR_THREAD_FREE = 0,			//!< child is free
	FR_THREAD_INITIALIZING,			//!< initialized, but not running
	FR_THREAD_RUNNING,			//!< running, and in the running queue
	FR_THREAD_EXITED,			//!< exited, and in the exited queue
	FR_THREAD_FAIL				//!< failed, and in the exited queue
} fr_thread_status_t;

typedef struct {
	char const		*name;		//!< of this thread
	int			id;		//!< unique ID for this thread
	fr_thread_status_t	status;		//!< running, etc.
	pthread_t		pthread_id;	//!< of this thread

	TALLOC_CTX		*ctx;  		//!< our allocation ctx
	fr_event_list_t		*el;   		//!< our event list

	/*
	 *	This field is owned and managed by the parent coordinator thread.
	 */
	fr_dlist_t		entry;		//!< entry into the parent linked list of threads
} fr_thread_t;

typedef void *(*fr_thread_entry_t)(void *);

int	fr_thread_create(pthread_t *thread, fr_thread_entry_t func, void *arg) CC_HINT(nonnull(1,2));

int	fr_thread_wait(fr_sem_t *sem, fr_dlist_head_t *head) CC_HINT(nonnull);

int	fr_thread_setup(fr_thread_t *out, char const *name) CC_HINT(nonnull);

int	fr_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el) CC_HINT(nonnull);

void	fr_thread_detach(void);
