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

/** Macros to abstract Thread Local Storage
 *
 * Simplifies calling thread local destructors (called when the thread exits).
 *
 * @file lib/util/thread_local.c
 *
 * @copyright 2020 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/thread_local.h>
#include <freeradius-devel/util/dlist.h>

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <errno.h>
#include <pthread.h>
#include <talloc.h>

/** Entry in exit handler list
 *
 */
typedef struct {
	fr_dlist_t			entry;		//!< Entry in the handler dlist.

	fr_thread_local_atexit_t	func;		//!< Function to call.
	void				*uctx;		//!< uctx to pass.
} fr_exit_handler_entry_t;

/** Head of a list of exit handlers
 *
 */
typedef struct {
	fr_dlist_head_t			head;		//!< Head of the list of destructors

	pthread_key_t			key;		//!< Key used to trigger thread local destructors.
	fr_exit_handler_entry_t 	*e;		//!< Inserted into the global exit handler list
							///< to ensure this memory is cleaned up.
} fr_exit_handler_list_t;

_Thread_local fr_exit_handler_list_t	*thread_local_atexit = NULL;
static fr_exit_handler_list_t		*global_atexit = NULL;
static pthread_mutex_t			global_atexit_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool				is_exiting;


/** Call the exit handler
 *
 */
static int _exit_handler_entry_free(fr_exit_handler_entry_t *e)
{
	if (fr_dlist_entry_in_list(&e->entry)) fr_dlist_entry_unlink(&e->entry);

	/*
	 *	If the exit handler wasn't disarmed, call it...
	 */
	if (e->func) e->func(e->uctx);

	return 0;
}

/** Allocate a new exit handler entry
 *
 */
static fr_exit_handler_entry_t *exit_handler_entry_alloc(fr_exit_handler_list_t *list,
							 fr_thread_local_atexit_t func, void const *uctx)
{
	fr_exit_handler_entry_t *e;

	e = talloc_zero(list, fr_exit_handler_entry_t);
	if (unlikely(!e)) return NULL;

	e->func = func;
	memcpy(&e->uctx, &uctx, sizeof(e->uctx));
	fr_dlist_insert_head(&list->head, e);
	talloc_set_destructor(e, _exit_handler_entry_free);

	return e;
}

/** Talloc destructor for freeing list elements in order
 *
 */
static int _thread_local_list_free(fr_exit_handler_list_t *ehl)
{
	fr_dlist_talloc_free(&ehl->head);	/* Free in order */
	ehl->e->func = NULL;			/* Disarm the global entry that'd free the thread-specific list */
	return 0;
}

/** Run all the thread local destructors
 *
 * @param[in] ehl	The thread-specific exit handler list.
 */
static void _thread_local_free(void *ehl)
{
	talloc_free(ehl);
}

/** Talloc destructor for freeing list elements in order
 *
 */
static int _global_list_free(fr_exit_handler_list_t *ehl)
{
	fr_dlist_talloc_free(&ehl->head);	/* Free in order */
	return 0;
}

/** Free any thread-local exit handler lists that pthread_key failed to fre
 *
 */
static void _global_free(void)
{
	pthread_mutex_lock(&global_atexit_mutex);
	fr_cond_assert_msg(!is_exiting, "Global free function called multiple times");
	is_exiting = true;
	pthread_mutex_unlock(&global_atexit_mutex);

	TALLOC_FREE(global_atexit);
}

/** Setup the atexit handler, should be called at the start of a program's execution
 *
 */
int fr_thread_local_atexit_setup(void)
{
	if (global_atexit) return 0;

	global_atexit = talloc_zero(NULL, fr_exit_handler_list_t);
	if (unlikely(!global_atexit)) return -1;

	fr_dlist_talloc_init(&global_atexit->head, fr_exit_handler_entry_t, entry);
	talloc_set_destructor(global_atexit, _global_list_free);
	atexit(_global_free);	/* Call all remaining destructors at process exit */

	return 0;
}

/** Add a new destructor
 *
 * @return
 *	- 0 on success.
 *      - -1 on memory allocation failure;
 */
int fr_thread_local_atexit(fr_thread_local_atexit_t func, void const *uctx)
{
	int ret = 0;

	/*
	 *	Initialise the global list containing all the thread-local
	 *	dlist destructors.
	 */
	pthread_mutex_lock(&global_atexit_mutex);
	fr_cond_assert_msg(!is_exiting, "New atexit handlers should not be allocated whilst exiting");
	if (!global_atexit) ret = fr_thread_local_atexit_setup();
	pthread_mutex_unlock(&global_atexit_mutex);
	if (ret < 0) return ret;

	/*
	 *	Initialise the thread local list, just for pthread_exit().
	 */
	if (!thread_local_atexit) {
		/*
		 *	Must be heap allocated, because thread local
		 *	structures can be freed before the key
		 *	destructor is run (depending on platform).
		 */
		thread_local_atexit = talloc_zero(NULL, fr_exit_handler_list_t);
		if (unlikely(!thread_local_atexit)) return -1;

		fr_dlist_talloc_init(&thread_local_atexit->head, fr_exit_handler_entry_t, entry);
		(void) pthread_key_create(&thread_local_atexit->key, _thread_local_free);

		/*
		 *	We need to pass in a pointer to the heap
		 *	memory because, again, the thread local
		 *	indirection table may have disappeared
		 *	by the time the thread destructor is
		 *	called.
		 */
		(void) pthread_setspecific(thread_local_atexit->key, thread_local_atexit);
		talloc_set_destructor(thread_local_atexit, _thread_local_list_free);

		/*
		 *	Add a destructor for the thread-local list
		 *	The pthread based destructor will disarm
		 *	this if it fires, but leave it enabled if
		 *	it doesn't, thus ensuring the memory is
		 *	*always* freed one way or another.
		 */
		pthread_mutex_lock(&global_atexit_mutex);
		thread_local_atexit->e = exit_handler_entry_alloc(global_atexit,
								  _thread_local_free,
								  thread_local_atexit);
		pthread_mutex_unlock(&global_atexit_mutex);
	}

	/*
	 *	Now allocate the actual atexit handler entry
	 */
	if (exit_handler_entry_alloc(thread_local_atexit, func, uctx) == NULL) return -1;

	return 0;
}

