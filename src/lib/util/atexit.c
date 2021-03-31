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
 * @file lib/util/atexit.c
 *
 * @copyright 2020-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/atexit.h>

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <errno.h>
#include <pthread.h>

#if defined(DEBUG_THREAD_LOCAL) && !defined(NDEBUG)
#  define THREAD_LOCAL_DEBUG		FR_FAULT_LOG
#else
#  define THREAD_LOCAL_DEBUG(...)
#endif

typedef struct fr_exit_handler_list_s fr_atexit_list_t;

/** Entry in exit handler list
 *
 */
typedef struct {
	fr_dlist_t			entry;		//!< Entry in the handler dlist.
	fr_atexit_list_t		*list;		//!< List this entry is in.

	fr_atexit_t			func;		//!< Function to call.
	void				*uctx;		//!< uctx to pass.

#ifndef NDEBUG
	char const			*file;		//!< File where this exit handler was added.
	int				line;		//!< Line where this exit handler was added.
#endif
} fr_atexit_entry_t;

/** Head of a list of exit handlers
 *
 */
struct fr_exit_handler_list_s {
	fr_dlist_head_t			head;		//!< Head of the list of destructors

	pthread_key_t			key;		//!< Key used to trigger thread local destructors.
	fr_atexit_entry_t 		*e;		//!< Inserted into the global exit handler list
							///< to ensure this memory is cleaned up.
};

static _Thread_local fr_atexit_list_t	*fr_atexit_thread_local = NULL;
static fr_atexit_list_t			*fr_atexit_global = NULL;
static pthread_mutex_t			fr_atexit_global_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool				is_exiting;


/** Call the exit handler
 *
 */
static int _atexit_entry_free(fr_atexit_entry_t *e)
{
	THREAD_LOCAL_DEBUG("%s - Thread %u freeing %p/%p func=%p, uctx=%p (alloced %s:%u)",
			   __FUNCTION__, (unsigned int)pthread_self(),
			   e->list, e, e->func, e->uctx, e->file, e->line);

	if (fr_dlist_entry_in_list(&e->entry)) fr_dlist_remove(&e->list->head, e);

	/*
	 *	If the exit handler wasn't disarmed, call it...
	 */
	if (e->func) e->func(e->uctx);

	return 0;
}

/** Allocate a new exit handler entry
 *
 */
static fr_atexit_entry_t *atexit_entry_alloc(NDEBUG_LOCATION_ARGS
					     fr_atexit_list_t *list,
					     fr_atexit_t func, void const *uctx)
{
	fr_atexit_entry_t *e;

	e = talloc_zero(list, fr_atexit_entry_t);
	if (unlikely(!e)) return NULL;

	e->list = list;
	e->func = func;
	e->uctx = UNCONST(void *, uctx);

#ifndef NDEBUG
	e->file = file;
	e->line = line;
#endif

	THREAD_LOCAL_DEBUG("%s - Thread %u arming %p/%p func=%p, uctx=%p (alloced %s:%u)",
			   __FUNCTION__, (unsigned int)pthread_self(),
			   list, e, e->func, e->uctx, e->file, e->line);

	fr_dlist_insert_head(&list->head, e);
	talloc_set_destructor(e, _atexit_entry_free);

	return e;
}

/** Talloc destructor for freeing list elements in order
 *
 */
static int _thread_local_list_free(fr_atexit_list_t *list)
{
	THREAD_LOCAL_DEBUG("%s - Freeing _Thread_local destructor list %p",
			   __FUNCTION__, list);

	fr_dlist_talloc_free(&list->head);	/* Free in order */
	list->e->func = NULL;			/* Disarm the global entry that'd free the thread-specific list */
	return 0;
}

/** Run all the thread local destructors
 *
 * @param[in] list	The thread-specific exit handler list.
 */
static void _thread_local_free(void *list)
{
	talloc_free(list);
}

/** Talloc destructor for freeing list elements in order
 *
 */
static int _global_list_free(fr_atexit_list_t *list)
{
	THREAD_LOCAL_DEBUG("%s - Freeing global destructor list %p",
			   __FUNCTION__, list);

	fr_dlist_talloc_free(&list->head);	/* Free in order */
	return 0;
}

/** Free any thread-local exit handler lists that pthread_key failed to fre
 *
 */
static void _global_free(void)
{
	pthread_mutex_lock(&fr_atexit_global_mutex);
	fr_cond_assert_msg(!is_exiting, "Global free function called multiple times");
	is_exiting = true;
	pthread_mutex_unlock(&fr_atexit_global_mutex);

	TALLOC_FREE(fr_atexit_global);
}

/** Setup the atexit handler, should be called at the start of a program's execution
 *
 */
int fr_atexit_global_setup(void)
{
	if (fr_atexit_global) return 0;

	fr_atexit_global = talloc_zero(NULL, fr_atexit_list_t);
	if (unlikely(!fr_atexit_global)) return -1;

	THREAD_LOCAL_DEBUG("%s - Alloced global destructor list %p", __FUNCTION__, fr_atexit_global);

	fr_dlist_talloc_init(&fr_atexit_global->head, fr_atexit_entry_t, entry);
	talloc_set_destructor(fr_atexit_global, _global_list_free);
	atexit(_global_free);	/* Call all remaining destructors at process exit */

	return 0;
}

/** Add a new destructor
 *
 * @return
 *	- 0 on success.
 *      - -1 on memory allocation failure;
 */
int _fr_atexit_thread_local(NDEBUG_LOCATION_ARGS
			    fr_atexit_t func, void const *uctx)
{
	int ret = 0;

	/*
	 *	Initialise the global list containing all the thread-local
	 *	dlist destructors.
	 */
	pthread_mutex_lock(&fr_atexit_global_mutex);
	fr_cond_assert_msg(!is_exiting, "New atexit handlers should not be allocated whilst exiting");
	if (!fr_atexit_global) ret = fr_atexit_global_setup();
	pthread_mutex_unlock(&fr_atexit_global_mutex);
	if (ret < 0) return ret;

	/*
	 *	Initialise the thread local list, just for pthread_exit().
	 */
	if (!fr_atexit_thread_local) {
		fr_atexit_list_t *list;

		/*
		 *	Must be heap allocated, because thread local
		 *	structures can be freed before the key
		 *	destructor is run (depending on platform).
		 */
		list = talloc_zero(NULL, fr_atexit_list_t);
		if (unlikely(!list)) return -1;

		THREAD_LOCAL_DEBUG("%s - Thread %u alloced _Thread_local destructor list %p",
				   __FUNCTION__,
				   (unsigned int)pthread_self(), list);

		fr_dlist_talloc_init(&list->head, fr_atexit_entry_t, entry);
		(void) pthread_key_create(&list->key, _thread_local_free);

		/*
		 *	We need to pass in a pointer to the heap
		 *	memory because, again, the thread local
		 *	indirection table may have disappeared
		 *	by the time the thread destructor is
		 *	called.
		 */
		(void) pthread_setspecific(list->key, list);
		talloc_set_destructor(list, _thread_local_list_free);

		/*
		 *	Add a destructor for the thread-local list
		 *	The pthread based destructor will disarm
		 *	this if it fires, but leave it enabled if
		 *	it doesn't, thus ensuring the memory is
		 *	*always* freed one way or another.
		 */
		pthread_mutex_lock(&fr_atexit_global_mutex);
		list->e = atexit_entry_alloc(NDEBUG_LOCATION_VALS
					     fr_atexit_global,
					     _thread_local_free,
					     list);

		pthread_mutex_unlock(&fr_atexit_global_mutex);

		fr_atexit_thread_local = list;
	}

	/*
	 *	Now allocate the actual atexit handler entry
	 */
	if (atexit_entry_alloc(NDEBUG_LOCATION_VALS fr_atexit_thread_local, func, uctx) == NULL) return -1;

	return 0;
}

/** Remove destructor
 *
 * @return
 *	- 0 on success.
 *      - -1 if function and uctx could not be found.
 */
int fr_atexit_thread_local_disarm(fr_atexit_t func, void const *uctx)
{
	fr_atexit_entry_t *e = NULL;

	if (!fr_atexit_thread_local) return -1;

	while ((e = fr_dlist_next(&fr_atexit_thread_local->head, e))) {
		if ((e->func == func) && (e->uctx == uctx)) {
			THREAD_LOCAL_DEBUG("%s - Thread %u disarming %p/%p func=%p, uctx=%p (alloced %s:%u)",
					   __FUNCTION__,
					   (unsigned int)pthread_self(),
					   fr_atexit_thread_local, e, e->func, e->uctx, e->file, e->line);
			fr_dlist_remove(&fr_atexit_thread_local->head, e);
			talloc_set_destructor(e, NULL);
			talloc_free(e);
			return 0;
		}
	}

	return -1;
}

void fr_atexit_thread_local_disarm_all(void)
{
	fr_atexit_entry_t *e = NULL;

	if (!fr_atexit_thread_local) return;

	while ((e = fr_dlist_pop_head(&fr_atexit_thread_local->head))) {
		THREAD_LOCAL_DEBUG("%s - Thread %u disarming %p/%p func=%p, uctx=%p (alloced %s:%u)",
				   __FUNCTION__,
				   (unsigned int)pthread_self(),
				   fr_atexit_thread_local, e, e->func, e->uctx, e->file, e->line);
		talloc_set_destructor(e, NULL);
		talloc_free(e);
	}
}

/** Iterates through all thread local destructor lists, causing destructor to be triggered
 *
 * This should only be called by the main process, and not by threads.
 *
 * @param[in] func	Entries matching this function will be triggered.
 * @return How many triggers fired.
 */
int fr_atexit_trigger(fr_atexit_t func)
{
	fr_atexit_entry_t		*e = NULL, *ee;
	fr_atexit_list_t		*list;
	unsigned int			count = 0;

	if (!fr_atexit_global) return 0;

	/*
	 *	Iterate over the list of thread local destructor
	 *	lists.
	 */
	while ((e = fr_dlist_next(&fr_atexit_global->head, e))) {
		if (!e->func) continue;	/* thread already joined */

		list = talloc_get_type_abort(e->uctx, fr_atexit_list_t);
		ee = NULL;
		while ((ee = fr_dlist_next(&list->head, ee))) {
			if (ee->func != func) continue;

			count++;
			ee = fr_dlist_talloc_free_item(&list->head, ee);
		}
	}

	return count;
}
