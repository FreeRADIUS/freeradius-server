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
#include <freeradius-devel/util/atexit.h>

#ifdef HAVE_PTHREADS
#include <pthread.h>
#endif

#if defined(DEBUG_ATEXIT) && !defined(NDEBUG)
#  define ATEXIT_DEBUG		FR_FAULT_LOG
#else
#  define ATEXIT_DEBUG(...)
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

	char const			*file;		//!< File where this exit handler was added.
	int				line;		//!< Line where this exit handler was added.
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

#ifdef HAVE_PTHREADS
static _Thread_local fr_atexit_list_t	*fr_atexit_thread_local = NULL;
static fr_atexit_list_t			*fr_atexit_threads = NULL;
static pthread_mutex_t			fr_atexit_global_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static fr_atexit_list_t			*fr_atexit_global = NULL;
static bool				is_exiting;

/** Call the exit handler
 *
 */
static int _atexit_entry_free(fr_atexit_entry_t *e)
{
	ATEXIT_DEBUG("%s - Thread %u freeing %p/%p func=%p, uctx=%p (alloced %s:%u)",
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
static fr_atexit_entry_t *atexit_entry_alloc(char const *file, int line,
					     fr_atexit_list_t *list,
					     fr_atexit_t func, void const *uctx)
{
	fr_atexit_entry_t *e;

	e = talloc_zero(list, fr_atexit_entry_t);
	if (unlikely(!e)) return NULL;

	e->list = list;
	e->func = func;
	e->uctx = UNCONST(void *, uctx);
	e->file = file;
	e->line = line;

	ATEXIT_DEBUG("%s - Thread %u arming %p/%p func=%p, uctx=%p (alloced %s:%u)",
		     __FUNCTION__, (unsigned int)pthread_self(),
		     list, e, e->func, e->uctx, e->file, e->line);

	fr_dlist_insert_head(&list->head, e);
	talloc_set_destructor(e, _atexit_entry_free);

	return e;
}

/** Talloc destructor for freeing list elements in order
 *
 */
static int _destructor_list_free(fr_atexit_list_t *list)
{
	ATEXIT_DEBUG("%s - Freeing destructor list %p", __FUNCTION__, list);

	fr_dlist_talloc_free(&list->head);	/* Free in order */
	return 0;
}

/** Free any thread-local exit handler lists that pthread_key failed to fre
 *
 */
static void _global_free(void)
{
#ifdef HAVE_PTHREADS
	pthread_mutex_lock(&fr_atexit_global_mutex);
#endif

	fr_cond_assert_msg(!is_exiting, "Global free function called multiple times");
	is_exiting = true;

#ifdef HAVE_PTHREADS
	pthread_mutex_unlock(&fr_atexit_global_mutex);
	TALLOC_FREE(fr_atexit_threads);	/* Forcefully cleanup any thread-specific memory */
#endif
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

	ATEXIT_DEBUG("%s - Alloced global destructor list %p", __FUNCTION__, fr_atexit_global);

	fr_dlist_talloc_init(&fr_atexit_global->head, fr_atexit_entry_t, entry);
	talloc_set_destructor(fr_atexit_global, _destructor_list_free);

#ifdef HAVE_PTHREADS
	fr_atexit_threads = talloc_zero(NULL, fr_atexit_list_t);
	if (unlikely(!fr_atexit_threads)) return -1;

	ATEXIT_DEBUG("%s - Alloced threads destructor list %p", __FUNCTION__, fr_atexit_threads);

	fr_dlist_talloc_init(&fr_atexit_threads->head, fr_atexit_entry_t, entry);
	talloc_set_destructor(fr_atexit_threads, _destructor_list_free);
#endif

	atexit(_global_free);	/* Call all remaining destructors at process exit */

	return 0;
}

#ifdef HAVE_PTHREADS
#define CHECK_GLOBAL_SETUP() \
do { \
	int _ret = 0; \
	pthread_mutex_lock(&fr_atexit_global_mutex); \
	fr_cond_assert_msg(!is_exiting, "New atexit handlers should not be allocated whilst exiting"); \
	if (!fr_atexit_global) _ret = fr_atexit_global_setup(); \
	pthread_mutex_unlock(&fr_atexit_global_mutex); \
	if (_ret < 0) return _ret; \
} while(0)
#else
#define CHECK_GLOBAL_SETUP() \
do { \
	int _ret = 0; \
	fr_cond_assert_msg(!is_exiting, "New atexit handlers should not be allocated whilst exiting"); \
	if (!fr_atexit_global) _ret = fr_atexit_global_setup(); \
	if (_ret < 0) return _ret; \
} while(0)
#endif

/** Add a free function to be called when the process exits
 *
 */
int _atexit_global(char const *file, int line, fr_atexit_t func, void const *uctx)
{
	CHECK_GLOBAL_SETUP();

	if (unlikely(atexit_entry_alloc(file, line, fr_atexit_global, func, uctx) == NULL)) return -1;

	return 0;
}

/** Remove a specific global destructor (without executing it)
 *
 * @note This function's primary purpose is to help diagnose issues with destructors
 *	 from within a debugger.
 *
 * @param[in] uctx_scope	Only process entries where the func and scope both match.
 * @param[in] func		Entries matching this function will be disarmed.
 * @param[in] uctx		associated with the entry.
 * @return How many global destructors were disarmed.
 */
unsigned int fr_atexit_global_disarm(bool uctx_scope, fr_atexit_t func, void const *uctx)
{
	fr_atexit_entry_t 	*e = NULL;
	unsigned int		count = 0;

	while ((e = fr_dlist_next(&fr_atexit_global->head, e))) {
		fr_atexit_entry_t *disarm;

		if ((e->func != func) || ((e->uctx != uctx) && uctx_scope)) continue;

		ATEXIT_DEBUG("%s - Disarming %p/%p func=%p, uctx=%p (alloced %s:%u)",
			     __FUNCTION__,
			     fr_atexit_global, e, e->func, e->uctx, e->file, e->line);

		disarm = e;
		e = fr_dlist_remove(&fr_atexit_global->head, e);
		talloc_set_destructor(disarm, NULL);
		talloc_free(disarm);

		count++;
	}

	return count;
}

/** Remove all global destructors (without executing them)
 *
 * @note This function's primary purpose is to help diagnose issues with destructors
 *	 from within a debugger.
 */
void fr_atexit_global_disarm_all(void)
{
	fr_atexit_entry_t *e = NULL;

	if (!fr_atexit_global) return;

	while ((e = fr_dlist_pop_head(&fr_atexit_global->head))) {
		ATEXIT_DEBUG("%s - Disarming %p/%p func=%p, uctx=%p (alloced %s:%u)",
			     __FUNCTION__,
			     fr_atexit_global, e, e->func, e->uctx, e->file, e->line);

		talloc_set_destructor(e, NULL);
		talloc_free(e);
	}
}

/** Cause all global free triggers to fire
 *
 * This is necessary when libraries (perl) register their own
 * atexit handlers using the normal POSIX mechanism, and we need
 * to ensure all our atexit handlers fire before so any global
 * deinit is done explicitly by us.
 *
 * @return
 *      - >= 0 The number of atexit handlers triggered on success.
 *      - <0 the return code from any atexit handlers that returned an error.
 */
int fr_atexit_global_trigger_all(void)
{
	fr_atexit_entry_t		*e = NULL, *to_free;
	unsigned int			count = 0;

	/*
	 *	Iterate over the list of thread local
	 *	destructor lists running the
	 *	destructors.
	 */
	while ((e = fr_dlist_next(&fr_atexit_global->head, e))) {
		ATEXIT_DEBUG("%s - Triggering %p/%p func=%p, uctx=%p (alloced %s:%u)",
			     __FUNCTION__,
			     fr_atexit_global, e, e->func, e->uctx, e->file, e->line);

		count++;
		to_free = e;
		e = fr_dlist_remove(&fr_atexit_global->head, e);
		if (talloc_free(to_free) < 0) {
			fr_strerror_printf_push("atexit handler failed %p/%p func=%p, uctx=%p"
						" (alloced %s:%u)",
						fr_atexit_global, to_free,
						to_free->func, to_free->uctx,
						to_free->file, to_free->line);
			return -1;
		}
	}

	return count;
}

/** Iterates through all thread local destructor lists, causing destructor to be triggered
 *
 * This should only be called by the main process not by threads.
 *
 * The main purpose of the function is to force cleanups at a specific time for problematic
 * destructors.
 *
 * @param[in] uctx_scope	Only process entries where the func and scope both match.
 * @param[in] func		Entries matching this function will be triggered.
 * @param[in] uctx		associated with the entry.
 * @return
 *      - >= 0 The number of atexit handlers triggered on success.
 *      - <0 the return code from any atexit handlers that returned an error.
 */
int fr_atexit_trigger(bool uctx_scope, fr_atexit_t func, void const *uctx)
{
	fr_atexit_entry_t		*e = NULL, *to_free;
#ifdef HAVE_PTHREADS
	fr_atexit_entry_t		*ee;
	fr_atexit_list_t		*list;
#endif
	unsigned int			count = 0;

	if (!fr_atexit_global) goto do_threads;

	/*
	 *	Iterate over the global destructors
	 */
	while ((e = fr_dlist_next(&fr_atexit_global->head, e))) {
		if ((e->func != func) || ((e->uctx != uctx) && uctx_scope)) continue;

		ATEXIT_DEBUG("%s - Triggering %p/%p func=%p, uctx=%p (alloced %s:%u)",
			     __FUNCTION__,
			     fr_atexit_global, e, e->func, e->uctx, e->file, e->line);

		count++;
		to_free = e;
		e = fr_dlist_remove(&fr_atexit_global->head, e);
		if (talloc_free(to_free) < 0) {
			fr_strerror_printf_push("atexit handler failed %p/%p func=%p, uctx=%p"
						" (alloced %s:%u)",
						fr_atexit_global, to_free,
						to_free->func, to_free->uctx,
						to_free->file, to_free->line);
			return -1;
		}
	}
	e = NULL;

do_threads:
#ifdef HAVE_PTHREADS
	if (!fr_atexit_threads) return 0;

	/*
	 *	Iterate over the list of thread local
	 *	destructor lists running the
	 *	destructors.
	 */
	while ((e = fr_dlist_next(&fr_atexit_threads->head, e))) {
		if (!e->func) continue;	/* thread already joined */

		list = talloc_get_type_abort(e->uctx, fr_atexit_list_t);
		ee = NULL;
		while ((ee = fr_dlist_next(&list->head, ee))) {
			if ((ee->func != func) || ((ee->uctx != uctx) && uctx_scope)) continue;

			ATEXIT_DEBUG("%s - Thread %u triggering %p/%p func=%p, uctx=%p (alloced %s:%u)",
				     __FUNCTION__,
				     (unsigned int)pthread_self(),
				     list, ee, ee->func, ee->uctx, ee->file, ee->line);

			count++;
			to_free = ee;
			ee = fr_dlist_remove(&list->head, ee);
			if (talloc_free(to_free) < 0) {
				fr_strerror_printf_push("atexit handler failed %p/%p func=%p, uctx=%p"
							" (alloced %s:%u)",
							list, to_free,
							to_free->func, to_free->uctx,
							to_free->file, to_free->line);
				return -1;
			}
		}
	}
#endif

	return count;
}


/** Return whether we're currently in the teardown phase
 *
 * When this function returns true no more thread local or global
 * destructors can be added.
 */
bool fr_atexit_is_exiting(void)
{
	return is_exiting;
}

#ifdef HAVE_PTHREADS
/** Talloc destructor for freeing list elements in order
 *
 */
static int _thread_local_list_free(fr_atexit_list_t *list)
{
	ATEXIT_DEBUG("%s - Freeing _Thread_local destructor list %p",  __FUNCTION__, list);

	fr_dlist_talloc_free(&list->head);	/* Free in order */
	list->e->func = NULL;			/* Disarm the global entry that'd free the thread-specific list */
	return 0;
}

/** Run all the thread local destructors
 *
 * @param[in] list	The thread-specific exit handler list.
 */
static void _thread_local_pthread_free(void *list)
{
	talloc_free(list);
}

/** Run all the thread local destructors
 *
 * @param[in] list	The thread-specific exit handler list.
 */
static int _thread_local_free(void *list)
{
	return talloc_free(list);
}

/** Add a new destructor
 *
 * @return
 *	- 0 on success.
 *      - -1 on memory allocation failure;
 */
int _fr_atexit_thread_local(char const *file, int line,
			    fr_atexit_t func, void const *uctx)
{
	CHECK_GLOBAL_SETUP();

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

		ATEXIT_DEBUG("%s - Thread %u alloced _Thread_local destructor list %p",
			     __FUNCTION__,
			     (unsigned int)pthread_self(), list);

		fr_dlist_talloc_init(&list->head, fr_atexit_entry_t, entry);
		(void) pthread_key_create(&list->key, _thread_local_pthread_free);

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
		list->e = atexit_entry_alloc(file, line,
					     fr_atexit_threads,
					     _thread_local_free,
					     list);

		pthread_mutex_unlock(&fr_atexit_global_mutex);

		fr_atexit_thread_local = list;
	}

	/*
	 *	Now allocate the actual atexit handler entry
	 */
	if (atexit_entry_alloc(file, line, fr_atexit_thread_local, func, uctx) == NULL) return -1;

	return 0;
}

/** Remove a specific destructor for this thread (without executing them)
 *
 * @note This function's primary purpose is to help diagnose issues with destructors
 *	 from within a debugger.
 *
 * @param[in] uctx_scope	Only process entries where the func and scope both match.
 * @param[in] func		Entries matching this function will be disarmed.
 * @param[in] uctx		associated with the entry.
 * @return How many destructors were disarmed.
 */
unsigned int fr_atexit_thread_local_disarm(bool uctx_scope, fr_atexit_t func, void const *uctx)
{
	fr_atexit_entry_t 	*e = NULL;
	unsigned int		count = 0;

	if (!fr_atexit_thread_local) return -1;

	while ((e = fr_dlist_next(&fr_atexit_thread_local->head, e))) {
		fr_atexit_entry_t *disarm;

		if ((e->func != func) || ((e->uctx != uctx) && uctx_scope)) continue;

		ATEXIT_DEBUG("%s - Thread %u disarming %p/%p func=%p, uctx=%p (alloced %s:%u)",
			     __FUNCTION__,
			     (unsigned int)pthread_self(),
			     fr_atexit_thread_local, e, e->func, e->uctx, e->file, e->line);
		disarm = e;
		e = fr_dlist_remove(&fr_atexit_thread_local->head, e);
		talloc_set_destructor(disarm, NULL);
		talloc_free(disarm);

		count++;
	}

	return count;
}

/** Remove all destructors for this thread (without executing them)
 *
 * @note This function's primary purpose is to help diagnose issues with destructors
 *	 from within a debugger.
 */
void fr_atexit_thread_local_disarm_all(void)
{
	fr_atexit_entry_t *e = NULL;

	if (!fr_atexit_thread_local) return;

	while ((e = fr_dlist_pop_head(&fr_atexit_thread_local->head))) {
		ATEXIT_DEBUG("%s - Thread %u disarming %p/%p func=%p, uctx=%p (alloced %s:%u)",
			     __FUNCTION__,
			     (unsigned int)pthread_self(),
			     fr_atexit_thread_local, e, e->func, e->uctx, e->file, e->line);
		talloc_set_destructor(e, NULL);
		talloc_free(e);
	}
}

/** Cause all thread local free triggers to fire
 *
 * This is necessary when we're running in single threaded mode
 * to ensure all "thread-local" memory (which isn't actually thread local)
 * is cleaned up.
 *
 * One example is the OpenSSL log BIOs which must be cleaned up
 * before fr_openssl_free is called.
 *
 * @return
 *      - >= 0 The number of atexit handlers triggered on success.
 *      - <0 the return code from any atexit handlers that returned an error.
 */
int fr_atexit_thread_trigger_all(void)
{
	fr_atexit_entry_t		*e = NULL, *ee, *to_free;
	fr_atexit_list_t		*list;
	unsigned int			count = 0;

	/*
	 *	Iterate over the list of thread local
	 *	destructor lists running the
	 *	destructors.
	 */
	while ((e = fr_dlist_next(&fr_atexit_threads->head, e))) {
		if (!e->func) continue;	/* thread already joined */

		list = talloc_get_type_abort(e->uctx, fr_atexit_list_t);
		ee = NULL;
		while ((ee = fr_dlist_next(&list->head, ee))) {
			ATEXIT_DEBUG("%s - Thread %u triggering %p/%p func=%p, uctx=%p (alloced %s:%u)",
				     __FUNCTION__,
				     (unsigned int)pthread_self(),
				     list, ee, ee->func, ee->uctx, ee->file, ee->line);

			count++;
			to_free = ee;
			ee = fr_dlist_remove(&list->head, ee);
			if (talloc_free(to_free) < 0) {
				fr_strerror_printf_push("atexit handler failed %p/%p func=%p, uctx=%p"
							" (alloced %s:%u)",
							list, to_free,
							to_free->func, to_free->uctx,
							to_free->file, to_free->line
							);
				return -1;
			}
		}
	}

	return count;
}
#endif
