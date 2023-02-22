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

/** Functions to help with cleanup
 *
 * Simplifies cleaning up thread local and global resources
 *
 * @file lib/util/atexit.h
 *
 * @copyright 2020-2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2016 The FreeRADIUS server project
 */
RCSIDH(atexit_h, "$Id$")

#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <freeradius-devel/util/talloc.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Destructor callback
 *
 * @param[in] uctx	to free.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int(*fr_atexit_t)(void *uctx);

int fr_atexit_global_setup(void);

int _atexit_global(char const *file, int line, fr_atexit_t func, void const *uctx);

/** Add a free function to the global free list
 *
 * @param[in] _func to call.
 * @param[in] _uctx to pass to func.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
#define fr_atexit_global(_func, _uctx) _atexit_global(__FILE__, __LINE__, _func, _uctx)

unsigned int	fr_atexit_global_disarm(bool uctx_scope, fr_atexit_t func, void const *uctx);

void		fr_atexit_global_disarm_all(void);

int		fr_atexit_global_trigger_all(void);

int		fr_atexit_trigger(bool uctx_scope, fr_atexit_t func, void const *uctx);

bool		fr_atexit_is_exiting(void);

#ifdef HAVE_PTHREADS
/*
 *	Because GCC only added support in 2013 *sigh*
 */
#ifdef TLS_STORAGE_CLASS
#  define _Thread_local TLS_STORAGE_CLASS
#endif

/*
 *  Stop complaints of...:
 *
 *    error: the address of 'x' will always evaluate as 'true' [-Werror=address]
 *
 *  ...when functions are tested directly in the fr_atexit_global_once macro
 */
static inline int _fr_atexit_global_once_funcs(fr_atexit_t init_func, fr_atexit_t free_func, void *uctx)
{
	if (init_func) if (init_func(uctx) < 0) return -1;
	if (free_func) fr_atexit_global(free_func, uctx);

	return 0;
}

/** A generic function to free talloc chunks.  Compatible with the fr_atexit_t type
 *
 * @param[in] to_free	talloc chunk to free.
 * @return the return code returned by talloc_free.
 */
static inline int fr_atexit_talloc_free(void *to_free)
{
	return talloc_free(to_free);
}

/** Setup pair of global init/free functions, returning errors from the specified init function
 *
 * Simplifies setting up data structures the first time a given function
 * is called.
 *
 * Should be used in the body of the function before any initialisation
 * dependent code.
 *
 * Will not share init status outside of the function.
 *
 * @param[out] _ret		A pointer to where to write the result
 *				of the init function if called.
 * @param[in] _init		function to call. Will be called once
 *				during the process lifetime.
 *				May be NULL.
 * @param[in] _free		function to call. Will be called once
 *				at exit.
 *				May be NULL.
 *				Pass fr_atexit_talloc_free if _uctx is
 *				just a talloc chunk and no special logic
 *				is needed.
 * @param[in] _uctx		data to be passed to free function.
 */
#define fr_atexit_global_once_ret(_ret, _init, _free, _uctx) \
{ \
	static atomic_bool	_init_done = false; \
	static pthread_mutex_t	_init_mutex = PTHREAD_MUTEX_INITIALIZER; \
	void *_our_uctx = _uctx; /* stop _uctx being evaluated multiple times, it may be a call to malloc() */ \
	*(_ret) = 0; \
	if (unlikely(!atomic_load(&_init_done))) { \
		pthread_mutex_lock(&_init_mutex); \
		if (!atomic_load(&_init_done)) { \
			if (_fr_atexit_global_once_funcs(_init, _free, _our_uctx) < 0) { \
				*(_ret) = -1; \
			} \
			atomic_store(&_init_done, true); \
		} \
		pthread_mutex_unlock(&_init_mutex); \
	} \
}

/** Setup pair of global init/free functions
 *
 * Simplifies setting up data structures the first time a given function
 * is called.
 *
 * Should be used in the body of the function before any initialisation
 * dependent code.
 *
 * Will not share init status outside of the function.
 *
 * @param[in] _init		function to call. Will be called once
 *				during the process lifetime.
 *				May be NULL.
 * @param[in] _free		function to call. Will be called once
 *				at exit.
 *				May be NULL.
 *				Pass fr_atexit_talloc_free if _uctx is
 *				just a talloc chunk and no special logic
 *				is needed.
 * @param[in] _uctx		data to be passed to free function.
 */
#define fr_atexit_global_once(_init, _free, _uctx) \
	fr_atexit_global_once_ret(&(int){ 0 }, _init, _free, _uctx)

/** Set a destructor for thread local storage to free the memory on thread exit
 *
 * @note Pointers to thread local storage seem to become unusable as threads are
 *	destroyed.  So we need to store the address of the memory to free, not
 *	the address of the thread local variable.
 *
 * @param[in] _name		Name of variable e.g. 'my_tls'.
 * @param[in] _free		Destructor, called when the thread exits to clean up any data.
 *				Pass fr_atexit_talloc_free if _uctx is
 *				just a talloc chunk and no special logic
 *				is needed.
 * @param[in] _uctx		Memory to free.
 */
#  define fr_atexit_thread_local(_name, _free, _uctx) \
do { \
	void *_our_uctx = _uctx; /* stop _uctx being evaluated multiple times, it may be a call to malloc() */ \
	_fr_atexit_thread_local(__FILE__, __LINE__, _free, _our_uctx); \
	_name = _our_uctx; \
} while (0);

int		_fr_atexit_thread_local(char const *file, int line,
					fr_atexit_t func, void const *uctx);

unsigned int	fr_atexit_thread_local_disarm(bool uctx_scope, fr_atexit_t func, void const *uctx);

void		fr_atexit_thread_local_disarm_all(void);

int		fr_atexit_thread_trigger_all(void);

/*
 *	If we're building without threading support,
 *	all this becomes much easier, and we just map
 *	all thread local cleanup entries to the global
 *	list.
 */
#else
/*
 *	Don't emit a _Thread_local_storage qualifier
 */
#  define __Thread_local
#  define fr_atexit_global_once(_init, _free, _uctx) \
do { \
	static bool _init_done = false; \
	void * _our_uctx = _uctx; /* stop _uctx being evaluated multiple times, it may be a call to malloc() */ \
	if (unlikely(!_init_done)) { \
		_init(_our_uctx); \
		fr_atexit_global(_free, _our_uctx); \
		_init_done = true; \
	} \
} while(0);
#  define fr_atexit_thread_local(_name, _free, _uctx) \
do { \
	static bool _init_done = false; \
	void * _our_uctx = _uctx; /* stop _uctx being evaluated multiple times, it may be a call to malloc() */ \
	if (unlikely(!_init_done)) { \
		fr_atexit_global(_free, _our_uctx); \
		_init_done = true; \
	} \
	_name = _our_uctx; \
} while(0);
#  define fr_atexit_thread_local_disarm(...)		fr_atexit_global_disarm(__VA_ARGS__)
#  define fr_atexit_thread_local_disarm_all(...)	fr_atexit_global_disarm_all(__VA_ARGS__)
#  define fr_atexit_thread_trigger_all(...)
#endif

#ifdef __cplusplus
}
#endif
