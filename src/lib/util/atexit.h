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
 * @param[in] func to call.
 * @param[in] uctx to pass to func.
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
 * @param[in] _free		function to call. Will be called once
 *				at exit.
 * @param[in] _uctx		data to be passed to free function.
 */
#define fr_atexit_global_once(_init, _free, _uctx) \
{ \
	static atomic_bool	_init_done = false; \
	static pthread_mutex_t	_init_mutex = PTHREAD_MUTEX_INITIALIZER; \
	void *_our_uctx = _uctx; /* stop _uctx being evaluated multiple times, it may be a call to malloc() */ \
	if (unlikely(!atomic_load(&_init_done))) { \
		pthread_mutex_lock(&_init_mutex); \
		if (!atomic_load(&_init_done)) { \
			_init(_our_uctx); \
			fr_atexit_global(_free, _our_uctx); \
			atomic_store(&_init_done, true); \
		} \
		pthread_mutex_unlock(&_init_mutex); \
	} \
}
/** Set a destructor for thread local storage to free the memory on thread exit
 *
 * @note Pointers to thread local storage seem to become unusable as threads are
 *	destroyed.  So we need to store the address of the memory to free, not
 *	the address of the thread local variable.
 *
 * @param[in] _name		Name of variable e.g. 'my_tls'.
 * @param[in] _free		Destructor, called when the thread exits to clean up any data.
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
