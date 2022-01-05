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

/*
 *	Because GCC only added support in 2013 *sigh*
 */
#ifdef TLS_STORAGE_CLASS
#  define _Thread_local TLS_STORAGE_CLASS
#endif

/** Destructor callback
 *
 * @param[in] uctx	to free.
 */
typedef void(*fr_atexit_t)(void *uctx);

int fr_atexit_global_setup(void);

int _atexit_global(NDEBUG_LOCATION_ARGS fr_atexit_t func, void const *uctx);

/** Add a free function to the global free list
 *
 * @param[in] func to call.
 * @param[in] uctx to pass to func.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
#define fr_atexit_global(_func, _uctx) \
	_atexit_global(NDEBUG_LOCATION_EXP _func, _uctx)

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
	if (unlikely(!atomic_load(&_init_done))) { \
		pthread_mutex_lock(&_init_mutex); \
		if (!atomic_load(&_init_done)) { \
			_init(_uctx); \
			fr_atexit_global(_free, _uctx); \
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
	_fr_atexit_thread_local(NDEBUG_LOCATION_EXP _free, _uctx); \
	_name = _uctx; \
} while (0);

int		_fr_atexit_thread_local(NDEBUG_LOCATION_ARGS
					fr_atexit_t func, void const *uctx);

unsigned int	fr_atexit_thread_local_disarm(bool uctx_scope, fr_atexit_t func, void const *uctx);

void		fr_atexit_thread_local_disarm_all(void);

unsigned int	fr_atexit_global_disarm(bool uctx_scope, fr_atexit_t func, void const *uctx);

void		fr_atexit_global_disarm_all(void);

unsigned int	fr_atexit_trigger(bool uctx_scope, fr_atexit_t func, void const *uctx);

#ifdef __cplusplus
}
#endif
