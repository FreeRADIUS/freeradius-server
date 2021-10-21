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

/** Functions to help with thread local destructors
 *
 * Simplifies calling thread local destructors (called when the thread exits).
 *
 * @file lib/util/atexit.h
 *
 * @copyright 2020-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2016 The FreeRADIUS server project
 */
RCSIDH(atexit_h, "$Id$")

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
 */
#define fr_atexit_global_once(_init, _free) \
{ \
	static atomic_bool	_init_done = false; \
	static pthread_mutex_t	_init_mutex = PTHREAD_MUTEX_INITIALIZER; \
	if (unlikely(!atomic_load(&_init_done))) { \
		pthread_mutex_lock(&_init_mutex); \
		if (!atomic_load(&_init_done)) { \
			_init(); \
			atexit(_free); \
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
 * @param _n	Name of variable e.g. 'my_tls'.
 * @param _f	Destructor, called when the thread exits to clean up any data.
 * @param _v	Memory to free.
 */
#  define fr_atexit_thread_local(_n, _f, _v) \
do { \
	_fr_atexit_thread_local(NDEBUG_LOCATION_EXP _f, _v); \
	_n = _v; \
} while (0);
int	_fr_atexit_thread_local(NDEBUG_LOCATION_ARGS
				fr_atexit_t func, void const *uctx);

int	fr_atexit_thread_local_disarm(fr_atexit_t func, void const *uctx);

void	fr_atexit_thread_local_disarm_all(void);

int	fr_atexit_trigger(fr_atexit_t func);

#ifdef __cplusplus
}
#endif
