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

/** Macros to abstract Thread Local Storage
 *
 * Simplifies calling thread local destructors (called when the thread exits).
 *
 * @file lib/util/thread_local.h
 *
 * @copyright 2013-2016 The FreeRADIUS server project
 */
RCSIDH(thread_local_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Because GCC only added support in 2013 *sigh*
 */
#ifdef TLS_STORAGE_CLASS
#  define _Thread_local TLS_STORAGE_CLASS
#endif

typedef void(*fr_thread_local_atexit_t)(void *uctx);

int fr_thread_local_atexit(fr_thread_local_atexit_t func, void const *uctx);

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
#  define fr_thread_local_set_destructor(_n, _f, _v) \
do { \
	fr_thread_local_atexit(_f, _v); \
	_n = _v; \
} while (0);

#ifdef __cplusplus
}
#endif
