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

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <errno.h>
#include <pthread.h>

typedef void (*pthread_destructor_t)(void*);

/*
 *	Because GCC only added support in 2013 *sigh*
 */
#ifdef TLS_STORAGE_CLASS
#  define _Thread_local TLS_STORAGE_CLASS
#endif

/*
 *	Now we define three macros for initialisation, updating, and retrieving
 *	These should ONLY be called where __Thread_local is a pointer to heap
 *	allocated memory that needs to be freed on thread exit.
 *
 *	Depending on the platform, the thread local storage itself may be freed
 *	before the destructor is called.
 *
 *	The only way this code can work is if the value passed to the destructor
 *	initialisation is the address of non-TLS memory.
 */
/** Pre-initialise resources required for a thread local destructor
 *
 * @note If destructors are not required, just use __Thread_local.
 *
 * @param _t	Type of variable e.g. 'char *'.  Must be a pointer type.
 * @param _n	Name of variable e.g. 'my_tls'.
 */
#  define fr_thread_local_setup(_t, _n) static _Thread_local _t _n;\
static pthread_key_t __fr_thread_local_key_##_n;\
static pthread_once_t __fr_thread_local_once_##_n = PTHREAD_ONCE_INIT;\
static pthread_destructor_t __fr_thread_local_destructor_##_n = NULL;\
static void __fr_thread_local_destroy_##_n(void *value)\
{\
	__fr_thread_local_destructor_##_n(value);\
}\
static void __fr_thread_local_key_init_##_n(void)\
{\
	(void) pthread_key_create(&__fr_thread_local_key_##_n, __fr_thread_local_destroy_##_n);\
}\
static int __fr_thread_local_set_destructor_##_n(pthread_destructor_t func, void *value)\
{\
	__fr_thread_local_destructor_##_n = func;\
	if (!value) { \
		errno = EINVAL; \
		return -1; \
	} \
	(void) pthread_once(&__fr_thread_local_once_##_n, __fr_thread_local_key_init_##_n);\
	(void) pthread_setspecific(__fr_thread_local_key_##_n, value);\
	_n = value;\
	return 0;\
}\
/* to permit semicolon after macro call, which keeps doxygen happy: */\
UNUSED static void *__fr_thread_local_macro_terminator_##_n

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
#  define fr_thread_local_set_destructor(_n, _f, _v) __fr_thread_local_set_destructor_##_n(_f, _v)

#ifdef __cplusplus
}
#endif
