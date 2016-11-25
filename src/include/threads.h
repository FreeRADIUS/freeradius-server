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
#ifndef _FR_THREADS_H
#define _FR_THREADS_H
/**
 * $Id$
 *
 * @file include/threads.h
 * @brief Macros to abstract Thread Local Storage
 *
 * @copyright 2013-2016 The FreeRADIUS server project
 */
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
 *	For other types like ints _Thread_local should be used directly
 *	without the macros.
 */
#ifndef HAVE_PTHREAD_H
#  define fr_thread_local_setup(_t, _n)	static _t _n;\
static inline int __fr_thread_local_destructor_##_n(pthread_destructor_t *ctx)\
{\
	pthread_destructor_t func = *ctx;\
	func(_n);\
	return 0;\
}\
static inline _t __fr_thread_local_init_##_n(pthread_destructor_t func)\
{\
	static pthread_destructor_t *ctx;\
	if (!ctx) {\
		ctx = talloc(talloc_autofree_context(), pthread_destructor_t);\
		talloc_set_destructor(ctx, __fr_thread_local_destructor_##_n);\
		*ctx = func;\
	}\
	return _n;\
}

#  define fr_thread_local_init(_n, _f) __fr_thread_local_init_##_n(_f)
#  define fr_thread_local_set(_n, _v) ((int)!((_n = _v) || 1))
#  define fr_thread_local_get(_n) _n
#else
#  include <pthread.h>
/** Create a thread local variable with initializers/destructors
 *
 * @param _t	Type of variable e.g. 'char *'.  Must be a pointer type.
 * @param _n	Name of variable e.g. 'my_tls'.
 */
#  define fr_thread_local_setup(_t, _n) static _Thread_local _t _n;\
static pthread_key_t __fr_thread_local_key_##_n;\
static pthread_once_t __fr_thread_local_once_##_n = PTHREAD_ONCE_INIT;\
static pthread_destructor_t __fr_thread_local_destructor_##_n = NULL;\
static void __fr_thread_local_destroy_##_n(UNUSED void *unused)\
{\
	__fr_thread_local_destructor_##_n(_n);\
}\
static void __fr_thread_local_key_init_##_n(void)\
{\
	(void) pthread_key_create(&__fr_thread_local_key_##_n, __fr_thread_local_destroy_##_n);\
}\
static _t __fr_thread_local_init_##_n(pthread_destructor_t func)\
{\
	__fr_thread_local_destructor_##_n = func;\
	if (_n) return _n; \
	(void) pthread_once(&__fr_thread_local_once_##_n, __fr_thread_local_key_init_##_n);\
	(void) pthread_setspecific(__fr_thread_local_key_##_n, &(_n));\
	return _n;\
}
/** If variable is NULL, call initialization function, else return the variable value
 *
 * @param _n	Name of variable e.g. 'my_tls'.
 * @param _f	Destructor, called when the thread exits to clean up any data.
 */
#  define fr_thread_local_init(_n, _f)	__fr_thread_local_init_##_n(_f)

/** Set a new variable value
 *
 * @param _n	Name of variable e.g. 'my_tls'.
 * @param _f	Function to call for initialization.
 */
#  define fr_thread_local_set(_n, _v) ((int)!((_n = _v) || 1))

/** Get an existing variable value
 *
 * @note In practice this is rarely used, and a call to fr_thread_local_init
 *	 is used to retrieve the value of the variable.
 *
 * @param _n	Name of variable e.g. 'my_tls'.
 */
#  define fr_thread_local_get(_n) _n
#endif
#endif /* _FR_THREADS_H */
