#ifndef FR_THREADS_H
#define FR_THREADS_H
/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file threads.h
 * @brief Macros to abstract Thread Local Storage
 *
 * @copyright 2013  The FreeRADIUS server project
 */
typedef void (*pthread_destructor_t)(void*);

#if !defined(HAVE_PTHREAD_H) && defined(WITH_THREADS)
#  error WITH_THREADS defined, but pthreads not available
#endif

/*
 *	First figure whether we have compiler support this is usually the case except on OSX,
 *	where we need to use pthreads.
 */
#ifdef TLS_STORAGE_CLASS
#  define __THREAD TLS_STORAGE_CLASS
#endif

/*
 *	Now we define three macros for initialisation, updating, and retrieving
 */
#ifndef WITH_THREADS
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
#elif defined(__THREAD)
#  include <pthread.h>
#  define fr_thread_local_setup(_t, _n) static __THREAD _t _n;\
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
#  define fr_thread_local_init(_n, _f)	__fr_thread_local_init_##_n(_f)
#  define fr_thread_local_set(_n, _v) ((int)!((_n = _v) || 1))
#  define fr_thread_local_get(_n) _n
#elif defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#  define fr_thread_local_setup(_t, _n) \
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
	(void) pthread_setspecific(__fr_thread_local_key_##_n, &(_n));\
}\
static _t __fr_thread_local_init_##_n(pthread_destructor_t func)\
{\
	__fr_thread_local_destructor_##_n = func;\
	if (_n) return _n; \
	(void) pthread_once(&__fr_thread_local_once_##_n, __fr_thread_local_key_init_##_n);\
	return _n;\
}
#  define fr_thread_local_init(_n, _f)			__fr_thread_local_init_##_n(_f)
#  define fr_thread_local_set(_n, _v)			__fr_thread_local_set_##_n(_v)
#  define fr_thread_local_get(_n)			__fr_thread_local_get_##_n()
#endif
#endif
