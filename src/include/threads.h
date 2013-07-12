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

/*
 * $Id$
 *
 * @file threads.h
 * @brief Macros to abstract Thread Local Storage
 *
 * @copyright 2013  The FreeRADIUS server project
 */

/*
 *	First figure whether we have compiler support this is usually the case except on OSX,
 *	where we need to use pthreads.	
 */
#ifdef HAVE_THREAD_TLS
/*
 *	GCC on most Linux systems
 */
#  define __THREAD __thread

#elif defined(HAVE_DECLSPEC_THREAD)
/*
 *	Visual C++, Borland (microsoft)
 */
#  define __THREAD __declspec(thread)
#endif

/*
 *	Now we define three macros for initialisation, updating, and retrieving
 */
#ifndef WITH_THREADS
#  define fr_thread_local_init(_x, _n)	static _x _n
#  define fr_thread_local_set(_n, _v) ((int)!((_n = _v) || 1))
#  define fr_thread_local_get(_n) _n
#elif defined(__THREAD)
#  define fr_thread_local_init(_x, _n)	static __THREAD _x _n
#  define fr_thread_local_set(_n, _v) ((int)!((_n = _v) || 1))
#  define fr_thread_local_get(_n) _n
#elif defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#  define fr_thread_local_init(_t, _n) \
static pthread_key_t __fr_thread_local_key_##_n;\
static pthread_once_t __fr_thread_local_once_##_n = PTHREAD_ONCE_INIT;\
static void __fr_thread_local_key_init_##_n(void)\
{\
	(void) pthread_key_create(&__fr_thread_local_key_##_n, NULL);\
}\
static _t __fr_thread_local_get_##_n(void)\
{\
	(void) pthread_once(&__fr_thread_local_once_##_n, __fr_thread_local_key_init_##_n);\
	return pthread_getspecific(__fr_thread_local_key_##_n);\
}\
static int __fr_thread_local_set_##_n(_t val)\
{\
	(void) pthread_once(&__fr_thread_local_once_##_n, __fr_thread_local_key_init_##_n);\
	return pthread_setspecific(__fr_thread_local_key_##_n, val);\
}
#  define fr_thread_local_set(_n, _v)	__fr_thread_local_set_##_n(_v)
#  define fr_thread_local_get(_n)	__fr_thread_local_get_##_n()
#else
# error WITH_THREADS defined, but no Thread Local Storage (TLS) available
#endif
