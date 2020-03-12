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

/** Support functions to allow libraries to provide errors to their callers
 *
 * @file src/lib/util/strerror.c
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/thread_local.h>

#include <stdbool.h>

#define FR_STRERROR_BUFSIZE (2048)

typedef struct fr_log_entry_s fr_log_entry_t;
struct fr_log_entry_s {
	char		*msg;		//!< Log message.
	fr_log_entry_t	*next;		//!< Next log message.
};

/** Holds data used by the logging stack
 *
 * pool_a and pool_b allow #fr_strerror and #fr_strerror_pop during
 * a call to #fr_strerror_printf or #fr_strerror_printf_push.
 */
typedef struct {
	TALLOC_CTX	*pool_a;	//!< Pool to avoid memory allocations.
	TALLOC_CTX	*pool_b;	//!< Pool to avoid memory allocations.
	TALLOC_CTX	*pool;		//!< Current pool in use.

	fr_cursor_t	cursor;		//!< Cursor to simplify pushing/popping messages.
	fr_log_entry_t	*head;		//!< Head of the current thread local stack of messages.
} fr_log_buffer_t;

static _Thread_local fr_log_buffer_t *fr_strerror_buffer;
static _Thread_local bool logging_stop;	//!< Due to ordering issues we may get errors being
					///< logged from within other thread local destructors
					///< which cause a crash on exit if the logging buffer
					///< has already been freed.

/*
 *	Explicitly cleanup the memory allocated to the error buffer,
 *	just in case valgrind complains about it.
 */
static void _fr_logging_free(void *arg)
{
	/*
	 *	Free arg instead of thread local storage
	 *	as address sanitizer does a better job
	 *	of tracking and doesn't report a leak.
	 */
	talloc_free(arg);
	fr_strerror_buffer = NULL;

	logging_stop = true;
}

/** Reset cursor state
 *
 * @param[in] buffer	to clear cursor of.
 */
static inline void fr_strerror_clear(fr_log_buffer_t *buffer)
{
	buffer->head = NULL;
	fr_cursor_talloc_init(&buffer->cursor, &buffer->head, fr_log_entry_t);
}

/** Initialise thread local storage
 *
 * @return fr_buffer_t containing log messages.
 */
static inline fr_log_buffer_t *fr_strerror_init(void)
{
	fr_log_buffer_t *buffer;

	if (logging_stop) return NULL;	/* No more logging */

	buffer = fr_strerror_buffer;
	if (!buffer) {
		buffer = talloc(NULL, fr_log_buffer_t);	/* One byte extra for status */
		if (!buffer) {
		oom:
			fr_perror("Failed allocating memory for libradius error buffer");
			return NULL;
		}
		buffer->pool_a = talloc_pool(buffer, FR_STRERROR_BUFSIZE);
		if (!buffer->pool_a) goto oom;

		buffer->pool_b = talloc_pool(buffer, FR_STRERROR_BUFSIZE);
		if (!buffer->pool_b) goto oom;

		buffer->pool = buffer->pool_a;

		fr_thread_local_set_destructor(fr_strerror_buffer, _fr_logging_free, buffer);

		fr_strerror_clear(buffer);
	}

	return buffer;
}

/** Log to thread local error buffer
 *
 * @param[in] fmt	printf style format string. If NULL clears any existing messages.
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list		ap;
	fr_log_entry_t	*entry;
	fr_log_buffer_t	*buffer;

	buffer = fr_strerror_init();
	if (!buffer) return;

	/*
	 *	Clear any existing log messages
	 */
	if (!fmt) {
		talloc_free_children(buffer->pool);
		fr_strerror_clear(buffer);

		return;
	}

	/*
	 *	If last pool was pool_a, allocate from pool_b
	 */
	if (buffer->pool == buffer->pool_a) {
		entry = talloc_zero(buffer->pool_b, fr_log_entry_t);
		if (!entry) {
		oom:
			fr_perror("Failed allocating memory for libradius error buffer");
			return;
		}

		va_start(ap, fmt);
		entry->msg = fr_vasprintf(entry, fmt, ap);
		va_end(ap);
		if (!entry->msg) goto oom;

		talloc_free_children(buffer->pool);
		buffer->pool = buffer->pool_b;
	/*
	 *	...and vice versa.  This prevents the pools
	 *	from leaking due to non-contiguous allocations.
	 */
	} else {
		entry = talloc_zero(buffer->pool_a, fr_log_entry_t);
		if (!entry) goto oom;

		va_start(ap, fmt);
		entry->msg = fr_vasprintf(entry, fmt, ap);
		va_end(ap);
		if (!entry->msg) goto oom;

		talloc_free_children(buffer->pool);
		buffer->pool = buffer->pool_a;
	}

	fr_strerror_clear(buffer);
	fr_cursor_prepend(&buffer->cursor, entry);	/* It's a LIFO (not that it matters here) */
}

/** Add a message to an existing stack of messages
 *
 * @param[in] fmt	printf style format string.
 */
void fr_strerror_printf_push(char const *fmt, ...)
{
	va_list		ap;
	fr_log_entry_t	*entry;
	fr_log_buffer_t	*buffer;

	if (!fmt) return;

	buffer = fr_strerror_init();
	if (!buffer) return;

	/*
	 *	Address pathological case where we could leak memory
	 *	if only a combination of fr_strerror and
	 *	fr_strerror_printf_push are used.
	 */
	if (!buffer->head) talloc_free_children(buffer->pool);

	entry = talloc_zero(buffer->pool_b, fr_log_entry_t);
	if (!entry) {
	oom:
		fr_perror("Failed allocating memory for libradius error buffer");
		return;
	}

	va_start(ap, fmt);
	entry->msg = fr_vasprintf(entry, fmt, ap);
	va_end(ap);
	if (!entry->msg) goto oom;

	fr_cursor_prepend(&buffer->cursor, entry);	/* It's a LIFO */
	fr_cursor_head(&buffer->cursor);		/* Reset current to first */
}

/** Get the last library error
 *
 * Will only return the last library error once, after which it will return a zero length string.
 * If there are additional messages on the log stack they will be discarded.
 *
 * @return library error or zero length string.
 */
char const *fr_strerror(void)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	fr_cursor_head(&buffer->cursor);
	entry = fr_cursor_remove(&buffer->cursor);
	if (!entry) return "";

	/*
	 *	Memory gets freed on next call to
	 *	fr_strerror_printf or fr_strerror_printf_push.
	 */
	fr_strerror_clear(buffer);

	return entry->msg;
}

/** Get the last library error
 *
 * @return library error or zero length string.
 */
char const *fr_strerror_peek(void)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	entry = fr_cursor_head(&buffer->cursor);
	if (!entry) return "";

	return entry->msg;
}

/** Pop the last library error
 *
 * Return the first message added to the error stack using #fr_strerror_printf
 * or #fr_strerror_printf_push.
 *
 * @note Unlink fr_strerror() will return NULL if no messages are pending.
 *
 * @return
 *	- A library error.
 *	- NULL if no errors are pending.
 */
char const *fr_strerror_pop(void)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return NULL;

	fr_cursor_head(&buffer->cursor);
	entry = fr_cursor_remove(&buffer->cursor);
	if (!entry) return NULL;

	return entry->msg;
}

/** Print the current error to stderr with a prefix
 *
 * Used by utility functions lacking their own logging infrastructure
 */
void fr_perror(char const *fmt, ...)
{
	char const	*error;
	char		*prefix;
	va_list		ap;

	va_start(ap, fmt);
	prefix = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);

	error = fr_strerror_pop();
	if (error && (error[0] != '\0')) {
		fprintf(stderr, "%s: %s\n", prefix, error);
	} else {
		fprintf(stderr, "%s\n", prefix);
		talloc_free(prefix);
		return;
	}

	while ((error = fr_strerror_pop())) {
		if (error && (error[0] != '\0')) {
			fprintf(stderr, "%s: %s\n", prefix, error);
		}
	}
	talloc_free(prefix);
}

/** Explicitly free the memory used by fr_strerror
 *
 *  Note that this function is ONLY called in single-threaded mode,
 *  and then ONLY when the main thread does not call pthread_exit(NULL)
 */
void fr_strerror_free(void)
{
	TALLOC_FREE(fr_strerror_buffer);
	logging_stop = true;
}

#ifdef TESTING_STRERROR
/*
 *  cc strerror.c -g3 -Wall -DTESTING_STRERROR -L/usr/local/lib -L ../../../build/lib/local/.libs/ -lfreeradius-util -I/usr/local/include -I../../ -I../ -include ../include/build.h -l talloc -o test_strerror && ./test_strerror
 */
#include <stddef.h>
#include <freeradius-devel/util/acutest.h>

void test_strerror_uninit(void)
{
	char const *error;

	error = fr_strerror();

	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

void test_strerror_pop_uninit(void)
{
	char const *error;

	error = fr_strerror_pop();

	TEST_CHECK(error == NULL);
}

void test_strerror_printf(void)
{
	char const *error;

	fr_strerror_printf("Testing %i", 123);

	error = fr_strerror();

	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 123") == 0);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

void test_strerror_printf_push_pop(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);

	error = fr_strerror_pop();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 1") == 0);

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

void test_strerror_printf_push_strerror(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 1") == 0);

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);
}

void test_strerror_printf_push_pop_multi(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf_push("Testing %i", 2);

	error = fr_strerror_pop();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 2") == 0);

	error = fr_strerror_pop();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 1") == 0);

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

void test_strerror_printf_push_strerror_multi(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf_push("Testing %i", 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 2") == 0);

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);
}

void test_strerror_printf_strerror_append(void)
{
	char const *error;

	fr_strerror_printf("Testing %i", 1);
	fr_strerror_printf("%s Testing %i", fr_strerror(), 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 1 Testing 2") == 0);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

void test_strerror_printf_push_append(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf("%s Testing %i", fr_strerror(), 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 1 Testing 2") == 0);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

void test_strerror_printf_push_append2(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf("%s Testing %i", fr_strerror_pop(), 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(strcmp(error, "Testing 1 Testing 2") == 0);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error[0] == '\0');
}

TEST_LIST = {
	{ "test_strerror_uninit",			test_strerror_uninit },
	{ "test_strerror_pop_uninit",			test_strerror_pop_uninit },

	{ "test_strerror_printf",			test_strerror_printf },
	{ "test_strerror_printf_push_pop", 		test_strerror_printf_push_pop },

	{ "test_strerror_printf_push_strerror",		test_strerror_printf_push_strerror },
	{ "test_strerror_printf_push_pop_multi",	test_strerror_printf_push_pop_multi },
	{ "test_strerror_printf_push_strerror_multi",	test_strerror_printf_push_strerror_multi },
	{ "test_strerror_printf_strerror_append",	test_strerror_printf_strerror_append },
	{ "test_strerror_printf_push_append",		test_strerror_printf_push_append },
	{ "test_strerror_printf_push_append2",		test_strerror_printf_push_append2 },

	{ 0 }
};
#endif
