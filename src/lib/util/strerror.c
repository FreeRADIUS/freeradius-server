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

	char		*subject;	//!< Subject for error markers.
	size_t		offset;		//!< Where to place the msg marker relative to the subject.

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

static fr_log_entry_t *fr_strerror_vprintf(char const *fmt, va_list ap)
{
	va_list		ap_p;
	fr_log_entry_t	*entry;
	fr_log_buffer_t	*buffer;

	buffer = fr_strerror_init();
	if (!buffer) return NULL;

	/*
	 *	Clear any existing log messages
	 */
	if (!fmt) {
		talloc_free_children(buffer->pool);
		fr_strerror_clear(buffer);

		return NULL;
	}

	/*
	 *	If last pool was pool_a, allocate from pool_b
	 */
	if (buffer->pool == buffer->pool_a) {
		entry = talloc_zero(buffer->pool_b, fr_log_entry_t);
		if (!entry) {
		oom:
			fr_perror("Failed allocating memory for libradius error buffer");
			return NULL;
		}

		va_copy(ap_p, ap);
		entry->msg = fr_vasprintf(entry, fmt, ap_p);
		va_end(ap_p);
		if (!entry->msg) goto oom;

		talloc_free_children(buffer->pool);
		buffer->pool = buffer->pool_b;
	/*
	 *	...and vice versa.  This prevents the pools
	 *	from leaking due to non-contiguous allocations
	 *	when we're using fr_strerror as an argument
	 *	for another message.
	 */
	} else {
		entry = talloc_zero(buffer->pool_a, fr_log_entry_t);
		if (!entry) goto oom;

		va_copy(ap_p, ap);
		entry->msg = fr_vasprintf(entry, fmt, ap_p);
		va_end(ap_p);
		if (!entry->msg) goto oom;

		talloc_free_children(buffer->pool);
		buffer->pool = buffer->pool_a;
	}

	fr_strerror_clear(buffer);
	fr_cursor_prepend(&buffer->cursor, entry);	/* It's a LIFO (not that it matters here) */

	return entry;
}

/** Log to thread local error buffer
 *
 * @param[in] fmt	printf style format string.
 *			If NULL clears any existing messages.
 * @param[in] ...	Arguments for the format string.
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_vprintf(fmt, ap);
	va_end(ap);
}

/** Add an error marker to an existing stack of messages
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 */
void fr_strerror_marker_printf(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list		ap;
	fr_log_entry_t	*entry;

	va_start(ap, fmt);
	entry = fr_strerror_vprintf(fmt, ap);
	va_end(ap);

	if (!entry) return;

	entry->subject = talloc_strdup(entry, subject);
	entry->offset = offset;
}

/** Add a message to an existing stack of messages
 *
 * @param[in] fmt	printf style format string.
 * @param[in] ap	Arguments for the error string.
 */
static fr_log_entry_t *fr_strerror_vprintf_push(char const *fmt, va_list ap)
{
	va_list		ap_p;
	fr_log_entry_t	*entry;
	fr_log_buffer_t	*buffer;

	if (!fmt) return NULL;

	buffer = fr_strerror_init();
	if (!buffer) return NULL;

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
		return NULL;
	}

	va_copy(ap_p, ap);
	entry->msg = fr_vasprintf(entry, fmt, ap_p);
	va_end(ap_p);
	if (!entry->msg) goto oom;

	fr_cursor_prepend(&buffer->cursor, entry);	/* It's a LIFO */
	fr_cursor_head(&buffer->cursor);		/* Reset current to first */

	return entry;
}

/** Add a message to an existing stack of messages
 *
 * @param[in] fmt	printf style format string.
 *			If NULL clears any existing messages.
 * @param[in] ...	Arguments for the format string.
 */
void fr_strerror_printf_push(char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_vprintf_push(fmt, ap);
	va_end(ap);
}

/** Add an error marker to an existing stack of messages
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 */
void fr_strerror_marker_printf_push(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list		ap;
	fr_log_entry_t	*entry;

	va_start(ap, fmt);
	entry = fr_strerror_vprintf_push(fmt, ap);
	va_end(ap);

	if (!entry) return;

	entry->subject = talloc_strdup(entry, subject);
	entry->offset = offset;
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

/** Get the last library error marker
 *
 * @param[out] subject	The subject string the error relates to.
 * @param[out] offset	Where to place the marker.
 * @return
 *	- NULL if there are no pending errors.
 *	- The error message if there was an error.
 */
char const *fr_strerror_marker(char const **subject, size_t *offset)
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

	*subject = entry->subject;
	*offset = entry->offset;

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

/** Get the last library error marker
 *
 * @param[out] subject	The subject string the error relates to.
 * @param[out] offset	Where to place the marker.
 * @return
 *	- NULL if there are no pending errors.
 *	- The error message if there was an error.
 */
char const *fr_strerror_marker_peek(char const **subject, size_t *offset)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	entry = fr_cursor_head(&buffer->cursor);
	if (!entry) return "";

	*subject = entry->subject;
	*offset = entry->offset;

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

/** Pop the last library error with marker information
 *
 * Return the first message added to the error stack using #fr_strerror_printf
 * or #fr_strerror_printf_push.
 *
 * @return
 *	- A library error.
 *	- NULL if no errors are pending.
 */
char const *fr_strerror_marker_pop(char const **subject, size_t *offset)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return NULL;

	fr_cursor_head(&buffer->cursor);
	entry = fr_cursor_remove(&buffer->cursor);
	if (!entry) return NULL;

	*subject = entry->subject;
	*offset = entry->offset;

	return entry->msg;
}

/** Print the current error to stderr with a prefix
 *
 * Used by utility functions lacking their own logging infrastructure
 */
void fr_perror(char const *fmt, ...)
{
	char const	*error;
	char const	*subject;
	size_t		offset;
	char		*prefix;
	va_list		ap;

	va_start(ap, fmt);
	prefix = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);

	error = fr_strerror_marker_pop(&subject, &offset);
	if (error) {
		fprintf(stderr, "%s: %s\n", prefix, error);
	} else {
		fprintf(stderr, "%s\n", prefix);
		talloc_free(prefix);
		return;
	}

	while ((error = fr_strerror_marker_pop(&subject, &offset))) {
		if (error && (error[0] != '\0')) {
			fprintf(stderr, "%s: %s\n", prefix, error);
		}
	}
	talloc_free(prefix);
}

#ifdef TESTING_STRERROR

#endif
