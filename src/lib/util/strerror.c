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
 * @copyright 2017-2020 The FreeRADIUS server project
 * @copyright 2017-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/thread_local.h>

#include <stdbool.h>

#define FR_STRERROR_BUFSIZE (2048)

typedef struct fr_log_entry_s fr_log_entry_t;
struct fr_log_entry_s {
	fr_dlist_t	list;
	char const	*msg;		//!< Log message.

	char const	*subject;	//!< Subject for error markers.
	size_t		offset;		//!< Where to place the msg marker relative to the subject.
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

	fr_dlist_head_t	entries;
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

/** Initialise thread local storage
 *
 * @return fr_buffer_t containing log messages.
 */
static fr_log_buffer_t *fr_strerror_init(void)
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

		fr_dlist_talloc_init(&buffer->entries, fr_log_entry_t, list);
	}

	return buffer;
}

/*
 *	If last pool was pool_a, allocate from pool_b
 *	...and vice versa.  This prevents the pools
 *	from leaking due to non-contiguous allocations
 *	when we're using fr_strerror as an argument
 *	for another message.
 */
static inline CC_HINT(always_inline) TALLOC_CTX *pool_alt(fr_log_buffer_t *buffer)
{
	if (buffer->pool == buffer->pool_a) {
		buffer->pool = buffer->pool_b;
		return buffer->pool;
	}
	return buffer->pool = buffer->pool_a;
}

static inline CC_HINT(always_inline) void pool_alt_free_children(fr_log_buffer_t *buffer)
{
	if (buffer->pool == buffer->pool_a) {
		talloc_free_children(buffer->pool_b);
		return;
	}
	talloc_free_children(buffer->pool_a);
}

/** Create an entry in the thread local logging stack, clearing all other entries
 *
 * @note Can't be inlined.
 *
 * @hidecallergraph
 */
static fr_log_entry_t *strerror_vprintf(char const *fmt, va_list ap)
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
		fr_strerror_clear();
		return NULL;
	}

	entry = talloc(pool_alt(buffer), fr_log_entry_t);
	if (unlikely(!entry)) {
	oom:
		fr_perror("Failed allocating memory for libradius error buffer");
		return NULL;
	}

	va_copy(ap_p, ap);
	entry->msg = fr_vasprintf(entry, fmt, ap_p);
	va_end(ap_p);
	if (unlikely(!entry->msg)) goto oom;
	entry->subject = NULL;
	entry->offset = 0;

	pool_alt_free_children(buffer);
	fr_dlist_clear(&buffer->entries);
	fr_dlist_insert_tail(&buffer->entries, entry);

	return entry;
}

/** Add a message to an existing stack of messages
 *
 * @param[in] fmt	printf style format string.
 * @param[in] ap	Arguments for the error string.
 *
 * @note Can't be inline.
 *
 * @hidecallergraph
 */
static fr_log_entry_t *strerror_vprintf_push(fr_log_buffer_t *buffer, char const *fmt, va_list ap)
{
	va_list		ap_p;
	fr_log_entry_t	*entry;

	if (!fmt) return NULL;

	/*
	 *	Address pathological case where we could leak memory
	 *	if only a combination of fr_strerror and
	 *	fr_strerror_printf_push are used.
	 */
	if (!fr_dlist_num_elements(&buffer->entries)) talloc_free_children(buffer->pool);

	entry = talloc(pool_alt(buffer), fr_log_entry_t);
	if (unlikely(!entry)) {
	oom:
		fr_perror("Failed allocating memory for libradius error buffer");
		return NULL;
	}

	va_copy(ap_p, ap);
	entry->msg = fr_vasprintf(entry, fmt, ap_p);
	va_end(ap_p);
	if (unlikely(!entry->msg)) goto oom;
	entry->subject = NULL;
	entry->offset = 0;

	return entry;
}

/** Log to thread local error buffer
 *
 * @param[in] fmt	printf style format string.
 *			If NULL clears any existing messages.
 * @param[in] ...	Arguments for the format string.
 *
 * @hidecallergraph
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	strerror_vprintf(fmt, ap);
	va_end(ap);
}

/** Add a message to an existing stack of messages at the tail
 *
 * @param[in] fmt	printf style format string.
 *			If NULL clears any existing messages.
 * @param[in] ...	Arguments for the format string.
 *
 * @hidecallergraph
 */
void fr_strerror_printf_push(char const *fmt, ...)
{
	va_list			ap;
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_init();
	if (unlikely(!buffer)) return;

	va_start(ap, fmt);
	entry = strerror_vprintf_push(buffer, fmt, ap);
	va_end(ap);

	if (unlikely(!entry)) return;

	fr_dlist_insert_tail(&buffer->entries, entry);
}

/** Add a message to an existing stack of messages at the head
 *
 * @param[in] fmt	printf style format string.
 *			If NULL clears any existing messages.
 * @param[in] ...	Arguments for the format string.
 *
 * @hidecallergraph
 */
void fr_strerror_printf_push_head(char const *fmt, ...)
{
	va_list			ap;
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_init();
	if (unlikely(!buffer)) return;

	va_start(ap, fmt);
	entry = strerror_vprintf_push(buffer, fmt, ap);
	va_end(ap);

	if (unlikely(!entry)) return;

	fr_dlist_insert_head(&buffer->entries, entry);
}

/** Add an error marker to an existing stack of messages
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 *
 * @hidecallergraph
 */
void fr_strerror_marker_printf(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list		ap;
	fr_log_entry_t	*entry;

	va_start(ap, fmt);
	entry = strerror_vprintf(fmt, ap);
	va_end(ap);

	if (unlikely(!entry)) return;

	entry->subject = talloc_strdup(entry, subject);
	entry->offset = offset;
}

/** Add an error marker to an existing stack of messages at the tail
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 *
 * @hidecallergraph
 */
void fr_strerror_marker_printf_push(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list			ap;
	fr_log_entry_t		*entry;
	fr_log_buffer_t		*buffer;

	buffer = fr_strerror_init();
	if (unlikely(!buffer)) return;

	va_start(ap, fmt);
	entry = strerror_vprintf_push(buffer, fmt, ap);
	va_end(ap);

	if (unlikely(!entry)) return;

	entry->subject = talloc_strdup(entry, subject);
	entry->offset = offset;

	fr_dlist_insert_tail(&buffer->entries, entry);
}

/** Add an error marker to an existing stack of messages at the head
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 *
 * @hidecallergraph
 */
void fr_strerror_marker_printf_push_head(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list			ap;
	fr_log_entry_t		*entry;
	fr_log_buffer_t		*buffer;

	buffer = fr_strerror_init();
	if (unlikely(!buffer)) return;

	va_start(ap, fmt);
	entry = strerror_vprintf_push(buffer, fmt, ap);
	va_end(ap);

	if (unlikely(!entry)) return;

	entry->subject = talloc_strdup(entry, subject);
	entry->offset = offset;

	fr_dlist_insert_head(&buffer->entries, entry);
}

/** Create an entry in the thread local logging stack using a const string, clearing all other entries
 *
 * @hidecallergraph
 */
static inline CC_HINT(always_inline) CC_HINT(nonnull) fr_log_entry_t *strerror_const(char const *msg)
{
	fr_log_entry_t	*entry;
	fr_log_buffer_t	*buffer;

	buffer = fr_strerror_init();
	if (unlikely(!buffer)) return NULL;

	entry = talloc(pool_alt(buffer), fr_log_entry_t);
	if (unlikely(!entry)) {
		fr_perror("Failed allocating memory for libradius error buffer");
		return NULL;
	}
	/*
	 *	For some reason this is significantly
	 *	more efficient than a compound literal
	 *	even though in the majority of cases
	 *	compound literals and individual field
	 *	assignments result in the same byte
	 *	code.
	 */
	entry->msg = msg;
	entry->subject = NULL;
	entry->offset = 0;

	pool_alt_free_children(buffer);
	fr_dlist_clear(&buffer->entries);
	fr_dlist_insert_tail(&buffer->entries, entry);

	return entry;
}

/** Log to thread local error buffer
 *
 * @param[in] msg	To add to error stack. Must have a
 *			lifetime equal to that of the program.
 * @hidecallergraph
 */
void fr_strerror_const(char const *msg)
{
	(void)strerror_const(msg);
}

/** Add a message to an existing stack of messages
 *
 * @param[in] msg	To add to error stack. Must have a
 *			lifetime equal to that of the program.
 *
 * @hidecallergraph
 */
static CC_HINT(always_inline) CC_HINT(nonnull)
fr_log_entry_t *strerror_const_push(fr_log_buffer_t *buffer, char const *msg)
{
	fr_log_entry_t	*entry;

	/*
	 *	Address pathological case where we could leak memory
	 *	if only a combination of fr_strerror and
	 *	fr_strerror_printf_push are used.
	 */
	if (!fr_dlist_num_elements(&buffer->entries)) talloc_free_children(buffer->pool);

	entry = talloc(pool_alt(buffer), fr_log_entry_t);
	if (unlikely(!entry)) {
		fr_perror("Failed allocating memory for libradius error buffer");
		return NULL;
	}
	/*
	 *	For some reason this is significantly
	 *	more efficient than a compound literal
	 *	even though in the majority of cases
	 *	compound literals and individual field
	 *	assignments result in the same byte
	 *	code.
	 */
	entry->msg = msg;
	entry->subject = NULL;
	entry->offset = 0;

	return entry;
}

/** Add a message to an existing stack of messages at the tail
 *
 * @param[in] msg	To add to error stack. Must have a
 *			lifetime equal to that of the program.
 *
 * @hidecallergraph
 */
void fr_strerror_const_push(char const *msg)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_init();
	if (!buffer) return;

	entry = strerror_const_push(buffer, msg);
	if (unlikely(!entry)) return;

	fr_dlist_insert_tail(&buffer->entries, entry);
}

/** Add a message to an existing stack of messages at the head
 *
 * @param[in] msg	To add to error stack. Must have a
 *			lifetime equal to that of the program.
 *
 * @hidecallergraph
 */
void fr_strerror_const_push_head(char const *msg)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_init();
	if (!buffer) return;

	entry = strerror_const_push(buffer, msg);
	if (unlikely(!entry)) return;

	fr_dlist_insert_head(&buffer->entries, entry);
}

/** Get the last library error
 *
 * Will only return the last library error once, after which it will return a zero length string.
 * If there are additional messages on the log stack they will be discarded.
 *
 * @return library error or zero length string.
 *
 * @hidecallergraph
 */
char const *fr_strerror(void)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	entry = fr_dlist_tail(&buffer->entries);
	if (!entry) return "";

	/*
	 *	Memory gets freed on next call to
	 *	fr_strerror_printf or fr_strerror_printf_push.
	 */
	fr_dlist_clear(&buffer->entries);

	return entry->msg;
}

/** Clears all pending messages from the talloc pools
 *
 */
void fr_strerror_clear(void)
{
	fr_log_buffer_t		*buffer;

	if (unlikely(!fr_strerror_buffer)) return;

	buffer = fr_strerror_init();
	fr_dlist_clear(&buffer->entries);
	talloc_free_children(buffer->pool_a);
	talloc_free_children(buffer->pool_b);
}

/** Get the last library error marker
 *
 * @param[out] subject	The subject string the error relates to.
 * @param[out] offset	Where to place the marker.
 * @return
 *	- NULL if there are no pending errors.
 *	- The error message if there was an error.
 *
 * @hidecallergraph
 */
char const *fr_strerror_marker(char const **subject, size_t *offset)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	entry = fr_dlist_head(&buffer->entries);
	if (!entry) return "";

	/*
	 *	Memory gets freed on next call to
	 *	fr_strerror_printf or fr_strerror_printf_push.
	 */
	fr_dlist_clear(&buffer->entries);

	*subject = entry->subject;
	*offset = entry->offset;

	return entry->msg;
}

/** Get the last library error
 *
 * @return library error or zero length string.
 *
 * @hidecallergraph
 */
char const *fr_strerror_peek(void)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	entry = fr_dlist_tail(&buffer->entries);
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
 *
 * @hidecallergraph
 */
char const *fr_strerror_marker_peek(char const **subject, size_t *offset)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return "";

	entry = fr_dlist_head(&buffer->entries);
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
 *
 * @hidecallergraph
 */
char const *fr_strerror_pop(void)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return NULL;

	entry = fr_dlist_head(&buffer->entries);
	if (!entry) return NULL;

	fr_dlist_remove(&buffer->entries, entry);

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
 *
 * @hidecallergraph
 */
char const *fr_strerror_marker_pop(char const **subject, size_t *offset)
{
	fr_log_buffer_t		*buffer;
	fr_log_entry_t		*entry;

	buffer = fr_strerror_buffer;
	if (!buffer) return NULL;

	entry = fr_dlist_head(&buffer->entries);
	if (!entry) return NULL;

	fr_dlist_remove(&buffer->entries, entry);

	*subject = entry->subject;
	*offset = entry->offset;

	return entry->msg;
}

/** Print the current error to stderr with a prefix
 *
 * Used by utility functions lacking their own logging infrastructure
 *
 * @hidecallergraph
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
