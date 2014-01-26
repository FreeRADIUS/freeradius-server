/*
 * log.c	Functions in the library call radlib_log() which
 *		does internal logging.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

/*
 *	Are we using glibc or a close relative?
 */
#ifdef HAVE_FEATURES_H
#  include <features.h>
#endif

#define FR_STRERROR_BUFSIZE (2048)

fr_thread_local_setup(char *, fr_strerror_buffer)	/* macro */
fr_thread_local_setup(char *, fr_syserror_buffer)	/* macro */


/*
 *	Explicitly cleanup the memory allocated to the error buffer,
 *	just in case valgrind complains about it.
 */
static void _fr_logging_free(void *arg)
{
	free(arg);
}

/** Log to thread local error buffer
 *
 * @param fmt printf style format string. If NULL sets the 'new' byte to false,
 *	  effectively clearing the last message.
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list ap;

	char *buffer;

	buffer = fr_thread_local_init(fr_strerror_buffer, _fr_logging_free);
	if (!buffer) {
		int ret;

		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = malloc(sizeof(char) * (FR_STRERROR_BUFSIZE + 1));	/* One byte extra for status */
		if (!buffer) {
			fr_perror("Failed allocating memory for libradius error buffer");
			return;
		}

		ret = fr_thread_local_set(fr_strerror_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed setting up TLS for libradius error buffer: %s", fr_syserror(ret));
			free(buffer);
			return;
		}
	}

	/*
	 *	NULL has a special meaning, setting the new byte to false.
	 */
	if (!fmt) {
		buffer[FR_STRERROR_BUFSIZE] = '\0';
		return;
	}

	va_start(ap, fmt);
	vsnprintf(buffer, FR_STRERROR_BUFSIZE, fmt, ap);
	buffer[FR_STRERROR_BUFSIZE] = '\1';			/* Flip the 'new' byte to true */
	va_end(ap);
}

/** Get the last library error
 *
 * Will only return the last library error once, after which it will return a zero length string.
 *
 * @return library error or zero length string
 */
char const *fr_strerror(void)
{
	char *buffer;

	buffer = fr_thread_local_get(fr_strerror_buffer);
	if (buffer && (buffer[FR_STRERROR_BUFSIZE] != '\0')) {
		buffer[FR_STRERROR_BUFSIZE] = '\0';		/* Flip the 'new' byte to false */
		return buffer;
	}

	return "";
}

/** Guaranteed to be thread-safe version of strerror
 *
 * @param num errno as returned by function or from global errno.
 * @return local specific error string relating to errno.
 */
char const *fr_syserror(int num)
{
	char *buffer;

	buffer = fr_thread_local_init(fr_syserror_buffer, _fr_logging_free);
	if (!buffer) {
		int ret;

		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = malloc(sizeof(char) * FR_STRERROR_BUFSIZE);
		if (!buffer) {
			fr_perror("Failed allocating memory for system error buffer");
			return NULL;
		}

		ret = fr_thread_local_set(fr_syserror_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed setting up TLS for system error buffer: %s", fr_syserror(ret));
			free(buffer);
			return NULL;
		}
	}

	/*
	 *	XSI-Compliant version
	 */
#if !defined(HAVE_FEATURES_H) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 500) && ! _GNU_SOURCE)
	if (!num || (strerror_r(num, buffer, FR_STRERROR_BUFSIZE) != 0)) {
		buffer[0] = '\0';
	}
	return buffer;
	/*
	 *	GNU Specific version
	 *
	 *	The GNU Specific version returns a char pointer. That pointer may point
	 *	the buffer you just passed in, or to an immutable static string.
	 */
#else
	{
		char const *p;
		p = strerror_r(num, buffer, FR_STRERROR_BUFSIZE);
		if (!num || !p) {
			buffer[0] = '\0';
			return buffer;
		}
		return p;
	}
#endif

}

void fr_perror(char const *fmt, ...)
{
	char const *error;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	if (strchr(fmt, ':') == NULL)
		fprintf(stderr, ": ");

	error = fr_strerror();
	if (error) {
		fprintf(stderr, "%s\n", error);
	}

	va_end(ap);
}

bool fr_assert_cond(char const *file, int line, char const *expr, bool cond)
{
	if (!cond) {
		fr_perror("SOFT ASSERT FAILED %s[%u]: %s", file, line, expr);
		return false;
	}

	return cond;
}

void NEVER_RETURNS _fr_exit(char const *file, int line, int status)
{
#ifndef NDEBUG
	fr_perror("EXIT CALLED %s[%u]: %i", file, line, status);
#endif
	fflush(stderr);

	fr_debug_break();	/* If running under GDB we'll break here */

	exit(status);
}

void NEVER_RETURNS _fr_exit_now(char const *file, int line, int status)
{
#ifndef NDEBUG
	fr_perror("_EXIT CALLED %s[%u]: %i", file, line, status);
#endif
	fflush(stderr);

	fr_debug_break();	/* If running under GDB we'll break here */

	_exit(status);
}
