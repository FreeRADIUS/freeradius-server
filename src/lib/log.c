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
#define FR_STRERROR_BUFSIZE (2048)

fr_thread_local_setup(char *, fr_strerror_buffer)	/* macro */

/*
 *	Explicitly cleanup the memory allocated to the error buffer,
 *	just in case valgrind complains about it.
 */
static void fr_logging_free(UNUSED void *arg)
{
	char *buffer;

	buffer = fr_thread_local_get(fr_strerror_buffer);
	if (!buffer) {
		return;
	}

	free(buffer);
}

/*
 *	Log to thread local error buffer
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list ap;

	char *buffer;

	buffer = fr_thread_local_init(fr_strerror_buffer, fr_logging_free);
	if (!buffer) {
		int ret;

		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = malloc(sizeof(char) * FR_STRERROR_BUFSIZE);
		if (!buffer) {
			fr_perror("Failed allocating memory for libradius error buffer");
			return;
		}

		ret = fr_thread_local_set(fr_strerror_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed setting up TLS for libradius error buffer: %s", strerror(ret));
			return;
		}
	}

	va_start(ap, fmt);
	vsnprintf(buffer, FR_STRERROR_BUFSIZE, fmt, ap);
	va_end(ap);
}

char const *fr_strerror(void)
{
	return fr_thread_local_get(fr_strerror_buffer);
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

inline bool fr_assert_cond(char const *file, int line, char const *expr, bool cond)
{
	if (!cond) {
		fr_perror("SOFT ASSERT FAILED %s[%u]: %s\n", file, line, expr);
		return false;
	}

	return cond;
}
