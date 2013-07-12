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
#define FR_STRERROR_BUFSIZE (1024)

fr_thread_local_init(char *, fr_strerror_buffer);	/* macro */

/*
 *	Log to a buffer, trying to be thread-safe.
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list ap;

	char *buffer;

	buffer = fr_thread_local_get(fr_strerror_buffer);	/* Will be NULL only on initialisation */
	if (!buffer) {
		int ret;

		buffer = malloc(sizeof(char) * FR_STRERROR_BUFSIZE);
		if (!buffer) {
			return;
		}

		ret = fr_thread_local_set(fr_strerror_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed recording thread error: %s", strerror(ret));
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
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	if (strchr(fmt, ':') == NULL)
		fprintf(stderr, ": ");
	fprintf(stderr, "%s\n", fr_strerror());
	va_end(ap);
}
