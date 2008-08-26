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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>


#define FR_STRERROR_BUFSIZE (1024)

static char fr_strerror_buffer[FR_STRERROR_BUFSIZE];


/*
 *  Do logging to a static buffer.  Note that we MIGHT be asked
 *  to write a previous log message to fr_strerror.
 *
 *  This also isn't multithreaded-safe, so it'll have to be changed
 *  in the future.
 */
void fr_strerror_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(fr_strerror_buffer, sizeof(fr_strerror_buffer), fmt, ap);
	va_end(ap);
}

const char *fr_strerror(void)
{
	return fr_strerror_buffer;
}

void fr_perror(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	if (strchr(fmt, ':') == NULL)
		fprintf(stderr, ": ");
	fprintf(stderr, "%s\n", fr_strerror());
	va_end(ap);
}
