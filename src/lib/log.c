/*
 * log.c	Functions in the library call radlib_log() which
 *		sets a global error string "char *librad_errstr".
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

char librad_errstr[1024];

/*
 *  Do logging to a static buffer.  Note that we MIGHT be asked
 *  to write a previous log message to librad_errstr.
 *
 *  This also isn't multithreaded-safe, so it'll have to be changed
 *  in the future.
 */
void librad_log(const char *fmt, ...)
{
	va_list ap;
	char my_errstr[sizeof(librad_errstr)];

	va_start(ap, fmt);
	vsnprintf(my_errstr, sizeof(my_errstr), fmt, ap);
	strcpy(librad_errstr, my_errstr);
	va_end(ap);
}

void librad_perror(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	if (strchr(fmt, ':') == NULL)
		fprintf(stderr, ": ");
	fprintf(stderr, "%s\n", librad_errstr);
	va_end(ap);
}
