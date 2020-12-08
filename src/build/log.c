/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file build/log.c
 * @brief Wrap make's logging facilities in C functions
 *
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <gnumake.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

/** Call a make logging keyword
 *
 */
void _make_vlog(char const *log_keyword, char const *file, int line, char const *fmt, va_list ap)
{
	va_list	ap_q;
	char	buffer[256];
	char	*p = buffer, *end = (p + (sizeof(buffer) - 1));

	strcpy(p, log_keyword);
	p += strlen(p);
	*p++ = ' ';

	va_copy(ap_q, ap);
	vsnprintf(p, end - p, fmt, ap_q);
	va_end(ap_q);

	*end = '\0';	/* Ensure we always \0 terminate */

	gmk_eval(buffer, &(gmk_floc){ .filenm = file, .lineno = line });
}

void _make_log(char const *log_keyword, char const *file, int line, char const *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	_make_vlog(log_keyword, file, line, fmt, ap);
	va_end(ap);
}
