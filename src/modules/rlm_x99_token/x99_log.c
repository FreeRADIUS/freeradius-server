/*
 * x99_log.c
 * $Id$
 *
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2002  Google, Inc.
 */

#ifdef FREERADIUS
#include "radiusd.h"
#endif
#include "x99.h"

#include <malloc.h>
#include <stdarg.h>
#include <string.h>
#ifndef FREERADIUS
#include <syslog.h>
#endif

static const char rcsid[] = "$Id$";

void
x99_log(int level, const char *format, ...)
{
    va_list ap;
    char *fmt;

    va_start(ap, format);
    fmt = malloc(strlen(X99_MODULE_NAME) + strlen(format) + 3);
    if (!fmt) {
	va_end(ap);
	return;
    }
    (void) sprintf(fmt, "%s: %s", X99_MODULE_NAME, format);

#ifdef FREERADIUS
    (void) vradlog(level, fmt, ap);
#else
    vsyslog(level, fmt, ap);
#endif

    va_end(ap);
    free(fmt);
}

