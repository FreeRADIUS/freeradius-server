/*
 * otp_log.c
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002  Google, Inc.
 * Copyright 2005 TRI-D Systems, Inc.
 */

#include "otp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#ifdef PAM
#include <syslog.h>
#endif

static const char rcsid[] = "$Id$";

void
otp_log(int level, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);

#ifdef FREERADIUS
  (void) vradlog(level, format, ap);
#else
  vsyslog(level, format, ap);
#endif

  va_end(ap);
}
