#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Provide missing types for fopencookie on systems that don't support it
 *
 * You should always include this file when using fopencookie
 *
 * @file src/lib/util/fopencookie.h
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(fopencookie_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#ifndef HAVE_FOPENCOOKIE
#define HAVE_FOPENCOOKIE 1

#if defined(__APPLE__)
/** Mac OS has always had a 64-bit off_t, so it doesn't have off64_t. */
typedef off_t off64_t;
#endif

typedef ssize_t (*cookie_read_function_t)(void *cookie, char *buf, size_t size);

typedef ssize_t (*cookie_write_function_t)(void *cookie, const char *buf, size_t size);

typedef int (*cookie_seek_function_t)(void *cookie, off64_t *offset, int whence);

typedef int (*cookie_close_function_t)(void *cookie);

typedef struct {
	cookie_read_function_t  read;
	cookie_write_function_t write;
	cookie_seek_function_t  seek;
	cookie_close_function_t close;
} cookie_io_functions_t;

FILE *fopencookie(void *cookie, const char *mode, cookie_io_functions_t io_funcs);

#endif

#ifdef __cplusplus
}
#endif
