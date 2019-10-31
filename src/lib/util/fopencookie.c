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

/** Wrap funopen to provide an fopencookie compatible interface on systems that don't support it
 *
 * @file src/lib/util/fopencookie.c
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#ifndef HAVE_FOPENCOOKIE
#include <stdio.h>
#include <talloc.h>
#include <errno.h>
#include "fopencookie.h"

#define NEED_READ 0x01
#define NEED_WRITE 0x02
#define NEED_SEEK 0x04

/** Holds the fopencookie function pointers plus the funopen cookie
 *
 */
typedef struct {
	void			*cookie;	//!< Original cookie passed to fopencookie
	cookie_io_functions_t	io_funcs;	//!< Fopencookie callbacks (which we wrap)
} fr_funopen_cookie_t;


/** Wrap fopencookie read function
 *
 */
static int _read(void *c, char *buf, int n)
{
	fr_funopen_cookie_t *oc = talloc_get_type_abort(c, fr_funopen_cookie_t);

	return (int)oc->io_funcs.read(oc->cookie, buf, (size_t)n);
}

/** Wrap fopencookie write function
 *
 */
static int _write(void *c, const char *buf, int n)
{
	fr_funopen_cookie_t *oc = talloc_get_type_abort(c, fr_funopen_cookie_t);

	return (int)oc->io_funcs.write(oc->cookie, buf, (size_t)n);
}

/** Wrap fopencookie seek function
 *
 */
static fpos_t _seek(void *c, fpos_t offset, int whence)
{
	fr_funopen_cookie_t *oc = talloc_get_type_abort(c, fr_funopen_cookie_t);
	int ret;

	/*
	 *	fopencookie seek cb should return
	 *	and update offset to be the new position,
	 *	or not zero and leave offset untouched.
	 *
	 *	funopen seek cb should return -1 for an error
	 *	or the new offset on success.
	 */
	ret = oc->io_funcs.seek(oc->cookie, (off64_t *)&offset, whence);
	if (ret != 0) return -1;

	return offset;
}

/** Wrap fopencookie close function and free our fr_funopen_cookie_t
 *
 */
static int _close(void *c)
{
	fr_funopen_cookie_t	*oc = talloc_get_type_abort(c, fr_funopen_cookie_t);
	int			ret = oc->io_funcs.close ? oc->io_funcs.close(oc->cookie) : 0;

	talloc_free(oc);

	return ret;
}

FILE *fopencookie(void *cookie, const char *mode, cookie_io_functions_t io_funcs)
{
	fr_funopen_cookie_t	*oc;
	int			need = 0;
	FILE			*f;
	char const		*p;

	/*
	 *	Process mode string as described by `man fopen`
	 */
	for (p = mode; *p != '\0'; p++) {
		switch (*p) {
		case 'r':
			need |= NEED_READ;

			if (p[1] == 'b') p++;	/* Skip binary */
			if (p[1] == '+') {
				p++;
				need |= NEED_WRITE;
				continue;
			}
			continue;

		case 'w':
			need |= NEED_WRITE;

			if (p[1] == 'b') p++;	/* Skip binary */
			if (p[1] == '+') {
				p++;
				need |= NEED_READ;
				continue;
			}
			continue;

		case 'a':
			need |= (NEED_SEEK | NEED_WRITE);

			if (p[1] == 'b') p++;	/* Skip binary */
			if (p[1] == '+') {
				p++;
				need |= NEED_READ;
				continue;
			}
			continue;

		/*
		 *	'b' is also allowed as the last char
		 */
		case 'b':
			if (p[1] != '\0') {
			invalid_arg:
				errno = EINVAL;
				return NULL;
			}
			continue;	/* Loop will exit next iteration */

		default:
			goto invalid_arg;
		}
	}

	if ((need & NEED_READ) && !io_funcs.read) goto invalid_arg;
	if ((need & NEED_WRITE) && !io_funcs.write) goto invalid_arg;
	if ((need & NEED_SEEK) && !io_funcs.seek) goto invalid_arg;

	oc = talloc_zero(NULL, fr_funopen_cookie_t);
	if (!oc) {
		errno = ENOMEM;
		return NULL;
	}

	oc->io_funcs = io_funcs;
	oc->cookie = cookie;

  	f = funopen(oc,
  		    oc->io_funcs.read ? _read : NULL,
  		    oc->io_funcs.write ? _write : NULL,
  		    oc->io_funcs.seek ? _seek : NULL,
  		    _close);
	if (!f) {
		talloc_free(oc);
		return NULL;
	}

	if (need & NEED_SEEK) {
		if (fseek(f, 0L, SEEK_END) < 0) {
			fclose(f);
			talloc_free(oc);
			return NULL;
		}
	}

	return f;
}
#endif
