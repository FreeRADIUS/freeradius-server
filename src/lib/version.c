/*
 * version.c	Validate application and library magic numbers.
 *
 * Version:	$Id$
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
 * Copyright 1999-2014  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

static uint64_t libmagic = RADIUSD_MAGIC_NUMBER;

/** Check if the application linking to the library has the correct magic number
 *
 * @param magic number as defined by RADIUSD_MAGIC_NUMBER
 * @returns 0 on success, -1 on prefix mismatch, -2 on version mismatch -3 on commit mismatch.
 */
int fr_check_lib_magic(uint64_t magic)
{
	if (MAGIC_PREFIX(magic) != MAGIC_PREFIX(libmagic)) {
		fr_strerror_printf("Application and libfreeradius-radius magic number (prefix) mismatch."
				   "  application: %x  library: %x",
				   MAGIC_PREFIX(magic), MAGIC_PREFIX(libmagic));
		return -1;
	}

	if (MAGIC_VERSION(magic) != MAGIC_VERSION(libmagic)) {
		fr_strerror_printf("Application and libfreeradius-radius magic number (version) mismatch."
				   "  application: %lx library: %lx",
				   (unsigned long) MAGIC_VERSION(magic), (unsigned long) MAGIC_VERSION(libmagic));
		return -2;
	}

	if (MAGIC_COMMIT(magic) != MAGIC_COMMIT(libmagic)) {
		fr_strerror_printf("Application and libfreeradius-radius magic number (commit) mismatch."
				   "  application: %lx library: %lx",
				   (unsigned long) MAGIC_COMMIT(magic), (unsigned long) MAGIC_COMMIT(libmagic));
		return -3;
	}

	return 0;
}
