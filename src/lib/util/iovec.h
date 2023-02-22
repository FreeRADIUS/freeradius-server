#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/** Structures and functions for parsing, printing, masking and retrieving IP addresses
 *
 * @file src/lib/util/inet.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(iovec_h, "$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/time.h>
#include <unistd.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

fr_slen_t	fr_concatv(fr_dbuff_t *out, struct iovec vector[], int iovcnt);
ssize_t		fr_writev(int fd, struct iovec vector[], int iovcnt, fr_time_delta_t timeout);

#ifdef __cplusplus
}
#endif
