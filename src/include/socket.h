#pragma once

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/** Functions for establishing and managing low level sockets
 *
 * @file src/include/socket.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2015 The FreeRADIUS project
 */
RCSIDH(socket_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
/*
 *  The linux headers define the macro as:
 *
 * # define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)        \
 *                      + strlen ((ptr)->sun_path))
 *
 * Which trips UBSAN, because it sees an operation on a NULL pointer.
 */
#  undef SUN_LEN
#  define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#ifdef __cplusplus
}
#endif
