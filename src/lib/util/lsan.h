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

/** Integration with the leak sanitizer interface
 *
 * @file src/lib/util/lsan.h
 *
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(lsan_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  include <sanitizer/lsan_interface.h>
#endif

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  define LSAN_DISABLE(_x) __lsan_disable(); _x; __lsan_enable()
#else
#  define LSAN_DISABLE(_x) _x
#endif

#ifdef __cplusplus
}
#endif
