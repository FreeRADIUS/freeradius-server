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

/** Boxed value structures and functions to manipulate them
 *
 * @file src/lib/util/size.h
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(size_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <freeradius-devel/util/sbuff.h>

fr_slen_t fr_size_from_str(size_t *out, fr_sbuff_t *in);

fr_slen_t fr_size_to_str(fr_sbuff_t *out, size_t in);

#ifdef __cplusplus
}
#endif
