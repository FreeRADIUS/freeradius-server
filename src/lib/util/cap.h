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

/** Deal with Linux capabilities
 *
 * @file src/lib/util/cap.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 The FreeRADIUS Server Project.
 */
RCSIDH(cap_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CAPABILITY_H
#  include <sys/capability.h>

int	fr_cap_set(cap_value_t cap);

#endif

#ifdef __cplusplus
}
#endif
