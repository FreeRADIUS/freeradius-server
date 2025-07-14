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

/** Functions to help with cleanup
 *
 * Allows for printing backtraces of memory allocations or after crashes
 *
 * @file lib/util/backtrace.h
 *
 * @copyright 2025 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(backtrace_h, "$Id$")

#include <freeradius-devel/util/fring.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct fr_bt_marker fr_bt_marker_t;

void			fr_backtrace_init(char const *program);

void			fr_backtrace_print(fr_fring_t *fring, void *obj);

fr_bt_marker_t		*fr_backtrace_attach(fr_fring_t **fring, TALLOC_CTX *obj);

void			fr_backtrace(void);

#ifdef __cplusplus
}
#endif
