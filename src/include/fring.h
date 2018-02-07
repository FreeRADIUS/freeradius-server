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
#ifndef _FR_CBUFF_H
#define _FR_CBUFF_H
/*
 * $Id$
 *
 * @file include/fring_buffer.h
 * @brief Simple ring buffer with fixed element sizes.
 *
 * @copyright 2015-2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>

typedef struct fr_fring_buffer fr_fring_t;

fr_fring_t		*fr_fring_alloc(TALLOC_CTX *ctx, uint32_t size, bool lock);
int			fr_fring_overwrite(fr_fring_t *fring, void *obj);
int			fr_fring_insert(fr_fring_t *fring, void *obj);
void			*fr_fring_next(fr_fring_t *fring);
#endif /* _FR_CBUFF_H */
