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

/**
 * $Id$
 *
 * @file lib/util/edit.h
 * @brief Structures and prototypes for editing lists.
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(map_h, "$Id$")

#include <freeradius-devel/util/pair.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_edit_list_s fr_edit_list_t;

fr_edit_list_t *fr_edit_list_alloc(TALLOC_CTX *ctx, int hint);

void fr_edit_list_abort(fr_edit_list_t *el);

#define fr_edit_list_commit(_x) talloc_free(_x)

int fr_edit_list_insert_after(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *pos, fr_pair_t *vp) CC_HINT(nonnull(2,4));

int fr_edit_list_delete(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *vp) CC_HINT(nonnull(2,3));

int fr_edit_list_record_value(fr_edit_list_t *el, fr_pair_t *vp) CC_HINT(nonnull(2));

int fr_edit_list_replace(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *to_replace, fr_pair_t *vp) CC_HINT(nonnull(2,3,4));

#ifdef __cplusplus
}
#endif
