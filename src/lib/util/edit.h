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

typedef enum {
	FR_EDIT_INVALID = 0,
	FR_EDIT_DELETE,			//!< delete a VP
	FR_EDIT_VALUE,			//!< edit a VP in place
	FR_EDIT_INSERT,			//!< insert a VP into a list, after another one.
} fr_edit_op_t;

typedef struct fr_edit_list_s fr_edit_list_t;

fr_edit_list_t *fr_edit_list_alloc(TALLOC_CTX *ctx);

void fr_edit_list_abort(fr_edit_list_t *el);

int fr_edit_list_record(fr_edit_list_t *el, fr_edit_op_t op, fr_pair_t *vp, fr_pair_list_t *list, fr_pair_t *prev);

#ifdef __cplusplus
}
#endif
