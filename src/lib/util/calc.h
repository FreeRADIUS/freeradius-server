
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
RCSIDH(calc_h, "$Id$")

#include <freeradius-devel/util/value.h>

#ifdef __cplusplus
extern "C" {
#endif

int fr_value_calc_binary_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_type_t hint, fr_value_box_t const *a, fr_token_t op, fr_value_box_t const *b) CC_HINT(nonnull(2,4,6));

int fr_value_calc_assignment_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_token_t op, fr_value_box_t const *src) CC_HINT(nonnull(2,4));

int fr_value_calc_unary_op(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_token_t op, fr_value_box_t const *src) CC_HINT(nonnull(1));

int fr_value_calc_list_op(TALLOC_CTX *ctx, fr_value_box_t *box, fr_token_t op, fr_value_box_list_t const *list);

int fr_value_calc_list_cmp(TALLOC_CTX *ctx, fr_value_box_t *dst, fr_value_box_list_t const *list1, fr_token_t op, fr_value_box_list_t const *list2) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
