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

/**
 * $Id$
 *
 * @file unlang/transaction_priv.h
 * @brief Declarations for unlang transactions
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include "unlang_priv.h"
#include <freeradius-devel/util/edit.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unlang_group_t	group;
} unlang_transaction_t;

/** A transaction stack entry
 */
typedef struct {
	fr_edit_list_t		*el;		//!< my edit list
} unlang_frame_state_transaction_t;

/** Cast a group structure to the transaction keyword extension
 *
 */
static inline unlang_transaction_t *unlang_group_to_transaction(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_transaction_t);
}

/** Cast a transaction keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_transaction_to_group(unlang_transaction_t *to)
{
	return (unlang_group_t *)to;
}

#ifdef __cplusplus
}
#endif
