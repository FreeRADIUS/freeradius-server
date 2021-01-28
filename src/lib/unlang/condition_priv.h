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
 * @file unlang/condition_priv.h
 *
 * @copyright 2020 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "unlang_priv.h"
#include <freeradius-devel/server/cond.h>

typedef struct {
	unlang_group_t	group;
	fr_cond_t	*cond;
} unlang_cond_t;

/** Cast a group structure to the cond keyword extension
 *
 */
static inline unlang_cond_t *unlang_group_to_cond(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_cond_t);
}

/** Cast a cond keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_cond_to_group(unlang_cond_t *cond)
{
	return (unlang_group_t *)cond;
}

#ifdef __cplusplus
}
#endif
