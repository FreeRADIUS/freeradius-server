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
 * @file unlang/map_priv.h
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "unlang_priv.h"

typedef struct {
	unlang_t		self;
	map_list_t		maps;		//!< Head of the map list
} unlang_edit_t;

/** Cast a generic structure to the edit extension
 *
 */
static inline unlang_edit_t *unlang_generic_to_edit(unlang_t const *p)
{
	fr_assert(p->type == UNLANG_TYPE_EDIT);
	return UNCONST(unlang_edit_t *, talloc_get_type_abort_const(p, unlang_edit_t));
}

static inline unlang_t *unlang_edit_to_generic(unlang_edit_t const *p)
{
	return UNCONST(unlang_t *, p);
}

#ifdef __cplusplus
}
#endif
