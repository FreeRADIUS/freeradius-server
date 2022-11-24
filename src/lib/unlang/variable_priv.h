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
 * @file unlang/variable_priv.h
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "unlang_priv.h"

typedef struct {
	unlang_t		self;
	fr_dict_t		*dict;
	fr_dict_attr_t const	*root;
	int			max_attr;
} unlang_variable_t;

/** Cast a generic structure to the edit extension
 *
 */
static inline unlang_variable_t *unlang_generic_to_variable(unlang_t const *p)
{
	fr_assert(p->type == UNLANG_TYPE_VARIABLE);
	return UNCONST(unlang_variable_t *, talloc_get_type_abort_const(p, unlang_variable_t));
}

static inline unlang_t *unlang_variable_to_generic(unlang_variable_t const *p)
{
	return UNCONST(unlang_t *, p);
}

#ifdef __cplusplus
}
#endif
