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
 * @copyright 2020 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "unlang_priv.h"

typedef struct {
	unlang_group_t		group;
	tmpl_t			*vpt;
	fr_map_list_t		map;		//!< Head of the map list
	map_proc_inst_t		*proc_inst;
} unlang_map_t;

/** Cast a group structure to the map keyword extension
 *
 */
static inline unlang_map_t *unlang_group_to_map(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_map_t);
}

/** Cast a map keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_map_to_group(unlang_map_t *map)
{
	return (unlang_group_t *)map;
}

#ifdef __cplusplus
}
#endif
