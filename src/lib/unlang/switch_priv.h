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
 * @file unlang/switch_priv.h
 *
 * @copyright 2020 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/htrie.h>

typedef struct {
	unlang_group_t	group;
	unlang_t	*default_case;
	tmpl_t		*vpt;
	fr_htrie_t	*ht;
} unlang_switch_t;

/** Cast a group structure to the switch keyword extension
 *
 */
static inline unlang_switch_t *unlang_group_to_switch(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_switch_t);
}

/** Cast a switch keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_switch_to_group(unlang_switch_t *sw)
{
	return (unlang_group_t *)sw;
}

typedef struct {
	unlang_group_t	group;
	tmpl_t		*vpt;
} unlang_case_t;

/** Cast a group structure to the case keyword extension
 *
 */
static inline unlang_case_t *unlang_group_to_case(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_case_t);
}

/** Cast a case keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_case_to_group(unlang_case_t *sw)
{
	return (unlang_group_t *)sw;
}

#ifdef __cplusplus
}
#endif
