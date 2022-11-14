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
 * @file unlang/timeout_priv.h
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/tmpl.h>

typedef struct {
	unlang_group_t	group;
	tmpl_t		*vpt;
	fr_time_delta_t	timeout;
} unlang_timeout_t;

/** Cast a group structure to the timeout keyword extension
 *
 */
static inline unlang_timeout_t *unlang_group_to_timeout(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_timeout_t);
}

/** Cast a timeout keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_timeout_to_group(unlang_timeout_t *to)
{
	return (unlang_group_t *)to;
}

#ifdef __cplusplus
}
#endif
