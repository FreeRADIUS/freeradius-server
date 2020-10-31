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
 * @file unlang/call_priv.h
 *
 * @copyright 2020 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "unlang_priv.h"
#include <freeradius-devel/unlang/unlang_priv.h>

typedef struct {
	unlang_group_t		group;
	CONF_SECTION		*server_cs;
	fr_dict_attr_t const	*attr_packet_type;
} unlang_call_t;

/** Cast a group structure to the call keyword extension
 *
 */
static inline unlang_call_t *unlang_group_to_call(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_call_t);
}

/** Cast a call keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_call_to_group(unlang_call_t *call)
{
	return (unlang_group_t *)call;
}

#ifdef __cplusplus
}
#endif
