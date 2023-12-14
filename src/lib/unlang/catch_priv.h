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
 * @file unlang/catch_priv.h
 * @brief Declarations for the "catch" keyword
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
#include "unlang_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unlang_group_t	group;

	bool		catching[RLM_MODULE_NUMCODES];
} unlang_catch_t;

unlang_action_t unlang_interpret_skip_to_catch(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame);

/** Cast a group structure to the transaction keyword extension
 *
 */
static inline unlang_catch_t *unlang_group_to_catch(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_catch_t);
}

/** Cast a generic structure to the catch keyword extension
 *
 */
static inline unlang_catch_t const *unlang_generic_to_catch(unlang_t const *g)
{
	return talloc_get_type_abort_const(g, unlang_catch_t);
}

#ifdef __cplusplus
}
#endif
