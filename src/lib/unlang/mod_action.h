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
 * @file unlang/mod_action.h
 * @brief Unlang module actions
 *
 * @copyright 2024 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/util/retry.h>

/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return.
 * There's also the keyword "reject", represented here by MOD_ACTION_REJECT
 * to cause an immediate reject. */
typedef enum {
	MOD_ACTION_RETURN = -1,
	MOD_ACTION_REJECT = -2,
	MOD_ACTION_RETRY = -3,

	MOD_PRIORITY_MIN = 0,
	MOD_PRIORITY_1 = 1,
	MOD_PRIORITY_2 = 2,
	MOD_PRIORITY_3 = 3,
	MOD_PRIORITY_4 = 4,

	/*
	 *	If ubsan or the compiler complains
	 *	about the missing enum values we'll
	 *	need to add them here.
	 *
	 *	Defining MOD_PRIORITY_MAX ensures the
	 *	enum will always be large enough.
	 */
	MOD_PRIORITY_MAX = 64
} unlang_mod_action_t;

typedef struct {
	unlang_mod_action_t	actions[RLM_MODULE_NUMCODES];
	fr_retry_config_t	retry;
} unlang_mod_actions_t;

extern unlang_mod_actions_t const mod_actions_authenticate;
extern unlang_mod_actions_t const mod_actions_authorize;
extern unlang_mod_actions_t const mod_actions_preacct;
extern unlang_mod_actions_t const mod_actions_accounting;
extern unlang_mod_actions_t const mod_actions_postauth;

#ifdef __cplusplus
}
#endif
