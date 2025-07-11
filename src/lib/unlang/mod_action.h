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

#define MOD_PRIORITY(_x) (_x)

typedef enum {
	MOD_ACTION_NOT_SET = -4,       	//!< default "not set by anything"
	MOD_ACTION_RETRY = -3,		//!< retry the instruction, MUST also set a retry config
	MOD_ACTION_REJECT = -2,		//!< change the rcode to REJECT, with unset priority
	MOD_ACTION_RETURN = -1,		//!< stop processing the section,
					//!<  and return the rcode with unset priority

	MOD_PRIORITY_1 = MOD_PRIORITY(1),
	MOD_PRIORITY_2 = MOD_PRIORITY(2),
	MOD_PRIORITY_3 = MOD_PRIORITY(3),
	MOD_PRIORITY_4 = MOD_PRIORITY(4),

	/*
	 *	If ubsan or the compiler complains
	 *	about the missing enum values we'll
	 *	need to add them here.
	 *
	 *	Defining MOD_PRIORITY_MAX ensures the
	 *	enum will always be large enough.
	 */
	MOD_PRIORITY_MAX = MOD_PRIORITY(64)
} unlang_mod_action_t;

#define MOD_PRIORITY_MIN MOD_PRIORITY_1

typedef struct {
	unlang_mod_action_t	actions[RLM_MODULE_NUMCODES];
	fr_retry_config_t	retry;
} unlang_mod_actions_t;

#define DEFAULT_MOD_ACTIONS { .actions = {}, .retry = RETRY_INIT }

extern unlang_mod_actions_t const mod_actions_authenticate;
extern unlang_mod_actions_t const mod_actions_authorize;
extern unlang_mod_actions_t const mod_actions_preacct;
extern unlang_mod_actions_t const mod_actions_accounting;
extern unlang_mod_actions_t const mod_actions_postauth;

#ifdef __cplusplus
}
#endif
