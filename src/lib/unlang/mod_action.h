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

#define MOD_PRIORITY(_x) ((_x) | 0x80)
#define MOD_DEFINE(_x) MOD_PRIORITY_ ## _x = MOD_PRIORITY(_x)

typedef enum {
	MOD_ACTION_NOT_SET = 0,       	//!< default "not set by anything"
	MOD_ACTION_RETRY = 1,		//!< retry the instruction, MUST also set a retry config
	MOD_ACTION_REJECT = 2,		//!< change the rcode to REJECT, with unset priority
	MOD_ACTION_RETURN = 3,		//!< stop processing the section,
					//!<  and return the rcode with unset priority

	MOD_DEFINE(1),
	MOD_DEFINE(2),
	MOD_DEFINE(3),
	MOD_DEFINE(4),
	MOD_DEFINE(5),
	MOD_DEFINE(6),
	MOD_DEFINE(7),
	MOD_DEFINE(8),

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
#define MOD_ACTION_VALID(_x)     ((((_x) >= 0) && ((_x) <= 3)) || (((_x) >= MOD_PRIORITY_MIN) && ((_x) <= MOD_PRIORITY_MAX)))
#define MOD_ACTION_VALID_SET(_x) ((((_x) > 0)  && ((_x) <= 3)) || (((_x) >= MOD_PRIORITY_MIN) && ((_x) <= MOD_PRIORITY_MAX)))

typedef struct {
	unlang_mod_action_t	actions[RLM_MODULE_NUMCODES];
	fr_retry_config_t	retry;
} unlang_mod_actions_t;

#define DEFAULT_MOD_ACTIONS { .actions = {}, .retry = RETRY_INIT }
#define MOD_ACTIONS_FAIL_TIMEOUT_RETURN { .actions = { [RLM_MODULE_FAIL] = MOD_ACTION_RETURN, [RLM_MODULE_TIMEOUT] = MOD_ACTION_RETURN,}, .retry = RETRY_INIT }

extern unlang_mod_actions_t const mod_actions_authenticate;
extern unlang_mod_actions_t const mod_actions_authorize;
extern unlang_mod_actions_t const mod_actions_preacct;
extern unlang_mod_actions_t const mod_actions_accounting;
extern unlang_mod_actions_t const mod_actions_postauth;
extern const char *mod_action_name[MOD_PRIORITY_MAX + 1];

#ifdef __cplusplus
}
#endif
