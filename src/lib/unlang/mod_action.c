/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file unlang/action.c
 * @brief Default action sets for virtual server actions.
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/unlang/mod_action.h>
#include <freeradius-devel/server/rcode.h>

unlang_mod_actions_t const mod_actions_authenticate = {
	.actions = {
		[RLM_MODULE_REJECT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,
		[RLM_MODULE_OK]		= MOD_PRIORITY(4),
		[RLM_MODULE_HANDLED]	= MOD_ACTION_RETURN,
		[RLM_MODULE_INVALID]	= MOD_ACTION_RETURN,
		[RLM_MODULE_DISALLOW]	= MOD_ACTION_RETURN,
		[RLM_MODULE_NOTFOUND]	= MOD_PRIORITY(1),
		[RLM_MODULE_NOOP]	= MOD_PRIORITY(2),
		[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_UPDATED]	= MOD_PRIORITY(4)
	},
	.retry = RETRY_INIT
};

unlang_mod_actions_t const mod_actions_authorize = {
	.actions = {
		[RLM_MODULE_REJECT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,
		[RLM_MODULE_OK]		= MOD_PRIORITY(3),
		[RLM_MODULE_HANDLED]	= MOD_ACTION_RETURN,
		[RLM_MODULE_INVALID]	= MOD_ACTION_RETURN,
		[RLM_MODULE_DISALLOW]	= MOD_ACTION_RETURN,
		[RLM_MODULE_NOTFOUND]	= MOD_PRIORITY(1),
		[RLM_MODULE_NOOP]	= MOD_PRIORITY(2),
		[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_UPDATED]	= MOD_PRIORITY(4)
	},
	.retry = RETRY_INIT,
};

unlang_mod_actions_t const mod_actions_preacct = {
	.actions = {
		[RLM_MODULE_REJECT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,
		[RLM_MODULE_OK]		= MOD_PRIORITY(3),
		[RLM_MODULE_HANDLED]	= MOD_ACTION_RETURN,
		[RLM_MODULE_INVALID]	= MOD_ACTION_RETURN,
		[RLM_MODULE_DISALLOW]	= MOD_ACTION_RETURN,
		[RLM_MODULE_NOTFOUND]	= MOD_PRIORITY(1),
		[RLM_MODULE_NOOP]	= MOD_PRIORITY(2),
		[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_UPDATED]	= MOD_PRIORITY(4)
	},
	.retry = RETRY_INIT,
};

unlang_mod_actions_t const mod_actions_accounting = {
	.actions = {
		[RLM_MODULE_REJECT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,
		[RLM_MODULE_OK]		= MOD_PRIORITY(3),
		[RLM_MODULE_HANDLED]	= MOD_ACTION_RETURN,
		[RLM_MODULE_INVALID]	= MOD_ACTION_RETURN,
		[RLM_MODULE_DISALLOW]	= MOD_ACTION_RETURN,
		[RLM_MODULE_NOTFOUND]	= MOD_PRIORITY(1),
		[RLM_MODULE_NOOP]	= MOD_PRIORITY(2),
		[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_UPDATED]	= MOD_PRIORITY(4)
	},
};

unlang_mod_actions_t const mod_actions_postauth = {
	.actions = {
		[RLM_MODULE_REJECT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,
		[RLM_MODULE_OK]		= MOD_PRIORITY(3),
		[RLM_MODULE_HANDLED]	= MOD_ACTION_RETURN,
		[RLM_MODULE_INVALID]	= MOD_ACTION_RETURN,
		[RLM_MODULE_DISALLOW]	= MOD_ACTION_RETURN,
		[RLM_MODULE_NOTFOUND]	= MOD_PRIORITY(1),
		[RLM_MODULE_NOOP]	= MOD_PRIORITY(2),
		[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,
		[RLM_MODULE_UPDATED]	= MOD_PRIORITY(4)
	},
	.retry = RETRY_INIT
};
