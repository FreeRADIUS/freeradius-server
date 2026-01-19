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

#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-designator"
#endif

const char *mod_action_name[MOD_PRIORITY_MAX + 1] = {
	[MOD_ACTION_NOT_SET] = "not-set",
	[MOD_ACTION_RETRY]   = "retry",
	[MOD_ACTION_REJECT]  = "reject",
	[MOD_ACTION_RETURN]  = "return",

	[4 ... 0x80] = "<INVALID>",

	// zsh: for x ({1..64}); do print -n "[MOD_PRIORITY($x)] = \"$x\", "; done
	[MOD_PRIORITY(1)] = "1", [MOD_PRIORITY(2)] = "2", [MOD_PRIORITY(3)] = "3", [MOD_PRIORITY(4)] = "4",
	[MOD_PRIORITY(5)] = "5", [MOD_PRIORITY(6)] = "6", [MOD_PRIORITY(7)] = "7", [MOD_PRIORITY(8)] = "8",
	[MOD_PRIORITY(9)] = "9", [MOD_PRIORITY(10)] = "10", [MOD_PRIORITY(11)] = "11", [MOD_PRIORITY(12)] = "12",
	[MOD_PRIORITY(13)] = "13", [MOD_PRIORITY(14)] = "14", [MOD_PRIORITY(15)] = "15", [MOD_PRIORITY(16)] = "16",
	[MOD_PRIORITY(17)] = "17", [MOD_PRIORITY(18)] = "18", [MOD_PRIORITY(19)] = "19", [MOD_PRIORITY(20)] = "20",
	[MOD_PRIORITY(21)] = "21", [MOD_PRIORITY(22)] = "22", [MOD_PRIORITY(23)] = "23", [MOD_PRIORITY(24)] = "24",
	[MOD_PRIORITY(25)] = "25", [MOD_PRIORITY(26)] = "26", [MOD_PRIORITY(27)] = "27", [MOD_PRIORITY(28)] = "28",
	[MOD_PRIORITY(29)] = "29", [MOD_PRIORITY(30)] = "30", [MOD_PRIORITY(31)] = "31", [MOD_PRIORITY(32)] = "32",
	[MOD_PRIORITY(33)] = "33", [MOD_PRIORITY(34)] = "34", [MOD_PRIORITY(35)] = "35", [MOD_PRIORITY(36)] = "36",
	[MOD_PRIORITY(37)] = "37", [MOD_PRIORITY(38)] = "38", [MOD_PRIORITY(39)] = "39", [MOD_PRIORITY(40)] = "40",
	[MOD_PRIORITY(41)] = "41", [MOD_PRIORITY(42)] = "42", [MOD_PRIORITY(43)] = "43", [MOD_PRIORITY(44)] = "44",
	[MOD_PRIORITY(45)] = "45", [MOD_PRIORITY(46)] = "46", [MOD_PRIORITY(47)] = "47", [MOD_PRIORITY(48)] = "48",
	[MOD_PRIORITY(49)] = "49", [MOD_PRIORITY(50)] = "50", [MOD_PRIORITY(51)] = "51", [MOD_PRIORITY(52)] = "52",
	[MOD_PRIORITY(53)] = "53", [MOD_PRIORITY(54)] = "54", [MOD_PRIORITY(55)] = "55", [MOD_PRIORITY(56)] = "56",
	[MOD_PRIORITY(57)] = "57", [MOD_PRIORITY(58)] = "58", [MOD_PRIORITY(59)] = "59", [MOD_PRIORITY(60)] = "60",
	[MOD_PRIORITY(61)] = "61", [MOD_PRIORITY(62)] = "62", [MOD_PRIORITY(63)] = "63", [MOD_PRIORITY(64)] = "64",
};
