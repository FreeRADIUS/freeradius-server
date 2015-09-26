/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_utf8.c
 * @brief Enforce UTF8 encoding in strings.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Reject any non-UTF8 data.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_utf8_clean(UNUSED void *instance, REQUEST *request)
{
	size_t i, len;
	VALUE_PAIR *vp;
	vp_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->type != PW_TYPE_STRING) continue;

		for (i = 0; i < vp->vp_length; i += len) {
			len = fr_utf8_char(&vp->vp_octets[i], -1);
			if (len == 0) return RLM_MODULE_FAIL;
		}
	}

	return RLM_MODULE_NOOP;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_utf8;
module_t rlm_utf8 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "utf8",
	.type		= RLM_TYPE_THREAD_SAFE,
	.methods = {
		[MOD_AUTHORIZE]		= mod_utf8_clean,
		[MOD_PREACCT]		= mod_utf8_clean,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_utf8_clean
#endif
	},
};
