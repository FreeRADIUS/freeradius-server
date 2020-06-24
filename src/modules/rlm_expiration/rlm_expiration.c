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
 * @file rlm_expiration.c
 * @brief Lockout user accounts based on control attributes.
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 * @copyright 2004 Kostas Kalevras (kkalev@noc.ntua.gr)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>

#include <ctype.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_expiration_dict[];
fr_dict_autoload_t rlm_expiration_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_expiration;

static fr_dict_attr_t const *attr_session_timeout;

extern fr_dict_attr_autoload_t rlm_expiration_dict_attr[];
fr_dict_attr_autoload_t rlm_expiration_dict_attr[] = {
	{ .out = &attr_expiration, .name = "Expiration", .type = FR_TYPE_DATE, .dict = &dict_freeradius },

	{ .out = &attr_session_timeout, .name = "Session-Timeout", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ NULL }
};

/*
 *      Check if account has expired, and if user may login now.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED module_ctx_t const *mctx, REQUEST *request)
{
	VALUE_PAIR *vp, *check_item = NULL;

	check_item = fr_pair_find_by_da(request->control, attr_expiration, TAG_ANY);
	if (check_item != NULL) {
		uint32_t left;

		/*
		*      Has this user's password expired?
		*
		*      If so, remove ALL reply attributes,
		*      and add our own Reply-Message, saying
		*      why they're being rejected.
		*/
		if (check_item->vp_date <= fr_time_to_unix_time(request->packet->timestamp)) {
			REDEBUG("Account expired at '%pV'", &check_item->data);

			return RLM_MODULE_DISALLOW;
		}
		RDEBUG2("Account will expire at '%pV'", &check_item->data);

		left = fr_time_to_sec(check_item->vp_date - request->packet->timestamp);

		/*
		 *	Else the account hasn't expired, but it may do so
		 *	in the future.  Set Session-Timeout.
		 */
		switch (pair_update_reply(&vp, attr_session_timeout)) {
		case 1:
			/* just update... */
			if (vp->vp_uint32 > (uint32_t)left) {
				vp->vp_uint32 = (uint32_t)left;
				RDEBUG2("&reply:Session-Timeout := %pV", &vp->data);
			}
			break;

		case 0:	/* no pre-existing */
			vp->vp_uint32 = (uint32_t)left;
			RDEBUG2("&reply:Session-Timeout := %pV", &vp->data);
			break;

		default: /* malloc failure */
			MEM(NULL);
		}
	} else {
		return RLM_MODULE_NOOP;
	}

	return RLM_MODULE_OK;
}

/*
 *      Compare the expiration date.
 */
static int expirecmp(UNUSED void *instance, REQUEST *req, UNUSED VALUE_PAIR *request, VALUE_PAIR *check,
		     UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	time_t now = 0;

	now = (req) ? fr_time_to_sec(req->packet->timestamp) : time(NULL);

	if (now <= fr_time_to_sec(check->vp_date)) return 0;

	return 1;
}


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	/*
	 *	Register the expiration comparison operation.
	 */
	paircmp_register(attr_expiration, NULL, false, expirecmp, instance);
	return 0;
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
extern module_t rlm_expiration;
module_t rlm_expiration = {
	.magic		= RLM_MODULE_INIT,
	.name		= "expiration",
	.type		= RLM_TYPE_THREAD_SAFE,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_authorize
	},
};
