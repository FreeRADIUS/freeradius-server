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
 *
 */

/**
 * $Id$
 * @file rlm_always.c
 * @brief Return preconfigured fixed rcodes.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	The instance data for rlm_always is the list of fake values we are
 *	going to return.
 */
typedef struct rlm_always_t {
	char const	*name;		//!< Name of this instance of the always module.
	char const	*rcode_str;	//!< The base value.

	rlm_rcode_t	rcode;		//!< The integer constant representing rcode_str.
	uint32_t	simulcount;
	bool		mpp;
} rlm_always_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ "rcode", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_always_t, rcode_str), "fail" },
	{ "simulcount", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_always_t, simulcount), "0" },
	{ "mpp", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_always_t, mpp), "no" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_always_t *inst = instance;

	inst->name = cf_section_name1(conf);
	if (!inst->name) inst->name = cf_section_name2(conf);
	/*
	 *	Convert the rcode string to an int
	 */
	inst->rcode = fr_str2int(mod_rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (inst->rcode == RLM_MODULE_UNKNOWN) {
		cf_log_err_cs(conf, "rcode value \"%s\" is invalid", inst->rcode_str);
		return -1;
	}

	return 0;
}

/*
 *	Just return the rcode ... this function is autz, auth, acct, and
 *	preacct!
 */
static rlm_rcode_t CC_HINT(nonnull) mod_always_return(void *instance, UNUSED REQUEST *request)
{
	rlm_always_t *inst = instance;
	return inst->rcode;
}

#ifdef WITH_SESSION_MGMT
/*
 *	checksimul fakes some other variables besides the rcode...
 */
static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(void *instance, REQUEST *request)
{
	struct rlm_always_t *inst = instance;

	request->simul_count = inst->simulcount;

	if (inst->mpp) request->simul_mpp = 2;

	return inst->rcode;
}
#endif

extern module_t rlm_always;
module_t rlm_always = {
	RLM_MODULE_INIT,
	"always",
	0,   	/* type */
	sizeof(rlm_always_t),		/* config size */
	module_config,			/* configuration */
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		mod_always_return,		/* authentication */
		mod_always_return,		/* authorization */
		mod_always_return,		/* preaccounting */
		mod_always_return,		/* accounting */
#ifdef WITH_SESSION_MGMT
		mod_checksimul,	/* checksimul */
#else
		NULL,
#endif
		mod_always_return,	       	/* pre-proxy */
		mod_always_return,		/* post-proxy */
		mod_always_return		/* post-auth */
#ifdef WITH_COA
		,
		mod_always_return,		/* recv-coa */
		mod_always_return		/* send-coa */
#endif
	},
};
