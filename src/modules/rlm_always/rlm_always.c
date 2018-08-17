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

#define LOG_PREFIX "rlm_always (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>

/*
 *	The instance data for rlm_always is the list of fake values we are
 *	going to return.
 */
typedef struct rlm_always_t {
	char const	*name;		//!< Name of this instance of the always module.
	char const	*rcode_str;	//!< The base value.
	char const	*rcode_old;	//!< Make changing the rcode work with %{poke:} and radmin.

	rlm_rcode_t	rcode;		//!< The integer constant representing rcode_str.
	uint32_t	simulcount;
	bool		mpp;
} rlm_always_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("rcode", FR_TYPE_STRING, rlm_always_t, rcode_str), .dflt = "fail" },
	{ FR_CONF_OFFSET("simulcount", FR_TYPE_UINT32, rlm_always_t, simulcount), .dflt = "0" },
	{ FR_CONF_OFFSET("mpp", FR_TYPE_BOOL, rlm_always_t, mpp), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_always_t *inst = instance;

	inst->name = cf_section_name1(conf);
	if (!inst->name) inst->name = cf_section_name2(conf);
	/*
	 *	Convert the rcode string to an int
	 */
	inst->rcode = fr_str2int(mod_rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (inst->rcode == RLM_MODULE_UNKNOWN) {
		cf_log_err(conf, "rcode value \"%s\" is invalid", inst->rcode_str);
		return -1;
	}
	inst->rcode_old = NULL;	/* Hack - forces the compiler not to optimise away rcode_old */

	return 0;
}

/** Reparse the rcode if it changed
 *
 * @note Look ma, no locks...
 *
 * @param inst Module instance.
 */
static void reparse_rcode(rlm_always_t *inst)
{
	rlm_rcode_t rcode;

	rcode = fr_str2int(mod_rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (rcode == RLM_MODULE_UNKNOWN) {
		WARN("Ignoring rcode change.  rcode value \"%s\" is invalid ", inst->rcode_str);
		return;
	}

	inst->rcode = rcode;
	inst->rcode_old = inst->rcode_str;
}

/*
 *	Just return the rcode ... this function is autz, auth, acct, and
 *	preacct!
 */
static rlm_rcode_t CC_HINT(nonnull) mod_always_return(void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	rlm_always_t *inst = instance;

	if (inst->rcode_old != inst->rcode_str) reparse_rcode(inst);

	return inst->rcode;
}

extern rad_module_t rlm_always;
rad_module_t rlm_always = {
	.magic		= RLM_MODULE_INIT,
	.name		= "always",
	.inst_size	= sizeof(rlm_always_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_always_return,
		[MOD_AUTHORIZE]		= mod_always_return,
		[MOD_PREACCT]		= mod_always_return,
		[MOD_ACCOUNTING]	= mod_always_return,
		[MOD_PRE_PROXY]		= mod_always_return,
		[MOD_POST_PROXY]	= mod_always_return,
		[MOD_POST_AUTH]		= mod_always_return,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_always_return,
		[MOD_SEND_COA]		= mod_always_return
#endif
	},
};
