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
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_always (%s) - "
#define LOG_PREFIX_ARGS dl_module_instance_name_by_data(inst)

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>

/*
 *	The instance data for rlm_always is the list of fake values we are
 *	going to return.
 */
typedef struct {
	char const	*xlat_name;
	char const	*rcode_str;	//!< The base value.

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

static int always_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((rlm_always_t **)xlat_inst) = talloc_get_type_abort(uctx, rlm_always_t);

	return 0;
}

/** Set module status or rcode
 *
 * Look ma, no locks...
 *
 * Example: "%{db_status:fail}"
 */
static xlat_action_t always_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
				 REQUEST *request, void const *xlat_inst,
				 UNUSED void *xlat_thread_inst,
				 fr_value_box_t **in)
{
	rlm_always_t const	*inst = talloc_get_type_abort_const(*((void const * const *)xlat_inst),rlm_always_t);
	module_instance_t	*mi;
	char const		*status;
	char const		*p;
	fr_value_box_t		*vb;

	mi = module_by_name(NULL, inst->xlat_name);
	if (!mi) {
		RERROR("Can't find the module that registered this xlat: %s", inst->xlat_name);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *      Expand to the existing status
	 */
	p = "alive";
	if (mi->force) {
		p = fr_table_str_by_value(rcode_table, mi->code, "<invalid>");
	}

	if (!(*in) || (*in)->vb_length == 0) goto done;
	status = (*in)->vb_strvalue;

	/*
	 *      Set the module status
	 */
	if (strcmp(status, "alive") == 0) {
		mi->force = false;
	} else {
		int rcode;

		rcode = fr_table_value_by_str(rcode_table, status, RLM_MODULE_UNKNOWN);
		if (rcode == RLM_MODULE_UNKNOWN) {
			RWARN("Unknown status \"%s\"", status);
			return XLAT_ACTION_FAIL;
		}

		mi->code = rcode;
		mi->force = true;

	}

done:

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_strdup(vb, vb, NULL, p, false);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;

}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_always_t	*inst = instance;
	xlat_t const	*xlat;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	xlat = xlat_async_register(inst, inst->xlat_name, always_xlat);
	xlat_async_instantiate_set(xlat, always_xlat_instantiate, rlm_always_t *, NULL, inst);

	return 0;
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_always_t *inst = instance;

	/*
	 *	Convert the rcode string to an int
	 */
	inst->rcode = fr_table_value_by_str(rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (inst->rcode == RLM_MODULE_UNKNOWN) {
		cf_log_err(conf, "rcode value \"%s\" is invalid", inst->rcode_str);
		return -1;
	}

	return 0;
}

/*
 *	Just return the rcode ... this function is autz, auth, acct, and
 *	preacct!
 */
static rlm_rcode_t CC_HINT(nonnull) mod_always_return(module_ctx_t const *mctx, UNUSED REQUEST *request)
{
	rlm_always_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_always_t);

	return inst->rcode;
}

extern module_t rlm_always;
module_t rlm_always = {
	.magic		= RLM_MODULE_INIT,
	.name		= "always",
	.inst_size	= sizeof(rlm_always_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
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
