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

#define LOG_PREFIX mctx->inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>

/*
 *	The instance data for rlm_always is the list of fake values we are
 *	going to return.
 */
typedef struct {
	char const	*rcode_str;	//!< The base value.
	module_instance_t *mi;

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

static xlat_arg_parser_t const always_xlat_args[] = {
	{ .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Set module status or rcode
 *
 * Look ma, no locks...
 *
 * Example: "%{db_status:fail}"
 */
static xlat_action_t always_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 xlat_ctx_t const *xctx,
				 request_t *request, fr_value_box_list_t *in)
{
	rlm_always_t		*inst = talloc_get_type_abort(xctx->mctx->inst->data, rlm_always_t);
	module_instance_t	*mi = inst->mi;
	char const		*status;
	char const		*p;
	fr_value_box_t		*vb;
	fr_value_box_t		*in_head = fr_dlist_head(in);

	/*
	 *      Expand to the existing status
	 */
	p = "alive";
	if (mi->force) {
		p = fr_table_str_by_value(rcode_table, mi->code, "<invalid>");
	}

	if (!in_head || in_head->vb_length == 0) goto done;
	status = in_head->vb_strvalue;

	/*
	 *      Set the module status
	 */
	if (strcmp(status, "alive") == 0) {
		mi->force = false;
	} else {
		int rcode;

		rcode = fr_table_value_by_str(rcode_table, status, RLM_MODULE_NOT_SET);
		if (rcode == RLM_MODULE_NOT_SET) {
			RWARN("Unknown status \"%s\"", status);
			return XLAT_ACTION_FAIL;
		}

		mi->code = rcode;
		mi->force = true;

	}

done:

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_strdup(vb, vb, NULL, p, false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;

}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_always_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_always_t);
	xlat_t		*xlat;

	inst->mi = module_rlm_by_name(NULL, mctx->inst->name);
	if (!inst->mi) {
		cf_log_err(mctx->inst->conf, "Can't find the module instance data for this module: %s", mctx->inst->name);
		return -1;
	}

	xlat = xlat_register_module(inst, mctx, mctx->inst->name, always_xlat, NULL);
	xlat_func_args(xlat, always_xlat_args);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_always_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_always_t);

	/*
	 *	Convert the rcode string to an int
	 */
	inst->rcode = fr_table_value_by_str(rcode_table, inst->rcode_str, RLM_MODULE_NOT_SET);
	if (inst->rcode == RLM_MODULE_NOT_SET) {
		cf_log_err(mctx->inst->conf, "rcode value \"%s\" is invalid", inst->rcode_str);
		return -1;
	}

	return 0;
}

/*
 *	Just return the rcode ... this function is autz, auth, acct, and
 *	preacct!
 */
static unlang_action_t CC_HINT(nonnull) mod_always_return(rlm_rcode_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	rlm_always_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_always_t);

	RETURN_MODULE_RCODE(inst->rcode);
}

extern module_rlm_t rlm_always;
module_rlm_t rlm_always = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "always",
		.inst_size	= sizeof(rlm_always_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = CF_IDENT_ANY, .name2 = CF_IDENT_ANY,		.method = mod_always_return     },
		MODULE_NAME_TERMINATOR
	}
};
