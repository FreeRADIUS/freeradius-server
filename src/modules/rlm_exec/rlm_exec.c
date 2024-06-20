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
 * @file rlm_exec.c
 * @brief Execute commands and parse the results.
 *
 * @copyright 2002,2006 The FreeRADIUS server project
 * @copyright 2002 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <stdint.h>

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/module.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	bool			wait;
	tmpl_t			*input_list;
	tmpl_t			*output_list;
	bool			shell_escape;
	bool			env_inherit;
	fr_time_delta_t		timeout;
	bool			timeout_is_set;
} rlm_exec_t;

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("wait", rlm_exec_t, wait), .dflt = "yes" },
	{ FR_CONF_OFFSET("input_pairs", rlm_exec_t, input_list) },
	{ FR_CONF_OFFSET("output_pairs", rlm_exec_t, output_list) },
	{ FR_CONF_OFFSET("shell_escape", rlm_exec_t, shell_escape), .dflt = "yes" },
	{ FR_CONF_OFFSET("env_inherit", rlm_exec_t, env_inherit), .dflt = "no" },
	{ FR_CONF_OFFSET_IS_SET("timeout", FR_TYPE_TIME_DELTA, 0, rlm_exec_t, timeout) },
	CONF_PARSER_TERMINATOR
};

typedef struct {
	tmpl_t	*program;
} exec_call_env_t;

static const call_env_method_t exec_method_env = {
	FR_CALL_ENV_METHOD_OUT(exec_call_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("program", FR_TYPE_STRING, CALL_ENV_FLAG_FORCE_QUOTE, exec_call_env_t, program), .pair.dflt_quote = T_BACK_QUOTED_STRING },
		CALL_ENV_TERMINATOR
	}
};

static xlat_action_t exec_xlat_oneshot_wait_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
						   xlat_ctx_t const *xctx,
						   request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_exec_state_t	*exec = talloc_get_type_abort(xctx->rctx, fr_exec_state_t);
	fr_value_box_t	*vb;

	if (exec->failed == FR_EXEC_FAIL_TIMEOUT) {
		RPEDEBUG("Execution of external program failed");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Allow a return code of 3 as success to match the behaviour of
	 *	inline module calls.
	 */
	if ((exec->status != 0) && (exec->status != 3)) {
		RPEDEBUG("Execution of external program returned %d", exec->status);
 		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));

	/*
	 *	Remove any trailing line endings and trim buffer
	 */
	fr_sbuff_trim(&exec->stdout_buff, sbuff_char_line_endings);
	fr_sbuff_trim_talloc(&exec->stdout_buff, SIZE_MAX);

	/*
	 *	Use the buffer for the output vb
	 */
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&exec->stdout_buff), true);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const exec_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_VOID},
	XLAT_ARG_PARSER_TERMINATOR
};

/** Exec programs from an xlat
 *
 * Example:
@verbatim
%exec('/bin/echo', 'hello') == "hello"
@endverbatim
 *
 * Exactly one request is consumed during the process lifetime,
 * after which the process exits.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t exec_xlat_oneshot(TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				       xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	rlm_exec_t const	*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_exec_t);
	fr_pair_list_t		*env_pairs = NULL;
	fr_exec_state_t		*exec;

	if (inst->input_list) {
		env_pairs = tmpl_list_head(request, tmpl_list(inst->input_list));
		if (!env_pairs) {
			REDEBUG("Failed to find input pairs for xlat");
			return XLAT_ACTION_FAIL;
		}
	}

	if (!inst->wait) {
		if (unlikely(fr_exec_oneshot_nowait(request, in, env_pairs, inst->shell_escape, inst->env_inherit) < 0)) {
			RPEDEBUG("Failed executing program");
			return XLAT_ACTION_FAIL;
		}

		return XLAT_ACTION_DONE;
	}

	MEM(exec = talloc_zero(unlang_interpret_frame_talloc_ctx(request), fr_exec_state_t));
	if (fr_exec_oneshot(exec, exec, request,
			    in,
			    env_pairs, inst->shell_escape, inst->env_inherit,
			    false,
			    inst->wait, ctx,
			    inst->timeout) < 0) {
		talloc_free(exec);
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, exec_xlat_oneshot_wait_resume, NULL, 0, exec);
}

typedef struct {
	fr_value_box_list_t	box;
	int			status;
} rlm_exec_ctx_t;

static const rlm_rcode_t status2rcode[] = {
	[0] = RLM_MODULE_OK,
	[1] = RLM_MODULE_REJECT,
	[2] = RLM_MODULE_FAIL,
	[3] = RLM_MODULE_OK,
	[4] = RLM_MODULE_HANDLED,
	[5] = RLM_MODULE_INVALID,
	[6] = RLM_MODULE_DISALLOW,
	[7] = RLM_MODULE_NOTFOUND,
	[8] = RLM_MODULE_NOOP,
	[9] = RLM_MODULE_UPDATED,
};


/** Process the exit code returned by one of the exec functions
 *
 * @param request Current request.
 * @param box Output string from exec call.
 * @param status code returned by exec call.
 * @return One of the RLM_MODULE_* values.
 */
static rlm_rcode_t rlm_exec_status2rcode(request_t *request, fr_value_box_t *box, int status)
{
	rlm_rcode_t rcode;

	if (status < 0) return RLM_MODULE_FAIL;

	/*
	 *	Exec'd programs are meant to return exit statuses that correspond
	 *	to the standard RLM_MODULE_* + 1.
	 *
	 *	This frees up 0, for success where it'd normally be reject.
	 */
	if (status == 0) {
		RDEBUG("Program executed successfully");

		return RLM_MODULE_OK;
	}

	if (status > 9) {
		REDEBUG("Program returned invalid code (greater than max rcode) (%i > 9): %pV",
			status, box);
		return RLM_MODULE_FAIL;
	}

	rcode = status2rcode[status];

	if (rcode == RLM_MODULE_FAIL) {
		if (box) RDEBUG("Program failed with output: %pV", box);

		return RLM_MODULE_FAIL;
	}

	return rcode;
}

/** Resume a request after xlat expansion.
 *
 */
static unlang_action_t mod_exec_oneshot_nowait_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx,
						      request_t *request)
{
	rlm_exec_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_exec_t);
	fr_value_box_list_t	*args = talloc_get_type_abort(mctx->rctx, fr_value_box_list_t);
	fr_pair_list_t		*env_pairs = NULL;

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input_list) {
		env_pairs = tmpl_list_head(request, tmpl_list(inst->input_list));
		if (!env_pairs) {
			RETURN_MODULE_INVALID;
		}
	}

	if (unlikely(fr_exec_oneshot_nowait(request, args, env_pairs, inst->shell_escape, inst->env_inherit) < 0)) {
		RPEDEBUG("Failed executing program");
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
}

static fr_sbuff_parse_rules_t const rhs_term = {
	.escapes = &(fr_sbuff_unescape_rules_t){
		.chr = '\\',
		.do_hex = true,
		.do_oct = false
	},
	.terminals = &FR_SBUFF_TERMS(
		L(""),
		L("\t"),
		L("\n"),
		L(","),
	)
};

/** Process the exit code and output of a short lived process
 *
 */
static unlang_action_t mod_exec_oneshot_wait_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	int			status;
	rlm_exec_t const       	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_exec_t);
	rlm_exec_ctx_t		*m = talloc_get_type_abort(mctx->rctx, rlm_exec_ctx_t);
	rlm_rcode_t		rcode;

	/*
	 *	Also prints stdout as an error if there was any...
	 */
	rcode = rlm_exec_status2rcode(request, fr_value_box_list_head(&m->box), m->status);
	switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		if (inst->output_list && !fr_value_box_list_empty(&m->box)) {
			ssize_t slen;
			map_t *map;
			fr_value_box_t *box = fr_value_box_list_head(&m->box);
			fr_sbuff_t	in = FR_SBUFF_IN(box->vb_strvalue, box->vb_length);
			tmpl_rules_t	lhs_rules = (tmpl_rules_t) {
				.attr = {
					.dict_def = request->dict,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO,
					.list_def = tmpl_list(inst->output_list),
					.list_presence = TMPL_ATTR_LIST_ALLOW,

					/*
					 *	Otherwise the tmpl code returns 0 when asked
					 *	to parse unknown names.  So we say "please
					 *	parse unknown names as unresolved attributes",
					 *	and then do a second pass to complain that the
					 *	thing isn't known.
					 */
					.allow_unresolved = false
				}
			};
			tmpl_rules_t	rhs_rules = lhs_rules;

			rhs_rules.attr.prefix = TMPL_ATTR_REF_PREFIX_YES;
			rhs_rules.attr.list_def = request_attr_request;
			rhs_rules.at_runtime = true;
			rhs_rules.xlat.runtime_el = unlang_interpret_event_list(request);

			while (true) {
				slen = map_afrom_substr(request, &map, NULL, &in,
							map_assignment_op_table, map_assignment_op_table_len,
							&lhs_rules, &rhs_rules, &rhs_term);
				if (slen < 0) {
					RPEDEBUG("Failed parsing exec output string");
					break;
				}
				if (!slen) {
					RDEBUG("Stopping due to no input at %.*s", (int) fr_sbuff_remaining(&in), fr_sbuff_current(&in));
					break;
				}

#ifdef STATIC_ANALYZER
				if (!map) return -1;
#endif

				RDEBUG("applying %s %s %s",
				       map->lhs->name, fr_tokens[map->op], map->rhs->name);

				if (radius_legacy_map_apply(request, map, NULL) < 0) {
					RPEDEBUG("Failed applying assignment");

					TALLOC_FREE(map);
					return -1;
				}
				TALLOC_FREE(map);

				fr_sbuff_adv_past_whitespace(&in, SIZE_MAX, NULL);

				if (!fr_sbuff_remaining(&in)) break;

				/*
				 *	Allow commas between attributes
				 */
				(void) fr_sbuff_next_if_char(&in, ',');
			}
		}
		break;

	default:
		break;
	}

	status = m->status;
	if (status < 0) {
		REDEBUG("Program exited with signal %d", -status);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	The status rcodes aren't quite the same as the rcode
	 *	enumeration.
	 */
	RETURN_MODULE_RCODE(rcode);
}

/** Dispatch one request using a short lived process
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_exec_dispatch_oneshot(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_exec_ctx_t		*m;
	fr_pair_list_t		*env_pairs = NULL;
	TALLOC_CTX		*ctx;
	rlm_exec_t const       	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_exec_t);
	exec_call_env_t		*env_data = talloc_get_type_abort(mctx->env_data, exec_call_env_t);

	if (!env_data->program) {
		RDEBUG("This module requires 'program' to be set.");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Get frame-local talloc ctx
	 */
	ctx = unlang_interpret_frame_talloc_ctx(request);

	/*
	 *	Do the asynchronous xlat expansion.
	 */
	if (!inst->wait) {
		fr_value_box_list_t *box = talloc_zero(ctx, fr_value_box_list_t);

		fr_value_box_list_init(box);

		/*
		 *  The xlat here only expands the arguments, then calls
		 *  the resume function we set to actually dispatch the
		 *  exec request.
		 */
		return unlang_module_yield_to_xlat(request, NULL, box, request, tmpl_xlat(env_data->program),
						   mod_exec_oneshot_nowait_resume, NULL, 0, box);
	}

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input_list) {
		env_pairs = tmpl_list_head(request, tmpl_list(inst->input_list));
		if (!env_pairs) RETURN_MODULE_INVALID;
	}

	if (inst->output_list) {
		if (!tmpl_list_head(request, tmpl_list(inst->output_list))) {
			RETURN_MODULE_INVALID;
		}
	}

	MEM(m = talloc_zero(ctx, rlm_exec_ctx_t));
	m->status = 2;	/* Fail if we couldn't exec */

	fr_value_box_list_init(&m->box);
	return unlang_module_yield_to_tmpl(m, &m->box,
					   request, env_data->program,
					   TMPL_ARGS_EXEC(env_pairs, inst->timeout, true, &m->status),
					   mod_exec_oneshot_wait_resume,
					   NULL, 0, &m->box);
}

static int mob_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_exec_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_exec_t);
	CONF_SECTION	*conf = mctx->mi->conf;

	if (inst->input_list && !tmpl_is_list(inst->input_list)) {
		cf_log_perr(conf, "Invalid input list '%s'", inst->input_list->name);
		return -1;
	}

	if (inst->output_list && !tmpl_is_list(inst->output_list)) {
		cf_log_err(conf, "Invalid output list '%s'", inst->output_list->name);
		return -1;
	}

	/*
	 *	Sanity check the config.  If we're told to NOT wait,
	 *	then the output pairs must not be defined.
	 */
	if (!inst->wait && (inst->output_list != NULL)) {
		cf_log_err(conf, "Cannot read output pairs if wait = no");
		return -1;
	}

	if (!inst->timeout_is_set || !fr_time_delta_ispos(inst->timeout)) {
		/*
		 *	Pick the shorter one
		 */
		inst->timeout = fr_time_delta_gt(main_config->max_request_time, fr_time_delta_from_sec(EXEC_TIMEOUT)) ?
						 fr_time_delta_from_sec(EXEC_TIMEOUT):
						 main_config->max_request_time;
	}
	else {
		if (fr_time_delta_lt(inst->timeout, fr_time_delta_from_sec(1))) {
			cf_log_err(conf, "Timeout '%pVs' is too small (minimum: 1s)", fr_box_time_delta(inst->timeout));
			return -1;
		}

		/*
		 *	Blocking a request longer than max_request_time isn't going to help anyone.
		 */
		if (fr_time_delta_gt(inst->timeout, main_config->max_request_time)) {
			cf_log_err(conf, "Timeout '%pVs' is too large (maximum: %pVs)",
				   fr_box_time_delta(inst->timeout), fr_box_time_delta(main_config->max_request_time));
			return -1;
		}
	}

	return 0;
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
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t			*xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, exec_xlat_oneshot, FR_TYPE_STRING);
	xlat_func_args_set(xlat, exec_xlat_args);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_exec;
module_rlm_t rlm_exec = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "exec",
		.inst_size	= sizeof(rlm_exec_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mob_instantiate
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_exec_dispatch_oneshot, .method_env = &exec_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
