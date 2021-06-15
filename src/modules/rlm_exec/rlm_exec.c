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

#define LOG_PREFIX "rlm_exec (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/debug.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const		*name;
	bool			wait;
	char const		*program;
	char const		*input;
	char const		*output;
	tmpl_pair_list_t	input_list;
	tmpl_pair_list_t	output_list;
	bool			shell_escape;
	fr_time_delta_t		timeout;
	bool			timeout_is_set;

	tmpl_t	*tmpl;
} rlm_exec_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("wait", FR_TYPE_BOOL, rlm_exec_t, wait), .dflt = "yes" },
	{ FR_CONF_OFFSET("program", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_exec_t, program) },
	{ FR_CONF_OFFSET("input_pairs", FR_TYPE_STRING, rlm_exec_t, input) },
	{ FR_CONF_OFFSET("output_pairs", FR_TYPE_STRING, rlm_exec_t, output) },
	{ FR_CONF_OFFSET("shell_escape", FR_TYPE_BOOL, rlm_exec_t, shell_escape), .dflt = "yes" },
	{ FR_CONF_OFFSET_IS_SET("timeout", FR_TYPE_TIME_DELTA, rlm_exec_t, timeout) },
	CONF_PARSER_TERMINATOR
};


static xlat_action_t exec_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				      UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      UNUSED fr_value_box_list_t *in, void *rctx)
{
	fr_exec_state_t	*exec = talloc_get_type_abort(rctx, fr_exec_state_t);
	fr_value_box_t	*vb;

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
	{ .variadic = true, .type = FR_TYPE_VOID},
	XLAT_ARG_PARSER_TERMINATOR
};

/** Exec programs from an xlat
 *
 * Example:
@verbatim
"%(exec:/bin/echo hello)" == "hello"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t exec_xlat(TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out, request_t *request,
			       void const *xlat_inst, UNUSED void *xlat_thread_inst,
			       fr_value_box_list_t *in)
{
	rlm_exec_t const	*inst;
	void			*instance;
	fr_pair_list_t		*input_pairs = NULL;
	fr_exec_state_t		*exec;

	memcpy(&instance, xlat_inst, sizeof(instance));

	inst = talloc_get_type_abort(instance, rlm_exec_t);

	if (inst->input_list) {
		input_pairs = tmpl_list_head(request, inst->input_list);
		if (!input_pairs) {
			REDEBUG("Failed to find input pairs for xlat");
			return XLAT_ACTION_FAIL;
		}
	}

	if (!inst->wait) {
		/* Not waiting for the response */
		fr_exec_nowait(request, in, input_pairs);
		return XLAT_ACTION_DONE;
	}

	exec = talloc_zero(request, fr_exec_state_t);
	exec->stdout_used = inst->wait;
	exec->outctx = ctx;

	if(fr_exec_wait_start_io(exec, exec, request, in, input_pairs, inst->timeout) < 0) {
		talloc_free(exec);
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, exec_xlat_resume, NULL, exec);
}

static int mod_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((void **)xlat_inst) = talloc_get_type_abort(uctx, rlm_exec_t);
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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	char const	*p;
	rlm_exec_t	*inst = instance;
	xlat_t		*xlat;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	xlat = xlat_register(NULL, inst->name, exec_xlat, true);
	xlat_func_args(xlat, exec_xlat_args);
	xlat_async_instantiate_set(xlat, mod_xlat_instantiate, rlm_exec_t *, NULL, inst);

	if (inst->input) {
		p = inst->input;
		p += tmpl_pair_list_name(&inst->input_list, p, PAIR_LIST_UNKNOWN);
		if ((inst->input_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err(conf, "Invalid input list '%s'", inst->input);
			return -1;
		}
	}

	if (inst->output) {
		p = inst->output;
		p += tmpl_pair_list_name(&inst->output_list, p, PAIR_LIST_UNKNOWN);
		if ((inst->output_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err(conf, "Invalid output list '%s'", inst->output);
			return -1;
		}
	}

	/*
	 *	Sanity check the config.  If we're told to NOT wait,
	 *	then the output pairs must not be defined.
	 */
	if (!inst->wait && (inst->output != NULL)) {
		cf_log_err(conf, "Cannot read output pairs if wait = no");
		return -1;
	}

	if (!inst->timeout_is_set || !inst->timeout) {
		/*
		 *	Pick the shorter one
		 */
		inst->timeout = main_config->max_request_time > fr_time_delta_from_sec(EXEC_TIMEOUT) ?
			fr_time_delta_from_sec(EXEC_TIMEOUT):
			main_config->max_request_time;
	}
	else {
		if (inst->timeout < fr_time_delta_from_sec(1)) {
			cf_log_err(conf, "Timeout '%pVs' is too small (minimum: 1s)", fr_box_time_delta(inst->timeout));
			return -1;
		}

		/*
		 *	Blocking a request longer than max_request_time isn't going to help anyone.
		 */
		if (inst->timeout > main_config->max_request_time) {
			cf_log_err(conf, "Timeout '%pVs' is too large (maximum: %pVs)",
				   fr_box_time_delta(inst->timeout), fr_box_time_delta(main_config->max_request_time));
			return -1;
		}
	}

	return 0;
}


/** Instantiate the module
 *
 * Creates a new instance of the module reading parameters from a configuration section.
 *
 * @param conf to parse.
 * @param instance configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_exec_t		*inst = instance;
	ssize_t			slen;

	if (!inst->program) return 0;

	slen = tmpl_afrom_substr(inst, &inst->tmpl,
				 &FR_SBUFF_IN(inst->program, strlen(inst->program)),
				 T_BACK_QUOTED_STRING, NULL,
				 &(tmpl_rules_t) {
				 	.allow_foreign = true,
				 	.allow_unresolved = false,
				 	.allow_unknown = false
				 });
	if (!inst->tmpl) {
		char *spaces, *text;

		fr_canonicalize_error(inst, &spaces, &text, slen, inst->program);

		cf_log_err(conf, "%s", text);
		cf_log_perr(conf, "%s^", spaces);

		talloc_free(spaces);
		talloc_free(text);
		return -1;
	}

	return 0;
}

/** Resume a request after xlat expansion.
 *
 */
static unlang_action_t mod_exec_nowait_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx,
					      request_t *request, void *rctx)
{
	rlm_exec_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_exec_t);
	fr_value_box_list_t	*box = talloc_get_type_abort(rctx, fr_value_box_list_t);
	fr_pair_list_t		*env_pairs = NULL;

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input) {
		env_pairs = tmpl_list_head(request, inst->input_list);
		if (!env_pairs) {
			RETURN_MODULE_INVALID;
		}
	}

	if (fr_exec_nowait(request, box, env_pairs) < 0) {
		RPEDEBUG("Failed executing program");
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
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
		goto fail;
	}

	rcode = status2rcode[status];

	if (rcode == RLM_MODULE_FAIL) {
	fail:

		if (box) log_module_failure_msg(request, "%pV", box);

		return RLM_MODULE_FAIL;
	}

	return rcode;
}

static unlang_action_t mod_exec_wait_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx,
					    request_t *request, void *rctx)
{
	int			status;
	rlm_exec_ctx_t		*m = talloc_get_type_abort(rctx, rlm_exec_ctx_t);
	rlm_exec_t const       	*inst = talloc_get_type_abort_const(mctx->instance, rlm_exec_t);

	if (inst->output && !fr_dlist_empty(&m->box)) {
		TALLOC_CTX *ctx;
		fr_pair_list_t vps, *output_pairs;
		fr_value_box_t *box = fr_dlist_head(&m->box);

		RDEBUG("EXEC GOT -- %pM", &m->box);

		fr_pair_list_init(&vps);
		output_pairs = tmpl_list_head(request, inst->output_list);
		fr_assert(output_pairs != NULL);

		ctx = tmpl_list_ctx(request, inst->output_list);

		fr_pair_list_afrom_box(ctx, &vps, request->dict, box);
		if (!fr_pair_list_empty(&vps)) fr_pair_list_move(output_pairs, &vps, T_OP_ADD);

		fr_dlist_talloc_free(&m->box);	/* has been consumed */
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
	RETURN_MODULE_RCODE(rlm_exec_status2rcode(request, fr_dlist_head(&m->box), status));
}

/*
 *  Dispatch an async exec method
 */
static unlang_action_t CC_HINT(nonnull) mod_exec_dispatch(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_exec_t const       	*inst = talloc_get_type_abort_const(mctx->instance, rlm_exec_t);
	rlm_exec_ctx_t		*m;
	fr_pair_list_t		*env_pairs = NULL;
	TALLOC_CTX		*ctx;

	if (!inst->tmpl) {
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
		return unlang_module_yield_to_xlat(request, box, request, tmpl_xlat(inst->tmpl), mod_exec_nowait_resume, NULL, box);
	}

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input) {
		env_pairs = tmpl_list_head(request, inst->input_list);
		if (!env_pairs) RETURN_MODULE_INVALID;
	}

	if (inst->output) {
		if (!tmpl_list_head(request, inst->output_list)) {
			RETURN_MODULE_INVALID;
		}
	}

	m = talloc_zero(ctx, rlm_exec_ctx_t);
	fr_value_box_list_init(&m->box);
	return unlang_module_yield_to_tmpl(m, &m->box, &m->status, request, inst->tmpl, env_pairs, mod_exec_wait_resume, NULL, &m->box);
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
extern module_t rlm_exec;
module_t rlm_exec = {
	.magic		= RLM_MODULE_INIT,
	.name		= "exec",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_exec_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_exec_dispatch,
		[MOD_AUTHORIZE]		= mod_exec_dispatch,
		[MOD_PREACCT]		= mod_exec_dispatch,
		[MOD_ACCOUNTING]	= mod_exec_dispatch,
		[MOD_POST_AUTH]		= mod_exec_dispatch,
	},
};
