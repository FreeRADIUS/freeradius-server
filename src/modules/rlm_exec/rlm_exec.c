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
	char const	*name;
	bool		wait;
	char const	*program;
	char const	*input;
	char const	*output;
	pair_list_t	input_list;
	pair_list_t	output_list;
	bool		shell_escape;
	fr_time_delta_t	timeout;
	bool		timeout_is_set;

	vp_tmpl_t	*tmpl;
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

static char const special[] = "\\'\"`<>|; \t\r\n()[]?#$^&*=";

/*
 *	Escape special characters
 */
static size_t rlm_exec_shell_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *in,
				    UNUSED void *inst)
{
	char *q, *end;
	char const *p;

	q = out;
	end = out + outlen;
	p = in;

	while (*p) {
		if ((q + 3) >= end) break;

		if (strchr(special, *p) != NULL) {
			*(q++) = '\\';
		}
		*(q++) = *(p++);
	}

	*q = '\0';
	return q - out;
}


/** Exec programs from an xlat
 *
 * Example:
@verbatim
"%{exec:/bin/echo hello}" == "hello"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t exec_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	int			result;
	rlm_exec_t const	*inst = mod_inst;
	VALUE_PAIR		**input_pairs = NULL;
	char *p;

	if (!inst->wait) {
		REDEBUG("'wait' must be enabled to use exec xlat");
		return -1;
	}

	if (inst->input_list) {
		input_pairs = radius_list(request, inst->input_list);
		if (!input_pairs) {
			REDEBUG("Failed to find input pairs for xlat");
			return -1;
		}
	}

	/*
	 *	This function does it's own xlat of the input program
	 *	to execute.
	 */
	result = radius_exec_program(request, *out, outlen, NULL, request, fmt, input_pairs ? *input_pairs : NULL,
				     inst->wait, inst->shell_escape, inst->timeout);
	if (result != 0) return -1;

	for (p = *out; *p != '\0'; p++) {
		if (*p < ' ') *p = ' ';
	}

	return strlen(*out);
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
	char const *p;
	rlm_exec_t	*inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	xlat_register(inst, inst->name, exec_xlat, rlm_exec_shell_escape, NULL, 0, XLAT_DEFAULT_BUF_LEN, false);

	if (inst->input) {
		p = inst->input;
		p += radius_list_name(&inst->input_list, p, PAIR_LIST_UNKNOWN);
		if ((inst->input_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err(conf, "Invalid input list '%s'", inst->input);
			return -1;
		}
	}

	if (inst->output) {
		p = inst->output;
		p += radius_list_name(&inst->output_list, p, PAIR_LIST_UNKNOWN);
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

	if (inst->timeout_is_set || !inst->timeout) {
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

	/*
	 *	Parse the program to execute into a template.
	 */
	MEM(inst->tmpl = tmpl_alloc(inst, TMPL_TYPE_EXEC, inst->program, strlen(inst->program), T_BACK_QUOTED_STRING));

	slen = xlat_tokenize_argv(inst->tmpl, &tmpl_xlat(inst->tmpl), inst->program, strlen(inst->program),
				  &(vp_tmpl_rules_t) { .dict_def = fr_dict_internal() });
	if (slen <= 0) {
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
static rlm_rcode_t mod_exec_nowait_resume(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	rlm_exec_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_exec_t);
	fr_value_box_t		*box = talloc_get_type_abort(rctx, fr_value_box_t);
	VALUE_PAIR		*env_pairs = NULL;

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input) {
		VALUE_PAIR **input_pairs;

		input_pairs = radius_list(request, inst->input_list);
		if (!input_pairs) {
			return RLM_MODULE_INVALID;
		}

		env_pairs = *input_pairs;
	}

	if (fr_exec_nowait(request, box, env_pairs) < 0) {
		RPEDEBUG("Failed executing program");
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

typedef struct {
	fr_value_box_t	*box;
	int		status;
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
static rlm_rcode_t rlm_exec_status2rcode(REQUEST *request, fr_value_box_t *box, int status)
{
	rlm_rcode_t rcode;

	if (status < 0) {
		return RLM_MODULE_FAIL;
	}

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

static rlm_rcode_t mod_exec_wait_resume(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	int			status;
	rlm_exec_ctx_t		*m = talloc_get_type_abort(rctx, rlm_exec_ctx_t);
	rlm_exec_t const       	*inst = talloc_get_type_abort_const(mctx->instance, rlm_exec_t);

	if (inst->output && m->box) {
		TALLOC_CTX *ctx;
		VALUE_PAIR *vps, **output_pairs;

		RDEBUG("EXEC GOT -- %pV", m->box);

		output_pairs = radius_list(request, inst->output_list);
		fr_assert(output_pairs != NULL);

		ctx = radius_list_ctx(request, inst->output_list);

		vps = fr_pair_list_afrom_box(ctx, request->dict, m->box);
		if (vps) fr_pair_list_move(output_pairs, &vps);

		m->box = NULL;	/* has been consumed */
	}

	status = m->status;

	if (status < 0) {
		REDEBUG("Program exited with signal %d", -status);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	The status rcodes aren't quite the same as the rcode
	 *	enumeration.
	 */
	return rlm_exec_status2rcode(request, m->box, status);
}

/*
 *  Dispatch an async exec method
 */
static rlm_rcode_t CC_HINT(nonnull) mod_exec_dispatch(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_exec_t const       	*inst = talloc_get_type_abort_const(mctx->instance, rlm_exec_t);
	rlm_exec_ctx_t		*m;
	VALUE_PAIR		*env_pairs = NULL;
	TALLOC_CTX		*ctx;

	if (!inst->tmpl) {
		RDEBUG("This module requires 'program' to be set.");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Get frame-local talloc ctx
	 */
	ctx = unlang_interpret_frame_talloc_ctx(request);

	/*
	 *	Do the asynchronous xlat expansion.
	 */
	if (!inst->wait) {
		fr_value_box_t *box;

		MEM(box = talloc_zero(ctx, fr_value_box_t));

		return unlang_module_yield_to_xlat(request, &box, request, tmpl_xlat(inst->tmpl), mod_exec_nowait_resume, NULL, box);
	}

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input) {
		VALUE_PAIR **input_pairs;

		input_pairs = radius_list(request, inst->input_list);
		if (!input_pairs) return RLM_MODULE_INVALID;

		env_pairs = *input_pairs;
	}

	if (inst->output) {
		if (!radius_list(request, inst->output_list)) {
			return RLM_MODULE_INVALID;
		}
	}

	m = talloc_zero(ctx, rlm_exec_ctx_t);

	return unlang_module_yield_to_tmpl(m, &m->box, &m->status, request, inst->tmpl, env_pairs, mod_exec_wait_resume, NULL, m);
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
