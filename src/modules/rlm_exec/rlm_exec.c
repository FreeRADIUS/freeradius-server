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
 * @copyright 2002,2006  The FreeRADIUS server project
 * @copyright 2002  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_exec (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/rad_assert.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_exec_t {
	char const	*name;
	bool		wait;
	char const	*program;
	char const	*input;
	char const	*output;
	pair_lists_t	input_list;
	pair_lists_t	output_list;
	bool		shell_escape;
	uint32_t	timeout;
} rlm_exec_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("wait", FR_TYPE_BOOL, rlm_exec_t, wait), .dflt = "yes" },
	{ FR_CONF_OFFSET("program", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_exec_t, program) },
	{ FR_CONF_OFFSET("input_pairs", FR_TYPE_STRING, rlm_exec_t, input) },
	{ FR_CONF_OFFSET("output_pairs", FR_TYPE_STRING, rlm_exec_t, output) },
	{ FR_CONF_OFFSET("shell_escape", FR_TYPE_BOOL, rlm_exec_t, shell_escape), .dflt = "yes" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_exec_t, timeout) },
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

/** Process the exit code returned by one of the exec functions
 *
 * @param request Current request.
 * @param answer Output string from exec call.
 * @param len length of data in answer.
 * @param status code returned by exec call.
 * @return One of the RLM_MODULE_* values.
 */
static rlm_rcode_t rlm_exec_status2rcode(REQUEST *request, char *answer, size_t len, int status)
{
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

	if (status > RLM_MODULE_NUMCODES) {
		REDEBUG("Program returned invalid code (greater than max rcode) (%i > %i): %s",
			status, RLM_MODULE_NUMCODES, answer);
		goto fail;
	}

	status--;	/* Lets hope no one ever re-enumerates RLM_MODULE_* */

	if (status == RLM_MODULE_FAIL) {
		fail:

		if (len > 0) {
			char *p = &answer[len - 1];

			/*
			 *	Trim off trailing returns
			 */
			while((p > answer) && ((*p == '\r') || (*p == '\n'))) {
				*p-- = '\0';
			}

			log_module_failure_msg(request, "%s", answer);
		}

		return RLM_MODULE_FAIL;
	}

	return status;
}

/*
 *	Do xlat of strings.
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

	/*
	 *	Get the time to wait before killing the child
	 */
	if (!inst->timeout) {
		inst->timeout = EXEC_TIMEOUT;
	}
	if (inst->timeout < 1) {
		cf_log_err(conf, "Timeout '%d' is too small (minimum: 1)", inst->timeout);
		return -1;
	}

	/*
	 *	Blocking a request longer than max_request_time isn't going to help anyone.
	 */
	if (inst->timeout > main_config->max_request_time) {
		cf_log_err(conf, "Timeout '%d' is too large (maximum: %d)",
			   inst->timeout, main_config->max_request_time);
		return -1;
	}

	return 0;
}


/*
 *  Dispatch an exec method
 */
static rlm_rcode_t CC_HINT(nonnull) mod_exec_dispatch(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_exec_t const	*inst = instance;
	rlm_rcode_t		rcode;
	int			status;

	VALUE_PAIR		**input_pairs = NULL, **output_pairs = NULL;
	VALUE_PAIR		*answer = NULL;
	TALLOC_CTX		*ctx = NULL;
	char			out[1024];

	/*
	 *	This needs to be a runtime check for now as
	 *	rlm_exec is often called via xlat instead
	 *	of with a static program.
	 */
	if (!inst->program) {
		REDEBUG("You must specify 'program' to execute");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Decide what input/output the program takes.
	 */
	if (inst->input) {
		input_pairs = radius_list(request, inst->input_list);
		if (!input_pairs) {
			return RLM_MODULE_INVALID;
		}
	}

	if (inst->output) {
		output_pairs = radius_list(request, inst->output_list);
		if (!output_pairs) {
			return RLM_MODULE_INVALID;
		}

		ctx = radius_list_ctx(request, inst->output_list);
	}

	/*
	 *	async changes:
	 *
	 *	- create rlm_exec_thread_t, with inst->el
	 *	  - or for the short term, just use request->el
	 *	- do our own xlat of inst->program
	 *	- call radius_start_program()
	 *	- call event loop to add callback for EVFILT_PROC, NOTE_EXIT | NOTE_EXITSTATUS, pid
	 *	- call event loop to add callback for reading from the pipe
	 *	- return YIELD
	 */

	/*
	 *	This function does it's own xlat of the input program
	 *	to execute.
	 */
	status = radius_exec_program(ctx, out, sizeof(out), inst->output ? &answer : NULL, request,
				     inst->program, inst->input ? *input_pairs : NULL,
				     inst->wait, inst->shell_escape, inst->timeout);
	rcode = rlm_exec_status2rcode(request, out, strlen(out), status);

	/*
	 *	Move the answer over to the output pairs.
	 *
	 *	If we're not waiting, then there are no output pairs.
	 */
	if (inst->output) {
		fr_pair_list_move(request, output_pairs, &answer);
	}
	fr_pair_list_free(&answer);

	return rcode;
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
extern rad_module_t rlm_exec;
rad_module_t rlm_exec = {
	.magic		= RLM_MODULE_INIT,
	.name		= "exec",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_exec_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_exec_dispatch,
		[MOD_AUTHORIZE]		= mod_exec_dispatch,
		[MOD_PREACCT]		= mod_exec_dispatch,
		[MOD_ACCOUNTING]	= mod_exec_dispatch,
		[MOD_PRE_PROXY]		= mod_exec_dispatch,
		[MOD_POST_PROXY]	= mod_exec_dispatch,
		[MOD_POST_AUTH]		= mod_exec_dispatch,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_exec_dispatch,
		[MOD_SEND_COA]		= mod_exec_dispatch
#endif
	},
};
