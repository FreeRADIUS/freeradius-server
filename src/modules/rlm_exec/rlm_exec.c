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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_exec_t {
	char const	*xlat_name;
	int		bare;
	bool		wait;
	char const	*program;
	char const	*input;
	char const	*output;
	pair_lists_t	input_list;
	pair_lists_t	output_list;
	char const	*packet_type;
	unsigned int	packet_code;
	bool		shell_escape;
	uint32_t	timeout;
} rlm_exec_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "wait", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_exec_t, wait), "yes" },
	{ "program", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_exec_t, program), NULL },
	{ "input_pairs", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_exec_t, input), NULL },
	{ "output_pairs", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_exec_t, output), NULL },
	{ "packet_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_exec_t, packet_type), NULL },
	{ "shell_escape", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_exec_t, shell_escape), "yes" },
	{ "timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_exec_t, timeout), NULL },
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

			module_failure_msg(request, "%s", answer);
		}

		return RLM_MODULE_FAIL;
	}

	return status;
}

/*
 *	Do xlat of strings.
 */
static ssize_t exec_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	int		result;
	rlm_exec_t	*inst = instance;
	VALUE_PAIR	**input_pairs = NULL;
	char *p;

	if (!inst->wait) {
		REDEBUG("'wait' must be enabled to use exec xlat");
		*out = '\0';
		return -1;
	}

	if (inst->input_list) {
		input_pairs = radius_list(request, inst->input_list);
		if (!input_pairs) {
			REDEBUG("Failed to find input pairs for xlat");
			*out = '\0';
			return -1;
		}
	}

	/*
	 *	This function does it's own xlat of the input program
	 *	to execute.
	 */
	result = radius_exec_program(request, out, outlen, NULL, request, fmt,  input_pairs ? *input_pairs : NULL,
				     inst->wait, inst->shell_escape, inst->timeout);
	if (result != 0) {
		out[0] = '\0';
		return -1;
	}

	for (p = out; *p != '\0'; p++) {
		if (*p < ' ') *p = ' ';
	}

	return strlen(out);
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
static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	char const *p;
	rlm_exec_t	*inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
		inst->bare = 1;
	}

	xlat_register(inst->xlat_name, exec_xlat, rlm_exec_shell_escape, inst);

	if (inst->input) {
		p = inst->input;
		p += radius_list_name(&inst->input_list, p, PAIR_LIST_UNKNOWN);
		if ((inst->input_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err_cs(conf, "Invalid input list '%s'", inst->input);
			return -1;
		}
	}

	if (inst->output) {
		p = inst->output;
		p += radius_list_name(&inst->output_list, p, PAIR_LIST_UNKNOWN);
		if ((inst->output_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err_cs(conf, "Invalid output list '%s'", inst->output);
			return -1;
		}
	}

	/*
	 *	Sanity check the config.  If we're told to NOT wait,
	 *	then the output pairs must not be defined.
	 */
	if (!inst->wait && (inst->output != NULL)) {
		cf_log_err_cs(conf, "Cannot read output pairs if wait = no");
		return -1;
	}

	/*
	 *	Get the packet type on which to execute
	 */
	if (!inst->packet_type) {
		inst->packet_code = 0;
	} else {
		DICT_VALUE	*dval;

		dval = dict_valbyname(PW_PACKET_TYPE, 0, inst->packet_type);
		if (!dval) {
			cf_log_err_cs(conf, "Unknown packet type %s: See list of VALUEs for Packet-Type in "
				      "share/dictionary", inst->packet_type);
			return -1;
		}
		inst->packet_code = dval->value;
	}

	/*
	 *	Get the time to wait before killing the child
	 */
	if (!inst->timeout) {
		inst->timeout = EXEC_TIMEOUT;
	}
	if (inst->timeout < 1) {
		cf_log_err_cs(conf, "Timeout '%d' is too small (minimum: 1)", inst->timeout);
		return -1;
	}
	/*
	 *	Blocking a request longer than max_request_time isn't going to help anyone.
	 */
	if (inst->timeout > main_config.max_request_time) {
		cf_log_err_cs(conf, "Timeout '%d' is too large (maximum: %d)", inst->timeout, main_config.max_request_time);
		return -1;
	}

	return 0;
}


/*
 *  Dispatch an exec method
 */
static rlm_rcode_t CC_HINT(nonnull) mod_exec_dispatch(void *instance, REQUEST *request)
{
	rlm_exec_t	*inst = (rlm_exec_t *)instance;
	rlm_rcode_t	rcode;
	int		status;

	VALUE_PAIR	**input_pairs = NULL, **output_pairs = NULL;
	VALUE_PAIR	*answer = NULL;
	TALLOC_CTX	*ctx = NULL;
	char		out[1024];

	/*
	 *	We need a program to execute.
	 */
	if (!inst->program) {
		ERROR("rlm_exec (%s): We require a program to execute", inst->xlat_name);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	See if we're supposed to execute it now.
	 */
	if (!((inst->packet_code == 0) || (request->packet->code == inst->packet_code) ||
	      (request->reply->code == inst->packet_code)
#ifdef WITH_PROXY
	      || (request->proxy && (request->proxy->code == inst->packet_code)) ||
	      (request->proxy_reply && (request->proxy_reply->code == inst->packet_code))
#endif
		    )) {
		RDEBUG2("Packet type is not %s. Not executing.", inst->packet_type);

		return RLM_MODULE_NOOP;
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
 *	First, look for Exec-Program && Exec-Program-Wait.
 *
 *	Then, call exec_dispatch.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_exec_t	*inst = (rlm_exec_t *) instance;
	rlm_rcode_t 	rcode;
	int		status;

	char		out[1024];
	bool		we_wait = false;
	VALUE_PAIR	*vp, *tmp;

	vp = fr_pair_find_by_num(request->reply->vps, PW_EXEC_PROGRAM, 0, TAG_ANY);
	if (vp) {
		we_wait = false;
	} else if ((vp = fr_pair_find_by_num(request->reply->vps, PW_EXEC_PROGRAM_WAIT, 0, TAG_ANY)) != NULL) {
		we_wait = true;
	}
	if (!vp) {
		if (!inst->program) {
			return RLM_MODULE_NOOP;
		}

		rcode = mod_exec_dispatch(instance, request);
		goto finish;
	}

	tmp = NULL;
	status = radius_exec_program(request, out, sizeof(out), &tmp, request, vp->vp_strvalue, request->packet->vps,
				     we_wait, inst->shell_escape, inst->timeout);
	rcode = rlm_exec_status2rcode(request, out, strlen(out), status);

	/*
	 *	Always add the value-pairs to the reply.
	 */
	fr_pair_list_move(request->reply, &request->reply->vps, &tmp);
	fr_pair_list_free(&tmp);

	finish:
	switch (rcode) {
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_REJECT:
		request->reply->code = PW_CODE_ACCESS_REJECT;
		break;

	default:
		break;
	}

	return rcode;
}

/*
 *	First, look for Exec-Program && Exec-Program-Wait.
 *
 *	Then, call exec_dispatch.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	rlm_exec_t	*inst = (rlm_exec_t *) instance;
	int		status;

	char		out[1024];
	bool 		we_wait = false;
	VALUE_PAIR	*vp;

	/*
	 *	The "bare" exec module takes care of handling
	 *	Exec-Program and Exec-Program-Wait.
	 */
	if (!inst->bare) {
		return mod_exec_dispatch(instance, request);
	}

	vp = fr_pair_find_by_num(request->reply->vps, PW_EXEC_PROGRAM, 0, TAG_ANY);
	if (vp) {
		we_wait = true;
	} else if ((vp = fr_pair_find_by_num(request->reply->vps, PW_EXEC_PROGRAM_WAIT, 0, TAG_ANY)) != NULL) {
		we_wait = false;
	}
	if (!vp) {
		return RLM_MODULE_NOOP;
	}

	status = radius_exec_program(request, out, sizeof(out), NULL, request, vp->vp_strvalue, request->packet->vps,
				     we_wait, inst->shell_escape, inst->timeout);
	return rlm_exec_status2rcode(request, out, strlen(out), status);
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
	.methods = {
		[MOD_AUTHENTICATE]	= mod_exec_dispatch,
		[MOD_AUTHORIZE]		= mod_exec_dispatch,
		[MOD_PREACCT]		= mod_exec_dispatch,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_PRE_PROXY]		= mod_exec_dispatch,
		[MOD_POST_PROXY]	= mod_exec_dispatch,
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_exec_dispatch,
		[MOD_SEND_COA]		= mod_exec_dispatch
#endif
	},
};
