/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
	int		wait;
	char		*program;
	char		*input;
	char		*output;
	pair_lists_t	input_list;
	pair_lists_t	output_list;
	char		*packet_type;
	unsigned int	packet_code;
	int		shell_escape;
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
	{ "wait", PW_TYPE_BOOLEAN,  offsetof(rlm_exec_t,wait), NULL, "yes" },
	{ "program",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,program), NULL, NULL },
	{ "input_pairs", PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,input), NULL, NULL },
	{ "output_pairs",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,output), NULL, NULL },
	{ "packet_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,packet_type), NULL, NULL },
	{ "shell_escape", PW_TYPE_BOOLEAN,  offsetof(rlm_exec_t,shell_escape), NULL, "yes" },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Do xlat of strings.
 */
static size_t exec_xlat(void *instance, REQUEST *request,
			char const *fmt, char *out, size_t outlen)
{
	int		result;
	rlm_exec_t	*inst = instance;
	VALUE_PAIR	**input_pairs = NULL;
	char *p;
	
	if (inst->input_list) {
		input_pairs = radius_list(request, inst->input_list);
		if (!input_pairs) {
			REDEBUG("Failed to find input pairs for xlat");
			out[0] = '\0';
			return 0;
		}
	}
	
	/*
	 *	FIXME: Do xlat of program name?
	 */
	result = radius_exec_program(fmt, request,
				     inst->wait, out, outlen,
				     input_pairs ? *input_pairs : NULL, NULL, inst->shell_escape);
	if (result != 0) {
		out[0] = '\0';
		return 0;
	}
	
	for (p = out; *p != '\0'; p++) {
		if (*p < ' ') *p = ' ';
	}

	return strlen(out);
}

static char const special[] = "\\'\"`<>|; \t\r\n()[]?#$^&*=";

/*
 *	Escape special characters
 */
static size_t shell_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *inst)
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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	char const *p;
	rlm_exec_t	*inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
		inst->bare = 1;
	}

	xlat_register(inst->xlat_name, exec_xlat, shell_escape, inst);
	
	if (inst->input) {
		p = inst->input;
		inst->input_list = radius_list_name(&p, PAIR_LIST_UNKNOWN);
		if ((inst->input_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err_cs(conf, "Invalid input list '%s'", inst->input);
			return -1;
		}
	}

	if (inst->output) {
		p = inst->output;
		inst->output_list = radius_list_name(&p, PAIR_LIST_UNKNOWN);
		if ((inst->output_list == PAIR_LIST_UNKNOWN) || (*p != '\0')) {
			cf_log_err_cs(conf, "Invalid output list '%s'", inst->output);
			return -1;
		}
	}

	/*
	 *	Sanity check the config.  If we're told to NOT wait,
	 *	then the output pairs must not be defined.
	 */
	if (!inst->wait &&
	    (inst->output != NULL)) {
		cf_log_err_cs(conf, "Cannot read output pairs if "
			      "wait=no");
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
			cf_log_err_cs(conf, "Unknown packet type %s: "
				      "See list of VALUEs for Packet-Type in "
				      "share/dictionary",
				      inst->packet_type);
			return -1;
		}
		inst->packet_code = dval->value;
	}

	return 0;
}


/*
 *  Dispatch an exec method
 */
static rlm_rcode_t exec_dispatch(void *instance, REQUEST *request)
{
	rlm_exec_t *inst = (rlm_exec_t *)instance;
	int result;
	VALUE_PAIR	**input_pairs = NULL, **output_pairs = NULL;
	VALUE_PAIR	*answer = NULL;
	char		out[1024];
	size_t		len;

	/*
	 *	We need a program to execute.
	 */
	if (!inst->program) {
		ERROR("rlm_exec (%s): We require a program to execute",
		       inst->xlat_name);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	See if we're supposed to execute it now.
	 */
	if (!((inst->packet_code == 0) ||
	      (request->packet->code == inst->packet_code) ||
	      (request->reply->code == inst->packet_code)
#ifdef WITH_PROXY
	      || (request->proxy &&
	       (request->proxy->code == inst->packet_code)) ||
	      (request->proxy_reply &&
	       (request->proxy_reply->code == inst->packet_code))
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
	}

	/*
	 *	This function does it's own xlat of the input program
	 *	to execute.
	 *
	 *	FIXME: if inst->program starts with %{, then
	 *	do an xlat ourselves.  This will allow us to do
	 *	program = %{Exec-Program}, which this module
	 *	xlat's into it's string value, and then the
	 *	exec program function xlat's it's string value
	 *	into something else.
	 */
	result = radius_exec_program(inst->program, request,
				     inst->wait, out, sizeof(out),
				     input_pairs ? *input_pairs : NULL, &answer, inst->shell_escape);
	/*
	 *	Write any exec output to module failure message
	 */
	if (*out) {
		/* Trim off returns and newlines */
		len = strlen(out);
		if (out[len - 1] == '\n' || out[len - 1] == '\r') {
			out[len - 1] = '\0';
		}
	}
	
	if (result < 0) {
		module_failure_msg(request, out);

		return RLM_MODULE_FAIL;
	}

	/*
	 *	Move the answer over to the output pairs.
	 *
	 *	If we're not waiting, then there are no output pairs.
	 */
	if (output_pairs) {
		pairmove(request, output_pairs, &answer);
	}
	
	pairfree(&answer);

	if (result == 0) {
		return RLM_MODULE_OK;
	}
	if (result > RLM_MODULE_NUMCODES) {
		module_failure_msg(request, out);

		return RLM_MODULE_FAIL;
	}
	
	return result - 1;
}


/*
 *	First, look for Exec-Program && Exec-Program-Wait.
 *
 *	Then, call exec_dispatch.
 */
static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request)
{
	int result;
	int exec_wait = 0;
	VALUE_PAIR *vp, *tmp;
	rlm_exec_t *inst = (rlm_exec_t *) instance;

	vp = pairfind(request->reply->vps, PW_EXEC_PROGRAM, 0, TAG_ANY);
	if (vp) {
		exec_wait = 0;

	} else if ((vp = pairfind(request->reply->vps, PW_EXEC_PROGRAM_WAIT, 0, TAG_ANY)) != NULL) {
		exec_wait = 1;
	}
	if (!vp) {
		if (!inst->program) return RLM_MODULE_NOOP;
		
		return exec_dispatch(instance, request);
	}

	tmp = NULL;
	result = radius_exec_program(vp->vp_strvalue, request, exec_wait,
				     NULL, 0, request->packet->vps, &tmp,
				     inst->shell_escape);

	/*
	 *	Always add the value-pairs to the reply.
	 */
	pairmove(request->reply, &request->reply->vps, &tmp);
	pairfree(&tmp);

	if (result < 0) {
		REDEBUG("Login incorrect (external check failed)");

		request->reply->code = PW_AUTHENTICATION_REJECT;
		return RLM_MODULE_REJECT;
	}
	if (result > 0) {
		/*
		 *	Reject. radius_exec_program() returns >0
		 *	if the exec'ed program had a non-zero
		 *	exit status.
		 */
		request->reply->code = PW_AUTHENTICATION_REJECT;
		
		REDEBUG("Login incorrect (external check said so)");
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

/*
 *	First, look for Exec-Program && Exec-Program-Wait.
 *
 *	Then, call exec_dispatch.
 */
static  rlm_rcode_t mod_accounting(void *instance, REQUEST *request)
{
	int result;
	int exec_wait = 0;
	VALUE_PAIR *vp;
	rlm_exec_t *inst = (rlm_exec_t *) instance;

	/*
	 *	The "bare" exec module takes care of handling
	 *	Exec-Program and Exec-Program-Wait.
	 */
	if (!inst->bare) return exec_dispatch(instance, request);

	vp = pairfind(request->reply->vps, PW_EXEC_PROGRAM, 0, TAG_ANY);
	if (vp) {
		exec_wait = 0;

	} else if ((vp = pairfind(request->reply->vps, PW_EXEC_PROGRAM_WAIT, 0, TAG_ANY)) != NULL) {
		exec_wait = 1;
	}
	if (!vp) return RLM_MODULE_NOOP;

	result = radius_exec_program(vp->vp_strvalue, request, exec_wait,
				     NULL, 0, request->packet->vps, NULL,
				     inst->shell_escape);
	if (result != 0) {
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
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
module_t rlm_exec = {
	RLM_MODULE_INIT,
	"exec",				/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	sizeof(rlm_exec_t),
	module_config,
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		exec_dispatch,		/* authentication */
		exec_dispatch,		/* authorization */
		exec_dispatch,		/* pre-accounting */
		mod_accounting,	/* accounting */
		NULL,			/* check simul */
		exec_dispatch,		/* pre-proxy */
		exec_dispatch,		/* post-proxy */
		mod_post_auth		/* post-auth */
#ifdef WITH_COA
		, exec_dispatch,
		exec_dispatch
#endif
	},
};
