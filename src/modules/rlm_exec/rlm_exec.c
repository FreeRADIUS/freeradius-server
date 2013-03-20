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
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_exec_t {
	const char		*xlat_name;
	int		bare;
	int		wait;
	char		*program;
	char		*input;
	char		*output;
	char	*packet_type;
	unsigned int	packet_code;
	int	shell_escape;
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
	  offsetof(rlm_exec_t,input), NULL, "request" },
	{ "output_pairs",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,output), NULL, NULL },
	{ "packet_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_exec_t,packet_type), NULL, NULL },
	{ "shell_escape", PW_TYPE_BOOLEAN,  offsetof(rlm_exec_t,shell_escape), NULL, "yes" },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Decode the configuration file string to a pointer to
 *	a value-pair list in the REQUEST data structure.
 */
static VALUE_PAIR **decode_string(REQUEST *request, const char *string)
{
	if (!string) return NULL;

	/*
	 *	Yuck.  We need a 'switch' over character strings
	 *	in C.
	 */
	if (strcmp(string, "request") == 0) {
		return &request->packet->vps;
	}

	if (strcmp(string, "reply") == 0) {
		if (!request->reply) return NULL;

		return &request->reply->vps;
	}

#ifdef WITH_PROXY
	if (strcmp(string, "proxy-request") == 0) {
		if (!request->proxy) return NULL;

		return &request->proxy->vps;
	}

	if (strcmp(string, "proxy-reply") == 0) {
		if (!request->proxy_reply) return NULL;

		return &request->proxy_reply->vps;
	}
#endif

	if (strcmp(string, "config") == 0) {
		return &request->config_items;
	}

	if (strcmp(string, "none") == 0) {
		return NULL;
	}

	return NULL;
}


/*
 *	Do xlat of strings.
 */
static size_t exec_xlat(void *instance, REQUEST *request,
		     const char *fmt, char *out, size_t outlen)
{
	int		result;
	rlm_exec_t	*inst = instance;
	VALUE_PAIR	**input_pairs;
	char *p;

	
	input_pairs = decode_string(request, inst->input);
	if (!input_pairs) {
		radlog(L_ERR, "rlm_exec (%s): Failed to find input pairs"
		       " for xlat", inst->xlat_name);
		out[0] = '\0';
		return 0;
	}

	/*
	 *	FIXME: Do xlat of program name?
	 */
	RDEBUG2("Executing %s", fmt);
	result = radius_exec_program(fmt, request, inst->wait,
				     out, outlen, *input_pairs, NULL, inst->shell_escape);
	RDEBUG2("result %d", result);
	if (result != 0) {
		out[0] = '\0';
		return 0;
	}

	for (p = out; *p != '\0'; p++) {
		if (*p < ' ') *p = ' ';
	}

	return strlen(out);
}


/*
 *	Detach an instance and free it's data.
 */
static int mod_detach(void *instance)
{
	rlm_exec_t	*inst = instance;

	if (inst->xlat_name) {
		xlat_unregister(inst->xlat_name, exec_xlat, instance);
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
static int mod_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_exec_t	*inst;
	const char	*xlat_name;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = inst = talloc_zero(conf, rlm_exec_t);
	if (!inst) return -1;
	
	xlat_name = cf_section_name2(conf);
	if (!xlat_name) {
		xlat_name = cf_section_name1(conf);
		inst->bare = 1;
	}
	if (xlat_name) {
		inst->xlat_name = xlat_name;
		xlat_register(xlat_name, exec_xlat, inst);
	}

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		radlog(L_ERR, "rlm_exec (%s): Failed parsing the "
		       "configuration", xlat_name);
		mod_detach(inst);
		return -1;
	}

	/*
	 *	No input pairs defined.  Why are we executing a program?
	 */
	if (!inst->input) {
		radlog(L_ERR, "rlm_exec (%s): Must define input pairs for "
		       "external program", xlat_name);
		mod_detach(inst);
		return -1;
	}

	/*
	 *	Sanity check the config.  If we're told to NOT wait,
	 *	then the output pairs must not be defined.
	 */
	if (!inst->wait &&
	    (inst->output != NULL)) {
		radlog(L_ERR, "rlm_exec (%s): Cannot read output pairs if "
			      "wait=no", xlat_name);
		mod_detach(inst);
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
			radlog(L_ERR, "rlm_exec (%s): Unknown packet type %s: "
			       "See list of VALUEs for Packet-Type in "
			       "share/dictionary", xlat_name,
			       inst->packet_type);
			mod_detach(inst);
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
	rlm_exec_t *inst = (rlm_exec_t *) instance;
	int result;
	VALUE_PAIR	**input_pairs, **output_pairs;
	VALUE_PAIR	*answer = NULL;
	char		msg[1024];
	size_t		len;

	/*
	 *	We need a program to execute.
	 */
	if (!inst->program) {
		radlog(L_ERR, "rlm_exec (%s): We require a program to execute",
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
		RDEBUG2("Packet type is not %s.  Not executing.",
		       inst->packet_type);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Decide what input/output the program takes.
	 */
	input_pairs = decode_string(request, inst->input);
	output_pairs = decode_string(request, inst->output);

	if (!input_pairs) {
		RDEBUG2W("Possible parse error in %s",
			inst->input);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	It points to the attribute list, but the attribute
	 *	list is empty.
	 */
	if (!*input_pairs) {
		RDEBUG2W("Input pairs are empty.  No attributes will be passed to the script");
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
				     inst->wait, msg, sizeof(msg),
				     *input_pairs, &answer, inst->shell_escape);
	if (result < 0) {
		radlog(L_ERR, "rlm_exec (%s): External script failed",
		       inst->xlat_name);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Move the answer over to the output pairs.
	 *
	 *	If we're not waiting, then there are no output pairs.
	 */
	if (output_pairs) pairmove(output_pairs, &answer);

	pairfree(&answer);

	if (result == 0) {
		return RLM_MODULE_OK;
	}
	if (result > RLM_MODULE_NUMCODES) {
		return RLM_MODULE_FAIL;
	}
	
	/*
	 *	Write any exec output to module failure message
	 */
	if (*msg) {
		/* Trim off returns and newlines */
		len = strlen(msg);
		if (msg[len - 1] == '\n' || msg[len - 1] == '\r') {
			msg[len - 1] = '\0';
		}
		
		RDEBUGE("%s", msg);
	}
	
	return result-1;
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
	pairmove(&request->reply->vps, &tmp);
	pairfree(&tmp);

	if (result < 0) {
		RDEBUGE("Login incorrect (external check failed)");

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
		
		RDEBUGE("Login incorrect (external check said so)");
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
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
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
