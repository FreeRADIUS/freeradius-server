/*
 * rlm_rest.c
 *
 * Version:	$Id$
 *
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
 * Copyright 2012  Arran Cudbard-Bell <arran.cudbardb@freeradius.org>>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/token.h>

#include "rest.h"

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	{ "cacertfile", PW_TYPE_FILENAME,
	  offsetof(rlm_rest_section_t,tls_cacertfile), NULL, NULL},
	{ "cacertdir", PW_TYPE_FILENAME,
	  offsetof(rlm_rest_section_t,tls_cacertdir), NULL, NULL},
	{ "certfile", PW_TYPE_FILENAME,
	  offsetof(rlm_rest_section_t,tls_certfile), NULL, NULL},
	{ "keyfile", PW_TYPE_FILENAME,
	  offsetof(rlm_rest_section_t,tls_keyfile), NULL, NULL },
	{ "keypassword", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rest_section_t, tls_keypassword), NULL, NULL },
	{ "randfile", PW_TYPE_STRING_PTR, /* OK if it changes on HUP */
	  offsetof(rlm_rest_section_t,tls_randfile), NULL, NULL },
	{ "verify_cert", PW_TYPE_BOOLEAN,
	  offsetof(rlm_rest_section_t, tls_verify_cert), NULL, "yes" },
	{ "verify_cert_cn", PW_TYPE_BOOLEAN,
	  offsetof(rlm_rest_section_t, tls_verify_cert_cn), NULL, "yes" },
	
	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER section_config[] = {
	{ "uri", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_section_t, uri), 	   NULL, ""  },
	{ "method", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_section_t, method_str), NULL, "GET"   },
	{ "body", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_section_t, body_str),   NULL, "post"  },
	 
	/* User authentication */
	{ "auth", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_section_t, auth_str),   NULL, "none"  },
	{ "username", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_section_t, username),   NULL, ""  },
	{ "password", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_section_t, password),   NULL, ""  },
	{ "require_auth", PW_TYPE_BOOLEAN,
	 offsetof(rlm_rest_section_t, require_auth), NULL, "no"},

	/* Transfer configuration */
	{ "timeout", PW_TYPE_INTEGER, 
	 offsetof(rlm_rest_section_t, timeout),    NULL, "0" },
	{ "chunk", PW_TYPE_INTEGER,
	 offsetof(rlm_rest_section_t, chunk), 	   NULL, "0" },

	/* TLS Parameters */
	{ "tls", PW_TYPE_SUBSECTION, 0, NULL, (const void *) tls_config },

	{ NULL, -1, 0, NULL, NULL }
};
 
static const CONF_PARSER module_config[] = {
	{ "connect_uri", PW_TYPE_STRING_PTR,
	 offsetof(rlm_rest_t, connect_uri), NULL, "http://localhost/" },

	{ NULL, -1, 0, NULL, NULL }
};

static int rlm_rest_perform (rlm_rest_t *instance, rlm_rest_section_t *section,
			     void *handle, REQUEST *request)
{
	size_t uri_len;
	char uri[REST_URI_MAX_LEN];
	
	int ret;
	
	RDEBUG("Expanding URI components");
	/*
	 *	Build xlat'd URI, this allows REST servers to be specified by
	 *	request attributes.
	 */
	uri_len = rest_uri_build(instance, section, request, uri, sizeof(uri));
	if (uri_len <= 0) return -1;

	RDEBUG("Sending HTTP %s to \"%s\"",
		fr_int2str(http_method_table, section->method, NULL),
		uri);

	/*
	 *	Configure various CURL options, and initialise the read/write
	 *	context data.
	 */
	ret = rest_request_config(instance, section, request,
		handle,
		section->method,
		section->body,
		uri);
	if (ret <= 0) return -1;

	/*
	 *	Send the CURL request, pre-parse headers, aggregate incoming
	 *	HTTP body data into a single contiguous buffer.
	 */
	ret = rest_request_perform(instance, section, handle);
	if (ret <= 0) return -1;

	return 1;
}

static void rlm_rest_cleanup (rlm_rest_t *instance, rlm_rest_section_t *section,
			      void *handle)
{
	rest_request_cleanup(instance, section, handle);
};

static int parse_sub_section(CONF_SECTION *parent, 
	 		     rlm_rest_t *instance, rlm_rest_section_t *config,
	 		     rlm_components_t comp)
{
	CONF_SECTION *cs;

	const char *name = section_type_value[comp].section;

	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		/* TODO: Should really setup section with default values */
		return 0;
	}
	cf_section_parse(cs, config, section_config);

	/*
	 *	Add section name (Maybe add to headers later?).
	 */
	config->name = name;

	/*
	 *	Convert HTTP method auth and body type strings into their
	 *	integer equivalents.
	 */
	config->auth = fr_str2int(http_auth_table, config->auth_str,
				  HTTP_AUTH_UNKNOWN);
				  
	if (config->auth == HTTP_AUTH_UNKNOWN) {
		radlog(L_ERR, "rlm_rest (%s): Unknown HTTP auth type \"%s\"",
		       instance->xlat_name, config->auth_str);
		return -1;	
	}
	
	if (!http_curl_auth[config->auth]) {
		radlog(L_ERR, "rlm_rest (%s): Unsupported HTTP auth type \"%s\""
		       ", check libcurl version, OpenSSL build configuration," 
		       " then recompile this module",
		       instance->xlat_name, config->auth_str);
		return -1;
	}
				    
	config->method = fr_str2int(http_method_table, config->method_str,
				    HTTP_METHOD_CUSTOM);

	config->body = fr_str2int(http_body_type_table, config->body_str,
				  HTTP_BODY_UNKNOWN);

	if (config->body == HTTP_BODY_UNKNOWN) {
		radlog(L_ERR, "rlm_rest (%s): Unknown HTTP body type \"%s\"",
		       instance->xlat_name, config->body_str);
		return -1;
	}

	if (http_body_type_supported[config->body] == HTTP_BODY_UNSUPPORTED) {
		radlog(L_ERR, "rlm_rest (%s): Unsupported HTTP body type \"%s\""
		       ", please submit patches", instance->xlat_name,
		       config->body_str);
		return -1;
	}

	return 1;
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
static int rlm_rest_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_rest_t *data;
	const char *xlat_name;

	/*
	 *	Allocate memory for instance data.
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) {
		xlat_name = cf_section_name1(conf);
	}

	data->xlat_name = xlat_name;

	/*
	 *	Parse sub-section configs.
	 */
	if (
		(parse_sub_section(conf, data, &data->authorize,
				   RLM_COMPONENT_AUTZ) < 0) ||
		(parse_sub_section(conf, data, &data->authenticate,
				   RLM_COMPONENT_AUTH) < 0) ||
		(parse_sub_section(conf, data, &data->accounting,
				   RLM_COMPONENT_ACCT) < 0) ||
		(parse_sub_section(conf, data, &data->checksimul,
				   RLM_COMPONENT_SESS) < 0) ||
		(parse_sub_section(conf, data, &data->postauth,
				   RLM_COMPONENT_POST_AUTH) < 0))
	{
		return -1;
	}

	/*
	 *	Initialise REST libraries.
	 */
	if (!rest_init(data)) {
		return -1;
	}

	data->conn_pool = fr_connection_pool_init(conf, data,
						  rest_socket_create,
						  rest_socket_alive,
						  rest_socket_delete);

	if (!data->conn_pool) {
		return -1;
	}

	*instance = data;

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int rlm_rest_authorize(void *instance, REQUEST *request)
{
	rlm_rest_t *my_instance = instance;
	rlm_rest_section_t *section = &my_instance->authorize;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	handle = fr_connection_get(my_instance->conn_pool);
	if (!handle) return RLM_MODULE_FAIL;

	ret = rlm_rest_perform(instance, section, handle, request);
	if (ret < 0) { 
		rcode = RLM_MODULE_FAIL;
		goto end;
	}

	hcode = rest_get_handle_code(handle);

	switch (hcode) {
		case 404:
		case 410:
			rcode = RLM_MODULE_NOTFOUND;
			break;
		case 403:
			rcode = RLM_MODULE_USERLOCK;
			break;
		case 401:
			/*
			 *	Attempt to parse content if there was any.
			 */
			ret = rest_request_decode(my_instance, section,
						  request, handle);
			if (ret < 0) {
				rcode = RLM_MODULE_FAIL;
				break;
			}

			rcode = RLM_MODULE_REJECT;
			break;
		case 204:
			rcode = RLM_MODULE_OK;
			break;
		default:
			/*
			 *	Attempt to parse content if there was any.
			 */
			if ((hcode >= 200) && (hcode < 300)) {
				ret = rest_request_decode(my_instance, section,
							  request, handle);
				if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
				else if (ret == 0) rcode = RLM_MODULE_OK;
				else		   rcode = RLM_MODULE_UPDATED;
				break;
			} else if (hcode < 500) {
				rcode = RLM_MODULE_INVALID;
			} else {
				rcode = RLM_MODULE_FAIL;
			}
	}

	end:

	rlm_rest_cleanup(instance, section, handle);

	fr_connection_release(my_instance->conn_pool, handle);

	return rcode;
}

/*
 *	Authenticate the user with the given password.
 */
static int rlm_rest_authenticate(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static int rlm_rest_accounting(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static int rlm_rest_checksimul(void *instance, REQUEST *request)
{
	instance = instance;

	request->simul_count=0;

	return RLM_MODULE_OK;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int rlm_rest_detach(void *instance)
{
	rlm_rest_t *my_instance = instance;

	fr_connection_pool_delete(my_instance->conn_pool);

	free(my_instance);

	/* Free any memory used by libcurl */
	rest_cleanup();

	return 0;
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
module_t rlm_rest = {
	RLM_MODULE_INIT,
	"rlm_rest",
	RLM_TYPE_THREAD_SAFE,		/* type */
	rlm_rest_instantiate,		/* instantiation */
	rlm_rest_detach,		/* detach */
	{
		rlm_rest_authenticate,	/* authentication */
		rlm_rest_authorize,	/* authorization */
		NULL,			/* preaccounting */
		rlm_rest_accounting,	/* accounting */
		rlm_rest_checksimul,	/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
