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
 * @file rlm_rest.c
 * @brief Integrate FreeRADIUS with RESTfull APIs
 *
 * @copyright 2012-2014  Arran Cudbard-Bell <arran.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>
#include "rest.h"

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_ca_file), NULL },
	{ "ca_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_ca_path), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_certificate_file), NULL },
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_private_key_file), NULL },
	{ "private_key_password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, rlm_rest_section_t, tls_private_key_password), NULL },
	{ "random_file", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, tls_random_file), NULL },
	{ "check_cert", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_rest_section_t, tls_check_cert), "yes" },
	{ "check_cert_cn", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_rest_section_t, tls_check_cert_cn), "yes" },

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
	{ "uri", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, uri), ""   },
	{ "method", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, method_str), "GET" },
	{ "body", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, body_str), "none" },
	{ "data", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, data), NULL },

	/* User authentication */
	{ "auth", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, auth_str), "none" },
	{ "username", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, username), NULL },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_section_t, password), NULL },
	{ "require_auth", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_rest_section_t, require_auth), "no" },

	/* Transfer configuration */
	{ "timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_rest_section_t, timeout), "4" },
	{ "chunk", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_rest_section_t, chunk), "0" },

	/* TLS Parameters */
	{ "tls", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) tls_config },

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER module_config[] = {
	{ "connect_uri", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rest_t, connect_uri), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

static int rlm_rest_perform(rlm_rest_t *instance, rlm_rest_section_t *section, void *handle, REQUEST *request,
			    char const *username, char const *password)
{
	ssize_t uri_len;
	char *uri = NULL;

	int ret;

	RDEBUG("Expanding URI components");

	/*
	 *  Build xlat'd URI, this allows REST servers to be specified by
	 *  request attributes.
	 */
	uri_len = rest_uri_build(&uri, instance, request, section->uri);
	if (uri_len <= 0) return -1;

	RDEBUG("Sending HTTP %s to \"%s\"", fr_int2str(http_method_table, section->method, NULL), uri);

	/*
	 *  Configure various CURL options, and initialise the read/write
	 *  context data.
	 */
	ret = rest_request_config(instance, section, request, handle, section->method, section->body,
				  uri, username, password);
	talloc_free(uri);
	if (ret < 0) return -1;

	/*
	 *  Send the CURL request, pre-parse headers, aggregate incoming
	 *  HTTP body data into a single contiguous buffer.
	 */
	ret = rest_request_perform(instance, section, request, handle);
	if (ret < 0) return -1;

	return 0;
}

static void rlm_rest_cleanup(rlm_rest_t *instance, rlm_rest_section_t *section, void *handle)
{
	rest_request_cleanup(instance, section, handle);
};

/*
 *	Simple xlat to read text data from a URL
 */
static ssize_t rest_xlat(void *instance, REQUEST *request,
			 char const *fmt, char *out, size_t freespace)
{
	rlm_rest_t	*inst = instance;
	void		*handle;
	int		hcode;
	int		ret;
	ssize_t		len, outlen = 0;
	char		*uri = NULL;
	char const	*p = fmt, *q;
	char const	*body;
	http_method_t	method;

	/* There are no configurable parameters other than the URI */
	rlm_rest_section_t section = {
		.name = "xlat",
		.method = HTTP_METHOD_GET,
		.body = HTTP_BODY_NONE,
		.body_str = "application/x-www-form-urlencoded",
		.require_auth = false,
		.timeout = 4,
		.force_to = HTTP_BODY_PLAIN
	};
	*out = '\0';

	rad_assert(fmt);

	RDEBUG("Expanding URI components");

	handle = fr_connection_get(inst->conn_pool);
	if (!handle) return -1;

	/*
	 *  Extract the method from the start of the format string (if there is one)
	 */
	method = fr_substr2int(http_method_table, p, HTTP_METHOD_UNKNOWN, -1);
	if (method != HTTP_METHOD_UNKNOWN) {
		section.method = method;
		p += strlen(http_method_table[method].name);
	}

	/*
	 *  Trim whitespace
	 */
	while (isspace(*p) && p++);

	/*
	 *  Unescape parts of xlat'd URI, this allows REST servers to be specified by
	 *  request attributes.
	 */
	len = rest_uri_host_unescape(&uri, instance, request, handle, p);
	if (len <= 0) {
		outlen = -1;
		goto finish;
	}

	/*
	 *  Extract freeform body data (url can't contain spaces)
	 */
	q = strchr(p, ' ');
	if (q && (*++q != '\0')) {
		section.body = HTTP_BODY_CUSTOM_LITERAL;
		section.data = q;
	}

	RDEBUG("Sending HTTP %s to \"%s\"", fr_int2str(http_method_table, section.method, NULL), uri);

	/*
	 *  Configure various CURL options, and initialise the read/write
	 *  context data.
	 *
	 *  @todo We could extract the User-Name and password from the URL string.
	 */
	ret = rest_request_config(instance, &section, request, handle, section.method, section.body,
				  uri, NULL, NULL);
	talloc_free(uri);
	if (ret < 0) return -1;

	/*
	 *  Send the CURL request, pre-parse headers, aggregate incoming
	 *  HTTP body data into a single contiguous buffer.
	 */
	ret = rest_request_perform(instance, &section, request, handle);
	if (ret < 0) return -1;

	hcode = rest_get_handle_code(handle);
	switch (hcode) {
	case 404:
	case 410:
	case 403:
	case 401:
	{
error:
		len = rest_get_handle_data(&body, handle);
		if (len > 0) REDEBUG("%s", body);
		outlen = -1;
		goto finish;
	}
	case 204:
		goto finish;

	default:
		/*
		 *	Attempt to parse content if there was any.
		 */
		if ((hcode >= 200) && (hcode < 300)) {
			break;
		} else if (hcode < 500) {
			outlen = -2;
			goto error;
		} else {
			outlen = -1;
			goto error;
		}
	}

	len = rest_get_handle_data(&body, handle);
	if ((size_t) len >= freespace) {
		REDEBUG("Insufficient space to write HTTP response, needed %zu bytes, have %zu bytes", len + 1,
			freespace);
		outlen = -1;
		goto finish;
	}
	if (len > 0) {
		outlen = len;
		strlcpy(out, body, len + 1);	/* strlcpy takes the size of the buffer */
	}

finish:
	rlm_rest_cleanup(instance, &section, handle);

	fr_connection_release(inst->conn_pool, handle);

	return outlen;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->authorize;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	handle = fr_connection_get(inst->conn_pool);
	if (!handle) return RLM_MODULE_FAIL;

	ret = rlm_rest_perform(instance, section, handle, request, NULL, NULL);
	if (ret < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
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
		ret = rest_response_decode(inst, section, request, handle);
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
			ret = rest_response_decode(inst, section, request, handle);
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

finish:
	rlm_rest_cleanup(instance, section, handle);

	fr_connection_release(inst->conn_pool, handle);

	return rcode;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->authenticate;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	VALUE_PAIR const *username;
	VALUE_PAIR const *password;

	username = request->username;
	if (!request->username) {
		REDEBUG("Can't perform authentication, 'User-Name' attribute not found in the request");

		return RLM_MODULE_INVALID;
	}

	password = request->password;
	if (!password ||
	    (password->da->attr != PW_USER_PASSWORD)) {
		REDEBUG("You set 'Auth-Type = REST' for a request that does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	handle = fr_connection_get(inst->conn_pool);
	if (!handle) return RLM_MODULE_FAIL;

	ret = rlm_rest_perform(instance, section, handle, request, username->vp_strvalue, password->vp_strvalue);
	if (ret < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
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
		ret = rest_response_decode(inst, section, request, handle);
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
			ret = rest_response_decode(inst, section, request, handle);
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

finish:
	rlm_rest_cleanup(instance, section, handle);

	fr_connection_release(inst->conn_pool, handle);

	return rcode;
}

/*
 *	Send accounting info to a REST API endpoint
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, UNUSED REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->accounting;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	handle = fr_connection_get(inst->conn_pool);
	if (!handle) return RLM_MODULE_FAIL;

	ret = rlm_rest_perform(inst, section, handle, request, NULL, NULL);
	if (ret < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	if (hcode >= 500) {
		rcode = RLM_MODULE_FAIL;
	} else if (hcode == 204) {
		rcode = RLM_MODULE_OK;
	} else if ((hcode >= 200) && (hcode < 300)) {
		ret = rest_response_decode(inst, section, request, handle);
		if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
		else if (ret == 0) rcode = RLM_MODULE_OK;
		else		   rcode = RLM_MODULE_UPDATED;
	} else {
		rcode = RLM_MODULE_INVALID;
	}

finish:
	rlm_rest_cleanup(inst, section, handle);

	fr_connection_release(inst->conn_pool, handle);

	return rcode;
}

/*
 *	Send post-auth info to a REST API endpoint
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, UNUSED REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->post_auth;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	handle = fr_connection_get(inst->conn_pool);
	if (!handle) return RLM_MODULE_FAIL;

	ret = rlm_rest_perform(inst, section, handle, request, NULL, NULL);
	if (ret < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	hcode = rest_get_handle_code(handle);
	if (hcode >= 500) {
		rcode = RLM_MODULE_FAIL;
	} else if (hcode == 204) {
		rcode = RLM_MODULE_OK;
	} else if ((hcode >= 200) && (hcode < 300)) {
		ret = rest_response_decode(inst, section, request, handle);
		if (ret < 0) 	   rcode = RLM_MODULE_FAIL;
		else if (ret == 0) rcode = RLM_MODULE_OK;
		else		   rcode = RLM_MODULE_UPDATED;
	} else {
		rcode = RLM_MODULE_INVALID;
	}

finish:
	rlm_rest_cleanup(inst, section, handle);

	fr_connection_release(inst->conn_pool, handle);

	return rcode;
}

static int parse_sub_section(CONF_SECTION *parent, rlm_rest_section_t *config, rlm_components_t comp)
{
	CONF_SECTION *cs;

	char const *name = section_type_value[comp].section;

	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		/* TODO: Should really setup section with default values */
		return 0;
	}

	if (cf_section_parse(cs, config, section_config) < 0) {
		return -1;
	}

	/*
	 *  Add section name (Maybe add to headers later?).
	 */
	config->name = name;

	/*
	 *  Sanity check
	 */
	 if ((config->username && !config->password) || (!config->username && config->password)) {
		cf_log_err_cs(cs, "'username' and 'password' must both be set or both be absent");

		return -1;
	 }

	/*
	 *  Convert HTTP method auth and body type strings into their integer equivalents.
	 */
	config->auth = fr_str2int(http_auth_table, config->auth_str, HTTP_AUTH_UNKNOWN);
	if (config->auth == HTTP_AUTH_UNKNOWN) {
		cf_log_err_cs(cs, "Unknown HTTP auth type '%s'", config->auth_str);

		return -1;
	} else if ((config->auth != HTTP_AUTH_NONE) && !http_curl_auth[config->auth]) {
		cf_log_err_cs(cs, "Unsupported HTTP auth type \"%s\", check libcurl version, OpenSSL build "
			      "configuration, then recompile this module", config->auth_str);

		return -1;
	}

	config->method = fr_str2int(http_method_table, config->method_str, HTTP_METHOD_CUSTOM);

	/*
	 *  We don't have any custom user data, so we need to select the right encoder based
	 *  on the body type.
	 *
	 *  To make this slightly more/less confusing, we accept both canonical body_types,
	 *  and content_types.
	 */
	if (!config->data) {
		config->body = fr_str2int(http_body_type_table, config->body_str, HTTP_BODY_UNKNOWN);
		if (config->body == HTTP_BODY_UNKNOWN) {
			config->body = fr_str2int(http_content_type_table, config->body_str, HTTP_BODY_UNKNOWN);
		}

		if (config->body == HTTP_BODY_UNKNOWN) {
			cf_log_err_cs(cs, "Unknown HTTP body type '%s'", config->body_str);
			return -1;
		}

		switch (http_body_type_supported[config->body]) {
		case HTTP_BODY_UNSUPPORTED:
			cf_log_err_cs(cs, "Unsupported HTTP body type \"%s\", please submit patches",
				      config->body_str);
			return -1;

		case HTTP_BODY_INVALID:
			cf_log_err_cs(cs, "Invalid HTTP body type.  \"%s\" is not a valid web API data "
				      "markup format", config->body_str);
			return -1;

		default:
			break;
		}
	/*
	 *  We have custom body data so we set HTTP_BODY_CUSTOM_XLAT, but also need to try and
	 *  figure out what content-type to use. So if they've used the canonical form we
	 *  need to convert it back into a proper HTTP content_type value.
	 */
	} else {
		http_body_type_t body;

		config->body = HTTP_BODY_CUSTOM_XLAT;

		body = fr_str2int(http_body_type_table, config->body_str, HTTP_BODY_UNKNOWN);
		if (body != HTTP_BODY_UNKNOWN) {
			config->body_str = fr_int2str(http_content_type_table, body, config->body_str);
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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_rest_t *inst = instance;
	char const *xlat_name;

	xlat_name = cf_section_name2(conf);
	if (!xlat_name) {
		xlat_name = cf_section_name1(conf);
	}

	inst->xlat_name = xlat_name;

	/*
	 *	Register the rest xlat function
	 */
	xlat_register(inst->xlat_name, rest_xlat, rest_uri_escape, inst);

	/*
	 *	Parse sub-section configs.
	 */
	if (
		(parse_sub_section(conf, &inst->authorize, RLM_COMPONENT_AUTZ) < 0) ||
		(parse_sub_section(conf, &inst->authenticate, RLM_COMPONENT_AUTH) < 0) ||
		(parse_sub_section(conf, &inst->accounting, RLM_COMPONENT_ACCT) < 0) ||

/* @todo add behaviour for checksimul */
/*		(parse_sub_section(conf, &inst->checksimul, RLM_COMPONENT_SESS) < 0) || */
		(parse_sub_section(conf, &inst->post_auth, RLM_COMPONENT_POST_AUTH) < 0))
	{
		return -1;
	}

	/*
	 *	Initialise REST libraries.
	 */
	if (rest_init(inst) < 0) {
		return -1;
	}

	inst->conn_pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, mod_conn_alive, NULL);
	if (!inst->conn_pool) {
		return -1;
	}

	return 0;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	rlm_rest_t *inst = instance;

	fr_connection_pool_delete(inst->conn_pool);

	xlat_unregister(inst->xlat_name, rest_xlat, instance);

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
	sizeof(rlm_rest_t),
	module_config,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		mod_authenticate,	/* authentication */
		mod_authorize,		/* authorization */
		NULL,			/* preaccounting */
		mod_accounting,		/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		mod_post_auth		/* post-auth */
	},
};
