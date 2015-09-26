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
	{ FR_CONF_OFFSET("ca_file", PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_ca_file) },
	{ FR_CONF_OFFSET("ca_path", PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_ca_path) },
	{ FR_CONF_OFFSET("certificate_file", PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_certificate_file) },
	{ FR_CONF_OFFSET("private_key_file", PW_TYPE_FILE_INPUT, rlm_rest_section_t, tls_private_key_file) },
	{ FR_CONF_OFFSET("private_key_password", PW_TYPE_STRING | PW_TYPE_SECRET, rlm_rest_section_t, tls_private_key_password) },
	{ FR_CONF_OFFSET("random_file", PW_TYPE_STRING, rlm_rest_section_t, tls_random_file) },
	{ FR_CONF_OFFSET("check_cert", PW_TYPE_BOOLEAN, rlm_rest_section_t, tls_check_cert), .dflt = "yes" },
	{ FR_CONF_OFFSET("check_cert_cn", PW_TYPE_BOOLEAN, rlm_rest_section_t, tls_check_cert_cn), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
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
	{ FR_CONF_OFFSET("uri", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rest_section_t, uri), .dflt = "" },
	{ FR_CONF_OFFSET("proxy", PW_TYPE_STRING, rlm_rest_section_t, proxy) },
	{ FR_CONF_OFFSET("method", PW_TYPE_STRING, rlm_rest_section_t, method_str), .dflt = "GET" },
	{ FR_CONF_OFFSET("body", PW_TYPE_STRING, rlm_rest_section_t, body_str), .dflt = "none" },
	{ FR_CONF_OFFSET("data", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rest_section_t, data) },
	{ FR_CONF_OFFSET("force_to", PW_TYPE_STRING, rlm_rest_section_t, force_to_str) },

	/* User authentication */
	{ FR_CONF_OFFSET("auth", PW_TYPE_STRING, rlm_rest_section_t, auth_str), .dflt = "none" },
	{ FR_CONF_OFFSET("username", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rest_section_t, username) },
	{ FR_CONF_OFFSET("password", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rest_section_t, password) },
	{ FR_CONF_OFFSET("require_auth", PW_TYPE_BOOLEAN, rlm_rest_section_t, require_auth), .dflt = "no" },

	/* Transfer configuration */
	{ FR_CONF_OFFSET("timeout", PW_TYPE_TIMEVAL, rlm_rest_section_t, timeout_tv), .dflt = "4.0" },
	{ FR_CONF_OFFSET("chunk", PW_TYPE_INTEGER, rlm_rest_section_t, chunk), .dflt = "0" },

	/* TLS Parameters */
	{ FR_CONF_POINTER("tls", PW_TYPE_SUBSECTION, NULL), .dflt = (void const *) tls_config },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("connect_uri", PW_TYPE_STRING, rlm_rest_t, connect_uri) },
	{ FR_CONF_DEPRECATED("connect_timeout", PW_TYPE_TIMEVAL, rlm_rest_t, connect_timeout) },
	{ FR_CONF_OFFSET("connect_proxy", PW_TYPE_STRING, rlm_rest_t, connect_proxy) },
	CONF_PARSER_TERMINATOR
};

static int rlm_rest_perform(rlm_rest_t *instance, rlm_rest_section_t *section, void *handle, REQUEST *request,
			    char const *username, char const *password)
{
	ssize_t	uri_len;
	char	*uri = NULL;

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

	{
		TALLOC_CTX	*ctx;
		VALUE_PAIR	**list;
		int		code;
		value_data_t	value;

		code = rest_get_handle_code(handle);

		RINDENT();
		RDEBUG2("&REST-HTTP-Code := %i", code);
		REXDENT();

		value.length = sizeof(value.integer);
		value.integer = code;

		/*
		 *	Find the reply list, and appropriate context in the
		 *	current request.
		 */
		RADIUS_LIST_AND_CTX(ctx, list, request, REQUEST_CURRENT, PAIR_LIST_REQUEST);
		if (!list || (fr_pair_update_by_num(ctx, list, PW_REST_HTTP_STATUS_CODE, 0,
						    TAG_ANY, PW_TYPE_INTEGER, &value) < 0)) {
			REDEBUG("Failed updating &REST-HTTP-Code");
			return -1;
		}
	}

	return 0;
}

static void rlm_rest_cleanup(rlm_rest_t const *instance, rlm_rest_section_t *section, void *handle)
{
	rest_request_cleanup(instance, section, handle);
}

static ssize_t jsonquote_xlat(char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      UNUSED REQUEST *request, char const *fmt)
{
	char const *p;
	char *out_p = *out;
	size_t freespace = outlen;
	size_t len;

	for (p = fmt; *p != '\0'; p++) {
		/* Indicate truncation */
		if (freespace < 3) {
			*out_p = '\0';
			return outlen + 1;
		}

		if (*p == '"') {
			*out_p++ = '\\';
			*out_p++ = '"';
			freespace -= 2;
		} else if (*p == '\\') {
			*out_p++ = '\\';
			*out_p++ = '\\';
			freespace -= 2;
		} else if (*p == '/') {
			*out_p++ = '\\';
			*out_p++ = '/';
			freespace -= 2;
		} else if (*p >= ' ') {
			*out_p++ = *p;
			freespace--;
		/*
		 *	Unprintable chars
		 */
		} else {
			*out_p++ = '\\';
			freespace--;

			switch (*p) {
			case '\b':
				*out_p++ = 'b';
				freespace--;
				break;

			case '\f':
				*out_p++ = 'f';
				freespace--;
				break;

			case '\n':
				*out_p++ = 'b';
				freespace--;
				break;

			case '\r':
				*out_p++ = 'r';
				freespace--;
				break;

			case '\t':
				*out_p++ = 't';
				freespace--;
				break;

			default:
				len = snprintf(out_p, freespace, "u%04X", *p);
				if (is_truncated(len, freespace)) return (outlen - freespace) + len;
				out_p += len;
				freespace -= len;
			}
		}
	}

	*out_p = '\0';

	return outlen - freespace;
}
/*
 *	Simple xlat to read text data from a URL
 */
static ssize_t rest_xlat(char **out, UNUSED size_t outlen,
			 void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	rlm_rest_t const	*inst = mod_inst;
	void			*handle;
	int			hcode;
	int			ret;
	ssize_t			len, slen = 0;
	char			*uri = NULL;
	char const		*p = fmt, *q;
	char const		*body;
	http_method_t		method;

	rad_assert(*out == NULL);

	/* There are no configurable parameters other than the URI */
	rlm_rest_section_t section = {
		.name = "xlat",
		.method = HTTP_METHOD_GET,
		.body = HTTP_BODY_NONE,
		.body_str = "application/x-www-form-urlencoded",
		.require_auth = false,
		.force_to = HTTP_BODY_PLAIN
	};

	rad_assert(fmt);

	RDEBUG("Expanding URI components");

	handle = fr_connection_get(inst->pool);
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
	len = rest_uri_host_unescape(&uri, mod_inst, request, handle, p);
	if (len <= 0) {
		slen = -1;
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
	ret = rest_request_config(mod_inst, &section, request, handle, section.method, section.body,
				  uri, NULL, NULL);
	talloc_free(uri);
	if (ret < 0) return -1;

	/*
	 *  Send the CURL request, pre-parse headers, aggregate incoming
	 *  HTTP body data into a single contiguous buffer.
	 */
	ret = rest_request_perform(mod_inst, &section, request, handle);
	if (ret < 0) return -1;

	hcode = rest_get_handle_code(handle);
	switch (hcode) {
	case 404:
	case 410:
	case 403:
	case 401:
	{
		slen = -1;
error:
		rest_response_error(request, handle);
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
			slen = -2;
			goto error;
		} else {
			slen = -1;
			goto error;
		}
	}

	len = rest_get_handle_data(&body, handle);
	if (len > 0) {
		*out = talloc_bstrndup(request, body, len);
		slen = len;
	}

finish:
	rlm_rest_cleanup(mod_inst, &section, handle);

	fr_connection_release(inst->pool, handle);

	return slen;
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

	if (!section->name) return RLM_MODULE_NOOP;

	handle = fr_connection_get(inst->pool);
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
	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_USERLOCK:
		rest_response_error(request, handle);
		break;

	default:
		break;
	}

	rlm_rest_cleanup(instance, section, handle);

	fr_connection_release(inst->pool, handle);

	return rcode;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->authenticate;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	VALUE_PAIR const *username;
	VALUE_PAIR const *password;

	if (!section->name) return RLM_MODULE_NOOP;

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

	handle = fr_connection_get(inst->pool);
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
	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_USERLOCK:
		rest_response_error(request, handle);
		break;

	default:
		break;
	}

	rlm_rest_cleanup(instance, section, handle);

	fr_connection_release(inst->pool, handle);

	return rcode;
}

/*
 *	Send accounting info to a REST API endpoint
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->accounting;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	if (!section->name) return RLM_MODULE_NOOP;

	handle = fr_connection_get(inst->pool);
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
	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
		rest_response_error(request, handle);
		break;

	default:
		break;
	}

	rlm_rest_cleanup(inst, section, handle);

	fr_connection_release(inst->pool, handle);

	return rcode;
}

/*
 *	Send post-auth info to a REST API endpoint
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_rest_t *inst = instance;
	rlm_rest_section_t *section = &inst->post_auth;

	void *handle;
	int hcode;
	int rcode = RLM_MODULE_OK;
	int ret;

	if (!section->name) return RLM_MODULE_NOOP;

	handle = fr_connection_get(inst->pool);
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
	switch (rcode) {
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
		rest_response_error(request, handle);
		break;

	default:
		break;
	}

	rlm_rest_cleanup(inst, section, handle);

	fr_connection_release(inst->pool, handle);

	return rcode;
}

static int parse_sub_section(CONF_SECTION *parent, rlm_rest_section_t *config, rlm_components_t comp)
{
	CONF_SECTION *cs;

	char const *name = section_type_value[comp].section;

	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		config->name = NULL;
		return 0;
	}

	if (cf_section_parse(cs, config, section_config) < 0) {
		config->name = NULL;
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
	config->timeout = ((config->timeout_tv.tv_usec * 1000) + (config->timeout_tv.tv_sec / 1000));

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

		case HTTP_BODY_UNAVAILABLE:
			cf_log_err_cs(cs, "Unavailable HTTP body type.  \"%s\" is not available in this "
				      "build", config->body_str);
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

	if (config->force_to_str) {
		config->force_to = fr_str2int(http_body_type_table, config->force_to_str, HTTP_BODY_UNKNOWN);
		if (config->force_to == HTTP_BODY_UNKNOWN) {
			config->force_to = fr_str2int(http_content_type_table, config->force_to_str, HTTP_BODY_UNKNOWN);
		}

		if (config->force_to == HTTP_BODY_UNKNOWN) {
			cf_log_err_cs(cs, "Unknown forced response body type '%s'", config->force_to_str);
			return -1;
		}

		switch (http_body_type_supported[config->force_to]) {
		case HTTP_BODY_UNSUPPORTED:
			cf_log_err_cs(cs, "Unsupported forced response body type \"%s\", please submit patches",
				      config->force_to_str);
			return -1;

		case HTTP_BODY_INVALID:
			cf_log_err_cs(cs, "Invalid HTTP forced response body type.  \"%s\" is not a valid web API data "
				      "markup format", config->force_to_str);
			return -1;

		default:
			break;
		}
	}

	return 0;
}


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_rest_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);

	/*
	 *	Register the rest xlat function
	 */
	xlat_register(inst->xlat_name, rest_xlat, 0, rest_uri_escape, inst);
	xlat_register("jsonquote", jsonquote_xlat, XLAT_DEFAULT_BUF_LEN, NULL, inst);

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

	/*
	 *	Parse sub-section configs.
	 */
	if (
		(parse_sub_section(conf, &inst->authorize, MOD_AUTHORIZE) < 0) ||
		(parse_sub_section(conf, &inst->authenticate, MOD_AUTHENTICATE) < 0) ||
		(parse_sub_section(conf, &inst->accounting, MOD_ACCOUNTING) < 0) ||

/* @todo add behaviour for checksimul */
/*		(parse_sub_section(conf, &inst->checksimul, MOD_SESSION) < 0) || */
		(parse_sub_section(conf, &inst->post_auth, MOD_POST_AUTH) < 0))
	{
		return -1;
	}

	/*
	 *	Initialise REST libraries.
	 */
	if (rest_init(inst) < 0) {
		return -1;
	}
	inst->pool = module_connection_pool_init(conf, inst, mod_conn_create, mod_conn_alive, NULL);
	if (!inst->pool) return -1;

	return 0;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	rlm_rest_t *inst = instance;

	fr_connection_pool_free(inst->pool);

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
extern module_t rlm_rest;
module_t rlm_rest = {
	.magic		= RLM_MODULE_INIT,
	.name		= "rest",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_rest_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
