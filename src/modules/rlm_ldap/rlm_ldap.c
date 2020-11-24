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
 * @file rlm_ldap.c
 * @brief LDAP authorization and authentication module.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2012,2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013,2015 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2012 Alan DeKok (aland@freeradius.org)
 * @copyright 1999-2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>

#include "rlm_ldap.h"

#include <freeradius-devel/server/map_proc.h>

static CONF_PARSER sasl_mech_dynamic[] = {
	{ FR_CONF_OFFSET("mech", FR_TYPE_TMPL | FR_TYPE_NOT_EMPTY, fr_ldap_sasl_t_dynamic_t, mech) },
	{ FR_CONF_OFFSET("proxy", FR_TYPE_TMPL, fr_ldap_sasl_t_dynamic_t, proxy) },
	{ FR_CONF_OFFSET("realm", FR_TYPE_TMPL, fr_ldap_sasl_t_dynamic_t, realm) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER sasl_mech_static[] = {
	{ FR_CONF_OFFSET("mech", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY, fr_ldap_sasl_t, mech) },
	{ FR_CONF_OFFSET("proxy", FR_TYPE_STRING, fr_ldap_sasl_t, proxy) },
	{ FR_CONF_OFFSET("realm", FR_TYPE_STRING, fr_ldap_sasl_t, realm) },
	CONF_PARSER_TERMINATOR
};

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	/*
	 *	Deprecated attributes
	 */
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_ca_file) },

	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_ca_path) },

	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_certificate_file) },

	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_private_key_file) },

	/*
	 *	LDAP Specific TLS attributes
	 */
	{ FR_CONF_OFFSET("start_tls", FR_TYPE_BOOL, fr_ldap_config_t, start_tls), .dflt = "no" },

	{ FR_CONF_OFFSET("require_cert", FR_TYPE_STRING, fr_ldap_config_t, tls_require_cert_str) },

	CONF_PARSER_TERMINATOR
};


static CONF_PARSER profile_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_TMPL, rlm_ldap_t, profile_filter), .dflt = "(&)", .quote = T_SINGLE_QUOTED_STRING },	//!< Correct filter for when the DN is known.
	{ FR_CONF_OFFSET("attribute", FR_TYPE_STRING, rlm_ldap_t, profile_attr) },
	{ FR_CONF_OFFSET("default", FR_TYPE_TMPL, rlm_ldap_t, default_profile) },
	CONF_PARSER_TERMINATOR
};

/*
 *	User configuration
 */
static CONF_PARSER user_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_TMPL, rlm_ldap_t, userobj_filter) },
	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, rlm_ldap_t, userobj_scope_str), .dflt = "sub" },
	{ FR_CONF_OFFSET("base_dn", FR_TYPE_TMPL, rlm_ldap_t, userobj_base_dn), .dflt = "", .quote = T_SINGLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("sort_by", FR_TYPE_STRING, rlm_ldap_t, userobj_sort_by) },

	{ FR_CONF_OFFSET("access_attribute", FR_TYPE_STRING, rlm_ldap_t, userobj_access_attr) },
	{ FR_CONF_OFFSET("access_positive", FR_TYPE_BOOL, rlm_ldap_t, access_positive), .dflt = "yes" },

	/* Should be deprecated */
	{ FR_CONF_OFFSET("sasl", FR_TYPE_SUBSECTION, rlm_ldap_t, user_sasl), .subcs = (void const *) sasl_mech_dynamic },
	CONF_PARSER_TERMINATOR
};

/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_STRING, rlm_ldap_t, groupobj_filter) },
	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, rlm_ldap_t, groupobj_scope_str), .dflt = "sub" },
	{ FR_CONF_OFFSET("base_dn", FR_TYPE_TMPL, rlm_ldap_t, groupobj_base_dn), .dflt = "", .quote = T_SINGLE_QUOTED_STRING },

	{ FR_CONF_OFFSET("name_attribute", FR_TYPE_STRING, rlm_ldap_t, groupobj_name_attr), .dflt = "cn" },
	{ FR_CONF_OFFSET("membership_attribute", FR_TYPE_STRING, rlm_ldap_t, userobj_membership_attr) },
	{ FR_CONF_OFFSET("membership_filter", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_ldap_t, groupobj_membership_filter) },
	{ FR_CONF_OFFSET("cacheable_name", FR_TYPE_BOOL, rlm_ldap_t, cacheable_group_name), .dflt = "no" },
	{ FR_CONF_OFFSET("cacheable_dn", FR_TYPE_BOOL, rlm_ldap_t, cacheable_group_dn), .dflt = "no" },
	{ FR_CONF_OFFSET("cache_attribute", FR_TYPE_STRING, rlm_ldap_t, cache_attribute) },
	{ FR_CONF_OFFSET("group_attribute", FR_TYPE_STRING, rlm_ldap_t, group_attribute) },
	{ FR_CONF_OFFSET("allow_dangling_group_ref", FR_TYPE_BOOL, rlm_ldap_t, allow_dangling_group_refs), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{ FR_CONF_OFFSET("reference", FR_TYPE_STRING | FR_TYPE_XLAT, ldap_acct_section_t, reference), .dflt = "." },
	CONF_PARSER_TERMINATOR
};

/*
 *	Various options that don't belong in the main configuration.
 *
 *	Note that these overlap a bit with the connection pool code!
 */
static CONF_PARSER option_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET("chase_referrals", FR_TYPE_BOOL, rlm_ldap_t, handle_config.chase_referrals) },

	{ FR_CONF_OFFSET("use_referral_credentials", FR_TYPE_BOOL, rlm_ldap_t, handle_config.use_referral_credentials), .dflt = "no" },

	{ FR_CONF_OFFSET("rebind", FR_TYPE_BOOL, rlm_ldap_t, handle_config.rebind) },

	{ FR_CONF_OFFSET("sasl_secprops", FR_TYPE_STRING, rlm_ldap_t, handle_config.sasl_secprops) },

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/* timeout on network activity */
	{ FR_CONF_DEPRECATED("net_timeout", FR_TYPE_TIME_DELTA, rlm_ldap_t, handle_config.net_timeout), .dflt = "10" },
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{ FR_CONF_OFFSET("idle", FR_TYPE_TIME_DELTA, rlm_ldap_t, handle_config.keepalive_idle), .dflt = "60" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{ FR_CONF_OFFSET("probes", FR_TYPE_UINT32, rlm_ldap_t, handle_config.keepalive_probes), .dflt = "3" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	{ FR_CONF_OFFSET("interval", FR_TYPE_TIME_DELTA, rlm_ldap_t, handle_config.keepalive_interval), .dflt = "30" },
#endif

	{ FR_CONF_OFFSET("dereference", FR_TYPE_STRING, rlm_ldap_t, handle_config.dereference_str) },

	/* allow server unlimited time for search (server-side limit) */
	{ FR_CONF_OFFSET("srv_timelimit", FR_TYPE_TIME_DELTA, rlm_ldap_t, handle_config.srv_timelimit), .dflt = "20" },

	/*
	 *	Instance config items
	 */
	/* timeout for search results */
	{ FR_CONF_OFFSET("res_timeout", FR_TYPE_TIME_DELTA, rlm_ldap_t, handle_config.res_timeout), .dflt = "20" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER global_config[] = {
	{ FR_CONF_OFFSET("random_file", FR_TYPE_FILE_EXISTS, rlm_ldap_t, tls_random_file) },

	{ FR_CONF_OFFSET("ldap_debug", FR_TYPE_UINT32, rlm_ldap_t, ldap_debug), .dflt = "0x0000" },		/* Debugging flags to the server */

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_MULTI, rlm_ldap_t, handle_config.server_str) },	/* Do not set to required */

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_ldap_t, handle_config.port) },

	{ FR_CONF_OFFSET("identity", FR_TYPE_STRING, rlm_ldap_t, handle_config.admin_identity) },
	{ FR_CONF_OFFSET("password", FR_TYPE_STRING | FR_TYPE_SECRET, rlm_ldap_t, handle_config.admin_password) },

	{ FR_CONF_OFFSET("sasl", FR_TYPE_SUBSECTION, rlm_ldap_t, handle_config.admin_sasl), .subcs = (void const *) sasl_mech_static },

	{ FR_CONF_OFFSET("valuepair_attribute", FR_TYPE_STRING, rlm_ldap_t, valuepair_attr) },

#ifdef LDAP_CONTROL_X_SESSION_TRACKING
	{ FR_CONF_OFFSET("session_tracking", FR_TYPE_BOOL, rlm_ldap_t, session_tracking), .dflt = "no" },
#endif

#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{ FR_CONF_OFFSET("edir", FR_TYPE_BOOL, rlm_ldap_t, edir) }, /* NULL defaults to "no" */

	/*
	 *	Attempt to bind with the cleartext password we got from eDirectory
	 *	Universal password for additional authorization checks.
	 */
	{ FR_CONF_OFFSET("edir_autz", FR_TYPE_BOOL, rlm_ldap_t, edir_autz) }, /* NULL defaults to "no" */
#endif

	{ FR_CONF_POINTER("user", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) user_config },

	{ FR_CONF_POINTER("group", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) group_config },

	{ FR_CONF_POINTER("profile", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) profile_config },

	{ FR_CONF_POINTER("options", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) option_config },

	{ FR_CONF_POINTER("global", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) global_config },

	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, rlm_ldap_t, handle_config), .subcs = (void const *) tls_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_ldap_dict[];
fr_dict_autoload_t rlm_ldap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_cleartext_password;
fr_dict_attr_t const *attr_crypt_password;
fr_dict_attr_t const *attr_ldap_userdn;
fr_dict_attr_t const *attr_nt_password;
fr_dict_attr_t const *attr_password_with_header;

fr_dict_attr_t const *attr_user_password;
fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_ldap_dict_attr[];
fr_dict_attr_autoload_t rlm_ldap_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Password.Crypt", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ldap_userdn, .name = "LDAP-UserDN", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "NT-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password.With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};


/** Escape LDAP string
 *
 * @ingroup xlat_functions
 */
static ssize_t ldap_escape_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 	UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 	request_t *request, char const *fmt)
{
	return fr_ldap_escape_func(request, *out, outlen, fmt, NULL);
}

/** Unescape LDAP string
 *
 * @ingroup xlat_functions
 */
static ssize_t ldap_unescape_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 	  request_t *request, char const *fmt)
{
	return fr_ldap_unescape_func(request, *out, outlen, fmt, NULL);
}

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 * @ingroup xlat_functions
 */
static ssize_t ldap_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			 void const *mod_inst, UNUSED void const *xlat_inst,
			 request_t *request, char const *fmt)
{
	fr_ldap_rcode_t		status;
	size_t			len = 0;
	rlm_ldap_t const	*inst = mod_inst;

	LDAPURLDesc		*ldap_url;
	LDAPMessage		*result = NULL;
	LDAPMessage		*entry = NULL;

	struct berval		**values;

	fr_ldap_connection_t	*conn;
	int			ldap_errno;

	char const		*url;
	char const		**attrs;

	LDAPControl		*server_ctrls[] = { NULL, NULL };

	url = fmt;

	if (!ldap_is_ldap_url(url)) {
		REDEBUG("String passed does not look like an LDAP URL");
		return -1;
	}

	if (ldap_url_parse(url, &ldap_url)){
		REDEBUG("Parsing LDAP URL failed");
		return -1;
	}

	/*
	 *	Nothing, empty string, "*" string, or got 2 things, die.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] ||
	    !*ldap_url->lud_attrs[0] ||
	    (strcmp(ldap_url->lud_attrs[0], "*") == 0) ||
	    ldap_url->lud_attrs[1]) {
		REDEBUG("Bad attributes list in LDAP URL. URL must specify exactly one attribute to retrieve");

		goto free_urldesc;
	}

	conn = mod_conn_get(inst, request);
	if (!conn) goto free_urldesc;

	memcpy(&attrs, &ldap_url->lud_attrs, sizeof(attrs));

	if (fr_ldap_parse_url_extensions(&server_ctrls[0], request, conn, ldap_url->lud_exts) < 0) goto free_socket;

	status = fr_ldap_search(&result, request, &conn, ldap_url->lud_dn, ldap_url->lud_scope,
				ldap_url->lud_filter, attrs, server_ctrls, NULL);

#ifdef HAVE_LDAP_CREATE_SORT_CONTROL
	if (server_ctrls[0]) ldap_control_free(server_ctrls[0]);
#endif

	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	default:
		goto free_socket;
	}

	fr_assert(conn);
	fr_assert(result);

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
		len = -1;
		goto free_result;
	}

	values = ldap_get_values_len(conn->handle, entry, ldap_url->lud_attrs[0]);
	if (!values) {
		RDEBUG2("No \"%s\" attributes found in specified object", ldap_url->lud_attrs[0]);
		goto free_result;
	}

	if (values[0]->bv_len >= outlen) goto free_values;

	memcpy(*out, values[0]->bv_val, values[0]->bv_len + 1);	/* +1 as strlcpy expects buffer size */
	len = values[0]->bv_len;

free_values:
	ldap_value_free_len(values);
free_result:
	ldap_msgfree(result);
free_socket:
	ldap_mod_conn_release(inst, request, conn);
free_urldesc:
	ldap_free_urldesc(ldap_url);

	return len;
}

/*
 *	Verify the result of the map.
 */
static int ldap_map_verify(CONF_SECTION *cs, UNUSED void *mod_inst, UNUSED void *proc_inst,
			   tmpl_t const *src, UNUSED map_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing LDAP URI");

		return -1;
	}

	return 0;
}

/** Perform a search and map the result of the search to server attributes
 *
 * Unlike LDAP xlat, this can be used to process attributes from multiple entries.
 *
 * @todo For xlat expansions we need to parse the raw URL first, and then apply
 *	different escape functions to the different parts.
 *
 * @param[in] mod_inst #rlm_ldap_t
 * @param[in] proc_inst unused.
 * @param[in,out] request The current request.
 * @param[in] url LDAP url specifying base DN and filter.
 * @param[in] maps Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned.
 *	- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *	- #RLM_MODULE_FAIL if an error occurred.
 */
static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, request_t *request,
				fr_value_box_t **url, map_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_UPDATED;
	rlm_ldap_t		*inst = talloc_get_type_abort(mod_inst, rlm_ldap_t);
	fr_ldap_rcode_t		status;

	LDAPURLDesc		*ldap_url;

	LDAPMessage		*result = NULL;
	LDAPMessage		*entry = NULL;
	map_t const		*map;
	char const 		*url_str;

	fr_ldap_connection_t		*conn;

	LDAPControl		*server_ctrls[] = { NULL, NULL };

	fr_ldap_map_exp_t	expanded; /* faster than allocing every time */

	/*
	 *	FIXME - Maybe it can be NULL?
	 */
	if (!*url) {
		REDEBUG("LDAP URL cannot be (null)");
		return RLM_MODULE_FAIL;
	}

	if (fr_value_box_list_concat(request, *url, url, FR_TYPE_STRING, true) < 0) {
		REDEBUG("Failed concatenating input");
		return RLM_MODULE_FAIL;
	}
	url_str = (*url)->vb_strvalue;

	if (!ldap_is_ldap_url(url_str)) {
		REDEBUG("Map query string does not look like a valid LDAP URI");
		return RLM_MODULE_FAIL;
	}

	if (ldap_url_parse(url_str, &ldap_url)){
		REDEBUG("Parsing LDAP URL failed");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Expand the RHS of the maps to get the name of the attributes.
	 */
	if (fr_ldap_map_expand(&expanded, request, maps) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto free_urldesc;
	}

	conn = mod_conn_get(inst, request);
	if (!conn) goto free_expanded;

	if (fr_ldap_parse_url_extensions(&server_ctrls[0], request, conn, ldap_url->lud_exts) < 0) goto free_socket;

	status = fr_ldap_search(&result, request, &conn, ldap_url->lud_dn, ldap_url->lud_scope,
				ldap_url->lud_filter, expanded.attrs, server_ctrls, NULL);

#ifdef HAVE_LDAP_CREATE_SORT_CONTROL
	if (server_ctrls[0]) ldap_control_free(server_ctrls[0]);
#endif

	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		rcode = RLM_MODULE_NOOP;
		goto free_socket;

	default:
		rcode = RLM_MODULE_FAIL;
		goto free_socket;
	}

	fr_assert(conn);
	fr_assert(result);

	for (entry = ldap_first_entry(conn->handle, result);
	     entry;
	     entry = ldap_next_entry(conn->handle, entry)) {
		char	*dn = NULL;
		int	i;


		if (RDEBUG_ENABLED2) {
			dn = ldap_get_dn(conn->handle, entry);
			RDEBUG2("Processing \"%s\"", dn);
		}

		RINDENT();
		for (map = maps, i = 0;
		     map != NULL;
		     map = map->next, i++) {
			int			ret;
			fr_ldap_result_t	attr;

			attr.values = ldap_get_values_len(conn->handle, entry, expanded.attrs[i]);
			if (!attr.values) {
				/*
				 *	Many LDAP directories don't expose the DN of
				 *	the object as an attribute, so we need this
				 *	hack, to allow the user to retrieve it.
				 */
				if (strcmp(LDAP_VIRTUAL_DN_ATTR, expanded.attrs[i]) == 0) {
					struct berval value;
					struct berval *values[2] = { &value, NULL };

					if (!dn) dn = ldap_get_dn(conn->handle, entry);
					value.bv_val = dn;
					value.bv_len = strlen(dn);

					attr.values = values;
					attr.count = 1;

					ret = map_to_request(request, map, fr_ldap_map_getvalue, &attr);
					if (ret == -1) {
						rcode = RLM_MODULE_FAIL;
						ldap_memfree(dn);
						goto free_result;
					}
					continue;
				}

				RDEBUG3("Attribute \"%s\" not found in LDAP object", expanded.attrs[i]);

				continue;
			}
			attr.count = ldap_count_values_len(attr.values);

			ret = map_to_request(request, map, fr_ldap_map_getvalue, &attr);
			ldap_value_free_len(attr.values);
			if (ret == -1) {
				rcode = RLM_MODULE_FAIL;
				ldap_memfree(dn);
				goto free_result;
			}
		}
		ldap_memfree(dn);
		REXDENT();
	}

free_result:
	ldap_msgfree(result);
free_socket:
	ldap_mod_conn_release(inst, request, conn);
free_expanded:
	talloc_free(expanded.ctx);
free_urldesc:
	ldap_free_urldesc(ldap_url);

	return rcode;
}

/** Perform LDAP-Group comparison checking
 *
 * Attempts to match users to groups using a variety of methods.
 *
 * @param instance of the rlm_ldap module.
 * @param request Current request.
 * @param thing Unknown.
 * @param check Which group to check for user membership.
 * @param check_list Unknown.
 * @return
 *	- 1 on failure (or if the user is not a member).
 *	- 0 on success.
 */
static int rlm_ldap_groupcmp(void *instance, request_t *request, UNUSED fr_pair_t *thing, fr_pair_t *check,
			     UNUSED fr_pair_t *check_list)
{
	rlm_ldap_t const	*inst = talloc_get_type_abort_const(instance, rlm_ldap_t);
	rlm_rcode_t		rcode;

	bool			found = false;
	bool			check_is_dn;

	fr_ldap_connection_t		*conn = NULL;
	char const		*user_dn;

	fr_assert(inst->groupobj_base_dn);

	RDEBUG2("Searching for user in group \"%pV\"", &check->data);

	if (check->vp_length == 0) {
		REDEBUG("Cannot do comparison (group name is empty)");
		return 1;
	}

	/*
	 *	Check if we can do cached membership verification
	 */
	check_is_dn = fr_ldap_util_is_dn(check->vp_strvalue, check->vp_length);
	if (check_is_dn) {
		char	*norm;
		size_t	len;

		MEM(norm = talloc_array(check, char, talloc_array_length(check->vp_strvalue)));
		len = fr_ldap_util_normalise_dn(norm, check->vp_strvalue);

		/*
		 *	Will clear existing buffer (i.e. check->vp_strvalue)
		 */
		fr_pair_value_bstrdup_buffer_shallow(check, norm, check->vp_tainted);

		/*
		 *	Trim buffer to match normalised DN
		 */
		fr_pair_value_bstr_realloc(check, NULL, len);
	}
	if ((check_is_dn && inst->cacheable_group_dn) || (!check_is_dn && inst->cacheable_group_name)) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_cached(&our_rcode, inst, request, check);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			found = false;
			goto finish;

		case RLM_MODULE_OK:
			found = true;
			goto finish;
		/*
		 *	Fallback to dynamic search on failure
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		default:
			break;
		}
	}

	conn = mod_conn_get(inst, request);
	if (!conn) return 1;

	/*
	 *	This is used in the default membership filter.
	 */
	user_dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!user_dn) {
		ldap_mod_conn_release(inst, request, conn);
		return 1;
	}

	fr_assert(conn);

	/*
	 *	Check groupobj user membership
	 */
	if (inst->groupobj_membership_filter) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_groupobj_dynamic(&our_rcode, inst, request, &conn, check);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			break;

		case RLM_MODULE_OK:
			found = true;
			FALL_THROUGH;

		default:
			goto finish;
		}
	}

	fr_assert(conn);

	/*
	 *	Check userobj group membership
	 */
	if (inst->userobj_membership_attr) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_userobj_dynamic(&our_rcode, inst, request, &conn, user_dn, check);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			break;

		case RLM_MODULE_OK:
			found = true;
			FALL_THROUGH;

		default:
			goto finish;
		}
	}

	fr_assert(conn);

finish:
	if (conn) ldap_mod_conn_release(inst, request, conn);

	if (!found) {
		RDEBUG2("User is not a member of \"%pV\"", &check->data);

		return 1;
	}

	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->instance, rlm_ldap_t);
	rlm_rcode_t		rcode;
	fr_ldap_rcode_t		status;
	char const		*dn;
	fr_ldap_connection_t	*conn;

	char			sasl_mech_buff[LDAP_MAX_DN_STR_LEN];
	char			sasl_proxy_buff[LDAP_MAX_DN_STR_LEN];
	char			sasl_realm_buff[LDAP_MAX_DN_STR_LEN];
	fr_ldap_sasl_t		sasl;
	fr_pair_t *username, *password;

	username = fr_pair_find_by_da(&request->request_pairs, attr_user_name);
	password = fr_pair_find_by_da(&request->request_pairs, attr_user_password);

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	if (!password) {
		RWDEBUG("You have set \"Auth-Type := LDAP\" somewhere");
		RWDEBUG("without checking if User-Password is present");
		RWDEBUG("*********************************************");
		RWDEBUG("* THAT CONFIGURATION IS WRONG.  DELETE IT.   ");
		RWDEBUG("* YOU ARE PREVENTING THE SERVER FROM WORKING");
		RWDEBUG("*********************************************");

		REDEBUG("Attribute \"User-Password\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (password->vp_length == 0) {
		REDEBUG("User-Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &password->data);
	} else {
		RDEBUG2("Login attempt with password");
	}

	conn = mod_conn_get(inst, request);
	if (!conn) RETURN_MODULE_FAIL;

	/*
	 *	Expand dynamic SASL fields
	 */
	if (inst->user_sasl.mech) {
		memset(&sasl, 0, sizeof(sasl));

		if (tmpl_expand(&sasl.mech, sasl_mech_buff, sizeof(sasl_mech_buff), request,
				inst->user_sasl.mech, fr_ldap_escape_func, inst) < 0) {
			RPEDEBUG("Failed expanding user.sasl.mech");
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		if (inst->user_sasl.proxy) {
			if (tmpl_expand(&sasl.proxy, sasl_proxy_buff, sizeof(sasl_proxy_buff), request,
					inst->user_sasl.proxy, fr_ldap_escape_func, inst) < 0) {
				RPEDEBUG("Failed expanding user.sasl.proxy");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}

		if (inst->user_sasl.realm) {
			if (tmpl_expand(&sasl.realm, sasl_realm_buff, sizeof(sasl_realm_buff), request,
					inst->user_sasl.realm, fr_ldap_escape_func, inst) < 0) {
				RPEDEBUG("Failed expanding user.sasl.realm");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}
	}

	RDEBUG2("Login attempt by \"%pV\"", &username->data);

	/*
	 *	Get the DN by doing a search.
	 */
	dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!dn) {
		ldap_mod_conn_release(inst, request, conn);

		RETURN_MODULE_RCODE(rcode);
	}
	conn->rebound = true;
	status = fr_ldap_bind(request,
			      &conn,
			      dn, password->vp_strvalue,
			      inst->user_sasl.mech ? &sasl : NULL,
			      0,
			      NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		rcode = RLM_MODULE_OK;
		RDEBUG2("Bind as user \"%s\" was successful", dn);
		break;

	case LDAP_PROC_NOT_PERMITTED:
		rcode = RLM_MODULE_DISALLOW;
		break;

	case LDAP_PROC_REJECT:
		rcode = RLM_MODULE_REJECT;
		break;

	case LDAP_PROC_BAD_DN:
		rcode = RLM_MODULE_INVALID;
		break;

	case LDAP_PROC_NO_RESULT:
		rcode = RLM_MODULE_NOTFOUND;
		break;

	default:
		rcode = RLM_MODULE_FAIL;
		break;
	};

finish:
	ldap_mod_conn_release(inst, request, conn);

	RETURN_MODULE_RCODE(rcode);
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common
 * sets of attributes to the request.
 *
 * @param[out] p_result		the result of applying the profile.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in,out] pconn		to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn		of profile object to apply.
 * @param[in] expanded		Structure containing a list of xlat
 *				expanded attribute names and mapping information.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t rlm_ldap_map_profile(rlm_rcode_t *p_result, rlm_ldap_t const *inst,
					    request_t *request, fr_ldap_connection_t **pconn,
					    char const *dn, fr_ldap_map_exp_t const *expanded)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	fr_ldap_rcode_t	status;
	LDAPMessage	*result = NULL, *entry = NULL;
	int		ldap_errno;
	LDAP		*handle = (*pconn)->handle;
	char const	*filter;
	char		filter_buff[LDAP_MAX_FILTER_STR_LEN];

	fr_assert(inst->profile_filter); 	/* We always have a default filter set */

	if (!dn || !*dn) RETURN_MODULE_OK;

	if (tmpl_expand(&filter, filter_buff, sizeof(filter_buff), request,
			inst->profile_filter, fr_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating profile filter");

		RETURN_MODULE_INVALID;
	}

	status = fr_ldap_search(&result, request, pconn, dn,
				LDAP_SCOPE_BASE, filter, expanded->attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_BAD_DN:
	case LDAP_PROC_NO_RESULT:
		RDEBUG2("Profile object \"%s\" not found", dn);
		RETURN_MODULE_NOTFOUND;

	default:
		RETURN_MODULE_FAIL;
	}

	fr_assert(*pconn);
	fr_assert(result);

	entry = ldap_first_entry(handle, result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_NOTFOUND;

		goto free_result;
	}

	RDEBUG2("Processing profile attributes");
	RINDENT();
	if (fr_ldap_map_do(request, *pconn, inst->valuepair_attr, expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
	REXDENT();

free_result:
	ldap_msgfree(result);

	RETURN_MODULE_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->instance, rlm_ldap_t);
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	int			ldap_errno;
	int			i;
	struct berval		**values;
	fr_ldap_connection_t	*conn;
	LDAPMessage		*result, *entry;
	char const 		*dn = NULL;
	fr_ldap_map_exp_t	expanded; /* faster than allocing every time */
#ifdef WITH_EDIR
	fr_ldap_rcode_t		status;
#endif

	/*
	 *	Don't be tempted to add a check for User-Name or
	 *	User-Password here.  LDAP authorization can be used
	 *	for many things besides searching for users.
	 */

	if (fr_ldap_map_expand(&expanded, request, inst->user_map) < 0) RETURN_MODULE_FAIL;

	conn = mod_conn_get(inst, request);
	if (!conn) RETURN_MODULE_FAIL;

	/*
	 *	Add any additional attributes we need for checking access, memberships, and profiles
	 */
	if (inst->userobj_access_attr) {
		expanded.attrs[expanded.count++] = inst->userobj_access_attr;
	}

	if (inst->userobj_membership_attr && (inst->cacheable_group_dn || inst->cacheable_group_name)) {
		expanded.attrs[expanded.count++] = inst->userobj_membership_attr;
	}

	if (inst->profile_attr) {
		expanded.attrs[expanded.count++] = inst->profile_attr;
	}

	if (inst->valuepair_attr) {
		expanded.attrs[expanded.count++] = inst->valuepair_attr;
	}

	expanded.attrs[expanded.count] = NULL;

	dn = rlm_ldap_find_user(inst, request, &conn, expanded.attrs, true, &result, &rcode);
	if (!dn) {
		goto finish;
	}

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		goto finish;
	}

	/*
	 *	Check for access.
	 */
	if (inst->userobj_access_attr) {
		rcode = rlm_ldap_check_access(inst, request, conn, entry);
		if (rcode != RLM_MODULE_OK) {
			goto finish;
		}
	}

	/*
	 *	Check if we need to cache group memberships
	 */
	if (inst->cacheable_group_dn || inst->cacheable_group_name) {
		if (inst->userobj_membership_attr) {
			rlm_ldap_cacheable_userobj(&rcode, inst, request, &conn, entry, inst->userobj_membership_attr);
			if (rcode != RLM_MODULE_OK) {
				goto finish;
			}
		}

		rlm_ldap_cacheable_groupobj(&rcode, inst, request, &conn);
		if (rcode != RLM_MODULE_OK) {
			goto finish;
		}
	}

#ifdef WITH_EDIR
	/*
	 *	We already have a Password.Cleartext.  Skip edir.
	 */
	if (fr_pair_find_by_da(&request->control_pairs, attr_cleartext_password)) goto skip_edir;

	/*
	 *      Retrieve Universal Password if we use eDirectory
	 */
	if (inst->edir) {
		fr_pair_t	*vp;
		int		res = 0;
		char		password[256];
		size_t		pass_size = sizeof(password);

		/*
		 *	Retrive universal password
		 */
		res = fr_ldap_edir_get_password(conn->handle, dn, password, &pass_size);
		if (res != 0) {
			REDEBUG("Failed to retrieve eDirectory password: (%i) %s", res, fr_ldap_edir_errstr(res));
			rcode = RLM_MODULE_FAIL;

			goto finish;
		}

		/*
		 *	Add Password.Cleartext attribute to the request
		 */
		MEM(pair_update_control(&vp, attr_cleartext_password) >= 0);
		fr_pair_value_bstrndup(vp, password, pass_size, true);

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Added eDirectory password.  control.%pP", vp);
		} else {
			RDEBUG2("Added eDirectory password");
		}

		if (inst->edir_autz) {
			RDEBUG2("Binding as user for eDirectory authorization checks");
			/*
			 *	Bind as the user
			 */
			conn->rebound = true;
			status = fr_ldap_bind(request, &conn, dn, vp->vp_strvalue, NULL, 0, NULL, NULL);
			switch (status) {
			case LDAP_PROC_SUCCESS:
				rcode = RLM_MODULE_OK;
				RDEBUG2("Bind as user '%s' was successful", dn);
				break;

			case LDAP_PROC_NOT_PERMITTED:
				rcode = RLM_MODULE_DISALLOW;
				goto finish;

			case LDAP_PROC_REJECT:
				rcode = RLM_MODULE_REJECT;
				goto finish;

			case LDAP_PROC_BAD_DN:
				rcode = RLM_MODULE_INVALID;
				goto finish;

			case LDAP_PROC_NO_RESULT:
				rcode = RLM_MODULE_NOTFOUND;
				goto finish;

			default:
				rcode = RLM_MODULE_FAIL;
				goto finish;
			};
		}
	}

skip_edir:
#endif

	/*
	 *	Apply ONE user profile, or a default user profile.
	 */
	if (inst->default_profile) {
		char const	*profile;
		char		profile_buff[1024];
		rlm_rcode_t	ret;

		if (tmpl_expand(&profile, profile_buff, sizeof(profile_buff),
				request, inst->default_profile, NULL, NULL) < 0) {
			REDEBUG("Failed creating default profile string");

			rcode = RLM_MODULE_INVALID;
			goto finish;
		}

		rlm_ldap_map_profile(&ret, inst, request, &conn, profile, &expanded);
		switch (ret) {
		case RLM_MODULE_INVALID:
			rcode = RLM_MODULE_INVALID;
			goto finish;

		case RLM_MODULE_FAIL:
			rcode = RLM_MODULE_FAIL;
			goto finish;

		case RLM_MODULE_UPDATED:
			rcode = RLM_MODULE_UPDATED;
			FALL_THROUGH;
		default:
			break;
		}
	}

	/*
	 *	Apply a SET of user profiles.
	 */
	if (inst->profile_attr) {
		values = ldap_get_values_len(conn->handle, entry, inst->profile_attr);
		if (values != NULL) {
			for (i = 0; values[i] != NULL; i++) {
				rlm_rcode_t ret;
				char *value;

				value = fr_ldap_berval_to_string(request, values[i]);
				rlm_ldap_map_profile(&ret, inst, request, &conn, value, &expanded);
				talloc_free(value);
				if (ret == RLM_MODULE_FAIL) {
					ldap_value_free_len(values);
					rcode = ret;
					goto finish;
				}

			}
			ldap_value_free_len(values);
		}
	}

	if (inst->user_map || inst->valuepair_attr) {
		RDEBUG2("Processing user attributes");
		RINDENT();
		if (fr_ldap_map_do(request, conn, inst->valuepair_attr,
				   &expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
		REXDENT();
		rlm_ldap_check_reply(inst, request, conn);
	}

finish:
	talloc_free(expanded.ctx);
	if (result) ldap_msgfree(result);
	ldap_mod_conn_release(inst, request, conn);

	RETURN_MODULE_RCODE(rcode);
}

/** Modify user's object in LDAP
 *
 * Process a modifcation map to update a user object in the LDAP directory.
 *
 * @param[out] p_result		the result of the modification.
 * @param[in] inst		rlm_ldap instance.
 * @param[in] request		Current request.
 * @param[in] section		that holds the map to process.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t user_modify(rlm_rcode_t *p_result, rlm_ldap_t const *inst,
				   request_t *request, ldap_acct_section_t *section)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	fr_ldap_rcode_t	status;

	fr_ldap_connection_t	*conn = NULL;

	LDAPMod		*mod_p[LDAP_MAX_ATTRMAP + 1], mod_s[LDAP_MAX_ATTRMAP];
	LDAPMod		**modify = mod_p;

	char		*passed[LDAP_MAX_ATTRMAP * 2];
	int		i, total = 0, last_pass = 0;

	char 		*expanded[LDAP_MAX_ATTRMAP];
	int		last_exp = 0;

	char const	*attr;
	char const	*value;

	char const	*dn;
	/*
	 *	Build our set of modifications using the update sections in
	 *	the config.
	 */
	CONF_ITEM  	*ci;
	CONF_PAIR	*cp;
	CONF_SECTION 	*cs;
	fr_token_t	op;
	char		path[FR_MAX_STRING_LEN];

	char		*p = path;

	fr_assert(section);

	/*
	 *	Locate the update section were going to be using
	 */
	if (section->reference[0] != '.') {
		*p++ = '.';
	}

	if (xlat_eval(p, (sizeof(path) - (p - path)) - 1, request, section->reference, NULL, NULL) < 0) {
		goto error;
	}

	ci = cf_reference_item(NULL, section->cs, path);
	if (!ci) {
		goto error;
	}

	if (!cf_item_is_section(ci)){
		REDEBUG("Reference must resolve to a section");

		goto error;
	}

	cs = cf_section_find(cf_item_to_section(ci), "update", NULL);
	if (!cs) {
		REDEBUG("Section must contain 'update' subsection");

		goto error;
	}

	/*
	 *	Iterate over all the pairs, building our mods array
	 */
	for (ci = cf_item_next(cs, NULL); ci != NULL; ci = cf_item_next(cs, ci)) {
		bool do_xlat = false;

		if (total == LDAP_MAX_ATTRMAP) {
			REDEBUG("Modify map size exceeded");

			goto error;
		}

		if (!cf_item_is_pair(ci)) {
			REDEBUG("Entry is not in \"ldap-attribute = value\" format");

			goto error;
		}

		/*
		 *	Retrieve all the information we need about the pair
		 */
		cp = cf_item_to_pair(ci);
		value = cf_pair_value(cp);
		attr = cf_pair_attr(cp);
		op = cf_pair_operator(cp);

		if (!value || (*value == '\0')) {
			RDEBUG2("Empty value string, skipping attribute \"%s\"", attr);

			continue;
		}

		switch (cf_pair_value_quote(cp)) {
		case T_BARE_WORD:
		case T_SINGLE_QUOTED_STRING:
			break;

		case T_BACK_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			do_xlat = true;
			break;

		default:
			fr_assert(0);
			goto error;
		}

		if (op == T_OP_CMP_FALSE) {
			passed[last_pass] = NULL;
		} else if (do_xlat) {
			char *exp = NULL;

			if (xlat_aeval(request, &exp, request, value, NULL, NULL) <= 0) {
				RDEBUG2("Skipping attribute \"%s\"", attr);

				talloc_free(exp);

				continue;
			}

			expanded[last_exp++] = exp;
			passed[last_pass] = exp;
		/*
		 *	Static strings
		 */
		} else {
			memcpy(&(passed[last_pass]), &value, sizeof(passed[last_pass]));
		}

		passed[last_pass + 1] = NULL;

		mod_s[total].mod_values = &(passed[last_pass]);

		last_pass += 2;

		switch (op) {
		/*
		 *  T_OP_EQ is *NOT* supported, it is impossible to
		 *  support because of the lack of transactions in LDAP
		 */
		case T_OP_ADD:
			mod_s[total].mod_op = LDAP_MOD_ADD;
			break;

		case T_OP_SET:
			mod_s[total].mod_op = LDAP_MOD_REPLACE;
			break;

		case T_OP_SUB:
		case T_OP_CMP_FALSE:
			mod_s[total].mod_op = LDAP_MOD_DELETE;
			break;

#ifdef LDAP_MOD_INCREMENT
		case T_OP_INCRM:
			mod_s[total].mod_op = LDAP_MOD_INCREMENT;
			break;
#endif
		default:
			REDEBUG("Operator '%s' is not supported for LDAP modify operations",
				fr_table_str_by_value(fr_tokens_table, op, "<INVALID>"));

			goto error;
		}

		/*
		 *	Now we know the value is ok, copy the pointers into
		 *	the ldapmod struct.
		 */
		memcpy(&(mod_s[total].mod_type), &attr, sizeof(mod_s[total].mod_type));

		mod_p[total] = &(mod_s[total]);
		total++;
	}

	if (total == 0) {
		rcode = RLM_MODULE_NOOP;
		goto release;
	}

	mod_p[total] = NULL;

	conn = mod_conn_get(inst, request);
	if (!conn) RETURN_MODULE_FAIL;


	dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!dn || (rcode != RLM_MODULE_OK)) {
		goto error;
	}

	status = fr_ldap_modify(request, &conn, dn, modify, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_REJECT:
	case LDAP_PROC_BAD_DN:
		rcode = RLM_MODULE_INVALID;
		break;

	default:
		rcode = RLM_MODULE_FAIL;
		break;
	};

release:
error:
	/*
	 *	Free up any buffers we allocated for xlat expansion
	 */
	for (i = 0; i < last_exp; i++) talloc_free(expanded[i]);

	ldap_mod_conn_release(inst, request, conn);

	RETURN_MODULE_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_ldap_t);

	if (inst->accounting) return user_modify(p_result, inst, request, inst->accounting);

	RETURN_MODULE_NOOP;
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_ldap_t);

	if (inst->postauth) return user_modify(p_result, inst, request, inst->postauth);

	RETURN_MODULE_NOOP;
}


/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int mod_detach(void *instance)
{
	rlm_ldap_t *inst = instance;

#ifdef HAVE_LDAP_CREATE_SORT_CONTROL
	if (inst->userobj_sort_ctrl) ldap_control_free(inst->userobj_sort_ctrl);
#endif

	fr_pool_free(inst->pool);

	return 0;
}

/** Parse an accounting sub section.
 *
 * Allocate a new ldap_acct_section_t and write the config data into it.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] parent of the config section.
 * @param[out] config to write the sub section parameters to.
 * @param[in] comp The section name were parsing the config for.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int parse_sub_section(rlm_ldap_t *inst, CONF_SECTION *parent, ldap_acct_section_t **config,
			     rlm_components_t comp)
{
	CONF_SECTION *cs;

	char const *name = section_type_value[comp];

	cs = cf_section_find(parent, name, NULL);
	if (!cs) {
		DEBUG2("rlm_ldap (%s) - Couldn't find configuration for %s, will return NOOP for calls "
		       "from this section", inst->name, name);

		return 0;
	}

	if (cf_section_rules_push(cs, acct_section_config) < 0) return -1;

	*config = talloc_zero(inst, ldap_acct_section_t);
	if (cf_section_parse(*config, *config, cs) < 0) {
		PERROR("rlm_ldap (%s) - Failed parsing configuration for section %s", inst->name, name);

		return -1;
	}

	(*config)->cs = cs;

	return 0;
}

/** Bootstrap the module
 *
 * Define attributes.
 *
 * @param conf to parse.
 * @param instance configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_ldap_t	*inst = instance;
	char		buffer[256];
	char const	*group_attribute;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	inst->handle_config.name = talloc_typed_asprintf(inst, "rlm_ldap (%s)", inst->name);

	if (inst->group_attribute) {
		group_attribute = inst->group_attribute;
	} else if (cf_section_name2(conf)) {
		snprintf(buffer, sizeof(buffer), "%s-LDAP-Group", inst->name);
		group_attribute = buffer;
	} else {
		group_attribute = "LDAP-Group";
	}

	if (paircmp_register_by_name(group_attribute, attr_user_name, false, rlm_ldap_groupcmp, inst) < 0) {
		PERROR("Error registering group comparison");
		goto error;
	}

	inst->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);

	/*
	 *	Setup the cache attribute
	 */
	if (inst->cache_attribute) {
		fr_dict_attr_flags_t	flags;

		memset(&flags, 0, sizeof(flags));
		if (fr_dict_attr_add(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
				     inst->cache_attribute, -1, FR_TYPE_STRING, &flags) < 0) {
			PERROR("Error creating cache attribute");
		error:
			return -1;

		}
		inst->cache_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->cache_attribute);
	} else {
		inst->cache_da = inst->group_da;	/* Default to the group_da */
	}

	xlat_register_legacy(inst, inst->name, ldap_xlat, fr_ldap_escape_func, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	xlat_register_legacy(inst, "ldap_escape", ldap_escape_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	xlat_register_legacy(inst, "ldap_unescape", ldap_unescape_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	map_proc_register(inst, inst->name, mod_map_proc, ldap_map_verify, 0);

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
	size_t		i;

	CONF_SECTION	*options, *update;
	rlm_ldap_t	*inst = instance;

	inst->cs = conf;

	options = cf_section_find(conf, "options", NULL);
	if (!options || !cf_pair_find(options, "chase_referrals")) {
		inst->handle_config.chase_referrals_unset = true;	 /* use OpenLDAP defaults */
	}

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((parse_sub_section(inst, conf, &inst->accounting, MOD_ACCOUNTING) < 0) ||
	    (parse_sub_section(inst, conf, &inst->postauth, MOD_POST_AUTH) < 0)) {
		cf_log_err(conf, "Failed parsing configuration");

		goto error;
	}

	/*
	 *	Sanity checks for cacheable groups code.
	 */
	if (inst->cacheable_group_name && inst->groupobj_membership_filter) {
		if (!inst->groupobj_name_attr) {
			cf_log_err(conf, "Configuration item 'group.name_attribute' must be set if cacheable "
				      "group names are enabled");

			goto error;
		}
	}

	/*
	 *	If we have a *pair* as opposed to a *section*
	 *	then the module is referencing another ldap module's
	 *	connection pool.
	 */
	if (!cf_pair_find(conf, "pool")) {
		if (!inst->handle_config.server_str) {
			cf_log_err(conf, "Configuration item 'server' must have a value");
			goto error;
		}
	}

#ifndef WITH_SASL
	if (inst->user_sasl.mech) {
		cf_log_err(conf, "Configuration item 'user.sasl.mech' not supported.  "
			   "Linked libldap does not provide ldap_sasl_bind( function");
		goto error;
	}

	if (inst->handle_config.admin_sasl.mech) {
		cf_log_err(conf, "Configuration item 'sasl.mech' not supported.  "
			   "Linked libldap does not provide ldap_sasl_interactive_bind function");
		goto error;
	}
#endif

#ifndef HAVE_LDAP_CREATE_SORT_CONTROL
	if (inst->userobj_sort_by) {
		cf_log_err(conf, "Configuration item 'sort_by' not supported.  "
			   "Linked libldap does not provide ldap_create_sort_control function");
		goto error;
	}
#endif

#ifndef HAVE_LDAP_URL_PARSE
	if (inst->handle_config.use_referral_credentials) {
		cf_log_err(conf, "Configuration item 'use_referral_credentials' not supported.  "
			   "Linked libldap does not support URL parsing");
		goto error;
	}
#endif

	/*
	 *	Initialise server with zero length string to
	 *	make code below simpler.
	 */
	inst->handle_config.server = talloc_strdup(inst, "");

	/*
	 *	Now iterate over all the 'server' config items
	 */
	for (i = 0; i < talloc_array_length(inst->handle_config.server_str); i++) {
		char const *value = inst->handle_config.server_str[i];
		size_t j;

		/*
		 *	Explicitly prevent multiple server definitions
		 *	being used in the same string.
		 */
		for (j = 0; j < talloc_array_length(value) - 1; j++) {
			switch (value[j]) {
			case ' ':
			case ',':
			case ';':
				cf_log_err(conf, "Invalid character '%c' found in 'server' configuration item",
					      value[j]);
				goto error;

			default:
				continue;
			}
		}

#ifdef LDAP_CAN_PARSE_URLS
		/*
		 *	Split original server value out into URI, server and port
		 *	so whatever initialization function we use later will have
		 *	the server information in the format it needs.
		 */
		if (ldap_is_ldap_url(value)) {
			LDAPURLDesc	*ldap_url;
			bool		set_port_maybe = true;
			int		default_port = LDAP_PORT;
			char		*p;

			if (ldap_url_parse(value, &ldap_url)){
				cf_log_err(conf, "Parsing LDAP URL \"%s\" failed", value);
			ldap_url_error:
				ldap_free_urldesc(ldap_url);
				return -1;
			}

			if (ldap_url->lud_dn && (ldap_url->lud_dn[0] != '\0')) {
				cf_log_err(conf, "Base DN cannot be specified via server URL");
				goto ldap_url_error;
			}

			if (ldap_url->lud_attrs && ldap_url->lud_attrs[0]) {
				cf_log_err(conf, "Attribute list cannot be specified via server URL");
				goto ldap_url_error;
			}

			/*
			 *	ldap_url_parse sets this to base by default.
			 */
			if (ldap_url->lud_scope != LDAP_SCOPE_BASE) {
				cf_log_err(conf, "Scope cannot be specified via server URL");
				goto ldap_url_error;
			}
			ldap_url->lud_scope = -1;	/* Otherwise LDAP adds ?base */

			/*
			 *	The public ldap_url_parse function sets the default
			 *	port, so we have to discover whether a port was
			 *	included ourselves.
			 */
			if ((p = strchr(value, ']')) && (p[1] == ':')) {			/* IPv6 */
				set_port_maybe = false;
			} else if ((p = strchr(value, ':')) && (strchr(p + 1, ':') != NULL)) {	/* IPv4 */
				set_port_maybe = false;
			}

			/* We allow extensions */

#  ifdef HAVE_LDAP_INITIALIZE
			{
				char *url;

				/*
				 *	Figure out the default port from the URL
				 */
				if (ldap_url->lud_scheme) {
					if (strcmp(ldap_url->lud_scheme, "ldaps") == 0) {
						if (inst->handle_config.start_tls == true) {
							cf_log_err(conf, "ldaps:// scheme is not compatible "
								      "with 'start_tls'");
							goto ldap_url_error;
						}
						default_port = LDAPS_PORT;

					} else if (strcmp(ldap_url->lud_scheme, "ldapi") == 0) {
						set_port_maybe = false; /* Unix socket, no port */
					}
				}

				if (set_port_maybe) {
					/*
					 *	URL port overrides configured port.
					 */
					ldap_url->lud_port = inst->handle_config.port;

					/*
					 *	If there's no URL port, then set it to the default
					 *	this is so debugging messages show explicitly
					 *	the port we're connecting to.
					 */
					if (!ldap_url->lud_port) ldap_url->lud_port = default_port;
				}

				url = ldap_url_desc2str(ldap_url);
				if (!url) {
					cf_log_err(conf, "Failed recombining URL components");
					goto ldap_url_error;
				}
				inst->handle_config.server = talloc_asprintf_append(inst->handle_config.server,
										    "%s ", url);
				free(url);
			}
#  else
			/*
			 *	No LDAP initialize function.  Can't specify a scheme.
			 */
			if (ldap_url->lud_scheme &&
			    ((strcmp(ldap_url->lud_scheme, "ldaps") == 0) ||
			    (strcmp(ldap_url->lud_scheme, "ldapi") == 0) ||
			    (strcmp(ldap_url->lud_scheme, "cldap") == 0))) {
				cf_log_err(conf, "%s is not supported by linked libldap",
					      ldap_url->lud_scheme);
				return -1;
			}

			/*
			 *	URL port over-rides the configured
			 *	port.  But if there's no configured
			 *	port, we use the hard-coded default.
			 */
			if (set_port_maybe) {
				ldap_url->lud_port = inst->handle_config.port;
				if (!ldap_url->lud_port) ldap_url->lud_port = default_port;
			}

			inst->handle_config.server = talloc_asprintf_append(inst->handle_config.server, "%s:%i ",
									    ldap_url->lud_host ? ldap_url->lud_host :
									   			 "localhost",
									    ldap_url->lud_port);
#  endif
			/*
			 *	@todo We could set a few other top level
			 *	directives using the URL, like base_dn
			 *	and scope.
			 */
			ldap_free_urldesc(ldap_url);
		/*
		 *	We need to construct an LDAP URI
		 */
		} else
#endif	/* HAVE_LDAP_URL_PARSE && HAVE_LDAP_IS_LDAP_URL && LDAP_URL_DESC2STR */
		/*
		 *	If it's not an URL, or we don't have the functions necessary
		 *	to break apart the URL and recombine it, then just treat
		 *	server as a hostname.
		 */
		{
#ifdef HAVE_LDAP_INITIALIZE
			char	const *p;
			char	*q;
			int	port = 0;
			size_t	len;

			port = inst->handle_config.port;

			/*
			 *	We don't support URLs if the library didn't provide
			 *	URL parsing functions.
			 */
			if (strchr(value, '/')) {
			bad_server_fmt:
#ifdef LDAP_CAN_PARSE_URLS
				cf_log_err(conf, "Invalid 'server' entry, must be in format <server>[:<port>] or "
					      "an ldap URI (ldap|cldap|ldaps|ldapi)://<server>:<port>");
#else
				cf_log_err(conf, "Invalid 'server' entry, must be in format <server>[:<port>]");
#endif
				return -1;
			}

			p = strrchr(value, ':');
			if (p) {
				port = (int)strtol((p + 1), &q, 10);
				if ((p == value) || ((p + 1) == q) || (*q != '\0')) goto bad_server_fmt;
				len = p - value;
			} else {
				len = strlen(value);
			}
			if (port == 0) port = LDAP_PORT;

			inst->handle_config.server = talloc_asprintf_append(inst->handle_config.server,
									    "ldap://%.*s:%i ",
									    (int) len, value, port);
#else
			/*
			 *	ldap_init takes port, which can be overridden by :port so
			 *	we don't need to do any parsing here.
			 */
			inst->handle_config.server = talloc_asprintf_append(inst->handle_config.server, "%s ", value);
#endif
		}
	}

	/*
	 *	inst->handle_config.server be unset if connection pool sharing is used.
	 */
	if (inst->handle_config.server) {
		inst->handle_config.server[talloc_array_length(inst->handle_config.server) - 2] = '\0';
		DEBUG4("rlm_ldap (%s) - LDAP server string: %s", inst->name, inst->handle_config.server);
	}

#ifdef LDAP_OPT_X_TLS_NEVER
	/*
	 *	Workaround for servers which support LDAPS but not START TLS
	 */
	if (inst->handle_config.port == LDAPS_PORT || inst->handle_config.tls_mode) {
		inst->handle_config.tls_mode = LDAP_OPT_X_TLS_HARD;
	} else {
		inst->handle_config.tls_mode = 0;
	}
#endif

	/*
	 *	Convert dereference strings to enumerated constants
	 */
	if (inst->handle_config.dereference_str) {
		inst->handle_config.dereference = fr_table_value_by_str(fr_ldap_dereference,
							     inst->handle_config.dereference_str, -1);
		if (inst->handle_config.dereference < 0) {
			cf_log_err(conf, "Invalid 'dereference' value \"%s\", expected 'never', 'searching', "
				      "'finding' or 'always'", inst->handle_config.dereference_str);
			goto error;
		}
	}

#if !defined (LDAP_SET_REBIND_PROC_ARGS) || LDAP_SET_REBIND_PROC_ARGS != 3
	/*
	 *	The 2-argument rebind doesn't take an instance variable.  Our rebind function needs the instance
	 *	variable for the username, password, etc.
	 */
	if (inst->handle_config.rebind == true) {
		cf_log_err(conf, "Cannot use 'rebind' configuration item as this version of libldap "
			      "does not support the API that we need");

		goto error;
	}
#endif

	/*
	 *	Convert scope strings to enumerated constants
	 */
	inst->userobj_scope = fr_table_value_by_str(fr_ldap_scope, inst->userobj_scope_str, -1);
	if (inst->userobj_scope < 0) {
#ifdef LDAP_SCOPE_CHILDREN
		cf_log_err(conf, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one', 'base' or 'children'",
			   inst->userobj_scope_str);
#else
		cf_log_err(conf, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one' or 'children'",
			   inst->userobj_scope_str);
#endif
		goto error;
	}

	inst->groupobj_scope = fr_table_value_by_str(fr_ldap_scope, inst->groupobj_scope_str, -1);
	if (inst->groupobj_scope < 0) {
#ifdef LDAP_SCOPE_CHILDREN
		cf_log_err(conf, "Invalid 'group.scope' value \"%s\", expected 'sub', 'one', 'base' or 'children'",
			   inst->groupobj_scope_str);
#else
		cf_log_err(conf, "Invalid 'group.scope' value \"%s\", expected 'sub', 'one' or 'children'",
			   inst->groupobj_scope_str);
#endif

		goto error;
	}

#ifdef HAVE_LDAP_CREATE_SORT_CONTROL
	/*
	 *	Build the server side sort control for user objects
	 */
	if (inst->userobj_sort_by) {
		LDAPSortKey	**keys;
		int		ret;
		char		*p;

		memcpy(&p, &inst->userobj_sort_by, sizeof(p));

		ret = ldap_create_sort_keylist(&keys, p);
		if (ret != LDAP_SUCCESS) {
			cf_log_err(conf, "Invalid user.sort_by value \"%s\": %s",
				      inst->userobj_sort_by, ldap_err2string(ret));
			goto error;
		}

		/*
		 *	Always set the control as critical, if it's not needed
		 *	the user can comment it out...
		 */
		ret = ldap_create_sort_control(ldap_global_handle, keys, 1, &inst->userobj_sort_ctrl);
		ldap_free_sort_keylist(keys);
		if (ret != LDAP_SUCCESS) {
			ERROR("Failed creating server sort control: %s", ldap_err2string(ret));
			goto error;
		}
	}
#endif

	if (inst->handle_config.tls_require_cert_str) {
#ifdef LDAP_OPT_X_TLS_NEVER
		/*
		 *	Convert cert strictness to enumerated constants
		 */
		inst->handle_config.tls_require_cert = fr_table_value_by_str(fr_ldap_tls_require_cert,
							      inst->handle_config.tls_require_cert_str, -1);
		if (inst->handle_config.tls_require_cert < 0) {
			cf_log_err(conf, "Invalid 'tls.require_cert' value \"%s\", expected 'never', "
				      "'demand', 'allow', 'try' or 'hard'", inst->handle_config.tls_require_cert_str);
			goto error;
		}
#else
		cf_log_err(conf, "Modifying 'tls.require_cert' is not supported by current "
			      "version of libldap. Please upgrade or substitute current libldap and "
			      "rebuild this module");

		goto error;
#endif
	}

	/*
	 *	Build the attribute map
	 */
	{
		tmpl_rules_t	parse_rules = {
			.allow_foreign = true	/* Because we don't know where we'll be called */
		};

		update = cf_section_find(inst->cs, "update", NULL);
		if (update && (map_afrom_cs(inst, &inst->user_map, update,
					    &parse_rules, &parse_rules, fr_ldap_map_verify, NULL,
					    LDAP_MAX_ATTRMAP) < 0)) {
			return -1;
		}
	}

	/*
	 *	Set global options
	 */
	if (fr_ldap_init() < 0) goto error;

	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = module_connection_pool_init(inst->cs, &inst->handle_config,
						 ldap_mod_conn_create, NULL, NULL, NULL, NULL);
	if (!inst->pool) goto error;

	fr_ldap_global_config(inst->ldap_debug, inst->tls_random_file);

	return 0;

error:
	return -1;
}

static int mod_load(void)
{
	fr_ldap_init();

	return 0;
}

static void mod_unload(void)
{
	fr_ldap_free();;
}

/* globally exported name */
extern module_t rlm_ldap;
module_t rlm_ldap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "ldap",
	.type		= 0,
	.inst_size	= sizeof(rlm_ldap_t),
	.config		= module_config,
	.onload		= mod_load,
	.unload		= mod_unload,
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
