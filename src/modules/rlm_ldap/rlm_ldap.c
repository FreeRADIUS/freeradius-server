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
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @author Alan DeKok <aland@freeradius.org>
 *
 * @copyright 2012,2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013,2015 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2012 Alan DeKok <aland@freeradius.org>
 * @copyright 1999-2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include	<freeradius-devel/rad_assert.h>

#include	<stdarg.h>
#include	<ctype.h>

#include	"ldap.h"

/*
 *	Scopes
 */
FR_NAME_NUMBER const ldap_scope[] = {
	{ "sub",	LDAP_SCOPE_SUB	},
	{ "one",	LDAP_SCOPE_ONE	},
	{ "base",	LDAP_SCOPE_BASE },
#ifdef LDAP_SCOPE_CHILDREN
	{ "children",	LDAP_SCOPE_CHILDREN },
#endif
	{  NULL , -1 }
};

#ifdef LDAP_OPT_X_TLS_NEVER
FR_NAME_NUMBER const ldap_tls_require_cert[] = {
	{ "never",	LDAP_OPT_X_TLS_NEVER	},
	{ "demand",	LDAP_OPT_X_TLS_DEMAND	},
	{ "allow",	LDAP_OPT_X_TLS_ALLOW	},
	{ "try",	LDAP_OPT_X_TLS_TRY	},
	{ "hard",	LDAP_OPT_X_TLS_HARD	},	/* oh yes, just like that */

	{  NULL , -1 }
};
#endif

static FR_NAME_NUMBER const ldap_dereference[] = {
	{ "never",	LDAP_DEREF_NEVER	},
	{ "searching",	LDAP_DEREF_SEARCHING	},
	{ "finding",	LDAP_DEREF_FINDING	},
	{ "always",	LDAP_DEREF_ALWAYS	},

	{  NULL , -1 }
};

static CONF_PARSER sasl_mech_dynamic[] = {
	{ "mech", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL | PW_TYPE_NOT_EMPTY, ldap_sasl_dynamic, mech), NULL },
	{ "proxy", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, ldap_sasl_dynamic, proxy), NULL },
	{ "realm", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, ldap_sasl_dynamic, realm), NULL },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER sasl_mech_static[] = {
	{ "mech", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, ldap_sasl, mech), NULL },
	{ "proxy", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_sasl, proxy), NULL },
	{ "realm", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_sasl, realm), NULL },
	CONF_PARSER_TERMINATOR
};

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	/*
	 *	Deprecated attributes
	 */
	{ "cacertfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, rlm_ldap_t, tls_ca_file), NULL },
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_ldap_t, tls_ca_file), NULL },

	{ "cacertdir", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, rlm_ldap_t, tls_ca_path), NULL },
	{ "ca_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_ldap_t, tls_ca_path), NULL },

	{ "certfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, rlm_ldap_t, tls_certificate_file), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_ldap_t, tls_certificate_file), NULL },

	{ "keyfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, rlm_ldap_t, tls_private_key_file), NULL }, // OK if it changes on HUP
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_ldap_t, tls_private_key_file), NULL }, // OK if it changes on HUP

	{ "randfile", FR_CONF_OFFSET(PW_TYPE_FILE_EXISTS | PW_TYPE_DEPRECATED, rlm_ldap_t, tls_random_file), NULL },
	{ "random_file", FR_CONF_OFFSET(PW_TYPE_FILE_EXISTS, rlm_ldap_t, tls_random_file), NULL },

	/*
	 *	LDAP Specific TLS attributes
	 */
	{ "start_tls", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, start_tls), "no" },
	{ "require_cert", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, tls_require_cert_str), NULL },
	CONF_PARSER_TERMINATOR
};


static CONF_PARSER profile_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_ldap_t, profile_filter), "(&)" },	//!< Correct filter for when the DN is known.
	{ "attribute", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, profile_attr), NULL },
	{ "default", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_ldap_t, default_profile), NULL },
	CONF_PARSER_TERMINATOR
};

/*
 *	User configuration
 */
static CONF_PARSER user_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_ldap_t, userobj_filter), NULL },
	{ "scope", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, userobj_scope_str), "sub" },
	{ "base_dn", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_ldap_t, userobj_base_dn), "" },
	{ "sort_by", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, userobj_sort_by), NULL },

	{ "access_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, userobj_access_attr), NULL },
	{ "access_positive", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, access_positive), "yes" },

	/* Should be deprecated */
	{ "sasl", FR_CONF_OFFSET(PW_TYPE_SUBSECTION, rlm_ldap_t, user_sasl), (void const *) sasl_mech_dynamic },
	CONF_PARSER_TERMINATOR
};

/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, groupobj_filter), NULL },
	{ "scope", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, groupobj_scope_str), "sub" },
	{ "base_dn", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_ldap_t, groupobj_base_dn), "" },

	{ "name_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, groupobj_name_attr), "cn" },
	{ "membership_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, userobj_membership_attr), NULL },
	{ "membership_filter", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_ldap_t, groupobj_membership_filter), NULL },
	{ "cacheable_name", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, cacheable_group_name), "no" },
	{ "cacheable_dn", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, cacheable_group_dn), "no" },
	{ "cache_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, cache_attribute), NULL },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER client_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, clientobj_filter), NULL },
	{ "scope", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, clientobj_scope_str), "sub" },
	{ "base_dn", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, clientobj_base_dn), "" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, ldap_acct_section_t, reference), "." },
	CONF_PARSER_TERMINATOR
};

/*
 *	Various options that don't belong in the main configuration.
 *
 *	Note that these overlap a bit with the connection pool code!
 */
static CONF_PARSER option_config[] = {
	/*
	 *	Debugging flags to the server
	 */
	{ "ldap_debug", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, ldap_debug), "0x0000" },

	{ "dereference", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, dereference_str), NULL },

	{ "chase_referrals", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, chase_referrals), NULL },

	{ "rebind", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, rebind), NULL },

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/* timeout on network activity */
	{ "net_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, net_timeout), "10" },
#endif

	/* timeout for search results */
	{ "res_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, res_timeout), "20" },

	/* allow server unlimited time for search (server-side limit) */
	{ "srv_timelimit", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, srv_timelimit), "20" },

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{ "idle", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, keepalive_idle), "60" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{ "probes", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, keepalive_probes), "3" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	{ "interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_ldap_t, keepalive_interval), "30" },
#endif
	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER module_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_MULTI, rlm_ldap_t, config_server), NULL },	/* Do not set to required */
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, rlm_ldap_t, port), NULL },

	{ "identity", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, admin_identity), NULL },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, rlm_ldap_t, admin_password), NULL },

	{ "sasl", FR_CONF_OFFSET(PW_TYPE_SUBSECTION, rlm_ldap_t, admin_sasl), (void const *) sasl_mech_static },

	{ "valuepair_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_ldap_t, valuepair_attr), NULL },

#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{ "edir", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, edir), NULL }, /* NULL defaults to "no" */

	/*
	 *	Attempt to bind with the cleartext password we got from eDirectory
	 *	Universal password for additional authorization checks.
	 */
	{ "edir_autz", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, edir_autz), NULL }, /* NULL defaults to "no" */
#endif

	{ "read_clients", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_ldap_t, do_clients), NULL }, /* NULL defaults to "no" */

	{ "user", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) user_config },

	{ "group", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) group_config },

	{ "client", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) client_config },

	{ "profile", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) profile_config },

	{ "options", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) option_config },

	{ "tls", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) tls_config },
	CONF_PARSER_TERMINATOR
};

static ssize_t ldapquote_xlat(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	return rlm_ldap_escape_func(request, out, freespace, fmt, NULL);
}

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 */
static ssize_t ldap_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	ldap_rcode_t		status;
	size_t			len = 0;
	rlm_ldap_t		*inst = instance;

	LDAPURLDesc		*ldap_url;
	LDAPMessage		*result = NULL;
	LDAPMessage		*entry = NULL;

	struct berval		**values;

	ldap_handle_t		*conn;
	int			ldap_errno;

	char const		*url;
	char const		**attrs;

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

	status = rlm_ldap_search(&result, inst, request, &conn, ldap_url->lud_dn, ldap_url->lud_scope,
				 ldap_url->lud_filter, attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	default:
		goto free_socket;
	}

	rad_assert(conn);
	rad_assert(result);

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
		len = -1;
		goto free_result;
	}

	values = ldap_get_values_len(conn->handle, entry, ldap_url->lud_attrs[0]);
	if (!values) {
		RDEBUG("No \"%s\" attributes found in specified object", ldap_url->lud_attrs[0]);
		goto free_result;
	}

	if (values[0]->bv_len >= freespace) goto free_values;

	memcpy(out, values[0]->bv_val, values[0]->bv_len + 1);	/* +1 as strlcpy expects buffer size */
	len = values[0]->bv_len;

free_values:
	ldap_value_free_len(values);
free_result:
	ldap_msgfree(result);
free_socket:
	mod_conn_release(inst, conn);
free_urldesc:
	ldap_free_urldesc(ldap_url);

	return len;
}

/** Perform LDAP-Group comparison checking
 *
 * Attempts to match users to groups using a variety of methods.
 *
 * @param instance of the rlm_ldap module.
 * @param request Current request.
 * @param thing Unknown.
 * @param check Which group to check for user membership.
 * @param check_pairs Unknown.
 * @param reply_pairs Unknown.
 * @return
 *	- 1 on failure (or if the user is not a member).
 *	- 0 on success.
 */
static int rlm_ldap_groupcmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			     UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_ldap_t	*inst = instance;
	rlm_rcode_t	rcode;

	bool		found = false;
	bool		check_is_dn;

	ldap_handle_t	*conn = NULL;
	char const	*user_dn;

	rad_assert(inst->groupobj_base_dn);

	RDEBUG("Searching for user in group \"%s\"", check->vp_strvalue);

	if (check->vp_length == 0) {
		REDEBUG("Cannot do comparison (group name is empty)");
		return 1;
	}

	/*
	 *	Check if we can do cached membership verification
	 */
	check_is_dn = rlm_ldap_is_dn(check->vp_strvalue, check->vp_length);
	if (check_is_dn) {
		char *norm;

		MEM(norm = talloc_memdup(check, check->vp_strvalue, talloc_array_length(check->vp_strvalue)));
		rlm_ldap_normalise_dn(norm, check->vp_strvalue);
		fr_pair_value_strsteal(check, norm);
	}
	if ((check_is_dn && inst->cacheable_group_dn) || (!check_is_dn && inst->cacheable_group_name)) {
		switch (rlm_ldap_check_cached(inst, request, check)) {
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
		mod_conn_release(inst, conn);
		return 1;
	}

	rad_assert(conn);

	/*
	 *	Check groupobj user membership
	 */
	if (inst->groupobj_membership_filter) {
		switch (rlm_ldap_check_groupobj_dynamic(inst, request, &conn, check)) {
		case RLM_MODULE_NOTFOUND:
			break;

		case RLM_MODULE_OK:
			found = true;

		default:
			goto finish;
		}
	}

	rad_assert(conn);

	/*
	 *	Check userobj group membership
	 */
	if (inst->userobj_membership_attr) {
		switch (rlm_ldap_check_userobj_dynamic(inst, request, &conn, user_dn, check)) {
		case RLM_MODULE_NOTFOUND:
			break;

		case RLM_MODULE_OK:
			found = true;

		default:
			goto finish;
		}
	}

	rad_assert(conn);

finish:
	if (conn) mod_conn_release(inst, conn);

	if (!found) {
		RDEBUG("User is not a member of \"%s\"", check->vp_strvalue);

		return 1;
	}

	return 0;
}

/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int mod_detach(void *instance)
{
	rlm_ldap_t *inst = instance;

	fr_connection_pool_free(inst->pool);

	if (inst->user_map) {
		talloc_free(inst->user_map);
	}

	/*
	 *	Keeping the dummy ld around for the lifetime
	 *	of the module should always work,
	 *	irrespective of what changes happen in libldap.
	 */
	if (inst->handle) {
#ifdef HAVE_LDAP_UNBIND_EXT_S
		ldap_unbind_ext_s(inst->handle, NULL, NULL);
#else
		ldap_unbind_s(inst->handle);
#endif
	}

#ifdef HAVE_LDAP_CREATE_SORT_CONTROL
	if (inst->userobj_sort_ctrl) ldap_control_free(inst->userobj_sort_ctrl);
#endif

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

	char const *name = section_type_value[comp].section;

	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		DEBUG2("rlm_ldap (%s): Couldn't find configuration for %s, will return NOOP for calls "
		       "from this section", inst->name, name);

		return 0;
	}

	*config = talloc_zero(inst, ldap_acct_section_t);
	if (cf_section_parse(cs, *config, acct_section_config) < 0) {
		LDAP_ERR("Failed parsing configuration for section %s", name);

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
static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_ldap_t *inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	/*
	 *	Group comparison checks.
	 */
	if (cf_section_name2(conf)) {
		char buffer[256];

		snprintf(buffer, sizeof(buffer), "%s-LDAP-Group", inst->name);

		if (paircompare_register_byname(buffer, dict_attrbyvalue(PW_USER_NAME, 0), false, rlm_ldap_groupcmp, inst) < 0) {
			LDAP_ERR("Error registering group comparison: %s", fr_strerror());
			goto error;
		}

		inst->group_da = dict_attrbyname(buffer);

		/*
		 *	We're the default instance
		 */
	} else {
		if (paircompare_register_byname("LDAP-Group", dict_attrbyvalue(PW_USER_NAME, 0),
						false, rlm_ldap_groupcmp, inst) < 0) {
			LDAP_ERR("Error registering group comparison: %s", fr_strerror());
			goto error;
		}

		inst->group_da = dict_attrbyname("LDAP-Group");
	}

	/*
	 *	Setup the cache attribute
	 */
	if (inst->cache_attribute) {
		ATTR_FLAGS flags;

		memset(&flags, 0, sizeof(flags));
		if (dict_addattr(inst->cache_attribute, -1, 0, PW_TYPE_STRING, flags) < 0) {
			LDAP_ERR("Error creating cache attribute: %s", fr_strerror());
		error:
			return -1;

		}
		inst->cache_da = dict_attrbyname(inst->cache_attribute);
	} else {
		inst->cache_da = inst->group_da;	/* Default to the group_da */
	}

	xlat_register(inst->name, ldap_xlat, rlm_ldap_escape_func, inst);
	xlat_register("ldapquote", ldapquote_xlat, NULL, inst);

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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	static bool	version_done;

	CONF_PAIR	*cp;
	CONF_ITEM	*ci;

	CONF_SECTION *options, *update;
	rlm_ldap_t *inst = instance;

	inst->cs = conf;

	options = cf_section_sub_find(conf, "options");
	if (!options || !cf_pair_find(options, "chase_referrals")) {
		inst->chase_referrals_unset = true;	 /* use OpenLDAP defaults */
	}

	/*
	 *	Only needs to be done once, prevents races in environment
	 *	initialisation within libldap.
	 *
	 *	See: https://github.com/arr2036/ldapperf/issues/2
	 */
#ifdef HAVE_LDAP_INITIALIZE
	ldap_initialize(&inst->handle, "");
#else
	inst->handle = ldap_init("", 0);
#endif

	/*
	 *	Get version info from the LDAP API.
	 */
	if (!version_done) {
		static LDAPAPIInfo info = { .ldapai_info_version = LDAP_API_INFO_VERSION };	/* static to quiet valgrind about this being uninitialised */
		int ldap_errno;

		version_done = true;

		ldap_errno = ldap_get_option(NULL, LDAP_OPT_API_INFO, &info);
		if (ldap_errno == LDAP_OPT_SUCCESS) {
			int i;

			/*
			 *	Don't generate warnings if the compile type vendor name
			 *	is found within the link time vendor name.
			 *
			 *	This allows the server to be built against OpenLDAP but
			 *	run with Symas OpenLDAP.
			 */
			if (strcasestr(info.ldapai_vendor_name, LDAP_VENDOR_NAME) == NULL) {
				WARN("rlm_ldap: libldap vendor changed since the server was built");
				WARN("rlm_ldap: linked: %s, built: %s", info.ldapai_vendor_name, LDAP_VENDOR_NAME);
			}

			if (info.ldapai_vendor_version < LDAP_VENDOR_VERSION) {
				WARN("rlm_ldap: libldap older than the version the server was built against");
				WARN("rlm_ldap: linked: %i, built: %i",
				     info.ldapai_vendor_version, LDAP_VENDOR_VERSION);
			}

			INFO("rlm_ldap: libldap vendor: %s, version: %i", info.ldapai_vendor_name,
			     info.ldapai_vendor_version);

			if (info.ldapai_extensions != NULL ) {
				for ( i = 0; info.ldapai_extensions[i] != NULL; i++) {
					ldap_memfree(info.ldapai_extensions[i]);
				}
				ldap_memfree(info.ldapai_extensions);
			}
			ldap_memfree(info.ldapai_vendor_name);
		} else {
			DEBUG("rlm_ldap: Falling back to build time libldap version info.  Query for LDAP_OPT_API_INFO "
			      "returned: %i", ldap_errno);
			INFO("rlm_ldap: libldap vendor: %s, version: %i.%i.%i", LDAP_VENDOR_NAME,
			     LDAP_VENDOR_VERSION_MAJOR, LDAP_VENDOR_VERSION_MINOR, LDAP_VENDOR_VERSION_PATCH);
		}
	}

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((parse_sub_section(inst, conf, &inst->accounting, MOD_ACCOUNTING) < 0) ||
	    (parse_sub_section(inst, conf, &inst->postauth, MOD_POST_AUTH) < 0)) {
		cf_log_err_cs(conf, "Failed parsing configuration");

		goto error;
	}

	/*
	 *	Sanity checks for cacheable groups code.
	 */
	if (inst->cacheable_group_name && inst->groupobj_membership_filter) {
		if (!inst->groupobj_name_attr) {
			cf_log_err_cs(conf, "Configuration item 'group.name_attribute' must be set if cacheable "
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
		if (!inst->config_server) {
			cf_log_err_cs(conf, "Configuration item 'server' must have a value");
			goto error;
		}
	}

#ifndef WITH_SASL
	if (inst->user_sasl.mech) {
		cf_log_err_cs(conf, "Configuration item 'user.sasl.mech' not supported.  "
			      "Linked libldap does not provide ldap_sasl_bind function");
		goto error;
	}

	if (inst->admin_sasl.mech) {
		cf_log_err_cs(conf, "Configuration item 'sasl.mech' not supported.  "
			      "Linked libldap does not provide ldap_sasl_interactive_bind function");
		goto error;
	}
#endif

#ifndef HAVE_LDAP_CREATE_SORT_CONTROL
	if (inst->userobj_sort_by) {
		cf_log_err_cs(conf, "Configuration item 'sort_by' not supported.  "
			      "Linked libldap does not provide ldap_create_sort_control function");
		goto error;
	}
#endif

	/*
	 *	For backwards compatibility hack up the first 'server'
	 *	CONF_ITEM into chunks, and add them back into the config.
	 *
	 *	@fixme this should be removed at some point.
	 */
	if (inst->config_server) {
		char const	*value;
		char const	*p;
		char const	*q;
		char		*buff;

		bool		done = false;
		bool		first = true;

		cp = cf_pair_find(conf, "server");
		if (!cp) {
			cf_log_err_cs(conf, "Configuration item 'server' must have a value");
			return -1;
		}

		value = cf_pair_value(cp);

		p = value;
		q = p;
		while (!done) {
			switch (*q) {
			case '\0':
				done = true;
				if (p == value) break;	/* string contained no separators */

				/* FALL-THROUGH */

			case ',':
			case ';':
			case ' ':
				while (isspace((int) *p)) p++;
				if (p == q) continue;

				buff = talloc_array(inst, char, (q - p) + 1);
				strlcpy(buff, p, talloc_array_length(buff));
				p = ++q;

				if (first) {
					WARN("Listing multiple LDAP servers in the 'server' configuration item "
					     "is deprecated and will be removed in a future release.  "
					     "Use multiple 'server' configuration items instead");
					WARN("- server = '%s'", value);
				}
				WARN("+ server = '%s'", buff);

				/*
				 *	For the first instance of server we find, just replace
				 *	the existing "server" config item.
				 */
				if (first) {
					cf_pair_replace(conf, cp, buff);
					first = false;
					continue;
				}

				/*
				 *	For subsequent instances we need to add new conf pairs.
				 */
				cp = cf_pair_alloc(conf, "server", buff, T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
				if (!cp) return -1;

				ci = cf_pair_to_item(cp);
				cf_item_add(conf, ci);

				break;

			default:
				q++;
				continue;
			}
		}
	}

	/*
	 *	Now iterate over all the 'server' config items
	 */
	if (!inst->server) inst->server = talloc_strdup(inst, "");
	for (cp = cf_pair_find(conf, "server");
	     cp;
	     cp = cf_pair_find_next(conf, cp, "server")) {
	     	char const *value;

		value = cf_pair_value(cp);

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
				cf_log_err_cs(conf, "Parsing LDAP URL \"%s\" failed", value);
			ldap_url_error:
				ldap_free_urldesc(ldap_url);
				return -1;
			}

			if (ldap_url->lud_dn && (ldap_url->lud_dn[0] != '\0')) {
				cf_log_err_cs(conf, "Base DN cannot be specified via server URL");
				goto ldap_url_error;
			}

			if (ldap_url->lud_attrs && ldap_url->lud_attrs[0]) {
				cf_log_err_cs(conf, "Attribute list cannot be specified via server URL");
				goto ldap_url_error;
			}

			/*
			 *	ldap_url_parse sets this to base by default.
			 */
			if (ldap_url->lud_scope != LDAP_SCOPE_BASE) {
				cf_log_err_cs(conf, "Scope cannot be specified via server URL");
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
			} else if ((p = strchr(value, ':')) && (p = strchr(p + 1, ':'))) {	/* IPv4 */
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
						if (inst->start_tls == true) {
							cf_log_err_cs(conf, "ldaps:// scheme is not compatible "
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
					ldap_url->lud_port = inst->port;

					/*
					 *	If there's no URL port, then set it to the default
					 *	this is so debugging messages show explicitly
					 *	the port we're connecting to.
					 */
					if (!ldap_url->lud_port) ldap_url->lud_port = default_port;
				}

				url = ldap_url_desc2str(ldap_url);
				if (!url) {
					cf_log_err_cs(conf, "Failed recombining URL components");
					goto ldap_url_error;
				}
				inst->server = talloc_asprintf_append(inst->server, "%s ", url);
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
				cf_log_err_cs(conf, "%s is not supported by linked libldap",
					      ldap_url->lud_scheme);
				return -1;
			}

			/*
			 *	URL port over-rides the configured
			 *	port.  But if there's no configured
			 *	port, we use the hard-coded default.
			 */
			if (set_port_maybe) {
				ldap_url->lud_port = inst->port;
				if (!ldap_url->lud_port) ldap_url->lud_port = default_port;
			}

			inst->server = talloc_asprintf_append(inst->server, "%s:%i ",
							      ldap_url->lud_host ? ldap_url->lud_host : "localhost",
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

			port = inst->port;

			/*
			 *	We don't support URLs if the library didn't provide
			 *	URL parsing functions.
			 */
			if (strchr(value, '/')) {
			bad_server_fmt:
#ifdef LDAP_CAN_PARSE_URLS
				cf_log_err_cp(cp, "Invalid server value, must be in format <server>[:<port>] or "
					      "an ldap URI (ldap|cldap|ldaps|ldapi)://<server>:<port>");
#else
				cf_log_err_cp(cp, "Invalid server value, must be in format <server>[:<port>]");
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

			inst->server = talloc_asprintf_append(inst->server, "ldap://%.*s:%i ", (int) len, value, port);
#else
			/*
			 *	ldap_init takes port, which can be overridden by :port so
			 *	we don't need to do any parsing here.
			 */
			inst->server = talloc_asprintf_append(inst->server, "%s ", value);
#endif
		}
	}
	if (inst->server) inst->server[talloc_array_length(inst->server) - 2] = '\0';

	DEBUG4("LDAP server string: %s", inst->server);

#ifdef LDAP_OPT_X_TLS_NEVER
	/*
	 *	Workaround for servers which support LDAPS but not START TLS
	 */
	if (inst->port == LDAPS_PORT || inst->tls_mode) {
		inst->tls_mode = LDAP_OPT_X_TLS_HARD;
	} else {
		inst->tls_mode = 0;
	}
#endif

	/*
	 *	Convert dereference strings to enumerated constants
	 */
	if (inst->dereference_str) {
		inst->dereference = fr_str2int(ldap_dereference, inst->dereference_str, -1);
		if (inst->dereference < 0) {
			cf_log_err_cs(conf, "Invalid 'dereference' value \"%s\", expected 'never', 'searching', "
				      "'finding' or 'always'", inst->dereference_str);
			goto error;
		}
	}

#if LDAP_SET_REBIND_PROC_ARGS != 3
	/*
	 *	The 2-argument rebind doesn't take an instance variable.  Our rebind function needs the instance
	 *	variable for the username, password, etc.
	 */
	if (inst->rebind == true) {
		cf_log_err_cs(conf, "Cannot use 'rebind' configuration item as this version of libldap "
			      "does not support the API that we need");

		goto error;
	}
#endif

	/*
	 *	Convert scope strings to enumerated constants
	 */
	inst->userobj_scope = fr_str2int(ldap_scope, inst->userobj_scope_str, -1);
	if (inst->userobj_scope < 0) {
		cf_log_err_cs(conf, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one'"
#ifdef LDAP_SCOPE_CHILDREN
			      ", 'base' or 'children'"
#else
			      " or 'base'"
#endif
			 , inst->userobj_scope_str);
		goto error;
	}

	inst->groupobj_scope = fr_str2int(ldap_scope, inst->groupobj_scope_str, -1);
	if (inst->groupobj_scope < 0) {
		cf_log_err_cs(conf, "Invalid 'group.scope' value \"%s\", expected 'sub', 'one'"
#ifdef LDAP_SCOPE_CHILDREN
			      ", 'base' or 'children'"
#else
			      " or 'base'"
#endif
			 , inst->groupobj_scope_str);
		goto error;
	}

	inst->clientobj_scope = fr_str2int(ldap_scope, inst->clientobj_scope_str, -1);
	if (inst->clientobj_scope < 0) {
		cf_log_err_cs(conf, "Invalid 'client.scope' value \"%s\", expected 'sub', 'one'"
#ifdef LDAP_SCOPE_CHILDREN
			      ", 'base' or 'children'"
#else
			      " or 'base'"
#endif
			 , inst->clientobj_scope_str);
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
			cf_log_err_cs(conf, "Invalid user.sort_by value \"%s\": %s",
				      inst->userobj_sort_by, ldap_err2string(ret));
			goto error;
		}

		/*
		 *	Always set the control as critical, if it's not needed
		 *	the user can comment it out...
		 */
		ret = ldap_create_sort_control(inst->handle, keys, 1, &inst->userobj_sort_ctrl);
		ldap_free_sort_keylist(keys);
		if (ret != LDAP_SUCCESS) {
			LDAP_ERR("Failed creating server sort control: %s", ldap_err2string(ret));
			goto error;
		}
	}
#endif

	if (inst->tls_require_cert_str) {
#ifdef LDAP_OPT_X_TLS_NEVER
		/*
		 *	Convert cert strictness to enumerated constants
		 */
		inst->tls_require_cert = fr_str2int(ldap_tls_require_cert, inst->tls_require_cert_str, -1);
		if (inst->tls_require_cert < 0) {
			cf_log_err_cs(conf, "Invalid 'tls.require_cert' value \"%s\", expected 'never', "
				      "'demand', 'allow', 'try' or 'hard'", inst->tls_require_cert_str);
			goto error;
		}
#else
		cf_log_err_cs(conf, "Modifying 'tls.require_cert' is not supported by current "
			      "version of libldap. Please upgrade or substitute current libldap and "
			      "rebuild this module");

		goto error;
#endif
	}

	/*
	 *	Build the attribute map
	 */
	update = cf_section_sub_find(inst->cs, "update");
	if (update && (map_afrom_cs(&inst->user_map, update,
				    PAIR_LIST_REPLY, PAIR_LIST_REQUEST, rlm_ldap_map_verify, inst,
				    LDAP_MAX_ATTRMAP) < 0)) {
		return -1;
	}

	/*
	 *	Set global options
	 */
	if (rlm_ldap_global_init(inst) < 0) goto error;

	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = fr_connection_pool_module_init(inst->cs, inst, mod_conn_create, NULL, NULL);
	if (!inst->pool) goto error;

	/*
	 *	Bulk load dynamic clients.
	 */
	if (inst->do_clients) {
		CONF_SECTION *cs, *map, *tmpl;

		cs = cf_section_sub_find(inst->cs, "client");
		if (!cs) {
			cf_log_err_cs(conf, "Told to load clients but no client section found");
			goto error;
		}

		map = cf_section_sub_find(cs, "attribute");
		if (!map) {
			cf_log_err_cs(cs, "Told to load clients but no attribute section found");
			goto error;
		}

		tmpl = cf_section_sub_find(cs, "template");

		if (rlm_ldap_client_load(inst, tmpl, map) < 0) {
			cf_log_err_cs(cs, "Error loading clients");

			return -1;
		}
	}

	return 0;

error:
	return -1;
}

static rlm_rcode_t mod_authenticate(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_rcode_t	rcode;
	ldap_rcode_t	status;
	char const	*dn;
	rlm_ldap_t	*inst = instance;
	ldap_handle_t	*conn;

	char		sasl_mech_buff[LDAP_MAX_DN_STR_LEN];
	char		sasl_proxy_buff[LDAP_MAX_DN_STR_LEN];
	char		sasl_realm_buff[LDAP_MAX_DN_STR_LEN];
	ldap_sasl	sasl;

	/*
	 * Ensure that we're being passed a plain-text password, and not
	 * anything else.
	 */

	if (!request->username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");

		return RLM_MODULE_INVALID;
	}

	if (!request->password ||
	    (request->password->da->attr != PW_USER_PASSWORD)) {
		RWDEBUG("You have set \"Auth-Type := LDAP\" somewhere");
		RWDEBUG("*********************************************");
		RWDEBUG("* THAT CONFIGURATION IS WRONG.  DELETE IT.   ");
		RWDEBUG("* YOU ARE PREVENTING THE SERVER FROM WORKING");
		RWDEBUG("*********************************************");

		REDEBUG("Attribute \"User-Password\" is required for authentication");

		return RLM_MODULE_INVALID;
	}

	if (request->password->vp_length == 0) {
		REDEBUG("Empty password supplied");

		return RLM_MODULE_INVALID;
	}

	conn = mod_conn_get(inst, request);
	if (!conn) return RLM_MODULE_FAIL;

	/*
	 *	Expand dynamic SASL fields
	 */
	if (conn->inst->user_sasl.mech) {
		memset(&sasl, 0, sizeof(sasl));

		if (tmpl_expand(&sasl.mech, sasl_mech_buff, sizeof(sasl_mech_buff), request,
				conn->inst->user_sasl.mech, rlm_ldap_escape_func, inst) < 0) {
			REDEBUG("Failed expanding user.sasl.mech: %s", fr_strerror());
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		if (conn->inst->user_sasl.proxy) {
			if (tmpl_expand(&sasl.proxy, sasl_proxy_buff, sizeof(sasl_proxy_buff), request,
					conn->inst->user_sasl.proxy, rlm_ldap_escape_func, inst) < 0) {
				REDEBUG("Failed expanding user.sasl.proxy: %s", fr_strerror());
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}

		if (conn->inst->user_sasl.realm) {
			if (tmpl_expand(&sasl.realm, sasl_realm_buff, sizeof(sasl_realm_buff), request,
					conn->inst->user_sasl.realm, rlm_ldap_escape_func, inst) < 0) {
				REDEBUG("Failed expanding user.sasl.realm: %s", fr_strerror());
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}
	}

	RDEBUG("Login attempt by \"%s\"", request->username->vp_strvalue);

	/*
	 *	Get the DN by doing a search.
	 */
	dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!dn) {
		mod_conn_release(inst, conn);

		return rcode;
	}
	conn->rebound = true;
	status = rlm_ldap_bind(inst, request, &conn, dn, request->password->vp_strvalue,
			       conn->inst->user_sasl.mech ? &sasl : NULL, true);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		rcode = RLM_MODULE_OK;
		RDEBUG("Bind as user \"%s\" was successful", dn);
		break;

	case LDAP_PROC_NOT_PERMITTED:
		rcode = RLM_MODULE_USERLOCK;
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
	mod_conn_release(inst, conn);

	return rcode;
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common sets of attributes
 * to the request.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn of profile object to apply.
 * @param[in] expanded Structure containing a list of xlat expanded attribute names and mapping information.
 * @return One of the RLM_MODULE_* values.
 */
static rlm_rcode_t rlm_ldap_map_profile(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					char const *dn, rlm_ldap_map_exp_t const *expanded)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	ldap_rcode_t	status;
	LDAPMessage	*result = NULL, *entry = NULL;
	int		ldap_errno;
	LDAP		*handle = (*pconn)->handle;
	char const	*filter;
	char		filter_buff[LDAP_MAX_FILTER_STR_LEN];

	rad_assert(inst->profile_filter); 	/* We always have a default filter set */

	if (!dn || !*dn) return RLM_MODULE_OK;

	if (tmpl_expand(&filter, filter_buff, sizeof(filter_buff), request,
			inst->profile_filter, rlm_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating profile filter");

		return RLM_MODULE_INVALID;
	}

	status = rlm_ldap_search(&result, inst, request, pconn, dn,
				 LDAP_SCOPE_BASE, filter, expanded->attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_BAD_DN:
	case LDAP_PROC_NO_RESULT:
		RDEBUG("Profile object \"%s\" not found", dn);
		return RLM_MODULE_NOTFOUND;

	default:
		return RLM_MODULE_FAIL;
	}

	rad_assert(*pconn);
	rad_assert(result);

	entry = ldap_first_entry(handle, result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_NOTFOUND;

		goto free_result;
	}

	RDEBUG("Processing profile attributes");
	if (rlm_ldap_map_do(inst, request, handle, expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;

free_result:
	ldap_msgfree(result);

	return rcode;
}

static rlm_rcode_t mod_authorize(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	ldap_rcode_t		status;
	int			ldap_errno;
	int			i;
	rlm_ldap_t		*inst = instance;
	struct berval		**values;
	VALUE_PAIR		*vp;
	ldap_handle_t		*conn;
	LDAPMessage		*result, *entry;
	char const 		*dn = NULL;
	rlm_ldap_map_exp_t	expanded; /* faster than mallocing every time */

	/*
	 *	Don't be tempted to add a check for request->username
	 *	or request->password here. rlm_ldap.authorize can be used for
	 *	many things besides searching for users.
	 */

	if (rlm_ldap_map_expand(&expanded, request, inst->user_map) < 0) return RLM_MODULE_FAIL;

	conn = mod_conn_get(inst, request);
	if (!conn) return RLM_MODULE_FAIL;

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
			rcode = rlm_ldap_cacheable_userobj(inst, request, &conn, entry, inst->userobj_membership_attr);
			if (rcode != RLM_MODULE_OK) {
				goto finish;
			}
		}

		rcode = rlm_ldap_cacheable_groupobj(inst, request, &conn);
		if (rcode != RLM_MODULE_OK) {
			goto finish;
		}
	}

#ifdef WITH_EDIR
	/*
	 *	We already have a Cleartext-Password.  Skip edir.
	 */
	if (fr_pair_find_by_num(request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) {
		goto skip_edir;
	}

	/*
	 *      Retrieve Universal Password if we use eDirectory
	 */
	if (inst->edir) {
		int res = 0;
		char password[256];
		size_t pass_size = sizeof(password);

		/*
		 *	Retrive universal password
		 */
		res = nmasldap_get_password(conn->handle, dn, password, &pass_size);
		if (res != 0) {
			REDEBUG("Failed to retrieve eDirectory password: (%i) %s", res, edir_errstr(res));
			rcode = RLM_MODULE_FAIL;

			goto finish;
		}

		/*
		 *	Add Cleartext-Password attribute to the request
		 */
		vp = radius_pair_create(request, &request->config, PW_CLEARTEXT_PASSWORD, 0);
		fr_pair_value_strcpy(vp, password);
		vp->vp_length = pass_size;

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Added eDirectory password.  control:%s += '%s'", vp->da->name, vp->vp_strvalue);
		} else {
			RDEBUG2("Added eDirectory password");
		}

		if (inst->edir_autz) {
			RDEBUG2("Binding as user for eDirectory authorization checks");
			/*
			 *	Bind as the user
			 */
			conn->rebound = true;
			status = rlm_ldap_bind(inst, request, &conn, dn, vp->vp_strvalue, NULL, true);
			switch (status) {
			case LDAP_PROC_SUCCESS:
				rcode = RLM_MODULE_OK;
				RDEBUG("Bind as user '%s' was successful", dn);
				break;

			case LDAP_PROC_NOT_PERMITTED:
				rcode = RLM_MODULE_USERLOCK;
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
		char const *profile;
		char profile_buff[1024];

		if (tmpl_expand(&profile, profile_buff, sizeof(profile_buff),
				request, inst->default_profile, NULL, NULL) < 0) {
			REDEBUG("Failed creating default profile string");

			rcode = RLM_MODULE_INVALID;
			goto finish;
		}

		switch (rlm_ldap_map_profile(inst, request, &conn, profile, &expanded)) {
		case RLM_MODULE_INVALID:
			rcode = RLM_MODULE_INVALID;
			goto finish;

		case RLM_MODULE_FAIL:
			rcode = RLM_MODULE_FAIL;
			goto finish;

		case RLM_MODULE_UPDATED:
			rcode = RLM_MODULE_UPDATED;
			/* FALL-THROUGH */
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

				value = rlm_ldap_berval_to_string(request, values[i]);
				ret = rlm_ldap_map_profile(inst, request, &conn, value, &expanded);
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
		RDEBUG("Processing user attributes");
		if (rlm_ldap_map_do(inst, request, conn->handle, &expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
		rlm_ldap_check_reply(inst, request);
	}

finish:
	talloc_free(expanded.ctx);
	if (result) ldap_msgfree(result);
	mod_conn_release(inst, conn);

	return rcode;
}

/** Modify user's object in LDAP
 *
 * Process a modifcation map to update a user object in the LDAP directory.
 *
 * @param inst rlm_ldap instance.
 * @param request Current request.
 * @param section that holds the map to process.
 * @return one of the RLM_MODULE_* values.
 */
static rlm_rcode_t user_modify(rlm_ldap_t *inst, REQUEST *request, ldap_acct_section_t *section)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	ldap_rcode_t	status;

	ldap_handle_t	*conn = NULL;

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
	FR_TOKEN	op;
	char		path[MAX_STRING_LEN];

	char		*p = path;

	rad_assert(section);

	/*
	 *	Locate the update section were going to be using
	 */
	if (section->reference[0] != '.') {
		*p++ = '.';
	}

	if (radius_xlat(p, (sizeof(path) - (p - path)) - 1, request, section->reference, NULL, NULL) < 0) {
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

	cs = cf_section_sub_find(cf_item_to_section(ci), "update");
	if (!cs) {
		REDEBUG("Section must contain 'update' subsection");

		goto error;
	}

	/*
	 *	Iterate over all the pairs, building our mods array
	 */
	for (ci = cf_item_find_next(cs, NULL); ci != NULL; ci = cf_item_find_next(cs, ci)) {
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
			RDEBUG("Empty value string, skipping attribute \"%s\"", attr);

			continue;
		}

		switch (cf_pair_value_type(cp)) {
		case T_BARE_WORD:
		case T_SINGLE_QUOTED_STRING:
			break;

		case T_BACK_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			do_xlat = true;
			break;

		default:
			rad_assert(0);
			goto error;
		}

		if (op == T_OP_CMP_FALSE) {
			passed[last_pass] = NULL;
		} else if (do_xlat) {
			char *exp = NULL;

			if (radius_axlat(&exp, request, value, NULL, NULL) <= 0) {
				RDEBUG("Skipping attribute \"%s\"", attr);

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
				fr_int2str(fr_tokens, op, "<INVALID>"));

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
	if (!conn) return RLM_MODULE_FAIL;


	dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!dn || (rcode != RLM_MODULE_OK)) {
		goto error;
	}

	status = rlm_ldap_modify(inst, request, &conn, dn, modify);
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
	for (i = 0; i < last_exp; i++) {
		talloc_free(expanded[i]);
	}

	mod_conn_release(inst, conn);

	return rcode;
}

static rlm_rcode_t mod_accounting(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_accounting(void *instance, REQUEST *request)
{
	rlm_ldap_t *inst = instance;

	if (inst->accounting) return user_modify(inst, request, inst->accounting);

	return RLM_MODULE_NOOP;
}

static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_ldap_t *inst = instance;

	if (inst->postauth) {
		return user_modify(inst, request, inst->postauth);
	}

	return RLM_MODULE_NOOP;
}


/* globally exported name */
extern module_t rlm_ldap;
module_t rlm_ldap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "ldap",
	.inst_size	= sizeof(rlm_ldap_t),
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
