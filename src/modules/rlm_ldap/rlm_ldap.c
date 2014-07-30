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
 * @file rlm_ldap.c
 * @brief LDAP authorization and authentication module.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @author Alan DeKok <aland@freeradius.org>
 *
 * @copyright 2013 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2012-2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
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

FR_NAME_NUMBER const ldap_dereference[] = {
	{ "never",	LDAP_DEREF_NEVER	},
	{ "searching",	LDAP_DEREF_SEARCHING	},
	{ "finding",	LDAP_DEREF_FINDING	},
	{ "always",	LDAP_DEREF_ALWAYS	},

	{  NULL , -1 }
};

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	/*
	 *	Deprecated attributes
	 */
	{ "cacertfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, ldap_instance_t, tls_ca_file), NULL },
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, ldap_instance_t, tls_ca_file), NULL },

	{ "cacertdir", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, ldap_instance_t, tls_ca_path), NULL },
	{ "ca_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, ldap_instance_t, tls_ca_path), NULL },

	{ "certfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, ldap_instance_t, tls_certificate_file), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, ldap_instance_t, tls_certificate_file), NULL },

	{ "keyfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, ldap_instance_t, tls_private_key_file), NULL }, // OK if it changes on HUP
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, ldap_instance_t, tls_private_key_file), NULL }, // OK if it changes on HUP

	{ "randfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, ldap_instance_t, tls_random_file), NULL },
	{ "random_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, ldap_instance_t, tls_random_file), NULL },

	/*
	 *	LDAP Specific TLS attributes
	 */
	{ "start_tls", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, start_tls), "no" },
	{ "require_cert", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, tls_require_cert_str), NULL },

	{ NULL, -1, 0, NULL, NULL }
};


static CONF_PARSER profile_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, profile_filter), "(&)" },	//!< Correct filter for
												//!< when the DN is
												//!< known.
	{ "attribute", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, profile_attr), NULL },
	{ "default", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, default_profile), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	User configuration
 */
static CONF_PARSER user_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, userobj_filter), "(uid=%u)" },
	{ "scope", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, userobj_scope_str), "sub" },
	{ "base_dn", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, userobj_base_dn), "" },

	{ "access_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, userobj_access_attr), NULL },
	{ "access_positive", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, access_positive), "yes" },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, groupobj_filter), NULL },
	{ "scope", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, groupobj_scope_str), "sub" },
	{ "base_dn", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, groupobj_base_dn), "" },

	{ "name_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, groupobj_name_attr), "cn" },
	{ "membership_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, userobj_membership_attr), NULL },
	{ "membership_filter", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, groupobj_membership_filter), NULL },
	{ "cacheable_name", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, cacheable_group_name), "no" },
	{ "cacheable_dn", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, cacheable_group_dn), "no" },
	{ "cache_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, cache_attribute), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Client configuration
 */
static CONF_PARSER client_attribute[] = {
	{ "identifier", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_identifier), "host" },
	{ "shortname", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_shortname), "cn" },
	{ "nas_type", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_type), NULL },
	{ "secret", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_secret), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_server), NULL },
	{ "require_message_authenticator", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_require_ma), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

static CONF_PARSER client_config[] = {
	{ "filter", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_filter), NULL },
	{ "scope", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_scope_str), "sub" },
	{ "base_dn", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, clientobj_base_dn), "" },
	{ "attribute", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) client_attribute },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_acct_section_t, reference), "." },

	{NULL, -1, 0, NULL, NULL}
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
	{ "ldap_debug", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, ldap_debug), "0x0000" },

	{ "dereference", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, dereference_str), NULL },

	{ "chase_referrals", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, chase_referrals), NULL },

	{ "rebind", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, rebind), NULL },

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/* timeout on network activity */
	{ "net_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, net_timeout), "10" },
#endif

	/* timeout for search results */
	{ "res_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, res_timeout), "20" },

	/* allow server unlimited time for search (server-side limit) */
	{ "srv_timelimit", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, srv_timelimit), "20" },

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{ "idle", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, keepalive_idle), "60" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{ "probes", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, keepalive_probes), "3" },
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	{ "interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, ldap_instance_t, keepalive_interval), "30" },
#endif

	{ NULL, -1, 0, NULL, NULL }
};


static const CONF_PARSER module_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, ldap_instance_t, server), "localhost" },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, ldap_instance_t, port), "389" },

	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, ldap_instance_t, password), "" },
	{ "identity", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, admin_dn), "" },

	{ "valuepair_attribute", FR_CONF_OFFSET(PW_TYPE_STRING, ldap_instance_t, valuepair_attr), NULL },

#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{ "edir", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, edir), NULL }, /* NULL defaults to "no" */

	/*
	 *	Attempt to bind with the cleartext password we got from eDirectory
	 *	Universal password for additional authorization checks.
	 */
	{ "edir_autz", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, edir_autz), NULL }, /* NULL defaults to "no" */
#endif

	{ "read_clients", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, ldap_instance_t, do_clients), NULL }, /* NULL defaults to "no" */

	{ "user", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) user_config },

	{ "group", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) group_config },

	{ "client", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) client_config },

	{ "profile", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) profile_config },

	{ "options", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) option_config },

	{ "tls", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) tls_config },

	{NULL, -1, 0, NULL, NULL}
};

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 */
static ssize_t ldap_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	ldap_rcode_t status;
	size_t len = 0;
	ldap_instance_t *inst = instance;
	LDAPURLDesc *ldap_url;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	char **vals;
	ldap_handle_t *conn;
	int ldap_errno;
	char const *url;
	char const **attrs;

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

	if (ldap_url->lud_host &&
	    ((strncmp(inst->server, ldap_url->lud_host, strlen(inst->server)) != 0) ||
	     ((uint32_t) ldap_url->lud_port != inst->port))) {
		RDEBUG("Requested server/port is \"%s:%i\"", ldap_url->lud_host, inst->port);

		goto free_urldesc;
	}

	conn = rlm_ldap_get_socket(inst, request);
	if (!conn) goto free_urldesc;

	memcpy(&attrs, &ldap_url->lud_attrs, sizeof(attrs));

	status = rlm_ldap_search(inst, request, &conn, ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter,
				 attrs, &result);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		RDEBUG("Search returned not found");

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

	vals = ldap_get_values(conn->handle, entry, ldap_url->lud_attrs[0]);
	if (!vals) {
		RDEBUG("No \"%s\" attributes found in specified object", ldap_url->lud_attrs[0]);
		goto free_result;
	}

	len = strlen(vals[0]);
	if (len >= freespace){
		goto free_vals;
	}

	strlcpy(out, vals[0], freespace);

free_vals:
	ldap_value_free(vals);
free_result:
	ldap_msgfree(result);
free_socket:
	rlm_ldap_release_socket(inst, conn);
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
 * @return 1 on failure (or if the user is not a member), else 0.
 */
static int rlm_ldap_groupcmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			     UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	ldap_instance_t	*inst = instance;
	rlm_rcode_t	rcode;

	bool		found = false;
	bool		check_is_dn;

	ldap_handle_t	*conn = NULL;
	char const	*user_dn;

	rad_assert(inst->groupobj_base_dn);

	RDEBUG("Searching for user in group \"%s\"", check->vp_strvalue);

	if (check->length == 0) {
		REDEBUG("Cannot do comparison (group name is empty)");
		return 1;
	}

	/*
	 *	Check if we can do cached membership verification
	 */
	check_is_dn = rlm_ldap_is_dn(check->vp_strvalue);
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

	conn = rlm_ldap_get_socket(inst, request);
	if (!conn) return 1;

	/*
	 *	This is used in the default membership filter.
	 */
	user_dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!user_dn) {
		rlm_ldap_release_socket(inst, conn);
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
	if (conn) rlm_ldap_release_socket(inst, conn);

	if (!found) {
		RDEBUG("User is not a member of specified group");

		return 1;
	}

	return 0;
}

/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int mod_detach(void *instance)
{
	ldap_instance_t *inst = instance;

	fr_connection_pool_delete(inst->pool);

	if (inst->user_map) {
		talloc_free(inst->user_map);
	}

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
 * @return 0 on success, else < 0 on failure.
 */
static int parse_sub_section(ldap_instance_t *inst, CONF_SECTION *parent, ldap_acct_section_t **config,
			     rlm_components_t comp)
{
	CONF_SECTION *cs;

	char const *name = section_type_value[comp].section;

	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		INFO("rlm_ldap (%s): Couldn't find configuration for %s, will return NOOP for calls "
		       "from this section", inst->xlat_name, name);

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

/** Instantiate the module
 *
 * Creates a new instance of the module reading parameters from a configuration section.
 *
 * @param conf to parse.
 * @param instance Where to write pointer to configuration data.
 * @return 0 on success < 0 on failure.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	static bool version_done;

	CONF_SECTION *options;
	ldap_instance_t *inst = instance;

	inst->cs = conf;

	options = cf_section_sub_find(conf, "options");
	if (!options || !cf_pair_find(options, "chase_referrals")) {
		inst->chase_referrals_unset = true;	 /* use OpenLDAP defaults */
	}

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	/*
	 *	Get version info from the LDAP API.
	 */
	if (!version_done) {
		int ldap_errno;
		LDAPAPIInfo info;

		version_done = true;

		ldap_errno = ldap_get_option(NULL, LDAP_OPT_API_INFO, &info);
		if (ldap_errno == LDAP_OPT_SUCCESS) {
			if (strcmp(info.ldapai_vendor_name, LDAP_VENDOR_NAME) != 0) {
				WARN("rlm_ldap: libldap vendor changed since the server was built");
				WARN("rlm_ldap: linked: %s built: %s", info.ldapai_vendor_name, LDAP_VENDOR_NAME);
			}

			if (info.ldapai_vendor_version != LDAP_VENDOR_VERSION) {
				WARN("rlm_ldap: libldap version changed since the server was built");
				WARN("rlm_ldap: linked: %i built: %i",
				     info.ldapai_vendor_version, LDAP_VENDOR_VERSION);
			}

			INFO("rlm_ldap: libldap vendor: %s version: %i", info.ldapai_vendor_name,
			     info.ldapai_vendor_version);
			ldap_memfree(info.ldapai_vendor_name);
			ldap_memfree(info.ldapai_extensions);
		} else {
			WARN("rlm_ldap: Falling back to build time libldap version info.  Query for LDAP_OPT_API_INFO "
			     "returned: %i", ldap_errno);
			INFO("rlm_ldap: libldap vendor: %s version: %i", LDAP_VENDOR_NAME, LDAP_VENDOR_VERSION);
		}
	}

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((parse_sub_section(inst, conf, &inst->accounting, RLM_COMPONENT_ACCT) < 0) ||
	    (parse_sub_section(inst, conf, &inst->postauth, RLM_COMPONENT_POST_AUTH) < 0)) {
		LDAP_ERR("Failed parsing configuration");

		goto error;
	}

	/*
	 *	Sanity checks for cacheable groups code.
	 */
	if (inst->cacheable_group_name && inst->groupobj_membership_filter) {
		if (!inst->groupobj_name_attr) {
			LDAP_ERR("Directive 'group.name_attribute' must be set if cacheable group names are enabled");

			goto error;
		}
	}

	/*
	 *	Check for URLs.  If they're used and the library doesn't support them, then complain.
	 */
	inst->is_url = 0;
	if (ldap_is_ldap_url(inst->server)) {
#ifdef HAVE_LDAP_INITIALIZE
		inst->is_url = 1;
		inst->port = 0;
#else
		LDAP_ERR("Directive 'server' is in URL form but ldap_initialize() is not available");
		goto error;
#endif
	}

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
			LDAP_ERR("Invalid 'dereference' value \"%s\", expected 'never', 'searching', "
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
		LDAP_ERR("Cannot use 'rebind' directive as this version of libldap does not support the API "
			 "that we need");

		goto error;
	}
#endif

	/*
	 *	Convert scope strings to enumerated constants
	 */
	inst->userobj_scope = fr_str2int(ldap_scope, inst->userobj_scope_str, -1);
	if (inst->userobj_scope < 0) {
		LDAP_ERR("Invalid 'user.scope' value \"%s\", expected 'sub', 'one'"
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
		LDAP_ERR("Invalid 'group.scope' value \"%s\", expected 'sub', 'one'"
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
		LDAP_ERR("Invalid 'client.scope' value \"%s\", expected 'sub', 'one'"
#ifdef LDAP_SCOPE_CHILDREN
			 ", 'base' or 'children'"
#else
			 " or 'base'"
#endif
			 , inst->clientobj_scope_str);
		goto error;
	}

	if (inst->tls_require_cert_str) {
#ifdef LDAP_OPT_X_TLS_NEVER
		/*
		 *	Convert cert strictness to enumerated constants
		 */
		inst->tls_require_cert = fr_str2int(ldap_tls_require_cert, inst->tls_require_cert_str, -1);
		if (inst->tls_require_cert < 0) {
			LDAP_ERR("Invalid 'tls.require_cert' value \"%s\", expected 'never', 'demand', 'allow', "
				 "'try' or 'hard'", inst->tls_require_cert_str);
			goto error;
		}
#else
		LDAP_ERR("Modifying 'tls.require_cert' is not supported by current version of libldap. "
			 "Please upgrade or substitute current libldap and rebuild this module");

		goto error;
#endif
	}
	/*
	 *	Build the attribute map
	 */
	if (rlm_ldap_map_verify(inst, &(inst->user_map)) < 0) {
		goto error;
	}

	/*
	 *	Group comparison checks.
	 */
	if (cf_section_name2(conf)) {
		static ATTR_FLAGS flags;
		char buffer[256];

		snprintf(buffer, sizeof(buffer), "%s-Ldap-Group", inst->xlat_name);
		if (dict_addattr(buffer, -1, 0, PW_TYPE_STRING, flags) < 0) {
			LDAP_ERR("Error creating group attribute: %s", fr_strerror());

			return -1;
		}
		inst->group_da = dict_attrbyname(buffer);
		if (!inst->group_da) {
			LDAP_ERR("Failed creating attribute %s", buffer);

			goto error;
		}

		paircompare_register(inst->group_da, dict_attrbyvalue(PW_USER_NAME, 0), false, rlm_ldap_groupcmp, inst);
	/*
	 *	Were the default instance
	 */
	} else {
		inst->group_da = dict_attrbyvalue(PW_LDAP_GROUP, 0);
		paircompare_register(dict_attrbyvalue(PW_LDAP_GROUP, 0), dict_attrbyvalue(PW_USER_NAME, 0),
				false, rlm_ldap_groupcmp, inst);
	}

	xlat_register(inst->xlat_name, ldap_xlat, rlm_ldap_escape_func, inst);

	/*
	 *	Setup the cache attribute
	 */
	if (inst->cache_attribute) {
		static ATTR_FLAGS flags;

		if (dict_addattr(inst->cache_attribute, -1, 0, PW_TYPE_STRING, flags) < 0) {
			LDAP_ERR("Error creating cache attribute: %s", fr_strerror());

			return -1;
		}
		inst->cache_da = dict_attrbyname(inst->cache_attribute);
	} else {
		inst->cache_da = inst->group_da;	/* Default to the group_da */
	}

	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = fr_connection_pool_module_init(inst->cs, inst, mod_conn_create, NULL, NULL);
	if (!inst->pool) return -1;

	/*
	 *	Bulk load dynamic clients.
	 */
	if (inst->do_clients) {
		if (rlm_ldap_load_clients(inst) < 0) {
			LDAP_ERR("Error loading clients");

			return -1;
		}
	}

	return 0;

error:
	return -1;
}

static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_rcode_t	rcode;
	ldap_rcode_t	status;
	char const	*dn;
	ldap_instance_t	*inst = instance;
	ldap_handle_t	*conn;

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

	if (request->password->length == 0) {
		REDEBUG("Empty password supplied");

		return RLM_MODULE_INVALID;
	}

	RDEBUG("Login attempt by \"%s\"", request->username->vp_strvalue);

	conn = rlm_ldap_get_socket(inst, request);
	if (!conn) return RLM_MODULE_FAIL;

	/*
	 *	Get the DN by doing a search.
	 */
	dn = rlm_ldap_find_user(inst, request, &conn, NULL, false, NULL, &rcode);
	if (!dn) {
		rlm_ldap_release_socket(inst, conn);

		return rcode;
	}

	/*
	 *	Bind as the user
	 */
	conn->rebound = true;
	status = rlm_ldap_bind(inst, request, &conn, dn, request->password->vp_strvalue, true);
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

	rlm_ldap_release_socket(inst, conn);

	return rcode;
}

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	ldap_rcode_t	status;
	int		ldap_errno;
	int		i;
	ldap_instance_t	*inst = instance;
	char		**vals;
	VALUE_PAIR	*vp;
	ldap_handle_t	*conn;
	LDAPMessage	*result, *entry;
	char const 	*dn = NULL;
	rlm_ldap_map_xlat_t	expanded; /* faster than mallocing every time */

	if (!request->username) {
		RDEBUG2("Attribute \"User-Name\" is required for authorization");

		return RLM_MODULE_NOOP;
	}

	/*
	 *	Check for valid input, zero length names not permitted
	 */
	if (request->username->length == 0) {
		RDEBUG2("Zero length username not permitted");

		return RLM_MODULE_INVALID;
	}

	if (rlm_ldap_map_xlat(request, inst->user_map, &expanded) < 0) {
		return RLM_MODULE_FAIL;
	}

	conn = rlm_ldap_get_socket(inst, request);
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
	if (pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) {
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
		vp = radius_paircreate(request, &request->config_items, PW_CLEARTEXT_PASSWORD, 0);
		pairstrcpy(vp, password);
		vp->length = pass_size;

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
			status = rlm_ldap_bind(inst, request, &conn, dn, vp->vp_strvalue, true);
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
		char profile[1024];

		if (radius_xlat(profile, sizeof(profile), request, inst->default_profile, NULL, NULL) < 0) {
			REDEBUG("Failed creating default profile string");

			rcode = RLM_MODULE_INVALID;
			goto finish;
		}

		rlm_ldap_map_profile(inst, request, &conn, profile, &expanded);
	}

	/*
	 *	Apply a SET of user profiles.
	 */
	if (inst->profile_attr) {
		vals = ldap_get_values(conn->handle, entry, inst->profile_attr);
		if (vals != NULL) {
			for (i = 0; vals[i] != NULL; i++) {
				rlm_ldap_map_profile(inst, request, &conn, vals[i], &expanded);
			}

			ldap_value_free(vals);
		}
	}

	if (inst->user_map || inst->valuepair_attr) {
		RDEBUG("Processing user attributes");
		rlm_ldap_map_do(inst, request, conn->handle, &expanded, entry);
		rlm_ldap_check_reply(inst, request);
	}

finish:
	rlm_ldap_map_xlat_free(&expanded);
	if (result) {
		ldap_msgfree(result);
	}
	rlm_ldap_release_socket(inst, conn);

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
static rlm_rcode_t user_modify(ldap_instance_t *inst, REQUEST *request, ldap_acct_section_t *section)
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

	cs = cf_section_sub_find(cf_itemtosection(ci), "update");
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
		cp = cf_itemtopair(ci);
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

	conn = rlm_ldap_get_socket(inst, request);
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

	rlm_ldap_release_socket(inst, conn);

	return rcode;
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST * request) {
	ldap_instance_t *inst = instance;

	if (inst->accounting) {
		return user_modify(inst, request, inst->accounting);
	}

	return RLM_MODULE_NOOP;
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST * request)
{
	ldap_instance_t	*inst = instance;

	if (inst->postauth) {
		return user_modify(inst, request, inst->postauth);
	}

	return RLM_MODULE_NOOP;
}


/* globally exported name */
module_t rlm_ldap = {
	RLM_MODULE_INIT,
	"ldap",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved 	 */
	sizeof(ldap_instance_t),
	module_config,
	mod_instantiate,	/* instantiation 	 */
	mod_detach,		/* detach 		 */
	{
		mod_authenticate,	/* authentication 	 */
		mod_authorize,		/* authorization 	 */
		NULL,			/* preaccounting 	 */
		mod_accounting,		/* accounting 		 */
		NULL,			/* checksimul 		 */
		NULL,			/* pre-proxy 		 */
		NULL,			/* post-proxy 		 */
		mod_post_auth		/* post-auth */
	},
};
