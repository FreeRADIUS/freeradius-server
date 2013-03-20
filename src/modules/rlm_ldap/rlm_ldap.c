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
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/rad_assert.h>

#include	<stdarg.h>
#include	<ctype.h>

#include	"ldap.h"

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	{"start_tls", PW_TYPE_BOOLEAN, offsetof(ldap_instance_t, start_tls), NULL, "no"},
	{"cacertfile", PW_TYPE_FILENAME, offsetof(ldap_instance_t, tls_cacertfile), NULL, NULL},
	{"cacertdir", PW_TYPE_FILENAME, offsetof(ldap_instance_t, tls_cacertdir), NULL, NULL},
	{"certfile", PW_TYPE_FILENAME, offsetof(ldap_instance_t, tls_certfile), NULL, NULL},
	{"keyfile", PW_TYPE_FILENAME, offsetof(ldap_instance_t, tls_keyfile), NULL, NULL}, // OK if it changes on HUP
	{"randfile", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t, tls_randfile), NULL, NULL},
	{"require_cert",PW_TYPE_STRING_PTR, offsetof(ldap_instance_t, tls_require_cert), NULL, TLS_DEFAULT_VERIFY},
	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Access limitations
 */
static CONF_PARSER attr_config[] = {
	/* LDAP attribute name that controls remote access */
	{"userobj_access_attr", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,userobj_access_attr), NULL, NULL},
	{"access_positive", PW_TYPE_BOOLEAN, offsetof(ldap_instance_t,access_positive), NULL, "yes"},
	{"base_filter", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,base_filter), NULL, "(objectclass=radiusprofile)"},
	{"default_profile", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,default_profile), NULL, NULL},
	{"profile_attribute", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,profile_attr), NULL, NULL},

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	/*
	 *	Group checks.  These could probably be done via dynamic xlat's.
	 */
	{"name_attribute", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,groupobj_name_attr), NULL, "cn"},
	{"membership_filter", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,groupobj_membership_filter), NULL,
	 "(|(&(objectClass=GroupOfNames)(member=%{Ldap-UserDn}))(&(objectClass=GroupOfUniqueNames)"
	 "(uniquemember=%{Ldap-UserDn})))"},
	{"membership_attribute", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,userobj_membership_attr), NULL, NULL},
	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{"reference", PW_TYPE_STRING_PTR, offsetof(ldap_acct_section_t, reference), NULL, "."},
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
	{"ldap_debug", PW_TYPE_INTEGER, offsetof(ldap_instance_t,ldap_debug), NULL, "0x0000"},

	{"chase_referrals", PW_TYPE_BOOLEAN, offsetof(ldap_instance_t,chase_referrals), NULL, NULL},

	{"rebind", PW_TYPE_BOOLEAN,offsetof(ldap_instance_t,rebind), NULL, NULL},

	/* timeout on network activity */
	{"net_timeout", PW_TYPE_INTEGER, offsetof(ldap_instance_t,net_timeout), NULL, "10"},

	/* timeout for search results */
	{"timeout", PW_TYPE_INTEGER, offsetof(ldap_instance_t,timeout), NULL, "20"},

	/* allow server unlimited time for search (server-side limit) */
	{"timelimit", PW_TYPE_INTEGER, offsetof(ldap_instance_t,timelimit), NULL, "20"},

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{"idle", PW_TYPE_INTEGER, offsetof(ldap_instance_t,keepalive_idle), NULL, "60"},
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{"probes", PW_TYPE_INTEGER, offsetof(ldap_instance_t,keepalive_probes), NULL, "3"},
#endif
#ifdef LDAP_OPT_ERROR_NUMBER
	{"interval", PW_TYPE_INTEGER,  offsetof(ldap_instance_t,keepalive_interval), NULL, "30"},
#endif
	{ NULL, -1, 0, NULL, NULL }
};


static const CONF_PARSER module_config[] = {
	{"server", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,server), NULL, "localhost"},
	{"port", PW_TYPE_INTEGER, offsetof(ldap_instance_t,port), NULL, "389"},

	{"password", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,password), NULL, ""},
	{"identity", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,login), NULL, ""},

	/*
	 *	DN's and filters.
	 */
	{"basedn", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,basedn), NULL, "o=notexist"},

	{"filter", PW_TYPE_STRING_PTR, offsetof(ldap_instance_t,userobj_filter), NULL, "(uid=%u)"},

#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{"edir", PW_TYPE_BOOLEAN, offsetof(ldap_instance_t,edir), NULL, NULL}, /* NULL defaults to "no" */

	/*
	 * Attempt to bind with the Cleartext password we got from eDirectory
	 * Universal password for additional authorization checks.
	 */
	{"edir_autz", PW_TYPE_BOOLEAN, offsetof(ldap_instance_t,edir_autz), NULL, NULL}, /* NULL defaults to "no" */
#endif

	/*
	 *	Terrible things which should be deleted.
	 */
	{ "profiles", PW_TYPE_SUBSECTION, 0, NULL, (const void *) attr_config },

	{ "group", PW_TYPE_SUBSECTION, 0, NULL, (const void *) group_config },

	{ "options", PW_TYPE_SUBSECTION, 0, NULL,
	 (const void *) option_config },

	{ "tls", PW_TYPE_SUBSECTION, 0, NULL, (const void *) tls_config },

	{NULL, -1, 0, NULL, NULL}
};

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 */
static size_t ldap_xlat(void *instance, REQUEST *request, const char *fmt,
			char *out, size_t freespace)
{
	ldap_rcode_t status;
	size_t length = 0;
	ldap_instance_t *inst = instance;
	LDAPURLDesc *ldap_url;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	char **vals;
	ldap_handle_t *conn;
	int ldap_errno;
	const char *url;
	const char **attrs;
	char buffer[LDAP_MAX_FILTER_STR_LEN];

	if (strchr(fmt, '%') != NULL) {
		if (!radius_xlat(buffer, sizeof(buffer), fmt, request, rlm_ldap_escape_func, NULL)) {
			RDEBUGE("Unable to create LDAP URL");
			return 0;
		}
		url = buffer;
	} else {
		url = fmt;
	}

	if (!ldap_is_ldap_url(url)) {
		RDEBUGE("String passed does not look like an LDAP URL");
		return 0;
	}

	if (ldap_url_parse(url, &ldap_url)){
		RDEBUGE("Parsing LDAP URL failed");
		return 0;
	}

	/*
	 *	Nothing, empty string, "*" string, or got 2 things, die.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] ||
	    !*ldap_url->lud_attrs[0] ||
	    (strcmp(ldap_url->lud_attrs[0], "*") == 0) ||
	    ldap_url->lud_attrs[1]) {
		RDEBUGE("Bad attributes list in LDAP URL. "
			"URL must specify exactly one attribute to "
		        "retrieve");
		       
		goto free_urldesc;
	}

	if (ldap_url->lud_host && 
	    ((strncmp(inst->server, ldap_url->lud_host, strlen(inst->server)) != 0) ||
	     (ldap_url->lud_port != inst->port))) {
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
		RDEBUGE("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
		goto free_result;
	}

	vals = ldap_get_values(conn->handle, entry, ldap_url->lud_attrs[0]);
	if (!vals) {
		RDEBUG("No \"%s\" attributes found in specified object", ldap_url->lud_attrs[0]);
		goto free_result;
	}

	length = strlen(vals[0]);
	if (length >= freespace){

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

	return length;
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
	ldap_rcode_t	status;
	int		i, found = FALSE;
	LDAPMessage     *result = NULL;
	LDAPMessage     *entry = NULL;
	int		ldap_errno;
	int		check_is_dn = FALSE, value_is_dn = FALSE;
	char		**vals = NULL;
	const char	*group_attrs[] = {inst->userobj_membership_attr, NULL};
	ldap_handle_t	*conn;
	const char	*user_dn;

	char		gr_filter[LDAP_MAX_FILTER_STR_LEN];
	char		filter[LDAP_MAX_FILTER_STR_LEN];
	char		basedn[LDAP_MAX_FILTER_STR_LEN];

	RDEBUG("Searching for user in group \"%s\"", check->vp_strvalue);

	if (check->length == 0) {
		RDEBUG("Cannot do comparison (group name is empty)");
		return 1;
	}

	conn = rlm_ldap_get_socket(inst, request);
	if (!conn) return 1;

	/*
	 *	This is used in the default membership filter.
	 */
	user_dn = rlm_ldap_find_user(inst, request, &conn, group_attrs, FALSE, &result, &rcode);
	if (!user_dn) {
		rlm_ldap_release_socket(inst, conn);
		return 1;
	}
	
	rad_assert(conn);
	
	if (!inst->groupobj_membership_filter) goto check_attr;

	if (!radius_xlat(gr_filter, sizeof(gr_filter),
			 inst->groupobj_membership_filter, request, rlm_ldap_escape_func,
			 NULL)) {
		RDEBUGE("Failed creating group filter");

		return 1;
	}

	/*
	 *	If it's a DN, use that.
	 */
	check_is_dn = rlm_ldap_is_dn(check->vp_strvalue);
	if (check_is_dn) {
		strlcpy(filter, gr_filter, sizeof(filter));
		strlcpy(basedn, check->vp_strvalue, sizeof(basedn));	
	} else {
		snprintf(filter, sizeof(filter), "(&(%s=%s)%s)",
			 inst->groupobj_name_attr,
			 check->vp_strvalue, gr_filter);

		/*
		 *	rlm_ldap_find_user does this, too.  Oh well.
		 */
		if (!radius_xlat(basedn, sizeof(basedn), inst->basedn, request, rlm_ldap_escape_func, NULL)) {
			RDEBUGE("Failed creating basedn");
			
			return 1;
		}
	}

	status = rlm_ldap_search(inst, request, &conn, basedn, LDAP_SCOPE_SUBTREE, filter, NULL, NULL);
	switch (status) {
		case LDAP_PROC_SUCCESS:
			RDEBUG("User found in group object");
			found = TRUE;
			goto finish;
		case LDAP_PROC_NO_RESULT:
			RDEBUG("Search returned not found");
			goto check_attr;
		default:
			goto finish;
	}
	
	rad_assert(conn);
	rad_assert(result);

	/*
	 *	Else the search returned NOTFOUND.  See if we're
	 *	configured to search for group membership using user
	 *	object attribute.
	 */
	if (!inst->userobj_membership_attr) {
		RDEBUG("Group object \"%s\" not found, or user is not a member", check->vp_strvalue);
		rlm_ldap_release_socket(inst, conn);

		return 1;
	}

check_attr:
	RDEBUG2("Checking user object membership (%s) attributes", inst->userobj_membership_attr);

	snprintf(filter ,sizeof(filter), "(objectclass=*)");

	status = rlm_ldap_search(inst, request, &conn, user_dn, LDAP_SCOPE_BASE, filter, group_attrs, &result);
	switch (status) {
		case LDAP_PROC_SUCCESS:
			break;
		case LDAP_PROC_NO_RESULT:
			RDEBUG("Can't check membership attributes, user object not found");
			
			/* FALL-THROUGH */
		default:
			rlm_ldap_release_socket(inst, conn);
			return 1;
	}

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		RDEBUGE("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
			       
		rlm_ldap_release_socket(inst, conn);
		ldap_msgfree(result);
		return 1;
	}

	vals = ldap_get_values(conn->handle, entry, inst->userobj_membership_attr);
	if (!vals) {
		RDEBUG("No group membership attribute(s) found in user object");
		rlm_ldap_release_socket(inst, conn);
		ldap_msgfree(result);
		return 1;
	}

	/*
	 *	Loop over the list of groups the user is a member of,
	 *	looking for a match.
	 */
	for (i = 0; i < ldap_count_values(vals); i++) {
		value_is_dn = rlm_ldap_is_dn(vals[i]);
		
		RDEBUG2("Processing group membership value \"%s\"", vals[i]);

		/*
		 *	Both literal group names, do case sensitive comparison
		 */
		if (!check_is_dn && !value_is_dn) {
			if (strcmp(vals[i], check->vp_strvalue) == 0){
				RDEBUG("User found (membership value matches check value)");
			       
				found = TRUE;
				break;
			}
			
			continue;
		}

		/*
		 *	Both DNs, do case insensitive comparison
		 */
		if (check_is_dn && value_is_dn) {
			if (strcasecmp(vals[i], check->vp_strvalue) == 0){
				RDEBUG("User found (membership DN matches check DN)");
			       
				found = TRUE;
				break;
			}
			
			continue;
		}
		
		/*
		 *	If the value is not a DN, or the check item is a DN
		 *	there's nothing more we can do.
		 */
		if (!value_is_dn && check_is_dn) continue;

		/*
		 *	We have a value which is a DN, and a check item which
		 *	specifies the name of a group, search using the value
		 *	DN for the group, and see if it has a groupobj_name_attr
		 *	which matches our check val.
		 */
		RDEBUG2("Searching with membership DN and group name");

		snprintf(filter,sizeof(filter), "(%s=%s)", inst->groupobj_name_attr, check->vp_strvalue);

		status = rlm_ldap_search(inst, request, &conn, vals[i], LDAP_SCOPE_BASE, filter, NULL, NULL);       
		switch (status) {
			case LDAP_PROC_SUCCESS:
				found = TRUE;
				RDEBUG("User found (group name in membership DN matches check value)");
				
				break;
			case LDAP_PROC_NO_RESULT:
				continue;
			default:
				goto finish;
		}

		break;
	}

	finish:
	
	ldap_value_free(vals);
	ldap_msgfree(result);
	rlm_ldap_release_socket(inst, conn);

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
		radius_mapfree(&inst->user_map);
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

	const char *name = section_type_value[comp].section;
	
	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		radlog(L_INFO, "rlm_ldap (%s): Couldn't find configuration for %s, will return NOOP for calls "
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
static int mod_instantiate(CONF_SECTION *conf, void **instance)
{
	ldap_instance_t *inst;

	*instance = inst = talloc_zero(conf, ldap_instance_t);
	if (!inst) return -1;

	inst->cs = conf;

	inst->chase_referrals = 2; /* use OpenLDAP defaults */
	inst->rebind = 2;
	
	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((cf_section_parse(conf, inst, module_config) < 0) ||
	    (parse_sub_section(inst, conf, &inst->accounting, RLM_COMPONENT_ACCT) < 0) ||
	    (parse_sub_section(inst, conf, &inst->postauth, RLM_COMPONENT_POST_AUTH) < 0)) {
		LDAP_ERR("Failed parsing configuration");
		
		goto error;
	}

	if (!inst->server) {
		LDAP_ERR("Missing 'server' directive");
		
		goto error;
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
		LDAP_ERR("'server' directive is in URL form but ldap_initialize() is not available");
		goto error;
#endif
	}

	/*
	 *	Workaround for servers which support LDAPS but not START TLS
	 */
	if (inst->port == LDAPS_PORT || inst->tls_mode) {
		inst->tls_mode = LDAP_OPT_X_TLS_HARD;
	} else {
		inst->tls_mode = 0;
	}

#if LDAP_SET_REBIND_PROC_ARGS != 3
	/*
	 *	The 2-argument rebind doesn't take an instance variable.  Our rebind function needs the instance
	 *	variable for the username, password, etc.
	 */
	if (inst->rebind == 1) {
		LDAP_ERR("Cannot use 'rebind' directive as this version of libldap does not support the API "
			 "that we need");
			 
		goto error;
	}
#endif

	/*
	 *	Build the attribute map
	 */
	if (rlm_ldap_map_verify(inst, &(inst->user_map)) < 0) {
		goto error;
	}

	/*
	 *	Group comparison checks.
	 */
	paircompare_register(PW_LDAP_GROUP, PW_USER_NAME, rlm_ldap_groupcmp, inst);	
	if (cf_section_name2(conf)) {
		const DICT_ATTR *da;
		ATTR_FLAGS flags;
		char buffer[256];

		snprintf(buffer, sizeof(buffer), "%s-Ldap-Group",
			 inst->xlat_name);
		memset(&flags, 0, sizeof(flags));

		dict_addattr(buffer, -1, 0, PW_TYPE_STRING, flags);
		da = dict_attrbyname(buffer);
		if (!da) {
			LDAP_ERR("Failed creating attribute %s", buffer);
			
			goto error;
		}

		paircompare_register(da->attr, PW_USER_NAME, rlm_ldap_groupcmp, inst);
	}

	xlat_register(inst->xlat_name, ldap_xlat, inst);

	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = fr_connection_pool_init(inst->cs, inst, rlm_ldap_conn_create, NULL, rlm_ldap_conn_delete);
	if (!inst->pool) {
		mod_detach(inst);
		return -1;
	}
	
	return 0;

error:
	mod_detach(inst);
	return -1;
}

/** Check the user's password against ldap database
 * 
 * @param instance rlm_ldap configuration.
 * @param request Current request.
 * @return one of the RLM_MODULE_* values.
 */
static rlm_rcode_t mod_authenticate(void *instance, REQUEST *request)
{
	rlm_rcode_t	rcode;
	const char	*user_dn;
	ldap_instance_t	*inst = instance;
	ldap_handle_t	*conn;

	/*
	 * Ensure that we're being passed a plain-text password, and not
	 * anything else.
	 */

	if (!request->username) {
		RDEBUGE("Attribute \"User-Name\" is required for authentication");

		return RLM_MODULE_INVALID;
	}

	if (!request->password ||
	    (request->password->da->attr != PW_USER_PASSWORD)) {
		RDEBUGW("  You have set \"Auth-Type := LDAP\" somewhere.");
		RDEBUGW("  *********************************************");
		RDEBUGW("  * THAT CONFIGURATION IS WRONG.  DELETE IT.   ");
		RDEBUGW("  * YOU ARE PREVENTING THE SERVER FROM WORKING.");
		RDEBUGW("  *********************************************");
		
		RDEBUGE("Attribute \"User-Password\" is required for authentication.");
		
		return RLM_MODULE_INVALID;
	}

	if (request->password->length == 0) {
		RDEBUGE("Empty password supplied");
		
		return RLM_MODULE_INVALID;
	}

	RDEBUG("Login attempt by \"%s\"", request->username->vp_strvalue);

	conn = rlm_ldap_get_socket(inst, request);
	if (!conn) return RLM_MODULE_FAIL;

	/*
	 *	Get the DN by doing a search.
	 */
	user_dn = rlm_ldap_find_user(inst, request, &conn, NULL, FALSE, NULL, &rcode);
	if (!user_dn) {
		rlm_ldap_release_socket(inst, conn);
		
		return rcode;
	}

	/*
	 *	Bind as the user
	 */
	conn->rebound = TRUE;
	rcode = rlm_ldap_bind(inst, request, &conn, user_dn, request->password->vp_strvalue, TRUE);
	if (rcode == RLM_MODULE_OK) {
		RDEBUG("Bind as user \"%s\" was successful", user_dn);
	}

	rlm_ldap_release_socket(inst, conn);
	
	return rcode;
}

/** Check if user is authorized for remote access
 *
 */
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	int		ldap_errno;
	ldap_instance_t	*inst = instance;
	char		**vals;
	VALUE_PAIR	*vp;
	ldap_handle_t	*conn;
	LDAPMessage	*result, *entry;
	const char 	*dn;
	rlm_ldap_map_xlat_t	expanded; /* faster that mallocing every time */
	
	if (!request->username) {
		RDEBUG2("Attribute \"User-Name\" is required for authorization.");
		
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
	if (inst->access_positive) {
		expanded.attrs[expanded.count++] = inst->userobj_access_attr;
	}

	if (inst->userobj_membership_attr) {
		expanded.attrs[expanded.count++] = inst->userobj_membership_attr;
	}
	
	if (inst->profile_attr) {
		expanded.attrs[expanded.count++] = inst->profile_attr;
	}
	
	expanded.attrs[expanded.count] = NULL;
	
	dn = rlm_ldap_find_user(inst, request, &conn, expanded.attrs, TRUE, &result, &rcode);
	if (!dn) {
		goto finish;			
	}

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		RDEBUGE("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
			 
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

#ifdef WITH_EDIR
	/*
	 *	We already have a Cleartext-Password.  Skip edir.
	 */
	if (inst->edir && pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY)) {
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
			RDEBUGW("Failed to retrieve eDirectory password");
			rcode = RLM_MODULE_NOOP;

			goto finish;
		}

		/*
		 *	Add Cleartext-Password attribute to the request
		 */
		vp = radius_paircreate(request, &request->config_items, PW_CLEARTEXT_PASSWORD, 0);
		strlcpy(vp->vp_strvalue, password, sizeof(vp->vp_strvalue));
		vp->length = pass_size;
		
		RDEBUG2("Added eDirectory password in check items as %s = %s", vp->da->name, vp->vp_strvalue);
			
		if (inst->edir_autz) {
			RDEBUG2("Binding as user for eDirectory authorization checks");
			/*
			 *	Bind as the user
			 */
			conn->rebound = TRUE;
			rcode = rlm_ldap_bind(inst, request, &conn, dn, vp->vp_strvalue, TRUE);
			if (rcode != RLM_MODULE_OK) {
				goto finish;
			}
			
			RDEBUG("Bind as user \"%s\" was successful", dn);
		}
	}

skip_edir:
#endif

	/*
	 *	Apply ONE user profile, or a default user profile.
	 */
	vp = pairfind(request->config_items, PW_USER_PROFILE, 0, TAG_ANY);
	if (vp || inst->default_profile) {
		const char *profile = inst->default_profile;

		if (vp) profile = vp->vp_strvalue;

		rlm_ldap_apply_profile(inst, request, &conn, profile, &expanded);
	}

	/*
	 *	Apply a SET of user profiles.
	 */
	if (inst->profile_attr) {
		vals = ldap_get_values(conn->handle, entry, inst->profile_attr);
		if (vals != NULL) {
			int i;
	
			for (i = 0; (vals[i] != NULL) && (*vals[i] != '\0'); i++) {
				rlm_ldap_apply_profile(inst, request, &conn, vals[i], &expanded);
			}
	
			ldap_value_free(vals);
		}
	}

	if (inst->user_map) {
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
	
	ldap_handle_t	*conn = NULL;
	
	LDAPMod		*mod_p[LDAP_MAX_ATTRMAP + 1], mod_s[LDAP_MAX_ATTRMAP];
	LDAPMod		**modify = mod_p;
	
	char		*passed[LDAP_MAX_ATTRMAP * 2];
	int		i, total = 0, last_pass = 0;
	
	char 		*expanded[LDAP_MAX_ATTRMAP];
	int		last_exp = 0;
	
	const char	*attr;
	const char	*value;
	
	const char	*dn;
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
	
	if (!radius_xlat(p, (sizeof(path) - (p - path)) - 1, section->reference, request, NULL, NULL)) {
		goto error;	
	}

	ci = cf_reference_item(NULL, section->cs, path);
	if (!ci) {
		goto error;	
	}
	
	if (!cf_item_is_section(ci)){
		RDEBUGE("Reference must resolve to a section");
		
		goto error;	
	}
	
	cs = cf_section_sub_find(cf_itemtosection(ci), "update");
	if (!cs) {
		RDEBUGE("Section must contain 'update' subsection");
		
		goto error;
	}
	
	/*
	 *	Iterate over all the pairs, building our mods array
	 */
	for (ci = cf_item_find_next(cs, NULL); ci != NULL; ci = cf_item_find_next(cs, ci)) {
	     	int do_xlat = FALSE;
	     	
	     	if (total == LDAP_MAX_ATTRMAP) {
	     		RDEBUGE("Modify map size exceeded");
	
	     		goto error;
	     	}
	     	
		if (!cf_item_is_pair(ci)) {
			RDEBUGE("Entry is not in \"ldap-attribute = value\" format");
			       
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

		switch (cf_pair_value_type(cp))
		{
			case T_BARE_WORD:
			case T_SINGLE_QUOTED_STRING:
			break;
			case T_BACK_QUOTED_STRING:
			case T_DOUBLE_QUOTED_STRING:
				do_xlat = TRUE;		
			break;
			default:
				rad_assert(0);
				goto error;
		}
		
		if (op == T_OP_CMP_FALSE) {
			passed[last_pass] = NULL;
		} else if (do_xlat) {
			p = rad_malloc(1024);
			if (radius_xlat(p, 1024, value, request, NULL, NULL) <= 0) {
				RDEBUG("xlat failed or empty value string, skipping attribute \"%s\"", attr);
			       	       
				free(p);
				
				continue;
			}
			
			expanded[last_exp++] = p;
			passed[last_pass] = p;
		/* 
		 *	Static strings
		 */
		} else {
			memcpy(&(passed[last_pass]), &value, sizeof(passed[last_pass]));
		}
		
		passed[last_pass + 1] = NULL;
		
		mod_s[total].mod_values = &(passed[last_pass]);
					
		last_pass += 2;
		
		switch (op)
		{
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
			RDEBUGE("Operator '%s' is not supported for LDAP modify operations",
			        fr_int2str(fr_tokens, op, "¿unknown?"));
			       
			goto error;
		}
		
		/*
		 *	Now we know the value is ok, copy the pointers into
		 *	the ldapmod struct.
		 */
		memcpy(&(mod_s[total].mod_type), &(attr), sizeof(mod_s[total].mod_type));
		
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


	dn = rlm_ldap_find_user(inst, request, &conn, NULL, FALSE, NULL, &rcode);
	if (!dn || (rcode != RLM_MODULE_OK)) {
		goto error;
	}
	
	rcode = rlm_ldap_modify(inst, request, &conn, dn, modify);
	
	release:
	error:
	/*
	 *	Free up any buffers we allocated for xlat expansion
	 */	
	for (i = 0; i < last_exp; i++) {
		free(expanded[i]);
	}

	rlm_ldap_release_socket(inst, conn);
	
	return rcode;
}

static rlm_rcode_t mod_accounting(void *instance, REQUEST * request) {
	ldap_instance_t *inst = instance;		

	if (inst->accounting) {
		return user_modify(inst, request, inst->accounting); 
	}
	
	return RLM_MODULE_NOOP;
}


/** Check the user's password against ldap database
 *
 */
static rlm_rcode_t mod_post_auth(void *instance, REQUEST * request)
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
	mod_instantiate,	/* instantiation 	 */
	mod_detach,		/* detach 		 */
	{
		mod_authenticate,	/* authentication 	 */
		mod_authorize,		/* authorization 	 */
		NULL,			/* preaccounting 	 */
		mod_accounting,	/* accounting 		 */
		NULL,			/* checksimul 		 */
		NULL,			/* pre-proxy 		 */
		NULL,			/* post-proxy 		 */
		mod_post_auth		/* post-auth */
	},
};
