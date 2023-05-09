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
 * @copyright 2013,2015 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2012 Alan DeKok (aland@freeradius.org)
 * @copyright 1999-2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/uri.h>

#include "rlm_ldap.h"
#include <freeradius-devel/ldap/conf.h>

#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module_rlm.h>

#include <freeradius-devel/unlang/xlat_func.h>

typedef struct {
	fr_value_box_t	user_base;
	fr_value_box_t	user_filter;
	fr_value_box_t	user_sasl_mech;
	fr_value_box_t	user_sasl_authname;
	fr_value_box_t	user_sasl_proxy;
	fr_value_box_t	user_sasl_realm;
} ldap_auth_call_env_t;

typedef struct {
	fr_value_box_t	user_base;
	fr_value_box_t	user_filter;
} ldap_usermod_call_env_t;

static const call_env_t sasl_call_env[] = {
	{ FR_CALL_ENV_OFFSET("mech", FR_TYPE_STRING, ldap_auth_call_env_t, user_sasl_mech,
			     NULL, T_INVALID, false, false, false) },
	{ FR_CALL_ENV_OFFSET("authname", FR_TYPE_STRING, ldap_auth_call_env_t, user_sasl_authname,
			     NULL, T_INVALID, false, false, false) },
	{ FR_CALL_ENV_OFFSET("proxy", FR_TYPE_STRING, ldap_auth_call_env_t, user_sasl_proxy,
			     NULL, T_INVALID, false, true, false) },
	{ FR_CALL_ENV_OFFSET("realm", FR_TYPE_STRING, ldap_auth_call_env_t, user_sasl_realm,
			     NULL, T_INVALID, false, true, false) },
	CALL_ENV_TERMINATOR
};

static CONF_PARSER profile_config[] = {
	{ FR_CONF_OFFSET("attribute", FR_TYPE_STRING, rlm_ldap_t, profile_attr) },
	CONF_PARSER_TERMINATOR
};

static const call_env_t autz_profile_call_env[] = {
	{ FR_CALL_ENV_OFFSET("default", FR_TYPE_STRING, ldap_autz_call_env_t, default_profile,
			     NULL, T_INVALID, false, false, true) },
	{ FR_CALL_ENV_OFFSET("filter", FR_TYPE_STRING, ldap_autz_call_env_t, profile_filter,
			     "(&)", T_SINGLE_QUOTED_STRING, false, false, true ) },	//!< Correct filter for when the DN is known.
	CALL_ENV_TERMINATOR
};

/*
 *	User configuration
 */
static CONF_PARSER user_config[] = {
	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, rlm_ldap_t, userobj_scope_str), .dflt = "sub" },
	{ FR_CONF_OFFSET("sort_by", FR_TYPE_STRING, rlm_ldap_t, userobj_sort_by) },

	{ FR_CONF_OFFSET("access_attribute", FR_TYPE_STRING, rlm_ldap_t, userobj_access_attr) },
	{ FR_CONF_OFFSET("access_positive", FR_TYPE_BOOL, rlm_ldap_t, access_positive), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

#define user_call_env(_prefix, _struct, ...) \
static const call_env_t _prefix ## _user_call_env[] = { \
	{ FR_CALL_ENV_OFFSET("base_dn", FR_TYPE_STRING, _struct, user_base, \
			     "", T_SINGLE_QUOTED_STRING, true, false, true) }, \
	{ FR_CALL_ENV_OFFSET("filter", FR_TYPE_STRING, _struct, user_filter, \
			     NULL, T_INVALID, false, true, true) }, \
	##__VA_ARGS__, \
	CALL_ENV_TERMINATOR \
}

user_call_env(auth, ldap_auth_call_env_t, { FR_CALL_ENV_SUBSECTION("sasl", NULL, sasl_call_env)} );

user_call_env(autz, ldap_autz_call_env_t);

user_call_env(usermod, ldap_usermod_call_env_t);

user_call_env(memberof, ldap_memberof_call_env_t);

/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_STRING, rlm_ldap_t, groupobj_filter) },
	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, rlm_ldap_t, groupobj_scope_str), .dflt = "sub" },

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

static const call_env_t autz_group_call_env[] = {
	{ FR_CALL_ENV_OFFSET("base_dn", FR_TYPE_STRING, ldap_autz_call_env_t, group_base,
			     NULL, T_INVALID, false, false, true) },
	CALL_ENV_TERMINATOR
};

static const call_env_t memberof_group_call_env[] = {
	{ FR_CALL_ENV_OFFSET("base_dn", FR_TYPE_STRING, ldap_memberof_call_env_t, group_base,
			       NULL, T_INVALID, false, false, true) },
	CALL_ENV_TERMINATOR
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{ FR_CONF_OFFSET("reference", FR_TYPE_STRING | FR_TYPE_XLAT, ldap_acct_section_t, reference), .dflt = "." },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_MULTI, rlm_ldap_t, handle_config.server_str) },	/* Do not set to required */

	/*
	 *	Common LDAP conf parsers
	 */
	FR_LDAP_COMMON_CONF(rlm_ldap_t),

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

	{ FR_CONF_OFFSET("pool", FR_TYPE_SUBSECTION, rlm_ldap_t, trunk_conf), .subcs = (void const *) fr_trunk_config },

	{ FR_CONF_OFFSET("bind_pool", FR_TYPE_SUBSECTION, rlm_ldap_t, bind_trunk_conf),
	  .subcs = (void const *) fr_trunk_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	Method specific call environments
 */
static const call_env_t authenticate_call_env[] = {
	{ FR_CALL_ENV_SUBSECTION("user", NULL, auth_user_call_env) },
	CALL_ENV_TERMINATOR
};

static const call_env_t authorize_call_env[] = {
	{ FR_CALL_ENV_SUBSECTION("user", NULL, autz_user_call_env) },
	{ FR_CALL_ENV_SUBSECTION("group", NULL, autz_group_call_env) },
	{ FR_CALL_ENV_SUBSECTION("profile", NULL, autz_profile_call_env) },
	CALL_ENV_TERMINATOR
};

static const call_env_t usermod_call_env[] = {
	{ FR_CALL_ENV_SUBSECTION("user", NULL, usermod_user_call_env) },
	CALL_ENV_TERMINATOR
};

static const call_env_t memberof_call_env[] = {
	{ FR_CALL_ENV_SUBSECTION("user", NULL, memberof_user_call_env) },
	{ FR_CALL_ENV_SUBSECTION("group", NULL, memberof_group_call_env) },
	CALL_ENV_TERMINATOR
};

static const call_method_env_t authenticate_method_env = {
	.inst_size = sizeof(ldap_auth_call_env_t),
	.inst_type = "ldap_auth_call_env_t",
	.env = authenticate_call_env
};

static const call_method_env_t authorize_method_env = {
	.inst_size = sizeof(ldap_autz_call_env_t),
	.inst_type = "ldap_autz_call_env_t",
	.env = authorize_call_env
};

static const call_method_env_t usermod_method_env = {
	.inst_size = sizeof(ldap_usermod_call_env_t),
	.inst_type = "ldap_usermod_call_env_t",
	.env = usermod_call_env
};

static const call_method_env_t memberof_method_env = {
	.inst_size = sizeof(ldap_memberof_call_env_t),
	.inst_type = "ldap_memberof_call_env_t",
	.env = memberof_call_env
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
	{ .out = &attr_nt_password, .name = "Password.NT", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password.With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

extern global_lib_autoinst_t const *rlm_ldap_lib[];
global_lib_autoinst_t const *rlm_ldap_lib[] = {
	&fr_libldap_global_config,
	GLOBAL_LIB_TERMINATOR
};

/** Holds state of in progress async authentication
 *
 */
typedef struct {
	char const		*dn;
	char const		*password;
	rlm_ldap_t const	*inst;
	fr_ldap_thread_t	*thread;
	ldap_auth_call_env_t	*call_env;
} ldap_auth_ctx_t;

/** Holds state of in progress async profile lookups
 *
 */
typedef struct {
	fr_ldap_query_t		*query;
	char const		*dn;
	rlm_ldap_t const	*inst;
	fr_ldap_map_exp_t	const *expanded;
} ldap_profile_ctx_t;

/** Holds state of in progress ldap user modifications
 *
 */
typedef struct {
	rlm_ldap_t const	*inst;
	ldap_usermod_call_env_t	*call_env;
	char const		*dn;
	char			*passed[LDAP_MAX_ATTRMAP * 2];
	LDAPMod			*mod_p[LDAP_MAX_ATTRMAP + 1];
	LDAPMod			mod_s[LDAP_MAX_ATTRMAP];
	fr_ldap_thread_trunk_t	*ttrunk;
	fr_ldap_query_t		*query;
} ldap_user_modify_ctx_t;

/** Holds state of in progress LDAP map
 *
 */
typedef struct {
	map_list_t const	*maps;
	LDAPURLDesc		*ldap_url;
	fr_ldap_query_t		*query;
	fr_ldap_map_exp_t	expanded;
	char const		*host_url;
} ldap_map_ctx_t;

static xlat_arg_parser_t const ldap_escape_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Escape LDAP string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_escape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*vb, *in_vb = fr_value_box_list_head(in);
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	MEM(vb = fr_value_box_alloc_null(ctx));
	/*
	 *	Maximum space needed for output would be 3 times the input if every
	 *	char needed escaping
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, in_vb->vb_length * 3, in_vb->vb_length * 3)) {
		REDEBUG("Failed to allocate buffer for escaped string");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the escape function, including the space for the trailing NULL
	 */
	len = fr_ldap_escape_func(request, fr_sbuff_buff(&sbuff), in_vb->vb_length * 3 + 1, in_vb->vb_strvalue, NULL);

	/*
	 *	Trim buffer to fit used space and assign to box
	 */
	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), in_vb->tainted);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

/** Unescape LDAP string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_unescape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*vb, *in_vb = fr_value_box_list_head(in);
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	MEM(vb = fr_value_box_alloc_null(ctx));
	/*
	 *	Maximum space needed for output will be the same as the input
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, in_vb->vb_length, in_vb->vb_length)) {
		REDEBUG("Failed to allocate buffer for unescaped string");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the unescape function, including the space for the trailing NULL
	 */
	len = fr_ldap_unescape_func(request, fr_sbuff_buff(&sbuff), in_vb->vb_length + 1, in_vb->vb_strvalue, NULL);

	/*
	 *	Trim buffer to fit used space and assign to box
	 */
	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), in_vb->tainted);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Escape function for a part of an LDAP URI
 *
 */
static int uri_part_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	/*
	 *	Maximum space needed for output would be 3 times the input if every
	 *	char needed escaping
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, vb->vb_length * 3, vb->vb_length * 3)) {
		fr_strerror_printf_push("Failed to allocate buffer for escaped argument");
		return -1;
	}

	/*
	 *	Call the escape function, including the space for the trailing NULL
	 */
	len = fr_ldap_escape_func(NULL, fr_sbuff_buff(&sbuff), vb->vb_length * 3 + 1, vb->vb_strvalue, NULL);

	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_clear_value(vb);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), vb->tainted);

	return 0;
}

/** Callback when LDAP query times out
 *
 */
static void ldap_query_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_trunk_request_t	*treq = talloc_get_type_abort(uctx, fr_trunk_request_t);
	fr_ldap_query_t		*query = talloc_get_type_abort(treq->preq, fr_ldap_query_t);
	request_t		*request = treq->request;

	ROPTIONAL(RERROR, ERROR, "Timeout waiting for LDAP query");
	if (query->msgid) {
		fr_trunk_request_signal_cancel(query->treq);
	}

	query->ret = LDAP_RESULT_TIMEOUT;
	unlang_interpret_mark_runnable(request);
}

/** Callback when resuming after async ldap query is completed
 *
 */
static xlat_action_t ldap_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
	 			      request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_ldap_query_t		*query = talloc_get_type_abort(xctx->rctx, fr_ldap_query_t);
	fr_ldap_connection_t	*ldap_conn = query->ldap_conn;
	fr_value_box_t		*vb = NULL;
	LDAPMessage		*msg;
	struct berval		**values;
	char const		**attr;
	int			count, i;

	if (query->ret != LDAP_RESULT_SUCCESS) return XLAT_ACTION_FAIL;

	/*
	 *	We only parse "entries"
	 */
	for (msg = ldap_first_entry(ldap_conn->handle, query->result); msg; msg = ldap_next_entry(ldap_conn->handle, msg)) {
		for (attr = query->search.attrs; *attr; attr++) {
			values = ldap_get_values_len(ldap_conn->handle, msg, *attr);
			if (!values) {
				RDEBUG2("No \"%s\" attributes found in specified object", *attr);
				continue;
			}

			count = ldap_count_values_len(values);
			for (i = 0; i < count; i++) {
				MEM(vb = fr_value_box_alloc_null(ctx));
				if (fr_value_box_bstrndup(ctx, vb, NULL, values[i]->bv_val, values[i]->bv_len, true) < 0) {
					talloc_free(vb);
					RPERROR("Failed creating value from LDAP response");
					break;
				}
				fr_dcursor_append(out, vb);
			}
			ldap_value_free_len(values);
		}
	}

	talloc_free(query);

	return XLAT_ACTION_DONE;
}

/** Callback for signalling async ldap query
 *
 */
static void ldap_xlat_signal(xlat_ctx_t const *xctx, request_t *request, UNUSED fr_signal_t action)
{
	fr_ldap_query_t		*query = talloc_get_type_abort(xctx->rctx, fr_ldap_query_t);

	RDEBUG2("Forcefully cancelling pending LDAP query");

	fr_trunk_request_signal_cancel(query->treq);
}


static fr_uri_part_t const ldap_uri_parts[] = {
	{ .name = "scheme", .terminals = &FR_SBUFF_TERMS(L(":")), .part_adv = { [':'] = 1 },
	  .tainted_allowed = false, .extra_skip = 2 },
	{ .name = "host", .terminals = &FR_SBUFF_TERMS(L(":"), L("/")), .part_adv = { [':'] = 1, ['/'] = 2 },
	  .tainted_allowed = false },
	{ .name = "port", .terminals = &FR_SBUFF_TERMS(L("/")), .part_adv = { ['/'] = 1 },
	  .tainted_allowed = false },
	{ .name = "dn", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 },
	  .tainted_allowed = true, .func = uri_part_escape },
	{ .name = "attrs", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 },
	  .tainted_allowed = false },
	{ .name = "scope", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 },
	  .tainted_allowed = true, .func = uri_part_escape },
	{ .name = "filter", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1},
	  .tainted_allowed = true, .func = uri_part_escape },
	{ .name = "exts", .tainted_allowed = true, .func = uri_part_escape },
	XLAT_URI_PART_TERMINATOR
};

static xlat_arg_parser_t const ldap_xlat_arg[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
			       xlat_ctx_t const *xctx,
	 		       request_t *request, fr_value_box_list_t *in)
{
	fr_ldap_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, fr_ldap_thread_t);
	fr_value_box_t		*uri_components, *uri;
	char			*host_url;
	fr_ldap_config_t const	*handle_config = t->config;
	fr_ldap_thread_trunk_t	*ttrunk;
	fr_ldap_query_t		*query = NULL;

	LDAPURLDesc		*ldap_url;

	XLAT_ARGS(in, &uri_components);

	if (fr_uri_escape(&uri_components->vb_group, ldap_uri_parts, NULL) < 0) return XLAT_ACTION_FAIL;

	/*
	 *	Smush everything into the first URI box
	 */
	uri = fr_value_box_list_head(&uri_components->vb_group);

	if (fr_value_box_list_concat_in_place(uri, uri, &uri_components->vb_group,
					      FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		REDEBUG("Failed concattenating input");
		return XLAT_ACTION_FAIL;
	}

	if (!ldap_is_ldap_url(uri->vb_strvalue)) {
		REDEBUG("String passed does not look like an LDAP URL");
		return XLAT_ACTION_FAIL;
	}

	if (ldap_url_parse(uri->vb_strvalue, &ldap_url)){
		REDEBUG("Parsing LDAP URL failed");
	error:
		ldap_free_urldesc(ldap_url);
		talloc_free(query);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Nothing, empty string, "*" string, or got 2 things, die.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] || !*ldap_url->lud_attrs[0] ||
	    (strcmp(ldap_url->lud_attrs[0], "*") == 0) || ldap_url->lud_attrs[1]) {
		REDEBUG("Bad attributes list in LDAP URL. URL must specify exactly one attribute to retrieve");

		goto error;
	}

	query = fr_ldap_search_alloc(unlang_interpret_frame_talloc_ctx(request),
				     ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter,
				     (char const * const*)ldap_url->lud_attrs, NULL, NULL);
	if (ldap_url->lud_exts) {
		LDAPControl	*serverctrls[LDAP_MAX_CONTROLS];
		int		i;

		if (fr_ldap_parse_url_extensions(serverctrls, NUM_ELEMENTS(serverctrls),
						 query->ldap_url->lud_exts) < 0) {
			RPERROR("Parsing URL extensions failed");
			goto error;
		}

		for (i = 0; i < LDAP_MAX_CONTROLS; i++) {
			if (!serverctrls[i]) break;
			query->serverctrls[i].control = serverctrls[i];
			query->serverctrls[i].freeit = true;
		}
	}

	/*
	 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
	 */
	if (!ldap_url->lud_host) {
		host_url = handle_config->server;
	} else {
		host_url = talloc_asprintf(query, "%s://%s:%d", ldap_url->lud_scheme,
	                        	   ldap_url->lud_host, ldap_url->lud_port);
	}

	ttrunk = fr_thread_ldap_trunk_get(t, host_url, handle_config->admin_identity,
					  handle_config->admin_password, request, handle_config);
	if (!ttrunk) {
		REDEBUG("Unable to get LDAP query for xlat");
		goto error;
	}

	query->ldap_url = ldap_url;	/* query destructor will free URL */

	fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL);

	if (fr_event_timer_in(query, unlang_interpret_event_list(request), &query->ev, handle_config->res_timeout,
			      ldap_query_timeout, query->treq) < 0) {
		REDEBUG("Unable to set timeout for LDAP query");
		fr_trunk_request_signal_cancel(query->treq);
		goto error;
	}

	return unlang_xlat_yield(request, ldap_xlat_resume, ldap_xlat_signal, ~FR_SIGNAL_CANCEL, query);
}

/** User object lookup as part of group membership xlat
 *
 * Called if the ldap membership xlat is used and the user DN is not already known
 */
static unlang_action_t ldap_memberof_xlat_user_find(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
						    request_t *request, void *uctx)
{
	ldap_memberof_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(uctx, ldap_memberof_xlat_ctx_t);

	if (xlat_ctx->env_data->user_filter.type == FR_TYPE_STRING) xlat_ctx->filter = &xlat_ctx->env_data->user_filter;

	xlat_ctx->basedn = &xlat_ctx->env_data->user_base;

	return rlm_ldap_find_user_async(xlat_ctx, xlat_ctx->inst, request, xlat_ctx->basedn, xlat_ctx->filter,
					xlat_ctx->ttrunk, xlat_ctx->attrs, &xlat_ctx->query);
}

/** Cancel an in-progress query for the LDAP group membership xlat
 *
 */
static void ldap_memberof_xlat_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_memberof_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(uctx, ldap_memberof_xlat_ctx_t);

	if (!xlat_ctx->query || !xlat_ctx->query->treq) return;

	fr_trunk_request_signal_cancel(xlat_ctx->query->treq);
}

#define REPEAT_LDAP_MEMBEROF_XLAT_RESULTS \
	if (unlang_function_repeat_set(request, ldap_memberof_xlat_results) < 0) { \
		rcode = RLM_MODULE_FAIL; \
		goto finish; \
	}

/** Run the state machine for the LDAP membership xlat
 *
 * This is called after each async lookup is completed
 */
static unlang_action_t ldap_memberof_xlat_results(rlm_rcode_t *p_result, UNUSED int *priority,
						  request_t *request, void *uctx)
{
	ldap_memberof_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(uctx, ldap_memberof_xlat_ctx_t);
	rlm_ldap_t const		*inst = xlat_ctx->inst;
	rlm_rcode_t			rcode = RLM_MODULE_NOTFOUND;

	switch (xlat_ctx->status) {
	case GROUP_XLAT_FIND_USER:
		if (!xlat_ctx->dn) xlat_ctx->dn = rlm_find_user_dn_cached(request);
		if (!xlat_ctx->dn) RETURN_MODULE_FAIL;

		if (inst->groupobj_membership_filter) {
			REPEAT_LDAP_MEMBEROF_XLAT_RESULTS;
			if (rlm_ldap_check_groupobj_dynamic(&rcode, request, xlat_ctx) == UNLANG_ACTION_PUSHED_CHILD) {
				xlat_ctx->status = GROUP_XLAT_MEMB_FILTER;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
		}
		FALL_THROUGH;

	case GROUP_XLAT_MEMB_FILTER:
		if (xlat_ctx->found) {
			rcode = RLM_MODULE_OK;
			goto finish;
		}

		if (inst->userobj_membership_attr) {
			REPEAT_LDAP_MEMBEROF_XLAT_RESULTS;
			if (rlm_ldap_check_userobj_dynamic(&rcode, request, xlat_ctx) == UNLANG_ACTION_PUSHED_CHILD) {
				xlat_ctx->status = GROUP_XLAT_MEMB_ATTR;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
		}
		FALL_THROUGH;

	case GROUP_XLAT_MEMB_ATTR:
		if (xlat_ctx->found) rcode = RLM_MODULE_OK;
		break;
	}

finish:
	RETURN_MODULE_RCODE(rcode);
}

/** Process the results of evaluating LDAP group membership
 *
 */
static xlat_action_t ldap_memberof_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					    UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	ldap_memberof_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(xctx->rctx, ldap_memberof_xlat_ctx_t);
	fr_value_box_t			*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
	vb->vb_bool = xlat_ctx->found;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const ldap_memberof_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Check for a user being in a LDAP group
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_memberof_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
	 				request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t			*vb = NULL, *group_vb = fr_value_box_list_pop_head(in);
	rlm_ldap_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t		*t = talloc_get_type_abort(xctx->mctx->thread, fr_ldap_thread_t);
	ldap_memberof_call_env_t	*env_data = talloc_get_type_abort(xctx->env_data, ldap_memberof_call_env_t);
	bool				group_is_dn;
	ldap_memberof_xlat_ctx_t	*xlat_ctx;

	RDEBUG2("Searching for user in group \"%pV\"", group_vb);

	if (group_vb->vb_length == 0) {
		REDEBUG("Cannot do comparison (group name is empty)");
		return XLAT_ACTION_FAIL;
	}

	group_is_dn = fr_ldap_util_is_dn(group_vb->vb_strvalue, group_vb->vb_length);
	if (group_is_dn) {
		char	*norm;
		size_t	len;

		MEM(norm = talloc_array(group_vb, char, talloc_array_length(group_vb->vb_strvalue)));
		len = fr_ldap_util_normalise_dn(norm, group_vb->vb_strvalue);

		/*
		 *	Will clear existing buffer (i.e. group_vb->vb_strvalue)
		 */
		fr_value_box_bstrdup_buffer_shallow(group_vb, group_vb, NULL, norm, group_vb->tainted);

		/*
		 *	Trim buffer to match normalised DN
		 */
		fr_value_box_bstr_realloc(group_vb, NULL, group_vb, len);
	}

	if ((group_is_dn && inst->cacheable_group_dn) || (!group_is_dn && inst->cacheable_group_name)) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_cached(&our_rcode, inst, request, group_vb);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			RDEBUG2("User is not a member of \"%pV\"", group_vb);
			return XLAT_ACTION_DONE;

		case RLM_MODULE_OK:
			MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
			vb->vb_bool = true;
			fr_dcursor_append(out, vb);
			return XLAT_ACTION_DONE;

		/*
		 *	Fallback to dynamic search
		 */
		default:
			break;
		}
	}

	MEM(xlat_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_memberof_xlat_ctx_t));

	*xlat_ctx = (ldap_memberof_xlat_ctx_t){
		.inst = inst,
		.group = group_vb,
		.dn = rlm_find_user_dn_cached(request),
		.attrs = { inst->userobj_membership_attr, NULL },
		.group_is_dn = group_is_dn,
		.env_data = env_data
	};

	xlat_ctx->ttrunk = fr_thread_ldap_trunk_get(t, inst->handle_config.server, inst->handle_config.admin_identity,
						    inst->handle_config.admin_password, request, &inst->handle_config);

	if (!xlat_ctx->ttrunk) {
		REDEBUG("Unable to get LDAP trunk for group membership check");
	error:
		talloc_free(xlat_ctx);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_yield(request, ldap_memberof_xlat_resume, NULL, 0, xlat_ctx) != XLAT_ACTION_YIELD) goto error;

	if (unlang_function_push(request, xlat_ctx->dn ? NULL : ldap_memberof_xlat_user_find,
				 ldap_memberof_xlat_results, ldap_memberof_xlat_cancel, ~FR_SIGNAL_CANCEL,
				 UNLANG_SUB_FRAME, xlat_ctx) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

/*
 *	Verify the result of the map.
 */
static int ldap_map_verify(CONF_SECTION *cs, UNUSED void *mod_inst, UNUSED void *proc_inst,
			   tmpl_t const *src, UNUSED map_list_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing LDAP URI");

		return -1;
	}

	return 0;
}

/** Process the results of an LDAP map query
 *
 * @param[out] p_result	Result of applying the map.
 * @param[in] priority	Unused.
 * @param[in] request	Current request.
 * @param[in] uctx	Map context.
 * @return One of UNLANG_ACTION_*
 */
static unlang_action_t mod_map_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	ldap_map_ctx_t		*map_ctx = talloc_get_type_abort(uctx, ldap_map_ctx_t);
	fr_ldap_query_t		*query = map_ctx->query;
	fr_ldap_map_exp_t	*expanded = &map_ctx->expanded;
	rlm_rcode_t		rcode = RLM_MODULE_NOTFOUND;
	LDAPMessage		*entry;
	map_t const		*map;

	switch (query->ret) {
	case LDAP_RESULT_SUCCESS:
		rcode = RLM_MODULE_UPDATED;
		break;

	case LDAP_RESULT_NO_RESULT:
		goto finish;

	default:
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	for (entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	     entry;
	     entry = ldap_next_entry(query->ldap_conn->handle, entry)) {
		char	*dn = NULL;
		int	i;

		if (RDEBUG_ENABLED2) {
			dn = ldap_get_dn(query->ldap_conn->handle, entry);
			RDEBUG2("Processing \"%s\"", dn);
		}

		RINDENT();
		for (map = map_list_head(map_ctx->maps), i = 0;
		     map != NULL;
		     map = map_list_next(map_ctx->maps, map), i++) {
			int			ret;
			fr_ldap_result_t	attr;

			attr.values = ldap_get_values_len(query->ldap_conn->handle, entry, expanded->attrs[i]);
			if (!attr.values) {
				/*
				 *	Many LDAP directories don't expose the DN of
				 *	the object as an attribute, so we need this
				 *	hack, to allow the user to retrieve it.
				 */
				if (strcmp(LDAP_VIRTUAL_DN_ATTR, expanded->attrs[i]) == 0) {
					struct berval value;
					struct berval *values[2] = { &value, NULL };

					if (!dn) dn = ldap_get_dn(query->ldap_conn->handle, entry);
					value.bv_val = dn;
					value.bv_len = strlen(dn);

					attr.values = values;
					attr.count = 1;

					ret = map_to_request(request, map, fr_ldap_map_getvalue, &attr);
					if (ret == -1) {
						rcode = RLM_MODULE_FAIL;
						ldap_memfree(dn);
						goto finish;
					}
					continue;
				}

				RDEBUG3("Attribute \"%s\" not found in LDAP object", expanded->attrs[i]);

				continue;
			}
			attr.count = ldap_count_values_len(attr.values);

			ret = map_to_request(request, map, fr_ldap_map_getvalue, &attr);
			ldap_value_free_len(attr.values);
			if (ret == -1) {
				rcode = RLM_MODULE_FAIL;
				ldap_memfree(dn);
				goto finish;
			}
		}
		ldap_memfree(dn);
		REXDENT();
	}

finish:
	RETURN_MODULE_RCODE(rcode);
}

/**  Ensure map context is properly cleared up
 *
 */
static int map_ctx_free(ldap_map_ctx_t *map_ctx)
{
	talloc_free(map_ctx->expanded.ctx);
	ldap_free_urldesc(map_ctx->ldap_url);
	return (0);
}

/** Perform a search and map the result of the search to server attributes
 *
 * Unlike LDAP xlat, this can be used to process attributes from multiple entries.
 *
 * @todo For xlat expansions we need to parse the raw URL first, and then apply
 *	different escape functions to the different parts.
 *
 * @param[out] p_result	Result of map expansion:
 *			- #RLM_MODULE_NOOP no rows were returned.
 *			- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *			- #RLM_MODULE_FAIL if an error occurred.
 * @param[in] mod_inst #rlm_ldap_t
 * @param[in] proc_inst unused.
 * @param[in,out] request The current request.
 * @param[in] url LDAP url specifying base DN and filter.
 * @param[in] maps Head of the map list.
 * @return UNLANG_ACTION_CALCULATE_RESULT
 */
static unlang_action_t mod_map_proc(rlm_rcode_t *p_result, void *mod_inst, UNUSED void *proc_inst, request_t *request,
				    fr_value_box_list_t *url, map_list_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_UPDATED;
	rlm_ldap_t		*inst = talloc_get_type_abort(mod_inst, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);

	LDAPURLDesc		*ldap_url;
	char const 		*url_str;

	fr_ldap_thread_trunk_t	*ttrunk;

	fr_value_box_t		*url_head = fr_value_box_list_head(url);
	ldap_map_ctx_t		*map_ctx;

	/*
	 *	FIXME - Maybe it can be NULL?
	 */
	if (!url_head) {
		REDEBUG("LDAP URL cannot be (null)");
		RETURN_MODULE_FAIL;
	}

	if (fr_value_box_list_concat_in_place(request,
					      url_head, url, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true,
					      SIZE_MAX) < 0) {
		REDEBUG("Failed concatenating input");
		RETURN_MODULE_FAIL;
	}
	url_str = url_head->vb_strvalue;

	if (!ldap_is_ldap_url(url_str)) {
		REDEBUG("Map query string does not look like a valid LDAP URI");
		RETURN_MODULE_FAIL;
	}

	MEM(map_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), ldap_map_ctx_t));
	talloc_set_destructor(map_ctx, map_ctx_free);
	map_ctx->maps = maps;

	if (ldap_url_parse(url_str, &map_ctx->ldap_url)){
		REDEBUG("Parsing LDAP URL failed");
	fail:
		talloc_free(map_ctx);
		RETURN_MODULE_FAIL;
	}
	ldap_url = map_ctx->ldap_url;

	/*
	 *	Expand the RHS of the maps to get the name of the attributes.
	 */
	if (fr_ldap_map_expand(&map_ctx->expanded, request, maps) < 0) goto fail;

	/*
	 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
	 */
	if (!ldap_url->lud_host) {
		map_ctx->host_url = inst->handle_config.server;
	} else {
		map_ctx->host_url = talloc_asprintf(map_ctx, "%s://%s:%d", ldap_url->lud_scheme,
						    ldap_url->lud_host, ldap_url->lud_port);
	}

	ttrunk =  fr_thread_ldap_trunk_get(thread, map_ctx->host_url, inst->handle_config.admin_identity,
					   inst->handle_config.admin_password, request, &inst->handle_config);
	if (!ttrunk) goto fail;

	if (unlang_function_push(request, NULL, mod_map_resume, NULL, 0,
				 UNLANG_SUB_FRAME, map_ctx) != UNLANG_ACTION_PUSHED_CHILD) goto fail;

	return fr_ldap_trunk_search(&rcode, map_ctx, &map_ctx->query, request, ttrunk, ldap_url->lud_dn,
				    ldap_url->lud_scope, ldap_url->lud_filter, map_ctx->expanded.attrs,
				    NULL, NULL);
}

/** Perform async lookup of user DN if required for authentication
 *
 */
static unlang_action_t mod_authenticate_start(rlm_rcode_t *p_result, UNUSED int *priority,
					      request_t *request, void *uctx)
{
	ldap_auth_ctx_t		*auth_ctx = talloc_get_type_abort(uctx, ldap_auth_ctx_t);
	fr_ldap_thread_trunk_t	*ttrunk;
	rlm_ldap_t const 	*inst = auth_ctx->inst;

	ttrunk = fr_thread_ldap_trunk_get(auth_ctx->thread, inst->handle_config.server, inst->handle_config.admin_identity,
					  inst->handle_config.admin_password, request, &inst->handle_config);
	if (!ttrunk) RETURN_MODULE_FAIL;

	return rlm_ldap_find_user_async(auth_ctx, auth_ctx->inst, request, &auth_ctx->call_env->user_base,
					&auth_ctx->call_env->user_filter, ttrunk, NULL, NULL);
}

/** Initiate async LDAP bind to authenticate user
 *
 */
static unlang_action_t mod_authenticate_resume(rlm_rcode_t *p_result, UNUSED int *priority,
					       request_t *request, void *uctx)
{
	ldap_auth_ctx_t	*auth_ctx = talloc_get_type_abort(uctx, ldap_auth_ctx_t);

	/*
	 *	Arriving here from an LDAP search will mean the dn in auth_ctx is NULL.
	 */
	if (!auth_ctx->dn) auth_ctx->dn = rlm_find_user_dn_cached(request);

	/*
	 *	No DN found - can't authenticate the user.
	 */
	if (!auth_ctx->dn) {
	fail:
		talloc_free(auth_ctx);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Attempt a bind using the thread specific trunk for bind auths
	 */
	if (auth_ctx->call_env->user_sasl_mech.type == FR_TYPE_STRING) {
#ifdef WITH_SASL
		ldap_auth_call_env_t *call_env = auth_ctx->call_env;
		if (fr_ldap_sasl_bind_auth_async(request, auth_ctx->thread, call_env->user_sasl_mech.vb_strvalue,
						 auth_ctx->dn, call_env->user_sasl_authname.vb_strvalue,
						 auth_ctx->password, call_env->user_sasl_proxy.vb_strvalue,
						 call_env->user_sasl_realm.vb_strvalue) < 0) goto fail;
#else
		RDEBUG("Configuration item 'sasl.mech' is not supported.  "
		       "The linked version of libldap does not provide ldap_sasl_bind( function");
		RETURN_MODULE_FAIL;
#endif
	} else {
		if (fr_ldap_bind_auth_async(request, auth_ctx->thread, auth_ctx->dn, auth_ctx->password) < 0) goto fail;
	}
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);
	ldap_auth_ctx_t		*auth_ctx;
	ldap_auth_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, ldap_auth_call_env_t);

	fr_pair_t *username, *password;

	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	password = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_password);

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

	RDEBUG2("Login attempt by \"%pV\"", &username->data);

	auth_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_auth_ctx_t);
	*auth_ctx = (ldap_auth_ctx_t){
		.password = password->vp_strvalue,
		.thread = thread,
		.inst = inst,
		.call_env = call_env
	};

	/*
	 *	Check for a cahed copy of the DN
	 */
	auth_ctx->dn = rlm_find_user_dn_cached(request);

	if (unlang_function_push(request, auth_ctx->dn ? NULL : mod_authenticate_start, mod_authenticate_resume,
				 NULL, 0, UNLANG_SUB_FRAME, auth_ctx) < 0) RETURN_MODULE_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Process the results of a profile lookup
 *
 */
static unlang_action_t ldap_map_profile_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request,
					       void *uctx)
{
	ldap_profile_ctx_t	*profile_ctx = talloc_get_type_abort(uctx, ldap_profile_ctx_t);
	fr_ldap_query_t		*query = profile_ctx->query;
	LDAP			*handle;
	LDAPMessage		*entry = NULL;
	int			ldap_errno;
	rlm_rcode_t		rcode = RLM_MODULE_OK;

	switch (query->ret) {
	case LDAP_RESULT_SUCCESS:
		break;

	case LDAP_RESULT_NO_RESULT:
	case LDAP_RESULT_BAD_DN:
		RDEBUG2("Profile object \"%s\" not found", profile_ctx->dn);
		rcode = RLM_MODULE_NOTFOUND;
		goto finish;

	default:
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	fr_assert(query->result);
	handle = query->ldap_conn->handle;

	entry = ldap_first_entry(handle, query->result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
		rcode = RLM_MODULE_NOTFOUND;
		goto finish;
	}

	RDEBUG2("Processing profile attributes");
	RINDENT();
	if (fr_ldap_map_do(request, profile_ctx->inst->valuepair_attr,
			   profile_ctx->expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
	REXDENT();

finish:
	talloc_free(profile_ctx);
	RETURN_MODULE_RCODE(rcode);
}

/** Cancel an in progress profile lookup
 *
 */
static void ldap_map_profile_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_profile_ctx_t	*profile_ctx = talloc_get_type_abort(uctx, ldap_profile_ctx_t);

	if (!profile_ctx->query || !profile_ctx->query->treq) return;

	fr_trunk_request_signal_cancel(profile_ctx->query->treq);
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common
 * sets of attributes to the request.
 *
 * @param[in] request		Current request.
 * @param[in] autz_ctx		Authorization context being processed.
 * @param[in] dn		of profile object to apply.
 * @param[in] expanded		Structure containing a list of xlat
 *				expanded attribute names and mapping information.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t rlm_ldap_map_profile(request_t *request, ldap_autz_ctx_t *autz_ctx,
					    char const *dn, fr_ldap_map_exp_t const *expanded)
{
	rlm_ldap_t const	*inst = autz_ctx->inst;
	fr_ldap_thread_trunk_t	*ttrunk = autz_ctx->ttrunk;
	ldap_profile_ctx_t	*profile_ctx;
	rlm_rcode_t		ret;

	if (!dn || !*dn) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(profile_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_profile_ctx_t));
	*profile_ctx = (ldap_profile_ctx_t) {
		.dn = dn,
		.expanded = expanded,
		.inst = inst
	};

	if (unlang_function_push(request, NULL, ldap_map_profile_resume, ldap_map_profile_cancel,
				 ~FR_SIGNAL_CANCEL, UNLANG_SUB_FRAME, profile_ctx) < 0) {
		talloc_free(profile_ctx);
		return UNLANG_ACTION_FAIL;
	}

	return fr_ldap_trunk_search(&ret, profile_ctx, &profile_ctx->query, request, ttrunk, dn,
				    LDAP_SCOPE_BASE, autz_ctx->call_env->profile_filter.vb_strvalue,
				    expanded->attrs, NULL, NULL);
}

/** Start LDAP authorization with async lookup of user DN
 *
 */
static unlang_action_t mod_authorize_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
					   request_t *request, void *uctx)
{
	ldap_autz_ctx_t	*autz_ctx = talloc_get_type_abort(uctx, ldap_autz_ctx_t);
	return rlm_ldap_find_user_async(autz_ctx, autz_ctx->inst, request, &autz_ctx->call_env->user_base,
					&autz_ctx->call_env->user_filter, autz_ctx->ttrunk, autz_ctx->expanded.attrs,
					&autz_ctx->query);
}

#define REPEAT_MOD_AUTHORIZE_RESUME \
	if (unlang_function_repeat_set(request, mod_authorize_resume) < 0) { \
		rcode = RLM_MODULE_FAIL; \
		goto finish; \
	}

/** Resume function called after each potential yield in LDAP authorization
 *
 * Some operations may or may not yeild.  E.g. if group membership is
 * read from an attribute returned with the user object and is already
 * in the correct form, that will not yeild.
 * Hence, each state may fall through to the next.
 *
 * @param p_result	Result of current authorization.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		Current authrorization context.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t mod_authorize_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	ldap_autz_ctx_t		*autz_ctx = talloc_get_type_abort(uctx, ldap_autz_ctx_t);
	rlm_ldap_t const	*inst = talloc_get_type_abort_const(autz_ctx->inst, rlm_ldap_t);
	ldap_autz_call_env_t	*call_env = talloc_get_type_abort(autz_ctx->call_env, ldap_autz_call_env_t);
	int			ldap_errno;
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	LDAP			*handle = fr_ldap_handle_thread_local();

	switch (autz_ctx->status) {
	case LDAP_AUTZ_FIND:
		/*
		 *	If a user entry has been found the current rcode will be OK
		 */
		if (*p_result != RLM_MODULE_OK) return UNLANG_ACTION_CALCULATE_RESULT;

		autz_ctx->entry = ldap_first_entry(handle, autz_ctx->query->result);
		if (!autz_ctx->entry) {
			ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
			REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

			goto finish;
		}

		/*
		 *	Check for access.
		 */
		if (inst->userobj_access_attr) {
			rcode = rlm_ldap_check_access(inst, request, autz_ctx->entry);
			if (rcode != RLM_MODULE_OK) {
				goto finish;
			}
		}

		/*
		 *	Check if we need to cache group memberships
		 */
		if ((inst->cacheable_group_dn || inst->cacheable_group_name) && (inst->userobj_membership_attr)) {
			REPEAT_MOD_AUTHORIZE_RESUME;
			if (rlm_ldap_cacheable_userobj(&rcode, request, autz_ctx,
						       inst->userobj_membership_attr) == UNLANG_ACTION_PUSHED_CHILD) {
				autz_ctx->status = LDAP_AUTZ_GROUP;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
			if (rcode != RLM_MODULE_OK) goto finish;
		}
		FALL_THROUGH;

	case LDAP_AUTZ_GROUP:
		if (inst->cacheable_group_dn || inst->cacheable_group_name) {
			REPEAT_MOD_AUTHORIZE_RESUME;
			if (rlm_ldap_cacheable_groupobj(&rcode, request, autz_ctx) == UNLANG_ACTION_PUSHED_CHILD) {
				autz_ctx->status = LDAP_AUTZ_POST_GROUP;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
			if (rcode != RLM_MODULE_OK) goto finish;
		}
		FALL_THROUGH;

	case LDAP_AUTZ_POST_GROUP:
#ifdef WITH_EDIR
		/*
		 *	We already have a Password.Cleartext.  Skip edir.
		 */
		if (fr_pair_find_by_da(&request->control_pairs, NULL, attr_cleartext_password)) goto skip_edir;

		/*
		 *      Retrieve Universal Password if we use eDirectory
		 */
		if (inst->edir) {
			autz_ctx->dn = rlm_find_user_dn_cached(request);;

			/*
			 *	Retrive universal password
			 */
			REPEAT_MOD_AUTHORIZE_RESUME;
			if (fr_ldap_edir_get_password(p_result, request, autz_ctx->dn, autz_ctx->ttrunk,
						      attr_cleartext_password) < 0) {
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			autz_ctx->status = LDAP_AUTZ_EDIR_BIND;
			return UNLANG_ACTION_PUSHED_CHILD;
		}
		FALL_THROUGH;

	case LDAP_AUTZ_EDIR_BIND:
		if (*p_result != RLM_MODULE_OK) {
			rcode = *p_result;
			goto finish;
		}

		if (inst->edir && inst->edir_autz) {
			fr_pair_t	*password = fr_pair_find_by_da(&request->control_pairs,
								       NULL, attr_cleartext_password);
			fr_ldap_thread_t *thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data,
									 fr_ldap_thread_t);

			if (!password) {
				REDEBUG("Failed to find &control.Password.Cleartext");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}

			RDEBUG2("Binding as %s for eDirectory authorization checks", autz_ctx->dn);

			/*
			 *	Bind as the user
			 */
			REPEAT_MOD_AUTHORIZE_RESUME;
			if (fr_ldap_bind_auth_async(request, thread, autz_ctx->dn, password->vp_strvalue) < 0) {
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			autz_ctx->status = LDAP_AUTZ_POST_EDIR;
			return UNLANG_ACTION_PUSHED_CHILD;
		}
		goto skip_edir;

	case LDAP_AUTZ_POST_EDIR:
		/*
		 *	The result of the eDirectory user bind will be in p_result.
		 *	Anything other than RLM_MODULE_OK is a failure.
		 */
		if (*p_result != RLM_MODULE_OK) {
			rcode = *p_result;
			goto finish;
		}

	skip_edir:
#endif
		/*
		 *	Apply ONE user profile, or a default user profile.
		 */
		if (call_env->default_profile.type == FR_TYPE_STRING) {
			unlang_action_t	ret;

			REPEAT_MOD_AUTHORIZE_RESUME;
			ret = rlm_ldap_map_profile(request, autz_ctx, call_env->default_profile.vb_strvalue,
						   &autz_ctx->expanded);
			switch (ret) {
			case UNLANG_ACTION_FAIL:
				rcode = RLM_MODULE_FAIL;
				goto finish;

			case UNLANG_ACTION_PUSHED_CHILD:
				autz_ctx->status = LDAP_AUTZ_POST_DEFAULT_PROFILE;
				return UNLANG_ACTION_PUSHED_CHILD;

			default:
				break;
			}
		}
		FALL_THROUGH;

	case LDAP_AUTZ_POST_DEFAULT_PROFILE:
		/*
		 *	Apply a SET of user profiles.
		 */
		if (inst->profile_attr) {
			autz_ctx->profile_values = ldap_get_values_len(handle, autz_ctx->entry, inst->profile_attr);
		}
		FALL_THROUGH;

	case LDAP_AUTZ_USER_PROFILE:
		/*
		 *	After each profile has been applied, execution will restart here.
		 *	Start by clearing the previously used value.
		 */
		TALLOC_FREE(autz_ctx->profile_value);

		if (autz_ctx->profile_values && autz_ctx->profile_values[autz_ctx->value_idx]) {
			unlang_action_t	ret;

			autz_ctx->profile_value = fr_ldap_berval_to_string(autz_ctx, autz_ctx->profile_values[autz_ctx->value_idx++]);
			REPEAT_MOD_AUTHORIZE_RESUME;
			ret = rlm_ldap_map_profile(request, autz_ctx, autz_ctx->profile_value, &autz_ctx->expanded);
			switch (ret) {
			case UNLANG_ACTION_FAIL:
				rcode = RLM_MODULE_FAIL;
				goto finish;

			case UNLANG_ACTION_PUSHED_CHILD:
				autz_ctx->status = LDAP_AUTZ_USER_PROFILE;
				return UNLANG_ACTION_PUSHED_CHILD;

			default:
				break;
			}
		}
		FALL_THROUGH;

	case LDAP_AUTZ_MAP:
		if (!map_list_empty(&inst->user_map) || inst->valuepair_attr) {
			RDEBUG2("Processing user attributes");
			RINDENT();
			if (fr_ldap_map_do(request, inst->valuepair_attr,
					   &autz_ctx->expanded, autz_ctx->entry) > 0) rcode = RLM_MODULE_UPDATED;
			REXDENT();
			rlm_ldap_check_reply(&(module_ctx_t){.inst = autz_ctx->dlinst}, request, autz_ctx->ttrunk);
		}
	}

finish:
	talloc_free(autz_ctx);

	RETURN_MODULE_RCODE(rcode);
}

/** Clear up when cancelling a mod_authorize call
 *
 */
static void mod_authorize_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_autz_ctx_t	*autz_ctx = talloc_get_type_abort(uctx, ldap_autz_ctx_t);

	if (autz_ctx->query && autz_ctx->query->treq) fr_trunk_request_signal_cancel(autz_ctx->query->treq);
}

/** Ensure authorization context is properly cleared up
 *
 */
static int autz_ctx_free(ldap_autz_ctx_t *autz_ctx)
{
	talloc_free(autz_ctx->expanded.ctx);
	if (autz_ctx->profile_values) ldap_value_free_len(autz_ctx->profile_values);
	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);
	ldap_autz_ctx_t		*autz_ctx;
	fr_ldap_map_exp_t	*expanded;
	ldap_autz_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, ldap_autz_call_env_t);

	MEM(autz_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), ldap_autz_ctx_t));
	talloc_set_destructor(autz_ctx, autz_ctx_free);
	expanded = &autz_ctx->expanded;

	/*
	 *	Don't be tempted to add a check for User-Name or
	 *	User-Password here.  LDAP authorization can be used
	 *	for many things besides searching for users.
	 */

	if (fr_ldap_map_expand(expanded, request, &inst->user_map) < 0) {
	fail:
		talloc_free(autz_ctx);
		RETURN_MODULE_FAIL;
	}

	autz_ctx->ttrunk =  fr_thread_ldap_trunk_get(thread, inst->handle_config.server, inst->handle_config.admin_identity,
						     inst->handle_config.admin_password, request, &inst->handle_config);
	if (!autz_ctx->ttrunk) goto fail;

	/*
	 *	Add any additional attributes we need for checking access, memberships, and profiles
	 */
	if (inst->userobj_access_attr) expanded->attrs[expanded->count++] = inst->userobj_access_attr;

	if (inst->userobj_membership_attr && (inst->cacheable_group_dn || inst->cacheable_group_name)) {
		expanded->attrs[expanded->count++] = inst->userobj_membership_attr;
	}

	if (inst->profile_attr) expanded->attrs[expanded->count++] = inst->profile_attr;

	if (inst->valuepair_attr) expanded->attrs[expanded->count++] = inst->valuepair_attr;

	expanded->attrs[expanded->count] = NULL;

	autz_ctx->dlinst = mctx->inst;
	autz_ctx->inst = inst;
	autz_ctx->call_env = call_env;
	autz_ctx->status = LDAP_AUTZ_FIND;

	if (unlang_function_push(request, mod_authorize_start, mod_authorize_resume, mod_authorize_cancel,
				 ~FR_SIGNAL_CANCEL, UNLANG_SUB_FRAME, autz_ctx) < 0) RETURN_MODULE_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Perform async lookup of user DN if required for user modification
 *
 */
static unlang_action_t user_modify_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
					 request_t *request, void *uctx)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(uctx, ldap_user_modify_ctx_t);

	return rlm_ldap_find_user_async(usermod_ctx, usermod_ctx->inst, request, &usermod_ctx->call_env->user_base,
		&usermod_ctx->call_env->user_filter, usermod_ctx->ttrunk, NULL, NULL);
}

/** Cancel an in progress user modification.
 *
 */
static void user_modify_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(uctx, ldap_user_modify_ctx_t);

	if (!usermod_ctx->query || !usermod_ctx->query->treq) return;

	fr_trunk_request_signal_cancel(usermod_ctx->query->treq);
}

/** Handle results of user modification.
 *
 */
static unlang_action_t user_modify_final(rlm_rcode_t *p_result, UNUSED int *priority,
					 request_t *request, void *uctx)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(uctx, ldap_user_modify_ctx_t);
	fr_ldap_query_t		*query = usermod_ctx->query;
	rlm_rcode_t		rcode = RLM_MODULE_OK;

	switch (query->ret) {
	case LDAP_RESULT_SUCCESS:
		break;

	case LDAP_RESULT_NO_RESULT:
	case LDAP_RESULT_BAD_DN:
		RDEBUG2("User object \"%s\" not modified", usermod_ctx->dn);
		rcode = RLM_MODULE_INVALID;
		break;

	default:
		rcode = RLM_MODULE_FAIL;
		break;
	}

	talloc_free(usermod_ctx);
	RETURN_MODULE_RCODE(rcode);
}

/** Take the retrieved user DN and launch the async modification.
 *
 */
static unlang_action_t user_modify_resume(rlm_rcode_t *p_result, UNUSED int *priority,
					  request_t *request, void *uctx)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(uctx, ldap_user_modify_ctx_t);
	LDAPMod			**modify = usermod_ctx->mod_p;

	/*
	 *	If an LDAP search was used to find the user DN
	 *	usermod_ctx->dn will be NULL.
	 */
	if (!usermod_ctx->dn) usermod_ctx->dn = rlm_find_user_dn_cached(request);

	if (!usermod_ctx->dn) {
	fail:
		talloc_free(usermod_ctx);
		RETURN_MODULE_FAIL;
	}

	if (unlang_function_push(request, NULL, user_modify_final, user_modify_cancel, ~FR_SIGNAL_CANCEL,
				 UNLANG_SUB_FRAME, usermod_ctx) < 0) goto fail;

	return fr_ldap_trunk_modify(p_result, usermod_ctx, &usermod_ctx->query, request, usermod_ctx->ttrunk,
				    usermod_ctx->dn, modify, NULL, NULL);
}

/** Modify user's object in LDAP
 *
 * Process a modifcation map to update a user object in the LDAP directory.
 *
 * @param[out] p_result		the result of the modification.
 * @param[in] inst		rlm_ldap instance.
 * @param[in] request		Current request.
 * @param[in] section		that holds the map to process.
 * @param[in] call_env		Call environment.  Contains expanded base and filter to find user.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t user_modify(rlm_rcode_t *p_result, rlm_ldap_t const *inst, request_t *request,
				   ldap_acct_section_t *section, ldap_usermod_call_env_t *call_env)
{
	rlm_rcode_t		rcode = RLM_MODULE_FAIL;
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);
	ldap_user_modify_ctx_t	*usermod_ctx = NULL;

	int		total = 0, last_pass = 0;

	char const	*attr;
	char const	*value;

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
	if (section->reference[0] != '.') *p++ = '.';

	if (xlat_eval(p, (sizeof(path) - (p - path)) - 1, request, section->reference, NULL, NULL) < 0) goto error;

	ci = cf_reference_item(NULL, section->cs, path);
	if (!ci) goto error;

	if (!cf_item_is_section(ci)){
		REDEBUG("Reference must resolve to a section");

		goto error;
	}

	cs = cf_section_find(cf_item_to_section(ci), "update", NULL);
	if (!cs) {
		REDEBUG("Section must contain 'update' subsection");

		goto error;
	}

	MEM(usermod_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_user_modify_ctx_t));
	*usermod_ctx = (ldap_user_modify_ctx_t) {
		.inst = inst,
		.call_env = call_env
	};

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
			usermod_ctx->passed[last_pass] = NULL;
		} else if (do_xlat) {
			char *exp = NULL;

			if (xlat_aeval(usermod_ctx, &exp, request, value, NULL, NULL) <= 0) {
				RDEBUG2("Skipping attribute \"%s\"", attr);
				talloc_free(exp);

				continue;
			}

			usermod_ctx->passed[last_pass] = exp;
		/*
		 *	Static strings
		 */
		} else {
			memcpy(&(usermod_ctx->passed[last_pass]), &value, sizeof(usermod_ctx->passed[last_pass]));
		}

		usermod_ctx->passed[last_pass + 1] = NULL;
		usermod_ctx->mod_s[total].mod_values = &(usermod_ctx->passed[last_pass]);
		last_pass += 2;

		switch (op) {
		/*
		 *  T_OP_EQ is *NOT* supported, it is impossible to
		 *  support because of the lack of transactions in LDAP
		 */
		case T_OP_ADD_EQ:
			usermod_ctx->mod_s[total].mod_op = LDAP_MOD_ADD;
			break;

		case T_OP_SET:
			usermod_ctx->mod_s[total].mod_op = LDAP_MOD_REPLACE;
			break;

		case T_OP_SUB_EQ:
		case T_OP_CMP_FALSE:
			usermod_ctx->mod_s[total].mod_op = LDAP_MOD_DELETE;
			break;

		case T_OP_INCRM:
			usermod_ctx->mod_s[total].mod_op = LDAP_MOD_INCREMENT;
			break;

		default:
			REDEBUG("Operator '%s' is not supported for LDAP modify operations",
				fr_table_str_by_value(fr_tokens_table, op, "<INVALID>"));

			goto error;
		}

		/*
		 *	Now we know the value is ok, copy the pointers into
		 *	the ldapmod struct.
		 */
		memcpy(&(usermod_ctx->mod_s[total].mod_type), &attr, sizeof(usermod_ctx->mod_s[total].mod_type));

		usermod_ctx->mod_p[total] = &(usermod_ctx->mod_s[total]);
		total++;
	}

	if (total == 0) {
		rcode = RLM_MODULE_NOOP;
		goto release;
	}

	usermod_ctx->mod_p[total] = NULL;

	usermod_ctx->ttrunk = fr_thread_ldap_trunk_get(thread, inst->handle_config.server,
						       inst->handle_config.admin_identity,
						       inst->handle_config.admin_password,
						       request, &inst->handle_config);
	if (!usermod_ctx->ttrunk) {
		REDEBUG("Unable to get LDAP trunk for update");
		talloc_free(usermod_ctx);
		RETURN_MODULE_FAIL;
	}

	usermod_ctx->dn = rlm_find_user_dn_cached(request);

	if (unlang_function_push(request, usermod_ctx->dn ? NULL : user_modify_start, user_modify_resume,
				 NULL, 0, UNLANG_SUB_FRAME, usermod_ctx) < 0) goto error;

	return UNLANG_ACTION_PUSHED_CHILD;

release:
error:
	TALLOC_FREE(usermod_ctx);
	RETURN_MODULE_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);
	ldap_usermod_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, ldap_usermod_call_env_t);

	if (inst->accounting) return user_modify(p_result, inst, request, inst->accounting, call_env);

	RETURN_MODULE_NOOP;
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);
	ldap_usermod_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, ldap_usermod_call_env_t);

	if (inst->postauth) return user_modify(p_result, inst, request, inst->postauth, call_env);

	RETURN_MODULE_NOOP;
}


/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_ldap_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);

	if (inst->userobj_sort_ctrl) ldap_control_free(inst->userobj_sort_ctrl);

	return 0;
}

/** Parse an accounting sub section.
 *
 * Allocate a new ldap_acct_section_t and write the config data into it.
 *
 * @param[in] mctx rlm_ldap configuration.
 * @param[in] parent of the config section.
 * @param[out] config to write the sub section parameters to.
 * @param[in] comp The section name were parsing the config for.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int parse_sub_section(module_inst_ctx_t const *mctx,
			     CONF_SECTION *parent, ldap_acct_section_t **config,
			     rlm_components_t comp)
{
	rlm_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	CONF_SECTION 	*cs;

	char const *name = section_type_value[comp];

	cs = cf_section_find(parent, name, NULL);
	if (!cs) {
		DEBUG2("rlm_ldap (%s) - Couldn't find configuration for %s, will return NOOP for calls "
		       "from this section", mctx->inst->name, name);

		return 0;
	}

	if (cf_section_rules_push(cs, acct_section_config) < 0) return -1;

	*config = talloc_zero(inst, ldap_acct_section_t);
	if (cf_section_parse(*config, *config, cs) < 0) {
		PERROR("rlm_ldap (%s) - Failed parsing configuration for section %s", mctx->inst->name, name);

		return -1;
	}

	(*config)->cs = cs;

	return 0;
}

/** Initialise thread specific data structure
 *
 */
static int mod_thread_instatiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_ldap_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t	*t = talloc_get_type_abort(mctx->thread, fr_ldap_thread_t);
	fr_ldap_thread_trunk_t	*ttrunk;

	/*
	 *	Initialise tree for connection trunks used by this thread
	 */
	MEM(t->trunks = fr_rb_inline_talloc_alloc(t, fr_ldap_thread_trunk_t, node, fr_ldap_trunk_cmp, NULL));

	t->config = &inst->handle_config;
	t->trunk_conf = &inst->trunk_conf;
	t->bind_trunk_conf = &inst->bind_trunk_conf;
	t->el = mctx->el;

	/*
	 *	Launch trunk for module default connection
	 */
	ttrunk = fr_thread_ldap_trunk_get(t, inst->handle_config.server, inst->handle_config.admin_identity,
					  inst->handle_config.admin_password, NULL, &inst->handle_config);
	if (!ttrunk) {
		ERROR("Unable to launch LDAP trunk");
		return -1;
	}

	/*
	 *	Set up a per-thread LDAP trunk to use for bind auths
	 */
	t->bind_trunk = fr_thread_ldap_bind_trunk_get(t);

	MEM(t->binds = fr_rb_inline_talloc_alloc(t, fr_ldap_bind_auth_ctx_t, node, fr_ldap_bind_auth_cmp, NULL));

	return 0;
}

/** Clean up thread specific data structure
 *
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	fr_ldap_thread_t	*t = talloc_get_type_abort(mctx->thread, fr_ldap_thread_t);
	void			**trunks_to_free;
	int			i;

	if (fr_rb_flatten_inorder(NULL, &trunks_to_free, t->trunks) < 0) return -1;

	for (i = talloc_array_length(trunks_to_free) - 1; i >= 0; i--) talloc_free(trunks_to_free[i]);
	talloc_free(trunks_to_free);
	talloc_free(t->trunks);

	return 0;
}

/** Bootstrap the module
 *
 * Define attributes.
 *
 * @param[in] mctx configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	CONF_SECTION	*conf = mctx->inst->conf;
	char		buffer[256];
	char const	*group_attribute;
	xlat_t		*xlat;

	inst->handle_config.name = talloc_typed_asprintf(inst, "rlm_ldap (%s)", mctx->inst->name);

	if (inst->group_attribute) {
		group_attribute = inst->group_attribute;
	} else if (cf_section_name2(conf)) {
		snprintf(buffer, sizeof(buffer), "%s-LDAP-Group", mctx->inst->name);
		group_attribute = buffer;
	} else {
		group_attribute = "LDAP-Group";
	}

	inst->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);

	/*
	 *	If the group attribute was not in the dictionary, create it
	 */
	if (!inst->group_da) {
		fr_dict_attr_flags_t	flags;

		memset(&flags, 0, sizeof(flags));
		if (fr_dict_attr_add(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
				     group_attribute, -1, FR_TYPE_STRING, &flags) < 0) {
			PERROR("Error creating group attribute");
			return -1;

		}
		inst->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);
	}

	/*
	 *	Setup the cache attribute
	 */
	if (inst->cache_attribute) {
		fr_dict_attr_flags_t	flags;

		memset(&flags, 0, sizeof(flags));
		if (fr_dict_attr_add(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
				     inst->cache_attribute, -1, FR_TYPE_STRING, &flags) < 0) {
			PERROR("Error creating cache attribute");
			return -1;

		}
		inst->cache_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->cache_attribute);
	} else {
		inst->cache_da = inst->group_da;	/* Default to the group_da */
	}

	/*
	 *	Trunks used for bind auth can only have one request in flight per connection.
	 */
	inst->bind_trunk_conf.target_req_per_conn = 1;
	inst->bind_trunk_conf.max_req_per_conn = 1;

	/*
	 *	Set sizes for trunk request pool.
	 */
	inst->bind_trunk_conf.req_pool_headers = 2;
	inst->bind_trunk_conf.req_pool_size = sizeof(fr_ldap_bind_auth_ctx_t) + sizeof(fr_ldap_sasl_ctx_t);

	xlat = xlat_func_register_module(NULL, mctx, mctx->inst->name, ldap_xlat, FR_TYPE_STRING);
	xlat_func_mono_set(xlat, ldap_xlat_arg);

	if (unlikely(!(xlat = xlat_func_register_module(NULL, mctx, "memberof", ldap_memberof_xlat,
							FR_TYPE_BOOL)))) return -1;
	xlat_func_args_set(xlat, ldap_memberof_xlat_arg);
	xlat_func_call_env_set(xlat, &memberof_method_env);

	map_proc_register(inst, mctx->inst->name, mod_map_proc, ldap_map_verify, 0);

	return 0;
}

/** Instantiate the module
 *
 * Creates a new instance of the module reading parameters from a configuration section.
 *
 * @param [in] mctx configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	size_t		i;

	CONF_SECTION	*options, *update;
	rlm_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	CONF_SECTION	*conf = mctx->inst->conf;

	map_list_init(&inst->user_map);

	options = cf_section_find(conf, "options", NULL);
	if (!options || !cf_pair_find(options, "chase_referrals")) {
		inst->handle_config.chase_referrals_unset = true;	 /* use OpenLDAP defaults */
	}

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((parse_sub_section(mctx, conf, &inst->accounting, MOD_ACCOUNTING) < 0) ||
	    (parse_sub_section(mctx, conf, &inst->postauth, MOD_POST_AUTH) < 0)) {
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
	if (inst->handle_config.admin_sasl.mech) {
		cf_log_err(conf, "Configuration item 'sasl.mech' not supported.  "
			   "Linked libldap does not provide ldap_sasl_interactive_bind function");
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

		/*
		 *	Split original server value out into URI, server and port
		 *	so whatever initialization function we use later will have
		 *	the server information in the format it needs.
		 */
		if (ldap_is_ldap_url(value)) {
			if (fr_ldap_server_url_check(&inst->handle_config, value, conf) < 0) return -1;
		} else
		/*
		 *	If it's not an URL, then just treat server as a hostname.
		 */
		{
			if (fr_ldap_server_config_check(&inst->handle_config, value, conf) < 0) return -1;
		}
	}

	/*
	 *	inst->handle_config.server be unset if connection pool sharing is used.
	 */
	if (inst->handle_config.server) {
		inst->handle_config.server[talloc_array_length(inst->handle_config.server) - 2] = '\0';
		DEBUG4("rlm_ldap (%s) - LDAP server string: %s", mctx->inst->name, inst->handle_config.server);
	}

	/*
	 *	Workaround for servers which support LDAPS but not START TLS
	 */
	if (inst->handle_config.port == LDAPS_PORT || inst->handle_config.tls_mode) {
		inst->handle_config.tls_mode = LDAP_OPT_X_TLS_HARD;
	} else {
		inst->handle_config.tls_mode = 0;
	}

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

	/*
	 *	Convert scope strings to enumerated constants
	 */
	inst->userobj_scope = fr_table_value_by_str(fr_ldap_scope, inst->userobj_scope_str, -1);
	if (inst->userobj_scope < 0) {
		cf_log_err(conf, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one', 'base' or 'children'",
			   inst->userobj_scope_str);
		goto error;
	}

	inst->groupobj_scope = fr_table_value_by_str(fr_ldap_scope, inst->groupobj_scope_str, -1);
	if (inst->groupobj_scope < 0) {
		cf_log_err(conf, "Invalid 'group.scope' value \"%s\", expected 'sub', 'one', 'base' or 'children'",
			   inst->groupobj_scope_str);
		goto error;
	}

	/*
	 *	Build the server side sort control for user objects
	 */
	if (inst->userobj_sort_by) {
		LDAPSortKey	**keys;
		int		ret;

		ret = ldap_create_sort_keylist(&keys, UNCONST(char *, inst->userobj_sort_by));
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

	if (inst->handle_config.tls_require_cert_str) {
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
	}

	if (inst->handle_config.tls_min_version_str) {
		if (strcmp(inst->handle_config.tls_min_version_str, "1.2") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2;

		} else if (strcmp(inst->handle_config.tls_min_version_str, "1.1") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_1;

		} else if (strcmp(inst->handle_config.tls_min_version_str, "1.0") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_0;

		} else {
			cf_log_err(conf, "Invalid 'tls.tls_min_version' value \"%s\"", inst->handle_config.tls_min_version_str);
			goto error;
		}
	}

	/*
	 *	Build the attribute map
	 */
	{
		tmpl_rules_t	parse_rules = {
			.attr = {
				.list_def = request_attr_request,
				.allow_foreign = true	/* Because we don't know where we'll be called */
			}
		};

		update = cf_section_find(conf, "update", NULL);
		if (update && (map_afrom_cs(inst, &inst->user_map, update,
					    &parse_rules, &parse_rules, fr_ldap_map_verify, NULL,
					    LDAP_MAX_ATTRMAP) < 0)) {
			return -1;
		}
	}

	return 0;

error:
	return -1;
}

static int mod_load(void)
{
	xlat_t	*xlat;

	if (unlikely(!(xlat = xlat_func_register(NULL, "ldap_escape", ldap_escape_xlat, FR_TYPE_STRING)))) return -1;
	xlat_func_mono_set(xlat, ldap_escape_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
	if (unlikely(!(xlat = xlat_func_register(NULL, "ldap_unescape", ldap_unescape_xlat, FR_TYPE_STRING)))) return -1;
	xlat_func_mono_set(xlat, ldap_escape_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("ldap_escape");
	xlat_func_unregister("ldap_unescape");
}

/* globally exported name */
extern module_rlm_t rlm_ldap;
module_rlm_t rlm_ldap = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "ldap",
		.type		= 0,
		.inst_size	= sizeof(rlm_ldap_t),
		.config		= module_config,
		.onload		= mod_load,
		.unload		= mod_unload,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
		.thread_inst_size	= sizeof(fr_ldap_thread_t),
		.thread_inst_type	= "fr_ldap_thread_t",
		.thread_instantiate	= mod_thread_instatiate,
		.thread_detach		= mod_thread_detach,
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	Hack to support old configurations
		 */
		{ .name1 = "authorize",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,
		  .method_env = &authorize_method_env		},

		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,
		  .method_env = &authorize_method_env		},
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting,
		  .method_env = &usermod_method_env		},
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate,
		  .method_env = &authenticate_method_env	},
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth,
		  .method_env = &usermod_method_env		},
		MODULE_NAME_TERMINATOR
	}
};
