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
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/uri.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/ldap/conf.h>
#include <freeradius-devel/ldap/base.h>

#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/rcode.h>

#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/map.h>

#include <ldap.h>
#include "rlm_ldap.h"

typedef struct {
	fr_dict_attr_t const	*group_da;
	fr_dict_attr_t const 	*cache_da;
	fr_dict_attr_t const    *user_da;
} rlm_ldap_boot_t;

typedef struct {
	fr_value_box_t	password;
	tmpl_t const	*password_tmpl;
	fr_value_box_t	user_sasl_mech;
	fr_value_box_t	user_sasl_authname;
	fr_value_box_t	user_sasl_proxy;
	fr_value_box_t	user_sasl_realm;
} ldap_auth_call_env_t;

typedef struct {
	char const	*attr;
	fr_token_t	op;
	tmpl_t const	*tmpl;
} ldap_mod_tmpl_t;
typedef struct {
	fr_value_box_t	user_base;
	fr_value_box_t	user_filter;
	ldap_mod_tmpl_t	**mod;
} ldap_usermod_call_env_t;

/** Call environment used in the profile xlat
 */
typedef struct {
	fr_value_box_t	profile_filter;			//!< Filter to use when searching for users.
	map_list_t	*profile_map;			//!< List of maps to apply to the profile.
} ldap_xlat_profile_call_env_t;

static int ldap_update_section_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci, call_env_ctx_t const *cec, call_env_parser_t const *rule);
static int ldap_mod_section_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci, call_env_ctx_t const *cec, call_env_parser_t const *rule);

static int ldap_group_filter_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule);

static const call_env_parser_t sasl_call_env[] = {
	{ FR_CALL_ENV_OFFSET("mech", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, ldap_auth_call_env_t, user_sasl_mech) },
	{ FR_CALL_ENV_OFFSET("authname", FR_TYPE_STRING, CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, ldap_auth_call_env_t, user_sasl_authname) },
	{ FR_CALL_ENV_OFFSET("proxy", FR_TYPE_STRING, CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, ldap_auth_call_env_t, user_sasl_proxy) },
	{ FR_CALL_ENV_OFFSET("realm", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, ldap_auth_call_env_t, user_sasl_realm) },
	CALL_ENV_TERMINATOR
};

static conf_parser_t profile_config[] = {
	{ FR_CONF_OFFSET("scope", rlm_ldap_t, profile.obj_scope), .dflt = "base",
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = fr_ldap_scope, .len = &fr_ldap_scope_len } },
	{ FR_CONF_OFFSET("attribute", rlm_ldap_t, profile.attr) },
	{ FR_CONF_OFFSET("attribute_suspend", rlm_ldap_t, profile.attr_suspend) },
	{ FR_CONF_OFFSET("check_attribute", rlm_ldap_t, profile.check_attr) },
	{ FR_CONF_OFFSET("sort_by", rlm_ldap_t, profile.obj_sort_by) },
	{ FR_CONF_OFFSET("fallthrough_attribute", rlm_ldap_t, profile.fallthrough_attr) },
	{ FR_CONF_OFFSET("fallthrough_default", rlm_ldap_t, profile.fallthrough_def), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

/*
 *	User configuration
 */
static conf_parser_t user_config[] = {
	{ FR_CONF_OFFSET("scope", rlm_ldap_t, user.obj_scope), .dflt = "sub",
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = fr_ldap_scope, .len = &fr_ldap_scope_len } },
	{ FR_CONF_OFFSET("sort_by", rlm_ldap_t, user.obj_sort_by) },

	{ FR_CONF_OFFSET("access_attribute", rlm_ldap_t, user.obj_access_attr) },
	{ FR_CONF_OFFSET("access_positive", rlm_ldap_t, user.access_positive), .dflt = "yes" },
	{ FR_CONF_OFFSET("access_value_negate", rlm_ldap_t, user.access_value_negate), .dflt = "false" },
	{ FR_CONF_OFFSET("access_value_suspend", rlm_ldap_t, user.access_value_suspend), .dflt = "suspended" },
	{ FR_CONF_OFFSET("dn_attribute", rlm_ldap_t, user.dn_attr_str), .dflt = "LDAP-UserDN" },
	{ FR_CONF_OFFSET_IS_SET("expect_password", FR_TYPE_BOOL, 0, rlm_ldap_t, user.expect_password) },
	CONF_PARSER_TERMINATOR
};

/*
 *	Group configuration
 */
static conf_parser_t group_config[] = {
	{ FR_CONF_OFFSET("filter", rlm_ldap_t, group.obj_filter) },
	{ FR_CONF_OFFSET("scope", rlm_ldap_t, group.obj_scope), .dflt = "sub",
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = fr_ldap_scope, .len = &fr_ldap_scope_len }  },

	{ FR_CONF_OFFSET("name_attribute", rlm_ldap_t, group.obj_name_attr), .dflt = "cn" },
	{ FR_CONF_OFFSET("membership_attribute", rlm_ldap_t, group.userobj_membership_attr) },
	{ FR_CONF_OFFSET_FLAGS("membership_filter", CONF_FLAG_XLAT, rlm_ldap_t, group.obj_membership_filter) },
	{ FR_CONF_OFFSET("cacheable_name", rlm_ldap_t, group.cacheable_name), .dflt = "no" },
	{ FR_CONF_OFFSET("cacheable_dn", rlm_ldap_t, group.cacheable_dn), .dflt = "no" },
	{ FR_CONF_OFFSET("cache_attribute", rlm_ldap_t, group.cache_attr_str) },
	{ FR_CONF_OFFSET("group_attribute", rlm_ldap_t, group.attribute) },
	{ FR_CONF_OFFSET("allow_dangling_group_ref", rlm_ldap_t, group.allow_dangling_refs), .dflt = "no" },
	{ FR_CONF_OFFSET("skip_on_suspend", rlm_ldap_t, group.skip_on_suspend), .dflt = "yes"},
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET_FLAGS("server", CONF_FLAG_MULTI, rlm_ldap_t, handle_config.server_str) },	/* Do not set to required */

	/*
	 *	Common LDAP conf parsers
	 */
	FR_LDAP_COMMON_CONF(rlm_ldap_t),

	{ FR_CONF_OFFSET("valuepair_attribute", rlm_ldap_t, valuepair_attr) },

#ifdef LDAP_CONTROL_X_SESSION_TRACKING
	{ FR_CONF_OFFSET("session_tracking", rlm_ldap_t, session_tracking), .dflt = "no" },
#endif

#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{ FR_CONF_OFFSET("edir", rlm_ldap_t, edir) }, /* NULL defaults to "no" */

	/*
	 *	Attempt to bind with the cleartext password we got from eDirectory
	 *	Universal password for additional authorization checks.
	 */
	{ FR_CONF_OFFSET("edir_autz", rlm_ldap_t, edir_autz) }, /* NULL defaults to "no" */
#endif

	{ FR_CONF_POINTER("user", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) user_config },

	{ FR_CONF_POINTER("group", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) group_config },

	{ FR_CONF_POINTER("profile", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) profile_config },

	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, rlm_ldap_t, trunk_conf, trunk_config ) },

	{ FR_CONF_OFFSET_SUBSECTION("bind_pool", 0, rlm_ldap_t, bind_trunk_conf, trunk_config ) },

	CONF_PARSER_TERMINATOR
};

#define USER_CALL_ENV_COMMON(_struct) \
	{ FR_CALL_ENV_OFFSET("base_dn", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT, _struct, user_base), .pair.dflt = "", .pair.dflt_quote = T_SINGLE_QUOTED_STRING }, \
	{ FR_CALL_ENV_OFFSET("filter", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT, _struct, user_filter), .pair.dflt = "(&)", .pair.dflt_quote = T_SINGLE_QUOTED_STRING }

static const call_env_method_t authenticate_method_env = {
	FR_CALL_ENV_METHOD_OUT(ldap_auth_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION("user", NULL, CALL_ENV_FLAG_REQUIRED,
					 ((call_env_parser_t[]) {
						{ FR_CALL_ENV_PARSE_OFFSET("password_attribute", FR_TYPE_STRING,
									  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE,
									  ldap_auth_call_env_t, password, password_tmpl),
									  .pair.dflt = "User-Password", .pair.dflt_quote = T_BARE_WORD },
						{ FR_CALL_ENV_SUBSECTION("sasl", NULL, CALL_ENV_FLAG_NONE, sasl_call_env) },
						CALL_ENV_TERMINATOR
					 })) },
		CALL_ENV_TERMINATOR
	}
};

/** Parameters to allow ldap_update_section_parse to be reused
 */
typedef struct {
	size_t		map_offset;
	ssize_t		expect_password_offset;
} ldap_update_rules_t;

static const call_env_method_t authorize_method_env = {
	FR_CALL_ENV_METHOD_OUT(ldap_autz_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC("update", CF_IDENT_ANY, CALL_ENV_FLAG_PARSE_MISSING, ldap_update_section_parse),
					      .uctx = &(ldap_update_rules_t){
						.map_offset = offsetof(ldap_autz_call_env_t, user_map),
					      	.expect_password_offset = offsetof(ldap_autz_call_env_t, expect_password)
					      } },
		{ FR_CALL_ENV_SUBSECTION("user", NULL, CALL_ENV_FLAG_REQUIRED,
					 ((call_env_parser_t[]) {
						USER_CALL_ENV_COMMON(ldap_autz_call_env_t),
						CALL_ENV_TERMINATOR
					 })) },
		{ FR_CALL_ENV_SUBSECTION("group", NULL, CALL_ENV_FLAG_NONE,
					 ((call_env_parser_t[]) {
						{ FR_CALL_ENV_OFFSET("base_dn", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_autz_call_env_t, group_base) },
						{ FR_CALL_ENV_PARSE_ONLY_OFFSET("membership_filter", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_autz_call_env_t, group_filter),
						  .pair.func = ldap_group_filter_parse,
						  .pair.escape = {
							  .box_escape = {
								  .func = fr_ldap_box_escape,
								  .safe_for = (fr_value_box_safe_for_t)fr_ldap_box_escape,
								  .always_escape = false,
							  },
							.mode = TMPL_ESCAPE_PRE_CONCAT
						  },
						  .pair.literals_safe_for = (fr_value_box_safe_for_t)fr_ldap_box_escape,
						},
						CALL_ENV_TERMINATOR
					 })) },
		{ FR_CALL_ENV_SUBSECTION("profile", NULL, CALL_ENV_FLAG_NONE,
					 ((call_env_parser_t[]) {
						{ FR_CALL_ENV_OFFSET("default", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_autz_call_env_t, default_profile) },
						{ FR_CALL_ENV_OFFSET("filter", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_autz_call_env_t, profile_filter),
								.pair.dflt = "(&)", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },	//!< Correct filter for when the DN is known.
						CALL_ENV_TERMINATOR
					 } )) },
		CALL_ENV_TERMINATOR
	}
};

#define USERMOD_ENV(_section) static const call_env_method_t _section ## _usermod_method_env = { \
	FR_CALL_ENV_METHOD_OUT(ldap_usermod_call_env_t), \
	.env = (call_env_parser_t[]) { \
		{ FR_CALL_ENV_SUBSECTION("user", NULL, CALL_ENV_FLAG_REQUIRED, \
					 ((call_env_parser_t[]) { \
						USER_CALL_ENV_COMMON(ldap_usermod_call_env_t), CALL_ENV_TERMINATOR \
					 })) }, \
		{ FR_CALL_ENV_SUBSECTION_FUNC(STRINGIFY(_section), CF_IDENT_ANY, CALL_ENV_FLAG_SUBSECTION | CALL_ENV_FLAG_PARSE_MISSING, ldap_mod_section_parse) }, \
		CALL_ENV_TERMINATOR \
	} \
}

USERMOD_ENV(accounting);
USERMOD_ENV(send);

static const call_env_method_t xlat_memberof_method_env = {
	FR_CALL_ENV_METHOD_OUT(ldap_xlat_memberof_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION("user", NULL, CALL_ENV_FLAG_REQUIRED,
					 ((call_env_parser_t[]) {
						USER_CALL_ENV_COMMON(ldap_xlat_memberof_call_env_t),
						CALL_ENV_TERMINATOR
					 })) },
		{ FR_CALL_ENV_SUBSECTION("group", NULL, CALL_ENV_FLAG_NONE,
					 ((call_env_parser_t[]) {
						{ FR_CALL_ENV_OFFSET("base_dn", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_xlat_memberof_call_env_t, group_base) },
						{ FR_CALL_ENV_PARSE_ONLY_OFFSET("membership_filter", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_xlat_memberof_call_env_t, group_filter),
						  .pair.func = ldap_group_filter_parse,
						  .pair.escape = {
							  .box_escape = {
								  .func = fr_ldap_box_escape,
								  .safe_for = (fr_value_box_safe_for_t)fr_ldap_box_escape,
								  .always_escape = false,
							  },
							.mode = TMPL_ESCAPE_PRE_CONCAT
						  },
						  .pair.literals_safe_for = (fr_value_box_safe_for_t)fr_ldap_box_escape,
						},
						CALL_ENV_TERMINATOR
					 })) },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t xlat_profile_method_env = {
	FR_CALL_ENV_METHOD_OUT(ldap_xlat_profile_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC("update", CF_IDENT_ANY, CALL_ENV_FLAG_PARSE_MISSING, ldap_update_section_parse),
					      .uctx = &(ldap_update_rules_t){
						.map_offset = offsetof(ldap_xlat_profile_call_env_t, profile_map),
					      	.expect_password_offset = -1
					      } },
		{ FR_CALL_ENV_SUBSECTION("profile", NULL, CALL_ENV_FLAG_NONE,
					 ((call_env_parser_t[])  {
						{ FR_CALL_ENV_OFFSET("filter", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, ldap_xlat_profile_call_env_t, profile_filter),
								     .pair.dflt = "(&)", .pair.dflt_quote = T_SINGLE_QUOTED_STRING }, //!< Correct filter for when the DN is known.
						CALL_ENV_TERMINATOR
					 })) },
		CALL_ENV_TERMINATOR
	}
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_ldap_dict[];
fr_dict_autoload_t rlm_ldap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *attr_password;
fr_dict_attr_t const *attr_cleartext_password;
fr_dict_attr_t const *attr_crypt_password;
fr_dict_attr_t const *attr_nt_password;
fr_dict_attr_t const *attr_password_with_header;
static fr_dict_attr_t const *attr_expr_bool_enum;

extern fr_dict_attr_autoload_t rlm_ldap_dict_attr[];
fr_dict_attr_autoload_t rlm_ldap_dict_attr[] = {
	{ .out = &attr_password, .name = "Password", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Password.Crypt", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "Password.NT", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password.With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_expr_bool_enum, .name = "Expr-Bool-Enum", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
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

/** Holds state of in progress ldap user modifications
 *
 */
typedef struct {
	rlm_ldap_t const	*inst;
	ldap_usermod_call_env_t	*call_env;
	char const		*dn;
	LDAPMod			**mod_p;
	LDAPMod			*mod_s;
	fr_ldap_thread_trunk_t	*ttrunk;
	fr_ldap_query_t		*query;
	fr_value_box_list_t	expanded;
	size_t			num_mods;
	size_t			current_mod;
	size_t			expanded_mods;
} ldap_user_modify_ctx_t;

/** Holds state of in progress LDAP map
 *
 */
typedef struct {
	map_list_t const	*maps;
	LDAPURLDesc		*ldap_url;
	fr_ldap_query_t		*query;
	fr_ldap_map_exp_t	expanded;
	LDAPControl		*serverctrls[LDAP_MAX_CONTROLS];
} ldap_map_ctx_t;

typedef enum {
	LDAP_SCHEME_UNIX = 0,
	LDAP_SCHEME_TCP,
	LDAP_SCHEME_TCP_SSL
} ldap_schemes_t;

static fr_table_num_sorted_t const ldap_uri_scheme_table[] = {
	{ L("ldap://"),		LDAP_SCHEME_UNIX	},
	{ L("ldapi://"),     	LDAP_SCHEME_TCP		},
	{ L("ldaps://"),        LDAP_SCHEME_TCP_SSL	},
};
static size_t ldap_uri_scheme_table_len = NUM_ELEMENTS(ldap_uri_scheme_table);

/** This is the common function that actually ends up doing all the URI escaping
 */
#define LDAP_URI_SAFE_FOR (fr_value_box_safe_for_t)fr_ldap_uri_escape_func

static xlat_arg_parser_t const ldap_uri_escape_xlat_arg[] = {
	{ .required=true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const ldap_safe_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Escape LDAP string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_uri_escape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*vb, *in_vb, *in_group = fr_value_box_list_head(in);
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	fr_assert(in_group->type == FR_TYPE_GROUP);

	while ((in_vb = fr_value_box_list_pop_head(&in_group->vb_group))) {
		/*
		 *	If it's already safe, just move it over.
		 */
		if (fr_value_box_is_safe_for_only(in_vb, LDAP_URI_SAFE_FOR)) {
			fr_dcursor_append(out, in_vb);
			continue;
		}

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
		len = fr_ldap_uri_escape_func(request, fr_sbuff_buff(&sbuff), in_vb->vb_length * 3 + 1, in_vb->vb_strvalue, NULL);

		/*
		 *	Trim buffer to fit used space and assign to box
		 */
		fr_sbuff_trim_talloc(&sbuff, len);
		fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), in_vb->tainted);
		talloc_free(in_vb);

		fr_dcursor_append(out, vb);
	}
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const ldap_uri_unescape_xlat_arg[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Unescape LDAP string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_uri_unescape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					    UNUSED xlat_ctx_t const *xctx,
					    request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*vb, *in_vb = NULL, *in_group = fr_value_box_list_head(in);
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	fr_assert(in_group->type == FR_TYPE_GROUP);

	while ((in_vb = fr_value_box_list_next(&in_group->vb_group, in_vb))) {

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
		len = fr_ldap_uri_unescape_func(request, fr_sbuff_buff(&sbuff), in_vb->vb_length + 1, in_vb->vb_strvalue, NULL);

		/*
		 *	Trim buffer to fit used space and assign to box
		 */
		fr_sbuff_trim_talloc(&sbuff, len);
		fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), in_vb->tainted);
		fr_dcursor_append(out, vb);
	}

	return XLAT_ACTION_DONE;
}

/** Escape function for a part of an LDAP URI
 *
 */
static int ldap_uri_part_escape(fr_value_box_t *vb, UNUSED void *uctx)
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
	len = fr_ldap_uri_escape_func(NULL, fr_sbuff_buff(&sbuff), vb->vb_length * 3 + 1, vb->vb_strvalue, NULL);

	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_strdup_shallow_replace(vb, fr_sbuff_buff(&sbuff), len);

	return 0;
}

/** Callback when LDAP query times out
 *
 */
static void ldap_query_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	fr_ldap_query_t		*query = talloc_get_type_abort(uctx, fr_ldap_query_t);
	trunk_request_t		*treq;
	request_t		*request;

	/*
	 *	If the trunk request has completed but the query
	 *	has not yet resumed, query->treq will be NULL
	 */
	if (!query->treq) return;

	treq = talloc_get_type_abort(query->treq, trunk_request_t);
	request = treq->request;

	ROPTIONAL(RERROR, ERROR, "Timeout waiting for LDAP query");

	trunk_request_signal_cancel(query->treq);

	query->ret = LDAP_RESULT_TIMEOUT;
	unlang_interpret_mark_runnable(request);
}

static xlat_arg_parser_t const ldap_uri_attr_option_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Modify an LDAP URI to append an option to all attributes
 *
 * This is for the corner case where a URI is provided by a third party system
 * and needs amending before being used. e.g. a CRL distribution point extracted
 * from a certificate may need the "binary" option appending to the attribute
 * being requested.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_xlat_uri_attr_option(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
	 				       request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*uri, *option_vb;
	char			*attrs_fixed, **attr, port[6];
	char const		*option;
	LDAPURLDesc		*ldap_url;
	fr_value_box_t		*vb;
	int			ret;

	XLAT_ARGS(in, &uri, &option_vb);

#ifdef STATIC_ANALYZER
	if (!option_vb) return XLAT_ACTION_FAIL;
#endif

	if (option_vb->vb_length < 1) {
		RERROR("LDAP attriubte option must not be blank");
		return XLAT_ACTION_FAIL;
	}

	if (!ldap_is_ldap_url(uri->vb_strvalue)) {
		REDEBUG("String passed does not look like an LDAP URL");
		return XLAT_ACTION_FAIL;
	}

	ret = ldap_url_parse(uri->vb_strvalue, &ldap_url);
	if (ret != LDAP_URL_SUCCESS){
		RPEDEBUG("Parsing LDAP URL failed - %s", fr_ldap_url_err_to_str(ret));
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	No attributes, just return what was presented.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] || !*ldap_url->lud_attrs[0]) {
		fr_value_box_list_remove(in, uri);
		talloc_steal(ctx, uri);
		fr_dcursor_append(out, uri);
		goto done;
	}

	if (option_vb->vb_strvalue[0] != ';') {
		option = talloc_asprintf(option_vb, ";%s", option_vb->vb_strvalue);
	} else {
		option = option_vb->vb_strvalue;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));
	attrs_fixed = talloc_strdup(vb, "");

	attr = ldap_url->lud_attrs;
	while (*attr) {
		attrs_fixed = talloc_strdup_append(attrs_fixed, *attr);
		if (!strstr(*attr, option)) attrs_fixed = talloc_strdup_append(attrs_fixed, option);
		attr++;
		if (*attr) attrs_fixed = talloc_strdup_append(attrs_fixed, ",");
	}

	snprintf(port, sizeof(port), "%d", ldap_url->lud_port);
	fr_value_box_asprintf(vb, vb, NULL, uri->tainted, "%s://%s%s%s/%s?%s?%s?%s",
			      ldap_url->lud_scheme,
			      ldap_url->lud_host ? ldap_url->lud_host : "",
			      ldap_url->lud_host ? ":" : "",
			      ldap_url->lud_host ? port : "",
			      ldap_url->lud_dn, attrs_fixed,
			      fr_table_str_by_value(fr_ldap_scope, ldap_url->lud_scope, ""),
			      ldap_url->lud_filter ? ldap_url->lud_filter : "");

	fr_dcursor_append(out, vb);
done:
	ldap_free_urldesc(ldap_url);
	return XLAT_ACTION_DONE;
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
				if (fr_value_box_bstrndup(vb, vb, NULL, values[i]->bv_val, values[i]->bv_len, true) < 0) {
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

	if (!query->treq)	return;

	RDEBUG2("Forcefully cancelling pending LDAP query");

	trunk_request_signal_cancel(query->treq);
}

/*
 *	If a part doesn't have an escaping function, parsing will fail unless the input
 *	was marked up with a safe_for value by the ldap arg parsing, i.e. was a literal
 *	input argument to the xlat.
 *
 *	This is equivalent to the old "tainted_allowed" flag.
 */
static fr_uri_part_t const ldap_uri_parts[] = {
	{ .name = "scheme", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L(":")), .part_adv = { [':'] = 1 }, .extra_skip = 2 },
	{ .name = "host", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L(":"), L("/")), .part_adv = { [':'] = 1, ['/'] = 2 } },
	{ .name = "port", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("/")), .part_adv = { ['/'] = 1 } },
	{ .name = "dn", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 }, .func = ldap_uri_part_escape },
	{ .name = "attrs", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 }},
	{ .name = "scope", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 }, .func = ldap_uri_part_escape },
	{ .name = "filter", .safe_for = LDAP_URI_SAFE_FOR, .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1}, .func = ldap_uri_part_escape },
	{ .name = "exts", .safe_for = LDAP_URI_SAFE_FOR, .func = ldap_uri_part_escape },
	XLAT_URI_PART_TERMINATOR
};

static fr_uri_part_t const ldap_dn_parts[] = {
	{ .name = "dn", .safe_for = LDAP_URI_SAFE_FOR , .func = ldap_uri_part_escape },
	XLAT_URI_PART_TERMINATOR
};

static xlat_arg_parser_t const ldap_xlat_arg[] = {
	{ .required = true, .type = FR_TYPE_STRING, .safe_for = LDAP_URI_SAFE_FOR, .will_escape = true, },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Produce canonical LDAP host URI for finding trunks
 *
 */
static inline CC_HINT(always_inline)
char *host_uri_canonify(request_t *request, LDAPURLDesc *url_parsed, fr_value_box_t *url_in)
{
	char *host;

	LDAPURLDesc tmp_desc = {
		.lud_scheme = url_parsed->lud_scheme,
		.lud_host = url_parsed->lud_host,
		.lud_port = url_parsed->lud_port,
		.lud_scope = -1
	};
	host = ldap_url_desc2str(&tmp_desc);
	if (unlikely(host == NULL)) REDEBUG("Invalid LDAP URL - %pV", url_in); \

	return host;
}

/** Utility function for parsing LDAP URLs
 *
 * All LDAP xlat functions that work with LDAP URLs should call this function to parse the URL.
 *
 * @param[out] uri_parsed	LDAP URL parsed.  Must be freed with ldap_url_desc_free.
 * @param[out] host_out		host name to use for the query.  Must be freed with ldap_mem_free
 *				if free_host_out is true.
 * @param[out] free_host_out	True if host_out should be freed.
 * @param[in] request		Request being processed.
 * @param[in] host_default	Default host to use if the URL does not specify a host.
 * @param[in] uri_in		URI to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int ldap_xlat_uri_parse(LDAPURLDesc **uri_parsed, char **host_out, bool *free_host_out,
			       request_t *request, char *host_default, fr_value_box_t *uri_in)
{
	fr_value_box_t	*uri;
	int		ldap_url_ret;

	*free_host_out = false;

	if (fr_uri_escape_list(&uri_in->vb_group, ldap_uri_parts, NULL) < 0){
		RPERROR("Failed to escape LDAP URI");
	error:
		*uri_parsed = NULL;
		return -1;
	}

	/*
	 *	Smush everything into the first URI box
	 */
	uri = fr_value_box_list_head(&uri_in->vb_group);

	if (fr_value_box_list_concat_in_place(uri, uri, &uri_in->vb_group,
					      FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Failed concatenating input");
		goto error;
	}

	if (!ldap_is_ldap_url(uri->vb_strvalue)) {
		REDEBUG("String passed does not look like an LDAP URL");
		goto error;
	}

	ldap_url_ret = ldap_url_parse(uri->vb_strvalue, uri_parsed);
	if (ldap_url_ret != LDAP_URL_SUCCESS){
		RPEDEBUG("Parsing LDAP URL failed - %s", fr_ldap_url_err_to_str(ldap_url_ret));
		goto error;
	}

	/*
	 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
	 */
	if (!(*uri_parsed)->lud_host) {
		*host_out = host_default;
	} else {
		*host_out = host_uri_canonify(request, *uri_parsed, uri);
		if (unlikely(*host_out == NULL)) {
			ldap_free_urldesc(*uri_parsed);
			*uri_parsed = NULL;
			return -1;
		}
		*free_host_out = true;
	}

	return 0;
}

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
			       xlat_ctx_t const *xctx,
	 		       request_t *request, fr_value_box_list_t *in)
{
	fr_ldap_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, fr_ldap_thread_t);
	fr_value_box_t		*uri;
	char			*host;
	bool			free_host = false;
	fr_ldap_config_t const	*handle_config = t->config;
	fr_ldap_thread_trunk_t	*ttrunk;
	fr_ldap_query_t		*query = NULL;

	LDAPURLDesc		*ldap_url;

	XLAT_ARGS(in, &uri);

	if (ldap_xlat_uri_parse(&ldap_url, &host, &free_host, request, handle_config->server, uri) < 0) return XLAT_ACTION_FAIL;

	/*
	 *	Nothing, empty string, "*" string, or got 2 things, die.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] || !*ldap_url->lud_attrs[0] ||
	    (strcmp(ldap_url->lud_attrs[0], "*") == 0) || ldap_url->lud_attrs[1]) {
		REDEBUG("Bad attributes list in LDAP URL. URL must specify exactly one attribute to retrieve");
		ldap_free_urldesc(ldap_url);
		return XLAT_ACTION_FAIL;
	}

	query = fr_ldap_search_alloc(unlang_interpret_frame_talloc_ctx(request),
				     ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter,
				     (char const * const*)ldap_url->lud_attrs, NULL, NULL);
	query->ldap_url = ldap_url;	/* query destructor will free URL */

	if (ldap_url->lud_exts) {
		LDAPControl	*serverctrls[LDAP_MAX_CONTROLS];
		int		i;

		serverctrls[0] = NULL;

		if (fr_ldap_parse_url_extensions(serverctrls, NUM_ELEMENTS(serverctrls),
						 query->ldap_url->lud_exts) < 0) {
			RPERROR("Parsing URL extensions failed");
			if (free_host) ldap_memfree(host);

		query_error:
			talloc_free(query);
			return XLAT_ACTION_FAIL;
		}

		for (i = 0; i < LDAP_MAX_CONTROLS; i++) {
			if (!serverctrls[i]) break;
			query->serverctrls[i].control = serverctrls[i];
			query->serverctrls[i].freeit = true;
		}
	}

	/*
	 *	Figure out what trunked connection we can use
	 *	to communicate with the host.
	 *
	 *	If free_host is true, we must free the host
	 *	after deciding on a trunk connection as it
	 *	was allocated by host_uri_canonify.
	 */
	ttrunk = fr_thread_ldap_trunk_get(t, host, handle_config->admin_identity,
					  handle_config->admin_password, request, handle_config);
	if (free_host) ldap_memfree(host);
	if (!ttrunk) {
		REDEBUG("Unable to get LDAP query for xlat");
		goto query_error;
	}

	switch (trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL)) {
	case TRUNK_ENQUEUE_OK:
	case TRUNK_ENQUEUE_IN_BACKLOG:
		break;

	default:
		REDEBUG("Unable to enqueue LDAP query for xlat");
		goto query_error;
	}

	if (fr_timer_in(query, unlang_interpret_event_list(request)->tl, &query->ev, handle_config->res_timeout,
			false, ldap_query_timeout, query) < 0) {
		REDEBUG("Unable to set timeout for LDAP query");
		trunk_request_signal_cancel(query->treq);
		goto query_error;
	}

	return unlang_xlat_yield(request, ldap_xlat_resume, ldap_xlat_signal, ~FR_SIGNAL_CANCEL, query);
}

/** User object lookup as part of group membership xlat
 *
 * Called if the ldap membership xlat is used and the user DN is not already known
 */
static unlang_action_t ldap_group_xlat_user_find(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	ldap_group_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(uctx, ldap_group_xlat_ctx_t);

	if (xlat_ctx->env_data->user_filter.type == FR_TYPE_STRING) xlat_ctx->filter = &xlat_ctx->env_data->user_filter;

	xlat_ctx->basedn = &xlat_ctx->env_data->user_base;

	return rlm_ldap_find_user_async(xlat_ctx,
					/* discard, this function is only used by xlats */NULL,
					xlat_ctx->inst, request,
					xlat_ctx->basedn, xlat_ctx->filter,
					xlat_ctx->ttrunk, xlat_ctx->attrs, &xlat_ctx->query);
}

/** Cancel an in-progress query for the LDAP group membership xlat
 *
 */
static void ldap_group_xlat_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_group_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(uctx, ldap_group_xlat_ctx_t);

	if (!xlat_ctx->query || !xlat_ctx->query->treq) return;

	trunk_request_signal_cancel(xlat_ctx->query->treq);
}

#define REPEAT_LDAP_MEMBEROF_XLAT_RESULTS \
	if (unlang_function_repeat_set(request, ldap_group_xlat_results) < 0) do { \
		RETURN_UNLANG_FAIL; \
	} while (0)

/** Run the state machine for the LDAP membership xlat
 *
 * This is called after each async lookup is completed
 *
 * Will stop early, and set p_result to unlang_result
 */
static unlang_action_t ldap_group_xlat_results(unlang_result_t *p_result, request_t *request, void *uctx)
{
	ldap_group_xlat_ctx_t		*xlat_ctx = talloc_get_type_abort(uctx, ldap_group_xlat_ctx_t);
	rlm_ldap_t const		*inst = xlat_ctx->inst;

	/*
	 *	Check to see if rlm_ldap_check_groupobj_dynamic or rlm_ldap_check_userobj_dynamic failed
	 */
	if (p_result->rcode == RLM_MODULE_FAIL) return UNLANG_ACTION_CALCULATE_RESULT;

	switch (xlat_ctx->status) {
	case GROUP_XLAT_FIND_USER:
		if (!xlat_ctx->dn) xlat_ctx->dn = rlm_find_user_dn_cached(inst, request);
		if (!xlat_ctx->dn) RETURN_UNLANG_FAIL;

		RDEBUG3("Entered GROUP_XLAT_FIND_USER with user DN \"%s\"", xlat_ctx->dn);
		if (inst->group.obj_membership_filter) {
			REPEAT_LDAP_MEMBEROF_XLAT_RESULTS;
			RDEBUG3("Checking for user in group objects");
			if (rlm_ldap_check_groupobj_dynamic(p_result, request, xlat_ctx) == UNLANG_ACTION_PUSHED_CHILD) {
				xlat_ctx->status = GROUP_XLAT_MEMB_FILTER;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
		}
		FALL_THROUGH;

	case GROUP_XLAT_MEMB_FILTER:
		if (xlat_ctx->found) RETURN_UNLANG_OK;

		RDEBUG3("Entered GROUP_XLAT_MEMB_FILTER with user DN \"%s\"", xlat_ctx->dn);
		if (inst->group.userobj_membership_attr) {
			REPEAT_LDAP_MEMBEROF_XLAT_RESULTS;
			if (rlm_ldap_check_userobj_dynamic(p_result, request, xlat_ctx) == UNLANG_ACTION_PUSHED_CHILD) {
				xlat_ctx->status = GROUP_XLAT_MEMB_ATTR;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
		}
		FALL_THROUGH;

	case GROUP_XLAT_MEMB_ATTR:
		RDEBUG3("Entered GROUP_XLAT_MEMB_ATTR with user DN \"%s\"", xlat_ctx->dn);
		if (xlat_ctx->found) RETURN_UNLANG_OK;
		break;
	}

	RETURN_UNLANG_NOTFOUND;
}

/** Process the results of evaluating LDAP group membership
 *
 */
static xlat_action_t ldap_group_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					    UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	ldap_group_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(xctx->rctx, ldap_group_xlat_ctx_t);
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
	vb->vb_bool = xlat_ctx->found;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const ldap_group_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING, .safe_for = LDAP_URI_SAFE_FOR },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Check for a user being in a LDAP group
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_group_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
	 			     request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t			*vb = NULL, *group_vb = fr_value_box_list_pop_head(in);
	rlm_ldap_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_ldap_t);
	fr_ldap_thread_t		*t = talloc_get_type_abort(xctx->mctx->thread, fr_ldap_thread_t);
	ldap_xlat_memberof_call_env_t	*env_data = talloc_get_type_abort(xctx->env_data, ldap_xlat_memberof_call_env_t);
	bool				group_is_dn;
	ldap_group_xlat_ctx_t		*xlat_ctx;

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

	if ((group_is_dn && inst->group.cacheable_dn) || (!group_is_dn && inst->group.cacheable_name)) {
		unlang_result_t our_result;

		rlm_ldap_check_cached(&our_result, inst, request, group_vb);
		switch (our_result.rcode) {
		case RLM_MODULE_NOTFOUND:
			RDEBUG2("User is not a member of \"%pV\"", group_vb);
			return XLAT_ACTION_DONE;

		case RLM_MODULE_OK:
			MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
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

	MEM(xlat_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_group_xlat_ctx_t));

	*xlat_ctx = (ldap_group_xlat_ctx_t){
		.inst = inst,
		.group = group_vb,
		.dn = rlm_find_user_dn_cached(inst, request),
		.attrs = { inst->group.userobj_membership_attr, NULL },
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

	if (unlang_xlat_yield(request, ldap_group_xlat_resume, NULL, 0, xlat_ctx) != XLAT_ACTION_YIELD) goto error;

	if (unlang_function_push_with_result(NULL,
					     request,
					     xlat_ctx->dn ? NULL : ldap_group_xlat_user_find,
					     ldap_group_xlat_results,
					     ldap_group_xlat_cancel, ~FR_SIGNAL_CANCEL,
					     UNLANG_SUB_FRAME,
					     xlat_ctx) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

typedef struct {
	fr_ldap_result_code_t	ret;
	int			applied;
	LDAPURLDesc		*url;
	fr_ldap_map_exp_t	expanded;
} ldap_xlat_profile_ctx_t;

/** Return whether evaluating the profile was successful
 *
 */
static xlat_action_t ldap_profile_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	ldap_xlat_profile_ctx_t		*xlat_ctx = talloc_get_type_abort(xctx->rctx, ldap_xlat_profile_ctx_t);
	fr_value_box_t			*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
	vb->vb_bool = (xlat_ctx->ret == LDAP_RESULT_SUCCESS) && (xlat_ctx->applied > 0);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static int ldap_xlat_profile_ctx_free(ldap_xlat_profile_ctx_t *to_free)
{
	if (to_free->url) {
		ldap_free_urldesc(to_free->url);
		to_free->url = NULL;
	}
	return 0;
}

/** Expand an LDAP URL into a query, applying the results using the user update map.
 *
 * For fetching profiles by DN.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_profile_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				       xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	rlm_ldap_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_ldap_t);
	fr_ldap_thread_t		*t = talloc_get_type_abort(xctx->mctx->thread, fr_ldap_thread_t);
	ldap_xlat_profile_call_env_t	*env_data = talloc_get_type_abort(xctx->env_data, ldap_xlat_profile_call_env_t);
	fr_value_box_t			*uri_components, *uri;
	char				*host_url, *host = NULL;
	fr_ldap_config_t const		*handle_config = t->config;
	fr_ldap_thread_trunk_t		*ttrunk;
	ldap_xlat_profile_ctx_t		*xlat_ctx = NULL;

	int				ldap_url_ret;

	char const			*dn;
	char const			*filter;
	int				scope;

	bool				is_dn;

	XLAT_ARGS(in, &uri_components);

	is_dn = (fr_uri_has_scheme(&uri_components->vb_group, ldap_uri_scheme_table, ldap_uri_scheme_table_len, -1) < 0);

	/*
	 *	Apply different escaping rules based on whether the first
	 *	arg lookgs like a URI or a DN.
	 */
	if (is_dn) {
		if (fr_uri_escape_list(&uri_components->vb_group, ldap_dn_parts, NULL) < 0) {
			RPERROR("Failed to escape LDAP profile DN");
			return XLAT_ACTION_FAIL;
		}
	} else {
		if (fr_uri_escape_list(&uri_components->vb_group, ldap_uri_parts, NULL) < 0) {
			RPERROR("Failed to escape LDAP profile URI");
			return XLAT_ACTION_FAIL;
		}
	}

	/*
	 *	Smush everything into the first URI box
	 */
	uri = fr_value_box_list_head(&uri_components->vb_group);
	if (fr_value_box_list_concat_in_place(uri, uri, &uri_components->vb_group,
					      FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Allocate a resumption context to store temporary resource and results
	 */
	MEM(xlat_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), ldap_xlat_profile_ctx_t));
	talloc_set_destructor(xlat_ctx, ldap_xlat_profile_ctx_free);

	if (is_dn) {
		host_url = handle_config->server;
		dn = talloc_typed_strdup_buffer(xlat_ctx, uri->vb_strvalue);
		filter = env_data->profile_filter.vb_strvalue;
		scope = inst->profile.obj_scope;
	} else {
		ldap_url_ret = ldap_url_parse(uri->vb_strvalue, &xlat_ctx->url);
		if (ldap_url_ret != LDAP_URL_SUCCESS){
			RPEDEBUG("Parsing LDAP URL failed - %s", fr_ldap_url_err_to_str(ldap_url_ret));
		error:
			talloc_free(xlat_ctx);
			return XLAT_ACTION_FAIL;
		}

		/*
		*	The URL must specify a DN
		*/
		if (!xlat_ctx->url->lud_dn) {
			REDEBUG("LDAP URI must specify a profile DN");
			goto error;
		}

		dn = xlat_ctx->url->lud_dn;
		/*
		 *	Either we use the filter from the URL or we use the default filter
		 *	configured for profiles.
		 */
		filter = xlat_ctx->url->lud_filter ? xlat_ctx->url->lud_filter : env_data->profile_filter.vb_strvalue;

		/*
		 *	Determine if the URL includes a scope.
		 */
		scope = xlat_ctx->url->lud_scope == LDAP_SCOPE_DEFAULT ? inst->profile.obj_scope : xlat_ctx->url->lud_scope;

		/*
		 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
		 */
		if (!xlat_ctx->url->lud_host) {
			host_url = handle_config->server;
		} else {
			host_url = host = host_uri_canonify(request, xlat_ctx->url, uri);
			if (unlikely(host_url == NULL)) goto error;
		}
	}

	/*
	 *	Synchronous expansion of maps (fixme!)
	 */
	if (fr_ldap_map_expand(xlat_ctx, &xlat_ctx->expanded, request, env_data->profile_map,
			       inst->valuepair_attr, inst->profile.check_attr, inst->profile.fallthrough_attr) < 0) goto error;
	ttrunk = fr_thread_ldap_trunk_get(t, host_url, handle_config->admin_identity,
					  handle_config->admin_password, request, handle_config);
	if (host) ldap_memfree(host);
	if (!ttrunk) {
		REDEBUG("Unable to get LDAP query for xlat");
		goto error;
	}

	if (unlang_xlat_yield(request, ldap_profile_xlat_resume, NULL, 0, xlat_ctx) != XLAT_ACTION_YIELD) goto error;

	/*
	 *	Pushes a frame onto the stack to retrieve and evaluate a profile
	 */
	if (rlm_ldap_map_profile(&xlat_ctx->ret, &xlat_ctx->applied, inst, request, ttrunk, dn,
				 scope, filter, &xlat_ctx->expanded) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

/*
 *	Verify the result of the map.
 */
static int ldap_map_verify(CONF_SECTION *cs, UNUSED void const *mod_inst, UNUSED void *proc_inst,
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
 * @param[out] p_result	Result of map expansion:
 *			- #RLM_MODULE_NOOP no rows were returned.
 *			- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *			- #RLM_MODULE_FAIL if an error occurred.
 * @param[in] mpctx module map ctx.
 * @param[in,out] request The current request.
 * @param[in] url LDAP url specifying base DN and filter.
 * @param[in] maps Head of the map list.
 * @return One of UNLANG_ACTION_*
 */
static unlang_action_t mod_map_resume(unlang_result_t *p_result, map_ctx_t const *mpctx, request_t *request,
				      UNUSED fr_value_box_list_t *url, UNUSED map_list_t const *maps)
{
	ldap_map_ctx_t		*map_ctx = talloc_get_type_abort(mpctx->rctx, ldap_map_ctx_t);
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
	case LDAP_RESULT_BAD_DN:
		goto finish;

	case LDAP_RESULT_TIMEOUT:
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
	RETURN_UNLANG_RCODE(rcode);
}

/**  Ensure map context is properly cleared up
 *
 */
static int map_ctx_free(ldap_map_ctx_t *map_ctx)
{
	int i = 0;
	talloc_free(map_ctx->expanded.ctx);
	ldap_free_urldesc(map_ctx->ldap_url);
	while ((i < LDAP_MAX_CONTROLS) && map_ctx->serverctrls[i]) {
		ldap_control_free(map_ctx->serverctrls[i]);
		i++;
	}
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
 * @param[in] mpctx module map ctx.
 * @param[in,out] request The current request.
 * @param[in] url LDAP url specifying base DN and filter.
 * @param[in] maps Head of the map list.
 * @return UNLANG_ACTION_CALCULATE_RESULT
 */
static unlang_action_t mod_map_proc(unlang_result_t *p_result, map_ctx_t const *mpctx, request_t *request,
				    fr_value_box_list_t *url, map_list_t const *maps)
{
	rlm_ldap_t const	*inst = talloc_get_type_abort_const(mpctx->moi, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_thread(inst->mi)->data, fr_ldap_thread_t);

	LDAPURLDesc		*ldap_url;
	int			ldap_url_ret;
	fr_ldap_thread_trunk_t	*ttrunk;

	fr_value_box_t		*url_head;
	ldap_map_ctx_t		*map_ctx;
	char			*host_url, *host = NULL;

	if (fr_uri_escape_list(url, ldap_uri_parts, NULL) < 0) {
		RPERROR("Failed to escape LDAP map URI");
		RETURN_UNLANG_FAIL;
	}

	url_head = fr_value_box_list_head(url);
	if (!url_head) {
		REDEBUG("LDAP URL cannot be empty");
		RETURN_UNLANG_FAIL;
	}

	if (fr_value_box_list_concat_in_place(url_head, url_head, url, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Failed concatenating input");
		RETURN_UNLANG_FAIL;
	}

	if (!ldap_is_ldap_url(url_head->vb_strvalue)) {
		REDEBUG("Map query string does not look like a valid LDAP URI");
		RETURN_UNLANG_FAIL;
	}

	MEM(map_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), ldap_map_ctx_t));
	talloc_set_destructor(map_ctx, map_ctx_free);
	map_ctx->maps = maps;

	ldap_url_ret = ldap_url_parse(url_head->vb_strvalue, &map_ctx->ldap_url);
	if (ldap_url_ret != LDAP_URL_SUCCESS){
		RPEDEBUG("Parsing LDAP URL failed - %s", fr_ldap_url_err_to_str(ldap_url_ret));
	fail:
		talloc_free(map_ctx);
		RETURN_UNLANG_FAIL;
	}
	ldap_url = map_ctx->ldap_url;

	if (ldap_url->lud_exts) {
		if (fr_ldap_parse_url_extensions(map_ctx->serverctrls, NUM_ELEMENTS(map_ctx->serverctrls),
						 ldap_url->lud_exts) < 0) {
			RPERROR("Parsing URL extensions failed");
			goto fail;
		}
	}

	/*
	 *	Expand the RHS of the maps to get the name of the attributes.
	 */
	if (fr_ldap_map_expand(map_ctx, &map_ctx->expanded, request, maps, NULL, NULL, NULL) < 0) goto fail;

	/*
	 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
	 */
	if (!ldap_url->lud_host) {
		host_url = inst->handle_config.server;
	} else {
		host_url = host = host_uri_canonify(request, ldap_url, url_head);
		if (unlikely(host_url == NULL)) goto fail;
	}

	ttrunk = fr_thread_ldap_trunk_get(thread, host_url, inst->handle_config.admin_identity,
					  inst->handle_config.admin_password, request, &inst->handle_config);
	if (host) ldap_memfree(host);
	if (!ttrunk) goto fail;

	if (unlikely(unlang_map_yield(request, mod_map_resume, NULL, 0, map_ctx) != UNLANG_ACTION_YIELD)) goto fail;

	return fr_ldap_trunk_search(map_ctx, &map_ctx->query, request, ttrunk, ldap_url->lud_dn,
				    ldap_url->lud_scope, ldap_url->lud_filter, map_ctx->expanded.attrs,
				    map_ctx->serverctrls, NULL);
}

static unlang_action_t CC_HINT(nonnull) mod_authenticate(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_thread(inst->mi)->data, fr_ldap_thread_t);
	ldap_auth_ctx_t		*auth_ctx;
	ldap_auth_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, ldap_auth_call_env_t);

	if (call_env->password.type != FR_TYPE_STRING) {
		RWDEBUG("You have set \"Auth-Type := LDAP\" somewhere");
		RWDEBUG("without checking if %s is present", call_env->password_tmpl->name);
		RWDEBUG("*********************************************");
		RWDEBUG("* THAT CONFIGURATION IS WRONG.  DELETE IT.   ");
		RWDEBUG("* YOU ARE PREVENTING THE SERVER FROM WORKING");
		RWDEBUG("*********************************************");

		REDEBUG("Attribute \"%s\" is required for authentication", call_env->password_tmpl->name);
		RETURN_UNLANG_INVALID;
	}

	auth_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_auth_ctx_t);
	*auth_ctx = (ldap_auth_ctx_t){
		.password = call_env->password.vb_strvalue,
		.thread = thread,
		.inst = inst,
		.call_env = call_env
	};

	/*
	 *	Find the user's DN
	 */
	auth_ctx->dn = rlm_find_user_dn_cached(inst, request);

	/*
	 *	The DN is required for non-SASL auth
	 */
	if (!auth_ctx->dn && (call_env->user_sasl_mech.type != FR_TYPE_STRING)) {
		REDEBUG("No DN found for authentication.  Populate control.%s with the DN to use in authentication.",
			inst->user.da->name);
		REDEBUG("You should call %s in the recv section and check its return.", inst->mi->name);
		talloc_free(auth_ctx);
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &call_env->password);
	} else {
		RDEBUG2("Login attempt with password");
	}

	/*
	 *	SASL bind auth will have the mech set.
	 */
	if (auth_ctx->call_env->user_sasl_mech.type == FR_TYPE_STRING) {
#ifdef WITH_SASL
		RDEBUG2("Login attempt using identity \"%pV\"", &call_env->user_sasl_authname);

		return fr_ldap_sasl_bind_auth_async(p_result, request, auth_ctx->thread, call_env->user_sasl_mech.vb_strvalue,
						    call_env->user_sasl_authname.vb_strvalue,
						    auth_ctx->password, call_env->user_sasl_proxy.vb_strvalue,
						    call_env->user_sasl_realm.vb_strvalue);
#else
		RDEBUG("Configuration item 'sasl.mech' is not supported.  "
		       "The linked version of libldap does not provide ldap_sasl_bind( function");
		RETURN_UNLANG_FAIL;
#endif
	}

	RDEBUG2("Login attempt as \"%s\"", auth_ctx->dn);

	return fr_ldap_bind_auth_async(p_result, request, auth_ctx->thread, auth_ctx->dn, auth_ctx->password);
}

#define REPEAT_MOD_AUTHORIZE_RESUME \
	if (unlang_module_yield(request, mod_authorize_resume, NULL, 0, autz_ctx) == UNLANG_ACTION_FAIL) do { \
		p_result->rcode = RLM_MODULE_FAIL; \
		goto finish; \
	} while (0)

/** Resume function called after each potential yield in LDAP authorization
 *
 * Some operations may or may not yield.  E.g. if group membership is
 * read from an attribute returned with the user object and is already
 * in the correct form, that will not yield.
 * Hence, each state may fall through to the next.
 *
 * @param p_result	Result of current authorization.
 * @param mctx		Module context.
 * @param request	Current request.
 * @return An rcode.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	ldap_autz_ctx_t		*autz_ctx = talloc_get_type_abort(mctx->rctx, ldap_autz_ctx_t);
	rlm_ldap_t const	*inst = talloc_get_type_abort_const(autz_ctx->inst, rlm_ldap_t);
	ldap_autz_call_env_t	*call_env = talloc_get_type_abort(autz_ctx->call_env, ldap_autz_call_env_t);
	int			ldap_errno;
	LDAP			*handle = fr_ldap_handle_thread_local();
	unlang_action_t		ret = UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	If a previous async call returned one of the "failure" results just return.
	 */
	switch (p_result->rcode) {
	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_HANDLED:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_DISALLOW:
		goto finish;

	default:
		break;
	}

	switch (autz_ctx->status) {
	case LDAP_AUTZ_FIND:
		/*
		 *	If a user entry has been found the current rcode will be OK
		 */
		if (p_result->rcode != RLM_MODULE_OK) return UNLANG_ACTION_CALCULATE_RESULT;

		autz_ctx->entry = ldap_first_entry(handle, autz_ctx->query->result);
		if (!autz_ctx->entry) {
			ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
			REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

			goto finish;
		}

		/*
		 *	Check for access.
		 */
		if (inst->user.obj_access_attr) {
			autz_ctx->access_state = rlm_ldap_check_access(inst, request, autz_ctx->entry);
			switch (autz_ctx->access_state) {
			case LDAP_ACCESS_ALLOWED:
				break;

			case LDAP_ACCESS_SUSPENDED:
				if (inst->group.skip_on_suspend) goto post_group;
				break;

			case LDAP_ACCESS_DISALLOWED:
				p_result->rcode = RLM_MODULE_DISALLOW;
				goto finish;
			}
		}

		/*
		 *	Check if we need to cache group memberships
		 */
		if ((inst->group.cacheable_dn || inst->group.cacheable_name) && (inst->group.userobj_membership_attr)) {
			REPEAT_MOD_AUTHORIZE_RESUME;
			if (rlm_ldap_cacheable_userobj(p_result, request, autz_ctx,
						       inst->group.userobj_membership_attr) == UNLANG_ACTION_PUSHED_CHILD) {
				autz_ctx->status = LDAP_AUTZ_GROUP;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
			if (p_result->rcode != RLM_MODULE_OK) goto finish;
		}
		FALL_THROUGH;

	case LDAP_AUTZ_GROUP:
		if (inst->group.cacheable_dn || inst->group.cacheable_name) {
			REPEAT_MOD_AUTHORIZE_RESUME;
			if (rlm_ldap_cacheable_groupobj(p_result, request, autz_ctx) == UNLANG_ACTION_PUSHED_CHILD) {
				autz_ctx->status = LDAP_AUTZ_POST_GROUP;
				return UNLANG_ACTION_PUSHED_CHILD;
			}
			if (p_result->rcode != RLM_MODULE_OK) goto finish;
		}
		FALL_THROUGH;

	case LDAP_AUTZ_POST_GROUP:
	post_group:
#ifdef WITH_EDIR
		/*
		 *	We already have a Password.Cleartext.  Skip edir.
		 */
		if (fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_cleartext_password)) goto skip_edir;

		/*
		 *      Retrieve Universal Password if we use eDirectory
		 */
		if (inst->edir) {
			autz_ctx->dn = rlm_find_user_dn_cached(inst, request);

			/*
			 *	Retrieve universal password
			 */
			REPEAT_MOD_AUTHORIZE_RESUME;
			autz_ctx->status = LDAP_AUTZ_EDIR_BIND;
			return fr_ldap_edir_get_password(p_result, request, autz_ctx->dn, autz_ctx->ttrunk,
							 attr_cleartext_password);
		}
		FALL_THROUGH;

	case LDAP_AUTZ_EDIR_BIND:
		if (inst->edir && inst->edir_autz) {
			fr_pair_t	*password = fr_pair_find_by_da(&request->control_pairs,
								       NULL, attr_cleartext_password);
			fr_ldap_thread_t *thread = talloc_get_type_abort(module_thread(inst->mi)->data,
									 fr_ldap_thread_t);

			if (!password) {
				REDEBUG("Failed to find control.Password.Cleartext");
				p_result->rcode = RLM_MODULE_FAIL;
				goto finish;
			}

			RDEBUG2("Binding as %s for eDirectory authorization checks", autz_ctx->dn);

			/*
			 *	Bind as the user
			 */
			REPEAT_MOD_AUTHORIZE_RESUME;
			autz_ctx->status = LDAP_AUTZ_POST_EDIR;
			return fr_ldap_bind_auth_async(p_result, request, thread, autz_ctx->dn, password->vp_strvalue);
		}
		goto skip_edir;

	case LDAP_AUTZ_POST_EDIR:
	{
		/*
		 *	The result of the eDirectory user bind will be in p_result.
		 *	Anything other than RLM_MODULE_OK is a failure.
		 */
		break;

	}
	FALL_THROUGH;

#endif
	case LDAP_AUTZ_MAP:
#ifdef WITH_EDIR
	skip_edir:
#endif
		if (!map_list_empty(call_env->user_map) || inst->valuepair_attr) {
			RDEBUG2("Processing user attributes");
			RINDENT();
			if (fr_ldap_map_do(request, NULL, inst->valuepair_attr,
					   &autz_ctx->expanded, autz_ctx->entry) > 0) autz_ctx->rcode = RLM_MODULE_UPDATED;
			REXDENT();
			rlm_ldap_check_reply(request, inst, autz_ctx->dlinst->name, call_env->expect_password->vb_bool, autz_ctx->ttrunk);
		}
		FALL_THROUGH;

	case LDAP_AUTZ_DEFAULT_PROFILE:
		/*
		 *	Apply ONE user profile, or a default user profile.
		 */
		if (call_env->default_profile.type == FR_TYPE_STRING) {
			REPEAT_MOD_AUTHORIZE_RESUME;
			ret = rlm_ldap_map_profile(NULL, NULL, inst, request, autz_ctx->ttrunk,
						   call_env->default_profile.vb_strvalue,
						   inst->profile.obj_scope, NULL, &autz_ctx->expanded);
			switch (ret) {
			case UNLANG_ACTION_FAIL:
				p_result->rcode = RLM_MODULE_FAIL;
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
		 *	Did we jump back her after applying the default profile?
		 */
		if (autz_ctx->status == LDAP_AUTZ_POST_DEFAULT_PROFILE) autz_ctx->rcode = RLM_MODULE_UPDATED;

		/*
		 *	Apply a SET of user profiles.
		 */
		switch (autz_ctx->access_state) {
		case LDAP_ACCESS_ALLOWED:
			if (inst->profile.attr) {
				int count;

				autz_ctx->profile_values = ldap_get_values_len(handle, autz_ctx->entry, inst->profile.attr);
				count = ldap_count_values_len(autz_ctx->profile_values);
				if (count > 0) {
					RDEBUG2("Processing %i profile(s) found in attribute \"%s\"", count, inst->profile.attr);
					if (RDEBUG_ENABLED3) {
						for (struct berval **bv_p = autz_ctx->profile_values; *bv_p; bv_p++) {
							RDEBUG3("Will evaluate profile with DN \"%pV\"", fr_box_strvalue_len((*bv_p)->bv_val, (*bv_p)->bv_len));
						}
					}
				} else {
					RDEBUG2("No profile(s) found in attribute \"%s\"", inst->profile.attr);
				}
			}
			break;

		case LDAP_ACCESS_SUSPENDED:
			if (inst->profile.attr_suspend) {
				int count;

				autz_ctx->profile_values = ldap_get_values_len(handle, autz_ctx->entry, inst->profile.attr_suspend);
				count = ldap_count_values_len(autz_ctx->profile_values);
				if (count > 0) {
					RDEBUG2("Processing %i suspension profile(s) found in attribute \"%s\"", count, inst->profile.attr_suspend);
					if (RDEBUG_ENABLED3) {
						for (struct berval **bv_p = autz_ctx->profile_values; *bv_p; bv_p++) {
							RDEBUG3("Will evaluate suspenension profile with DN \"%pV\"",
								fr_box_strvalue_len((*bv_p)->bv_val, (*bv_p)->bv_len));
						}
					}
				} else {
					RDEBUG2("No suspension profile(s) found in attribute \"%s\"", inst->profile.attr_suspend);
				}
			}
			break;

		case LDAP_ACCESS_DISALLOWED:
			break;
		}

		FALL_THROUGH;

	case LDAP_AUTZ_USER_PROFILE:
		/*
		 *	After each profile has been applied, execution will restart here.
		 *	Start by clearing the previously used value.
		 */
		if (autz_ctx->profile_value) {
			TALLOC_FREE(autz_ctx->profile_value);
			autz_ctx->rcode = RLM_MODULE_UPDATED;	/* We're back here after applying a profile successfully */
		}

		if (autz_ctx->profile_values && autz_ctx->profile_values[autz_ctx->value_idx]) {
			autz_ctx->profile_value = fr_ldap_berval_to_string(autz_ctx, autz_ctx->profile_values[autz_ctx->value_idx++]);
			REPEAT_MOD_AUTHORIZE_RESUME;
			ret = rlm_ldap_map_profile(NULL, NULL, inst, request, autz_ctx->ttrunk, autz_ctx->profile_value,
						   inst->profile.obj_scope, autz_ctx->call_env->profile_filter.vb_strvalue, &autz_ctx->expanded);
			switch (ret) {
			case UNLANG_ACTION_FAIL:
				p_result->rcode = RLM_MODULE_FAIL;
				goto finish;

			case UNLANG_ACTION_PUSHED_CHILD:
				autz_ctx->status = LDAP_AUTZ_USER_PROFILE;
				return UNLANG_ACTION_PUSHED_CHILD;

			default:
				break;
			}
		}
		break;
	}

	p_result->rcode = autz_ctx->rcode;

finish:
	return ret;
}

/** Clear up when cancelling a mod_authorize call
 *
 */
static void mod_authorize_cancel(module_ctx_t const *mctx, UNUSED request_t *request, UNUSED fr_signal_t action)
{
	ldap_autz_ctx_t	*autz_ctx = talloc_get_type_abort(mctx->rctx, ldap_autz_ctx_t);

	if (autz_ctx->query && autz_ctx->query->treq) trunk_request_signal_cancel(autz_ctx->query->treq);
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

static unlang_action_t CC_HINT(nonnull) mod_authorize(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_thread(inst->mi)->data, fr_ldap_thread_t);
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
	if (fr_ldap_map_expand(autz_ctx, expanded, request, call_env->user_map, inst->valuepair_attr,
			       inst->profile.check_attr, inst->profile.fallthrough_attr) < 0) {
	fail:
		talloc_free(autz_ctx);
		RETURN_UNLANG_FAIL;
	}

	autz_ctx->ttrunk =  fr_thread_ldap_trunk_get(thread, inst->handle_config.server, inst->handle_config.admin_identity,
						     inst->handle_config.admin_password, request, &inst->handle_config);
	if (!autz_ctx->ttrunk) goto fail;

#define CHECK_EXPANDED_SPACE(_expanded) fr_assert((size_t)_expanded->count < (NUM_ELEMENTS(_expanded->attrs) - 1));

	/*
	 *	Add any additional attributes we need for checking access, memberships, and profiles
	 */
	if (inst->user.obj_access_attr) {
		CHECK_EXPANDED_SPACE(expanded);
		expanded->attrs[expanded->count++] = inst->user.obj_access_attr;
	}

	if (inst->group.userobj_membership_attr && (inst->group.cacheable_dn || inst->group.cacheable_name)) {
		CHECK_EXPANDED_SPACE(expanded);
		expanded->attrs[expanded->count++] = inst->group.userobj_membership_attr;
	}

	if (inst->profile.attr) {
		CHECK_EXPANDED_SPACE(expanded);
		expanded->attrs[expanded->count++] = inst->profile.attr;
	}

	if (inst->profile.attr_suspend) {
		CHECK_EXPANDED_SPACE(expanded);
		expanded->attrs[expanded->count++] = inst->profile.attr_suspend;
	}
	expanded->attrs[expanded->count] = NULL;

	autz_ctx->dlinst = mctx->mi;
	autz_ctx->inst = inst;
	autz_ctx->call_env = call_env;
	autz_ctx->status = LDAP_AUTZ_FIND;
	autz_ctx->rcode = RLM_MODULE_OK;

	if (unlikely(unlang_module_yield(request,
					 mod_authorize_resume,
					 mod_authorize_cancel, ~FR_SIGNAL_CANCEL,
					 autz_ctx) == UNLANG_ACTION_FAIL)) {
		talloc_free(autz_ctx);
		RETURN_UNLANG_FAIL;
	}

	return rlm_ldap_find_user_async(autz_ctx, p_result,
					autz_ctx->inst, request, &autz_ctx->call_env->user_base,
					&autz_ctx->call_env->user_filter, autz_ctx->ttrunk, autz_ctx->expanded.attrs,
					&autz_ctx->query);
}

/** Cancel an in progress user modification.
 *
 */
static void user_modify_cancel(module_ctx_t const *mctx, UNUSED request_t *request, UNUSED fr_signal_t action)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(mctx->rctx, ldap_user_modify_ctx_t);

	if (!usermod_ctx->query || !usermod_ctx->query->treq) return;

	trunk_request_signal_cancel(usermod_ctx->query->treq);
}

/** Handle results of user modification.
 *
 */
static unlang_action_t CC_HINT(nonnull) user_modify_final(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(mctx->rctx, ldap_user_modify_ctx_t);
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

	case LDAP_RESULT_TIMEOUT:
		rcode = RLM_MODULE_TIMEOUT;
		break;

	default:
		rcode = RLM_MODULE_FAIL;
		break;
	}

	talloc_free(usermod_ctx);
	RETURN_UNLANG_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) user_modify_mod_build_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(mctx->rctx, ldap_user_modify_ctx_t);
	ldap_usermod_call_env_t	*call_env = usermod_ctx->call_env;
	LDAPMod			**modify;
	ldap_mod_tmpl_t		*mod;
	fr_value_box_t		*vb = NULL;
	int			mod_no = usermod_ctx->expanded_mods, i = 0;
	struct berval		**value_refs;
	struct berval		*values;

	mod = call_env->mod[usermod_ctx->current_mod];

	/*
	 *	If the tmpl produced no boxes, skip
	 */
	if ((mod->op != T_OP_CMP_FALSE) && (fr_value_box_list_num_elements(&usermod_ctx->expanded) == 0)) {
		RDEBUG2("Expansion \"%s\" produced no value, skipping attribute \"%s\"", mod->tmpl->name, mod->attr);
		goto next;
	}

	switch (mod->op) {
	/*
	 *	T_OP_EQ is *NOT* supported, it is impossible to
	 *	support because of the lack of transactions in LDAP
	 *
	 *	To allow for binary data, all data is provided as berval which
	 *	requires the operation to be logical ORed with LDAP_MOD_BVALUES
	 */
	case T_OP_ADD_EQ:
		usermod_ctx->mod_s[mod_no].mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		break;

	case T_OP_SET:
		usermod_ctx->mod_s[mod_no].mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
		break;

	case T_OP_SUB_EQ:
	case T_OP_CMP_FALSE:
		usermod_ctx->mod_s[mod_no].mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
		break;

	case T_OP_INCRM:
		usermod_ctx->mod_s[mod_no].mod_op = LDAP_MOD_INCREMENT | LDAP_MOD_BVALUES;
		break;

	default:
		REDEBUG("Operator '%s' is not supported for LDAP modify operations",
			fr_table_str_by_value(fr_tokens_table, mod->op, "<INVALID>"));

		RETURN_UNLANG_INVALID;
	}

	if (mod->op == T_OP_CMP_FALSE) {
		MEM(value_refs = talloc_zero_array(usermod_ctx, struct berval *, 1));
	} else {
		MEM(value_refs = talloc_zero_array(usermod_ctx, struct berval *,
						   fr_value_box_list_num_elements(&usermod_ctx->expanded) + 1));
		MEM(values = talloc_zero_array(usermod_ctx, struct berval,
					       fr_value_box_list_num_elements(&usermod_ctx->expanded)));
		while ((vb = fr_value_box_list_pop_head(&usermod_ctx->expanded))) {
			switch (vb->type) {
			case FR_TYPE_OCTETS:
				if (vb->vb_length == 0) continue;
				memcpy(&values[i].bv_val, &vb->vb_octets, sizeof(values[i].bv_val));
				values[i].bv_len = vb->vb_length;
				break;

			case FR_TYPE_STRING:
			populate_string:
				if (vb->vb_length == 0) continue;
				memcpy(&values[i].bv_val, &vb->vb_strvalue, sizeof(values[i].bv_val));
				values[i].bv_len = vb->vb_length;
				break;

			case FR_TYPE_GROUP:
			{
				fr_value_box_t	*vb_head = fr_value_box_list_head(&vb->vb_group);
				if (fr_value_box_list_concat_in_place(vb_head, vb_head, &vb->vb_group, FR_TYPE_STRING,
								      FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
					RPEDEBUG("Failed concatenating update value");
					RETURN_UNLANG_FAIL;
				}
				vb = vb_head;
				goto populate_string;
			}

			case FR_TYPE_FIXED_SIZE:
				if (fr_value_box_cast_in_place(vb, vb, FR_TYPE_STRING, NULL) < 0) {
					RPEDEBUG("Failed casting update value");
					RETURN_UNLANG_FAIL;
				}
				goto populate_string;

			default:
				fr_assert(0);

			}
			value_refs[i] = &values[i];
			i++;
		}
		if (i == 0) {
			RDEBUG2("Expansion \"%s\" produced zero length value, skipping attribute \"%s\"", mod->tmpl->name, mod->attr);
			goto next;
		}
	}

	/*
	 *	Now everything is evaluated, set up the pointers for the LDAPMod
	 */
	memcpy(&(usermod_ctx->mod_s[mod_no].mod_type), &mod->attr, sizeof(usermod_ctx->mod_s[mod_no].mod_type));
	usermod_ctx->mod_s[mod_no].mod_bvalues = value_refs;
	usermod_ctx->mod_p[mod_no] = &usermod_ctx->mod_s[mod_no];

	usermod_ctx->expanded_mods++;
	usermod_ctx->mod_p[usermod_ctx->expanded_mods] = NULL;

next:
	usermod_ctx->current_mod++;

	/*
	 *	Keep calling until we've completed all the modifications
	 */
	if (usermod_ctx->current_mod < usermod_ctx->num_mods) {
		if (unlang_module_yield(request, user_modify_mod_build_resume, NULL, 0, usermod_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		if (unlang_tmpl_push(usermod_ctx, NULL, &usermod_ctx->expanded, request,
				     usermod_ctx->call_env->mod[usermod_ctx->current_mod]->tmpl, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	modify = usermod_ctx->mod_p;

	if (unlang_module_yield(request, user_modify_final, user_modify_cancel, ~FR_SIGNAL_CANCEL, usermod_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;

	return fr_ldap_trunk_modify(usermod_ctx, &usermod_ctx->query, request, usermod_ctx->ttrunk,
				    usermod_ctx->dn, modify, NULL, NULL);
}

/** Take the retrieved user DN and launch the async tmpl expansion of mod_values.
 *
 */
static unlang_action_t CC_HINT(nonnull) user_modify_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	ldap_user_modify_ctx_t	*usermod_ctx = talloc_get_type_abort(mctx->rctx, ldap_user_modify_ctx_t);

	/*
	 *	If an LDAP search was used to find the user DN
	 *	usermod_ctx->dn will be NULL.
	 */
	if (!usermod_ctx->dn) usermod_ctx->dn = rlm_find_user_dn_cached(mctx->mi->data, request);

	if (!usermod_ctx->dn) {
	fail:
		talloc_free(usermod_ctx);
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Allocate arrays to hold mods.  mod_p is one element longer to hold a terminating NULL entry
	 */
	MEM(usermod_ctx->mod_p = talloc_zero_array(usermod_ctx, LDAPMod *, usermod_ctx->num_mods + 1));
	MEM(usermod_ctx->mod_s = talloc_array(usermod_ctx, LDAPMod, usermod_ctx->num_mods));
	fr_value_box_list_init(&usermod_ctx->expanded);

	if (unlang_module_yield(request, user_modify_mod_build_resume, NULL, 0, usermod_ctx) == UNLANG_ACTION_FAIL) goto fail;
;
	if (unlang_tmpl_push(usermod_ctx, NULL, &usermod_ctx->expanded, request,
			     usermod_ctx->call_env->mod[0]->tmpl, NULL, UNLANG_SUB_FRAME) < 0) goto fail;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Modify user's object in LDAP
 *
 * Process a modification map to update a user object in the LDAP directory.
 *
 * The module method called in "accouting" and "send" sections.
 */
static unlang_action_t CC_HINT(nonnull) mod_modify(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_ldap_t);
	ldap_usermod_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, ldap_usermod_call_env_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_thread(inst->mi)->data, fr_ldap_thread_t);
	ldap_user_modify_ctx_t	*usermod_ctx = NULL;

	size_t		num_mods = talloc_array_length(call_env->mod);

	if (num_mods == 0) RETURN_UNLANG_NOOP;

	/*
	 *	Include a talloc pool allowing for one value per modification
	 */
	MEM(usermod_ctx = talloc_pooled_object(unlang_interpret_frame_talloc_ctx(request), ldap_user_modify_ctx_t,
					       2 * num_mods + 2,
					       (sizeof(struct berval) + (sizeof(struct berval *) * 2) +
					        (sizeof(LDAPMod) + sizeof(LDAPMod *))) * num_mods));
	*usermod_ctx = (ldap_user_modify_ctx_t) {
		.inst = inst,
		.call_env = call_env,
		.num_mods = num_mods
	};

	usermod_ctx->ttrunk = fr_thread_ldap_trunk_get(thread, inst->handle_config.server,
						       inst->handle_config.admin_identity,
						       inst->handle_config.admin_password,
						       request, &inst->handle_config);
	if (!usermod_ctx->ttrunk) {
		REDEBUG("Unable to get LDAP trunk for update");
		talloc_free(usermod_ctx);
		RETURN_UNLANG_FAIL;
	}

	usermod_ctx->dn = rlm_find_user_dn_cached(inst, request);
	/*
	 *	Find the user first
	 */
	if (!usermod_ctx->dn) {
		if (unlang_module_yield(request, user_modify_resume, NULL, 0, usermod_ctx) == UNLANG_ACTION_FAIL) {
			talloc_free(usermod_ctx);
			RETURN_UNLANG_FAIL;
		}

		/* Pushes a frame for user resolution */
		if (rlm_ldap_find_user_async(usermod_ctx,
					     p_result,
					     usermod_ctx->inst, request,
					     &usermod_ctx->call_env->user_base,
					     &usermod_ctx->call_env->user_filter,
					     usermod_ctx->ttrunk, NULL, NULL) == UNLANG_ACTION_FAIL) {
			RETURN_UNLANG_FAIL;
		}

		return UNLANG_ACTION_PUSHED_CHILD;
	}

	{
		module_ctx_t our_mctx = *mctx;
		our_mctx.rctx = usermod_ctx;

		return user_modify_resume(p_result, &our_mctx, request);
	}
}

/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_ldap_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_ldap_t);

	if (inst->user.obj_sort_ctrl) ldap_control_free(inst->user.obj_sort_ctrl);
	if (inst->profile.obj_sort_ctrl) ldap_control_free(inst->profile.obj_sort_ctrl);

	return 0;
}

static int ldap_update_section_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules,
				     CONF_ITEM *ci,
				     UNUSED call_env_ctx_t const *cec, call_env_parser_t const *rule)
{
	map_list_t			*maps;
	CONF_SECTION			*update = cf_item_to_section(ci);
	ldap_update_rules_t const	*ur = rule->uctx;

	bool				expect_password = false;

	/*
	 *	Build the attribute map
	 */
	{
		map_t const		*map = NULL;
		tmpl_attr_t const	*ar;
		call_env_parsed_t	*parsed;

		MEM(parsed = call_env_parsed_add(ctx, out,
						 &(call_env_parser_t){
							.name = "update",
							.flags = CALL_ENV_FLAG_PARSE_ONLY,
							.pair = {
								.parsed = {
									.offset = ur->map_offset,
									.type = CALL_ENV_PARSE_TYPE_VOID
								}
							}
						 }));

		MEM(maps = talloc(parsed, map_list_t));
		map_list_init(maps);

		if (update && (map_afrom_cs(maps, maps, update, t_rules, t_rules, fr_ldap_map_verify,
					    NULL, LDAP_MAX_ATTRMAP)) < 0) {
			call_env_parsed_free(out, parsed);
			return -1;
		}
		/*
		 *	Check map to see if a password is being retrieved.
		 *	fr_ldap_map_verify ensures that all maps have attributes on the LHS.
		 *	All passwords have a common parent attribute of attr_password
		 */
		while ((map = map_list_next(maps, map))) {
			ar = tmpl_attr_tail(map->lhs);
			if (ar->da->parent == attr_password) {
				expect_password = true;
				break;
			}
		}
		call_env_parsed_set_data(parsed, maps);
	}

	/*
	 *	Write out whether we expect a password to be returned from the ldap data
	 */
	if (ur->expect_password_offset >= 0) {
		call_env_parsed_t *parsed;
		fr_value_box_t *vb;

		MEM(parsed = call_env_parsed_add(ctx, out,
						 &(call_env_parser_t){
							.name = "expect_password",
							.flags = CALL_ENV_FLAG_PARSE_ONLY,
							.pair = {
								.parsed = {
									.offset = ur->expect_password_offset,
									.type = CALL_ENV_PARSE_TYPE_VALUE_BOX
								}
							}
						 }));
		MEM(vb = fr_value_box_alloc(parsed, FR_TYPE_BOOL, NULL));
		vb->vb_bool = expect_password;
		call_env_parsed_set_value(parsed, vb);
	}

	return 0;
}

static int ldap_mod_section_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules,
				  CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	CONF_SECTION const	*subcs = NULL;
	CONF_PAIR const		*to_parse = NULL;
	tmpl_t			*parsed_tmpl;
	call_env_parsed_t	*parsed_env;
	char			*section2, *p;
	ssize_t			count, slen, multi_index = 0;
	ldap_mod_tmpl_t		*mod;

	fr_assert(cec->type == CALL_ENV_CTX_TYPE_MODULE);

	section2 = talloc_strdup(NULL, section_name_str(cec->asked->name2));
	p = section2;
	while (*p != '\0') {
		*(p) = tolower((uint8_t)*p);
		p++;
	}

	if (!ci) {
	not_found:
		cf_log_warn(ci, "No section found for \"%s.%s\" in module \"%s\", this call will have no effect.",
			    section_name_str(cec->asked->name1), section2, cec->mi->name);
	free:
		talloc_free(section2);
		return 0;
	}

	subcs = cf_section_find(cf_item_to_section(ci), section2, CF_IDENT_ANY);
	if (!subcs) goto not_found;

	subcs = cf_section_find(subcs, "update", CF_IDENT_ANY);
	if (!subcs) {
		cf_log_warn(ci, "No update found inside \"%s -> %s\" in module \"%s\"",
			    section_name_str(cec->asked->name1), section2, cec->mi->name);
		goto free;
	}

	count = cf_pair_count_descendents(subcs);
	if (count == 0) {
		cf_log_warn(ci, "No modifications found for \"%s.%s\" in module \"%s\"",
			    section_name_str(cec->asked->name1), section2, cec->mi->name);
		goto free;
	}
	talloc_free(section2);

	while ((to_parse = cf_pair_next(subcs, to_parse))) {
		switch (cf_pair_operator(to_parse)) {
		case T_OP_SET:
		case T_OP_ADD_EQ:
		case T_OP_SUB_EQ:
		case T_OP_CMP_FALSE:
		case T_OP_INCRM:
			break;

		default:
			cf_log_perr(to_parse, "Invalid operator for LDAP modification");
			return -1;
		}

		MEM(parsed_env = call_env_parsed_add(ctx, out,
						     &(call_env_parser_t){
							FR_CALL_ENV_PARSE_ONLY_OFFSET(cf_pair_attr(to_parse), FR_TYPE_VOID,
										      CALL_ENV_FLAG_MULTI,
										      ldap_usermod_call_env_t, mod)
						     }));

		slen = tmpl_afrom_substr(parsed_env, &parsed_tmpl,
					 &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
					 cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
					 t_rules);

		if (slen <= 0) {
			cf_canonicalize_error(to_parse, slen, "Failed parsing LDAP modification \"%s\"", cf_pair_value(to_parse));
		error:
			call_env_parsed_free(out, parsed_env);
			return -1;
		}
		if (tmpl_needs_resolving(parsed_tmpl) &&
		    (tmpl_resolve(parsed_tmpl, &(tmpl_res_rules_t){ .dict_def = t_rules->attr.dict_def }) <0)) {
			cf_log_perr(to_parse, "Failed resolving LDAP modification \"%s\"", cf_pair_value(to_parse));
			goto error;
		}

		MEM(mod = talloc(parsed_env, ldap_mod_tmpl_t));
		mod->attr = cf_pair_attr(to_parse);
		mod->tmpl = parsed_tmpl;
		mod->op = cf_pair_operator(to_parse);

		call_env_parsed_set_multi_index(parsed_env, count, multi_index++);
		call_env_parsed_set_data(parsed_env, mod);
	}

	return 0;
}

static int ldap_group_filter_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, UNUSED CONF_ITEM *ci,
				   call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_ldap_t const		*inst = talloc_get_type_abort_const(cec->mi->data, rlm_ldap_t);
	char const			*filters[] = { inst->group.obj_filter, inst->group.obj_membership_filter };
	tmpl_t				*parsed;

	if (fr_ldap_filter_to_tmpl(ctx, t_rules, filters, NUM_ELEMENTS(filters), &parsed) < 0) return -1;

	*(void **)out = parsed;
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

/** Initialise thread specific data structure
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_ldap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_ldap_t);
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
	t->trigger_args = inst->trigger_args;
	t->bind_trigger_args = inst->bind_trigger_args;

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
	size_t			i;

	CONF_SECTION		*options;
	rlm_ldap_boot_t	const	*boot = talloc_get_type_abort(mctx->mi->boot, rlm_ldap_boot_t);
	rlm_ldap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_ldap_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	inst->mi = mctx->mi;	/* Cached for IO callbacks */
	inst->group.da = boot->group_da;
	inst->group.cache_da = boot->cache_da;
	inst->user.da = boot->user_da;

	inst->handle_config.name = talloc_typed_asprintf(inst, "rlm_ldap (%s)", mctx->mi->name);

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

	options = cf_section_find(conf, "options", NULL);
	if (!options || !cf_pair_find(options, "chase_referrals")) {
		inst->handle_config.chase_referrals_unset = true;	 /* use OpenLDAP defaults */
	}

	/*
	 *	Sanity checks for cacheable groups code.
	 */
	if (inst->group.cacheable_name && inst->group.obj_membership_filter) {
		if (!inst->group.obj_name_attr) {
			cf_log_err(conf, "Configuration item 'group.name_attribute' must be set if cacheable "
				      "group names are enabled");

			return -1;
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
			return -1;
		}
	}

#ifndef WITH_SASL
	if (inst->handle_config.admin_sasl.mech) {
		cf_log_err(conf, "Configuration item 'sasl.mech' not supported.  "
			   "Linked libldap does not provide ldap_sasl_interactive_bind function");
		return -1;
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
				return -1;

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
		DEBUG4("rlm_ldap (%s) - LDAP server string: %s", mctx->mi->name, inst->handle_config.server);
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
			return -1;
		}
	}

	/*
	 *	Build the server side sort control for user / profile objects
	 */
#define SSS_CONTROL_BUILD(_obj) if (inst->_obj.obj_sort_by) { \
		LDAPSortKey	**keys; \
		int		ret; \
		ret = ldap_create_sort_keylist(&keys, UNCONST(char *, inst->_obj.obj_sort_by)); \
		if (ret != LDAP_SUCCESS) { \
			cf_log_err(conf, "Invalid " STRINGIFY(_obj) ".sort_by value \"%s\": %s", \
				      inst->_obj.obj_sort_by, ldap_err2string(ret)); \
			return -1; \
		} \
		/* \
		 *	Always set the control as critical, if it's not needed \
		 *	the user can comment it out... \
		 */ \
		ret = ldap_create_sort_control(ldap_global_handle, keys, 1, &inst->_obj.obj_sort_ctrl); \
		ldap_free_sort_keylist(keys); \
		if (ret != LDAP_SUCCESS) { \
			ERROR("Failed creating server sort control: %s", ldap_err2string(ret)); \
			return -1; \
		} \
	}

	SSS_CONTROL_BUILD(user)
	SSS_CONTROL_BUILD(profile)

	if (inst->handle_config.tls_require_cert_str) {
		/*
		 *	Convert cert strictness to enumerated constants
		 */
		inst->handle_config.tls_require_cert = fr_table_value_by_str(fr_ldap_tls_require_cert,
							      inst->handle_config.tls_require_cert_str, -1);
		if (inst->handle_config.tls_require_cert < 0) {
			cf_log_err(conf, "Invalid 'tls.require_cert' value \"%s\", expected 'never', "
				      "'demand', 'allow', 'try' or 'hard'", inst->handle_config.tls_require_cert_str);
			return -1;
		}
	}

	if (inst->handle_config.tls_min_version_str) {
#ifdef LDAP_OPT_X_TLS_PROTOCOL_TLS1_3
		if (strcmp(inst->handle_config.tls_min_version_str, "1.3") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_3;

		} else
#endif
		if (strcmp(inst->handle_config.tls_min_version_str, "1.2") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2;

		} else if (strcmp(inst->handle_config.tls_min_version_str, "1.1") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_1;

		} else if (strcmp(inst->handle_config.tls_min_version_str, "1.0") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_0;

		} else {
			cf_log_err(conf, "Invalid 'tls.tls_min_version' value \"%s\"", inst->handle_config.tls_min_version_str);
			return -1;
		}
	}

	if (inst->trunk_conf.conn_triggers) {
		MEM(inst->trigger_args = fr_pair_list_alloc(inst));
		if (module_trigger_args_build(inst->trigger_args, inst->trigger_args, cf_section_find(conf, "pool", NULL),
					      &(module_trigger_args_t) {
							.module = mctx->mi->module->name,
							.name = mctx->mi->name,
							.server = inst->handle_config.server,
							.port = inst->handle_config.port
					      }) < 0) return -1;
	}

	if (inst->bind_trunk_conf.conn_triggers) {
		MEM(inst->bind_trigger_args = fr_pair_list_alloc(inst));
		if (module_trigger_args_build(inst->bind_trigger_args, inst->bind_trigger_args, cf_section_find(conf, "bind_pool", NULL),
					      &(module_trigger_args_t) {
							.module = mctx->mi->module->name,
							.name = mctx->mi->name,
							.server = inst->handle_config.server,
							.port = inst->handle_config.port
					      }) < 0) return -1;
	}
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
	rlm_ldap_boot_t		*boot = talloc_get_type_abort(mctx->mi->boot, rlm_ldap_boot_t);
	rlm_ldap_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ldap_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	char			buffer[256];
	char const		*group_attribute;
	xlat_t			*xlat;

	if (inst->group.attribute) {
		group_attribute = inst->group.attribute;
	} else if (cf_section_name2(conf)) {
		snprintf(buffer, sizeof(buffer), "%s-LDAP-Group", mctx->mi->name);
		group_attribute = buffer;
	} else {
		group_attribute = "LDAP-Group";
	}

	boot->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);

	/*
	 *	If the group attribute was not in the dictionary, create it
	 */
	if (!boot->group_da) {
		if (fr_dict_attr_add_name_only(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
					       group_attribute, FR_TYPE_STRING, NULL) < 0) {
			PERROR("Error creating group attribute");
			return -1;

		}
		boot->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);
	}

	/*
	 *	Setup the cache attribute
	 */
	if (inst->group.cache_attr_str) {
		boot->cache_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->group.cache_attr_str);
		if (!boot->cache_da) {
			if (fr_dict_attr_add_name_only(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
						       inst->group.cache_attr_str, FR_TYPE_STRING, NULL) < 0) {
				PERROR("Error creating cache attribute");
				return -1;
			}
			boot->cache_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->group.cache_attr_str);
		}
	} else {
		boot->cache_da = boot->group_da;	/* Default to the group_da */
	}


	if (inst->user.dn_attr_str) {
		boot->user_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->user.dn_attr_str);
		if (!boot->user_da) {
			if (fr_dict_attr_add_name_only(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
						       inst->user.dn_attr_str, FR_TYPE_STRING, NULL) < 0) {
				PERROR("Error creating user DN cache attribute");
				return -1;
			}
			boot->user_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->user.dn_attr_str);
		}
	}

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, ldap_xlat, FR_TYPE_STRING);
	xlat_func_args_set(xlat, ldap_xlat_arg);

	if (unlikely(!(xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "group", ldap_group_xlat,
							FR_TYPE_BOOL)))) return -1;
	xlat_func_args_set(xlat, ldap_group_xlat_arg);
	xlat_func_call_env_set(xlat, &xlat_memberof_method_env);

	if (unlikely(!(xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "profile", ldap_profile_xlat,
							FR_TYPE_BOOL)))) return -1;
	xlat_func_args_set(xlat, ldap_xlat_arg);
	xlat_func_call_env_set(xlat, &xlat_profile_method_env);

	map_proc_register(mctx->mi->boot, inst, mctx->mi->name, mod_map_proc, ldap_map_verify, 0, LDAP_URI_SAFE_FOR);

	return 0;
}

static int mod_load(void)
{
	xlat_t	*xlat;

	if (unlikely(!(xlat = xlat_func_register(NULL, "ldap.uri.escape", ldap_uri_escape_xlat, FR_TYPE_STRING)))) return -1;
	xlat_func_args_set(xlat, ldap_uri_escape_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
	xlat_func_safe_for_set(xlat, LDAP_URI_SAFE_FOR);	/* Used for all LDAP escaping */

	if (unlikely(!(xlat = xlat_func_register(NULL, "ldap.uri.safe", xlat_transparent, FR_TYPE_STRING)))) return -1;
	xlat_func_args_set(xlat, ldap_safe_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
	xlat_func_safe_for_set(xlat, LDAP_URI_SAFE_FOR);

	if (unlikely(!(xlat = xlat_func_register(NULL, "ldap.uri.unescape", ldap_uri_unescape_xlat, FR_TYPE_STRING)))) return -1;
	xlat_func_args_set(xlat, ldap_uri_unescape_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);

	if (unlikely(!(xlat = xlat_func_register(NULL, "ldap.uri.attr_option", ldap_xlat_uri_attr_option, FR_TYPE_STRING)))) return -1;
	xlat_func_args_set(xlat, ldap_uri_attr_option_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("ldap.uri.escape");
	xlat_func_unregister("ldap.uri.safe");
	xlat_func_unregister("ldap.uri.unescape");
}

/* globally exported name */
extern module_rlm_t rlm_ldap;
module_rlm_t rlm_ldap = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "ldap",
		.flags			= 0,
		MODULE_BOOT(rlm_ldap_boot_t),
		MODULE_INST(rlm_ldap_t),
		.config			= module_config,
		.onload			= mod_load,
		.unload			= mod_unload,
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,
		MODULE_THREAD_INST(fr_ldap_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			/*
			 *	Hack to support old configurations
			 */
			{ .section = SECTION_NAME("accounting", CF_IDENT_ANY), .method = mod_modify, .method_env = &accounting_usermod_method_env },
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate, .method_env = &authenticate_method_env },
			{ .section = SECTION_NAME("authorize", CF_IDENT_ANY), .method = mod_authorize, .method_env = &authorize_method_env },

			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_authorize, .method_env = &authorize_method_env },
			{ .section = SECTION_NAME("send", CF_IDENT_ANY), .method = mod_modify, .method_env = &send_usermod_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
