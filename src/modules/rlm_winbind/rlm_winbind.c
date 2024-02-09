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
 * @file rlm_winbind.c
 * @brief Authenticates against Active Directory or Samba using winbind
 *
 * @author Matthew Newton (matthew@newtoncomputing.co.uk)
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Matthew Newton (matthew@newtoncomputing.co.uk)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/util/debug.h>

#include "rlm_winbind.h"
#include "auth_wbclient_pap.h"
#include <grp.h>
#include <wbclient.h>

static const conf_parser_t group_config[] = {
	{ FR_CONF_OFFSET("search_username", rlm_winbind_t, group_username) },
	{ FR_CONF_OFFSET("add_domain", rlm_winbind_t, group_add_domain), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("domain", rlm_winbind_t, wb_domain) },
	{ FR_CONF_POINTER("group", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) group_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_winbind_dict[];
fr_dict_autoload_t rlm_winbind_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_expr_bool_enum;

extern fr_dict_attr_autoload_t rlm_winbind_dict_attr[];
fr_dict_attr_autoload_t rlm_winbind_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_expr_bool_enum, .name = "Expr-Bool-Enum", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ NULL }
};

typedef struct {
	tmpl_t	*password;
} winbind_autz_call_env_t;

/** Group comparison for Winbind-Group
 *
 * @param inst		Instance of this module
 * @param request	The current request
 * @param name		Group name to be searched
 *
 * @return
 *	- 0 user is in group
 *	- 1 failure or user is not in group
 */
static bool winbind_check_group(rlm_winbind_t const *inst, request_t *request, char const *name)
{
	bool			rcode = false;
	struct wbcContext	*wb_ctx;
	wbcErr			err;
	uint32_t		num_groups, i;
	gid_t			*wb_groups = NULL;

	char const		*domain = NULL;
	size_t			domain_len = 0;
	char const		*user = NULL;
	char			*user_buff = NULL;
	char const		*username;
	char			*username_buff = NULL;
	fr_pair_t		*vp_username;

	ssize_t			slen;
	size_t			backslash = 0;

	vp_username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	if (!vp_username) return false;

	RINDENT();

	/*
	 *	Work out what username to check groups for, made up from
	 *	either winbind_domain and either group_search_username or
	 *	just User-Name.
	 */

	/*
	 *	Include the domain in the username?
	 */
	if (inst->group_add_domain && inst->wb_domain) {
		slen = tmpl_aexpand(request, &domain, request, inst->wb_domain, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Unable to expand group_search_username");
			goto error;
		}
		domain_len = (size_t)slen;
	}

	/*
	 *	Sort out what User-Name we are going to use.
	 */
	if (inst->group_username) {
		slen = tmpl_aexpand(request, &user_buff, request, inst->group_username, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Unable to expand group_search_username");
			goto error;
		}
		user = user_buff;
	} else {
		/*
		 *	This is quite unlikely to work without a domain, but
		 *	we've not been given much else to work on.
		 */
		if (!domain) {
			RWDEBUG("Searching group with plain username, this will probably fail");
			RWDEBUG("Ensure winbind_domain and group_search_username are both correctly set");
		}
		user = vp_username->vp_strvalue;
	}

	if (domain) {
		username = username_buff = talloc_typed_asprintf(request, "%s\\%s", domain, user);
	} else {
		username = user;
	}

	/*
	 *	Get a libwbclient connection from the pool
	 */
	wb_ctx = fr_pool_connection_get(inst->wb_pool, request);
	if (wb_ctx == NULL) {
		RERROR("Unable to get winbind connection from the pool");
		goto error;
	}

	REDEBUG2("Trying to find user \"%s\" in group \"%s\"", username, name);

	err = wbcCtxGetGroups(wb_ctx, username, &num_groups, &wb_groups);
	switch (err) {
	case WBC_ERR_SUCCESS:
		if (!num_groups) {
			REDEBUG2("No groups returned");
			goto finish;
		}

		REDEBUG2("Successfully retrieved user's groups");
		break;

	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		RERROR("Failed retrieving groups: Unable to contact winbindd");	/* Global error */
		goto finish;

	case WBC_ERR_DOMAIN_NOT_FOUND:
		/* Yeah, weird. libwbclient returns this if the username is unknown */
		REDEBUG("Failed retrieving groups: User or Domain not found");
		goto finish;

	case WBC_ERR_UNKNOWN_USER:
		REDEBUG("Failed retrieving groups: User cannot be found");
		goto finish;

	default:
		REDEBUG("Failed retrieving groups: %s", wbcErrorString(err));
		goto finish;
	}

	/*
	 *	See if any of the groups match
	 */

	/*
	 *	We try and find where the '\' is in the returned group, which saves
	 *	looking for it each time. There seems to be no way to get a list of
	 *	groups without the domain in them, but at least the backslash is
	 * 	always going to be in the same place.
	 *
	 *	Maybe there should be an option to include the domain in the compared
	 *	group name in case people have multiple domains?
	 */
	if (domain_len > 0) backslash = domain_len - 1;

	for (i = 0; i < num_groups; i++) {
		struct group	*group;
		char		*group_name;

		/* Get the group name from the (fake winbind) gid */
		err = wbcCtxGetgrgid(wb_ctx, wb_groups[i], &group);
		if (err != WBC_ERR_SUCCESS) {
			REDEBUG("Failed resolving GID %i: %s", wb_groups[i], wbcErrorString(err));
			if (wb_groups[i] == UINT32_MAX) {
				REDEBUG("GID appears to be winbind placeholder value, idmap likely failed");
			}
			continue;
		}

		REDEBUG2("Resolved GID %i to name \"%s\"", wb_groups[i], group->gr_name);

		/* Find the backslash in the returned group name */
		if ((backslash < strlen(group->gr_name)) && (group->gr_name[backslash] == '\\')) {
			group_name = group->gr_name + backslash + 1;
		} else if ((group_name = strchr(group->gr_name, '\\'))) {
			group_name++;
			backslash = group_name - (group->gr_name - 1);
		} else {
			group_name = group->gr_name;
		}

		/* See if the group matches */
		REDEBUG2("Checking plain group name \"%s\"", group_name);
		if (!strcasecmp(group_name, name)) {
			REDEBUG2("Found matching group: %s", group_name);
			rcode = true;
		}
		wbcFreeMemory(group);

		/* Short-circuit to save unnecessary enumeration */
		if (rcode) break;
	}

	if (!rcode) REDEBUG2("No groups found that match");

finish:
	wbcFreeMemory(wb_groups);
	fr_pool_connection_release(inst->wb_pool, request, wb_ctx);

error:
	talloc_free(user_buff);
	talloc_free(username_buff);
	talloc_const_free(domain);
	REXDENT();

	return rcode;
}


/** Check if the user is a member of a particular winbind group
 *
@verbatim
%winbind.group(<name>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t winbind_group_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	rlm_winbind_t const	*inst = talloc_get_type_abort(xctx->mctx->inst->data, rlm_winbind_t);
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	char const		*p = arg->vb_strvalue;
	fr_value_box_t		*vb;

	fr_skip_whitespace(p);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
	vb->vb_bool = winbind_check_group(inst, request, p);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Free connection pool winbind context
 *
 * @param[in] wb_ctx libwbclient context
 * @return 0
 */
static int _mod_conn_free(struct wbcContext **wb_ctx)
{
	wbcCtxFree(*wb_ctx);

	return 0;
}


/** Create connection pool winbind context
 *
 * @param[in] ctx	talloc context
 * @param[in] instance	Module instance (unused)
 * @param[in] timeout	Connection timeout
 *
 * @return pointer to libwbclient context
 */
static void *mod_conn_create(TALLOC_CTX *ctx, UNUSED void *instance, UNUSED fr_time_delta_t timeout)
{
	struct wbcContext **wb_ctx;

	wb_ctx = talloc_zero(ctx, struct wbcContext *);
	*wb_ctx = wbcCtxCreate();

	if (*wb_ctx == NULL) {
		PERROR("failed to create winbind context");
		talloc_free(wb_ctx);
		return NULL;
	}

	talloc_set_destructor(wb_ctx, _mod_conn_free);

	return *wb_ctx;
}


static xlat_arg_parser_t const winbind_group_xlat_arg[] = {
	{ .required = true, .type = FR_TYPE_STRING, .concat = true },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Bootstrap this module
 *
 * Register pair compare function for Winbind-Group fake attribute
 *
 * @param[in] mctx	data for this module
 *
 * @return
 *	- 0	success
 *	- -1	failure
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_winbind_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_winbind_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	xlat_t			*xlat;

	/*
	 *	Define the %winbind.group(name) xlat.  The register
	 *	function automatically adds the module instance name
	 *	as a prefix.
	 */
	xlat = xlat_func_register_module(inst, mctx, "group", winbind_group_xlat, FR_TYPE_BOOL);
	if (!xlat) {
		cf_log_err(conf, "Failed registering group expansion");
		return -1;
	}

	xlat_func_mono_set(xlat, winbind_group_xlat_arg);

	return 0;
}


/** Instantiate this module
 *
 * @param[in] mctx	data for this module
 *
 * @return
 *	- 0	instantiation succeeded
 *	- -1	instantiation failed
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_winbind_t			*inst = talloc_get_type_abort(mctx->inst->data, rlm_winbind_t);
	CONF_SECTION			*conf = mctx->inst->conf;

	inst->wb_pool = module_rlm_connection_pool_init(conf, inst, mod_conn_create, NULL, NULL, NULL, NULL);
	if (!inst->wb_pool) {
		cf_log_err(conf, "Unable to initialise winbind connection pool");
		return -1;
	}

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, mctx->inst->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  Winbind authentication will likely not work",
		     mctx->inst->name);
	}

	return 0;
}


/** Tidy up module instance
 *
 * Frees up the libwbclient connection pool.
 *
 * @param[in] mctx	data for this module
 * @return 0
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_winbind_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_winbind_t);

	fr_pool_free(inst->wb_pool);

	return 0;
}


/** Authorize for libwbclient/winbind authentication
 *
 * Checks there is a password available so we can authenticate
 * against winbind and, if so, sets Auth-Type to ourself.
 *
 * @param[out] p_result		The result of the module call:
 *				- #RLM_MODULE_NOOP unable to use winbind authentication
 *				- #RLM_MODULE_OK Auth-Type has been set to winbind
 * @param[in] mctx		Module instance data.
 * @param[in] request		The current request.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_winbind_t const	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_winbind_t);
	winbind_autz_call_env_t	*env = talloc_get_type_abort(mctx->env_data, winbind_autz_call_env_t);
	fr_pair_t		*vp;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, tmpl_attr_tail_da(env->password));
	if (!vp) {
		REDEBUG2("No %s found in the request; not doing winbind authentication.",
			 tmpl_attr_tail_da(env->password)->name);
		RETURN_MODULE_NOOP;
	}

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup Winbind authentication",
		     mctx->inst->name, mctx->inst->name);
		RETURN_MODULE_NOOP;
	}

	if (!module_rlm_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_MODULE_NOOP;

	RETURN_MODULE_OK;
}


/** Authenticate the user via libwbclient and winbind
 *
 * @param[out] p_result		The result of the module call.
 * @param[in] mctx		Module instance data.
 * @param[in] request		The current request
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_winbind_t const	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_winbind_t);
	winbind_auth_call_env_t	*env = talloc_get_type_abort(mctx->env_data, winbind_auth_call_env_t);

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (env->password.vb_length == 0) {
		REDEBUG("User-Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &env->password);
	} else {
		RDEBUG2("Login attempt with password");
	}

	/*
	 *	Authenticate and return OK if successful. No need for
	 *	many debug outputs or errors as the auth function is
	 *	chatty enough.
	 */
	if (do_auth_wbclient_pap(inst, request, env) == 0) {
		REDEBUG2("User authenticated successfully using winbind");
		RETURN_MODULE_OK;
	}

	RETURN_MODULE_REJECT;
}

static const call_env_method_t winbind_autz_method_env = {
	FR_CALL_ENV_METHOD_OUT(winbind_autz_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("password", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_PARSE_ONLY, winbind_autz_call_env_t, password),
			.pair.dflt = "&User-Password", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

static int domain_call_env_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
				 UNUSED void const *data, UNUSED call_env_parser_t const *rule)
{
	CONF_PAIR const			*to_parse = cf_item_to_pair(ci);
	tmpl_t				*parsed_tmpl = NULL;
	struct wbcInterfaceDetails	*wb_info = NULL;

	if (strlen(cf_pair_value(to_parse)) > 0) {
		if (tmpl_afrom_substr(ctx, &parsed_tmpl,
				      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
				      cf_pair_value_quote(to_parse), NULL, t_rules) < 0) return -1;
	} else {
		/*
		 *	If the domain has not been specified, try and find
		 *	out what it is from winbind.
		 */
		wbcErr			err;
		struct wbcContext	*wb_ctx;

		cf_log_warn(ci, "winbind domain unspecified; trying to get it from winbind");

		wb_ctx = wbcCtxCreate();
		if (!wb_ctx) {
			/* this should be very unusual */
			cf_log_err(ci, "Unable to get libwbclient context, cannot get domain");
			goto no_domain;
		}

		err = wbcCtxInterfaceDetails(wb_ctx, &wb_info);
		wbcCtxFree(wb_ctx);

		if (err != WBC_ERR_SUCCESS) {
			cf_log_err(ci, "libwbclient returned wbcErr code %d; unable to get domain name.", err);
			cf_log_err(ci, "Is winbind running and does the winbind_privileged socket have");
			cf_log_err(ci, "the correct permissions?");
			goto no_domain;
		}

		if (!wb_info->netbios_domain) {
			cf_log_err(ci, "winbind returned blank domain name");
			goto no_domain;
		}

		tmpl_afrom_substr(ctx, &parsed_tmpl,
			          &FR_SBUFF_IN(wb_info->netbios_domain, strlen(wb_info->netbios_domain)),
			          T_SINGLE_QUOTED_STRING, NULL, t_rules);
		if (!parsed_tmpl) {
			cf_log_perr(ci, "Bad domain");
			wbcFreeMemory(wb_info);
			return -1;
		}

		cf_log_info(ci, "Using winbind_domain '%s'", parsed_tmpl->name);

	no_domain:
		wbcFreeMemory(wb_info);
	}

	*(void **)out = parsed_tmpl;
	return parsed_tmpl ? 0 : -1;
}

static const call_env_method_t winbind_auth_method_env = {
	FR_CALL_ENV_METHOD_OUT(winbind_auth_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED, winbind_auth_call_env_t, username) },
		{ FR_CALL_ENV_OFFSET("domain", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, winbind_auth_call_env_t, domain),
			.pair.dflt = "", .pair.dflt_quote = T_SINGLE_QUOTED_STRING, .pair.func = domain_call_env_parse },
		{ FR_CALL_ENV_OFFSET("password", FR_TYPE_STRING, CALL_ENV_FLAG_SECRET, winbind_auth_call_env_t, password),
			.pair.dflt = "&User-Password", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_winbind;
module_rlm_t rlm_winbind = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "winbind",
		.inst_size	= sizeof(rlm_winbind_t),
		.config		= module_config,
		.instantiate	= mod_instantiate,
		.bootstrap	= mod_bootstrap,
		.detach		= mod_detach
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,
		  .method_env = &winbind_autz_method_env },
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate,
		  .method_env = &winbind_auth_method_env },
		MODULE_NAME_TERMINATOR
	}
};
