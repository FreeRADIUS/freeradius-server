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
 * @author Matthew Newton <matthew@newtoncomputing.co.uk>
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Matthew Newton <matthew@newtoncomputing.co.uk>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_winbind.h"
#include "auth_wbclient_pap.h"
#include <grp.h>
#include <wbclient.h>

static const CONF_PARSER group_config[] = {
	{ FR_CONF_OFFSET("group_search_username", FR_TYPE_TMPL, rlm_winbind_t, group_username) },
	{ FR_CONF_OFFSET("group_add_domain", FR_TYPE_BOOL, rlm_winbind_t, group_add_domain), .dflt = "yes" },
	{ FR_CONF_OFFSET("group_attribute", FR_TYPE_STRING, rlm_winbind_t, group_attribute) },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("winbind_username", FR_TYPE_TMPL, rlm_winbind_t, wb_username) },
	{ FR_CONF_OFFSET("winbind_domain", FR_TYPE_TMPL, rlm_winbind_t, wb_domain) },
	{ FR_CONF_POINTER("group", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) group_config },
	CONF_PARSER_TERMINATOR
};

/** Group comparison for Winbind-Group
 *
 * @param instance	Instance of this module
 * @param request	The current request
 * @param attr		Attribute to look up in group
 * @param check		Value pair containing group to be searched
 * @param check_pairs	Unknown
 * @param reply_pairs	Unknown
 *
 * @return
 *	- 0 user is in group
 *	- 1 failure or user is not in group
 */
static int winbind_group_cmp(void *instance, REQUEST *request, VALUE_PAIR *attr, VALUE_PAIR *check,
			     UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_winbind_t		*inst = instance;
	rlm_rcode_t		rcode = 1;
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

	ssize_t			slen;
	size_t			backslash = 0;

	RINDENT();

	if (check->vp_length == 0) {
		REDEBUG("Group name is empty, nothing to check!");
		goto error;
	}

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
		user = attr->vp_strvalue;
	}

	if (domain) {
		username = username_buff = talloc_asprintf(request, "%s\\%s", domain, user);
	} else {
		username = user;
	}

	/*
	 *	Get a libwbclient connection from the pool
	 */
	wb_ctx = fr_connection_get(inst->wb_pool, request);
	if (wb_ctx == NULL) {
		RERROR("Unable to get winbind connection from the pool");
		goto error;
	}

	RDEBUG2("Trying to find user \"%s\" in group \"%s\"", username, check->vp_strvalue);

	err = wbcCtxGetGroups(wb_ctx, username, &num_groups, &wb_groups);
	switch (err) {
	case WBC_ERR_SUCCESS:
		rcode = 0;
		RDEBUG2("Successfully retrieved user's groups");
		break;

	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		RERROR("Failed retrieving groups: Unable to contact winbindd");	/* Global error */
		break;

	case WBC_ERR_DOMAIN_NOT_FOUND:
		/* Yeah, weird. libwbclient returns this if the username is unknown */
		REDEBUG("Failed retrieving groups: User or Domain not found");
		break;

	case WBC_ERR_UNKNOWN_USER:
		REDEBUG("Failed retrieving groups: User cannot be found");
		break;

	default:
		REDEBUG("Failed retrieving groups: %s", wbcErrorString(err));
		break;
	}

	if (!num_groups) RDEBUG("No groups returned");

	if (rcode) goto finish;
	rcode = 1;

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

		bool		found = false;

		/* Get the group name from the (fake winbind) gid */
		err = wbcCtxGetgrgid(wb_ctx, wb_groups[i], &group);
		if (err != WBC_ERR_SUCCESS) {
			REDEBUG("Failed resolving GID %i: %s", wb_groups[i], wbcErrorString(err));
			if (wb_groups[i] == UINT32_MAX) {
				REDEBUG("GID appears to be winbind placeholder value, idmap likely failed");
			}
			continue;
		}

		RDEBUG3("Resolved GID %i to name \"%s\"", wb_groups[i], group->gr_name);

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
		RDEBUG3("Checking plain group name \"%s\"", group_name);
		if (!strcasecmp(group_name, check->vp_strvalue)) {
			RDEBUG("Found matching group: %s", group_name);
			found = true;
			rcode = 0;
		}
		wbcFreeMemory(group);

		/* Short-circuit to save unnecessary enumeration */
		if (found) break;
	}

	if (rcode) RDEBUG2("No groups found that match");

finish:
	wbcFreeMemory(wb_groups);
	fr_connection_release(inst->wb_pool, request, wb_ctx);

error:
	talloc_free(user_buff);
	talloc_free(username_buff);
	talloc_const_free(domain);
	REXDENT();

	return rcode;
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
static void *mod_conn_create(TALLOC_CTX *ctx, UNUSED void *instance, UNUSED struct timeval const *timeout)
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


/** Bootstrap this module
 *
 * Register pair compare function for Winbind-Group fake attribute
 *
 * @param[in] conf	Module configuration
 * @param[in] instance	This module's instance
 *
 * @return
 *	- 0	success
 *	- -1	failure
 */
static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_winbind_t		*inst = instance;
	fr_dict_attr_t const	*user_name_da;
	char const		*group_attribute;
	char			buffer[256];

	user_name_da = fr_dict_attr_by_num(NULL, 0, FR_USER_NAME);
	if (!user_name_da) {
		ERROR("Unable to find User-Name attribute in dictionary");
		return -1;
	}

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (inst->group_attribute) {
		group_attribute = inst->group_attribute;
	} else if (cf_section_name2(conf)) {
		snprintf(buffer, sizeof(buffer), "%s-Winbind-Group", inst->name);
		group_attribute = buffer;
	} else {
		group_attribute = "Winbind-Group";
	}

	if (paircompare_register_byname(group_attribute, user_name_da, false,
					winbind_group_cmp, inst) < 0) {
		PERROR("Error registering group comparison");
		return -1;
	}

	return 0;
}


/** Instantiate this module
 *
 * @param[in] conf	Module configuration
 * @param[in] instance	This module's instance
 *
 * @return
 *	- 0	instantiation succeeded
 *	- -1	instantiation failed
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_winbind_t			*inst = instance;
	struct wbcInterfaceDetails	*wb_info = NULL;

	if (!inst->wb_username) {
		cf_log_err_cs(conf, "winbind_username must be defined to use rlm_winbind");
		return -1;
	}

	inst->wb_pool = module_connection_pool_init(conf, inst, mod_conn_create, NULL, NULL, NULL, NULL);
	if (!inst->wb_pool) {
		cf_log_err_cs(conf, "Unable to initialise winbind connection pool");
		return -1;
	}

	/*
	 *	If the domain has not been specified, try and find
	 *	out what it is from winbind.
	 */
	if (!inst->wb_domain) {
		wbcErr			err;
		struct wbcContext	*wb_ctx;

		cf_log_err_cs(conf, "winbind_domain unspecified; trying to get it from winbind");

		wb_ctx = wbcCtxCreate();
		if (!wb_ctx) {
			/* this should be very unusual */
			cf_log_err_cs(conf, "Unable to get libwbclient context, cannot get domain");
			goto no_domain;
		}

		err = wbcCtxInterfaceDetails(wb_ctx, &wb_info);
		wbcCtxFree(wb_ctx);

		if (err != WBC_ERR_SUCCESS) {
			cf_log_err_cs(conf, "libwbclient returned wbcErr code %d; unable to get domain name.", err);
			cf_log_err_cs(conf, "Is winbind running and does the winbind_privileged socket have");
			cf_log_err_cs(conf, "the correct permissions?");
			goto no_domain;
		}

		if (!wb_info->netbios_domain) {
			cf_log_err_cs(conf, "winbind returned blank domain name");
			goto no_domain;
		}

		tmpl_afrom_str(instance, &inst->wb_domain, wb_info->netbios_domain,
			       strlen(wb_info->netbios_domain), T_SINGLE_QUOTED_STRING,
			       REQUEST_CURRENT, PAIR_LIST_REQUEST, false);

		cf_log_err_cs(conf, "Using winbind_domain '%s'", inst->wb_domain->name);

no_domain:
		wbcFreeMemory(wb_info);
	}

	return 0;
}


/** Tidy up module instance
 *
 * Frees up the libwbclient connection pool.
 *
 * @param[in] instance This module's instance (unused)
 * @return 0
 */
static int mod_detach(UNUSED void *instance)
{
	rlm_winbind_t *inst = instance;

	fr_connection_pool_free(inst->wb_pool);
	return 0;
}


/** Authorize for libwbclient/winbind authentication
 *
 * Checks there is a password available so we can authenticate
 * against winbind and, if so, sets Auth-Type to ourself.
 *
 * @param[in] instance	Module instance.
 * @param[in] thread	Thread specific data.
 * @param[in] request	The current request.
 *
 * @return
 *	- #RLM_MODULE_NOOP unable to use winbind authentication
 *	- #RLM_MODULE_OK Auth-Type has been set to winbind
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	if (!request->password || (request->password->da->attr != FR_USER_PASSWORD)) {
		RDEBUG("No User-Password found in the request; not doing winbind authentication.");
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_num(request->control, 0, FR_AUTH_TYPE, TAG_ANY) != NULL) {
		RWDEBUG2("Auth-type already set, not setting to winbind");
		return RLM_MODULE_NOOP;
	}

	RDEBUG("Setting Auth-Type to winbind");
	pair_make_config("Auth-Type", "winbind", T_OP_EQ);

	return RLM_MODULE_OK;
}


/** Authenticate the user via libwbclient and winbind
 *
 * @param[in] instance	Module instance
 * @param[in] thread	Thread specific data.
 * @param[in] request	The current request
 *
 * @return One of the RLM_MODULE_* values
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_winbind_t const *inst = instance;

	/*
	 *	Check the admin hasn't been silly
	 */
	if (!request->password ||
	    (request->password->da->vendor != 0) ||
	    (request->password->da->attr != FR_USER_PASSWORD)) {
		REDEBUG("You set 'Auth-Type = winbind' for a request that does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (request->password->vp_length == 0) {
		REDEBUG("Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG3("Login attempt with password \"%s\" (%zd)", request->password->vp_strvalue,
			request->password->vp_length);
	} else {
		RDEBUG("Login attempt with password");
	}

	/*
	 *	Authenticate and return OK if successful. No need for
	 *	many debug outputs or errors as the auth function is
	 *	chatty enough.
	 */
	if (do_auth_wbclient_pap(inst, request) == 0) {
		RDEBUG("User authenticated successfully using winbind");
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_REJECT;
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
extern rad_module_t rlm_winbind;
rad_module_t rlm_winbind = {
	.magic		= RLM_MODULE_INIT,
	.name		= "winbind",
	.inst_size	= sizeof(rlm_winbind_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.bootstrap	= mod_bootstrap,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
