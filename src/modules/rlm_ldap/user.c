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
 * @file groups.c
 * @brief LDAP module group functions.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2013 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>

#define LOG_PREFIX mctx->mi->name

#include "rlm_ldap.h"

/** Holds state of user searches in progress
 *
 */
typedef struct {
	rlm_ldap_t const	*inst;
	fr_ldap_thread_trunk_t	*ttrunk;
	char const		*base_dn;
	char const		*filter;
	char const * const	*attrs;
	fr_ldap_query_t		*query;
	fr_ldap_query_t		**out;
} ldap_user_find_ctx_t;

/** Process the results of an async user lookup
 *
 */
static unlang_action_t ldap_find_user_async_result(unlang_result_t *p_result, request_t *request, void *uctx)
{
	ldap_user_find_ctx_t	*user_ctx = talloc_get_type_abort(uctx, ldap_user_find_ctx_t);
	fr_ldap_query_t		*query = user_ctx->query;
	LDAPMessage		*entry;
	int			cnt, ldap_errno;
	char			*dn;
	fr_pair_t		*vp;

	if (!query) RETURN_UNLANG_FAIL;

	/*
	 *	Make the result available to the query
	 */
	if (user_ctx->out) *user_ctx->out = user_ctx->query;

	switch (query->ret) {
	case LDAP_RESULT_SUCCESS:
		break;

	case LDAP_RESULT_NO_RESULT:
	/*
	 *	DNs can now be dynamic, so a BAD DN often means the same thing as an empty result
	 */
	case LDAP_RESULT_BAD_DN:
		RETURN_UNLANG_NOTFOUND;

	default:
		RETURN_UNLANG_FAIL;
	}

	cnt = ldap_count_entries(query->ldap_conn->handle, query->result);

	if ((!user_ctx->inst->user.obj_sort_ctrl) && (cnt > 1)) {
		REDEBUG("Ambiguous search result, returned %i unsorted entries (should return 1 or 0).  "
			"Enable sorting, or specify a more restrictive base_dn, filter or scope", cnt);
		REDEBUG("The following entries were returned:");
		RINDENT();
		for (entry = ldap_first_entry(query->ldap_conn->handle, query->result);
		     entry;
		     entry = ldap_next_entry(query->ldap_conn->handle, entry)) {
			dn = ldap_get_dn(query->ldap_conn->handle, entry);
			REDEBUG("%s", dn);
			ldap_memfree(dn);
		}
		REXDENT();
		RETURN_UNLANG_INVALID;
	}

	entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	if (!entry) {
		ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s",
			ldap_err2string(ldap_errno));

		RETURN_UNLANG_FAIL;
	}

	dn = ldap_get_dn(query->ldap_conn->handle, entry);
	if (!dn) {
		ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

		RETURN_UNLANG_FAIL;
	}
	fr_ldap_util_normalise_dn(dn, dn);

	RDEBUG2("User object found at DN \"%s\"", dn);

	MEM(pair_update_control(&vp, user_ctx->inst->user.da) >= 0);
	fr_pair_value_strdup(vp, dn, false);
	ldap_memfree(dn);

	RETURN_UNLANG_OK;
}

/** Cancel a user search
 */
static void ldap_find_user_async_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_user_find_ctx_t	*user_ctx = talloc_get_type_abort(uctx, ldap_user_find_ctx_t);

	/*
	 *	If the query is not in flight, just return
	 */
	if (!user_ctx->query || !user_ctx->query->treq) return;

	trunk_request_signal_cancel(user_ctx->query->treq);
}

/** Initiate asynchronous retrieval of the DN of a user object
 *
 * Retrieves the DN of a user and adds it to the control list as LDAP-UserDN.
 * Will also retrieve any attributes passed.
 *
 * This potentially allows for all authorization and authentication checks to be performed in one
 * ldap search operation, which is a big bonus given the number of crappy, slow *cough*AD*cough*
 * LDAP directory servers out there.
 *
 * @param[in] ctx	in which to allocate the query.
 * @param[in] p_result	Where rcode from running the query will be written.
 * @param[in] inst	rlm_ldap configuration.
 * @param[in] request	Current request.
 * @param[in] base	DN to search in.
 * @param[in] filter	to use in LDAP search.
 * @param[in] ttrunk	LDAP thread trunk to use.
 * @param[in] attrs	Additional attributes to retrieve, may be NULL.
 * @param[in] query_out	Where to put a pointer to the LDAP query structure -
 *			for extracting extra returned attributes, may be NULL.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t rlm_ldap_find_user_async(TALLOC_CTX *ctx,
					 unlang_result_t *p_result,
					 rlm_ldap_t const *inst, request_t *request,
					 fr_value_box_t *base, fr_value_box_t *filter,
					 fr_ldap_thread_trunk_t *ttrunk, char const *attrs[], fr_ldap_query_t **query_out)
{
	static char const	*tmp_attrs[] = { NULL };
	ldap_user_find_ctx_t	*user_ctx;
	LDAPControl		*serverctrls[] = { inst->user.obj_sort_ctrl, NULL };

	if (!attrs) memset(&attrs, 0, sizeof(tmp_attrs));

	user_ctx = talloc_zero(ctx, ldap_user_find_ctx_t);
	*user_ctx = (ldap_user_find_ctx_t) {
		.inst = inst,
		.ttrunk = ttrunk,
		.base_dn = base->vb_strvalue,
		.attrs = attrs,
		.out = query_out
	};

	if (filter) user_ctx->filter = filter->vb_strvalue;
	if (unlang_function_push_with_result(/* ldap_find_user_async_result sets an rcode based on the search result */ p_result,
					     request,
					     NULL,
					     ldap_find_user_async_result,
					     ldap_find_user_async_cancel, ~FR_SIGNAL_CANCEL,
					     UNLANG_SUB_FRAME, user_ctx) < 0) {
		talloc_free(user_ctx);
		return UNLANG_ACTION_FAIL;
	}

	return fr_ldap_trunk_search(user_ctx, &user_ctx->query, request, user_ctx->ttrunk,
				    user_ctx->base_dn, user_ctx->inst->user.obj_scope, user_ctx->filter,
				    user_ctx->attrs, serverctrls, NULL);
}

/** Check for presence of access attribute in result
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in] entry retrieved by rlm_ldap_find_user or fr_ldap_search.
 * @return
 *	- #RLM_MODULE_DISALLOW if the user was denied access.
 *	- #RLM_MODULE_OK otherwise.
 */
ldap_access_state_t rlm_ldap_check_access(rlm_ldap_t const *inst, request_t *request, LDAPMessage *entry)
{
	ldap_access_state_t ret = LDAP_ACCESS_ALLOWED;
	struct berval **values = NULL;

	values = ldap_get_values_len(fr_ldap_handle_thread_local(), entry, inst->user.obj_access_attr);
	if (values) {
		size_t negate_value_len = talloc_array_length(inst->user.access_value_negate) - 1;
		if (inst->user.access_positive) {
			if ((values[0]->bv_len >= negate_value_len) &&
			    (strncasecmp(values[0]->bv_val, inst->user.access_value_negate, negate_value_len) == 0)) {
				REDEBUG("\"%s\" attribute exists but is set to '%s' - user locked out",
				        inst->user.obj_access_attr, inst->user.access_value_negate);
				ret = LDAP_ACCESS_DISALLOWED;
				goto done;
			}
			/* RLM_MODULE_OK set above... */
		} else if ((values[0]->bv_len < negate_value_len) ||
		           (strncasecmp(values[0]->bv_val, inst->user.access_value_negate, negate_value_len) != 0)) {
			REDEBUG("\"%s\" attribute exists - user locked out", inst->user.obj_access_attr);
			ret = LDAP_ACCESS_DISALLOWED;
			goto done;
		}
		{
			size_t suspend_value_len = talloc_array_length(inst->user.access_value_suspend) - 1;
			if ((values[0]->bv_len == suspend_value_len) &&
			    (strncasecmp(values[0]->bv_val, inst->user.access_value_suspend, suspend_value_len) == 0)) {
				RIDEBUG("\"%s\" attribute exists and indicates suspension", inst->user.obj_access_attr);
				ret = LDAP_ACCESS_SUSPENDED;
				goto done;
			}
		}
	done:
		ldap_value_free_len(values);
	} else if (inst->user.access_positive) {
		REDEBUG("No \"%s\" attribute - user locked out", inst->user.obj_access_attr);
		ret = LDAP_ACCESS_DISALLOWED;
	}

	return ret;
}

/** Verify we got a password from the search
 *
 * Checks to see if after the LDAP to RADIUS mapping has been completed that a reference password.
 *
 * @param[in] request		Current request.
 * @param[in] inst		Current LDAP instance.
 * @param[in] inst_name		Name of LDAP module instance for debug messages.
 * @param[in] expect_password	Whether we should be expecting a password.
 * @param[in] ttrunk		the connection thread trunk.
 */
void rlm_ldap_check_reply(request_t *request, rlm_ldap_t const *inst, char const *inst_name, bool expect_password, fr_ldap_thread_trunk_t const *ttrunk)
{
	fr_pair_t 		*parent;

       /*
	*	More warning messages for people who can't be bothered to read the documentation.
	*
	*	Expect_password is set when we process the mapping, and is only true if there was a mapping between
	*	an LDAP attribute and a password reference attribute in the control list.
	*/
	if ((inst->user.expect_password_is_set && !inst->user.expect_password) || !expect_password || !RDEBUG_ENABLED2) return;

	parent = fr_pair_find_by_da(&request->control_pairs, NULL, attr_password);
	if (!parent) goto warnings;

	if (!fr_pair_find_by_da(&parent->vp_group, NULL, attr_cleartext_password) &&
	    !fr_pair_find_by_da(&parent->vp_group, NULL, attr_nt_password) &&
	    !fr_pair_find_by_da(&parent->vp_group, NULL, attr_password_with_header) &&
	    !fr_pair_find_by_da(&parent->vp_group, NULL, attr_crypt_password)) {
	warnings:
		switch (ttrunk->directory->type) {
		case FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY:
		case FR_LDAP_DIRECTORY_SAMBA:
			RWDEBUG2("!!! Found map between LDAP attribute and a FreeRADIUS password attribute");
			RWDEBUG2("!!! %s does not allow passwords to be read via LDAP",
				(ttrunk->directory->type == FR_LDAP_DIRECTORY_SAMBA ? "Samba" : "Active Directory"));
			RWDEBUG2("!!! Remove the password map and either:");
			RWDEBUG2("!!!  - Configure authentication via ntlm_auth (mschapv2 only)");
			RWDEBUG2("!!!  - Configure authentication via wbclient (mschapv2 only)");
			RWDEBUG2("!!!  - Bind as the user by listing %s in an 'authenticate %s' section, and",
				 inst_name, inst_name);
			RWDEBUG2("!!!	setting attribute control.Auth-Type := '%s' in the 'recv Access-Request' section",
				 inst_name);
			RWDEBUG2("!!!    (pap only)");

			break;

		case FR_LDAP_DIRECTORY_EDIRECTORY:
			RWDEBUG2("!!! Found map between LDAP attribute and a FreeRADIUS password attribute");
			RWDEBUG2("!!! eDirectory does not allow passwords to be retrieved via LDAP search");
			RWDEBUG2("!!! Remove the password map and either:");
			RWDEBUG2("!!!  - Set 'edir = yes' and enable the universal password feature on your");
			RWDEBUG2("!!!    eDir server (recommended)");
			RWDEBUG2("!!!  - Bind as the user by listing %s in an 'authenticate %s' section, and",
				 inst_name, inst_name);
			RWDEBUG2("!!!	setting attribute control.Auth-Type := '%s' in the 'recv Access-Request' section",
				 inst_name);
			RWDEBUG("!!!    (pap only)");
			break;

		default:
			RWDEBUG2("!!! Found map between LDAP attribute and a FreeRADIUS password attribute");
			RWDEBUG2("!!! but no password attribute found in search result");
			RWDEBUG2("!!! Either:");
			RWDEBUG2("!!!  - Ensure the user object contains a password attribute, and that");
			RWDEBUG2("!!!    %c%s%c has permission to read that password attribute (recommended)",
				 ttrunk->config.admin_identity ? '"' : '\0',
				 ttrunk->config.admin_identity ? ttrunk->config.admin_identity : "the bind user",
				 ttrunk->config.admin_identity ? '"' : '\0');
			RWDEBUG2("!!!  - Bind as the user by listing %s in an 'authenticate %s' section, and",
				 inst_name, inst_name);
			RWDEBUG2("!!!    setting attribute control.Auth-Type := '%s' in the 'recv Access-Request' section",
				 inst_name);
			RWDEBUG2("!!!    (pap only)");
			break;
		}
	}
}
