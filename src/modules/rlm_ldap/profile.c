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

#include "rlm_ldap.h"
#include <freeradius-devel/ldap/conf.h>

#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module_rlm.h>

/** Holds state of in progress async profile lookups
 *
 */
typedef struct {
	fr_ldap_result_code_t	*ret;			//!< Result of the query and applying the map.
	fr_ldap_query_t		*query;
	char const		*dn;
	rlm_ldap_t const	*inst;
	fr_ldap_map_exp_t	const *expanded;
} ldap_profile_ctx_t;

/** Process the results of a profile lookup
 *
 */
static unlang_action_t ldap_map_profile_resume(UNUSED rlm_rcode_t *p_result, UNUSED int *priority, request_t *request,
					       void *uctx)
{
	ldap_profile_ctx_t	*profile_ctx = talloc_get_type_abort(uctx, ldap_profile_ctx_t);
	fr_ldap_query_t		*query = profile_ctx->query;
	LDAP			*handle;
	LDAPMessage		*entry = NULL;
	int			ldap_errno;
	char			*dn = NULL;

	/*
	 *	Tell the caller what happened
	 */
	if (profile_ctx->ret) *profile_ctx->ret = query->ret;

	switch (query->ret) {
	case LDAP_RESULT_SUCCESS:
		break;

	case LDAP_RESULT_NO_RESULT:
	case LDAP_RESULT_BAD_DN:
		RDEBUG2("Profile object \"%s\" not found", profile_ctx->dn);
		goto finish;

	default:
		goto finish;
	}

	fr_assert(query->result);
	handle = query->ldap_conn->handle;

	entry = ldap_first_entry(handle, query->result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));
		if (profile_ctx->ret) *profile_ctx->ret = LDAP_RESULT_NO_RESULT;
		goto finish;
	}

	RDEBUG2("Processing profile attributes");
	RINDENT();
	while (entry) {
		if (RDEBUG_ENABLED2) {
			dn = ldap_get_dn(handle, entry);
			RDEBUG2("Processing \"%s\"", dn);
			ldap_memfree(dn);
		}
		RINDENT();
		if (fr_ldap_map_do(request, profile_ctx->inst->profile_check_attr, profile_ctx->inst->valuepair_attr,
				   profile_ctx->expanded, entry) < 0) {
			if (profile_ctx->ret) *profile_ctx->ret = LDAP_RESULT_ERROR;
		}
		entry = ldap_next_entry(handle, entry);
		REXDENT();
	}
	REXDENT();

finish:
	talloc_free(profile_ctx);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Cancel an in progress profile lookup
 *
 */
static void ldap_map_profile_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_profile_ctx_t	*profile_ctx = talloc_get_type_abort(uctx, ldap_profile_ctx_t);

	if (!profile_ctx->query || !profile_ctx->query->treq) return;

	trunk_request_signal_cancel(profile_ctx->query->treq);
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common
 * sets of attributes to the request.
 *
 * @param[out] ret		Where to write the result of the query.
 * @param[in] inst		LDAP module instance.
 * @param[in] request		Current request.
 * @param[in] ttrunk		Trunk connection on which to run LDAP queries.
 * @param[in] dn		of profile object to apply.
 * @param[in] scope		to apply when looking up profiles.
 * @param[in] filter		to apply when looking up profiles.
 * @param[in] expanded		Structure containing a list of xlat
 *				expanded attribute names and mapping information.
 * @return One of the RLM_MODULE_* values.
 */
unlang_action_t rlm_ldap_map_profile(fr_ldap_result_code_t *ret,
				     rlm_ldap_t const *inst, request_t *request, fr_ldap_thread_trunk_t *ttrunk,
				     char const *dn, int scope, char const *filter, fr_ldap_map_exp_t const *expanded)
{
	ldap_profile_ctx_t	*profile_ctx;
	LDAPControl		*serverctrls[] = { inst->profile_sort_ctrl, NULL };

	if (!dn || !*dn) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(profile_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_profile_ctx_t));
	*profile_ctx = (ldap_profile_ctx_t) {
		.ret = ret,
		.dn = dn,
		.expanded = expanded,
		.inst = inst
	};
	if (ret) *ret = LDAP_RESULT_ERROR;

	if (unlang_function_push(request, NULL, ldap_map_profile_resume, ldap_map_profile_cancel,
				 ~FR_SIGNAL_CANCEL, UNLANG_SUB_FRAME, profile_ctx) < 0) {
		talloc_free(profile_ctx);
		return UNLANG_ACTION_FAIL;
	}

	return fr_ldap_trunk_search(profile_ctx, &profile_ctx->query, request, ttrunk, dn,
				    scope, filter,
				    expanded->attrs, serverctrls, NULL);
}
