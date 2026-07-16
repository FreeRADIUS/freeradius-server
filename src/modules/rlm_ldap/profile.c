/*
 *   This program is free software; you can redistribute it and/or modify
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
	int			*applied;		//!< Number of profiles applied.
	fr_ldap_query_t		*query;
	char const		*dn;			//!< DN of the profile object being retrieved.
							///< NULL when all profiles are retrieved by one search.
	rlm_ldap_t const	*inst;
	fr_ldap_map_exp_t	const *expanded;
	fr_ldap_thread_trunk_t	*ttrunk;		//!< Trunk used for profile searches.
	char const		*filter;		//!< Filter to apply to profile searches.
	char const * const	*next;			//!< Next profile DN to search for (search_mode = seq).
} ldap_profile_ctx_t;

/** Apply the attribute map to a single profile entry
 *
 * @param[out] fallthrough	Whether processing should continue to the next profile entry.
 * @param[in] request		Current request.
 * @param[in] profile_ctx	Profile lookup state.
 * @param[in] handle		libldap handle the result was received on.
 * @param[in] entry		Profile object to apply.
 */
static void ldap_profile_entry_map(bool *fallthrough, request_t *request, ldap_profile_ctx_t *profile_ctx,
				   LDAP *handle, LDAPMessage *entry)
{
	int	ret;

	// Set fallthrough to the configured default
	*fallthrough = profile_ctx->inst->profile.fallthrough_def;

	ret = fr_ldap_map_do(request, profile_ctx->inst->profile.check_attr, profile_ctx->inst->valuepair_attr,
			   profile_ctx->expanded, entry);
	if (ret < 0) {
		if (profile_ctx->ret) *profile_ctx->ret = LDAP_RESULT_ERROR;
	} else {
		if (profile_ctx->applied) *profile_ctx->applied += ret;
	}

	if (profile_ctx->inst->profile.fallthrough_attr) {
		struct berval		**values;
		int			count;
		char			*value;
		xlat_exp_head_t		*cond_expr = NULL;
		fr_value_box_list_t	res;

		tmpl_rules_t const parse_rules = {
			.attr = {
				.dict_def = request->local_dict,
				.list_def = request_attr_request,
			},
			.xlat = {
				.runtime_el = unlang_interpret_event_list(request),
			},
			.at_runtime = true,
		};

		values = ldap_get_values_len(handle, entry, profile_ctx->inst->profile.fallthrough_attr);
		count = ldap_count_values_len(values);
		if (count == 0) goto free_values;
		if (count > 1) {
			RWARN("%s returned more than 1 value.  Only evaluating the first.",
			      profile_ctx->inst->profile.fallthrough_attr);
		}
		value = fr_ldap_berval_to_string(request, values[0]);

		RDEBUG3("Parsing fallthrough condition %s", value);
		if (xlat_tokenize_expression(request, &cond_expr,
					     &FR_SBUFF_IN(value, talloc_strlen(value)),
					     NULL, &parse_rules) < 0) {
			RPEDEBUG("Failed parsing '%s' value \"%s\"", profile_ctx->inst->profile.fallthrough_attr, value);
			goto free;
		}

		if (xlat_impure_func(cond_expr)) {
			fr_strerror_const("Fallthrough expression cannot depend on functions which call external databases");
			goto free;
		}

		RDEBUG2("Checking fallthrough condition %s", value);
		fr_value_box_list_init(&res);
		if (unlang_xlat_eval(request, &res, request, cond_expr) < 0) {
			RPEDEBUG("Failed evaluating condition");
			goto free;
		}
		*fallthrough = (fr_value_box_list_head(&res) && fr_value_box_is_truthy(fr_value_box_list_head(&res))) ? true : false;
		fr_value_box_list_talloc_free(&res);
		RDEBUG2("Fallthrough condition evaluated to %s", *fallthrough ? "true" : "false");
	free:
		talloc_free(value);
		talloc_free(cond_expr);
	free_values:
		ldap_value_free_len(values);
	}
}

/** Process the results of a profile lookup
 *
 */
static unlang_action_t ldap_map_profile_resume(request_t *request, void *uctx)
{
	ldap_profile_ctx_t	*profile_ctx = talloc_get_type_abort(uctx, ldap_profile_ctx_t);
	fr_ldap_query_t		*query = profile_ctx->query;
	LDAP			*handle;
	LDAPMessage		*entry;
	int			ldap_errno;
	char			*dn = NULL;
	bool			fallthrough = true;

	/*
	 *	Tell the caller what happened
	 */
	if (profile_ctx->ret) *profile_ctx->ret = query->ret;

	switch (query->ret) {
	case LDAP_RESULT_SUCCESS:
		break;

	case LDAP_RESULT_NO_RESULT:
	case LDAP_RESULT_BAD_DN:
		if (profile_ctx->dn) {
			RDEBUG2("Profile object \"%s\" not found", profile_ctx->dn);
		} else {
			RDEBUG2("No profile objects found");
		}
		goto next;

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
		ldap_profile_entry_map(&fallthrough, request, profile_ctx, handle, entry);
		REXDENT();
		if (!fallthrough) break;

		entry = ldap_next_entry(handle, entry);
	}
	REXDENT();

	if (!fallthrough) goto finish;

next:
	/*
	 *	Chain the search for the next profile (search_mode = seq)
	 */
	while (profile_ctx->next && *profile_ctx->next) {
		LDAPControl	*serverctrls[] = { profile_ctx->inst->profile.obj_sort_ctrl, NULL };

		TALLOC_FREE(profile_ctx->query);

		profile_ctx->dn = *profile_ctx->next++;

		if (unlang_function_repeat_set(request, ldap_map_profile_resume) < 0) {
			talloc_free(profile_ctx);
			return UNLANG_ACTION_FAIL;
		}
		return fr_ldap_trunk_search(profile_ctx, &profile_ctx->query, request, profile_ctx->ttrunk,
					    profile_ctx->dn, profile_ctx->inst->profile.obj_scope,
					    profile_ctx->filter, profile_ctx->expanded->attrs, serverctrls, NULL);
	}

finish:
	talloc_free(profile_ctx);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push the resume frame and start the first profile search
 *
 * Cancellation is handled by the frame fr_ldap_trunk_search pushes above
 * this one, which abandons the in-flight query and detaches it from the
 * trunk request before the unwind frees profile_ctx.
 */
static unlang_action_t ldap_profile_search_push(ldap_profile_ctx_t *profile_ctx, request_t *request,
						char const *base, int scope, char const *filter)
{
	LDAPControl	*serverctrls[] = { profile_ctx->inst->profile.obj_sort_ctrl, NULL };

	if (unlang_function_push(request,
				 NULL,
				 ldap_map_profile_resume,
				 NULL, 0,
				 UNLANG_SUB_FRAME,
				 profile_ctx) < 0) {
		talloc_free(profile_ctx);
		return UNLANG_ACTION_FAIL;
	}

	return fr_ldap_trunk_search(profile_ctx, &profile_ctx->query, request, profile_ctx->ttrunk,
				    base, scope, filter,
				    profile_ctx->expanded->attrs, serverctrls, NULL);
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common
 * sets of attributes to the request.
 *
 * @param[out] ret		Where to write the result of the query.
 * @param[out] applied		Where to write the number of profiles applied.
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
unlang_action_t rlm_ldap_map_profile(fr_ldap_result_code_t *ret, int *applied,
				     rlm_ldap_t const *inst, request_t *request, fr_ldap_thread_trunk_t *ttrunk,
				     char const *dn, int scope, char const *filter, fr_ldap_map_exp_t const *expanded)
{
	ldap_profile_ctx_t	*profile_ctx;

	if (!dn || !*dn) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(profile_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_profile_ctx_t));
	*profile_ctx = (ldap_profile_ctx_t) {
		.ret = ret,
		.applied = applied,
		.dn = dn,
		.expanded = expanded,
		.inst = inst,
		.ttrunk = ttrunk
	};
	if (ret) *ret = LDAP_RESULT_ERROR;

	return ldap_profile_search_push(profile_ctx, request, dn, scope, filter);
}

/** Search for and apply a set of LDAP profiles
 *
 * With search_mode = bulk, a single search retrieves every profile object, matching
 * entries by DN using the attribute configured (or detected) for the directory,
 * and profiles are applied in result order.
 * With search_mode = seq, one search is run per profile DN, applied in list order.
 *
 * @param[out] ret		Where to write the result of the last query.
 * @param[out] applied		Incremented by the number of profile maps applied.
 * @param[in] inst		LDAP module instance.
 * @param[in] request		Current request.
 * @param[in] ttrunk		Trunk connection on which to run LDAP queries.
 * @param[in] dn_list		NULL terminated list of profile object DNs to apply,
 *				in application order (default profile first).
 *				Must contain at least one DN, and no empty strings.
 * @param[in] filter		to apply when looking up profiles.
 * @param[in] expanded		Structure containing a list of xlat
 *				expanded attribute names and mapping information.
 * @return An unlang_action_t.
 */
unlang_action_t rlm_ldap_map_profiles(fr_ldap_result_code_t *ret, int *applied,
				      rlm_ldap_t const *inst, request_t *request, fr_ldap_thread_trunk_t *ttrunk,
				      char const * const *dn_list, char const *filter,
				      fr_ldap_map_exp_t const *expanded)
{
	ldap_profile_ctx_t	*profile_ctx;

	fr_assert(dn_list && *dn_list);

	MEM(profile_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_profile_ctx_t));
	*profile_ctx = (ldap_profile_ctx_t) {
		.ret = ret,
		.applied = applied,
		.expanded = expanded,
		.inst = inst,
		.ttrunk = ttrunk,
		.filter = filter
	};
	if (ret) *ret = LDAP_RESULT_ERROR;

	switch (inst->profile.search_mode) {
	case LDAP_PROFILE_SEARCH_MODE_BULK:
	{
		char const	*base, *dn_attr;

		dn_attr = inst->dn_attr;
		if (!dn_attr) dn_attr = ttrunk->directory->dn_attr;
		fr_assert(dn_attr);

		base = fr_ldap_directory_common_base_find(ttrunk->directory, dn_list);
		if (!base) {
			RWDEBUG("Retrieving profiles one at a time, no naming context contains every profile DN");
			goto seq;
		}

		return ldap_profile_search_push(profile_ctx, request, base, LDAP_SCOPE_SUB,
						fr_ldap_filter_afrom_dn_list(profile_ctx, dn_attr, filter, dn_list));
	}

	case LDAP_PROFILE_SEARCH_MODE_SEQ:
	seq:
		profile_ctx->dn = dn_list[0];
		profile_ctx->next = dn_list + 1;

		return ldap_profile_search_push(profile_ctx, request, profile_ctx->dn, inst->profile.obj_scope, filter);

	case LDAP_PROFILE_SEARCH_MODE_AUTO:
		fr_assert_msg(false, "search mode auto should've been resolved at startup");
		break;
	}

	talloc_free(profile_ctx);
	return UNLANG_ACTION_FAIL;
}
