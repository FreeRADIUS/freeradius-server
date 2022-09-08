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
 * @copyright 2013 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <ctype.h>

#define LOG_PREFIX inst->name

#include "rlm_ldap.h"

/** Convert multiple group names into a DNs
 *
 * Given an array of group names, builds a filter matching all names, then retrieves all group objects
 * and stores the DN associated with each group object.
 *
 * @param[out] p_result		The result of trying to resolve a group name to a dn.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @param[in] names		to convert to DNs (NULL terminated).
 * @param[out] out		Where to write the DNs. DNs must be freed with
 *				ldap_memfree(). Will be NULL terminated.
 * @param[in] outlen		Size of out.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t rlm_ldap_group_name2dn(rlm_rcode_t *p_result, rlm_ldap_t const *inst, request_t *request,
					      fr_ldap_thread_trunk_t *ttrunk,
					      char **names, char **out, size_t outlen)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	int		ldap_errno;

	unsigned int	name_cnt = 0;
	unsigned int	entry_cnt;
	char const	*attrs[] = { NULL };

	LDAPMessage	*entry;
	fr_ldap_query_t	*query = NULL;

	char		**name = names;
	char		**dn = out;
	char const	*base_dn = NULL;
	char		base_dn_buff[LDAP_MAX_DN_STR_LEN];
	char		buffer[LDAP_MAX_GROUP_NAME_LEN + 1];

	char		*filter;

	*dn = NULL;

	if (!*names) RETURN_MODULE_OK;

	if (!inst->groupobj_name_attr) {
		REDEBUG("Told to convert group names to DNs but missing 'group.name_attribute' directive");

		RETURN_MODULE_INVALID;
	}

	RDEBUG2("Converting group name(s) to group DN(s)");

	/*
	 *	It'll probably only save a few ms in network latency, but it means we can send a query
	 *	for the entire group list at once.
	 */
	filter = talloc_typed_asprintf(request, "%s%s%s",
				 inst->groupobj_filter ? "(&" : "",
				 inst->groupobj_filter ? inst->groupobj_filter : "",
				 names[0] && names[1] ? "(|" : "");
	while (*name) {
		fr_ldap_escape_func(request, buffer, sizeof(buffer), *name++, NULL);
		filter = talloc_asprintf_append_buffer(filter, "(%s=%s)", inst->groupobj_name_attr, buffer);

		name_cnt++;
	}
	filter = talloc_asprintf_append_buffer(filter, "%s%s",
					       inst->groupobj_filter ? ")" : "",
					       names[0] && names[1] ? ")" : "");

	if (tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request,
			inst->groupobj_base_dn, fr_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating base_dn");

		RETURN_MODULE_INVALID;
	}

	if (fr_ldap_trunk_search(&rcode,
				 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, base_dn,
				 inst->groupobj_scope, filter, attrs, NULL, NULL, false) < 0 ) {
		goto finish;
	}
	switch (rcode) {
	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_NOTFOUND:
		RDEBUG2("Tried to resolve group name(s) to DNs but got no results");
		goto finish;

	default:
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	entry_cnt = ldap_count_entries(query->ldap_conn->handle, query->result);
	if (entry_cnt > name_cnt) {
		REDEBUG("Number of DNs exceeds number of names, group and/or dn should be more restrictive");
		rcode = RLM_MODULE_INVALID;

		goto finish;
	}

	if (entry_cnt > (outlen - 1)) {
		REDEBUG("Number of DNs exceeds limit (%zu)", outlen - 1);
		rcode = RLM_MODULE_INVALID;

		goto finish;
	}

	if (entry_cnt < name_cnt) {
		RWDEBUG("Got partial mapping of group names (%i) to DNs (%i), membership information may be incomplete",
			name_cnt, entry_cnt);
	}

	entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	if (!entry) {
		ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	do {
		*dn = ldap_get_dn(query->ldap_conn->handle, entry);
		if (!*dn) {
			ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
			REDEBUG("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
		fr_ldap_util_normalise_dn(*dn, *dn);

		RDEBUG2("Got group DN \"%s\"", *dn);
		dn++;
	} while((entry = ldap_next_entry(query->ldap_conn->handle, entry)));

	*dn = NULL;

finish:
	talloc_free(filter);

	/*
	 *	Be nice and cleanup the output array if we error out.
	 */
	if (rcode != RLM_MODULE_OK) {
		dn = out;
		while(*dn) ldap_memfree(*dn++);
		*dn = NULL;
	}

	RETURN_MODULE_RCODE(rcode);
}

/** Convert a single group DN into a name
 *
 * Unlike the inverse conversion of a name to a DN, most LDAP directories don't allow filtering by DN,
 * so we need to search for each DN individually.
 *
 * @param[out] p_result		The result of trying to resolve a dn to a group name.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @param[in] dn		to resolve.
 * @param[out] out		Where to write group name (must be freed with talloc_free).
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t rlm_ldap_group_dn2name(rlm_rcode_t *p_result, rlm_ldap_t const *inst, request_t *request,
					      fr_ldap_thread_trunk_t *ttrunk, char const *dn, char **out)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	int		ldap_errno;

	struct berval	**values = NULL;
	char const	*attrs[] = { inst->groupobj_name_attr, NULL };
	LDAPMessage	*entry;
	fr_ldap_query_t	*query = NULL;

	*out = NULL;

	if (!inst->groupobj_name_attr) {
		REDEBUG("Told to resolve group DN to name but missing 'group.name_attribute' directive");

		RETURN_MODULE_INVALID;
	}

	RDEBUG2("Resolving group DN \"%s\" to group name", dn);

	if (fr_ldap_trunk_search(&rcode,
				 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, dn,
				 LDAP_SCOPE_BASE, NULL, attrs, NULL, NULL, false) < 0) {
		RETURN_MODULE_FAIL;
	}
	switch (rcode) {
	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_NOTFOUND:
		REDEBUG("Group DN \"%s\" did not resolve to an object", dn);
		RETURN_MODULE_RCODE(inst->allow_dangling_group_refs ? RLM_MODULE_NOOP : RLM_MODULE_INVALID);

	default:
		RETURN_MODULE_FAIL;
	}

	entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	if (!entry) {
		ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_INVALID;
		goto finish;
	}

	values = ldap_get_values_len(query->ldap_conn->handle, entry, inst->groupobj_name_attr);
	if (!values) {
		REDEBUG("No %s attributes found in object", inst->groupobj_name_attr);

		rcode = RLM_MODULE_INVALID;

		goto finish;
	}

	*out = fr_ldap_berval_to_string(request, values[0]);
	RDEBUG2("Group DN \"%s\" resolves to name \"%s\"", dn, *out);

finish:
	if (values) ldap_value_free_len(values);

	RETURN_MODULE_RCODE(rcode);
}

/** Convert group membership information into attributes
 *
 * @param[out] p_result		The result of trying to resolve a dn to a group name.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @param[in] entry		retrieved by rlm_ldap_find_user or fr_ldap_search.
 * @param[in] attr		membership attribute to look for in the entry.
 * @return One of the RLM_MODULE_* values.
 */
unlang_action_t rlm_ldap_cacheable_userobj(rlm_rcode_t *p_result, rlm_ldap_t const *inst,
					   request_t *request, fr_ldap_thread_trunk_t *ttrunk,
					   LDAPMessage *entry, char const *attr)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;

	struct berval **values;

	char *group_name[LDAP_MAX_CACHEABLE + 1];
	char **name_p = group_name;

	char *group_dn[LDAP_MAX_CACHEABLE + 1];
	char **dn_p;

	char *name;

	fr_pair_t *vp;
	fr_pair_list_t *list, groups;
	TALLOC_CTX *list_ctx, *value_ctx;

	int is_dn, i, count;

	fr_assert(entry);
	fr_assert(attr);

	/*
	 *	Parse the membership information we got in the initial user query.
	 */
	values = ldap_get_values_len(fr_ldap_handle_thread_local(), entry, attr);
	if (!values) {
		RDEBUG2("No cacheable group memberships found in user object");

		RETURN_MODULE_OK;
	}
	count = ldap_count_values_len(values);

	list = tmpl_list_head(request, PAIR_LIST_CONTROL);
	list_ctx = tmpl_list_ctx(request, PAIR_LIST_CONTROL);
	fr_assert(list != NULL);
	fr_assert(list_ctx != NULL);

	/*
	 *	Simplifies freeing temporary values
	 */
	value_ctx = talloc_new(request);

	/*
	 *	Temporary list to hold new group VPs, will be merged
	 *	once all group info has been gathered/resolved
	 *	successfully.
	 */
	fr_pair_list_init(&groups);

	for (i = 0; (i < LDAP_MAX_CACHEABLE) && (i < count); i++) {
		is_dn = fr_ldap_util_is_dn(values[i]->bv_val, values[i]->bv_len);

		if (inst->cacheable_group_dn) {
			/*
			 *	The easy case, we're caching DNs and we got a DN.
			 */
			if (is_dn) {
				MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
				fr_pair_value_bstrndup(vp, values[i]->bv_val, values[i]->bv_len, true);
				fr_pair_append(&groups, vp);
			/*
			 *	We were told to cache DNs but we got a name, we now need to resolve
			 *	this to a DN. Store all the group names in an array so we can do one query.
			 */
			} else {
				*name_p++ = fr_ldap_berval_to_string(value_ctx, values[i]);
			}
		}

		if (inst->cacheable_group_name) {
			/*
			 *	The easy case, we're caching names and we got a name.
			 */
			if (!is_dn) {
				MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
				fr_pair_value_bstrndup(vp, values[i]->bv_val, values[i]->bv_len, true);
				fr_pair_append(&groups, vp);
			/*
			 *	We were told to cache names but we got a DN, we now need to resolve
			 *	this to a name.
			 *	Only Active Directory supports filtering on DN, so we have to search
			 *	for each individual group.
			 */
			} else {
				char *dn;

				dn = fr_ldap_berval_to_string(value_ctx, values[i]);
				rlm_ldap_group_dn2name(&rcode, inst, request, ttrunk, dn, &name);
				talloc_free(dn);

				if (rcode == RLM_MODULE_NOOP) continue;

				if (rcode != RLM_MODULE_OK) {
					ldap_value_free_len(values);
					talloc_free(value_ctx);
					fr_pair_list_free(&groups);

					RETURN_MODULE_RCODE(rcode);
				}

				MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
				fr_pair_value_bstrdup_buffer(vp, name, true);
				fr_pair_append(&groups, vp);
				talloc_free(name);
			}
		}
	}
	*name_p = NULL;

	rlm_ldap_group_name2dn(&rcode, inst, request, ttrunk, group_name, group_dn, sizeof(group_dn));

	ldap_value_free_len(values);
	talloc_free(value_ctx);

	if (rcode != RLM_MODULE_OK) RETURN_MODULE_RCODE(rcode);

	RDEBUG2("Adding cacheable user object memberships");
	RINDENT();
	if (RDEBUG_ENABLED) {
		for (vp = fr_pair_list_head(&groups);
		     vp;
		     vp = fr_pair_list_next(&groups, vp)) {
			RDEBUG2("&control.%s += \"%pV\"", inst->cache_da->name, &vp->data);
		}
	}

	fr_pair_list_append(list, &groups);

	for (dn_p = group_dn; *dn_p; dn_p++) {
		MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
		fr_pair_value_strdup(vp, *dn_p, false);
		fr_pair_append(list, vp);

		RDEBUG2("&control.%s += \"%pV\"", inst->cache_da->name, &vp->data);
		ldap_memfree(*dn_p);
	}
	REXDENT();

	RETURN_MODULE_RCODE(rcode);
}

/** Convert group membership information into attributes
 *
 * @param[out] p_result		The result of trying to resolve a dn to a group name.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @return One of the RLM_MODULE_* values.
 */
unlang_action_t rlm_ldap_cacheable_groupobj(rlm_rcode_t *p_result, rlm_ldap_t const *inst,
					    request_t *request, fr_ldap_thread_trunk_t *ttrunk)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	int		ldap_errno;

	LDAPMessage	*entry;
	fr_ldap_query_t	*query;

	char const	*base_dn;
	char		base_dn_buff[LDAP_MAX_DN_STR_LEN];

	char const	*filters[] = { inst->groupobj_filter, inst->groupobj_membership_filter };
	char		filter[LDAP_MAX_FILTER_STR_LEN + 1];

	char const	*attrs[] = { inst->groupobj_name_attr, NULL };

	fr_pair_t	*vp;
	char		*dn;

	fr_assert(inst->groupobj_base_dn);

	if (!inst->groupobj_membership_filter) {
		RDEBUG2("Skipping caching group objects as directive 'group.membership_filter' is not set");

		RETURN_MODULE_OK;
	}

	if (fr_ldap_xlat_filter(request,
				 filters, NUM_ELEMENTS(filters),
				 filter, sizeof(filter)) < 0) {
		RETURN_MODULE_INVALID;
	}

	if (tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request,
			inst->groupobj_base_dn, fr_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating base_dn");

		RETURN_MODULE_INVALID;
	}

	if (fr_ldap_trunk_search(&rcode,
				 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, base_dn,
				 inst->groupobj_scope, filter, attrs, NULL, NULL, false) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}
	switch (rcode) {
	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_NOTFOUND:
		RDEBUG2("No cacheable group memberships found in group objects");
		goto finish;

	default:
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	if (!entry) {
		ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		goto finish;
	}

	RDEBUG2("Adding cacheable group object memberships");
	do {
		if (inst->cacheable_group_dn) {
			dn = ldap_get_dn(query->ldap_conn->handle, entry);
			if (!dn) {
				ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
				REDEBUG("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

				goto finish;
			}
			fr_ldap_util_normalise_dn(dn, dn);

			MEM(pair_append_control(&vp, inst->cache_da) == 0);
			fr_pair_value_strdup(vp, dn, false);

			RINDENT();
			RDEBUG2("&control.%pP", vp);
			REXDENT();
			ldap_memfree(dn);
		}

		if (inst->cacheable_group_name) {
			struct berval **values;

			values = ldap_get_values_len(query->ldap_conn->handle, entry, inst->groupobj_name_attr);
			if (!values) continue;

			MEM(pair_append_control(&vp, inst->cache_da) == 0);
			fr_pair_value_bstrndup(vp, values[0]->bv_val, values[0]->bv_len, true);

			RINDENT();
			RDEBUG2("&control.%pP", vp);
			REXDENT();

			ldap_value_free_len(values);
		}
	} while ((entry = ldap_next_entry(query->ldap_conn->handle, entry)));

finish:

	RETURN_MODULE_RCODE(rcode);
}

/** Query the LDAP directory to check if a group object includes a user object as a member
 *
 * @param[out] p_result		Result of calling the module.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @param[in] check		vp containing the group value (name or dn).
 */
unlang_action_t rlm_ldap_check_groupobj_dynamic(rlm_rcode_t *p_result, rlm_ldap_t const *inst, request_t *request,
						fr_ldap_thread_trunk_t *ttrunk, fr_pair_t const *check)
{
	rlm_rcode_t	rcode;
	fr_ldap_query_t	*query = NULL;

	char const	*base_dn;
	char		base_dn_buff[LDAP_MAX_DN_STR_LEN + 1];
	char 		filter[LDAP_MAX_FILTER_STR_LEN + 1];
	int		ret;

	fr_assert(inst->groupobj_base_dn);

	switch (check->op) {
	case T_OP_CMP_EQ:
	case T_OP_CMP_FALSE:
	case T_OP_CMP_TRUE:
	case T_OP_REG_EQ:
	case T_OP_REG_NE:
		break;

	default:
		REDEBUG("Operator \"%s\" not allowed for LDAP group comparisons",
			fr_table_str_by_value(fr_tokens_table, check->op, "<INVALID>"));
		return 1;
	}

	RDEBUG2("Checking for user in group objects");

	if (fr_ldap_util_is_dn(check->vp_strvalue, check->vp_length)) {
		char const *filters[] = { inst->groupobj_filter, inst->groupobj_membership_filter };

		RINDENT();
		ret = fr_ldap_xlat_filter(request,
					   filters, NUM_ELEMENTS(filters),
					   filter, sizeof(filter));
		REXDENT();

		if (ret < 0) RETURN_MODULE_INVALID;

		base_dn = check->vp_strvalue;
	} else {
		char name_filter[LDAP_MAX_FILTER_STR_LEN];
		char const *filters[] = { name_filter, inst->groupobj_filter, inst->groupobj_membership_filter };

		if (!inst->groupobj_name_attr) {
			REDEBUG("Told to search for group by name, but missing 'group.name_attribute' "
				"directive");

			RETURN_MODULE_INVALID;
		}

		snprintf(name_filter, sizeof(name_filter), "(%s=%s)", inst->groupobj_name_attr, check->vp_strvalue);
		RINDENT();
		ret = fr_ldap_xlat_filter(request,
					   filters, NUM_ELEMENTS(filters),
					   filter, sizeof(filter));
		REXDENT();
		if (ret < 0) RETURN_MODULE_INVALID;


		/*
		 *	rlm_ldap_find_user does this, too.  Oh well.
		 */
		RINDENT();
		ret = tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request, inst->groupobj_base_dn,
				  fr_ldap_escape_func, NULL);
		REXDENT();
		if (ret < 0) {
			REDEBUG("Failed creating base_dn");

			RETURN_MODULE_INVALID;
		}
	}

	RINDENT();
	if (fr_ldap_trunk_search(&rcode,
				 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, base_dn,
				 inst->groupobj_scope, filter, NULL, NULL, NULL, false) < 0) {
		REXDENT();
		RETURN_MODULE_FAIL;
	}
	REXDENT();
	switch (rcode) {
	case RLM_MODULE_OK:
		RDEBUG2("User found in group object \"%s\"", base_dn);
		break;

	case RLM_MODULE_NOTFOUND:
		RETURN_MODULE_NOTFOUND;

	default:
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
}

/** Query the LDAP directory to check if a user object is a member of a group
 *
 * @param[out] p_result		Result of calling the module.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @param[in] dn		of user object.
 * @param[in] check		vp containing the group value (name or dn).
 */
unlang_action_t rlm_ldap_check_userobj_dynamic(rlm_rcode_t *p_result, rlm_ldap_t const *inst, request_t *request,
					       fr_ldap_thread_trunk_t *ttrunk,
					       char const *dn, fr_pair_t const *check)
{
	rlm_rcode_t	rcode = RLM_MODULE_NOTFOUND, ret;
	bool		name_is_dn = false, value_is_dn = false;
	fr_ldap_query_t	*query;

	LDAPMessage     *entry = NULL;
	struct berval	**values = NULL;

	char const	*attrs[] = { inst->userobj_membership_attr, NULL };
	int		i, count, ldap_errno;

	RDEBUG2("Checking user object's %s attributes", inst->userobj_membership_attr);
	RINDENT();
	if (fr_ldap_trunk_search(&rcode,
				 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, dn,
				 LDAP_SCOPE_BASE, NULL, attrs, NULL, NULL, false) < 0) {
		REXDENT();
		goto finish;
	}
	REXDENT();
	switch (rcode) {
	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_NOTFOUND:
		RDEBUG2("Can't check membership attributes, user object not found");

		FALL_THROUGH;
	default:
		goto finish;
	}

	entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	if (!entry) {
		ldap_get_option(query->ldap_conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_FAIL;

		goto finish;
	}

	values = ldap_get_values_len(query->ldap_conn->handle, entry, inst->userobj_membership_attr);
	if (!values) {
		RDEBUG2("No group membership attribute(s) found in user object");

		goto finish;
	}

	/*
	 *	Loop over the list of groups the user is a member of,
	 *	looking for a match.
	 */
	name_is_dn = fr_ldap_util_is_dn(check->vp_strvalue, check->vp_length);
	count = ldap_count_values_len(values);
	for (i = 0; i < count; i++) {
		value_is_dn = fr_ldap_util_is_dn(values[i]->bv_val, values[i]->bv_len);

		RDEBUG2("Processing %s value \"%pV\" as a %s", inst->userobj_membership_attr,
			fr_box_strvalue_len(values[i]->bv_val, values[i]->bv_len),
			value_is_dn ? "DN" : "group name");

		/*
		 *	Both literal group names, do case sensitive comparison
		 */
		if (!name_is_dn && !value_is_dn) {
			if ((check->vp_length == values[i]->bv_len) &&
			    (memcmp(values[i]->bv_val, check->vp_strvalue, values[i]->bv_len) == 0)) {
				RDEBUG2("User found in group \"%s\". Comparison between membership: name, check: name",
				       check->vp_strvalue);
				rcode = RLM_MODULE_OK;

				goto finish;
			}

			continue;
		}

		/*
		 *	Both DNs, do case insensitive, binary safe comparison
		 */
		if (name_is_dn && value_is_dn) {
			if (check->vp_length == values[i]->bv_len) {
				int j;

				for (j = 0; j < (int)values[i]->bv_len; j++) {
					if (tolower(values[i]->bv_val[j]) != tolower(check->vp_strvalue[j])) break;
				}
				if (j == (int)values[i]->bv_len) {
					RDEBUG2("User found in group DN \"%s\". "
					       "Comparison between membership: dn, check: dn", check->vp_strvalue);
					rcode = RLM_MODULE_OK;

					goto finish;
				}
			}

			continue;
		}

		/*
		 *	If the value is not a DN, and the name we were given is a dn
		 *	convert the value to a DN and do a comparison.
		 */
		if (!value_is_dn && name_is_dn) {
			char *resolved;
			bool eq = false;

			RINDENT();
			rlm_ldap_group_dn2name(&ret, inst, request, ttrunk, check->vp_strvalue, &resolved);
			REXDENT();

			if (ret == RLM_MODULE_NOOP) continue;

			if (ret != RLM_MODULE_OK) {
				rcode = ret;
				goto finish;
			}

			if (((talloc_array_length(resolved) - 1) == values[i]->bv_len) &&
			    (memcmp(values[i]->bv_val, resolved, values[i]->bv_len) == 0)) eq = true;
			talloc_free(resolved);
			if (eq) {
				RDEBUG2("User found in group \"%pV\". Comparison between membership: name, check: name "
				       "(resolved from DN \"%s\")",
				       fr_box_strvalue_len(values[i]->bv_val, values[i]->bv_len), check->vp_strvalue);
				rcode = RLM_MODULE_OK;

				goto finish;
			}

			continue;
		}

		/*
		 *	We have a value which is a DN, and a check item which specifies the name of a group,
		 *	convert the value to a name so we can do a comparison.
		 */
		if (value_is_dn && !name_is_dn) {
			char *resolved;
			char *value;
			bool eq = false;

			value = fr_ldap_berval_to_string(request, values[i]);
			RINDENT();
			rlm_ldap_group_dn2name(&ret, inst, request, ttrunk, value, &resolved);
			REXDENT();
			talloc_free(value);

			if (ret == RLM_MODULE_NOOP) continue;

			if (ret != RLM_MODULE_OK) {
				rcode = ret;
				goto finish;
			}

			if (((talloc_array_length(resolved) - 1) == check->vp_length) &&
			    (memcmp(check->vp_strvalue, resolved, check->vp_length) == 0)) eq = true;
			talloc_free(resolved);
			if (eq) {
				RDEBUG2("User found in group \"%pV\". Comparison between membership: name "
				       "(resolved from DN \"%s\"), check: name", &check->data, value);
				rcode = RLM_MODULE_OK;

				goto finish;
			}

			continue;
		}
		fr_assert(0);
	}

finish:
	if (values) ldap_value_free_len(values);

	RETURN_MODULE_RCODE(rcode);
}

/** Check group membership attributes to see if a user is a member.
 *
 * @param[out] p_result		Result of calling the module.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] check		vp containing the group value (name or dn).
 */
unlang_action_t rlm_ldap_check_cached(rlm_rcode_t *p_result,
				      rlm_ldap_t const *inst, request_t *request, fr_pair_t const *check)
{
	fr_pair_t	*vp;
	int		ret;
	fr_dcursor_t	cursor;

	/*
	 *	We return RLM_MODULE_INVALID here as an indication
	 *	the caller should try a dynamic group lookup instead.
	 */
	vp =  fr_pair_dcursor_by_da_init(&cursor, &request->control_pairs, inst->cache_da);
	if (!vp) RETURN_MODULE_INVALID;

	for (vp = fr_dcursor_current(&cursor);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		ret = fr_pair_cmp_op(T_OP_CMP_EQ, vp, check);
		if (ret == 1) {
			RDEBUG2("User found. Matched cached membership");
			RETURN_MODULE_OK;
		}

		if (ret < -1) RETURN_MODULE_FAIL;
	}

	RDEBUG2("Cached membership not found");

	RETURN_MODULE_NOTFOUND;
}
