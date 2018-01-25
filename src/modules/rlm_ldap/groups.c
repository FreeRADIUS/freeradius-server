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
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2013 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
#include	<freeradius-devel/rad_assert.h>
#include	<ctype.h>

#include	"ldap.h"

/** Convert multiple group names into a DNs
 *
 * Given an array of group names, builds a filter matching all names, then retrieves all group objects
 * and stores the DN associated with each group object.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] names to covert to DNs (NULL terminated).
 * @param[out] out Where to write the DNs. DNs must be freed with ldap_memfree(). Will be NULL terminated.
 * @param[in] outlen Size of out.
 * @return One of the RLM_MODULE_* values.
 */
static rlm_rcode_t rlm_ldap_group_name2dn(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					  char **names, char **out, size_t outlen)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	ldap_rcode_t status;
	int ldap_errno;

	unsigned int name_cnt = 0;
	unsigned int entry_cnt;
	char const *attrs[] = { NULL };

	LDAPMessage *result = NULL, *entry;

	char **name = names;
	char **dn = out;
	char const *base_dn = NULL;
	char base_dn_buff[LDAP_MAX_DN_STR_LEN];
	char buffer[LDAP_MAX_GROUP_NAME_LEN + 1];

	char *filter;

	*dn = NULL;

	if (!*names) {
		return RLM_MODULE_OK;
	}

	if (!inst->groupobj_name_attr) {
		REDEBUG("Told to convert group names to DNs but missing 'group.name_attribute' directive");

		return RLM_MODULE_INVALID;
	}

	RDEBUG("Converting group name(s) to group DN(s)");

	/*
	 *	It'll probably only save a few ms in network latency, but it means we can send a query
	 *	for the entire group list at once.
	 */
	filter = talloc_typed_asprintf(request, "%s%s%s",
				 inst->groupobj_filter ? "(&" : "",
				 inst->groupobj_filter ? inst->groupobj_filter : "",
				 names[0] && names[1] ? "(|" : "");
	while (*name) {
		rlm_ldap_escape_func(request, buffer, sizeof(buffer), *name++, NULL);
		filter = talloc_asprintf_append_buffer(filter, "(%s=%s)", inst->groupobj_name_attr, buffer);

		name_cnt++;
	}
	filter = talloc_asprintf_append_buffer(filter, "%s%s",
					       inst->groupobj_filter ? ")" : "",
					       names[0] && names[1] ? ")" : "");

	if (tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request,
			inst->groupobj_base_dn, rlm_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating base_dn");

		return RLM_MODULE_INVALID;
	}

	status = rlm_ldap_search(&result, inst, request, pconn, base_dn, inst->groupobj_scope,
				 filter, attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		RDEBUG("Tried to resolve group name(s) to DNs but got no results");
		goto finish;

	default:
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	entry_cnt = ldap_count_entries((*pconn)->handle, result);
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

	entry = ldap_first_entry((*pconn)->handle, result);
	if (!entry) {
		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	do {
		*dn = ldap_get_dn((*pconn)->handle, entry);
		if (!*dn) {
			ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
			REDEBUG("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
		rlm_ldap_normalise_dn(*dn, *dn);

		RDEBUG("Got group DN \"%s\"", *dn);
		dn++;
	} while((entry = ldap_next_entry((*pconn)->handle, entry)));

	*dn = NULL;

finish:
	talloc_free(filter);
	if (result) {
		ldap_msgfree(result);
	}

	/*
	 *	Be nice and cleanup the output array if we error out.
	 */
	if (rcode != RLM_MODULE_OK) {
		dn = out;
		while(*dn) ldap_memfree(*dn++);
		*dn = NULL;
	}

	return rcode;
}

/** Convert a single group name into a DN
 *
 * Unlike the inverse conversion of a name to a DN, most LDAP directories don't allow filtering by DN,
 * so we need to search for each DN individually.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn to resolve.
 * @param[out] out Where to write group name (must be freed with talloc_free).
 * @return One of the RLM_MODULE_* values.
 */
static rlm_rcode_t rlm_ldap_group_dn2name(rlm_ldap_t const *inst, REQUEST *request,
					  ldap_handle_t **pconn, char const *dn, char **out)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	ldap_rcode_t status;
	int ldap_errno;

	struct berval **values = NULL;
	char const *attrs[] = { inst->groupobj_name_attr, NULL };
	LDAPMessage *result = NULL, *entry;

	*out = NULL;

	if (!inst->groupobj_name_attr) {
		REDEBUG("Told to resolve group DN to name but missing 'group.name_attribute' directive");

		return RLM_MODULE_INVALID;
	}

	RDEBUG("Resolving group DN \"%s\" to group name", dn);

	status = rlm_ldap_search(&result, inst, request, pconn, dn, LDAP_SCOPE_BASE, NULL, attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		REDEBUG("Group DN \"%s\" did not resolve to an object", dn);
		return RLM_MODULE_INVALID;

	default:
		return RLM_MODULE_FAIL;
	}

	entry = ldap_first_entry((*pconn)->handle, result);
	if (!entry) {
		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_INVALID;
		goto finish;
	}

	values = ldap_get_values_len((*pconn)->handle, entry, inst->groupobj_name_attr);
	if (!values) {
		REDEBUG("No %s attributes found in object", inst->groupobj_name_attr);

		rcode = RLM_MODULE_INVALID;

		goto finish;
	}

	*out = rlm_ldap_berval_to_string(request, values[0]);
	RDEBUG("Group DN \"%s\" resolves to name \"%s\"", dn, *out);

finish:
	if (result) ldap_msgfree(result);
	if (values) ldap_value_free_len(values);

	return rcode;
}

/** Convert group membership information into attributes
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] entry retrieved by rlm_ldap_find_user or rlm_ldap_search.
 * @param[in] attr membership attribute to look for in the entry.
 * @return One of the RLM_MODULE_* values.
 */
rlm_rcode_t rlm_ldap_cacheable_userobj(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
				       LDAPMessage *entry, char const *attr)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;

	struct berval **values;

	char *group_name[LDAP_MAX_CACHEABLE + 1];
	char **name_p = group_name;

	char *group_dn[LDAP_MAX_CACHEABLE + 1];
	char **dn_p;

	char *name;

	VALUE_PAIR *vp, **list, *groups = NULL;
	TALLOC_CTX *list_ctx, *value_ctx;
	vp_cursor_t list_cursor, groups_cursor;

	int is_dn, i, count;

	rad_assert(entry);
	rad_assert(attr);

	/*
	 *	Parse the membership information we got in the initial user query.
	 */
	values = ldap_get_values_len((*pconn)->handle, entry, attr);
	if (!values) {
		RDEBUG2("No cacheable group memberships found in user object");

		return RLM_MODULE_OK;
	}
	count = ldap_count_values_len(values);

	list = radius_list(request, PAIR_LIST_CONTROL);
	list_ctx = radius_list_ctx(request, PAIR_LIST_CONTROL);

	/*
	 *	Simplifies freeing temporary values
	 */
	value_ctx = talloc_new(request);

	/*
	 *	Temporary list to hold new group VPs, will be merged
	 *	once all group info has been gathered/resolved
	 *	successfully.
	 */
	fr_cursor_init(&groups_cursor, &groups);

	for (i = 0; (i < LDAP_MAX_CACHEABLE) && (i < count); i++) {
		is_dn = rlm_ldap_is_dn(values[i]->bv_val, values[i]->bv_len);

		if (inst->cacheable_group_dn) {
			/*
			 *	The easy case, we're caching DNs and we got a DN.
			 */
			if (is_dn) {
				MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
				fr_pair_value_bstrncpy(vp, values[i]->bv_val, values[i]->bv_len);
				fr_cursor_insert(&groups_cursor, vp);
			/*
			 *	We were told to cache DNs but we got a name, we now need to resolve
			 *	this to a DN. Store all the group names in an array so we can do one query.
			 */
			} else {
				*name_p++ = rlm_ldap_berval_to_string(value_ctx, values[i]);
			}
		}

		if (inst->cacheable_group_name) {
			/*
			 *	The easy case, we're caching names and we got a name.
			 */
			if (!is_dn) {
				MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
				fr_pair_value_bstrncpy(vp, values[i]->bv_val, values[i]->bv_len);
				fr_cursor_insert(&groups_cursor, vp);
			/*
			 *	We were told to cache names but we got a DN, we now need to resolve
			 *	this to a name.
			 *	Only Active Directory supports filtering on DN, so we have to search
			 *	for each individual group.
			 */
			} else {
				char *dn;

				dn = rlm_ldap_berval_to_string(value_ctx, values[i]);
				rcode = rlm_ldap_group_dn2name(inst, request, pconn, dn, &name);
				talloc_free(dn);
				if (rcode != RLM_MODULE_OK) {
					ldap_value_free_len(values);
					talloc_free(value_ctx);
					fr_pair_list_free(&groups);

					return rcode;
				}

				MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
				fr_pair_value_bstrncpy(vp, name, talloc_array_length(name) - 1);
				fr_cursor_insert(&groups_cursor, vp);
				talloc_free(name);
			}
		}
	}
	*name_p = NULL;

	rcode = rlm_ldap_group_name2dn(inst, request, pconn, group_name, group_dn, sizeof(group_dn));

	ldap_value_free_len(values);
	talloc_free(value_ctx);

	if (rcode != RLM_MODULE_OK) return rcode;

	fr_cursor_init(&list_cursor, list);

	RDEBUG("Adding cacheable user object memberships");
	RINDENT();
	if (RDEBUG_ENABLED) {
		for (vp = fr_cursor_first(&groups_cursor);
		     vp;
		     vp = fr_cursor_next(&groups_cursor)) {
			RDEBUG("&control:%s += \"%s\"", inst->cache_da->name, vp->vp_strvalue);
		}
	}

	fr_cursor_merge(&list_cursor, groups);

	for (dn_p = group_dn; *dn_p; dn_p++) {
		MEM(vp = fr_pair_afrom_da(list_ctx, inst->cache_da));
		fr_pair_value_strcpy(vp, *dn_p);
		fr_cursor_insert(&list_cursor, vp);

		RDEBUG("&control:%s += \"%s\"", inst->cache_da->name, vp->vp_strvalue);
		ldap_memfree(*dn_p);
	}
	REXDENT();

	return rcode;
}

/** Convert group membership information into attributes
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @return One of the RLM_MODULE_* values.
 */
rlm_rcode_t rlm_ldap_cacheable_groupobj(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	ldap_rcode_t status;
	int ldap_errno;

	LDAPMessage *result = NULL;
	LDAPMessage *entry;

	char const *base_dn;
	char base_dn_buff[LDAP_MAX_DN_STR_LEN];

	char const *filters[] = { inst->groupobj_filter, inst->groupobj_membership_filter };
	char filter[LDAP_MAX_FILTER_STR_LEN + 1];

	char const *attrs[] = { inst->groupobj_name_attr, NULL };

	VALUE_PAIR *vp;
	char *dn;

	rad_assert(inst->groupobj_base_dn);

	if (!inst->groupobj_membership_filter) {
		RDEBUG2("Skipping caching group objects as directive 'group.membership_filter' is not set");

		return RLM_MODULE_OK;
	}

	if (rlm_ldap_xlat_filter(request,
				 filters, sizeof(filters) / sizeof(*filters),
				 filter, sizeof(filter)) < 0) {
		return RLM_MODULE_INVALID;
	}

	if (tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request,
			inst->groupobj_base_dn, rlm_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating base_dn");

		return RLM_MODULE_INVALID;
	}

	status = rlm_ldap_search(&result, inst, request, pconn, base_dn,
				 inst->groupobj_scope, filter, attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		RDEBUG2("No cacheable group memberships found in group objects");
		goto finish;

	default:
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	entry = ldap_first_entry((*pconn)->handle, result);
	if (!entry) {
		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		goto finish;
	}

	RDEBUG("Adding cacheable group object memberships");
	do {
		if (inst->cacheable_group_dn) {
			dn = ldap_get_dn((*pconn)->handle, entry);
			if (!dn) {
				ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
				REDEBUG("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

				goto finish;
			}
			rlm_ldap_normalise_dn(dn, dn);

			MEM(vp = pair_make_config(inst->cache_da->name, NULL, T_OP_ADD));
			fr_pair_value_strcpy(vp, dn);

			RINDENT();
			RDEBUG("&control:%s += \"%s\"", inst->cache_da->name, dn);
			REXDENT();
			ldap_memfree(dn);
		}

		if (inst->cacheable_group_name) {
			struct berval **values;

			values = ldap_get_values_len((*pconn)->handle, entry, inst->groupobj_name_attr);
			if (!values) continue;

			MEM(vp = pair_make_config(inst->cache_da->name, NULL, T_OP_ADD));
			fr_pair_value_bstrncpy(vp, values[0]->bv_val, values[0]->bv_len);

			RINDENT();
			RDEBUG("&control:%s += \"%.*s\"", inst->cache_da->name,
			       (int)values[0]->bv_len, values[0]->bv_val);
			REXDENT();

			ldap_value_free_len(values);
		}
	} while ((entry = ldap_next_entry((*pconn)->handle, entry)));

finish:
	if (result) ldap_msgfree(result);

	return rcode;
}

/** Query the LDAP directory to check if a group object includes a user object as a member
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] check vp containing the group value (name or dn).
 * @return One of the RLM_MODULE_* values.
 */
rlm_rcode_t rlm_ldap_check_groupobj_dynamic(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					    VALUE_PAIR *check)

{
	ldap_rcode_t	status;

	char const	*base_dn;
	char		base_dn_buff[LDAP_MAX_DN_STR_LEN + 1];
	char 		filter[LDAP_MAX_FILTER_STR_LEN + 1];
	int		ret;

	rad_assert(inst->groupobj_base_dn);

	switch (check->op) {
	case T_OP_CMP_EQ:
	case T_OP_CMP_FALSE:
	case T_OP_CMP_TRUE:
	case T_OP_REG_EQ:
	case T_OP_REG_NE:
		break;

	default:
		REDEBUG("Operator \"%s\" not allowed for LDAP group comparisons",
			fr_int2str(fr_tokens, check->op, "<INVALID>"));
		return 1;
	}

	RDEBUG2("Checking for user in group objects");

	if (rlm_ldap_is_dn(check->vp_strvalue, check->vp_length)) {
		char const *filters[] = { inst->groupobj_filter, inst->groupobj_membership_filter };

		RINDENT();
		ret = rlm_ldap_xlat_filter(request,
					   filters, sizeof(filters) / sizeof(*filters),
					   filter, sizeof(filter));
		REXDENT();

		if (ret < 0) return RLM_MODULE_INVALID;

		base_dn = check->vp_strvalue;
	} else {
		char name_filter[LDAP_MAX_FILTER_STR_LEN];
		char const *filters[] = { name_filter, inst->groupobj_filter, inst->groupobj_membership_filter };

		if (!inst->groupobj_name_attr) {
			REDEBUG("Told to search for group by name, but missing 'group.name_attribute' "
				"directive");

			return RLM_MODULE_INVALID;
		}

		snprintf(name_filter, sizeof(name_filter), "(%s=%s)", inst->groupobj_name_attr, check->vp_strvalue);
		RINDENT();
		ret = rlm_ldap_xlat_filter(request,
					   filters, sizeof(filters) / sizeof(*filters),
					   filter, sizeof(filter));
		REXDENT();
		if (ret < 0) return RLM_MODULE_INVALID;


		/*
		 *	rlm_ldap_find_user does this, too.  Oh well.
		 */
		RINDENT();
		ret = tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request, inst->groupobj_base_dn,
				  rlm_ldap_escape_func, NULL);
		REXDENT();
		if (ret < 0) {
			REDEBUG("Failed creating base_dn");

			return RLM_MODULE_INVALID;
		}
	}

	RINDENT();
	status = rlm_ldap_search(NULL, inst, request, pconn, base_dn, inst->groupobj_scope, filter, NULL, NULL, NULL);
	REXDENT();
	switch (status) {
	case LDAP_PROC_SUCCESS:
		RDEBUG("User found in group object \"%s\"", base_dn);
		break;

	case LDAP_PROC_NO_RESULT:
		return RLM_MODULE_NOTFOUND;

	default:
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

/** Query the LDAP directory to check if a user object is a member of a group
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn of user object.
 * @param[in] check vp containing the group value (name or dn).
 * @return One of the RLM_MODULE_* values.
 */
rlm_rcode_t rlm_ldap_check_userobj_dynamic(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					   char const *dn, VALUE_PAIR *check)
{
	rlm_rcode_t	rcode = RLM_MODULE_NOTFOUND, ret;
	ldap_rcode_t	status;
	bool		name_is_dn = false, value_is_dn = false;

	LDAPMessage     *result = NULL;
	LDAPMessage     *entry = NULL;
	struct berval	**values = NULL;

	char const	*attrs[] = { inst->userobj_membership_attr, NULL };
	int		i, count, ldap_errno;

	RDEBUG2("Checking user object's %s attributes", inst->userobj_membership_attr);
	RINDENT();
	status = rlm_ldap_search(&result, inst, request, pconn, dn, LDAP_SCOPE_BASE, NULL, attrs, NULL, NULL);
	REXDENT();
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		RDEBUG("Can't check membership attributes, user object not found");

		rcode = RLM_MODULE_NOTFOUND;

		/* FALL-THROUGH */
	default:
		goto finish;
	}

	entry = ldap_first_entry((*pconn)->handle, result);
	if (!entry) {
		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_FAIL;

		goto finish;
	}

	values = ldap_get_values_len((*pconn)->handle, entry, inst->userobj_membership_attr);
	if (!values) {
		RDEBUG("No group membership attribute(s) found in user object");

		goto finish;
	}

	/*
	 *	Loop over the list of groups the user is a member of,
	 *	looking for a match.
	 */
	name_is_dn = rlm_ldap_is_dn(check->vp_strvalue, check->vp_length);
	count = ldap_count_values_len(values);
	for (i = 0; i < count; i++) {
		value_is_dn = rlm_ldap_is_dn(values[i]->bv_val, values[i]->bv_len);

		RDEBUG2("Processing %s value \"%.*s\" as a %s", inst->userobj_membership_attr,
			(int)values[i]->bv_len, values[i]->bv_val, value_is_dn ? "DN" : "group name");

		/*
		 *	Both literal group names, do case sensitive comparison
		 */
		if (!name_is_dn && !value_is_dn) {
			if ((check->vp_length == values[i]->bv_len) &&
			    (memcmp(values[i]->bv_val, check->vp_strvalue, values[i]->bv_len) == 0)) {
				RDEBUG("User found in group \"%s\". Comparison between membership: name, check: name",
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
					RDEBUG("User found in group DN \"%s\". "
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
			ret = rlm_ldap_group_dn2name(inst, request, pconn, check->vp_strvalue, &resolved);
			REXDENT();
			if (ret != RLM_MODULE_OK) {
				rcode = ret;
				goto finish;
			}

			if (((talloc_array_length(resolved) - 1) == values[i]->bv_len) &&
			    (memcmp(values[i]->bv_val, resolved, values[i]->bv_len) == 0)) eq = true;
			talloc_free(resolved);
			if (eq) {
				RDEBUG("User found in group \"%.*s\". Comparison between membership: name, check: name "
				       "(resolved from DN \"%s\")", (int)values[i]->bv_len,
				       values[i]->bv_val, check->vp_strvalue);
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

			value = rlm_ldap_berval_to_string(request, values[i]);
			RINDENT();
			ret = rlm_ldap_group_dn2name(inst, request, pconn, value, &resolved);
			REXDENT();
			talloc_free(value);
			if (ret != RLM_MODULE_OK) {
				rcode = ret;
				goto finish;
			}

			if (((talloc_array_length(resolved) - 1) == check->vp_length) &&
			    (memcmp(check->vp_strvalue, resolved, check->vp_length) == 0)) eq = true;
			talloc_free(resolved);
			if (eq) {
				RDEBUG("User found in group \"%s\". Comparison between membership: name "
				       "(resolved from DN \"%s\"), check: name", check->vp_strvalue, value);
				rcode = RLM_MODULE_OK;

				goto finish;
			}

			continue;
		}
		rad_assert(0);
	}

finish:
	if (values) ldap_value_free_len(values);
	if (result) ldap_msgfree(result);

	return rcode;
}

/** Check group membership attributes to see if a user is a member.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in] check vp containing the group value (name or dn).
 *
 * @return One of the RLM_MODULE_* values.
 */
rlm_rcode_t rlm_ldap_check_cached(rlm_ldap_t const *inst, REQUEST *request, VALUE_PAIR *check)
{
	VALUE_PAIR	*vp;
	int		ret;
	vp_cursor_t	cursor;

	fr_cursor_init(&cursor, &request->config);

	/*
	 *	We return RLM_MODULE_INVALID here as an indication
	 *	the caller should try a dynamic group lookup instead.
	 */
	vp = fr_cursor_next_by_num(&cursor, inst->cache_da->attr, inst->cache_da->vendor, TAG_ANY);
	if (!vp) return RLM_MODULE_INVALID;
	fr_cursor_first(&cursor);

	while ((vp = fr_cursor_next_by_num(&cursor, inst->cache_da->attr, inst->cache_da->vendor, TAG_ANY))) {
		ret = fr_pair_cmp_op(T_OP_CMP_EQ, vp, check);
		if (ret == 1) {
			RDEBUG2("User found. Matched cached membership");
			return RLM_MODULE_OK;
		}

		if (ret < -1) {
			return RLM_MODULE_FAIL;
		}
	}

	RDEBUG2("Cached membership not found");
	return RLM_MODULE_NOTFOUND;
}
