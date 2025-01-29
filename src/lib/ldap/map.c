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
 * @file src/lib/ldap/map.c
 * @brief Functions for mapping between LDAP and FreeRADIUS attributes.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/ldap/base.h>

/** Callback for map_to_request
 *
 * Performs exactly the same job as map_to_vp, but pulls attribute values from LDAP entries
 *
 * @see map_to_vp
 */
int fr_ldap_map_getvalue(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, map_t const *map, void *uctx)
{
	fr_ldap_result_t	*self = uctx;
	fr_pair_list_t		head;
	fr_pair_list_t		tmp_list;
	fr_pair_t		*vp;
	int			i;

	fr_pair_list_init(&head);
	fr_pair_list_init(&tmp_list);

	fr_assert(map->lhs->type == TMPL_TYPE_ATTR);

	/*
	 *	This is a mapping in the form of:
	 *		<list>. += <ldap attr>
	 *
	 *	Where <ldap attr> is:
	 *		<list>.<attr> <op> <value>
	 *
	 *	It is to allow for legacy installations which stored
	 *	RADIUS control and reply attributes in separate LDAP
	 *	attributes.
	 */
	if (tmpl_is_list(map->lhs)) {
		for (i = 0; i < self->count; i++) {
			map_t	*attr = NULL;
			char	*attr_str;

			tmpl_rules_t	lhs_rules = {
				.attr = {
					.dict_def = request->dict,
					.request_def = tmpl_request(map->lhs),
					.list_def = tmpl_list(map->lhs),
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				},
				.xlat = {
					.runtime_el = unlang_interpret_event_list(request),
				},
				.at_runtime = true,
			};

			tmpl_rules_t rhs_rules = {
				.attr = {
					.dict_def = request->dict
				},
				.xlat = {
					.runtime_el = lhs_rules.xlat.runtime_el,
				},
				.at_runtime = true,
			};

			RDEBUG3("Parsing valuepair string \"%pV\"",
				fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len));

			/*
			 *	bv_val is NOT \0 terminated, so we need to make it
			 *	safe (\0 terminate it) before passing it to any
			 *	functions which take C strings and no lengths.
			 */
			attr_str = talloc_bstrndup(NULL, self->values[i]->bv_val, self->values[i]->bv_len);
			if (!attr_str) {
				RWDEBUG("Failed making attribute string safe");
				continue;
			}

			if (map_afrom_attr_str(ctx, &attr,
					       attr_str,
					       &lhs_rules, &rhs_rules) < 0) {
				RPWDEBUG("Failed parsing \"%pV\" as valuepair, skipping...",
					 fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len));
				talloc_free(attr_str);
				continue;
			}

			talloc_free(attr_str);

			if (tmpl_is_data_unresolved(attr->lhs)) {
			    RWDEBUG("Failed parsing left side of \"%pV\", skipping...",
					fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len));
				talloc_free(attr);
				continue;
			}

			if (tmpl_request_ref_list_cmp(tmpl_request(attr->lhs), tmpl_request(map->lhs)) != 0) {
				char *attr_request;
				char *map_request;

				tmpl_request_ref_list_aprint(NULL, &attr_request, tmpl_request(attr->lhs));
				tmpl_request_ref_list_aprint(NULL, &map_request, tmpl_request(map->lhs));

				RWDEBUG("valuepair \"%pV\" has conflicting request qualifier (%s vs %s), skipping...",
					fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len),
					attr_request, map_request);

				talloc_free(attr_request);
				talloc_free(map_request);

			next_pair:
				talloc_free(attr);
				continue;
			}

			if ((tmpl_list(attr->lhs) != tmpl_list(map->lhs))) {
				RWDEBUG("valuepair \"%pV\" has conflicting list qualifier (%s vs %s), skipping...",
					fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len),
					tmpl_list_name(tmpl_list(attr->lhs), "<INVALID>"),
					tmpl_list_name(tmpl_list(map->lhs), "<INVALID>"));
				goto next_pair;
			}

			if (map_to_request(request, attr, map_to_vp, NULL) < 0) {
				RWDEBUG("Failed creating attribute for valuepair \"%pV\", skipping...",
					fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len));
				goto next_pair;
			}

			talloc_free(attr);

			/*
			 *	Only process the first value, unless the operator is +=
			 */
			if (map->op != T_OP_ADD_EQ) break;
		}
		goto finish;
	}

	/*
	 *	Iterate over all the retrieved values,
	 *	don't try and be clever about changing operators
	 *	just use whatever was set in the attribute map.
	 */
	for (i = 0; i < self->count; i++) {
		if (!self->values[i]->bv_len) continue;

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs)));

		if (fr_pair_value_from_str(vp, self->values[i]->bv_val,
					   self->values[i]->bv_len, NULL, true) < 0) {
			RPWDEBUG("Failed parsing value \"%pV\" for attribute %s",
				 fr_box_strvalue_len(self->values[i]->bv_val, self->values[i]->bv_len),
				 tmpl_attr_tail_da(map->lhs)->name);

			talloc_free(vp); /* also frees escaped */
			continue;
		}

		fr_pair_append(&head, vp);

		/*
		 *	Only process the first value, unless the operator is +=
		 */
		if (map->op != T_OP_ADD_EQ) break;
	}

finish:
	fr_pair_list_append(out, &head);

	return 0;
}

int fr_ldap_map_verify(map_t *map, UNUSED void *instance)
{
	/*
	 *	Destinations where we can put the fr_pair_ts we
	 *	create using LDAP values.
	 */
	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
		break;

	case TMPL_TYPE_ATTR_UNRESOLVED:
		cf_log_err(map->ci, "Unknown attribute %s", tmpl_attr_tail_unresolved(map->lhs));
		return -1;

	default:
		cf_log_err(map->ci, "Left hand side of map must be an attribute or list, not a %s",
			   tmpl_type_to_str(map->lhs->type));
		return -1;
	}

	/*
	 *	Sources we can use to get the name of the attribute
	 *	we're retrieving from LDAP.
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_DATA_UNRESOLVED:
		break;

	case TMPL_TYPE_ATTR_UNRESOLVED:
		cf_log_err(map->ci, "Unknown attribute %s", tmpl_attr_tail_unresolved(map->rhs));
		return -1;

	default:
		cf_log_err(map->ci, "Right hand side of map must be an xlat, attribute, exec, or literal, not a %s",
			   tmpl_type_to_str(map->rhs->type));
		return -1;
	}

	/*
	 *	Only =, :=, += and -= operators are supported for LDAP mappings.
	 */
	switch (map->op) {
	case T_OP_SET:
	case T_OP_EQ:
	case T_OP_SUB_EQ:
	case T_OP_ADD_EQ:
		break;

	default:
		cf_log_err(map->ci, "Operator \"%s\" not allowed for LDAP mappings",
			   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		return -1;
	}

	return 0;
}

/** Expand values in an attribute map where needed
 *
 * @param[in] ctx		o allocate any dynamic expansions in.
 * @param[out] expanded		array of attributes. Need not be initialised (we'll initialise).
 * @param[in] request		The current request.
 * @param[in] maps		to expand.
 * @param[in] generic_attr	name to append to the attribute list.
 * @param[in] check_attr	name to append to the attribute list.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_map_expand(TALLOC_CTX *ctx, fr_ldap_map_exp_t *expanded, request_t *request, map_list_t const *maps,
		       char const *generic_attr, char const *check_attr)
{
	map_t const	*map = NULL;
	unsigned int	total = 0;

	TALLOC_CTX	*our_ctx = NULL;
	char const	*attr;
	char		attr_buff[1024 + 1];	/* X.501 says we need to support at least 1024 chars for attr names */

	while ((map = map_list_next(maps, map))) {
		if (tmpl_expand(&attr, attr_buff, sizeof(attr_buff), request, map->rhs, NULL, NULL) < 0) {
			REDEBUG("Expansion of LDAP attribute \"%s\" failed", map->rhs->name);
			TALLOC_FREE(our_ctx);
			return -1;
		}

		/*
		 *	Dynamic value
		 */
		if (attr == attr_buff) {
			if (!our_ctx) our_ctx = talloc_new(ctx);
			expanded->attrs[total++] = talloc_strdup(our_ctx, attr_buff);
			continue;
		}
		expanded->attrs[total++] = attr;
	}

	if (generic_attr) expanded->attrs[total++] = generic_attr;
	if (check_attr) expanded->attrs[total++] = check_attr;

	expanded->attrs[total] = NULL;
	expanded->count = total;
	expanded->maps = maps;

	return 0;
}


/** Convert attribute map into valuepairs
 *
 * Use the attribute map built earlier to convert LDAP values into valuepairs and insert them into whichever
 * list they need to go into.
 *
 * This is *NOT* atomic, but there's no condition for which we should error out...
 *
 * @param[in] request		Current request.
 * @param[in] check_attr	Treat attribute with this name as a condition to process the map.
 * @param[in] valuepair_attr	Treat attribute with this name as holding complete AVP definitions.
 * @param[in] expanded		attributes (rhs of map).
 * @param[in] entry		to retrieve attributes from.
 * @return
 *	- Number of maps successfully applied.
 *	- -1 on failure.
 */
int fr_ldap_map_do(request_t *request, char const *check_attr,
		   char const *valuepair_attr, fr_ldap_map_exp_t const *expanded, LDAPMessage *entry)
{
	map_t const		*map = NULL;
	unsigned int		total = 0;
	int			applied = 0;	/* How many maps have been applied to the current request */

	fr_ldap_result_t	result;
	char const		*name;
	LDAP			*handle = fr_ldap_handle_thread_local();

	if (check_attr) {
		struct berval	**values;
		int		count, i;
		tmpl_rules_t const parse_rules = {
			.attr = {
				.dict_def = request->dict,
				.list_def = request_attr_request,
				.prefix = TMPL_ATTR_REF_PREFIX_AUTO
			},
			.xlat = {
				.runtime_el = unlang_interpret_event_list(request),
			},
			.at_runtime = true,
		};

		values = ldap_get_values_len(handle, entry, check_attr);
		count = ldap_count_values_len(values);

		for (i = 0; i < count; i++) {
			map_t	*check = NULL;
			char	*value = fr_ldap_berval_to_string(request, values[i]);

			RDEBUG3("Parsing condition %s", value);
			if (map_afrom_attr_str(request, &check, value, &parse_rules, &parse_rules) < 0) {
				RPEDEBUG("Failed parsing '%s' value \"%s\"", check_attr, value);
			fail:
				applied = -1;
			free:
				talloc_free(check);
				talloc_free(value);
				ldap_value_free_len(values);
				return applied;
			}

			if (!fr_comparison_op[check->op]) {
				REDEBUG("Invalid operator '%s'", fr_tokens[check->op]);
				goto fail;
			}

			if (fr_type_is_structural(tmpl_attr_tail_da(check->lhs)->type) &&
			    (check->op != T_OP_CMP_TRUE) && (check->op != T_OP_CMP_FALSE)) {
				REDEBUG("Invalid comparison for structural type");
				goto fail;
			}

			RDEBUG2("Checking condition %s %s %s", check->lhs->name, fr_tokens[check->op], check->rhs->name);
			if (radius_legacy_map_cmp(request, check) != 1) {
				RDEBUG2("Failed match: skipping this profile");
				goto free;
			}
			talloc_free(value);
			talloc_free(check);
		}
		ldap_value_free_len(values);
	}

	while ((map = map_list_next(expanded->maps, map))) {
		int ret;

		name = expanded->attrs[total++];

		/*
		 *	Binary safe
		 */
		result.values = ldap_get_values_len(handle, entry, name);
		if (!result.values) {
			RDEBUG3("Attribute \"%s\" not found in LDAP object", name);

			goto next;
		}

		/*
		 *	Find out how many values there are for the
		 *	attribute and extract all of them.
		 */
		result.count = ldap_count_values_len(result.values);

		/*
		 *	If something bad happened, just skip, this is probably
		 *	a case of the dst being incorrect for the current
		 *	request context
		 */
		ret = map_to_request(request, map, fr_ldap_map_getvalue, &result);
		if (ret == -1) return -1;	/* Fail */

		/*
		 *	How many maps we've processed
		 */
		applied++;

	next:
		ldap_value_free_len(result.values);
	}


	/*
	 *	Retrieve any valuepair attributes from the result, these are generic values specifying
	 *	a radius list, operator and value.
	 */
	if (valuepair_attr) {
		struct berval	**values;
		int		count, i;

		values = ldap_get_values_len(handle, entry, valuepair_attr);
		count = ldap_count_values_len(values);

		for (i = 0; i < count; i++) {
			map_t	*attr;
			char		*value;

			tmpl_rules_t const parse_rules = {
				.attr = {
					.dict_def = request->dict,
					.list_def = request_attr_request,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				},
				.xlat = {
					.runtime_el = unlang_interpret_event_list(request),
				},
				.at_runtime = true,
			};

			value = fr_ldap_berval_to_string(request, values[i]);
			RDEBUG3("Parsing attribute string '%s'", value);
			if (map_afrom_attr_str(request, &attr, value,
					       &parse_rules, &parse_rules) < 0) {
				RPWDEBUG("Failed parsing '%s' value \"%s\" as valuepair, skipping...",
					 valuepair_attr, value);
				talloc_free(value);
				continue;
			}
			if (map_to_request(request, attr, map_to_vp, NULL) < 0) {
				RWDEBUG("Failed adding \"%s\" to request, skipping...", value);
			} else {
				applied++;
			}
			talloc_free(attr);
			talloc_free(value);
		}
		ldap_value_free_len(values);
	}

	return applied;
}
