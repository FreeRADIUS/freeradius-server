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
 * @copyright 2013 Network RADIUS SARL (legal@networkradius.com)
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

	switch (map->lhs->type) {
	/*
	 *	Iterate over all the retrieved values,
	 *	don't try and be clever about changing operators
	 *	just use whatever was set in the attribute map.
	 */
	case TMPL_TYPE_ATTR:
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
		break;

	default:
		fr_assert(0);
	}

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
	case TMPL_TYPE_UNRESOLVED:
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
 * @param[out] expanded array of attributes. Need not be initialised (we'll initialise).
 * @param[in] request The current request.
 * @param[in] maps to expand.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_map_expand(fr_ldap_map_exp_t *expanded, request_t *request, map_list_t const *maps)
{
	map_t const	*map = NULL;
	unsigned int	total = 0;

	TALLOC_CTX	*ctx = NULL;
	char const	*attr;
	char		attr_buff[1024 + 1];	/* X.501 says we need to support at least 1024 chars for attr names */

	while ((map = map_list_next(maps, map))) {
		if (tmpl_expand(&attr, attr_buff, sizeof(attr_buff), request, map->rhs, NULL, NULL) < 0) {
			REDEBUG("Expansion of LDAP attribute \"%s\" failed", map->rhs->name);
			TALLOC_FREE(ctx);
			return -1;
		}

		/*
		 *	Dynamic value
		 */
		if (attr == attr_buff) {
			if (!ctx) ctx = talloc_new(NULL);
			expanded->attrs[total++] = talloc_strdup(ctx, attr_buff);
			continue;
		}
		expanded->attrs[total++] = attr;
	}
	expanded->attrs[total] = NULL;
	expanded->ctx = ctx;	/* Freeing this frees any dynamic values */
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
 * @param[in] valuepair_attr	Treat attribute with this name as holding complete AVP definitions.
 * @param[in] expanded		attributes (rhs of map).
 * @param[in] entry		to retrieve attributes from.
 * @return
 *	- Number of maps successfully applied.
 *	- -1 on failure.
 */
int fr_ldap_map_do(request_t *request,
		   char const *valuepair_attr, fr_ldap_map_exp_t const *expanded, LDAPMessage *entry)
{
	map_t const		*map = NULL;
	unsigned int		total = 0;
	int			applied = 0;	/* How many maps have been applied to the current request */

	fr_ldap_result_t	result;
	char const		*name;
	LDAP			*handle = fr_ldap_handle_thread_local();

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

			tmpl_rules_t parse_rules = {
				.attr = {
					.ctx = tmpl_attr_ctx_rules_default(NULL, NULL, request->dict),
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				}
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
