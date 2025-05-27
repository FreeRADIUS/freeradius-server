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
 * @file ldap.c
 * @brief Functions for mapping between LDAP and FreeRADIUS attributes.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2013 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/rad_assert.h>
#include "ldap.h"

/** Callback for map_to_request
 *
 * Performs exactly the same job as map_to_vp, but pulls attribute values from LDAP entries
 *
 * @see map_to_vp
 */
int rlm_ldap_map_getvalue(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map, void *uctx)
{
	rlm_ldap_result_t *self = uctx;
	VALUE_PAIR *head = NULL, *vp;
	vp_cursor_t cursor;
	int i;

	fr_cursor_init(&cursor, &head);

	switch (map->lhs->type) {
	/*
	 *	This is a mapping in the form of:
	 *		<list>: += <ldap attr>
	 *
	 *	Where <ldap attr> is:
	 *		<list>:<attr> <op> <value>
	 *
	 *	It is to allow for legacy installations which stored
	 *	RADIUS control and reply attributes in separate LDAP
	 *	attributes.
	 */
	case TMPL_TYPE_LIST:
		for (i = 0; i < self->count; i++) {
			vp_map_t *attr = NULL;

			RDEBUG3("Parsing valuepair string \"%s\"", self->values[i]->bv_val);
			if (map_afrom_attr_str(ctx, &attr, self->values[i]->bv_val,
					       map->lhs->tmpl_request, map->lhs->tmpl_list,
					       REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
				RWDEBUG("Failed parsing \"%s\" as valuepair (%s), skipping...", fr_strerror(),
					self->values[i]->bv_val);
				continue;
			}

			if (attr->lhs->tmpl_request != map->lhs->tmpl_request) {
				RWDEBUG("valuepair \"%s\" has conflicting request qualifier (%s vs %s), skipping...",
					self->values[i]->bv_val,
					fr_int2str(request_refs, attr->lhs->tmpl_request, "<INVALID>"),
					fr_int2str(request_refs, map->lhs->tmpl_request, "<INVALID>"));
			next_pair:
				talloc_free(attr);
				continue;
			}

			if ((attr->lhs->tmpl_list != map->lhs->tmpl_list)) {
				RWDEBUG("valuepair \"%s\" has conflicting list qualifier (%s vs %s), skipping...",
					self->values[i]->bv_val,
					fr_int2str(pair_lists, attr->lhs->tmpl_list, "<INVALID>"),
					fr_int2str(pair_lists, map->lhs->tmpl_list, "<INVALID>"));
				goto next_pair;
			}

			if (map_to_vp(request, &vp, request, attr, NULL) < 0) {
				RWDEBUG("Failed creating attribute for valuepair \"%s\", skipping...",
					self->values[i]->bv_val);
				goto next_pair;
			}

			fr_cursor_merge(&cursor, vp);
			talloc_free(attr);

			/*
			 *	Only process the first value, unless the operator is +=
			 */
			if (map->op != T_OP_ADD) break;
		}
		break;

	/*
	 *	Iterate over all the retrieved values,
	 *	don't try and be clever about changing operators
	 *	just use whatever was set in the attribute map.
	 */
	case TMPL_TYPE_ATTR:
		for (i = 0; i < self->count; i++) {
			if (!self->values[i]->bv_len) continue;

			RDEBUG3("Parsing %s = %s", map->lhs->name, self->values[i]->bv_val);

			vp = fr_pair_afrom_da(ctx, map->lhs->tmpl_da);
			rad_assert(vp);

			vp->op = map->op;
			vp->tag = map->lhs->tmpl_tag;

			if (fr_pair_value_from_str(vp, self->values[i]->bv_val, self->values[i]->bv_len) < 0) {
				char *escaped;

				escaped = fr_aprints(vp, self->values[i]->bv_val, self->values[i]->bv_len, '"');
				RWDEBUG("Failed parsing value \"%s\" for attribute %s: %s", escaped,
					map->lhs->tmpl_da->name, fr_strerror());

				talloc_free(vp); /* also frees escaped */
				continue;
			}

			fr_cursor_insert(&cursor, vp);

			/*
			 *	Only process the first value, unless the operator is +=
			 */
			if (map->op != T_OP_ADD) break;
		}
		break;

	default:
		rad_assert(0);
	}

	*out = head;

	return 0;
}

int rlm_ldap_map_verify(vp_map_t *map, void *instance)
{
	rlm_ldap_t *inst = instance;

	/*
	 *	Destinations where we can put the VALUE_PAIRs we
	 *	create using LDAP values.
	 */
	switch (map->lhs->type) {
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR:
		break;

	case TMPL_TYPE_ATTR_UNDEFINED:
		cf_log_err(map->ci, "Unknown attribute %s", map->lhs->tmpl_unknown_name);
		return -1;

	default:
		cf_log_err(map->ci, "Left hand side of map must be an attribute or list, not a %s",
			   fr_int2str(tmpl_names, map->lhs->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Sources we can use to get the name of the attribute
	 *	we're retrieving from LDAP.
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_LITERAL:
		break;

	case TMPL_TYPE_ATTR_UNDEFINED:
		cf_log_err(map->ci, "Unknown attribute %s", map->rhs->tmpl_unknown_name);
		return -1;

	default:
		cf_log_err(map->ci, "Right hand side of map must be an xlat, attribute, exec, or literal, not a %s",
			   fr_int2str(tmpl_names, map->rhs->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Only =, :=, and += aoperators are supported for LDAP mappings.
	 */
	switch (map->op) {
	case T_OP_SET:
	case T_OP_EQ:
	case T_OP_ADD:
		break;

	default:
		cf_log_err(map->ci, "Operator \"%s\" not allowed for LDAP mappings",
			   fr_int2str(fr_tokens, map->op, "<INVALID>"));
		return -1;
	}

	/*
	 *	Be smart about whether we warn the user about missing passwords.
	 *	If there are no password attributes in the mapping, then the user's either an idiot
	 *	and has no idea what they're doing, or they're authenticating the user using a different
	 *	method.
	 */
	if (!inst->expect_password && (map->lhs->type == TMPL_TYPE_ATTR) && map->lhs->tmpl_da) {
		switch (map->lhs->tmpl_da->attr) {
		case PW_CLEARTEXT_PASSWORD:
		case PW_NT_PASSWORD:
		case PW_USER_PASSWORD:
		case PW_PASSWORD_WITH_HEADER:
		case PW_CRYPT_PASSWORD:
			/*
			 *	Because you just know someone is going to map NT-Password to the
			 *	request list, and then complain it's not working...
			 */
			if (map->lhs->tmpl_list != PAIR_LIST_CONTROL) {
				LDAP_DBGW("Mapping LDAP (%s) attribute to \"known good\" password attribute "
					  "(%s) in %s list. This is probably *NOT* the correct list, "
					  "you should prepend \"control:\" to password attribute "
					  "(control:%s)",
					  map->rhs->name, map->lhs->tmpl_da->name,
					  fr_int2str(pair_lists, map->lhs->tmpl_list, "<invalid>"),
					  map->lhs->tmpl_da->name);
			}

			inst->expect_password = true;
		default:
			break;
		}
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
int rlm_ldap_map_expand(rlm_ldap_map_exp_t *expanded, REQUEST *request, vp_map_t const *maps)
{
	vp_map_t const	*map;
	unsigned int	total = 0;

	TALLOC_CTX	*ctx = NULL;
	char const	*attr;
	char		attr_buff[1024 + 1];	/* X.501 says we need to support at least 1024 chars for attr names */

	for (map = maps; map != NULL; map = map->next) {
		if (tmpl_expand(&attr, attr_buff, sizeof(attr_buff), request, map->rhs, NULL, NULL) < 0) {
			RDEBUG("Expansion of LDAP attribute \"%s\" failed", map->rhs->name);
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
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in] handle associated with entry.
 * @param[in] expanded attributes (rhs of map).
 * @param[in] entry to retrieve attributes from.
 * @return
 *	- Number of maps successfully applied.
 *	- -1 on failure.
 */
int rlm_ldap_map_do(const rlm_ldap_t *inst, REQUEST *request, LDAP *handle,
		    rlm_ldap_map_exp_t const *expanded, LDAPMessage *entry)
{
	vp_map_t const 	*map;
	unsigned int		total = 0;
	int			applied = 0;	/* How many maps have been applied to the current request */

	rlm_ldap_result_t	result;
	char const		*name;

	for (map = expanded->maps; map != NULL; map = map->next) {
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
		ret = map_to_request(request, map, rlm_ldap_map_getvalue, &result);
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
	if (inst->valuepair_attr) {
		struct berval	**values;
		int		count, i;

		values = ldap_get_values_len(handle, entry, inst->valuepair_attr);
		count = ldap_count_values_len(values);

		for (i = 0; i < count; i++) {
			vp_map_t *attr;
			char *value;

			value = rlm_ldap_berval_to_string(request, values[i]);
			RDEBUG3("Parsing attribute string '%s'", value);
			if (map_afrom_attr_str(request, &attr, value,
					       REQUEST_CURRENT, PAIR_LIST_REPLY,
					       REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
				RWDEBUG("Failed parsing '%s' value \"%s\" as valuepair (%s), skipping...",
					fr_strerror(), inst->valuepair_attr, value);
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
