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
static int rlm_ldap_map_getvalue(VALUE_PAIR **out, REQUEST *request, value_pair_map_t const *map, void *ctx)
{
	rlm_ldap_result_t *self = ctx;
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
			value_pair_map_t *attr = NULL;

			RDEBUG3("Parsing valuepair string \"%s\"", self->values[i]->bv_val);
			if (map_afrom_attr_str(request, &attr, self->values[i]->bv_val,
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

			if (map_to_vp(&vp, request, attr, NULL) < 0) {
				RWDEBUG("Failed creating attribute for valuepair \"%s\", skipping...",
					self->values[i]->bv_val);
				goto next_pair;
			}

			fr_cursor_merge(&cursor, vp);
			talloc_free(attr);
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

			vp = pairalloc(request, map->lhs->tmpl_da);
			rad_assert(vp);

			if (pairparsevalue(vp, self->values[i]->bv_val, self->values[i]->bv_len) < 0) {
				char *escaped;

				escaped = fr_aprints(vp, self->values[i]->bv_val, self->values[i]->bv_len, '"');
				RWDEBUG("Failed parsing value \"%s\" for attribute %s: %s", escaped,
					map->lhs->tmpl_da->name, fr_strerror());

				talloc_free(vp); /* also frees escaped */
				continue;
			}

			vp->op = map->op;
			fr_cursor_insert(&cursor, vp);
		}
		break;

	default:
		rad_assert(0);
	}

	*out = head;

	return 0;
}

int rlm_ldap_map_verify(value_pair_map_t *map, void *instance)
{
	ldap_instance_t *inst = instance;

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
	 *	Only =, :=, += and -= operators are supported for LDAP mappings.
	 */
	switch (map->op) {
	case T_OP_SET:
	case T_OP_EQ:
	case T_OP_SUB:
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

/** Free attribute map values
 *
 */
void rlm_ldap_map_xlat_free(rlm_ldap_map_xlat_t const *expanded)
{
	value_pair_map_t const *map;
	unsigned int total = 0;

	char const *name;

	for (map = expanded->maps; map != NULL; map = map->next) {
		name = expanded->attrs[total++];
		if (!name) return;

		switch (map->rhs->type) {
		case TMPL_TYPE_EXEC:
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_ATTR:
			rad_const_free(name);
			break;
		default:
			break;
		}
	}
}

/** Expand values in an attribute map where needed
 *
 */
int rlm_ldap_map_xlat(REQUEST *request, value_pair_map_t const *maps, rlm_ldap_map_xlat_t *expanded)
{
	value_pair_map_t const *map;
	unsigned int total = 0;

	VALUE_PAIR *found, **from = NULL;
	REQUEST *context;

	for (map = maps; map != NULL; map = map->next) {
		switch (map->rhs->type) {
		case TMPL_TYPE_XLAT:
		{
			ssize_t len;
			char *exp = NULL;

			len = radius_axlat(&exp, request, map->rhs->name, NULL, NULL);
			if (len < 0) {
				RDEBUG("Expansion of LDAP attribute \"%s\" failed", map->rhs->name);

				goto error;
			}

			expanded->attrs[total++] = exp;
			break;
		}

		case TMPL_TYPE_ATTR:
			context = request;

			if (radius_request(&context, map->rhs->tmpl_request) == 0) {
				from = radius_list(context, map->rhs->tmpl_list);
			}
			if (!from) continue;

			found = pair_find_by_da(*from, map->rhs->tmpl_da, TAG_ANY);
			if (!found) continue;

			expanded->attrs[total++] = talloc_typed_strdup(request, found->vp_strvalue);
			break;

		case TMPL_TYPE_EXEC:
		{
			char answer[1024];
			VALUE_PAIR **input_pairs = NULL;
			int result;

			input_pairs = radius_list(request, PAIR_LIST_REQUEST);
			result = radius_exec_program(answer, sizeof(answer), NULL, request,
						     map->rhs->name, input_pairs ? *input_pairs : NULL,
						     true, true, EXEC_TIMEOUT);
			if (result != 0) {
				return -1;
			}

			expanded->attrs[total++] = talloc_typed_strdup(request, answer);
		}
			break;

		case TMPL_TYPE_LITERAL:
			expanded->attrs[total++] = map->rhs->name;
			break;

		default:
			rad_assert(0);
		error:
			expanded->attrs[total] = NULL;

			rlm_ldap_map_xlat_free(expanded);

			return -1;
		}
	}

	rad_assert(total < LDAP_MAX_ATTRMAP);

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
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in] handle associated with entry.
 * @param[in] expanded attributes (rhs of map).
 * @param[in] entry to retrieve attributes from.
 * @return number of maps successfully applied, or -1 on error.
 */
int rlm_ldap_map_do(const ldap_instance_t *inst, REQUEST *request, LDAP *handle,
		    rlm_ldap_map_xlat_t const *expanded, LDAPMessage *entry)
{
	value_pair_map_t const 	*map;
	unsigned int		total = 0;
	int			applied = 0;	/* How many maps have been applied to the current request */

	rlm_ldap_result_t	result;
	char const		*name;

	RINDENT();
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
	REXDENT();

	/*
	 *	Retrieve any valuepair attributes from the result, these are generic values specifying
	 *	a radius list, operator and value.
	 */
	if (inst->valuepair_attr) {
		struct berval	**values;
		int		count, i;

		values = ldap_get_values_len(handle, entry, inst->valuepair_attr);
		count = ldap_count_values_len(values);

		RINDENT();
		for (i = 0; i < count; i++) {
			value_pair_map_t *attr;
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
		REXDENT();
		ldap_value_free_len(values);
	}

	return applied;
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common sets of attributes
 * to the request.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn of profile object to apply.
 * @param[in] expanded Structure containing a list of xlat expanded attribute names and mapping information.
 * @return One of the RLM_MODULE_* values.
 */
rlm_rcode_t rlm_ldap_map_profile(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
				 char const *dn, rlm_ldap_map_xlat_t const *expanded)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	ldap_rcode_t	status;
	LDAPMessage	*result = NULL, *entry = NULL;
	int		ldap_errno;
	LDAP		*handle = (*pconn)->handle;
	char const	*filter;
	char		filter_buff[LDAP_MAX_FILTER_STR_LEN];

	rad_assert(inst->profile_filter); 	/* We always have a default filter set */

	if (!dn || !*dn) return RLM_MODULE_OK;

	if (tmpl_expand(&filter, filter_buff, sizeof(filter_buff), request,
			inst->profile_filter, rlm_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating profile filter");

		return RLM_MODULE_INVALID;
	}

	status = rlm_ldap_search(&result, inst, request, pconn, dn,
				 LDAP_SCOPE_BASE, filter, expanded->attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_BAD_DN:
	case LDAP_PROC_NO_RESULT:
		RDEBUG("Profile object \"%s\" not found", dn);
		return RLM_MODULE_NOTFOUND;

	default:
		return RLM_MODULE_FAIL;
	}

	rad_assert(*pconn);
	rad_assert(result);

	entry = ldap_first_entry(handle, result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		rcode = RLM_MODULE_NOTFOUND;

		goto free_result;
	}

	RDEBUG("Processing profile attributes");
	RINDENT();
	if (rlm_ldap_map_do(inst, request, handle, expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
	REXDENT();

free_result:
	ldap_msgfree(result);

	return rcode;
}

