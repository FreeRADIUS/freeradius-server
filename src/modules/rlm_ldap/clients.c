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
 * @file clients.c
 * @brief LDAP module dynamic clients.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 The FreeRADIUS Server Project.
 */
#include	<freeradius-devel/rad_assert.h>
#include	<ctype.h>

#include	"ldap.h"

/** Iterate over pairs in mapping section recording their values in an array
 *
 * This array is the list of attributes we retrieve from LDAP, and is NULL
 * terminated.
 *
 * If we hit a CONF_SECTION we recurse and process its CONF_PAIRS too.
 *
 * @param[out] values array of char pointers.
 * @param[in,out] idx records current array offset.
 * @param[in] cs to iterate over.
 * @return 0 on success else -1 on error.
 */
static int rlm_ldap_client_get_attrs(char const **values, int *idx, CONF_SECTION const *cs)
{
	CONF_ITEM const *ci;

	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {
	     	char const *value;

		if (cf_item_is_section(ci)) {
			if (rlm_ldap_client_get_attrs(values, idx, cf_item_to_section(ci)) < 0) return -1;
			continue;
		}

		value = cf_pair_value(cf_item_to_pair(ci));
		if (!value) return -1;

		values[(*idx)++] = value;
	}

	values[*idx] = NULL;

	return 0;
}

/** Iterate over pairs in mapping section creating equivalent client pairs from LDAP values
 *
 * If we hit a CONF_SECTION we recurse and process its CONF_PAIRS too.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[out] client config section.
 * @param[in] map section.
 * @param[in] conn LDAP connection.
 * @param[in] entry returned from search.
 * @return 0 on success else -1 on error.
 */
static int rlm_ldap_client_map_section(ldap_instance_t const *inst, CONF_SECTION *client,
				       CONF_SECTION const *map, ldap_handle_t *conn,
				       LDAPMessage *entry)
{
	CONF_ITEM const *ci;

	for (ci = cf_item_find_next(map, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(map, ci)) {
	     	CONF_PAIR const *cp;
	     	struct berval **values;
	     	char *value;
		char const *attr;

		/*
		 *	Recursively process map subsection
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *cs, *cc;

			cs = cf_item_to_section(ci);
			cc = cf_section_alloc(client, cf_section_name1(cs), cf_section_name2(cs));
			if (!cc) return -1;

			cf_section_add(client, cc);

			if (rlm_ldap_client_map_section(inst, cc, cs, conn, entry) < 0) return -1;
			continue;
		}

		cp = cf_item_to_pair(ci);
		attr = cf_pair_attr(cp);

		values = ldap_get_values_len(conn->handle, entry, cf_pair_value(cp));
		if (!values) continue;

		value = rlm_ldap_berval_to_string(NULL, values[0]);
		cp = cf_pair_alloc(client, attr, value, T_OP_SET, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
		if (!cp) {
			LDAP_ERR("Failed allocing pair \"%s\" = \"%s\"", attr, value);
			talloc_free(value);
			return -1;
		}
		talloc_free(value);
		ldap_value_free_len(values);
		cf_item_add(client, cf_pair_to_item(cp));
	}

	return 0;
}

/** Load clients from LDAP on server start
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] cs to load client attribute/LDAP attribute mappings from.
 * @return -1 on error else 0.
 */
int rlm_ldap_client_load(ldap_instance_t const *inst, CONF_SECTION *cs)
{
	int 		ret = 0;
	ldap_rcode_t	status;
	ldap_handle_t	*conn = NULL;

	char const	**attrs = NULL;

	CONF_PAIR	*cp;
	int		count = 0, idx = 0;

	LDAPMessage	*result = NULL;
	LDAPMessage	*entry;
	char		*dn = NULL;

	RADCLIENT	*c;

	LDAP_DBG("Loading dynamic clients");

	rad_assert(inst->clientobj_base_dn);

	if (!inst->clientobj_filter) {
		LDAP_ERR("Told to load clients but 'client.filter' not specified");

		return -1;
	}

	count = cf_pair_count(cs);
	count++;

	/*
	 *	Create an array of LDAP attributes to feed to rlm_ldap_search.
	 */
	attrs = talloc_array(inst, char const *, count);
	if (rlm_ldap_client_get_attrs(attrs, &idx, cs) < 0) return -1;

	conn = mod_conn_get(inst, NULL);
	if (!conn) return -1;

	/*
	 *	Perform all searches as the admin user.
	 */
	if (conn->rebound) {
		status = rlm_ldap_bind(inst, NULL, &conn, conn->inst->admin_dn, conn->inst->password,
				       conn->inst->admin_sasl_mech, true);
		if (status != LDAP_PROC_SUCCESS) {
			ret = -1;
			goto finish;
		}

		rad_assert(conn);

		conn->rebound = false;
	}

	status = rlm_ldap_search(inst, NULL, &conn, inst->clientobj_base_dn, inst->clientobj_scope,
				 inst->clientobj_filter, attrs, &result);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		LDAP_INFO("No clients were found in the directory");
		ret = 0;
		goto finish;

	default:
		ret = -1;
		goto finish;
	}

	rad_assert(conn);
	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		int ldap_errno;

		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		LDAP_ERR("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		ret = -1;
		goto finish;
	}

	do {
		CONF_SECTION *cc;
		char *id;

		struct berval **values;
		char *value = NULL;

		id = dn = ldap_get_dn(conn->handle, entry);
		if (!dn) {
			int ldap_errno;

			ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
			LDAP_ERR("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

			goto finish;
		}
		rlm_ldap_normalise_dn(dn, dn);

		cp = cf_pair_find(cs, "identifier");
		if (cp) {
			values = ldap_get_values_len(conn->handle, entry, cf_pair_value(cp));
			if (values) id = rlm_ldap_berval_to_string(NULL, values[0]);
			ldap_value_free_len(values);
		}

		/*
		 *	Iterate over mapping sections
		 */
		cc = cf_section_alloc(NULL, "client", id);
		talloc_free(value);

		if (rlm_ldap_client_map_section(inst, cc, cs, conn, entry) < 0) {
			talloc_free(cc);
			ret = -1;
			goto finish;
		}

		/*
		 *@todo these should be parented from something
		 */
		c = client_afrom_cs(NULL, cc, false, false);
		if (!c) {
			talloc_free(cc);
			ret = -1;
			goto finish;
		}

		/*
		 *	Client parents the CONF_SECTION which defined it
		 */
		talloc_steal(c, cc);

		if (!client_add(NULL, c)) {
			LDAP_ERR("Failed to add client \"%s\", possible duplicate?", dn);
			ret = -1;
			client_free(c);
			goto finish;
		}

		LDAP_DBG("Client \"%s\" added", dn);

		ldap_memfree(dn);
		dn = NULL;
	} while ((entry = ldap_next_entry(conn->handle, entry)));

finish:
	talloc_free(attrs);
	if (dn) ldap_memfree(dn);
	if (result) ldap_msgfree(result);

	mod_conn_release(inst, conn);

	return ret;
}

