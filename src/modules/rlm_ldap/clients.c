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
 * @copyright 2013,2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013-2015 The FreeRADIUS Server Project.
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
 * @return
 *	- 0 on success.
 *	- -1 on failure.
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

typedef struct ldap_client_data {
	ldap_handle_t *conn;
	LDAPMessage *entry;
} ldap_client_data_t;

static int _get_client_value(char **out, CONF_PAIR const *cp, void *data)
{
	struct berval **values;
	ldap_client_data_t *this = data;

	values = ldap_get_values_len(this->conn->handle, this->entry, cf_pair_value(cp));
	if (!values) {
		*out = NULL;
		return 0;
	}

	*out = rlm_ldap_berval_to_string(NULL, values[0]);
	ldap_value_free_len(values);

	if (!*out) return -1;
	return 0;
}

/** Load clients from LDAP on server start
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] tmpl to use as the base for the new client.
 * @param[in] map to load client attribute/LDAP attribute mappings from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rlm_ldap_client_load(rlm_ldap_t const *inst, CONF_SECTION *tmpl, CONF_SECTION *map)
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

	count = cf_pair_count(map);
	count++;

	/*
	 *	Create an array of LDAP attributes to feed to rlm_ldap_search.
	 */
	attrs = talloc_array(inst, char const *, count);
	if (rlm_ldap_client_get_attrs(attrs, &idx, map) < 0) {
		talloc_free(attrs);
		return -1;
	}

	conn = mod_conn_get(inst, NULL);
	if (!conn) {
		talloc_free(attrs);
		return -1;
	}

	/*
	 *	Perform all searches as the admin user.
	 */
	if (conn->rebound) {
		status = rlm_ldap_bind(inst, NULL, &conn, conn->inst->admin_identity, conn->inst->admin_password,
				       &(conn->inst->admin_sasl), true);
		if (status != LDAP_PROC_SUCCESS) {
			ret = -1;
			goto finish;
		}

		rad_assert(conn);

		conn->rebound = false;
	}

	status = rlm_ldap_search(&result, inst, NULL, &conn, inst->clientobj_base_dn, inst->clientobj_scope,
				 inst->clientobj_filter, attrs, NULL, NULL);
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
		ldap_client_data_t	data;

		CONF_SECTION		*client;
		char			*id;

		struct berval		**values;

		id = dn = ldap_get_dn(conn->handle, entry);
		if (!dn) {
			int ldap_errno;

			ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
			LDAP_ERR("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

			goto finish;
		}
		rlm_ldap_normalise_dn(dn, dn);

		cp = cf_pair_find(map, "identifier");
		if (cp) {
			values = ldap_get_values_len(conn->handle, entry, cf_pair_value(cp));
			if (values) id = rlm_ldap_berval_to_string(NULL, values[0]);
			ldap_value_free_len(values);
		}

		/*
		 *	Iterate over mapping sections
		 */
		client = tmpl ? cf_section_dup(NULL, tmpl, "client", id, true) :
				cf_section_alloc(NULL, "client", id);

		data.conn = conn;
		data.entry = entry;

		if (client_map_section(client, map, _get_client_value, &data) < 0) {
			talloc_free(client);
			ret = -1;
			goto finish;
		}

		/*
		 *@todo these should be parented from something
		 */
		c = client_afrom_cs(NULL, client, false, false);
		if (!c) {
			talloc_free(client);
			ret = -1;
			goto finish;
		}

		/*
		 *	Client parents the CONF_SECTION which defined it
		 */
		talloc_steal(c, client);

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

