/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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

 /** Load clients from LDAP on server start
  *
  * @param[in] inst rlm_ldap configuration.
  * @return -1 on error else 0.
  */
int rlm_ldap_load_clients(ldap_instance_t const *inst, CONF_SECTION *cs)
{
	int 		ret = 0;
	ldap_rcode_t	status;
	ldap_handle_t	*conn = NULL;

	char const	**attrs = NULL;
	char const	**attrs_p;

	CONF_ITEM	*ci;
	CONF_PAIR	*cp;
	int		count = 1;	/* +1 for NULL termination */

	LDAPMessage	*result = NULL;
	LDAPMessage	*entry;

	RADCLIENT	*c;

	LDAP_DBG("Loading dynamic clients");

	rad_assert(inst->clientobj_base_dn);

	if (!inst->clientobj_filter) {
		LDAP_ERR("Told to load clients but 'client.filter' not specified");

		return -1;
	}

	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"attribute = value\" format");
			return -1;
		}

		count++;
	}

	/*
	 *	Create an array of LDAP attributes to feed to rlm_ldap_search.
	 */
	attrs_p = attrs = talloc_array(inst, char const *, count);
	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {
	     	char const *value;

		cp = cf_itemtopair(ci);
		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err(ci, "Failed getting LDAP attribute name");
			talloc_free(attrs);
			return -1;
		}

		*attrs_p++ = value;
	}
	*attrs_p = NULL;

	conn = rlm_ldap_get_socket(inst, NULL);
	if (!conn) return -1;

	/*
	 *	Perform all searches as the admin user.
	 */
	if (conn->rebound) {
		status = rlm_ldap_bind(inst, NULL, &conn, inst->admin_dn, inst->password, true);
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
		char *dn = NULL, *id;

		char **value;

		id = dn = ldap_get_dn(conn->handle, entry);
		cp = cf_pair_find(cs, "identifier");
		if (cp) {
			value = ldap_get_values(conn->handle, entry, cf_pair_value(cp));
			if (value) id = value[0];
		}

		cc = cf_section_alloc(NULL, "client", id);

		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
		     	char const *attr;

			cp = cf_itemtopair(ci);
		     	attr = cf_pair_attr(cp);

			value = ldap_get_values(conn->handle, entry, cf_pair_value(cp));
			if (!value) continue;

			cp = cf_pair_alloc(cc, attr, value[0], T_OP_SET, T_SINGLE_QUOTED_STRING);
			if (!cp) {
				LDAP_ERR("Failed allocing pair \"%s\" = \"%s\"", attr, value[0]);
				ret = -1;
				goto finish;
			}
			cf_item_add(cc, cf_pairtoitem(cp));
		}

		/*
		 * @todo these should be parented from something
		 */
		c = client_afrom_cs(NULL, cc, false);
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
	} while ((entry = ldap_next_entry(conn->handle, entry)));

finish:
	talloc_free(attrs);
	if (dn) ldap_memfree(dn);
	if (result) ldap_msgfree(result);

	rlm_ldap_release_socket(inst, conn);

	return ret;
}

