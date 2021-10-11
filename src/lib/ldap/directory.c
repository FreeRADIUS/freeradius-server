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
 * @file lib/ldap/directory.c
 * @brief Determine remote server implementation and capabilities.
 *
 * As described by http://ldapwiki.willeke.com/wiki/Determine%20LDAP%20Server%20Vendor
 *
 * @copyright 2016 The FreeRADIUS Server Project.
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS name

#include <freeradius-devel/ldap/base.h>

static fr_table_num_sorted_t const fr_ldap_directory_type_table[] = {
	{ L("Active Directory"),		FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY		},
	{ L("IBM"),			FR_LDAP_DIRECTORY_IBM				},
	{ L("NetScape"),			FR_LDAP_DIRECTORY_NETSCAPE			},
	{ L("OpenLDAP"),			FR_LDAP_DIRECTORY_OPENLDAP			},
	{ L("Oracle Internet Directory"),	FR_LDAP_DIRECTORY_ORACLE_INTERNET_DIRECTORY 	},
	{ L("Oracle Unified Directory"),	FR_LDAP_DIRECTORY_ORACLE_UNIFIED_DIRECTORY	},
	{ L("Oracle Virtual Directory"),	FR_LDAP_DIRECTORY_ORACLE_VIRTUAL_DIRECTORY	},
	{ L("Siemens AG"),			FR_LDAP_DIRECTORY_SIEMENS_AG			},
	{ L("Sun One Directory"),		FR_LDAP_DIRECTORY_SUN_ONE_DIRECTORY		},
	{ L("Unbound ID"),			FR_LDAP_DIRECTORY_UNBOUND_ID			},
	{ L("Unknown"),			FR_LDAP_DIRECTORY_UNKNOWN			},
	{ L("eDirectory"),			FR_LDAP_DIRECTORY_EDIRECTORY			}
};
static size_t fr_ldap_directory_type_table_len = NUM_ELEMENTS(fr_ldap_directory_type_table);

static int ldap_directory_result_parse(fr_ldap_directory_t *directory, LDAP *handle,
				       LDAPMessage *result, char const *name)
{
	int			entry_cnt, i, num, ldap_errno;
	LDAPMessage		*entry;
	struct berval		**values = NULL;

	entry_cnt = ldap_count_entries(handle, result);
	if (entry_cnt != 1) {
		WARN("Capability check failed: Ambiguous result for rootDSE, expected 1 entry, got %i", entry_cnt);
		return 1;
	}

	entry = ldap_first_entry(handle, result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);

		WARN("Capability check failed: Failed retrieving entry: %s", ldap_err2string(ldap_errno));
		return 1;
	}

	values = ldap_get_values_len(handle, entry, "vendorname");
	if (values) {
		directory->vendor_str = fr_ldap_berval_to_string(directory, values[0]);
		INFO("Directory vendor: %s", directory->vendor_str);

		ldap_value_free_len(values);
	}

	values = ldap_get_values_len(handle, entry, "vendorversion");
	if (values) {
		directory->version_str = fr_ldap_berval_to_string(directory, values[0]);
		INFO("Directory version: %s", directory->version_str);

		ldap_value_free_len(values);
	}

	if (directory->vendor_str) {
		if (strcasestr(directory->vendor_str, "International Business Machines")) {
			directory->type = FR_LDAP_DIRECTORY_EDIRECTORY;
		}

		goto found;
	}

	if (directory->version_str) {
		/*
		 *	Novell eDirectory vendorversion contains eDirectory
		 */
		if (strcasestr(directory->version_str, "eDirectory")) {
			directory->type = FR_LDAP_DIRECTORY_EDIRECTORY;
		/*
		 *	Oracle unified directory vendorversion contains Oracle Unified Directory
		 */
		} else if (strcasestr(directory->version_str, "Oracle Unified Directory")) {
			directory->type = FR_LDAP_DIRECTORY_ORACLE_UNIFIED_DIRECTORY;
		/*
		 *	Unbound directory vendorversion contains UnboundID
		 */
		} else if (strcasestr(directory->version_str, "UnboundID")) {
			directory->type = FR_LDAP_DIRECTORY_UNBOUND_ID;
		/*
		 *	NetScape directory venderversion contains Netscape-Directory
		 */
		} else if (strcasestr(directory->version_str, "Netscape-Directory")) {
			directory->type = FR_LDAP_DIRECTORY_NETSCAPE;
		/*
		 *	Siemens AG directory vendorversion contains DirX Directory
		 */
		} else if (strcasestr(directory->version_str, "DirX Directory")) {
			directory->type = FR_LDAP_DIRECTORY_SIEMENS_AG;
		/*
		 *	Sun One Directory vendorversion contains Sun Java
		 */
		} else if (strcasestr(directory->version_str, "Sun Java")) {
			directory->type = FR_LDAP_DIRECTORY_SUN_ONE_DIRECTORY;
		}
		goto found;
	}

	/*
	 *	isGlobalCatalogReady is only present on ActiveDirectory
	 *	instances. AD doesn't provide vendorname or vendorversion
	 */
	values = ldap_get_values_len(handle, entry, "isGlobalCatalogReady");
	if (values) {
		directory->type = FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY;
		ldap_value_free_len(values);
		goto found;
	}

	/*
	 *	OpenLDAP has a special objectClass for its RootDSE
	 */
	values = ldap_get_values_len(handle, entry, "objectClass");
	if (values) {
		num = ldap_count_values_len(values);
		for (i = 0; i < num; i++) {
			if (strncmp("OpenLDAProotDSE", values[i]->bv_val, values[i]->bv_len) == 0) {
				directory->type = FR_LDAP_DIRECTORY_OPENLDAP;
			}
		}
		ldap_value_free_len(values);
		goto found;
	}

	/*
	 *	Oracle Virtual Directory and Oracle Internet Directory
	 */
	values = ldap_get_values_len(handle, entry, "orcldirectoryversion");
	if (values) {
		if (memmem(values[0]->bv_val, values[0]->bv_len, "OID", 3)) {
			directory->type = FR_LDAP_DIRECTORY_ORACLE_INTERNET_DIRECTORY;
		} else if (memmem(values[0]->bv_val, values[0]->bv_len, "OVD", 3)) {
			directory->type = FR_LDAP_DIRECTORY_ORACLE_VIRTUAL_DIRECTORY;
		}
		ldap_value_free_len(values);
	}

found:
	INFO("Directory type: %s", fr_table_str_by_value(fr_ldap_directory_type_table, directory->type, "<INVALID>"));

	switch (directory->type) {
	case FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY:
	case FR_LDAP_DIRECTORY_EDIRECTORY:
		directory->cleartext_password = false;
		break;

	default:
		directory->cleartext_password = true;
		break;
	}

	return 0;
}

/** Extract useful information from the rootDSE of the LDAP server
 *
 * @param[in] ctx	to allocate fr_ldap_directory_t in.
 * @param[out] out	where to write pointer to new fr_ldap_directory_t struct.
 * @param[in,out] pconn	connection for querying the directory.
 * @return
 *	- 0 on success.
 *	- 1 if we failed identifying the directory server.
 *	- -1 on error.
 */
int fr_ldap_directory_alloc(TALLOC_CTX *ctx, fr_ldap_directory_t **out, fr_ldap_connection_t **pconn)
{
	static char const	*attrs[] = { "vendorname",
					     "vendorversion",
					     "isGlobalCatalogReady",
					     "objectClass",
					     "orcldirectoryversion",
					     NULL };
	fr_ldap_rcode_t		status;
	int			rcode = 0;
	fr_ldap_directory_t	*directory;
	char const		*name = (*pconn)->config->name;

	LDAPMessage *result = NULL;

	*out = NULL;

	directory = talloc_zero(ctx, fr_ldap_directory_t);
	if (!directory) return -2;
	*out = directory;

	directory->type = FR_LDAP_DIRECTORY_UNKNOWN;

	status = fr_ldap_search(&result, NULL, pconn, "", LDAP_SCOPE_BASE, "(objectclass=*)",
				attrs, NULL, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_NO_RESULT:
		WARN("Capability check failed: Can't access rootDSE");
		rcode = 1;
		goto finish;

	default:
		rcode = 1;
		goto finish;
	}

	rcode = ldap_directory_result_parse(directory, (*pconn)->handle, result, name);

finish:
	if (result) ldap_msgfree(result);

	return rcode;
}

/** Parse results of search on rootDSE to gather data on LDAP server
 *
 * @param[in] query	which requested the rootDSE.
 * @param[in] result	head of LDAP results message chain.
 */
static void ldap_trunk_directory_alloc_read(fr_ldap_query_t *query, LDAPMessage *result)
{
	fr_ldap_thread_trunk_t	*ttrunk = query->ttrunk;
	fr_ldap_config_t const	*config = query->ldap_conn->config;

	(void)ldap_directory_result_parse(ttrunk->directory, query->ldap_conn->handle, result, config->name);
}

/** Async extract useful information from the rootDSE of the LDAP server
 *
 * This is called once for each new thread trunk when it first connects.
 *
 * @param[in] ctx	to allocate fr_ldap_directory_t in.
 * @param[in] ttrunk	Thread trunk connection to be queried
 * @return
 *	- 0 on success
 *	< 0 on failure
 */
int fr_ldap_trunk_directory_alloc_async(TALLOC_CTX *ctx, fr_ldap_thread_trunk_t *ttrunk)
{
	fr_ldap_query_t		*query;

	ttrunk->directory = talloc_zero(ctx, fr_ldap_directory_t);
	if (!ttrunk->directory) return -1;

	ttrunk->directory->type = FR_LDAP_DIRECTORY_UNKNOWN;

	query = fr_ldap_query_alloc(ctx);
	query->type = LDAP_REQUEST_SEARCH;
	query->ttrunk = ttrunk;
	query->parser = ldap_trunk_directory_alloc_read;
	ldap_url_parse("ldap:///?vendorname,vendorversion,isGlobalCatalogReady,objectClass,orcldirectoryversion"
		       "?base?(objectClass=*)", &query->ldap_url);

	fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, NULL, query, NULL);

	return 0;
}
