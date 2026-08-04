/*
 *   This program is free software; you can redistribute it and/or modify
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

#define LOG_PREFIX name

#include <freeradius-devel/ldap/base.h>

static fr_table_num_sorted_t const fr_ldap_directory_type_table[] = {
	{ L("Active Directory"),		FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY		},
	{ L("IBM"),				FR_LDAP_DIRECTORY_IBM				},
	{ L("NetScape"),			FR_LDAP_DIRECTORY_NETSCAPE			},
	{ L("OpenLDAP"),			FR_LDAP_DIRECTORY_OPENLDAP			},
	{ L("Oracle Internet Directory"),	FR_LDAP_DIRECTORY_ORACLE_INTERNET_DIRECTORY 	},
	{ L("Oracle Unified Directory"),	FR_LDAP_DIRECTORY_ORACLE_UNIFIED_DIRECTORY	},
	{ L("Oracle Virtual Directory"),	FR_LDAP_DIRECTORY_ORACLE_VIRTUAL_DIRECTORY	},
	{ L("Samba"),				FR_LDAP_DIRECTORY_SAMBA				},
	{ L("Siemens AG"),			FR_LDAP_DIRECTORY_SIEMENS_AG			},
	{ L("Sun One Directory"),		FR_LDAP_DIRECTORY_SUN_ONE_DIRECTORY		},
	{ L("Unbound ID"),			FR_LDAP_DIRECTORY_UNBOUND_ID			},
	{ L("Unknown"),				FR_LDAP_DIRECTORY_UNKNOWN			},
	{ L("eDirectory"),			FR_LDAP_DIRECTORY_EDIRECTORY			}
};
static size_t fr_ldap_directory_type_table_len = NUM_ELEMENTS(fr_ldap_directory_type_table);

/** Hash a naming context, case insensitively
 *
 */
static uint32_t _naming_context_hash(void const *data)
{
	return fr_hash_case_string(data);
}

/** Compare two naming contexts, case insensitively
 *
 */
static int8_t _naming_context_cmp(void const *one, void const *two)
{
	return CMP(strcasecmp(one, two), 0);
}

int fr_ldap_directory_result_parse(fr_ldap_directory_t *directory, LDAP *handle,
				   LDAPMessage *result, char const *name)
{
	int			entry_cnt, i, num, ldap_errno;
	LDAPMessage		*entry;
	struct berval		**values = NULL;
	struct berval		value;
	talloc_str_list_t	*list;
	char const * const	*context_p;

	/*
	 *	Connections spawned concurrently may each run discovery
	 *	against a shared directory, only parse the first response.
	 */
	if (directory->discovered) return 0;

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
	directory->discovered = true;

	if (fr_ldap_entry_value_find(&value, handle, entry, "vendorname") > 0) {
		directory->vendor_str = fr_ldap_berval_to_string(directory, &value);
		INFO("Directory vendor: %s", directory->vendor_str);
	}

	if (fr_ldap_entry_value_find(&value, handle, entry, "vendorversion") > 0) {
		directory->version_str = fr_ldap_berval_to_string(directory, &value);
		INFO("Directory version: %s", directory->version_str);
	}

	if (directory->vendor_str) {
		if (strcasestr(directory->vendor_str, "International Business Machines")) {
			directory->type = FR_LDAP_DIRECTORY_IBM;
		} else if (strcasestr(directory->vendor_str, "Samba Team")) {
			directory->type = FR_LDAP_DIRECTORY_SAMBA;
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
	if (fr_ldap_entry_value_find(&value, handle, entry, "isGlobalCatalogReady") > 0) {
		directory->type = FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY;
		goto found;
	}

	/*
	 *	OpenLDAP has a special objectClass for its RootDSE
	 */
	values = ldap_get_values_len(handle, entry, "objectClass");
	if (values) {
		num = ldap_count_values_len(values);
		for (i = 0; i < num; i++) {
			if ((values[i]->bv_len == sizeof("OpenLDAProotDSE") - 1) &&
			    (memcmp("OpenLDAProotDSE", values[i]->bv_val, values[i]->bv_len) == 0)) {
				directory->type = FR_LDAP_DIRECTORY_OPENLDAP;
			}
		}
		ldap_value_free_len(values);
		goto found;
	}

	/*
	 *	Oracle Virtual Directory and Oracle Internet Directory
	 */
	if (fr_ldap_entry_value_find(&value, handle, entry, "orcldirectoryversion") > 0) {
		if (memmem(value.bv_val, value.bv_len, "OID", 3)) {
			directory->type = FR_LDAP_DIRECTORY_ORACLE_INTERNET_DIRECTORY;
		} else if (memmem(value.bv_val, value.bv_len, "OVD", 3)) {
			directory->type = FR_LDAP_DIRECTORY_ORACLE_VIRTUAL_DIRECTORY;
		}
	}

found:
	INFO("Directory type: %s", fr_table_str_by_value(fr_ldap_directory_type_table, directory->type, "<INVALID>"));

	switch (directory->type) {
	/*
	 *	Active Directory and Samba don't implement RFC 5020 entryDN,
	 *	but allow equality matches on distinguishedName instead.
	 */
	case FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY:
	case FR_LDAP_DIRECTORY_SAMBA:
		directory->dn_attr = "distinguishedName";
		directory->cleartext_password = false;
		break;

	case FR_LDAP_DIRECTORY_EDIRECTORY:
		directory->cleartext_password = false;
		break;

	default:
		directory->cleartext_password = true;
		break;
	}

	/*
	 *	Evaluate what type of sync the directory supports
	 */
	values = ldap_get_values_len(handle, entry, "supportedControl");
	if (values) {
		num = ldap_count_values_len(values);
		for (i = 0; i < num; i++) {
			if ((values[i]->bv_len == strlen(LDAP_CONTROL_SYNC)) &&
			    (memcmp(LDAP_CONTROL_SYNC, values[i]->bv_val, values[i]->bv_len) == 0)) {
				INFO("Directory supports RFC 4533");
				directory->sync_type = FR_LDAP_SYNC_RFC4533;
				break;
			}
			if ((values[i]->bv_len == strlen(LDAP_SERVER_NOTIFICATION_OID)) &&
			    (memcmp(LDAP_SERVER_NOTIFICATION_OID, values[i]->bv_val, values[i]->bv_len) == 0)) {
				INFO("Directory supports LDAP_SERVER_NOTIFICATION_OID");
				directory->sync_type = FR_LDAP_SYNC_ACTIVE_DIRECTORY;
				break;
			}
			if ((values[i]->bv_len == strlen(LDAP_CONTROL_PERSIST_REQUEST)) &&
			    (memcmp(LDAP_CONTROL_PERSIST_REQUEST, values[i]->bv_val, values[i]->bv_len) == 0)) {
				INFO("Directory supports persistent search");
				directory->sync_type = FR_LDAP_SYNC_PERSISTENT_SEARCH;
				break;
			}
		}
		ldap_value_free_len(values);
	} else {
		WARN("No supportedControl returned by LDAP server");
	}

	/*
	 *	Extract naming contexts
	 */
	list = fr_ldap_str_list_afrom_result(directory, handle, result, "namingContexts", 0);
	if (unlikely(!list)) {
		WARN("Capability check failed: %s", fr_strerror());
		return 1;
	}
	if (talloc_str_list_num(list) == 0) {
		talloc_free(list);
		return 0;
	}

	directory->naming_contexts = list->strings;
	MEM(directory->naming_contexts_ht = fr_hash_table_alloc(directory, _naming_context_hash,
								_naming_context_cmp, NULL));
	for (context_p = list->strings; context_p < list->p; context_p++) {
		fr_hash_table_insert(directory->naming_contexts_ht, *context_p);
	}

	return 0;
}

/** Allocate a directory structure with defaults
 *
 * dn_attr defaults to the RFC 5020 entryDN attribute, overridden when
 * parsing the rootDSE detects a directory which doesn't implement entryDN.
 */
fr_ldap_directory_t *fr_ldap_directory_alloc(TALLOC_CTX *ctx)
{
	fr_ldap_directory_t *directory;

	MEM(directory = talloc_zero(ctx, fr_ldap_directory_t));
	directory->dn_attr = "entryDN";

	return directory;
}

/** Find the naming context which contains a set of DNs
 *
 * Looks up successively shorter suffixes of each DN in the hash table of
 * naming contexts (database suffixes) built when the rootDSE was parsed,
 * and returns the naming context containing every DN.  A search with the
 * returned base covers all the DNs.
 *
 * @param[in] directory	Directory discovery results, providing the naming contexts.
 * @param[in] dn_list	NULL terminated list of DNs to cover, no empty strings.
 * @return
 *	- The matching naming context.
 *	- NULL if the directory hasn't been discovered yet, or no single
 *	  naming context contains every DN.
 */
char const *fr_ldap_directory_common_base_find(fr_ldap_directory_t const *directory, char const * const *dn_list)
{
	char const		*common = NULL;
	char const * const	*dn_p;

	if (!directory->naming_contexts_ht) return NULL;

	for (dn_p = dn_list; *dn_p; dn_p++) {
		char const	*context = NULL;
		char const	*p = *dn_p;

		/*
		 *	Check successively shorter suffixes of the DN,
		 *	starting after each RDN separator.
		 */
		while (p) {
			context = fr_hash_table_find(directory->naming_contexts_ht, p);
			if (context) break;

			p = strchr(p, ',');
			if (p) p++;
		}
		if (!context) return NULL;

		/*
		 *	Lookups return the stored string, so pointer
		 *	comparison is enough to check every DN resolved
		 *	to the same naming context.
		 */
		if (!common) {
			common = context;
			continue;
		}
		if (common != context) return NULL;
	}

	return common;
}

/** State of an in progress rootDSE search on a connection being established
 *
 */
typedef struct {
	fr_ldap_connection_t	*c;			//!< Connection the rootDSE search was sent on.
	int			msgid;			//!< Of the outstanding rootDSE search.
} ldap_directory_discover_ctx_t;

/** Error reading from or writing to the file descriptor
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	The error that occurred.
 * @param[in] uctx	discover_ctx containing the connection and message ID.
 */
static void _ldap_directory_discover_io_error(UNUSED fr_event_list_t *el, UNUSED int fd,
					      UNUSED int flags, UNUSED int fd_errno, void *uctx)
{
	ldap_directory_discover_ctx_t	*discover_ctx = talloc_get_type_abort(uctx, ldap_directory_discover_ctx_t);
	fr_ldap_connection_t		*c = discover_ctx->c;

	talloc_free(discover_ctx);
	fr_ldap_state_error(c);			/* Restart the connection state machine */
}

/** Parse a rootDSE response from a server
 *
 * A failure parsing the rootDSE leaves the directory with its defaults, the
 * connection is still usable, so the state machine advances either way.
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	discover_ctx containing the connection and message ID.
 */
static void _ldap_directory_discover_io_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	ldap_directory_discover_ctx_t	*discover_ctx = talloc_get_type_abort(uctx, ldap_directory_discover_ctx_t);
	fr_ldap_connection_t		*c = discover_ctx->c;
	char const			*name = c->config->name;
	LDAPMessage			*result = NULL;

	fr_ldap_rcode_t			status;

	status = fr_ldap_result(&result, NULL, c, discover_ctx->msgid, LDAP_MSG_ALL, "", fr_time_delta_wrap(0));
	if (status == LDAP_PROC_SUCCESS) {
		(void)fr_ldap_directory_result_parse(c->directory, c->handle, result, name);
	} else {
		PWARN("Directory discovery failed, proceeding without directory capability data");
	}
	if (result) ldap_msgfree(result);

	fr_ldap_state_next(c);			/* onto the next operation */

	talloc_free(discover_ctx);		/* Also removes fd events */
}

/** Send a rootDSE search on a connection being established
 *
 * Called by the connection state machine after binding, so the directory
 * capabilities (vendor, naming contexts) are known before the connection
 * starts serving requests.  Results are parsed into c->directory.
 *
 * @param[in] c		LDAP connection to be queried.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_directory_discover_async(fr_ldap_connection_t *c)
{
	static char const		*attrs[] = LDAP_DIRECTORY_ATTRS;
	ldap_directory_discover_ctx_t	*discover_ctx;
	int				fd = -1;

	MEM(discover_ctx = talloc_zero(c, ldap_directory_discover_ctx_t));
	discover_ctx->c = c;

	if (fr_ldap_search_async(&discover_ctx->msgid, NULL, c, "", LDAP_SCOPE_BASE, "(objectclass=*)",
				 attrs, NULL, NULL) != LDAP_PROC_SUCCESS) {
	error:
		talloc_free(discover_ctx);
		return -1;
	}

	if ((ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) != LDAP_OPT_SUCCESS) || (fd < 0)) goto error;

	if (fr_event_fd_insert(discover_ctx, NULL, c->conn->el, fd,
			       _ldap_directory_discover_io_read,
			       NULL,
			       _ldap_directory_discover_io_error,
			       discover_ctx) < 0) goto error;

	fr_ldap_connection_timeout_reset(c);

	return 0;
}

/** Asynchronously extract useful information from the rootDSE of the LDAP server
 *
 * This version is for a single connection rather than a connection trunk
 *
 * @param[in] ldap_conn	connection to be queried
 * @return
 *	- message ID on success
 *	< 0 on failure
 */
int fr_ldap_conn_directory_alloc_async(fr_ldap_connection_t *ldap_conn)
{
	int			msgid;
	static char const	*attrs[] = LDAP_DIRECTORY_ATTRS;

	ldap_conn->directory = fr_ldap_directory_alloc(ldap_conn);

	if (fr_ldap_search_async(&msgid, NULL, ldap_conn, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs,
				 NULL, NULL) != LDAP_PROC_SUCCESS) return -1;

	return msgid;
}
