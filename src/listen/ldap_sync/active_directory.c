/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * @file active_directory.c
 * @brief LDAP sync callback functions for Active Directory servers.
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */

#define LOG_PREFIX "ldap_sync_ad"

#include "active_directory.h"
#include <freeradius-devel/util/debug.h>

static int active_directory_sync_attr_add(char const *attr, void *uctx)
{
	sync_config_t	*config = uctx;

	return ldap_sync_conf_attr_add(config, attr);
}

/** Allocate a sync state structure and issue the search
 *
 * Active Directory uses its own control to mark persistent searches.
 * In addition we add the control to request the return of deleted objects
 * which allows searches specifically on the Deleted Objects container.
 *
 * Neither of these controls take values.
 *
 * @param[in] conn 		Connection to issue the search request on.
 * @param[in] sync_no		number of the sync in the array of configs.
 * @param[in] inst		instance of ldap_sync this query relates to.
 * @param[in] cookie		unused for Active Directory
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int active_directory_sync_state_init(fr_ldap_connection_t *conn, size_t sync_no, proto_ldap_sync_t const *inst,
				     UNUSED uint8_t const *cookie)
{
	static char const	*notify_oid = LDAP_SERVER_NOTIFICATION_OID;
	static char const	*deleted_oid = LDAP_SERVER_SHOW_DELETED_OID;
	LDAPControl		ctrl = {0}, ctrl2 = {0}, *ctrls[3] = { &ctrl, &ctrl2, NULL };
	fr_slen_t		ret;
	fr_ldap_rcode_t		rcode;
	sync_state_t		*sync;
	fr_rb_tree_t		*tree;
	char const		*filter = NULL;
	sync_config_t const	*config = inst->sync_config[sync_no];

	fr_assert(conn);
	fr_assert(config);

	/*
	 *	Allocate or retrieve the tree of outstanding msgids
	 *	these are specific to the connection.
	 */
	if (!conn->uctx) {
		MEM(tree = fr_rb_inline_talloc_alloc(conn, sync_state_t, node, sync_state_cmp, NULL));
		conn->uctx = tree;
	} else {
		tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);
	}

	sync = sync_state_alloc(tree, conn, inst, sync_no, config);

	/*
	 *	Notification control - marks this as a persistent search.
	 */
	memcpy(&ctrl.ldctl_oid, &notify_oid, sizeof(ctrl.ldctl_oid));
	ctrl.ldctl_value.bv_len = 0;
	ctrl.ldctl_value.bv_val = NULL;
	ctrl.ldctl_iscritical = 1;

	/*
	 *	Show deleted control - instructs the server to include deleted
	 *	objects in the reply.
	 */
	memcpy(&ctrl2.ldctl_oid, &deleted_oid, sizeof(ctrl2.ldctl_oid));
	ctrl2.ldctl_value.bv_len = 0;
	ctrl2.ldctl_value.bv_val = NULL;
	ctrl2.ldctl_iscritical = 1;
	ctrls[1] = &ctrl2;
	ctrl2.ldctl_iscritical = 1;

	/*
	 *	Active Directory only takes the filter (objectClass=*) when the
	 *	notification control is used.  To compensate for this we parse the
	 *	filter and implement our own basic version of a filter.
	 */
	if (strcasecmp(sync->config->filter, "(objectClass=*)") != 0) {
		DEBUG2("LDAP filter %s does not match Active Directory requirements, parsing for local filtering.",
			sync->config->filter);
		filter = "(objectClass=*)";
		ret = fr_ldap_filter_parse(sync, &sync->filter, &FR_SBUFF_IN(config->filter, strlen(config->filter)),
					   active_directory_sync_attr_add, UNCONST(sync_config_t *,config));
		if (ret < 0) {
			CONF_ITEM	*ci;

			ci = (CONF_ITEM *)cf_pair_find(sync->config->cs, "filter");
			cf_log_err(ci, "Invalid LDAP filter");
			EMARKER(config->filter, ret + 1, fr_strerror());

		error:
			talloc_free(sync);
			return -1;
		}
	}

	/*
	 *	The isDeleted attribute needs to be in the requested list
	 *	in order to detect if a notification is because an entry is deleted
	 */
	ldap_sync_conf_attr_add(UNCONST(sync_config_t *, config), "isDeleted");

	rcode = fr_ldap_search_async(&sync->msgid, NULL, &conn, config->base_dn, config->scope,
				     filter ? filter : config->filter, config->attrs, ctrls, NULL);

	if (rcode != LDAP_PROC_SUCCESS) goto error;

	if (!fr_rb_insert(tree, sync)) {
		ERROR("Duplicate sync (msgid %i)", sync->msgid);
		goto error;
	}

	DEBUG3("Sync created with msgid %i", sync->msgid);

	return 0;
}
/** Handle a LDAP_RES_SEARCH_ENTRY (SearchResultEntry) response
 *
 * This version is specific to Active Directory, which does things its own way.
 *
 * In response to a search request containing the Server Notification Control, Active Directory
 * will initially return nothing.
 *
 * Then as entries matching the query are changed, SearchResultEntry messages will be returned
 * for the matching entries.  There is no indication as to whether the change is an addition or
 * a modification.
 *
 * In order to be notified about deleted objects, the Recycle Bin optional feature must be enabled
 * and the search must have a base DN which includes the Deleted Objects container, then,
 * an attribute isDeleted will indicate the state of the entry.
 *
 * @param[in] sync	message was associated with.
 * @param[in] msg	containing an entry to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int active_directory_sync_search_entry(sync_state_t *sync, LDAPMessage *msg, UNUSED LDAPControl **ctrls)
{
	int		count, i, ret = 0;
	sync_op_t	op = SYNC_OP_MODIFY;
	struct berval	**values;

	fr_assert(sync->conn);
	fr_assert(sync);
	fr_assert(msg);

	/*
	 *	Implement our own filtering if the config has specified
	 *	something other than (objectClass=*)
	 */
	if (sync->filter && !fr_ldap_filter_eval(sync->filter, sync->conn, msg)) {
		DEBUG2("Discarding packet which fails LDAP filter");
		ldap_msgfree(msg);
		return 0;
	}

	/*
	 *	Look for an "isDeleted" attribute - this is Active Directory's indicator
	 *	for a deleted object - process these through the recv Delete section.
	 */
	values = ldap_get_values_len(sync->conn->handle, msg, "isDeleted");
	count = ldap_count_values_len(values);
	for (i = 0; i < count; i++) {
		if ((values[i]->bv_len == 4) && (strncmp(values[i]->bv_val, "TRUE", 4) == 0)) {
			op = SYNC_OP_DELETE;
			break;
		}
	}
	ldap_value_free_len(values);

	/*
	 *  Send the packet with the entry change notification
	 */
	ret = ldap_sync_entry_send(sync, NULL, NULL, msg, op);

	return ret;
}
