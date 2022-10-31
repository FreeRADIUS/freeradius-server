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
 * @file persistent_search.c
 * @brief LDAP sync callback functions for servers implementing persistent search.
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */

#define LOG_PREFIX "ldap_sync_persistent"

#include "persistent_search.h"
#include "proto_ldap_sync_ldap.h"
#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/util/debug.h>

/** Allocate and initialise sync queries for persistent searches.
 *
 * Servers implementing https://tools.ietf.org/id/draft-ietf-ldapext-psearch-03.txt
 *
 * The persisntent search control is defined as
 *
 *  PersistentSearch ::= SEQUENCE {
 *	changeTypes INTEGER,
 *	changesOnly BOOLEAN
 *	returnECs BOOLEAN
 *  }
 *
 * The sync structure is parented off the conn.  When the sync is no longer needed, or
 * an error has occurred, it should be freed with talloc_free(), which will result in
 * an ldap_abandon message to the server to tell it to cancel the search.
 *
 * @param[in] conn 		Connection to issue the search request on.
 * @param[in] sync_no		number of the sync in the array of configs.
 * @param[in] inst		instance of ldap_sync this query relates to.
 * @param[in] cookie		not applicable to persistent search LDAP servers.
 */
int persistent_sync_state_init(fr_ldap_connection_t *conn, size_t sync_no, proto_ldap_sync_t const *inst, UNUSED uint8_t const *cookie)
{
	static char const	*notify_oid = LDAP_CONTROL_PERSIST_REQUEST;
	LDAPControl		ctrl = {0}, *ctrls[2] = { &ctrl, NULL };
	BerElement		*ber = NULL;
	int			ret;
	sync_state_t		*sync;
	fr_rb_tree_t		*tree;
	sync_config_t		*config = inst->sync_config[sync_no];

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

	/*
	 *	Allocate the sync request control
	 */
	ber = ber_alloc_t(LBER_USE_DER);
	if (!ber) {
		ERROR("Failed allocating sync control");
		return -1;
	}

	sync = sync_state_alloc(tree, conn, inst, sync_no, config);

	memcpy(&ctrl.ldctl_oid, &notify_oid, sizeof(ctrl.ldctl_oid));

	/*
	 *	The value for the search control is
	 *	 - changeTypes - what changes to receive notifications of
	 *	 - changesOnly - don't send initial directory contents first
	 *	 - returnECs - send Entry Change Notification control with change responses.
	 */
	ber_printf(ber, "{ibb}", LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD |
				 LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE |
				 LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY |
				 LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME,
				 config->changes_only, true );
	ret = ber_flatten2(ber, &ctrl.ldctl_value, 0);
	if (ret < 0) {
		ERROR("Failed creating sync control");
		ber_free(ber, 1);
	error:
		talloc_free(sync);
		return -1;
	}
	memcpy(&ctrl.ldctl_oid, &notify_oid, sizeof(ctrl.ldctl_oid));

	/*
	 *	Mark the control as critical
	 */
	ctrl.ldctl_iscritical = 1;

	ret = fr_ldap_search_async(&sync->msgid, NULL, &conn, config->base_dn, config->scope,
				   config->filter, config->attrs, ctrls, NULL);
	ber_free(ber, 1);

	if (ret != LDAP_PROC_SUCCESS) {
		ERROR("Failed to start persistent search query");
		goto error;
	}

	if (!fr_rb_insert(tree, sync)) {
		ERROR("Duplicate sync (msgid %i)", sync->msgid);
		goto error;
	}

	DEBUG3("Sync created with msgid %i", sync->msgid);

	/*
	 *	Register event to store cookies at a regular interval
	 *	Whilst persistent search LDAP servers don't provide cookies as such
	 *	we treat change numbers, if provided, as cookies.
	 */
	fr_event_timer_in(sync, conn->conn->el, &sync->cookie_ev, inst->cookie_interval, ldap_sync_cookie_event, sync);

	return 0;
}

/** Handle a SearchResultEntry response from Persistent Search LDAP servers
 *
 * Upon receipt of a search request containing the PersistentSearch control, if changesOnly is
 * false, the server provides the initial content using zero or more SearchResultEntries
 * without EntryChangeNotification controls.
 *
 * Changes subsequent to the initial search request, result in SearchResultEntry or SearchResultReference
 * with the EntryChangeNotification control which indicates what type of change is being reported.
 *
 * The Entry Change Notification is an LDAP Control where the controlType is the object identifier
 * 2.16.840.1.113730.3.4.3 and the controlValue, an OCTET STRING.
 * It contains a BER-encoded syncStateValue.
 *
 * EntryChangeNotification ::= SEQUENCE {
 *     changeType ENUMERATED {
 *         add (1),
 *         delete (2)
 *         modify (4),
 *         modDN (8)
 *     },
 *     previousDN LDAPDN OPTIONAL,    -- only when the changeType is modDN
 *     changeNumber INTEGER OPTIONAL  -- if supported, the changeNumber from the change log.
 * }
 *
 * The Sync State Control is only included in SearchResultEntry and SearchResultReference Messages.
 *
 * @param[in] sync	message was associated with.
 * @param[in] msg	containing an entry to process.
 * @param[in] ctrls	associated with the msg.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int persistent_sync_search_entry(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
{
	int			ret = 0, i;
	ber_len_t		len;
	BerElement		*ber = NULL;
	sync_op_t		op = SYNC_OP_INVALID;
	int			change_type, change_no;
	struct berval		orig_dn = { 0, NULL };

	fr_assert(sync);
	fr_assert(sync->conn);
	fr_assert(msg);

	if (!ctrls) {
	missing_control:
		/*
		 *	Initial directory sync does not have Entry Change
		 *	Notification control in the returned messages.
		 */
		if (sync->phase == SYNC_PHASE_INIT) {
			op = SYNC_OP_ADD;
			goto process_entry;
		}
		ERROR("searchResEntry missing EntryChangeNotification control");
	error:
		ldap_msgfree(msg);
		return -1;
	}

	/*
	 *  Every SearchResultEntry must contain a Entry Change Notification Control
	 *  describing the state of an object/the changes that should be made to it.
	 *
	 *   EntryChangeNotification ::= SEQUENCE {
	 *	changeType ENUMERATED {
	 *		add		(1),
	 *		delete		(2),
	 *		modify		(4),
	 *		modDN		(8)
	 *	},
	 *	previousDN   LDAPDN OPTIONAL,	-- modifyDN ops. only
	 *	changeNumber INTEGER OPTIONAL	-- if supported
	 *   }
	 *
	 *  If the entry doesn't have this control then the LDAP server is broken.
	 */
	for (i = 0; ctrls[i] != NULL; i++) {
		if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE) == 0) break;
	}
	if (!ctrls[i]) goto missing_control;

	if (sync->phase == SYNC_PHASE_INIT) sync->phase = SYNC_PHASE_DONE;

	/*
	 *  Get the value of the control.
	 */
	ber = ber_init(&ctrls[i]->ldctl_value);
	if (!ber) {
		ERROR("Failed allocating ber to handle syncStateValue control");

	free_ber:
		if (ber) ber_free(ber, 1);
		goto error;
	}

	/*
	 *	Extract the change type - the only non-optional value.
	 */
	if (ber_scanf(ber, "{e", &change_type) == LBER_ERROR) {
		ERROR("Maformed EntryChangeNotification control");
		goto free_ber;
	}

	/*
	 *	Modifications provide object previous DN.
	 */
	if ((change_type == LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME) &&
	    (ber_scanf(ber, "m", &orig_dn) == LBER_ERROR)) {
		ERROR("Maformed EntryChangeNotification for entry modification");
		goto free_ber;
	}

	if (ber_peek_tag(ber, &len) == 0x02) {
		if (ber_scanf(ber, "i", &change_no) == LBER_ERROR) {
			ERROR("Malformed changeNumber control");
			goto free_ber;
		}
		/*
		 *	The server has returned a changeNumber, treat it as a new cookie
		 */
		if (sync->cookie) talloc_free(sync->cookie);
		sync->cookie = (uint8_t *)talloc_asprintf(sync, "%d", change_no);
		if (ldap_sync_cookie_store(sync, false) < 0) goto error;
	}

	if (ber_scanf(ber, "}") == LBER_ERROR) {
		ERROR("Malformed syncStatevalue sequence");
		goto free_ber;
	}

	/*
	 *	Map persistent change types to sync states
	 */
	switch(change_type) {
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD:
		op = SYNC_OP_ADD;
		break;
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE:
		op = SYNC_OP_DELETE;
		break;
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY:
		op = SYNC_OP_MODIFY;
		break;
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME:
		op = SYNC_OP_MODIFY;
		break;
	default:
		ERROR("Invalid changeType returned");
		goto free_ber;
	}

process_entry:
	if (DEBUG_ENABLED3) {
		char	*entry_dn = ldap_get_dn(sync->conn->handle, msg);

		DEBUG3("Processing searchResEntry (%s), dn \"%s\"",
		       fr_table_str_by_value(sync_op_table, op, "<unknown>"),
		       entry_dn ? entry_dn : "<unknown>");

		ldap_memfree(entry_dn);
	}

	/*
	 *  Send the packet with the entry change notification
	 */
	ret = ldap_sync_entry_send(sync, NULL, &orig_dn, msg, op);

	ber_free(ber, 1);

	return ret;
}
