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
 * @file src/lib/ldap/sync.c
 *
 * @brief Synchronisation controls for interacting with directories impliementing
 *	"LDAP Content Sync Operation" (RFC 4533), Active Directory's notification OID,
 *	or LDAP Persistent Search.
 *
 * This code was inspired by the example client sync code available in libldap/ldap_sync.c
 * written by Pierangelo Masarati.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */

#define LOG_PREFIX "ldap_sync"

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/ldap/sync.h>
#include <freeradius-devel/util/debug.h>
#include <lber.h>

fr_table_num_sorted_t sync_state_table[] = {
	{ L("present"),			SYNC_STATE_PRESENT		},
	{ L("add"),			SYNC_STATE_ADD			},
	{ L("modify"),			SYNC_STATE_MODIFY		},
	{ L("delete"),			SYNC_STATE_DELETE		}
};
size_t sync_state_table_len = NUM_ELEMENTS(sync_state_table);

fr_table_num_sorted_t sync_phase_table[] = {
	{ L("delete"),			SYNC_PHASE_DELETE		},
	{ L("done"),			SYNC_PHASE_DONE			},
	{ L("init"),			SYNC_PHASE_INIT			},
	{ L("present"),			SYNC_PHASE_PRESENT		},
};
size_t sync_phase_table_len = NUM_ELEMENTS(sync_state_table);

fr_table_num_sorted_t sync_protocol_op_table[] = {
	{ L("intermediateResponse"),	LDAP_RES_INTERMEDIATE		},
	{ L("searchRes"),		LDAP_RES_SEARCH_RESULT		},
	{ L("searchResEntry"),		LDAP_RES_SEARCH_ENTRY		},
	{ L("searchResReference"),	LDAP_RES_SEARCH_REFERENCE	}
};
size_t sync_protocol_op_table_len = NUM_ELEMENTS(sync_state_table);

fr_table_num_sorted_t sync_info_tag_table[] = {
 	{ L("newCookie"),		LDAP_TAG_SYNC_NEW_COOKIE	},
 	{ L("refreshDelete"),		LDAP_TAG_SYNC_REFRESH_DELETE	},
	{ L("refreshIDSet"),		LDAP_TAG_SYNC_ID_SET		},
 	{ L("refreshPresent"),		LDAP_TAG_SYNC_REFRESH_PRESENT	}
};
size_t sync_info_tag_table_len = NUM_ELEMENTS(sync_state_table);


/** Check for the presence of a cookie in a ber value
 *
 * If a new cookie is found, the sync state will be updated.
 *
 * @param[out] new_cookie	Whether we got a new cookie value.
 * @param[in] sync		which the message was associated with.
 * @param[in] ber		value possibly containing a cookie tag (will be advanced).
 * @return
 *	- 0 success, a cookie was parsed successfully.
 *	- -1 parse error.
 */
static int sync_new_cookie(bool *new_cookie, sync_state_t *sync, BerElement *ber)
{
	struct berval	cookie;
	size_t		cookie_len;
	ber_tag_t	bv_ret;
	ber_len_t	len;

	if (new_cookie) *new_cookie = false;

	/*
	 *  Look for the (optional) cookie.
	 */
	bv_ret = ber_peek_tag(ber, &len);
	if ((bv_ret != LDAP_TAG_SYNC_COOKIE) && (bv_ret != LDAP_TAG_SYNC_NEW_COOKIE)) return 0;

	bv_ret = ber_scanf(ber, "m", &cookie);
	if (bv_ret == LBER_ERROR) {
		ERROR("Malformed cookie tag");
		return -1;
	}

	/*
	 *  "no cookie" can mean either no cookie element,
	 *  or a NULL cookie element (as per the RFC).
	 */
	if ((!cookie.bv_val) || (cookie.bv_len == 0)) return 0;

	if (sync->cookie) {
		if (talloc_array_length(sync->cookie) == cookie.bv_len) {
			cookie_len = talloc_array_length(sync->cookie);
			if (memcmp(sync->cookie, cookie.bv_val, cookie.bv_len) == 0) {
				WARN("Ignoring new cookie \"%pV\": Identical to old cookie",
				     fr_box_strvalue_len((char const *)sync->cookie, cookie_len));
				return 0;
			}
		}
	}

	talloc_free(sync->cookie);
	sync->cookie = fr_ldap_berval_to_bin(sync, &cookie);
	cookie_len = talloc_array_length(sync->cookie);
	DEBUG3("Got new cookie value \"%pV\" (%zu)",
	       fr_box_strvalue_len((char const *)sync->cookie, cookie_len), cookie_len);

	if (new_cookie) *new_cookie = true;

	return 0;
}

/** Handle a SearchResultEntry or SearchResultReference response from an RFC 4533 server
 *
 * Upon receipt of a search request containing the syncControl the server provides the initial
 * content using zero or more SearchResultEntries followed by a SearchResultdone.
 *
 * Each SearchResultEntry includes a Sync State control with state set to add, an entryUUID
 * containing the entry's UUID, and no cookie.
 *
 * For refreshAndPersist operations SearchResultEntries are also used after the refresh phase
 * to inform clients of changes to entries within the scope of the search request.
 *
 * The Sync State Control is an LDAP Control where the controlType is the object identifier
 * 1.3.6.1.4.1.4203.1.9.1.2 and the controlValue, an OCTET STRING.
 * It contains a BER-encoded syncStateValue.
 *
 * syncStateValue ::= SEQUENCE {
 *     state ENUMERATED {
 *         present (0),
 *         add (1),
 *         modify (2),
 *         delete (3)
 *     },
 *     entryUUID syncUUID,
 *     cookie    syncCookie OPTIONAL
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
static int sync_search_rfc4533_entry(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
{
	int			ret = 0, i;
	ber_tag_t		bv_ret;
	BerElement		*ber = NULL;
	struct berval		entry_uuid = { 0 };
	sync_states_t		state = SYNC_STATE_INVALID;
	bool			new_cookie;

	fr_assert(sync->conn);
	fr_assert(sync);
	fr_assert(msg);

	if (!ctrls) {
	missing_control:
		ERROR("searchResEntry missing syncStateValue control");
		return -1;
	}

	/*
	 *  Every SearchResultEntry/Reference must contain a Sync State Control
	 *  describing the state of an object/the changes that should
	 *  be made to it.
	 *
	 *  If the entry doesn't have this control then the LDAP server
	 *  is broken.
	 */
	for (i = 0; ctrls[i] != NULL; i++) {
		if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_SYNC_STATE) == 0) break;
	}
	if (!ctrls[i]) goto missing_control;

	/*
	 *  Get the value of the control.
	 */
	ber = ber_init(&ctrls[i]->ldctl_value);
	if (!ber) {
		ERROR("Failed allocating ber to handle syncStateValue control");

	error:
		if (ber) ber_free(ber, 1);

		return -1;
	}

	bv_ret = ber_scanf(ber, "{em", &state, &entry_uuid);
	if ((bv_ret == LBER_ERROR) || (entry_uuid.bv_len == 0)) {
		ERROR("Malformed syncUUID value");
		goto error;
	}

	if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

	if (ber_scanf(ber, "}") == LBER_ERROR ) {
		ERROR("Malformed syncStatevalue sequence");
		goto error;
	}

	switch (state) {
	case SYNC_STATE_PRESENT:
		switch (sync->phase) {

		case SYNC_PHASE_INIT:
			sync->phase = SYNC_PHASE_PRESENT;
			break;

		case SYNC_PHASE_PRESENT:
			break;

		default:
		bad_phase:
			ERROR("Entries with %s state are not allowed during refresh %s phase",
			      fr_table_str_by_value(sync_state_table, state, "<unknown>"),
			      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"));
			goto error;
		}
		break;

	case SYNC_STATE_DELETE:
		switch (sync->phase) {
		case SYNC_PHASE_DELETE:
		case SYNC_PHASE_DONE:
			break;

		default:
			goto bad_phase;
		}
		break;

	case SYNC_STATE_ADD:
	case SYNC_STATE_MODIFY:
		/*
		 *	RFC 4533 is less than clear about when added or modified entries
		 *	should be sent during the initial refresh stage.
		 *	If this is the first thing we see, then it will be the Present
		 *	phase.
		 *	All other phases can receive added / modified entries, and those
		 *	do not indicate a change in phase.
		 */
		switch (sync->phase) {
		case SYNC_PHASE_INIT:
			sync->phase = SYNC_PHASE_PRESENT;
			break;

		default:
			break;
		}
		break;


	default:
		ERROR("Unknown entry state (%i)", state);
		goto error;
	}

	if (DEBUG_ENABLED3) {
		char		*entry_dn;
		fr_value_box_t	uuid_box;

		entry_dn = ldap_get_dn(sync->conn->handle, msg);
		fr_ldap_berval_to_value_shallow(&uuid_box, &entry_uuid);

		DEBUG3("Processing %s (%s), dn \"%s\", entryUUID %pV",
		       fr_table_str_by_value(sync_protocol_op_table, ldap_msgtype(msg), "<unknown>"),
		       fr_table_str_by_value(sync_state_table, state, "<unknown>"),
		       entry_dn ? entry_dn : "<unknown>",
		       &uuid_box);

		ldap_memfree(entry_dn);
	}

	/*
	 *  Call the entry callback to notify caller that the object has changed.
	 */
	if (ldap_msgtype(msg) == LDAP_RES_SEARCH_REFERENCE) {
		if (sync->config->reference) {
			ret = sync->config->reference(sync, (uint8_t const *)entry_uuid.bv_val, NULL, msg, state);
		}
	} else {
		if (sync->config->entry) {
			ret = sync->config->entry(sync, (uint8_t const *)entry_uuid.bv_val, NULL, msg, state);
		}
	}

	if ((ret == 0) && new_cookie && sync->config->cookie) {
		ret = sync->config->cookie(sync, sync->cookie, false);
	}
	ber_free(ber, 1);

	return ret;
}

/** Handle a SearchResultEntry or SearchResultReference response from Persistent Search LDAP servers
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
static int sync_search_persistent_search_entry(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
{
	int			ret = 0, i;
	ber_len_t		len;
	BerElement		*ber = NULL;
	sync_states_t		state = SYNC_STATE_INVALID;
	int			change_type, change_no;
	struct berval		orig_dn = { 0, NULL };

	fr_assert(sync->conn);
	fr_assert(sync);
	fr_assert(msg);

	if (!ctrls) {
	missing_control:
		/*
		 *	Initial directory sync does not have Entry Change
		 *	Notification control in the returned messages.
		 */
		if (sync->phase == SYNC_PHASE_INIT) {
			state = SYNC_STATE_ADD;
			goto process_entry;
		}
		ERROR("searchResEntry missing EntryChangeNotification control");
	error:
		ldap_msgfree(msg);
		return -1;
	}

	/*
	 *  Every SearchResultEntry/Reference must contain a Entry Change Notification Control
	 *  describing the state of an object/the changes that should
	 *  be made to it.
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
		ber_scanf(ber, "i", &change_no);
		/*
		 *	The server has returned a changeNumber, treat it as a new cookie
		 */
		if (sync->cookie) talloc_free(sync->cookie);
		sync->cookie = (uint8_t *)talloc_asprintf(sync, "%d", change_no);
		if (sync->config->cookie(sync, sync->cookie, false) < 0) goto error;
	}

	if (ber_scanf(ber, "}") == LBER_ERROR ) {
		ERROR("Malformed syncStatevalue sequence");
		goto free_ber;
	}

	/*
	 *	Map persistent change types to sync states
	 */
	switch(change_type) {
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD:
		state = SYNC_STATE_ADD;
		break;
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE:
		state = SYNC_STATE_DELETE;
		break;
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY:
		state = SYNC_STATE_MODIFY;
		break;
	case LDAP_CONTROL_PERSIST_ENTRY_CHANGE_RENAME:
		state = SYNC_STATE_MODIFY;
		break;
	default:
		ERROR("Invalid changeType returned");
		goto free_ber;
	}

process_entry:
	if (DEBUG_ENABLED3) {
		char		*entry_dn;

		entry_dn = ldap_get_dn(sync->conn->handle, msg);

		DEBUG3("Processing %s (%s), dn \"%s\"",
		       fr_table_str_by_value(sync_protocol_op_table, ldap_msgtype(msg), "<unknown>"),
		       fr_table_str_by_value(sync_state_table, state, "<unknown>"),
		       entry_dn ? entry_dn : "<unknown>");

		ldap_memfree(entry_dn);
	}

	/*
	 *  Call the entry callback to notify caller that the object has changed.
	 */
	if (ldap_msgtype(msg) == LDAP_RES_SEARCH_REFERENCE) {
		if (sync->config->reference) {
			ret = sync->config->reference(sync, NULL, &orig_dn, msg, state);
		}
	} else {
		if (sync->config->entry) {
			ret = sync->config->entry(sync, NULL, &orig_dn, msg, state);
		}
	}

	ber_free(ber, 1);

	return ret;
}

/** Handle a LDAP_RES_SEARCH_ENTRY (SearchResultEntry) or LDAP_RES_SEARCH_REFRENCE (SearchResultReference) response
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
static int sync_search_active_directory_entry(sync_state_t *sync, LDAPMessage *msg)
{
	int		count, i, ret = 0;
	sync_states_t	state = SYNC_STATE_MODIFY;
	struct berval	**values;

	fr_assert(sync->conn);
	fr_assert(sync);
	fr_assert(msg);

	/*
	 *	Look for an "isDeleted" attribute - this is Active Directory's indicator
	 *	for a deleted object - process these through the recv Delete section.
	 */
	values = ldap_get_values_len(sync->conn->handle, msg, "isDeleted");
	count = ldap_count_values_len(values);
	for (i = 0; i < count; i++) {
		if ((values[i]->bv_len == 4) && (strncmp(values[i]->bv_val, "TRUE", 4) == 0)) {
			state = SYNC_STATE_DELETE;
			break;
		}
	}
	ldap_value_free_len(values);

	/*
	 *  Call the entry callback to notify caller that the object has changed.
	 */
	if (ldap_msgtype(msg) == LDAP_RES_SEARCH_REFERENCE) {
		if (sync->config->reference) {
			ret = sync->config->reference(sync, NULL, NULL, msg, state);
		}
	} else {
		if (sync->config->entry) {
			ret = sync->config->entry(sync, NULL, NULL, msg, state);
		}
	}

	return ret;
}

/** Handle a LDAP_RES_INTERMEDIATE (SyncInfo) response
 *
 * These allow the LDAP server to communicate sync state to clients
 *
 * The Sync Info Message is an LDAP Intermediate Response Message [RFC4511] where
 * responseName is the object identifier 1.3.6.1.4.1.4203.1.9.1.4 and responseValue
 * contains a BER-encoded syncInfoValue.
 *
 * syncInfoValue ::= CHOICE {
 *     newcookie      [0] syncCookie,
 *     refreshDelete  [1] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDone    BOOLEAN DEFAULT TRUE
 *     },
 *     refreshPresent [2] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDone    BOOLEAN DEFAULT TRUE
 *     },
 *     syncIdSet      [3] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDeletes BOOLEAN DEFAULT FALSE,
 *         syncUUIDs      SET OF syncUUID
 *     }
 * }
 *
 * @param[in] sync	message was associated with.
 * @param[in] msg	containing an entry to process.
 * @param[in] ctrls	associated with the msg.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int sync_intermediate(sync_state_t *sync, LDAPMessage *msg, UNUSED LDAPControl **ctrls)
{
	int			ret, i;
	char			*oid = NULL;
        struct berval		*data = NULL;
	BerElement		*ber = NULL;
	ber_len_t		len;
	ber_tag_t		sync_info_tag;
	int			refresh_deletes = 0;
	BerVarray		sync_uuids = NULL;

	bool			new_cookie;
	int			refresh_done = false;

	ret = ldap_parse_intermediate(sync->conn->handle, msg, &oid, &data, NULL, 0);
	if (!fr_cond_assert(ret == LDAP_SUCCESS)) return -1;	/* should have been caught earlier */

	if (!oid || (strcmp(oid, LDAP_SYNC_INFO) != 0)) {
		WARN("Ignoring intermediateResult with unexpected OID \"%s\"", oid ? oid : "<unknown>");
		return 0;
	}

	ber = ber_init(data);
	if (ber == NULL) {
		ERROR("Failed allocating ber to handle syncInfo data");

		return -1;
	}

	sync_info_tag = ber_peek_tag(ber, &len);
	DEBUG3("Processing syncInfo (%s)", fr_table_str_by_value(sync_info_tag_table, sync_info_tag, "<unknown>"));

	switch (sync_info_tag) {
	case LDAP_TAG_SYNC_NEW_COOKIE:
		if (sync_new_cookie(&new_cookie, sync, ber) < 0) {
		error:
			if (sync_uuids) ber_bvarray_free(sync_uuids);
			if (ber) ber_free(ber, 1);
			if (data) ber_bvfree(data);
			if (oid) ldap_memfree(oid);

			return -1;
		}

		if (!new_cookie) {
			ERROR("Missing cookie value");
			goto error;
		}
		break;

	case LDAP_TAG_SYNC_REFRESH_PRESENT:
		switch (sync->phase) {
		case SYNC_PHASE_INIT:
			sync->phase = SYNC_PHASE_PRESENT;
			break;

		case SYNC_PHASE_PRESENT:
			break;

		default:
			ERROR("Invalid refresh phase transition (%s->%s)",
			      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"),
			      fr_table_str_by_value(sync_phase_table, SYNC_PHASE_DELETE, "<unknown>"));
			goto error;
		}

		if (ber_scanf(ber, "{") == LBER_ERROR) {
			ERROR("Malformed refreshPresent sequence");
			goto error;
		}

		if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

		if (ber_peek_tag(ber, &len) == LDAP_TAG_REFRESHDONE) {
			if (ber_scanf(ber, "b", &refresh_done) == LBER_ERROR) {
				ERROR("Malformed refresh sequence: Missing refreshDone tag value");
				goto error;
			}
		} else {
			refresh_done = true;	/* Default (when absent) is true */
		}

		if (ber_scanf(ber, "}") == LBER_ERROR ) {
			ERROR("Malformed refreshPresent sequence");
			goto error;
		}

		/*
		 *  The refreshPresent contains refreshDone, which is always FALSE in the
		 *  refreshOnly mode of Sync Operation because it is followed by a delete
		 *  phase.
		 */
		if (!sync->config->persist) {
			ERROR("Got refreshPresent refreshDone = true in refreshOnly mode (which is invalid)");
			goto error;
		}

		if (refresh_done) sync->phase = SYNC_PHASE_DONE;
		break;

	case LDAP_TAG_SYNC_REFRESH_DELETE:
		switch (sync->phase) {
		case SYNC_PHASE_INIT:
		case SYNC_PHASE_PRESENT:
			sync->phase = SYNC_PHASE_DELETE;
			break;

		case SYNC_PHASE_DELETE:
			break;

		default:
			ERROR("Invalid refresh phase transition (%s->%s)",
			      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"),
			      fr_table_str_by_value(sync_phase_table, SYNC_PHASE_DELETE, "<unknown>"));

			goto error;
		}

		if (ber_scanf(ber, "{") == LBER_ERROR) {
			ERROR("Malformed refreshPresent sequence");
			goto error;
		}

		if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

		if (ber_peek_tag(ber, &len) == LDAP_TAG_REFRESHDONE) {
			if (ber_scanf(ber, "b", &refresh_done) == LBER_ERROR) {
				ERROR("Malformed refresh sequence: Missing refreshDone tag value");
				goto error;
			}
		} else {
			refresh_done = true;
		}

		if (ber_scanf(ber, "}") == LBER_ERROR ) {
			ERROR("Malformed refreshPresent sequence");
			goto error;
		}
		if (refresh_done) sync->phase = SYNC_PHASE_DONE;
		break;

	/*
	 *	An intermediate response message with the syncInfoValue containing
	 *	a syncIDSet.
	 *	If refreshDeletes is false, the list of UUIDs are "present"
	 *	If refreshDeletes is true, the list of UUIDs are entries to be deleted
	 */
	case LDAP_TAG_SYNC_ID_SET:
		if (ber_scanf( ber, "{") == LBER_ERROR) {
			ERROR("Malformed syncIDSet");
			goto error;
		}

		if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

		if (ber_peek_tag(ber, &len) == LDAP_TAG_REFRESHDELETES) {
			if (ber_scanf(ber, "b", &refresh_deletes) == LBER_ERROR) {
				ERROR("Malformed refresh_deletes tag");
				goto error;
			}
		}

		if ((ber_scanf(ber, "[W]}", &sync_uuids) == LBER_ERROR) || !sync_uuids) {
			ERROR("syncIDSet missing set of IDs");
			goto error;
		}

		if (refresh_deletes) {
		/*
		 *	refresh_deletes == true indicates we are starting, in or at the end
		 *	of a delete phase.
		 */
			switch (sync->phase) {
			case SYNC_PHASE_INIT:
			case SYNC_PHASE_PRESENT:
				sync->phase = SYNC_PHASE_DELETE;
				break;

			case SYNC_PHASE_DELETE:
				break;

			default:
				ERROR("Invalid refresh phase transition (%s->%s)",
				      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"),
				      fr_table_str_by_value(sync_phase_table, SYNC_PHASE_DELETE, "<unknown>"));
				goto error;
			}
		} else {
		/*
		 *	refresh_deletes == false indicates we are starting, in or at the end
		 *	of a present phase
		 */
			switch (sync->phase) {
			case SYNC_PHASE_INIT:
				sync->phase = SYNC_PHASE_PRESENT;
				break;

			case SYNC_PHASE_PRESENT:
				break;

			default:
				ERROR("Invalid refresh phase transition (%s->%s)",
				      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"),
				      fr_table_str_by_value(sync_phase_table, SYNC_PHASE_PRESENT, "<unknown>"));
				goto error;
			}
		}

		/*
		 *	Process the list of UUIDs provided.
		 *	The state of refresh_deletes indicates whether these are "present" or "delete"
		 */
		for (i = 0; sync_uuids[i].bv_val != NULL; i++) {
			if (sync_uuids[i].bv_len != SYNC_UUID_LENGTH) {
				ERROR("Invalid entryUUID length, expected " STRINGIFY(SYNC_UUID_LENGTH) " "
				      "bytes got %zu bytes", sync_uuids[i].bv_len);
				goto error;
			}
			ret = sync->config->entry(sync, (uint8_t const *)sync_uuids[i].bv_val, NULL, NULL,
						  (refresh_deletes ? SYNC_STATE_DELETE : SYNC_STATE_PRESENT));
			if (ret < 0) goto error;
		}

		ber_bvarray_free(sync_uuids);
		sync_uuids = NULL;
		break;

	default:
		ERROR("Invalid syncInfo tag %lu", sync_info_tag);
		goto error;

	}

	if (new_cookie && sync->config->cookie) {
		ret = sync->config->cookie(sync, sync->cookie, false);
	}

	if (ber) ber_free(ber, 1);
	if (oid) ldap_memfree(oid);
	if (data) ber_bvfree(data);

	return ret;
}

/** Handle a LDAP_RES_SEARCH_RESULT (searchResultDone)
 *
 * The Sync Done Control is an LDAP Control where the controlType is the object identifier
 * 1.3.6.1.4.1.4203.1.9.1.3 and the controlValue contains a BER-encoded syncDoneValue.
 *
 * syncDoneValue ::= SEQUENCE {
 *     cookie          syncCookie OPTIONAL,
 *     refreshDeletes  BOOLEAN DEFAULT FALSE
 * }
 *
 * The Sync Done Control is only applicable to the SearchResultDone Message.
 *
 * It's essentially used to make the end of the set of searchEntries, and indicate the
 * possible start of a present of delete phase.
 *
 * It's used for refreshOnly operations to indicate that the server is done returning
 * search results, with refreshAndPersist an intermediateResult message is used instead.
 *
 * In addition, it is used if the server wishes to indicate that a refresh is required
 * by sending the e-syncRefreshRequired result code.  In this case, any cookie provided
 * should be used on a query to re-start the sync.  If no cookie is provided, the new
 * query should be performed without a cookie to get a full refresh.
 *
 * @param[in] sync	message was associated with.
 * @param[in] ctrls	associated with the msg.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int sync_search_result(sync_state_t *sync, LDAPControl **ctrls)
{
	int		ret = 0;
	int		refresh_deletes = 0;

	int		i;
	BerElement	*ber = NULL;
	ber_len_t	len;
	bool		new_cookie;

	fr_assert(sync->conn);
	fr_assert(sync);

	/*
	 *	Should not happen with refreshAndPersist.
	 */
	if (sync->config->persist) {
		ERROR("searchResult is invalid for refreshAndPersist mode");
		return -1;
	}

	/*
	 *	All phases other than DONE can see a searchResult message.
	 */
	if (sync->phase == SYNC_PHASE_DONE) {
		ERROR("searchResult returned after refresh stage completed");
		return -1;
	}

	/*
	 *	Process the syncDoneValue
	 */
	if (!ctrls) {
	missing_control:
		ERROR("searchResult missing syncDoneValue control");
		return -1;
	}
	for (i = 0; ctrls[i] != NULL; i++) {
		if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_SYNC_DONE) == 0) break;
	}
	if (!ctrls[i]) goto missing_control;

	ber = ber_init(&ctrls[i]->ldctl_value);
	if (!ber) {
		ERROR("Failed allocating ber to handle syncDoneValue control");

	error:
		if (ber) ber_free(ber, 1);

		return -1;
	}

	if (ber_scanf( ber, "{" /*"}"*/) == LBER_ERROR) goto error;

	if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

	/*
	 *	refreshDeletes tag in a searchResult message has the following meaning:
	 *
	 *	- FALSE:  what the server is sent has included reference to all entries
	 *		  which are in the result set.  Anything in the cached copy which
	 *		  has not been referenced should be deleted.
	 *	- TRUE:   the messages returned have been sufficient to bring any cached
	 *		  copy up to date, including deleting any removed entries.
	 */
	if (ber_peek_tag(ber, &len) == LDAP_TAG_REFRESHDELETES) {
		if (ber_scanf(ber, "b", &refresh_deletes) == LBER_ERROR) {
			ERROR("Malformed refresh sequence: Missing refreshDeletes tag value");
			goto error;
		}
	} else {
		refresh_deletes = 0;
	}

	if (ber_scanf( ber, /*"{"*/ "}" ) == LBER_ERROR) {
		ERROR("Malformed syncDoneValue sequence");
		goto error;
	}

	ber_free(ber, 1);

	if (sync->config->done) {
		ret = sync->config->done(sync, sync->phase, refresh_deletes);
		if (ret != 0) goto error;
	}

	if (new_cookie && sync->config->cookie) {
		ret = sync->config->cookie(sync, sync->cookie, false);
	}

	sync->phase = SYNC_PHASE_DONE;

	return ret;
}

/** Handle result code of e-syncRefreshRequired
 *
 * If the server wishes to indicate that a refresh is required, it sends a searchResultDone
 * message with the result code e-syncRefreshRequired result code.  Any cookie provided
 * should be used on a query to re-start the sync.  If no cookie is provided, the new
 * query should be performed without a cookie to get a full refresh.
 *
 * @param[in] sync		message was associated with.
 * @param[in] ctrls		associated with the msg.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int sync_refresh_required(sync_state_t *sync, LDAPControl **ctrls)
{
	int		ret = 0;
	int		refresh_deletes = 0;

	int		i;
	BerElement	*ber = NULL;
	ber_len_t	len;
	bool		new_cookie = false;

	fr_assert(sync->conn);
	fr_assert(sync);

	/*
	 *	We may or may not have controls.
	 *	If the server wants the refresh to occur from a specific change it will
	 *	send a cookie which should be used when re-starting the sync query.
	 */
	if (ctrls) {
		for (i = 0; ctrls[i] != NULL; i++) {
			if (strcmp(ctrls[i]->ldctl_oid, LDAP_CONTROL_SYNC_DONE) == 0) break;
		}

		if (ctrls[i]) {
			ber = ber_init(&ctrls[i]->ldctl_value);
			if (!ber) {
				ERROR("Failed allocating ber to handle syncDoneValue control");

			error:
				if (ber) ber_free(ber, 1);

				return -1;
			}

			if (ber_scanf( ber, "{" /*"}"*/) == LBER_ERROR) goto error;

			if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

			if (ber_peek_tag(ber, &len) == LDAP_TAG_REFRESHDELETES) {
				if (ber_scanf(ber, "b", &refresh_deletes) == LBER_ERROR) {
					ERROR("Malformed refresh sequence: Missing refreshDeletes tag value");
					goto error;
				}
			}

			if (ber_scanf( ber, /*"{"*/ "}" ) == LBER_ERROR) {
				ERROR("Malformed syncDoneValue sequence");
				goto error;
			}

			ber_free(ber, 1);
		}
	}

	/*
	 *	If we received e-syncRefreshRequired but no cookie the server is
	 *	indicating we should clear the cookie before restarting the sync.
	 */
	if (!new_cookie) {
		talloc_free(sync->cookie);
		sync->cookie = NULL;
		new_cookie = true;
	}

	if (sync->config->cookie) ret = sync->config->cookie(sync, sync->cookie, true);

	return ret;
}

/** Function to call when the LDAP handle's FD is readable
 *
 * @param[in] conn	to service.
 * @return
 *	- 0 on success.
 *	- -1 on sync error.
 *	- -2 on conn error.  Requires the handle to be destroyed.
 */
int sync_demux(fr_ldap_connection_t *conn)
{
	struct	timeval		poll = { 1, 0 };	/* Poll */
	LDAPMessage		*msg = NULL;
	int			ret = 0;
	fr_ldap_rcode_t		rcode;
	sync_state_t		find = { .msgid = -1 }, *sync = NULL;
	fr_rb_tree_t		*tree;
	int			type, msgid;
	LDAPControl		**ctrls = NULL;

	tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);

	fr_assert(conn);

	/*
	 *	Pull the next outstanding message from this connection.
	 *	We process one message at a time so that the message can be
	 *	passed to the worker, and freed once the request has been
	 *	handled.
	 */
	ret = ldap_result(conn->handle, LDAP_RES_ANY, LDAP_MSG_ONE, &poll, &msg);
	switch (ret) {
	case 0:	/* timeout - shouldn't happen */
		fr_assert(0);
		return -2;

	case -1:
		rcode = fr_ldap_error_check(NULL, conn, NULL, NULL);
		if (rcode == LDAP_PROC_BAD_CONN) return -2;
		return -1;

	default:
		break;
	}

	/*
	 *	De-multiplex based on msgid
	 */
	if (!msg) return 0;

	msgid = ldap_msgid(msg);
	type = ldap_msgtype(msg);

	ret = 0;
	if (msgid == 0) {
		WARN("Ignoring unsolicited %s message",
		     fr_table_str_by_value(sync_protocol_op_table, type, "<invalid>"));
	free_msg:
		if (ctrls) ldap_controls_free(ctrls);
		ldap_msgfree(msg);
		return ret;
	}

	find.msgid = msgid;

	sync = fr_rb_find(tree, &find);
	if (!sync) {
		WARN("Ignoring msgid %i, doesn't match any outstanding syncs",
		     find.msgid);
		goto free_msg;
	}

	/*
	 *	Check for errors contained within the message.
	 *	This has to be per message, as multiple syncs
	 *	are multiplexed together on one connection.
	 */
	switch (fr_ldap_error_check(&ctrls, conn, msg, sync->config->base_dn)) {
	case LDAP_PROC_SUCCESS:
		break;

	/*
	 *	The e-syncRefresRequired result code is the server informing us that
	 *	the query needs to be restarted	for a new refresh phase to run.
	 *	It is sent as the result code for a SearchResultsDone message.
	 */
	case LDAP_PROC_REFRESH_REQUIRED:
		if (type != LDAP_RES_SEARCH_RESULT) {
			PERROR("e-syncRefreshRequired result code received on wrong message type");
			ret = -1;
			goto free_msg;
		}

		DEBUG2("LDAP Server returned e-syncRefreshRequired");
		ret = sync_refresh_required(sync, ctrls);
		goto free_msg;

	/*
	 *	Don't think this should happen... but libldap
	 *	is wonky sometimes...
	 */
	case LDAP_PROC_BAD_CONN:
		PERROR("Connection unusable");
		ret = -2;
		goto free_msg;

	default:
	sync_error:
		PERROR("Sync error");
		ret = -1;
		goto free_msg;
	}

	DEBUG3("Got %s message for sync (msgid %i)",
	       fr_table_str_by_value(sync_protocol_op_table, type, "<invalid>"), sync->msgid);

	switch (type) {
	case LDAP_RES_SEARCH_REFERENCE:
	case LDAP_RES_SEARCH_ENTRY:
		switch(sync->conn->directory->sync_type) {
		case FR_LDAP_SYNC_RFC4533:
			ret = sync_search_rfc4533_entry(sync, msg, ctrls);
			break;

		case FR_LDAP_SYNC_ACTIVE_DIRECTORY:
			ret = sync_search_active_directory_entry(sync, msg);
			break;

		case FR_LDAP_SYNC_PERSISTENT_SEARCH:
			ret = sync_search_persistent_search_entry(sync, msg, ctrls);
			break;

		default:
			fr_assert(1);
		}
		if (ret < 0) goto sync_error;
		break;

	case LDAP_RES_SEARCH_RESULT:
		ret = sync_search_result(sync, ctrls);
		if (ret < 0) goto sync_error;
		ldap_msgfree(msg);
		break;

	case LDAP_RES_INTERMEDIATE:
		ret = sync_intermediate(sync, msg, ctrls);
		if (ret < 0) goto sync_error;
		ldap_msgfree(msg);
		break;

	default:
		WARN("Ignoring unexpected message type (%i)", type);
		ret = 0;
		goto free_msg;
	}

	ldap_controls_free(ctrls);

	return 0;
}

/** Tell the remote server to stop the sync
 *
 * Terminates the search informing the remote server that we no longer want to receive results
 * for this sync.  A RFC 4511 abandon request is used to inform the server.
 *
 * This allows individual syncs to be stopped without destroying the underlying connection.
 *
 * Removes the sync's msgid from the tree of msgids associated with the connection.
 *
 * @param[in] sync to abandon.
 * @return 0
 */
static int _sync_state_free(sync_state_t *sync)
{

	fr_ldap_connection_t	*conn = talloc_get_type_abort(sync->conn, fr_ldap_connection_t);	/* check for premature free */
	fr_rb_tree_t	*tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);
	sync_state_t	find = { .msgid = sync->msgid };

	DEBUG3("Abandoning sync");

	if (!sync->conn->handle) return 0;	/* Handled already closed? */

	/*
	 *	Tell the remote server to stop sending results
	 */
	if (sync->msgid >= 0) ldap_abandon_ext(sync->conn->handle, sync->msgid, NULL, NULL);
	fr_rb_delete(tree, &find);

	return 0;
}

/** Compare two sync state structures on msgid
 *
 * @param[in] one first sync to compare.
 * @param[in] two second sync to compare.
 * @return CMP(one, two)
 */
static int8_t _sync_cmp(void const *one, void const *two)
{
	sync_state_t const *a = one, *b = two;

	return CMP(a->msgid, b->msgid);
}

/** Destroy a sync (does not free config)
 *
 * Frees up a sync specified by msgid, informing the server it no longer needs to send
 * messages, freeing the sync state, and removing it from the connection sync tree.
 *
 * If the connection has no syncs, or the msgid isn't found, call becomes a noop.
 *
 * This function does not need to be called when exiting, or closing a connection, as
 * the talloc destructor.
 *
 * @param[in] conn	the connection.
 * @param[in] msgid	of the sync to destroy.
 */
void sync_state_destroy(fr_ldap_connection_t *conn, int msgid)
{
	sync_state_t	find, *sync;
	fr_rb_tree_t	*tree;

	if (!conn->uctx) return;

	tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);

	find.msgid = msgid;

	sync = fr_rb_find(tree, &find);
	talloc_free(sync);	/* Will inform the server */
}

/** Allocate a sync state structure and issue the search
 *
 * The sync structure is parented off the conn.  When the sync is no longer needed, or
 * an error has occurred, it should be freed with talloc_free(), which will result in
 * an ldap_abandon message to the server to tell it to cancel the search.
 *
 * @param[in] conn 		Connection to issue the search request on.
 * @param[in] config		containing callbacks and search parameters.
 * @param[in] cookie		NULL to perform a complete refresh, else the last
 *				cookie provided
 * @param[in] reload_hint	If true, hint to the server that we need to be sent all
 *				entries in the directory.
 */
int sync_state_init(fr_ldap_connection_t *conn, sync_config_t const *config,
		    uint8_t const *cookie, bool reload_hint)
{
	LDAPControl		ctrl = {0}, ctrl2 = {0}, *ctrls[3] = { &ctrl, NULL, NULL };
	BerElement		*ber = NULL;
	int			ret;
	int			mode;
	sync_state_t		*sync;
	fr_rb_tree_t		*tree;

	fr_assert(conn);
	fr_assert(config);

	mode = config->persist ? LDAP_SYNC_REFRESH_AND_PERSIST : LDAP_SYNC_REFRESH_ONLY;

	/*
	 *	Allocate or retrieve the tree of outstanding msgids
	 *	these are specific to the connection.
	 */
	if (!conn->uctx) {
		MEM(tree = fr_rb_inline_talloc_alloc(conn, sync_state_t, node, _sync_cmp, NULL));
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

	/*
	 *	If the connection is freed, all the sync state is also freed
	 */
	MEM(sync = talloc_zero(tree, sync_state_t));
	sync->config = config;
	sync->phase = SYNC_PHASE_INIT;
	sync->conn = conn;
	talloc_set_destructor(sync, _sync_state_free);

	switch (conn->directory->sync_type) {
	/*
	 *	Directories implementing RFC4533
	 *
	 *	The Sync Request Control is an LDAP Control [RFC4511] where the controlType is the object
	 *	identifier 1.3.6.1.4.1.4203.1.9.1.1 and the controlValue, an OCTET STRING, contains a
	 *	BER-encoded syncRequestValue.  The criticality field is either TRUE or FALSE.
	 *
	 *	 syncRequestValue ::= SEQUENCE {
	 *	     mode ENUMERATED {
	 *	         -- 0 unused
	 *	         refreshOnly       (1),
	 *	         -- 2 reserved
	 *	         refreshAndPersist (3)
	 *	     },
	 *	     cookie     syncCookie OPTIONAL,
	 *	     reloadHint BOOLEAN DEFAULT FALSE
	 *	 }
	 *
	 *	 The Sync Request Control is only applicable to the SearchRequest Message.
	 *
	 */
	case FR_LDAP_SYNC_RFC4533:
	{
		static char const	*sync_ctl_oid = LDAP_CONTROL_SYNC;

		/*
		 *	Might not necessarily have a cookie
		 */
		if (cookie) {
			char *bv_val;
			struct berval bvc;

			memcpy(&bv_val, &cookie, sizeof(bv_val));

			bvc.bv_val = bv_val;
			bvc.bv_len = talloc_array_length(cookie);

			ber_printf(ber, "{eOb}",mode, &bvc, reload_hint);
		} else {
			ber_printf(ber, "{eb}", mode, reload_hint );
		}

		ret = ber_flatten2(ber, &ctrl.ldctl_value, 0);
		if (ret < 0) {
			ERROR("Failed creating sync control");
		error:
			ber_free(ber, 1);
	                talloc_free(sync);

			return -1;
	        }
		memcpy(&ctrl.ldctl_oid, &sync_ctl_oid, sizeof(ctrl.ldctl_oid));
	}
		break;

	/*
	 *	Active Directory uses its own control to mark persistent searches.
	 *	In addition we add the control to request the return of deleted objects
	 *	which allows searches specifically on the Deleted Objects container.
	 *
	 *	Neither of these controls take values.
	 */
	case FR_LDAP_SYNC_ACTIVE_DIRECTORY:
	{
		static char const	*notify_oid = LDAP_SERVER_NOTIFICATION_OID;
		static char const	*deleted_oid = LDAP_SERVER_SHOW_DELETED_OID;

		memcpy(&ctrl.ldctl_oid, &notify_oid, sizeof(ctrl.ldctl_oid));
		ctrl.ldctl_value.bv_len = 0;
		ctrl.ldctl_value.bv_val = NULL;

		memcpy(&ctrl2.ldctl_oid, &deleted_oid, sizeof(ctrl2.ldctl_oid));
		ctrl2.ldctl_value.bv_len = 0;
		ctrl2.ldctl_value.bv_val = NULL;
		ctrl2.ldctl_iscritical = 1;
		ctrls[1] = &ctrl2;
	}
		break;

	/*
	 *	Persistent Search https://tools.ietf.org/id/draft-ietf-ldapext-psearch-03.txt
	 */
	case FR_LDAP_SYNC_PERSISTENT_SEARCH:
	{
		static char const	*notify_oid = LDAP_CONTROL_PERSIST_REQUEST;

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
					 sync->config->changes_only, true );
		ret = ber_flatten2(ber, &ctrl.ldctl_value, 0);
		if (ret < 0) {
			ERROR("Failed creating sync control");
			goto error;
		}
		memcpy(&ctrl.ldctl_oid, &notify_oid, sizeof(ctrl.ldctl_oid));
	}
		break;

	default:
		ERROR("No LDAP sync protocols are supported by directory");
		goto error;

	}

	/*
	 *	Mark the control as critical
	 */
	ctrl.ldctl_iscritical = 1;

	ret = fr_ldap_search_async(&sync->msgid, NULL, &conn, config->base_dn, config->scope,
				   config->filter, config->attrs, ctrls, NULL);
	ber_free(ber, 1);

	if (ret != LDAP_PROC_SUCCESS) {
		talloc_free(sync);
		return -1;
	}

	if (!fr_rb_insert(tree, sync)) {
		ERROR("Duplicate sync (msgid %i)", sync->msgid);
		return -1;
	}
	DEBUG3("Sync created with msgid %i", sync->msgid);

	return 0;
}
