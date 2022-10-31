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
 * @file rfc4533.c
 * @brief LDAP sync callback functions for RFC 4533 servers.
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */

#define LOG_PREFIX "ldap_sync_rfc4533"

#include "rfc4533.h"
#include <freeradius-devel/util/debug.h>

/** Types of Sync Info messages
 */
static fr_table_num_sorted_t const sync_info_tag_table[] = {
 	{ L("newCookie"),		LDAP_TAG_SYNC_NEW_COOKIE	},
 	{ L("refreshDelete"),		LDAP_TAG_SYNC_REFRESH_DELETE	},
	{ L("refreshIDSet"),		LDAP_TAG_SYNC_ID_SET		},
 	{ L("refreshPresent"),		LDAP_TAG_SYNC_REFRESH_PRESENT	}
};
static size_t const sync_info_tag_table_len = NUM_ELEMENTS(sync_info_tag_table);

/** Phases of an RFC 4533 sync
 */
static fr_table_num_sorted_t const sync_phase_table[] = {
	{ L("delete"),			SYNC_PHASE_DELETE		},
	{ L("done"),			SYNC_PHASE_DONE			},
	{ L("init"),			SYNC_PHASE_INIT			},
	{ L("present"),			SYNC_PHASE_PRESENT		},
};
static size_t const sync_phase_table_len = NUM_ELEMENTS(sync_phase_table);

/** Allocate and initialise RFC 4533 sync queries.
 *
 * The Sync Request Control is an LDAP Control [RFC4511] where the controlType is the object
 * identifier 1.3.6.1.4.1.4203.1.9.1.1 and the controlValue, an OCTET STRING, contains a
 * BER-encoded syncRequestValue.
 *
 *  syncRequestValue ::= SEQUENCE {
 *      mode ENUMERATED {
 *          -- 0 unused
 *          refreshOnly       (1),
 *          -- 2 reserved
 *          refreshAndPersist (3)
 *      },
 *      cookie     syncCookie OPTIONAL,
 *      reloadHint BOOLEAN DEFAULT FALSE
 *  }
 *
 * reloadHint specifies whether we prefer a complete directory load or an eSyncRefreshRequired
 * response when the provided cookie does not give the server a point in its change log
 * from which it can send suitable changes to bring the client into sync.
 * We always send 'false' since we handle eSyncRefreshRequired.
 *
 * The Sync Request Control is only applicable to the SearchRequest Message.
 */
int rfc4533_sync_init(fr_ldap_connection_t *conn, size_t sync_no, proto_ldap_sync_t const *inst, uint8_t const *cookie)
{
	LDAPControl		ctrl = {0}, *ctrls[2] = { &ctrl, NULL };
	BerElement		*ber = NULL;
	static char const	*sync_ctl_oid = LDAP_CONTROL_SYNC;
	int			ret;
	fr_rb_tree_t		*tree;
	sync_state_t		*sync;
	sync_config_t const 	*config = inst->sync_config[sync_no];

	fr_assert(conn);
	fr_assert(config);

	if (!conn->uctx) {
		MEM(tree = fr_rb_inline_talloc_alloc(conn, sync_state_t, node, sync_state_cmp, NULL));
		conn->uctx = tree;
	} else {
		tree = talloc_get_type_abort(conn->uctx, fr_rb_tree_t);
	}

	ber = ber_alloc_t(LBER_USE_DER);
	if (!ber) {
		ERROR("Failed allocating ber for sync control");
		return -1;
	}

	sync = sync_state_alloc(tree, conn, inst, sync_no, config);

	/*
	 *	Might not necessarily have a cookie
	 */
	if (cookie) {
		char *bv_val;
		struct berval bvc;

		memcpy(&bv_val, &cookie, sizeof(bv_val));

		bvc.bv_val = bv_val;
		bvc.bv_len = talloc_array_length(cookie);

		ber_printf(ber, "{eOb}", LDAP_SYNC_REFRESH_AND_PERSIST, &bvc, false);
	} else {
		DEBUG2("Sync starting without a cookie");
		ber_printf(ber, "{eb}", LDAP_SYNC_REFRESH_AND_PERSIST, false);
	}

	ret = ber_flatten2(ber, &ctrls[0]->ldctl_value, 0);
	if (ret < 0) {
		ERROR("Failed creating sync control");
		ber_free(ber, 1);
	error:
		talloc_free(sync);
		return -1;
        }

	memcpy(&ctrls[0]->ldctl_oid, &sync_ctl_oid, sizeof(ctrls[0]->ldctl_oid));
	ctrl.ldctl_iscritical = 1;

	ret = fr_ldap_search_async(&sync->msgid, NULL, &conn, config->base_dn, config->scope,
				   config->filter, config->attrs, ctrls, NULL);
	ber_free(ber, 1);

	if (ret != LDAP_PROC_SUCCESS) {
		ERROR("Failed to start RFC 4533 query");
		goto error;
	}

	if (!fr_rb_insert(tree, sync)) {
		ERROR("Duplicate sync (msgid %i)", sync->msgid);
		goto error;
	}

	DEBUG3("Sync created with msgid %i", sync->msgid);

	/*
	 *	Register event to store cookies at a regular interval
	 */
	if (fr_event_timer_in(sync, conn->conn->el, &sync->cookie_ev,
			      inst->cookie_interval, ldap_sync_cookie_event, sync) < 0) {
		PERROR("Inserting LDAP cookie timer failed");
		goto error;
	}

	return 0;
}

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
int rfc4533_sync_search_entry(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
{
	int			ret = 0, i;
	ber_tag_t		bv_ret;
	BerElement		*ber = NULL;
	struct berval		entry_uuid = { 0 };
	sync_op_t		op = SYNC_OP_INVALID;
	bool			new_cookie;

	fr_assert(sync);
	fr_assert(sync->conn);
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

	bv_ret = ber_scanf(ber, "{em", &op, &entry_uuid);
	if ((bv_ret == LBER_ERROR) || (entry_uuid.bv_len == 0)) {
		ERROR("Malformed syncUUID value");
		goto error;
	}

	if (sync_new_cookie(&new_cookie, sync, ber) < 0) goto error;

	if (ber_scanf(ber, "}") == LBER_ERROR ) {
		ERROR("Malformed syncStatevalue sequence");
		goto error;
	}

	switch (op) {
	case SYNC_OP_PRESENT:
		switch (sync->phase) {

		case SYNC_PHASE_INIT:
			sync->phase = SYNC_PHASE_PRESENT;
			break;

		case SYNC_PHASE_PRESENT:
			break;

		default:
		bad_phase:
			ERROR("Entries with %s state are not allowed during refresh %s phase",
			      fr_table_str_by_value(sync_op_table, op, "<unknown>"),
			      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"));
			goto error;
		}
		break;

	case SYNC_OP_DELETE:
		switch (sync->phase) {
		case SYNC_PHASE_DELETE:
		case SYNC_PHASE_DONE:
			break;

		default:
			goto bad_phase;
		}
		break;

	case SYNC_OP_ADD:
	case SYNC_OP_MODIFY:
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
		ERROR("Unknown entry state (%i)", op);
		goto error;
	}

	if (DEBUG_ENABLED3) {
		char		*entry_dn;
		fr_value_box_t	uuid_box;

		entry_dn = ldap_get_dn(sync->conn->handle, msg);
		fr_ldap_berval_to_value_shallow(&uuid_box, &entry_uuid);

		DEBUG3("Processing %s (%s), dn \"%s\", entryUUID %pV",
		       fr_table_str_by_value(sync_ldap_msg_table, ldap_msgtype(msg), "<unknown>"),
		       fr_table_str_by_value(sync_op_table, op, "<unknown>"),
		       entry_dn ? entry_dn : "<unknown>",
		       &uuid_box);

		ldap_memfree(entry_dn);
	}

	/*
	 *	Send the appropriate packet type to process the message
	 */
	switch (ldap_msgtype(msg)) {
	case LDAP_RES_SEARCH_ENTRY:
		ret = ldap_sync_entry_send(sync, (uint8_t const *)entry_uuid.bv_val, NULL, msg, op);
		break;

	case LDAP_RES_SEARCH_REFERENCE:
	/* TODO - handle references */
		ldap_msgfree(msg);
		break;

	default:
		fr_assert(0);
	}

	/*
	 *	We have a new cookie - store it
	 */
	if ((ret == 0) && new_cookie) {
		ret = ldap_sync_cookie_store(sync, false);
	}
	ber_free(ber, 1);

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
int rfc4533_sync_intermediate(sync_state_t *sync, LDAPMessage *msg, UNUSED LDAPControl **ctrls)
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

	/*
	 *	Extract data from the message.  Setting freeit to 1 means the message
	 *	will be freed after the extract.
	 */
	ret = ldap_parse_intermediate(sync->conn->handle, msg, &oid, &data, NULL, 1);
	if (!fr_cond_assert(ret == LDAP_SUCCESS)) return -1;

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
	/*
	 *	A new cookie to store.
	 *	Typically provided when data in the directory has changed
	 *	but those changes don't match the search.
	 */
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

	/*
	 *	During the initial refresh operation, indicates the
	 *	end of the "present" phase.
	 */
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

		if (refresh_done) sync->phase = SYNC_PHASE_DONE;
		break;

	/*
	 *	During the initial refresh operation, indicates the
	 *	end of the "delete" phase.
	 */
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
		 *	The value of refresh_deletes indicates whether these are "present" or "delete"
		 */
		for (i = 0; sync_uuids[i].bv_val != NULL; i++) {
			if (sync_uuids[i].bv_len != SYNC_UUID_LENGTH) {
				ERROR("Invalid entryUUID length, expected " STRINGIFY(SYNC_UUID_LENGTH) " "
				      "bytes got %zu bytes", sync_uuids[i].bv_len);
				goto error;
			}
			ret = ldap_sync_entry_send(sync, (uint8_t const *)sync_uuids[i].bv_val, NULL, NULL,
						  (refresh_deletes ? SYNC_OP_DELETE : SYNC_OP_PRESENT));
			if (ret < 0) goto error;
		}

		ber_bvarray_free(sync_uuids);
		sync_uuids = NULL;
		break;

	default:
		ERROR("Invalid syncInfo tag %lu", sync_info_tag);
		goto error;

	}

	if (new_cookie) {
		ret = ldap_sync_cookie_store(sync, false);
	}

	if (ber) ber_free(ber, 1);
	if (oid) ldap_memfree(oid);
	if (data) ber_bvfree(data);

	return ret;
}

/** Handle result code of e-syncRefreshRequired
 *
 * If the server wishes to indicate that a refresh is required, it sends a searchResultDone
 * message with the result code e-syncRefreshRequired result code.  Any cookie provided
 * should be used on a query to re-start the sync.  If no cookie is provided, the new
 * query should be performed without a cookie to get a full refresh.
 *
 * @param[in] sync	message was associated with.
 * @param[in] msg	requesting the refresh.
 * @param[in] ctrls	associated with the msg.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rfc4533_sync_refresh_required(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
{
	int		refresh_deletes = 0;

	int		i;
	BerElement	*ber = NULL;
	ber_len_t	len;
	bool		new_cookie = false;

	fr_assert(sync);
	fr_assert(sync->conn);

	ldap_msgfree(msg);

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

	return ldap_sync_cookie_store(sync, true);
}
