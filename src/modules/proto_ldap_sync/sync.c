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
 * @file src/modules/proto_ldap_sync/sync.c
 *
 * @brief Synchronisation controls for interacting with directories impliementing
 *	"LDAP Content Sync Operation" (RFC 4533).
 *
 * This code was inspired by the example client sync code available in libldap/ldap_sync.c
 * written by Pierangelo Masarati.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/util/debug.h>
#include <lber.h>
#include "sync.h"

struct sync_state_s {
	fr_ldap_connection_t 			*conn;

	sync_config_t const		*config;

	int				msgid;			//!< The unique identifier for this sync session.

	uint8_t				*cookie;		//!< Opaque cookie, used to resume synchronisation.

	sync_phases_t			phase;
};

fr_table_num_sorted_t sync_state_table[] = {
	{ "present",			SYNC_STATE_PRESENT		},
	{ "add",			SYNC_STATE_ADD			},
	{ "modify",			SYNC_STATE_MODIFY		},
	{ "delete",			SYNC_STATE_DELETE		}
};
size_t sync_state_table_len = NUM_ELEMENTS(sync_state_table);

fr_table_num_sorted_t sync_phase_table[] = {
	{ "delete",			SYNC_PHASE_DELETE		},
	{ "delete-idset",		SYNC_PHASE_DELETE_IDSET		},
	{ "done",			SYNC_PHASE_DONE			},
	{ "init",			SYNC_PHASE_INIT			},
	{ "present",			SYNC_PHASE_PRESENT		},
	{ "present-idset",		SYNC_PHASE_PRESENT_IDSET	}
};
size_t sync_phase_table_len = NUM_ELEMENTS(sync_state_table);

fr_table_num_sorted_t sync_protocol_op_table[] = {
	{ "intermediateResponse",	LDAP_RES_INTERMEDIATE		},
	{ "searchRes",			LDAP_RES_SEARCH_RESULT		},
	{ "searchResEntry",		LDAP_RES_SEARCH_ENTRY		},
	{ "searchResReference",		LDAP_RES_SEARCH_REFERENCE	}
};
size_t sync_protocol_op_table_len = NUM_ELEMENTS(sync_state_table);

fr_table_num_sorted_t sync_info_tag_table[] = {
 	{ "newCookie",			LDAP_TAG_SYNC_NEW_COOKIE	},
 	{ "refreshDelete",		LDAP_TAG_SYNC_REFRESH_DELETE	},
	{ "refreshIDSet",		LDAP_TAG_SYNC_ID_SET		},
 	{ "refreshPresent",		LDAP_TAG_SYNC_REFRESH_PRESENT	}
};
size_t sync_info_tag_table_len = NUM_ELEMENTS(sync_state_table);

/** Process a cookie element
 *
 * @param[out] new_cookie	Whether we got a new cookie value.
 * @param[in] sync		message was associated with.
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
	if (ber_peek_tag(ber, &len) != LDAP_TAG_SYNC_COOKIE) return 0;

	bv_ret = ber_scanf(ber, "m", &cookie);
	if (bv_ret == LBER_ERROR) {
		ERROR("Malformed cookie tag");
		return -1;
	}

	/*
	 *  "no cookie" can mean either no cookie element,
	 *  or a NULL cookie element (as per the RFC).
	 */
	if (!cookie.bv_val) return 0;

	if (sync->cookie) {
		if (talloc_array_length(sync->cookie) == cookie.bv_len) {
			cookie_len = talloc_array_length(sync->cookie);
			if (memcmp(sync->cookie, cookie.bv_val, cookie.bv_len)) {
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

/** Handle a LDAP_RES_SEARCH_ENTRY (SearchResultEntry) or LDAP_RES_SEARCH_REFRENCE (SearchResultReference) response
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
static int sync_search_entry_or_reference(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
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
/*
		case SYNC_PHASE_INIT:
			sync->phase = SYNC_PHASE_PRESENT;
			break;
*/

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
		switch (sync->phase) {
		case SYNC_PHASE_INIT:
		case SYNC_PHASE_DONE:
			break;

		default:
			goto bad_phase;
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
			ret = sync->config->reference(sync->conn, sync->config, sync->msgid, sync->phase,
						      (uint8_t const *)entry_uuid.bv_val,
						      msg, state, sync->config->user_ctx);
		}
	} else {
		if (sync->config->entry) {
			ret = sync->config->entry(sync->conn, sync->config, sync->msgid, sync->phase,
						  (uint8_t const *)entry_uuid.bv_val,
						  msg, state, sync->config->user_ctx);
		}
	}

	if ((ret == 0) && new_cookie && sync->config->cookie) {
		ret = sync->config->cookie(sync->conn, sync->config, sync->msgid, sync->cookie, sync->config->user_ctx);
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
		case SYNC_PHASE_PRESENT_IDSET:
			sync->phase = SYNC_PHASE_DELETE;
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
			switch (sync->phase) {
			case SYNC_PHASE_INIT:
			case SYNC_PHASE_PRESENT:
			case SYNC_PHASE_PRESENT_IDSET:
				sync->phase = SYNC_PHASE_DELETE_IDSET;
				break;

			default:
				ERROR("Invalid refresh phase transition (%s->%s)",
				      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"),
				      fr_table_str_by_value(sync_phase_table, SYNC_PHASE_DELETE, "<unknown>"));
				goto error;
			}
		} else {
			switch (sync->phase) {
			case SYNC_PHASE_INIT:
				sync->phase = SYNC_PHASE_PRESENT_IDSET;
				break;

			default:
				ERROR("Invalid refresh phase transition (%s->%s)",
				      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"),
				      fr_table_str_by_value(sync_phase_table, SYNC_PHASE_DELETE, "<unknown>"));
				goto error;
			}
		}

		for (i = 0; sync_uuids[i].bv_val != NULL; i++) {
			if (sync_uuids[i].bv_len != SYNC_UUID_LENGTH) {
				ERROR("Invalid entryUUID length, expected " STRINGIFY(SYNC_UUID_LENGTH) " "
				      "bytes got %zu bytes", sync_uuids[i].bv_len);
				goto error;
			}

			ret = sync->config->entry(sync->conn, sync->config, sync->msgid, sync->phase,
						  (uint8_t const *)sync_uuids[i].bv_val, NULL, SYNC_STATE_DELETE,
						  sync->config->user_ctx);
			if (!ret) goto error;
		}

		ber_bvarray_free(sync_uuids);
		sync_uuids = NULL;
		break;

	default:
		ERROR("Invalid syncInfo tag %lu", sync_info_tag);
		goto error;

	}

	if (new_cookie && sync->config->cookie) {
		ret = sync->config->cookie(sync->conn, sync->config, sync->msgid, sync->cookie, sync->config->user_ctx);
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
 * It's only used for refreshOnly operations to indicate that the server is done returning
 * search results, with refreshAndPersist an intermediateResult message is used instead.
 *
 * @param[in] sync	message was associated with.
 * @param[in] msg	containing an entry to process.
 * @param[in] ctrls	associated with the msg.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int sync_search_result(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls)
{
	int		ret = 0;
	int		refresh_deletes = 0;

	int		i;
	BerElement	*ber = NULL;
	ber_len_t	len;
	bool		new_cookie;

	fr_assert(sync->conn);
	fr_assert(sync);
	fr_assert(msg);

	/*
	 *	Should not happen with refreshAndPersist
	 */
	if (sync->config->persist) {
		ERROR("searchResult is invalid for refreshAndPersist mode");
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

	/*
	 *	Check the searchDoneValue matches the phase we're in
	 */
	if (refresh_deletes) {
		switch (sync->phase) {
		case SYNC_PHASE_DELETE:
		case SYNC_PHASE_DELETE_IDSET:
			break;

		default:
			ERROR("syncDone control indicated end of refresh delete phase but "
			      "We were in refresh %s phase",
			      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"));
			goto error;
		}
	} else {
		switch (sync->phase) {
		case SYNC_PHASE_PRESENT:
		case SYNC_PHASE_PRESENT_IDSET:
			break;

		default:
			ERROR("syncDone control indicated end of refresh present phase but "
			      "we were in refresh %s phase",
			      fr_table_str_by_value(sync_phase_table, sync->phase, "<unknown>"));
			goto error;
		}
	}

	if (sync->config->done) {
		ret = sync->config->done(sync->conn, sync->config, sync->msgid, sync->phase, sync->config->user_ctx);
		if (ret != 0) goto error;
	}

	if (new_cookie && sync->config->cookie) {
		ret = sync->config->cookie(sync->conn, sync->config, sync->msgid, sync->cookie, sync->config->user_ctx);
	}
	if (msg) ldap_memfree(msg);

	sync->phase = SYNC_PHASE_DONE;

	return ret;
}

/** Function to call when the LDAP handle's FD is readable
 *
 * @param[out] sync_id		the last sync_id serviced.
 * @param[in] conn		to service.
 * @return
 *	- 0 on success.
 *	- -1 on sync error.
 *	- -2 on conn error.  Requires the handle to be destroyed.
 */
int sync_demux(int *sync_id, fr_ldap_connection_t *conn)
{
	struct	timeval		poll = { 1, 0 };	/* Poll */
	LDAPMessage		*msg, *head = NULL;
	int			ret = 0;
	fr_ldap_rcode_t		rcode;
	sync_state_t		find = { .msgid = -1 }, *sync = NULL;
	rbtree_t		*tree;

	tree = talloc_get_type_abort(conn->uctx, rbtree_t);

	fr_assert(conn);

	/*
	 *	Drain any messages outstanding on this connection
	 */
	ret = ldap_result(conn->handle, LDAP_RES_ANY, LDAP_MSG_RECEIVED, &poll, &head);
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
	for (msg = ldap_first_message(conn->handle, head);
	     msg;
	     msg = ldap_next_message(conn->handle, msg)) {
		int		type;
		int		msgid;
		LDAPControl	**ctrls;

		*sync_id = msgid = ldap_msgid(msg);
		type = ldap_msgtype(msg);

		if (msgid == 0) {
			WARN("Ignoring unsolicited %s message",
			     fr_table_str_by_value(sync_protocol_op_table, type, "<invalid>"));
			continue;
		}

		/*
		 *	Only search if we're receiving messages from
		 *	a different sync.
		 */
		if (!sync || (sync->msgid != msgid)) {
			find.msgid = msgid;

			sync = rbtree_finddata(tree, &find);
			if (!sync) {
				WARN("Ignoring msgid %i, doesn't match any outstanding syncs",
				     find.msgid);
				continue;
			}
		}

		/*
		 *	Check for errors contained within the message
		 *	This has to be per message, as multiple syncs
		 *	are multiplexed together on one connection.
		 */
		switch (fr_ldap_error_check(&ctrls, conn, msg, sync->config->base_dn)) {
		case LDAP_PROC_SUCCESS:
			break;

		case LDAP_PROC_REFRESH_REQUIRED:
			if (!sync->config->refresh_required) return -1;

			DEBUG2("LDAP Server returned e-syncRefreshRequired");
			return sync->config->refresh_required(conn, sync->config, sync->msgid,
							      sync->phase, sync->config->user_ctx);

		/*
		 *	Don't think this should happen... but libldap
		 *	is wonky sometimes...
		 */
		case LDAP_PROC_BAD_CONN:
			if (ctrls) ldap_controls_free(ctrls);
			PERROR("Connection unusable");
			return -2;

		default:
		sync_error:
			if (ctrls) ldap_controls_free(ctrls);
			PERROR("Sync error");
			return -1;
		}

		DEBUG3("Got %s message for sync (msgid %i)",
		       fr_table_str_by_value(sync_protocol_op_table, type, "<invalid>"), sync->msgid);

		switch (type) {
		case LDAP_RES_SEARCH_REFERENCE:
		case LDAP_RES_SEARCH_ENTRY:
			ret = sync_search_entry_or_reference(sync, msg, ctrls);
			if (ret < 0) goto sync_error;
			break;

		case LDAP_RES_SEARCH_RESULT:
			ret = sync_search_result(sync, msg, ctrls);
			if (ret < 0) goto sync_error;
			break;

		case LDAP_RES_INTERMEDIATE:
			ret = sync_intermediate(sync, msg, ctrls);
			if (ret < 0) goto sync_error;
			break;

		default:
			WARN("Ignoring unexpected message type (%i)", type);
			break;
		}

		ldap_controls_free(ctrls);
	}

	ldap_msgfree(head);

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
	rbtree_t	*tree = talloc_get_type_abort(conn->uctx, rbtree_t);
	sync_state_t	find = { .msgid = sync->msgid };

	fr_assert(sync->conn->handle);

	DEBUG3("Abandoning sync");

	if (!sync->conn->handle) return 0;	/* Handled already closed? */

	/*
	 *	Tell the remote server to stop sending results
	 */
	ldap_abandon_ext(sync->conn->handle, sync->msgid, NULL, NULL);
	rbtree_deletebydata(tree, &find);

	return 0;
}

/** Compare two sync state structures on msgid
 *
 * @param[in] one first sync to compare.
 * @param[in] two second sync to compare.
 * @return the difference between the msgids.
 */
static int _sync_cmp(void const *one, void const *two)
{
	sync_state_t const *a = one, *b = two;

	return a->msgid - b->msgid;
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
	rbtree_t	*tree;

	if (!conn->uctx) return;

	tree = talloc_get_type_abort(conn->uctx, rbtree_t);

	find.msgid = msgid;

	sync = rbtree_finddata(tree, &find);
	talloc_free(sync);	/* Will inform the server */
}

/** Return the configuration of a sync
 *
 * @param[in] conn	the connection.
 * @param[in] msgid	of the sync to return the config for.
 */
sync_config_t const *sync_state_config_get(fr_ldap_connection_t *conn, int msgid)
{
	sync_state_t	find, *sync;
	rbtree_t	*tree;

	if (!conn->uctx) return NULL;

	tree = talloc_get_type_abort(conn->uctx, rbtree_t);

	find.msgid = msgid;

	sync = rbtree_finddata(tree, &find);
	return sync->config;
}

/** Allocate a sync state structure and issue the search
 *
 * The Sync Request Control is an LDAP Control [RFC4511] where the controlType is the object
 * identifier 1.3.6.1.4.1.4203.1.9.1.1 and the controlValue, an OCTET STRING, contains a
 * BER-encoded syncRequestValue.  The criticality field is either TRUE or FALSE.
 *
 * syncRequestValue ::= SEQUENCE {
 *     mode ENUMERATED {
 *         -- 0 unused
 *         refreshOnly       (1),
 *         -- 2 reserved
 *         refreshAndPersist (3)
 *     },
 *     cookie     syncCookie OPTIONAL,
 *     reloadHint BOOLEAN DEFAULT FALSE
 * }
 *
 * The Sync Request Control is only applicable to the SearchRequest Message.
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
	static char const	*sync_ctl_oid = LDAP_CONTROL_SYNC;

	LDAPControl		ctrl = {0}, *ctrls[2] = { &ctrl, NULL };
	BerElement		*ber = NULL;
	int			ret;
	int			mode;
	sync_state_t		*sync;
	rbtree_t		*tree;

	fr_assert(conn);
	fr_assert(config);

	mode = config->persist ? LDAP_SYNC_REFRESH_AND_PERSIST : LDAP_SYNC_REFRESH_ONLY;

	/*
	 *	Allocate or retrieve the tree of outstanding msgids
	 *	these are specific to the connection.
	 */
	if (!conn->uctx) {
		MEM(tree = rbtree_talloc_alloc(conn, _sync_cmp, sync_state_t, NULL, RBTREE_FLAG_NONE));
		conn->uctx = tree;
	} else {
		tree = talloc_get_type_abort(conn->uctx, rbtree_t);
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

		ber_free(ber, 1);
                talloc_free(sync);

		return -1;
        }

	/*
	 *	Mark the control as critical
	 */
	memcpy(&ctrl.ldctl_oid, &sync_ctl_oid, sizeof(ctrl.ldctl_oid));
	ctrl.ldctl_iscritical = 1;

	ret = fr_ldap_search_async(&sync->msgid, NULL,
				   &conn,
				   config->base_dn, config->scope, config->filter, config->attrs,
				   ctrls, NULL);
	ber_free(ber, 1);
	if (ret != LDAP_PROC_SUCCESS) {
		talloc_free(sync);
		return -1;
	}

	if (!rbtree_insert(tree, sync)) {
		ERROR("Duplicate sync (msgid %i)", sync->msgid);
		return -1;
	}
	DEBUG3("Sync created with msgid %i", sync->msgid);

	return 0;
}
