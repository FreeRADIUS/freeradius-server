#pragma once
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
 * @file src/modules/proto_ldap_sync/sync.h
 *
 * @brief Perform persistent searches against LDAP directories, to perform actions
 *	  if their contents change.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/ldap/base.h>
#include <lber.h>

/** Types of the internal packets for processing LDAP sync messages
 */
typedef enum {
	FR_LDAP_SYNC_CODE_UNDEFINED		= 0,	//!< Packet code has not been set.
	FR_LDAP_SYNC_CODE_PRESENT		= 1,	//!< LDAP server indicates a particular object is
							//!< present and unchanged.
	FR_LDAP_SYNC_CODE_ADD			= 2,	//!< Object has been added to the LDAP directory.
	FR_LDAP_SYNC_CODE_MODIFY		= 3,	//!< Object has been modified.
	FR_LDAP_SYNC_CODE_DELETE		= 4,	//!< Object has been deleted.
	FR_LDAP_SYNC_CODE_ENTRY_RESPONSE	= 5,	//!< Response packet to present / add / modify / delete.
	FR_LDAP_SYNC_CODE_COOKIE_LOAD		= 6,	//!< Before the sync starts, request any previously stored cookie.
	FR_LDAP_SYNC_CODE_COOKIE_LOAD_RESPONSE	= 7,	//!< Response with the returned cookie.
	FR_LDAP_SYNC_CODE_COOKIE_STORE		= 8,	//!< The server has sent a new cookie.
	FR_LDAP_SYNC_CODE_COOKIE_STORE_RESPONSE	= 9,	//!< Response to storing the new cookie.
	FR_LDAP_SYNC_CODE_MAX			= 10,
	FR_LDAP_SYNC_CODE_DO_NOT_RESPOND	= 256	//!< Special rcode to indicate we will not respond.
} fr_ldap_sync_packet_code_t;

#define FR_LDAP_SYNC_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_LDAP_SYNC_CODE_MAX))

#define SYNC_UUID_LENGTH		16

/** Operations to perform on entries
 */
typedef enum {
	SYNC_STATE_INVALID		= -1,			//!< Invalid sync state.
	SYNC_STATE_PRESENT		= 0,			//!< Entry is present and unchanged on the server.
	SYNC_STATE_ADD			= 1,			//!< Entry should be added to our copy.
	SYNC_STATE_MODIFY		= 2,			//!< Entry should be updated in our copy.
	SYNC_STATE_DELETE		= 3			//!< Entry should be deleted from our copy.
} sync_states_t;

/** Phases of the initial refresh stage for RFC 4533 servers
 */
typedef enum {
	SYNC_PHASE_INIT			= 0,			//!< We haven't entered any of the refresh phases.
	SYNC_PHASE_PRESENT		= 1,			//!< Currently in the present phase.
	SYNC_PHASE_DELETE		= 2,			//!< Currently in the delete phase.
	SYNC_PHASE_DONE			= 3			//!< Refresh phase is complete.
} sync_phases_t;

typedef struct sync_config_s sync_config_t;

typedef struct ldap_filter_s ldap_filter_t;

/** State of an individual sync
 */
struct sync_state_s {
	fr_rb_node_t			node;			//!< Entry in the tree of nodes.

	fr_ldap_connection_t 		*conn;			//!< Connection the sync is running on.

	sync_config_t const		*config;		//!< Configuration for this sync

	int				msgid;			//!< The unique identifier for this sync session.

	uint8_t				*cookie;		//!< Opaque cookie, used to resume synchronisation.

	sync_phases_t			phase;			//!< Phase this sync is in.
};

typedef struct sync_state_s sync_state_t;

/** Tracking structure for individual sync packets
 *
 * Allows the LDAPMessage to be passed from network to worker.
 */
struct sync_entry_packet_s {
	LDAPMessage			*msg;			//!< The LDAP message received.

	fr_ldap_connection_t		*conn;			//!< Connection on which wht message was received.

	sync_config_t const		*config;		//!< Config of sync the message relates to.
};

typedef struct sync_entry_packet_s sync_entry_packet_t;

/** Tracking structure for connections requiring refresh
 */
struct sync_refresh_packet_s {
	sync_state_t			*sync;			//!< Sync requiring refresh

	uint8_t				*refresh_cookie;	//!< Cookie provided by the server for the refresh.
};

typedef struct sync_refresh_packet_s sync_refresh_packet_t;

/** Received a new cookie
 *
 * Called any time we receive a new cookie value from the server which is different
 * from a previous cookie value.
 *
 * This callback should store the cookie value so that it can be passed to sync_state_init
 * on reload.
 *
 * @param[in] sync	we received the message containing the cookie for.
 * @param[in] cookie	the opaque cookie valie.  May or may not be a printable string.
 * 			Use the talloc_array_length(cookie) to get the length.
 * @param[in] refresh	After this cookie has been stored, restart the search - the server
 *			indicated a refresh is required.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_new_cookie_t)(sync_state_t *sync, uint8_t const *cookie, bool refresh);

/** Informed that the refresh phase has changed
 *
 * Called any time the refresh phase changes.
 *
 * @param[in] sync	we received the message indicating a refresh phase change for.
 * @param[in] phase	the sync is now in.
 * @param[in] refresh_deletes	flag (if applicable).
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_phase_change_t)(sync_state_t *sync, sync_phases_t phase, int refresh_deletes);

/** Received an update for an entry
 *
 * Called whenever the server returns an entry, during any phase of the sync.
 *
 * This function is responsible for freeing the LDAP message.
 *
 * @param[in] sync	we received the message for.
 * @param[in] uuid	of the entries relevant to this phase.
 * @param[in] orig_dn	original DN of the entry, if renamed and supported by the server.
 * @param[in] msg	the LDAP message.
 * @param[in] state	type of modification to perform.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_entry_t)(sync_state_t *sync, uint8_t const uuid[SYNC_UUID_LENGTH],
			    struct berval *orig_dn, LDAPMessage *msg, sync_states_t state);


/** Areas of the directory to receive notifications for
 *
 */
struct sync_config_s {
	char const			*filter;		//!< Filter to retrieve only user objects.
	char const			*base_dn;		//!< DN to search for users under.

	char const			**attrs;		//!< Zero terminated attribute array.

	int				scope;
	char const			*scope_str;		//!< Scope (sub, one, base).
	size_t				size_limit;		//!< Maximum size of the entry to return.
	fr_time_delta_t			time_limit;		//!< Time limit.
	bool				persist;		//!< Whether we do a search and persist, or periodic
								//!< refreshes.  RFC 4533 servers
	bool				changes_only;		//!< Do we only want changes, or do we want a full
								//!< directory load.  Persistent search servers.
	bool				allow_refresh;		//!< If false, we synthesize the cookie value
								//!< when no cookie is available.

	/*
	 *	LDAP attribute to RADIUS map
	 */
	map_list_t			entry_map;		//!< How to convert attributes in entries
								//!< to FreeRADIUS attributes.

	/*
	 *	Callbacks for various events
	 */
	sync_new_cookie_t		cookie;			//!< Called when we have a new cookie.

	sync_phase_change_t		done;			//!< Called when refresh is complete.

	sync_entry_t			entry;			//!< Called when we receive a new entry.

	sync_entry_t			reference;		//!< Called when we receive a new reference.

	void				*user_ctx;		//!< User ctx to pass to the callbacks.
};

extern fr_table_num_sorted_t sync_state_table[];
extern size_t sync_state_table_len;
extern fr_table_num_sorted_t sync_phase_table[];
extern size_t sync_phase_table_len;
extern fr_table_num_sorted_t sync_protocol_op_table[];
extern size_t sync_protocol_op_table_len;
extern fr_table_num_sorted_t sync_info_tag_table[];
extern size_t sync_info_tag_table_len;

int	sync_demux(fr_ldap_connection_t *conn);

void	sync_state_destroy(fr_ldap_connection_t *conn, int msgid);

int	sync_state_init(fr_ldap_connection_t *conn, sync_config_t const *config, uint8_t const *cookie,
			bool reload_hint);
