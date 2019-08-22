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
 * @file src/modules/proto_ldap_sync/sync.h
 *
 * @brief Perform persistent searches against LDAP directories, to perform actions
 *	  if their contents change.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/ldap/base.h>
#include <lber.h>

#define SYNC_UUID_LENGTH		16

/** Operations to perform on entries
 */
typedef enum {
	SYNC_STATE_INVALID		= -1,			//!< Invalid sync state.
	SYNC_STATE_PRESENT		= 0,			//!< Entry is present on the server.
	SYNC_STATE_ADD			= 1,			//!< Entry should be added to our copy.
	SYNC_STATE_MODIFY		= 2,			//!< Entry should be updated in our copy.
	SYNC_STATE_DELETE		= 3			//!< Entry should be deleted from our copy.
} sync_states_t;

typedef enum {
	SYNC_PHASE_FLAG_IDSET		= 0x10,			//!< We received an IDSET instead of individual entries.

	SYNC_PHASE_INIT			= 0x00,			//!< We haven't entered any of the refresh phases.
	SYNC_PHASE_PRESENT		= 0x01,			//!< Currently in the present phase.
	SYNC_PHASE_DELETE		= 0x02,			//!< Currently in the delete phase.
	SYNC_PHASE_PRESENT_IDSET 	= (SYNC_PHASE_PRESENT | SYNC_PHASE_FLAG_IDSET),
	SYNC_PHASE_DELETE_IDSET 	= (SYNC_PHASE_PRESENT | SYNC_PHASE_FLAG_IDSET),
	SYNC_PHASE_DONE			= 0x04			//!< Refresh phase is complete.
} sync_phases_t;

typedef struct sync_state_s sync_state_t;
typedef struct sync_config_s sync_config_t;

/** Received a new cookie
 *
 * Called any time we receive a new cookie value from the server which is different
 * from a previous cookie value.
 *
 * This callback should store the cookie value so that it can be passed to sync_state_init
 * on reload.
 *
 * @param[in] conn	we received the message containing the cookie on.
 * @param[in] config	defining the sync.
 * @param[in] sync_id	the cookie is related to.
 * @param[in] cookie	the opaque cookie value.  May or may not be a printable string.
 *			Use talloc_array_length(cookie) to get the length.
 * @param[in] user_ctx	data.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_new_cookie_t)(fr_ldap_connection_t *conn, sync_config_t const *config,
				 int sync_id, uint8_t const *cookie, void *user_ctx);

/** Informed that the refresh phase has changed
 *
 * Called any time the refresh phase changes.
 *
 * @param[in] conn	we received the message indicating a refresh phase change on.
 * @param[in] config	defining the sync.
 * @param[in] sync_id	the refresh phase change is related to.
 * @param[in] phase	the sync is now in.
 * @param[in] user_ctx	data.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_phase_change_t)(fr_ldap_connection_t *conn, sync_config_t const *config,
				   int sync_id, sync_phases_t phase, void *user_ctx);

/** Received an e-syncRefreshRequired error code
 *
 * Called any time the server wants us to perform a complete refresh of the contents
 * of the directory.
 *
 * @param[in] conn	we received the message indicating a refresh phase change on.
 * @param[in] config	defining the sync.
 * @param[in] sync_id	the refresh phase change is related to.
 * @param[in] phase	the sync was in.
 * @param[in] user_ctx	data.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_refresh_required_t)(fr_ldap_connection_t *conn, sync_config_t const *config,
				       int sync_id, sync_phases_t phase, void *user_ctx);

/** Received an update for en entry
 *
 * Called during
 *
 * @param[in] conn	we received the message indicating a refresh phase change on.
 * @param[in] config	defining the sync.
 * @param[in] sync_id	the refresh phase change is related to.
 * @param[in] phase	the sync is now in.
 * @param[in] uuid	of the entries relevant to this phase.
 * @param[in] user_ctx	data.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_entry_t)(fr_ldap_connection_t *conn, sync_config_t const *config,
			    int sync_id, sync_phases_t phase,
			    uint8_t const uuid[SYNC_UUID_LENGTH], LDAPMessage *msg, sync_states_t state,
			    void *user_ctx);


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
								//!< refreshes.
	bool				allow_refresh;		//!< If false, we synthesize the cookie value
								//!< when no cookie is available.

	/*
	 *	LDAP attribute to RADIUS map
	 */
	vp_map_t			*entry_map;		//!< How to convert attributes in entries
								//!< to FreeRADIUS attributes.

	/*
	 *	Callbacks for various events
	 */
	sync_new_cookie_t		cookie;			//!< Called when we have a new cookie.

	sync_phase_change_t		present;		//!< Called when entering the present phase.

	sync_phase_change_t		delete;			//!< Called when entering the delete phase.

	sync_refresh_required_t		refresh_required;	//!< Called when we receive e-syncRefreshRequired.

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

int			sync_demux(int *sync_id, fr_ldap_connection_t *conn);

void			sync_state_destroy(fr_ldap_connection_t *conn, int msgid);

sync_config_t const	*sync_state_config_get(fr_ldap_connection_t *conn, int msgid);

int			sync_state_init(fr_ldap_connection_t *conn, sync_config_t const *config,
					uint8_t const *cookie, bool reload_hint);
