# pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * $Id$
 *
 * @file proto_ldap_sync.h
 * @brief Structures for the LDAP Sync protocol
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/ldap/sync.h>

typedef struct sync_config_s sync_config_t;

/** An instance of a proto_ldap_sync listen section
 *
 */
typedef struct {
	CONF_SECTION		*server_cs;			//!< server CS for this listener.
	CONF_SECTION		*cs;				//!< my configuration.

	sync_config_t		**sync_config;			//!< DNs and filters to monitor.

	fr_app_t		*self;				//!< child / parent linking issues

	dl_module_inst_t	*io_submodule;			//!< As provided by the transport_parse
								//!< callback.  Broken out into the
								//!< app_io_* fields below for convenience.

	fr_app_io_t const	*app_io;			//!< Easy access to the app_io handle.
	void			*app_io_instance;		//!< Easy access to the app_io_instance.
	CONF_SECTION		*app_io_conf;			//!< Easy access to the app_io's configuration.

	fr_dict_t		*dict;				//!< root dictionary

	uint32_t		max_packet_size;		//!< for message ring buffer
	uint32_t		num_messages;			//!< for message ring buffer
	uint32_t		priority;			//!< for packet processing.

	fr_time_delta_t		cookie_interval;		//!< Interval between storing cookies.
	uint32_t		cookie_changes;			//!< Number of LDAP changes to process between
								//!< each cookie store operation.

	fr_schedule_t		*sc;

	fr_listen_t		*listen;			//!< The listener structure which describes
								//! the I/O path.
} proto_ldap_sync_t;

/** Operations to perform on entries
 */
typedef enum {
	SYNC_OP_INVALID			= -1,		//!< Invalid sync operation.
	SYNC_OP_PRESENT			= 0,		//!< Entry is present and unchanged on the server.
	SYNC_OP_ADD			= 1,		//!< Entry should be added to our copy.
	SYNC_OP_MODIFY			= 2,		//!< Entry should be updated in our copy.
	SYNC_OP_DELETE			= 3		//!< Entry should be deleted from our copy.
} sync_op_t;

typedef struct sync_state_s sync_state_t;

/** Allocate and initialise a sync query
 *
 * Called at the start of the sync operation, after any cookie has been retrieved.
 *
 * Sends the persistent search query to the LDAP server with the appropriate
 * controls for type of directory in use.
 *
 * @param[in] conn		to initialise the sync on
 * @param[in] sync_no		number of the sync in the array of configs.
 * @param[in] inst		instance of ldap_sync this query relates to
 * @param[in] cookie		to send with the query (RFC 4533 only)
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
 typedef int (*sync_init_t)(fr_ldap_connection_t *conn, size_t sync_no, proto_ldap_sync_t const *inst,
 			    uint8_t const *cookie);

/** Received an LDAP message related to a sync
 *
 * Called whenever the server returns a message, during any phase of the sync.
 *
 * This function is responsible for freeing the LDAP message.
 *
 * @param[in] sync	we received the message for.
 * @param[in] msg	the LDAP message received.
 * @param[in] ctrls	received with the message.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
typedef int (*sync_msg_t)(sync_state_t *sync, LDAPMessage *msg, LDAPControl **ctrls);

/** Areas of the directory to receive notifications for
 *
 */
struct sync_config_s {
	char const		*filter;		//!< Filter to retrieve only user objects.
	char const		*base_dn;		//!< DN to search for users under.

	char const		**attrs;		//!< Zero terminated attribute array.

	int			scope;			//!< Scope as its libldap value
	char const		*scope_str;		//!< Scope (sub, one, base).
	bool			changes_only;		//!< Do we only want changes, or do we want a full
							//!< directory load.  Not supported by Active Directory.

	map_list_t		entry_map;		//!< How to convert attributes in entries
							//!< to FreeRADIUS attributes.

	char const		*root_dn;		//!< The root DN for the directory.

	CONF_SECTION		*cs;			//!< Config section where this sync was defined.
							//!< Used for logging.

	/*
	 *	Callbacks for various events
	 */
	sync_init_t		init;			//!< Called to initialise a new search.

	sync_msg_t		entry;			//!< Called when we receive a searchEntry message.

	sync_msg_t		reference;		//!< Called when we receive a searchReference message.

	sync_msg_t		intermediate;		//!< Called when we receive a syncIntermediate message.

	sync_msg_t		refresh;		//!< Called when we receive a eSyncRefreshRequired code.

	void			*user_ctx;		//!< User ctx to pass to the callbacks.

	fr_pair_list_t		sync_pairs;		//!< Pairs representing the sync config sent to the worker
							//!< with each request.
};

int ldap_sync_conf_attr_add(sync_config_t *config, char const * attr);
