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
 * @file proto_ldap_sync_ldap.h
 * @brief Callback routines for the LDAP Sync protocol
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */

#include "proto_ldap_sync.h"
#include <lber.h>

#define SYNC_UUID_LENGTH		16

/** Phases of the initial refresh stage for RFC 4533 servers
 */
typedef enum {
	SYNC_PHASE_INIT			= 0,		//!< We haven't entered any of the refresh phases.
	SYNC_PHASE_PRESENT		= 1,		//!< Currently in the present phase.
	SYNC_PHASE_DELETE		= 2,		//!< Currently in the delete phase.
	SYNC_PHASE_DONE			= 3		//!< Refresh phase is complete.
} sync_phases_t;

/** State of an individual sync
 */
struct sync_state_s {
	fr_rb_node_t			node;		//!< Entry in the tree of nodes.

	fr_ldap_connection_t 		*conn;		//!< Connection the sync is running on.

	sync_config_t const		*config;	//!< Configuration for this sync

	int				msgid;		//!< The unique identifier for this sync session.

	size_t				sync_no;	//!< Array position of config for this sync.

	uint8_t				*cookie;	//!< Opaque cookie, used to resume synchronisation.

	sync_phases_t			phase;		//!< Phase this sync is in.

	fr_dlist_head_t			*filter;	//!< Parsed filter to be applied on the network side
							//!< before passing packets to the worker.
							//!< Predominantly to overcome Active Directory's lack
							//!< of filtering in persistent searches.

	proto_ldap_sync_t const		*inst;		//!< Module instance for this sync.

	fr_dlist_head_t			pending;	//!< List of pending changes in progress.

	uint32_t			pending_cookies;	//!< How many cookies are in the pending heap
	uint32_t			changes_since_cookie;	//!< How many changes have been added since
								//!< the last cookie was stored.

	fr_event_timer_t const		*cookie_ev;	//!< Timer event for sending cookies.
};

typedef struct sync_state_s sync_state_t;

/** Types of LDAP messages relevant to LDAP sync
 */
static fr_table_num_sorted_t const sync_ldap_msg_table[] = {
	{ L("intermediateResponse"),	LDAP_RES_INTERMEDIATE		},
	{ L("searchRes"),		LDAP_RES_SEARCH_RESULT		},
	{ L("searchResEntry"),		LDAP_RES_SEARCH_ENTRY		},
	{ L("searchResReference"),	LDAP_RES_SEARCH_REFERENCE	}
};
static size_t const sync_ldap_msg_table_len = NUM_ELEMENTS(sync_ldap_msg_table);

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	proto_ldap_sync_t		*parent;		//!< The module that spawned us.

	fr_ldap_config_t		handle_config;		//!< Connection configuration instance

	char const			*server;		//!< Server string from the config.  LDAP sync needs to
								//!< remain against a single server so this is used rather
								//!< than the server_str array in fr_ldap_config_t.

	char const			*tls_random_file;	//!< Path to the random file if /dev/random
								//!< and /dev/urandom are unavailable.

	uint32_t			ldap_debug;		//!< Debug flag for the SDK.
} proto_ldap_sync_ldap_t;

typedef struct {
	char const			*name;			//!< socket name
	proto_ldap_sync_ldap_t const	*inst;			//!< instance data

	fr_event_list_t			*el;			//!< Network side event list.
	fr_network_t			*nr;			//!< Network handler.
	fr_listen_t			*parent;		//!< master IO handler.
	fr_listen_t			*li;			//!< Our listener.

	fr_event_timer_t const		*conn_retry_ev;		//!< When to retry re-establishing the conn.

	fr_connection_t			*conn;			//!< Our connection to the LDAP directory.
} proto_ldap_sync_ldap_thread_t;

typedef enum {
	SYNC_PACKET_PENDING = 0,				//!< Packet not yet sent.
	SYNC_PACKET_PREPARING,					//!< Packet being prepared.
	SYNC_PACKET_PROCESSING,					//!< Packet sent to worker.
	SYNC_PACKET_COMPLETE,					//!< Packet response received from worker.
} sync_packet_status_t;

typedef enum {
	SYNC_PACKET_TYPE_CHANGE = 0,				//!< Packet is an entry change.
	SYNC_PACKET_TYPE_COOKIE
} sync_packet_type_t;

/** Tracking structure for ldap sync packets
 */
struct sync_packet_ctx_s {
	sync_packet_type_t		type;			//!< Type of packet.
	sync_packet_status_t		status;			//!< Status of this packet.
	sync_state_t			*sync;			//!< Sync packet relates to.

	uint8_t				*cookie;		//!< Cookie to store - can be NULL.
	bool				refresh;		//!< Does the sync require a refresh.

	fr_dlist_t			entry;			//!< Entry in list of pending packets.
};

typedef struct sync_packet_ctx_s sync_packet_ctx_t;

extern fr_table_num_sorted_t const sync_op_table[];
extern size_t sync_op_table_len;

int8_t sync_state_cmp(void const *one, void const *two);

sync_state_t *sync_state_alloc(TALLOC_CTX *ctx, fr_ldap_connection_t *conn, proto_ldap_sync_t const *inst,
			       size_t sync_no, sync_config_t const *config);

int ldap_sync_cookie_store(sync_state_t *sync, bool refresh);

void ldap_sync_cookie_event(fr_event_list_t *el, fr_time_t now, void *uctx);

int ldap_sync_cookie_send(sync_packet_ctx_t *sync_packet_ctx);

int ldap_sync_entry_send(sync_state_t *sync, uint8_t const uuid[SYNC_UUID_LENGTH], struct berval *orig_dn,
			LDAPMessage *msg, sync_op_t op);
