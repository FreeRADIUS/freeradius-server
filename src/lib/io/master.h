#pragma once
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

/**
 * $Id$
 *
 * @file io/master.h
 * @brief Master IO handler
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(master_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/util/talloc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_io_client_s fr_io_client_t;

typedef struct fr_io_track_s {
	fr_rb_node_t			node;		//!< rbtree node in the tracking tree.
	fr_listen_t const		*li;		//!< listener associated with this tracking structure
	fr_timer_t			*ev;		//!< when we clean up this tracking entry
	fr_time_t			timestamp;	//!< when this packet was received
	fr_time_t			expires;	//!< when this packet expires
	int				packets;     	//!< number of packets using this entry
	uint8_t				*reply;		//!< reply packet (if any)
	size_t				reply_len;	//!< length of reply, or 1 for "do not reply"

	bool				discard;	//!< whether or not we discard the packet
	bool				do_not_respond;	//!< don't respond
	bool				finished;	//!< are we finished the request?

	fr_time_t			dynamic;	//!< timestamp for packet doing dynamic client definition
	fr_io_address_t const  		*address;	//!< of this packet.. shared between multiple packets
	fr_io_client_t			*client;	//!< client handling this packet.
	uint8_t				*packet;	//!< really a tracking structure, not a packet
} fr_io_track_t;

/** The master IO instance
 *
 *  This structure is the instance data for the "master" IO handler.
 *  The structure is exposed for simplicity right now.  It may be
 *  made private in the future.
 *
 *  The fr_master_io_listen() should be used to create a listener from
 *  this structure.
 *
 *  Note that most entries of this structure MUST be initialized
 *  before fr_master_io_listen() is called.  That function only
 *  creates the listener, and adds it to the scheduler.
 */
typedef struct {
	module_instance_t 	  	*mi;				//!< our parent mi
	module_list_t			*clients;			//!< Holds client modules created to represent
									///< sockets created as clients connect to the
									///< listener.

	uint32_t			max_connections;		//!< maximum number of connections to allow
	uint32_t			max_clients;			//!< maximum number of dynamic clients to allow
	uint32_t			max_pending_packets;		//!< maximum number of pending packets

	fr_time_delta_t			cleanup_delay;			//!< for Access-Request packets
	fr_time_delta_t			idle_timeout;			//!< for connected clients
	fr_time_delta_t			dynamic_timeout;		//!< for dynamic clients
	fr_time_delta_t			nak_lifetime;			//!< lifetime of NAKed clients
	fr_time_delta_t			check_interval;			//!< polling for closed sockets

	bool				dynamic_clients;		//!< do we have dynamic clients.
	bool				log_ignored_clients;		//!< Whether we emit log messages when we ignore
									///< a client because it's unknown, or outside
									///< of the allowed networks.  This is here for
									///< people who expose their RADIUS servers to
									///< the internet, and don't want their logs filling
									///< up with random connection attempts.

	CONF_SECTION			*server_cs;			//!< server CS for this listener

	module_instance_t		*submodule;			//!< As provided by the transport_parse
									///< callback.  Broken out into the
									///< app_io_* fields below for convenience.
	fr_app_t			*app;				//!< main protocol handler
	void				*app_instance;			//!< instance data for main protocol handler

	fr_app_io_t const		*app_io;			//!< Easy access to the app_io handle.
	void				*app_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION			*app_io_conf;			//!< Easy access to the app_io's config section.

	int				ipproto;			//!< IP proto by number
	fr_trie_t const			*networks;     			//!< trie of allowed networks
} fr_io_instance_t;

extern fr_app_io_t fr_master_app_io;

fr_trie_t *fr_master_io_network(TALLOC_CTX *ctx, int af, fr_ipaddr_t *allow, fr_ipaddr_t *deny);
int fr_master_io_listen(fr_io_instance_t *io, fr_schedule_t *sc,
			size_t default_message_size, size_t num_messages) CC_HINT(nonnull);
fr_io_track_t *fr_master_io_track_alloc(fr_listen_t *li, fr_client_t *client, fr_ipaddr_t const *src_ipaddr, int src_port,
					fr_ipaddr_t const *dst_ipaddr, int dst_port);

#ifdef __cplusplus
}
#endif
