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
 * @copyright 2018 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(master_h, "$Id$")

#include <talloc.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/trie.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	fr_event_timer_t const		*ev;		//!< when we clean up this tracking entry
	fr_time_t			timestamp;	//!< when this packet was received
	int				packets;     	//!< number of packets using this entry
	uint8_t				*reply;		//!< reply packet (if any)
	size_t				reply_len;	//!< length of reply, or 1 for "do not reply"

	/*
	 *	We can't set the "process" function here, because a
	 *	second (conflicting) packet may arrive while we're
	 *	processing this one.  Instead, set the timestamp of
	 *	the packet which creates the dynamic client
	 *	definition.
	 */
	fr_time_t			dynamic;	//!< timestamp for packet doing dynamic client definition
	fr_io_address_t   		*address;	//!< of this packet.. shared between multiple packets
	struct fr_io_client_t		*client;	//!< client handling this packet.
	uint8_t				packet[20];	//!< original request packet
} fr_io_track_t;


typedef struct fr_io_instance_t {
	int				magic;				//!< sparkles and unicorns

	TALLOC_CTX			*ctx;				//!< this struct might not be talloc'd
	dl_instance_t const   		*dl_inst;			//!< our parent dl_inst

	uint32_t			max_connections;		//!< maximum number of connections to allow
	uint32_t			max_clients;			//!< maximum number of dynamic clients to allow
	uint32_t			max_pending_packets;		//!< maximum number of pending packets

	// @todo - count num_nak_clients, and num_nak_connections, too
	uint32_t			num_connections;		//!< number of dynamic connections
	uint32_t			num_clients;			//!< number of dynamic clients
	uint32_t			num_pending_packets;   		//!< number of pending packets

	struct timeval			cleanup_delay;			//!< for Access-Request packets
	struct timeval			idle_timeout;			//!< for dynamic clients
	struct timeval			nak_lifetime;			//!< lifetime of NAKed clients
	struct timeval			check_interval;			//!< polling for closed sockets

	bool				dynamic_clients;		//!< do we have dynamic clients.

	CONF_SECTION			*server_cs;			//!< server CS for this listener

	dl_instance_t			*submodule;			//!< As provided by the transport_parse
									///< callback.  Broken out into the
									///< app_io_* fields below for convenience.

	fr_app_t			*app;				//!< main protocol handler
	void				*app_instance;			//!< instance data for main protocol handler

	fr_app_io_t const		*app_io;			//!< Easy access to the app_io handle.
	void				*app_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION			*app_io_conf;			//!< Easy access to the app_io's config section.

	fr_listen_t const		*listen;			//!< The listener structure which describes
									///< the I/O path.
	fr_schedule_t			*sc;				//!< the scheduler

	int				ipproto;			//!< IP proto by number
	char const			*transport;			//!< transport, typically name of IP proto

	fr_event_list_t			*el;				//!< event list, for the master socket.
	fr_network_t			*nr;				//!< network for the master socket

	fr_trie_t			*trie;				//!< trie of clients
	fr_trie_t const			*networks;     			//!< trie of allowed networks
	fr_heap_t			*pending_clients;		//!< heap of pending clients
} fr_io_instance_t;

extern fr_app_io_t fr_master_app_io;

fr_trie_t *fr_master_io_network(TALLOC_CTX *ctx, int af, fr_ipaddr_t *allow, fr_ipaddr_t *deny);

#ifdef __cplusplus
}
#endif
