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

/*
 * $Id$
 *
 * @file proto_radius.h
 * @brief Structures for the RADIUS protocol
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */

#include <freeradius-devel/trie.h>


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
	struct fr_io_client_t		*client;	//!< for this packet
	uint8_t				packet[20];	//!< original RADIUS packet.
} fr_io_track_t;

/** A saved packet
 *
 */
typedef struct {
	int			heap_id;
	uint32_t		priority;
	fr_time_t		recv_time;
	fr_io_track_t		*track;
	uint8_t			*buffer;
	size_t			buffer_len;
} fr_io_pending_packet_t;


/** Client states
 *
 */
typedef enum {
	PR_CLIENT_INVALID = 0,
	PR_CLIENT_STATIC,				//!< static / global clients
	PR_CLIENT_NAK,					//!< negative cache entry
	PR_CLIENT_DYNAMIC,				//!< dynamically defined client
	PR_CLIENT_CONNECTED,				//!< dynamically defined client in a connected socket
	PR_CLIENT_PENDING,				//!< dynamic client pending definition
} fr_io_client_state_t;

/** Client definitions for proto_radius
 *
 */
typedef struct fr_io_client_t {
	fr_io_client_state_t		state;		//!< state of this client
	fr_ipaddr_t			src_ipaddr;	//!< packets come from this address
	fr_ipaddr_t			network;	//!< network for dynamic clients
	RADCLIENT			*radclient;	//!< old-style definition of this client

	int				packets;	//!< number of packets using this client
	int				heap_id;	//!< for pending clients

	bool				connected;	//!< is this client for a connected socket?
	bool				use_connected;	//!< does this client allow connected sub-sockets?
	bool				ready_to_delete; //!< are we ready to delete this client?
	bool				in_trie;	//!< is the client in the trie?

	struct fr_io_instance_t		*inst;		//!< parent instance for master IO handler
	fr_event_timer_t const		*ev;		//!< when we clean up the client
	rbtree_t			*table;		//!< tracking table for packets

	fr_heap_t			*pending;	//!< pending packets for this client
	fr_hash_table_t			*addresses;	//!< list of src/dst addresses used by this client

	pthread_mutex_t			mutex;		//!< for parent / child signaling
	fr_hash_table_t			*ht;		//!< for tracking connected sockets
} fr_io_client_t;

/** Track a connection
 *
 *  This structure contains information about the connection,
 *  a pointer to the library instance so that we can clean up on exit,
 *  and the listener.
 *
 *  It also points to a client structure which is for this connection,
 *  and only this connection.
 *
 *  Finally, a pointer to the parent client, so that the child can
 *  tell the parent it's alive, and the parent can push packets to the
 *  child.
 */
typedef struct {
	int				magic;		//!< sparkles and unicorns
	char const			*name;		//!< taken from proto_radius_TRANSPORT
	int				packets;	//!< number of packets using this connection
	fr_io_address_t   		*address;      	//!< full information about the connection.
	fr_listen_t			*listen;	//!< listener for this socket
	fr_io_client_t			*client;	//!< our local client (pending or connected).
	fr_io_client_t			*parent;	//!< points to the parent client.
	dl_instance_t   		*dl_inst;	//!< for submodule

	bool				dead;		//!< roundabout way to get the network side to close a socket
	bool				paused;		//!< event filter doesn't like resuming something that isn't paused
	void				*app_io_instance; //!< as described
	fr_event_list_t			*el;		//!< event list for this connection
	fr_network_t			*nr;		//!< network for this connection
} fr_io_connection_t;

extern fr_app_io_t proto_radius_master_io;

typedef struct fr_io_instance_t {
	int				magic;				//!< sparkles and unicorns

	dl_instance_t const    		*dl_inst;			//!< our parent dl_inst

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

/** An instance of a proto_radius listen section
 *
 */
typedef struct proto_radius_t {
	fr_io_instance_t		io;				//!< wrapper for IO abstraction

	dl_instance_t			**type_submodule;		//!< Instance of the various types
	dl_instance_t			*dynamic_submodule;		//!< proto_radius_dynamic_client
									//!< only one instance per type allowed.
	fr_io_process_t			process_by_code[FR_MAX_PACKET_CODE];	//!< Lookup process entry point by code.

	uint32_t			max_packet_size;		//!< for message ring buffer.
	uint32_t			num_messages;			//!< for message ring buffer.

	bool				tunnel_password_zeros;		//!< check for trailing zeroes in Tunnel-Password.

	bool				code_allowed[FR_CODE_MAX + 1];	//!< Allowed packet codes.

	uint32_t			priorities[FR_MAX_PACKET_CODE];	//!< priorities for individual packets
} proto_radius_t;

#define PR_CONNECTION_MAGIC (0x434f4e4e)
#define PR_MAIN_MAGIC	    (0x4d4149e4)

