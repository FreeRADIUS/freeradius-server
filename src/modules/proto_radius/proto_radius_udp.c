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
 * @file proto_radius_udp.c
 * @brief RADIUS handler for UDP.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/track.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

typedef struct {
	int				if_index;

	fr_ipaddr_t			src_ipaddr;
	fr_ipaddr_t			dst_ipaddr;
	uint16_t			src_port;
	uint16_t 			dst_port;

	int				code;			//!< for duplicate detection
	int				id;			//!< for duplicate detection

	RADCLIENT			*client;
} proto_radius_udp_address_t;

typedef struct dynamic_client_t {
	dl_instance_t			*submodule;		//!< proto_radius_dynamic_client
	fr_ipaddr_t			*network;		//!< dynamic networks to allow

	RADCLIENT_LIST			*clients;		//!< local clients
	RADCLIENT_LIST			*expired;		//!< expired local clients

	fr_dlist_t			packets;       		//!< list of accepted packets
	fr_dlist_t			pending;		//!< pending clients

	uint32_t			max_clients;		//!< maximum number of dynamic clients
	uint32_t			num_clients;		//!< total number of active clients
	uint32_t			max_pending_clients;	//!< maximum number of pending clients
	uint32_t			num_pending_clients;	//!< number of pending clients
	uint32_t			max_pending_packets;	//!< maximum accepted pending packets
	uint32_t			num_pending_packets;	//!< how many packets are received, but not accepted

	uint32_t			lifetime;		//!< of the dynamic client, in seconds.
} dynamic_client_t;

typedef struct {
	proto_radius_t	const		*parent;		//!< The module that spawned us!
	char const			*name;			//!< socket name

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request
	fr_network_t			*nr;			//!< for fr_network_listen_read();

	fr_ipaddr_t			ipaddr;			//!< Ipaddr to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint16_t			port;			//!< Port to listen on.
	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	fr_tracking_t			*ft;			//!< tracking table
	uint32_t			cleanup_delay;		//!< cleanup delay for Access-Request packets

	fr_stats_t			stats;			//!< statistics for this socket

	dynamic_client_t		dynamic_clients;	//!< dynamic client infromation

	bool				dynamic_clients_is_set;	//!< set if we have dynamic clients
	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	uint32_t			priorities[FR_MAX_PACKET_CODE];	//!< priorities for individual packets
} proto_radius_udp_t;


typedef struct dynamic_packet_t {
	uint8_t			*packet;
	fr_tracking_entry_t	*track;
	fr_dlist_t		entry;
} dynamic_packet_t;

static const CONF_PARSER dynamic_client_config[] = {
	{ FR_CONF_OFFSET("network", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, dynamic_client_t, network) },

	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, dynamic_client_t, max_clients), .dflt = "65536" },
	{ FR_CONF_OFFSET("max_pending_clients", FR_TYPE_UINT32, dynamic_client_t, max_pending_clients), .dflt = "256" },
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, dynamic_client_t, max_pending_packets), .dflt = "65536" },

	{ FR_CONF_OFFSET("lifetime", FR_TYPE_UINT32, dynamic_client_t, lifetime), .dflt = "600" },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_radius_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_radius_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_radius_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_radius_udp_t, port) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, proto_radius_udp_t, recv_buff) },

	{ FR_CONF_OFFSET("cleanup_delay", FR_TYPE_UINT32, proto_radius_udp_t, cleanup_delay), .dflt = "5" },

	/*
	 *	Note that we have to pass offset of dynamic_client to get the "IS_SET" functionality.
	 *	But that screws up the entries in the dynamic_client_config, which are now offset
	 *	from THIS offset, instead of offset from the start of proto_radius_udp_t;
	 */
	{ FR_CONF_IS_SET_OFFSET("dynamic_clients", FR_TYPE_SUBSECTION | FR_TYPE_OK_MISSING, proto_radius_udp_t, dynamic_clients),
	  .subcs = (void const *) dynamic_client_config },
	CONF_PARSER_TERMINATOR
};


/*
 *	Allow configurable priorities for each listener.
 */
static uint32_t priorities[FR_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_REQUEST] = PRIORITY_HIGH,
	[FR_CODE_ACCOUNTING_REQUEST] = PRIORITY_LOW,
	[FR_CODE_COA_REQUEST] = PRIORITY_NORMAL,
	[FR_CODE_DISCONNECT_REQUEST] = PRIORITY_NORMAL,
	[FR_CODE_STATUS_SERVER] = PRIORITY_NOW,
};


static const CONF_PARSER priority_config[] = {
	{ FR_CONF_OFFSET("Access-Request", FR_TYPE_UINT32, proto_radius_udp_t, priorities[FR_CODE_ACCESS_REQUEST]),
	  .dflt = STRINGIFY(PRIORITY_HIGH) },
	{ FR_CONF_OFFSET("Accounting-Request", FR_TYPE_UINT32, proto_radius_udp_t, priorities[FR_CODE_ACCOUNTING_REQUEST]),
	  .dflt = STRINGIFY(PRIORITY_LOW) },
	{ FR_CONF_OFFSET("CoA-Request", FR_TYPE_UINT32, proto_radius_udp_t, priorities[FR_CODE_COA_REQUEST]),
	  .dflt = STRINGIFY(PRIORITY_NORMAL) },
	{ FR_CONF_OFFSET("Disconnect-Request", FR_TYPE_UINT32, proto_radius_udp_t, priorities[FR_CODE_DISCONNECT_REQUEST]),
	  .dflt = STRINGIFY(PRIORITY_NORMAL) },
	{ FR_CONF_OFFSET("Status-Server", FR_TYPE_UINT32, proto_radius_udp_t, priorities[FR_CODE_STATUS_SERVER]),
	  .dflt = STRINGIFY(PRIORITY_NOW) },

	CONF_PARSER_TERMINATOR
};


/*
 *	@todo - put packets to be cleaned up in a heap or linked list,
 *	and then have one cleanup delay per rlm_radius_udp_t.  That
 *	way we can have a timer which fires periodically, and then
 *	cleans up multiple packets.
 */
static void mod_cleanup_delay(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	fr_tracking_entry_t *track = uctx;
	// proto_radius_udp_t const *inst = talloc_parent(track->ft);

	DEBUG2("TIMER - proto_radius cleanup delay for ID %d", track->data[1]);

	(void) fr_radius_tracking_entry_delete(track->ft, track);
}

/** Return the src address associated with the packet_ctx
 *
 */
static int mod_src_address(fr_socket_addr_t *src, UNUSED void const *instance, void const *packet_ctx)
{
	fr_tracking_entry_t const		*track = packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	memset(src, 0, sizeof(*src));

	src->proto = IPPROTO_UDP;
	memcpy(&src->ipaddr, &address->src_ipaddr, sizeof(src->ipaddr));

	return 0;
}

/** Return the dst address associated with the packet_ctx
 *
 */
static int mod_dst_address(fr_socket_addr_t *dst, UNUSED void const *instance, void const *packet_ctx)
{
	fr_tracking_entry_t const		*track = packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	memset(dst, 0, sizeof(*dst));

	dst->proto = IPPROTO_UDP;
	memcpy(&dst->ipaddr, &address->dst_ipaddr, sizeof(dst->ipaddr));

	return 0;
}

/** Return the client associated with the packet_ctx
 *
 */
static RADCLIENT *mod_client(UNUSED void const *instance, void const *packet_ctx)
{
	fr_tracking_entry_t const		*track = packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	return address->client;
}


static ssize_t mod_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_udp_t const		*inst = instance;
	fr_tracking_entry_t const		*track = request->async->packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;
	RADCLIENT				*client;

	/*
	 *	Not a dynamic client, or it's an active one.  Let
	 *	proto_radius do all of the work.
	 */
	if (!inst->dynamic_clients_is_set || !address->client->dynamic || address->client->active) return 0;

	/*
	 *	This will never happen...
	 */
	if (buffer_len < sizeof(client)) {
		buffer[0] = 1;
		return 1;
	}

	/*
	 *	Allocate the client.  If that fails, send back a NAK.
	 *
	 *	@todo - deal with NUMA zones?  Or just deal with this
	 *	client being in different memory.
	 *
	 *	Maybe we should create a CONF_SECTION from the client,
	 *	and pass *that* back to mod_write(), which can then
	 *	parse it to create the actual client....
	 */
	client = client_afrom_request(NULL, request);
	if (!client) {
		ERROR("Failed creating new client: %s", fr_strerror());
		buffer[0] = 1;
		return 1;
	}

	memcpy(buffer, &client, sizeof(client));
	return sizeof(client);
}


static int mod_decode(void const *instance, REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{
	proto_radius_udp_t const			*inst = instance;
	fr_tracking_entry_t const		*track = request->async->packet_ctx;
	proto_radius_udp_address_t const	*address = track->src_dst;

	rad_assert(track->src_dst_size == sizeof(proto_radius_udp_address_t));

	request->client = address->client;
	request->packet->if_index = address->if_index;
	request->packet->src_ipaddr = address->src_ipaddr;
	request->packet->src_port = address->src_port;
	request->packet->dst_ipaddr = address->dst_ipaddr;
	request->packet->dst_port = address->dst_port;

	request->reply->if_index = address->if_index;
	request->reply->src_ipaddr = address->dst_ipaddr;
	request->reply->src_port = address->dst_port;
	request->reply->dst_ipaddr = address->src_ipaddr;
	request->reply->dst_port = address->src_port;

	request->root = &main_config;
	REQUEST_VERIFY(request);

	if (request->client->dynamic && !request->client->active) {
		fr_app_process_t const	*app_process;
		vp_cursor_t cursor;
		VALUE_PAIR *vp;

		app_process = (fr_app_process_t const *) inst->dynamic_clients.submodule->module->common;

		request->async->process = app_process->process;

		/*
		 *	Mash all encrypted attributes to sane
		 *	(i.e. non-hurtful) values.
		 */
		for (vp = fr_pair_cursor_init(&cursor, &request->packet->vps);
		     vp != NULL;
		     vp = fr_pair_cursor_next(&cursor)) {
			if (vp->da->flags.encrypt != FLAG_ENCRYPT_NONE) {
				switch (vp->da->type) {
				default:
					break;

				case FR_TYPE_UINT32:
					vp->vp_uint32 = 0;
					break;

				case FR_TYPE_IPV4_ADDR:
					vp->vp_ipv4addr = INADDR_ANY;
					break;

				case FR_TYPE_OCTETS:
					fr_pair_value_memcpy(vp, (uint8_t const *) "", 1);
					break;

				case FR_TYPE_STRING:
					fr_pair_value_strcpy(vp, "");
					break;
				}
			}
		}
	}

	return 0;
}

static ssize_t dynamic_client_packet_restore(proto_radius_udp_t *inst, uint8_t *buffer, size_t buffer_len,
					     fr_tracking_entry_t **track)
{
	fr_dlist_t		*entry;
	dynamic_packet_t	*saved;
	size_t			packet_len;

	entry = FR_DLIST_FIRST(inst->dynamic_clients.packets);
	if (!entry) return -1;
	fr_dlist_remove(entry);

	saved = fr_ptr_to_type(dynamic_packet_t, entry, entry);
	rad_assert(saved);
	rad_assert(saved->packet != NULL);
	rad_assert(saved->track != NULL);

	/*
	 *	Can't copy the packet over, there's nothing more we
	 *	can do.
	 */
	packet_len = talloc_array_length(saved->packet);
	if (packet_len > buffer_len) {
		(void) fr_radius_tracking_entry_delete(inst->ft, saved->track);
		talloc_free(saved);
		return -1;
	}

	/*
	 *	Copy the saved packet back to the output buffer.
	 */
	memcpy(buffer, saved->packet, packet_len);
	*track = saved->track;
	talloc_free(saved);

	return packet_len;
}


static int dynamic_client_packet_save(proto_radius_udp_t *inst, uint8_t *packet, size_t packet_len,
				      proto_radius_udp_address_t *address, fr_tracking_entry_t **track)
{
	dynamic_packet_t	*saved;
	fr_tracking_status_t	tracking_status;

	if (inst->dynamic_clients.num_pending_packets >= inst->dynamic_clients.max_pending_packets) {
		DEBUG("Too many pending packets - ignoring packet.");
		return -1;
	}

	tracking_status = fr_radius_tracking_entry_insert(track, inst->ft, packet, fr_time(), address);
	switch (tracking_status) {
	case FR_TRACKING_ERROR:
	case FR_TRACKING_UNUSED:
		rad_assert(0 == 1);
		return 0;	/* shouldn't happen */

		/*
		 *	Retransmit of the same packet.  There's
		 *	nothing we can do.
		 */
	case FR_TRACKING_SAME:
		return 0;

		/*
		 *	We're done the old packet, and have received a
		 *	new packet.  This shouldn't happen here.  If
		 *	we're done the old packet, we shouldn't be calling this function.
		 */
	case FR_TRACKING_UPDATED:
		DEBUG3("UPDATED packet");
		rad_assert(0 == 1);
		return 0;

		/*
		 *	We're NOT done the old packet, and have
		 *	received a new packet.  This can happen if the
		 *	old packet is taking too long.  Oh well... we
		 *	will just discard the old one in mod_write()
		 */
	case FR_TRACKING_CONFLICTING:
		DEBUG3("CONFLICTING packet ID %d", packet[1]);
		break;

		/*
		 *	We have a brand new packet.  Remember it!
		 */
	case FR_TRACKING_NEW:
		DEBUG3("NEW packet");
		break;
	}

	MEM(saved = talloc_zero(inst, dynamic_packet_t));
	MEM(saved->packet = talloc_memdup(saved, packet, packet_len));
	saved->track = *track;
	fr_dlist_insert_tail(&address->client->packets, &saved->entry);

	inst->dynamic_clients.num_pending_packets++;

	return 0;
}


static ssize_t dynamic_client_alloc(proto_radius_udp_t *inst, uint8_t *packet, size_t packet_len,
				    proto_radius_udp_address_t *address, fr_tracking_entry_t **track, fr_ipaddr_t *network)
{
	RADCLIENT *client;

	/*
	 *	Limit the total number of clients.
	 */
	if (inst->dynamic_clients.num_clients >= inst->dynamic_clients.max_clients) {
		DEBUG("Too many dynamic clients - ignoring packet.");
		return 0;
	}

	/*
	 *	Limit the total number of pending clients.
	 */
	if (inst->dynamic_clients.num_pending_clients >= inst->dynamic_clients.max_pending_clients) {
		DEBUG("Too many pending dynamic clients");
		return 0;
	}

	/*
	 *	Allocate the bare client, and fill in some basic fields.
	 */
	client = talloc_zero(inst, RADCLIENT);
	if (!client) {
		return 0;
	}

	FR_DLIST_INIT(client->packets);
	client->active = false;
	client->dynamic = true;
	client->secret = client->longname = client->shortname = client->nas_type = talloc_strdup(client, "");

	client->ipaddr = address->src_ipaddr;
	client->src_ipaddr = address->dst_ipaddr;
	client->network = *network;

	address->client = client;

	/*
	 *	Save a copy of this packet in the client, so that we
	 *	can re-play it once we accept the client.
	 */
	if (dynamic_client_packet_save(inst, packet, packet_len, address, track) < 0) {
		talloc_free(client);
		return 0;
	}

	/*
	 *	It's now one of our clients (pending).
	 *
	 *	We can rely on the worker enforcing max_request_time,
	 *	so we don't need to do something similar here.
	 *
	 *	i.e. if the client takes 30s to define, well, too
	 *	bad...
	 */
	if (!client_add(inst->dynamic_clients.clients, client)) {
		talloc_free(client);
		return -1;
	}

	fr_dlist_insert_tail(&inst->dynamic_clients.pending, &client->pending);

	inst->dynamic_clients.num_pending_clients++;

	/*
	 *	Check for the case of renewing an expired client.  If
	 *	so, delete it's expiration timer.
	 *
	 *	We'll do the same checks when we create or NAK the
	 *	client in mod_write().  If it matches, we'll just
	 *	renew the existing client, instead of defining a new
	 *	one.  That allows for *renewal* instead of deletion
	 *	and re-creation.
	 */
	client = client_find(inst->dynamic_clients.expired, &address->src_ipaddr, IPPROTO_UDP);
	if (client && client->ev) (void) fr_event_timer_delete(inst->el, &client->ev);

	return packet_len;
}

static void dynamic_client_timer(proto_radius_udp_t *inst, RADCLIENT *client, uint32_t timer);

static void dynamic_client_expire(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	RADCLIENT *client = uctx;
	proto_radius_udp_t *inst = client->ctx;

	DEBUG("TIMER - checking dynamic client %s for expiration.", client->shortname);

	/*
	 *	The client has expired, and no one is using it.
	 *	Remove it from the expired list, and free it.
	 */
	if (client->expired) {
		DEBUG("%s - deleting client %s.", inst->name, client->shortname);
		(void) client_delete(inst->dynamic_clients.expired, client);
		rad_assert(client->outstanding == 0);
		client_free(client);
		return;
	}

	/*
	 *	Mark the client as "expired", so that any new packets
	 *	will result in us trying to re-define it.  Remove it
	 *	from the main list, BUT add it to the "expired" list.
	 */
	client->expired = true;
	client_delete(inst->dynamic_clients.clients, client);
	client_add(inst->dynamic_clients.expired, client);

	/*
	 *	There are no active requests using this client.  It
	 *	can be deleted.  However, we only free the client when
	 *	we're sure that all packets associated with the client
	 *	have timed out.
	 *
	 *	@todo - move to a tracking table per client (or per
	 *	connection).  That way we know that when we delete the
	 *	client or close the connection, we can free all
	 *	packets associated with it.  Even if the packets are
	 *	in "cleanup_delay" state.
	 */
	if (client->outstanding == 0) {
		DEBUG("%s - marking dynamic client %s for deletion.", inst->name, client->shortname);
		dynamic_client_timer(inst, client, inst->cleanup_delay + 5);
		return;
	}

	/*
	 *	Else there are still packets in the workers, wake up
	 *	in another 30 seconds and try again.
	 */
	DEBUG("%s - there are still outstanding packets for client %s, will try again in 30s.",
	      inst->name, client->shortname);
	dynamic_client_timer(inst, client, 30);
}

static void dynamic_client_timer(proto_radius_udp_t *inst, RADCLIENT *client, uint32_t timer)
{
	struct timeval when;

	/*
	 *	This client lives forever.  Don't expire it!
	 */
	if (!timer) return;

	/*
	 *	It's not active, AND it's not a negative cache.  We
	 *	had some other error trying to insert a "good" client
	 *	into the list of known clients.  Just nuke it, and
	 *	allow another packet to try to recreate it.
	 */
	if (!client->expired && !client->active && !client->negative) {
		talloc_free(client);
		return;
	}

	gettimeofday(&when, NULL);
	when.tv_sec += timer;

	client->ctx = inst;	/* nowhere else to put this... */

	if (fr_event_timer_insert(client, inst->el, &client->ev,
				  &when, dynamic_client_expire, client) < 0) {
		ERROR("Failed adding timeout for dynamic client.  It will be permanent!");
		return;
	}
}

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority)
{
	proto_radius_udp_t		*inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	ssize_t				data_size;
	size_t				packet_len;
	decode_fail_t			reason;

	struct timeval			timestamp;
	fr_tracking_status_t		tracking_status;
	fr_tracking_entry_t		*track = NULL;
	proto_radius_udp_address_t	address;
	fr_dlist_t			*entry;

	/*
	 *	There are saved packets.  Go read them.
	 */
	entry = FR_DLIST_FIRST(inst->dynamic_clients.packets);
	if (entry) {
		data_size = dynamic_client_packet_restore(inst, buffer, buffer_len, &track);
		if (data_size < 0) {
			rad_assert(0 == 1);
			return 0;
		}

		packet_len = data_size;

		rad_assert(track != NULL);
		rad_assert(track->src_dst != NULL);
		address.client = ((proto_radius_udp_address_t *)track->src_dst)->client;
		goto received_packet;
	}

	*leftover = 0;

	data_size = udp_recv(inst->sockfd, buffer, buffer_len, 0,
			     &address.src_ipaddr, &address.src_port,
			     &address.dst_ipaddr, &address.dst_port,
			     &address.if_index, &timestamp);
	if (data_size < 0) {
		DEBUG2("proto_radius_udp got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_radius_udp got no data: ignoring");
		return 0;
	}

	packet_len = data_size;

	if (data_size < 20) {
		DEBUG2("proto_radius_udp got 'too short' packet size %zd", data_size);
		inst->stats.total_malformed_requests++;
		return 0;
	}

	if ((buffer[0] == 0) || (buffer[0] > FR_MAX_PACKET_CODE)) {
		DEBUG("proto_radius_udp got invalid packet code %d", buffer[0]);
		inst->stats.total_unknown_types++;
		return 0;
	}

	if (!inst->parent->process_by_code[buffer[0]]) {
		DEBUG("proto_radius_udp got unexpected packet code %d", buffer[0]);
		inst->stats.total_unknown_types++;
		return 0;
	}

	/*
	 *	If it's not a RADIUS packet, ignore it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, inst->parent->max_attributes, false, &reason)) {
		/*
		 *	@todo - check for F5 load balancer packets.  <sigh>
		 */
		DEBUG2("proto_radius_udp got a packet which isn't RADIUS");
		inst->stats.total_malformed_requests++;
		return 0;
	}

	/*
	 *	Track the packet ID.
	 */
	address.code = buffer[0];
	address.id = buffer[1];

	/*
	 *	Look up the client.  It either exists, or we create
	 *	it.
	 */
	address.client = client_find(NULL, &address.src_ipaddr, IPPROTO_UDP);
	if (!address.client) {
		size_t i, num;

		if (!inst->dynamic_clients_is_set) {
		unknown:
			ERROR("Packet from unknown client at address %pV:%u - ignoring.",
			      fr_box_ipaddr(address.src_ipaddr), address.src_port);
			inst->stats.total_invalid_requests++;
			return 0;
		}

		/*
		 *	We have dynamic clients.  Try to find the
		 *	client in the dynamic client set.
		 */
		address.client = client_find(inst->dynamic_clients.clients, &address.src_ipaddr, IPPROTO_UDP);
		if (address.client) {
			if (!address.client->dynamic || address.client->active) goto found;

			if (address.client->negative) {
				goto unknown;
			}

			/*
			 *	It's dynamic, but inactive.  Save the
			 *	packet in the client, and return.
			 *
			 *	When the client becomes active, the
			 *	packet will be removed from the list,
			 *	and sent to the network side.
			 */
			if (dynamic_client_packet_save(inst, buffer, packet_len, &address, &track) < 0) {
				goto unknown;
			}

			return 0;
		}

		/*
		 *	The client wasn't found.  It MIGHT be allowed.
		 *	Search through the allowed networks, to see if
		 *	the source IP matches a listed network.
		 *
		 *	@todo - put the networks && clients into a
		 *	patricia tree, so we only do one search for
		 *	them, instead of N searches.
		 */
		num = talloc_array_length(inst->dynamic_clients.network);
		for (i = 0; i < num; i++) {
			fr_ipaddr_t ipaddr;

			/*
			 *	fr_ipaddr_cmp() compares prefixes,
			 *	too.  So we have to mask the source
			 *	IP.
			 */
			ipaddr = address.src_ipaddr;
			fr_ipaddr_mask(&ipaddr, inst->dynamic_clients.network[i].prefix);

			if (fr_ipaddr_cmp(&ipaddr, &inst->dynamic_clients.network[i]) == 0) {
				DEBUG("Found matching network.  Checking for dynamic client definition.");
				if (dynamic_client_alloc(inst, buffer, packet_len, &address, &track,
							 &inst->dynamic_clients.network[i]) < 0) {
					DEBUG("Failed allocating dynamic client");
					goto unknown;
				}

				/*
				 *	Return the packet, but it's
				 *	ALREADY been inserted into the
				 *	tracking table.
				 */
				goto return_packet;
			}
		}

		/*
		 *	No match, it's definitely unknown;
		 */
		goto unknown;
	}

found:
	/*
	 *	If the signature fails validation, ignore it.
	 */
	if (fr_radius_verify(buffer, NULL,
			     (uint8_t const *)address.client->secret,
			     talloc_array_length(address.client->secret) - 1) < 0) {
		DEBUG2("proto_radius_udp packet failed verification: %s", fr_strerror());
		inst->stats.total_bad_authenticators++;
		return 0;
	}

	tracking_status = fr_radius_tracking_entry_insert(&track, inst->ft, buffer, fr_time(), &address);
	switch (tracking_status) {
	case FR_TRACKING_ERROR:
	case FR_TRACKING_UNUSED:
		inst->stats.total_packets_dropped++;
		return -1;	/* Fatal */

		/*
		 *	If the entry already has a cleanup delay, we
		 *	extend the cleanup delay.  i.e. the cleanup
		 *	delay is from the last reply we sent, not from
		 *	the first one.
		 */
	case FR_TRACKING_SAME:
		DEBUG3("SAME packet");
		if (track->ev) {
			struct timeval tv;

			gettimeofday(&tv, NULL);
			tv.tv_sec += inst->cleanup_delay;

			DEBUG3("SAME packet - cleanup");
			(void) fr_event_timer_insert(NULL, inst->el, &track->ev,
						     &tv, mod_cleanup_delay, track);
		}

		inst->stats.total_dup_requests++;

		/*
		 *	We are intentionally not responding.
		 */
		if (track->reply_len == 1) {
			return 0;
		}

		/*
		 *	Otherwise it's a duplicate packet.  Send the
		 *	whole thing over to the network stack, noting
		 *	that the tracking code ensures we get
		 *	"recv_time" from the ORIGINAL packet, and not
		 *	from now.
		 */
		break;

	/*
	 *	Delete any pre-existing cleanup_delay timers.
	 */
	case FR_TRACKING_UPDATED:
		DEBUG3("UPDATED packet");
		if (track->ev) (void) fr_event_timer_delete(inst->el, &track->ev);
		break;

	case FR_TRACKING_CONFLICTING:
		DEBUG3("CONFLICTING packet ID %d", buffer[1]);
		return 0;	/* discard it */

	case FR_TRACKING_NEW:
		DEBUG3("NEW packet");
		break;
	}

received_packet:
	inst->stats.total_requests++;
	rad_assert(address.client != NULL);
	address.client->outstanding++;

return_packet:
	*packet_ctx = track;
	*recv_time = &track->timestamp;
	*priority = priorities[buffer[0]];

	return packet_len;
}


static ssize_t mod_write(void *instance, void *packet_ctx,
			 fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_udp_t		*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	fr_tracking_entry_t		*track = packet_ctx;
	proto_radius_udp_address_t	*address = track->src_dst;

	ssize_t				data_size;
	fr_time_t			reply_time;
	struct timeval			tv;

	/*
	 *	Check for the first packet back from a dynamic client
	 *	definition.  If we find it, add the client (or not),
	 *	as required.
	 */
	if (inst->dynamic_clients_is_set && address->client->dynamic && !address->client->active) {
		RADCLIENT *client = address->client;
		RADCLIENT *newclient, *expired = NULL;
		fr_dlist_t *entry;
		dynamic_packet_t *saved;

		/*
		 *	@todo - maybe just duplicate the new client fields,
		 *	and talloc_free(newclient).
		 */
		inst->dynamic_clients.num_pending_clients--;

		/*
		 *	NAK: drop all packets.
		 *
		 *	If it's an explicit NAK, then add the source
		 *	IP to a negative cache as a DoS prevention.
		 */
		if (buffer_len == 1) {
			client->negative = true;

		nak:
			while ((entry = FR_DLIST_FIRST(client->packets)) != NULL) {
				saved = fr_ptr_to_type(dynamic_packet_t, entry, entry);
				(void) fr_radius_tracking_entry_delete(inst->ft, saved->track);
				fr_dlist_remove(&saved->entry);
				talloc_free(saved);
				inst->dynamic_clients.num_pending_packets--;
			}

			/*
			 *	If we were renewing an expired client,
			 *	then delete the expired one, and add
			 *	the new definition.
			 */
			if (!expired) {
				expired = client_find(inst->dynamic_clients.expired, &client->ipaddr, IPPROTO_UDP);
				if (expired) {
					rad_assert(expired->outstanding == 0);
					client_delete(inst->dynamic_clients.expired, expired);
					talloc_free(expired);
				}
			}

			dynamic_client_timer(inst, client, 30);
			return buffer_len;
		}

		rad_assert(buffer_len == sizeof(newclient));
		memcpy(&newclient, buffer, sizeof(newclient));

		/*
		 *	Delete the "pending" client from the client list.
		 */
		client_delete(inst->dynamic_clients.clients, client);

		/*
		 *	See if we had a previously expired client.  If
		 *	not, just create a new one.
		 */
		expired = client_find(inst->dynamic_clients.expired, &newclient->ipaddr, IPPROTO_UDP);
		if (!expired) {
			DEBUG("%s - Defining new client %s", inst->name, client->shortname);
			newclient->dynamic = true;

			/*
			 *	If we can't add it, then clean it up.  BUT
			 *	allow other packets to come from the same IP.
			 */
			if (!client_add(inst->dynamic_clients.clients, newclient)) {
				talloc_free(newclient);
				client->negative = false;
				goto nak;
			}

			newclient->active = true;
			inst->dynamic_clients.num_clients++;

		} else {
			ssize_t elen, nlen;

			elen = talloc_array_length(expired->secret);
			nlen = talloc_array_length(newclient->secret);

			/*
			 *	Catch stupid administrator issues.
			 */
			if ((elen != nlen) || (memcmp(expired->secret, newclient->secret, elen) != 0)) {
				ERROR("Shared secret for clients cannot be changed until all outstanding packets have been processed");
				expired->active = false;
				goto nak;
			}

			if (fr_ipaddr_cmp(&expired->ipaddr, &newclient->ipaddr) != 0) {
				ERROR("IP / netmask for clients cannot be changed until all outstanding packets have been processed");
				expired->active = false;
				goto nak;
			}

			DEBUG("%s - Renewing client %s", inst->name, expired->shortname);
			rad_assert(expired->ev == NULL);

			talloc_free(newclient);
			newclient = expired;
			newclient->expired = false;

			client_delete(inst->dynamic_clients.expired, expired);
			if (!client_add(inst->dynamic_clients.clients, newclient)) {
				talloc_free(newclient);
				newclient->negative = false;
				goto nak;
			}

			rad_assert(newclient->active == true);
			rad_assert(newclient->negative == false);
		}

		/*
		 *	This particular packet had a later one
		 *	over-ride it.  We still add the client, but
		 *	don't send the packet on towards mod_read()
		 */
		if (track->timestamp != request_time) {
			DEBUG3("First packet was too late, discarding it.");

			entry = FR_DLIST_FIRST(client->packets);
			rad_assert(entry != NULL);
			saved = fr_ptr_to_type(dynamic_packet_t, entry, entry);

			fr_dlist_remove(&saved->entry);
			/* leave the tracking table entry - it's used by a later packet */
			rad_assert(saved->track == track);
			talloc_free(saved);
			inst->dynamic_clients.num_pending_packets--;
		}

		/*
		 *	Move the packets over to the pending list, and
		 *	re-write their client pointers to be the newly
		 *	allocated one.
		 */
		while ((entry = FR_DLIST_FIRST(client->packets)) != NULL) {
			DEBUG3("Restoring packet...");

			saved = fr_ptr_to_type(dynamic_packet_t, entry, entry);
			fr_dlist_remove(&saved->entry);
			fr_dlist_insert_tail(&inst->dynamic_clients.packets, &saved->entry);

			address = saved->track->src_dst;
			address->client = newclient;

			rad_assert(inst->dynamic_clients.num_pending_packets > 0);
			inst->dynamic_clients.num_pending_packets--;
		}

		/*
		 *	Set up the lifetime for the newly defined
		 *	client.
		 */
		dynamic_client_timer(inst, newclient, inst->dynamic_clients.lifetime);
		fr_dlist_remove(&client->pending);
		talloc_free(client);

		/*
		 *	Tell the network side to call mod_read(), if necessary.
		 */
		entry = FR_DLIST_FIRST(inst->dynamic_clients.packets);
		if (entry) {
			DEBUG3("Emptying pending queue");
			fr_network_listen_read(inst->nr, inst->parent->listen);
		}

		return buffer_len;
	}

	/*
	 *	One less packet outstanding.
	 */
	rad_assert(address->client->outstanding > 0);
	address->client->outstanding--;

	/*
	 *	The original packet has changed.  Suppress the write,
	 *	as the client will never accept the response.
	 *
	 *	But since we still own the tracking entry, we have to delete it.
	 */
	if (track->timestamp != request_time) {
		inst->stats.total_packets_dropped++;
		DEBUG3("Suppressing reply as we have a newer packet");
		rad_assert(track->ev == NULL);
		(void) fr_radius_tracking_entry_delete(inst->ft, track);
		return buffer_len;
	}

	inst->stats.total_responses++;

	/*
	 *	Figure out when we've sent the reply.
	 */
	 reply_time = fr_time();

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	if (buffer_len >= 20) {
		data_size = udp_send(inst->sockfd, buffer, buffer_len, 0,
				     &address->dst_ipaddr, address->dst_port,
				     address->if_index,
				     &address->src_ipaddr, address->src_port);
		if (data_size < 0) {
		done:
			if (track->ev) (void) fr_event_timer_delete(inst->el, &track->ev);
			(void) fr_radius_tracking_entry_delete(inst->ft, track);
			return data_size;
		}

	} else {
		/*
		 *	Otherwise lie, and say we've written it all...
		 */
		data_size = buffer_len;
		DEBUG3("Got NAK, not writing reply");
	}

	/*
	 *	Root through the reply to determine any
	 *	connection-level negotiation data.
	 */
	if (track->data[0] == FR_CODE_STATUS_SERVER) {
//		status_check_reply(inst, buffer, buffer_len);
	}

	/*
	 *	Most packets are cleaned up immediately.  Also, if
	 *	cleanup_delay = 0, then we even clean up
	 *	Access-Request packets immediately.
	 */
	if ((track->data[0] != FR_CODE_ACCESS_REQUEST) || !inst->cleanup_delay) {
		DEBUG3("Not Access-Request.  Deleting tracking table entry");
		goto done;
	}

	/*
	 *	Add the reply to the tracking entry.
	 */
	if (fr_radius_tracking_entry_reply(inst->ft, track, reply_time,
					   buffer, buffer_len) < 0) {
		DEBUG3("Failed adding reply to tracking table");
		goto done;
	}

	/*
	 *	@todo - Move event timers to fr_time_t
	 */
	gettimeofday(&tv, NULL);

	tv.tv_sec += inst->cleanup_delay;

	/*
	 *	Set cleanup timer.
	 */
	if (fr_event_timer_insert(NULL, inst->el, &track->ev,
				  &tv, mod_cleanup_delay, track) < 0) {
		DEBUG3("Failed adding cleanup timer");
		goto done;
	}

	/*
	 *	Don't delete the tracking entry.  The cleanup timer
	 *	will do that.
	 */
	return data_size;
}

/** Open a UDP listener for RADIUS
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	int				sockfd = 0;
	uint16_t			port = inst->port;
	char				src_buf[128];

	sockfd = fr_socket_server_udp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		ERROR("Failed opening UDP socket: %s", fr_strerror());
	error:
		return -1;
	}

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		ERROR("Failed binding socket: %s", fr_strerror());
		goto error;
	}

	if (fr_ipaddr_is_inaddr_any(&inst->ipaddr)) {
		if (inst->ipaddr.af == AF_INET) {
			strlcpy(src_buf, "*", sizeof(src_buf));
		} else {
			rad_assert(inst->ipaddr.af == AF_INET6);
			strlcpy(src_buf, "::", sizeof(src_buf));
		}
	} else {
		fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(inst->ipaddr), 0);
	}

	rad_assert(inst->name == NULL);
	inst->name = talloc_typed_asprintf(inst, "proto udp address %s port %u",
				     src_buf, port);
	inst->sockfd = sockfd;

	// @todo - also print out auth / acct / coa, etc.
	DEBUG("Listening on radius address %s bound to virtual server %s",
	      inst->name, cf_section_name2(inst->parent->server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_radius_udp_t const *inst = talloc_get_type_abort_const(instance, proto_radius_udp_t);

	return inst->sockfd;
}


/** Set the event list for a new socket
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el, void *nr)
{
	proto_radius_udp_t *inst;

	memcpy(&inst, &instance, sizeof(inst)); /* const issues */

	inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	/*
	 *	Dynamic clients require an event list for cleanups.
	 */
	if (!inst->dynamic_clients_is_set) {
		/*
		 *	Only Access-Request gets a cleanup delay.
		 */
		if (!inst->parent->code_allowed[FR_CODE_ACCESS_REQUEST]) return;

		/*
		 *	And then, only if it is non-zero.
		 */
		if (!inst->cleanup_delay) return;
	}

	inst->el = el;
	inst->nr = nr;
}


static int mod_instantiate(void *instance, CONF_SECTION *cs)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(cs, "No 'ipaddr' was specified in the 'udp' section");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (!inst->port) {
		struct servent *s;

		if (!inst->port_name) {
			cf_log_err(cs, "No 'port' was specified in the 'udp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "udp");
		if (!s) {
			cf_log_err(cs, "Unknown value for 'port_name = %s", inst->port_name);
			return -1;
		}

		inst->port = ntohl(s->s_port);
	}

	FR_INTEGER_BOUND_CHECK("cleanup_delay", inst->cleanup_delay, <=, 30);

	inst->ft = fr_radius_tracking_create(inst, sizeof(proto_radius_udp_address_t), inst->parent->code_allowed);
	if (!inst->ft) {
		cf_log_err(cs, "Failed to create tracking table: %s", fr_strerror());
		return -1;
	}

	/*
	 *	Instantiate proto_radius_dynamic_client
	 */
	if (inst->dynamic_clients_is_set) {
		fr_app_process_t const	*app_process;

		app_process = (fr_app_process_t const *)inst->dynamic_clients.submodule->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->dynamic_clients.submodule->data,
									  cf_item_to_section(cf_parent(cs))) < 0)) {
			cf_log_err(cs, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}
	}

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	dl_instance_t const	*dl_inst;
	CONF_SECTION		*subcs;

	/*
	 *	Find the dl_instance_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_instance_find(instance);
	rad_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_radius_t);

	/*
	 *	Hide this for now.  It's only for people who know what
	 *	they're doing.
	 */
	subcs = cf_section_find(cs, "priority", NULL);
	if (subcs) {
		if (cf_section_rules_push(subcs, priority_config) < 0) return -1;
		if (cf_section_parse(NULL, NULL, subcs) < 0) return -1;

	} else {
		rad_assert(sizeof(inst->priorities) == sizeof(priorities));
		memcpy(&inst->priorities, &priorities, sizeof(priorities));
	}

	if (inst->dynamic_clients_is_set) {
		size_t i, num;
		dl_instance_t *parent_inst;

		if (!inst->dynamic_clients.network) {
			cf_log_err(cs, "One or more 'network' entries MUST be specified for dynamic clients.");
			return -1;
		}

		num = talloc_array_length(inst->dynamic_clients.network);
		for (i = 0; i < num; i++) {
			if (inst->dynamic_clients.network[i].af != inst->ipaddr.af) {
				char buffer[256];

				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->dynamic_clients.network[i]), 0);

				cf_log_err(cs, "Address family in entry %zd - 'network = %s' does not match 'ipaddr'", i + 1, buffer);
				return -1;
			}
		}

		parent_inst = cf_data_value(cf_data_find(cf_parent(cs), dl_instance_t, "proto_radius"));
		rad_assert(parent_inst != NULL);

		if (dl_instance(inst, &inst->dynamic_clients.submodule,
				cs, parent_inst, "dynamic_client", DL_TYPE_SUBMODULE) < 0) {
			cf_log_err(cs, "Failed finding proto_radius_dynamic_client: %s", fr_strerror());
			return -1;
		}

		FR_DLIST_INIT(inst->dynamic_clients.pending);
		FR_DLIST_INIT(inst->dynamic_clients.packets);

		/*
		 *	Allow static clients for this virtual server.
		 */
		inst->dynamic_clients.clients = client_list_init(NULL); // client_list_parse_section(inst->parent->server_cs, false);
		inst->dynamic_clients.expired = client_list_init(NULL);

		FR_INTEGER_BOUND_CHECK("max_clients", inst->dynamic_clients.max_clients, >=, 1);
		FR_INTEGER_BOUND_CHECK("max_clients", inst->dynamic_clients.max_clients, <=, (1 << 20));

		FR_INTEGER_BOUND_CHECK("max_pending_clients", inst->dynamic_clients.max_pending_clients, >=, 4);
		FR_INTEGER_BOUND_CHECK("max_pending_clients", inst->dynamic_clients.max_pending_clients, <=, 2048);

		FR_INTEGER_BOUND_CHECK("max_pending_packets", inst->dynamic_clients.max_pending_clients, >=, 256);
		FR_INTEGER_BOUND_CHECK("max_pending_packets", inst->dynamic_clients.max_pending_clients, <=, 65536);

		if (inst->dynamic_clients.lifetime) {
			FR_INTEGER_BOUND_CHECK("lifetime", inst->dynamic_clients.lifetime, >=, 30);
			FR_INTEGER_BOUND_CHECK("lifetime", inst->dynamic_clients.lifetime, <=, 86400);
		}
	}

	return 0;
}

static int mod_detach(void *instance)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	/*
	 *	@todo - have our OWN event loop for timers, and a
	 *	"copy timer from -> to, which means we only have to
	 *	delete our child event loop from the parent on close.
	 */

	if (inst->dynamic_clients.clients) TALLOC_FREE(inst->dynamic_clients.clients);

	close(inst->sockfd);
	return 0;
}


/** Private interface for use by proto_radius
 *
 */
extern proto_radius_app_io_t proto_radius_app_io_private;
proto_radius_app_io_t proto_radius_app_io_private = {
	.client			= mod_client,
	.src			= mod_src_address,
	.dst			= mod_dst_address
};

extern fr_app_io_t proto_radius_udp;
fr_app_io_t proto_radius_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_radius_udp_t),
	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,
	.track_duplicates	= true,

	.open			= mod_open,
	.read			= mod_read,
	.decode			= mod_decode,
	.encode			= mod_encode, /* only for dynamic client creation */
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
