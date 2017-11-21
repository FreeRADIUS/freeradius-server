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
	fr_ipaddr_t			*network;		//!< dynamic networks to allow
	fr_dlist_t			list;			//!< list of accepted packets

	uint32_t			max_clients;		//!< maximum number of dynamic clients
	uint32_t			num_clients;		//!< total number of active clients
	uint32_t			max_pending_clients;	//!< maximum number of pending clients
	uint32_t			num_pending_clients;	//!< number of pending clients
	uint32_t			max_pending_packets;	//!< maximum accepted pending packets
	uint32_t			num_pending_packets;	//!< how many packets are received, but not accepted
} dynamic_client_t;

typedef struct {
	proto_radius_t	const		*parent;		//!< The module that spawned us!
	char const			*name;			//!< socket name

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request

	fr_ipaddr_t			ipaddr;			//!< Ipaddr to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint16_t			port;			//!< Port to listen on.
	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.
	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.

	fr_tracking_t			*ft;			//!< tracking table
	uint32_t			cleanup_delay;		//!< cleanup delay for Access-Request packets

	fr_stats_t			stats;			//!< statistics for this socket

	RADCLIENT_LIST			*clients;		//!< local clients

	bool				dynamic_clients_is_set;	//!< set if we have dynamic clients
	dynamic_client_t		dynamic_clients;	//!< dynamic client infromation

	uint32_t			priorities[FR_MAX_PACKET_CODE];	//!< priorities for individual packets
} proto_radius_udp_t;

static const CONF_PARSER dynamic_client_config[] = {
	{ FR_CONF_OFFSET("network", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, dynamic_client_t, network) },

	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, dynamic_client_t, max_clients), .dflt = "65536" },
	{ FR_CONF_OFFSET("max_pending_clients", FR_TYPE_UINT32, dynamic_client_t, max_pending_clients), .dflt = "256" },
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, dynamic_client_t, max_pending_packets), .dflt = "65536" },

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
	{ FR_CONF_IS_SET_OFFSET("dynamic_clients", FR_TYPE_SUBSECTION, proto_radius_udp_t, dynamic_clients), .subcs = (void const *) dynamic_client_config },
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

static int mod_decode(UNUSED void const *instance, REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{

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

	return 0;
}

static int dynamic_client_save_packet(UNUSED proto_radius_udp_t *inst, UNUSED uint8_t *packet, UNUSED size_t packet_len,
				      UNUSED proto_radius_udp_address_t *address)
{
	return 0;
}


static ssize_t dynamic_client_alloc(proto_radius_udp_t *inst, uint8_t *packet, size_t packet_len,
				    proto_radius_udp_address_t *address, UNUSED fr_ipaddr_t *network)
{
	RADCLIENT *client;

	/*
	 *	Limit the total number of clients.
	 */
	if (inst->dynamic_clients.num_clients >= inst->dynamic_clients.max_clients) {
		DEBUG("Too many dynamic clients");
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

	client->active = false;
	client->secret = client->longname = client->shortname = client->nas_type = "";

	client->ipaddr = address->src_ipaddr;
	client->src_ipaddr = address->dst_ipaddr;

	address->client = client;

	/*
	 *	Save a copy of this packet in the client, so that we
	 *	can re-play it once we accept the client.
	 */
	if (dynamic_client_save_packet(inst, packet, packet_len, address) < 0) {
		talloc_free(client);
		return 0;
	}

	/*
	 *	It's now one of our clients (pending).
	 *
	 *	@todo - add creation time, and delete it when the
	 *	request hits max_request_time.
	 */
	if (!client_add(inst->clients, client)) {
		talloc_free(client);
		return 0;
	}

	inst->dynamic_clients.num_pending_clients++;

	return packet_len;
}


static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority)
{
	proto_radius_udp_t		*inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	ssize_t				data_size;
	size_t				packet_len;
	decode_fail_t			reason;

	struct timeval			timestamp;
	fr_tracking_status_t		tracking_status;
	fr_tracking_entry_t		*track;
	proto_radius_udp_address_t	address;

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
		DEBUG2("proto_radius_udp got a packet which isn't RADIUS");
		inst->stats.total_malformed_requests++;
		return 0;
	}

	/*
	 *	Lookup the client - Must exist to continue.
	 */
	address.client = client_find(NULL, &address.src_ipaddr, IPPROTO_UDP);
	if (!address.client) {
		size_t i, num;

		if (!inst->dynamic_clients_is_set) {
		unknown:
			ERROR("Unknown client from address %pV:%u.  Ignoring...",
			      fr_box_ipaddr(address.src_ipaddr), address.src_port);
			inst->stats.total_invalid_requests++;
			return 0;
		}

		/*
		 *	We have dynamic clients.  Try to find the
		 *	client in the dynamic client set.
		 */
		address.client = client_find(inst->clients, &address.src_ipaddr, IPPROTO_UDP);
		if (address.client) {
			if (address.client->active) goto found;

			if (address.client->negative) {
				// @todo - extend the expiry time?
				goto unknown;
			}

			// @todo - add the packet to the pending list and return
			goto unknown;
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
			if (fr_ipaddr_cmp(&address.src_ipaddr, &inst->dynamic_clients.network[i]) == 0) {
				return dynamic_client_alloc(inst, buffer, packet_len, &address, &inst->dynamic_clients.network[i]);
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

	/*
	 *	Track the packet ID.
	 */
	address.code = buffer[0];
	address.id = buffer[1];

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

	*packet_ctx = track;
	*recv_time = &track->timestamp;
	*priority = priorities[buffer[0]];

	inst->stats.total_requests++;

	return packet_len;
}

static ssize_t mod_write(void *instance, void *packet_ctx,
			 fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_udp_t		*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	fr_tracking_entry_t		*track = packet_ctx;
	proto_radius_udp_address_t const *address = track->src_dst;

	ssize_t				data_size;
	fr_time_t			reply_time;
	struct timeval			tv;

	/*
	 *	The original packet has changed.  Suppress the write,
	 *	as the client will never accept the response.
	 *
	 *	But since we still own the tracking entry, we have to delete it.
	 */
	if (track->timestamp != request_time) {
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
 * @param[in] nr_ctx context from the network side
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el, UNUSED void *nr_ctx)
{
	proto_radius_udp_t *inst;

	memcpy(&inst, &instance, sizeof(inst)); /* const issues */

	inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	/*
	 *	Only Access-Request gets a cleanup delay.
	 */
	if (!inst->parent->code_allowed[FR_CODE_ACCESS_REQUEST]) return;

	/*
	 *	And then, only if it is non-zero.
	 */
	if (!inst->cleanup_delay) return;

	inst->el = el;
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

	if (inst->dynamic_clients_is_set) {
		size_t i, num;

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

		// @todo - sanity check parameters
	}

	inst->ft = fr_radius_tracking_create(inst, sizeof(proto_radius_udp_address_t), inst->parent->code_allowed);
	if (!inst->ft) {
		cf_log_err(cs, "Failed to create tracking table: %s", fr_strerror());
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
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
