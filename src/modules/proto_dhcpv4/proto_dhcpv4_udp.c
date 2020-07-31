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
 * @file proto_dhcpv4_udp.c
 * @brief DHCPv4 handler for UDP.
 *
 * @copyright 2018 The FreeRADIUS server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/dhcpv4/freeradius.internal.h>
#include <freeradius-devel/arp/arp.h>
#include "proto_dhcpv4.h"

extern fr_app_io_t proto_dhcpv4_udp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket
}  proto_dhcpv4_udp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	fr_ipaddr_t			src_ipaddr;    		//!< IP address to source replies

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	uint16_t			port;			//!< Port to listen on.

	bool				broadcast;		//!< whether we listen for broadcast packets

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				dynamic_clients;	//!< whether we have dynamic clients

	RADCLIENT_LIST			*clients;		//!< local clients
	RADCLIENT			*default_client;	//!< default 0/0 client

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_dhcpv4_udp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dhcpv4_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dhcpv4_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_IPV4_ADDR, proto_dhcpv4_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_dhcpv4_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_dhcpv4_udp_t, src_ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_dhcpv4_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_dhcpv4_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_dhcpv4_udp_t, port) },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_dhcpv4_udp_t, recv_buff) },

	{ FR_CONF_OFFSET("broadcast", FR_TYPE_BOOL, proto_dhcpv4_udp_t, broadcast) } ,

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_dhcpv4_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_dhcpv4_udp_t, max_packet_size), .dflt = "4096" } ,
       	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_dhcpv4_udp_t, max_attributes), .dflt = STRINGIFY(DHCPV4_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t proto_dhcpv4_udp_dict[];
fr_dict_autoload_t proto_dhcpv4_udp_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_dhcp_server_identifier;

extern fr_dict_attr_autoload_t proto_dhcpv4_udp_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv4_udp_dict_attr[] = {
	{ .out = &attr_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_dhcp_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ NULL }
};

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_dhcpv4_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv4_udp_thread_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;
	uint8_t				message_type;
	uint32_t			xid, ipaddr;
	dhcp_packet_t			*packet;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_dhcpv4.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	data_size = udp_recv(thread->sockfd, buffer, buffer_len, flags,
			     &address->src_ipaddr, &address->src_port,
			     &address->dst_ipaddr, &address->dst_port,
			     &address->if_index, recv_time_p);
	if (data_size < 0) {
		DEBUG2("proto_dhvpv4_udp got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_dhcpv4_udp got no data: ignoring");
		return 0;
	}

	/*
	 *	@todo - make this take "&packet_len", as the DHCPv4
	 *	packet may be smaller than the parent UDP packet.
	 */
	if (!fr_dhcpv4_ok(buffer, data_size, &message_type, &xid)) {
		DEBUG2("proto_dhcpv4_udp got invalid packet, ignoring it - %s",
			fr_strerror());
		return 0;
	}

	packet_len = data_size;

	/*
	 *	We've seen a server reply to this port, but the giaddr
	 *	is *not* our address.  Drop it.
	 */
	packet = (dhcp_packet_t *) buffer;
	memcpy(&ipaddr, &packet->giaddr, 4);
	if ((packet->opcode == 2) && (ipaddr != address->dst_ipaddr.addr.v4.s_addr)) {
		DEBUG2("Ignoring server reply which was not meant for us (was for 0x%x).",
			ntohl(address->dst_ipaddr.addr.v4.s_addr));
		return 0;
	}

	/*
	 *	proto_dhcpv4 sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_dhcpv4_udp - Received %s XID %08x length %d %s",
	       dhcp_message_types[message_type], xid,
	       (int) packet_len, thread->name);

	return packet_len;
}


static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_dhcpv4_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv4_udp_t);
	proto_dhcpv4_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv4_udp_thread_t);

	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_io_address_t			address;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_dhcpv4
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	fr_assert(track->reply_len == 0);

	/*
	 *	Swap src/dst IP/port
	 */
	address.src_ipaddr = track->address->dst_ipaddr;
	address.src_port = track->address->dst_port;
	address.dst_ipaddr = track->address->src_ipaddr;
	address.dst_port = track->address->src_port;
	address.if_index = track->address->if_index;

	/*
	 *	Figure out which kind of packet we're sending.
	 */
	if (!thread->connection) {
		uint8_t const *code, *sid;
		dhcp_packet_t *packet = (dhcp_packet_t *) buffer;
		dhcp_packet_t *request = (dhcp_packet_t *) track->packet; /* only 20 bytes tho! */
#ifdef WITH_IFINDEX_IPADDR_RESOLUTION
		fr_ipaddr_t primary;
#endif

		/*
		 *	This isn't available in the packet header.
		 */
		code = fr_dhcpv4_packet_get_option(packet, buffer_len, attr_message_type);
		if (!code || (code[1] < 1) || (code[2] == 0) || (code[2] > FR_DHCP_LEASE_ACTIVE)) {
			DEBUG("WARNING - silently discarding reply due to invalid or missing message type");
			return 0;
		}

		/*
		 *	Set the source IP we'll use for sending the packets.
		 *
		 *	- if src_ipaddr is unicast, use that
		 *	- else if socket wasn't bound to *, then use that
		 *	- else if we have if_index, get main IP from that interface and use that.
		 *	- else for offer/ack, look at option 54, for Server Identification and use that
		 *	- else leave source IP as whatever is already in "address.src_ipaddr".
		 */
		if (inst->src_ipaddr.addr.v4.s_addr != INADDR_ANY) {
			address.src_ipaddr = inst->src_ipaddr;

		} else if (inst->ipaddr.addr.v4.s_addr != INADDR_ANY) {
			address.src_ipaddr = inst->ipaddr;

#ifdef WITH_IFINDEX_IPADDR_RESOLUTION
		} else if ((address->if_index > 0) &&
			   (fr_ipaddr_from_ifindex(&primary, thread->sockfd, &address.dst_ipaddr.af,
						   &address.if_index) == 0)) {
			address.src_ipaddr = primary;
#endif
		} else if (((code[2] == FR_DHCP_OFFER) || (code[2] == FR_DHCP_ACK)) &&
			   ((sid = fr_dhcpv4_packet_get_option(packet, buffer_len, attr_dhcp_server_identifier)) != NULL) &&
			   (sid[1] == 4)) {
			memcpy(&address.src_ipaddr.addr.v4.s_addr, sid + 2, 4);
		}

		/*
		 *	If we're forwarding the Discover or Request,
		 *	then we need to figure out where to forward it
		 *	to?
		 */
		if ((code[2] == FR_DHCP_DISCOVER) || (code[2] == FR_DHCP_REQUEST)) {
			DEBUG("WARNING - silently discarding client request, as we do not know where to send it.");
			return 0;
		}

		/*
		 *	We have GIADDR in the packet, so send it
		 *	there.  The packet is FROM our IP address and
		 *	port, TO the destination IP address, at the
		 *	same (i.e. server) port.
		 *
		 *	RFC 2131 page 23
		 *
		 *	"If the 'giaddr' field in a DHCP message from
		 *	a client is non-zero, the server sends any
		 *	return messages to the 'DHCP server' port on
		 *	the BOOTP relay agent whose address appears in
		 *	'giaddr'.
		 */
		if (packet->giaddr != INADDR_ANY) {
			DEBUG("Reply will be sent to giaddr.");
			address.dst_ipaddr.addr.v4.s_addr = packet->giaddr;
			address.dst_port = inst->port;
			address.src_port = inst->port;

			/*
			 *	Increase the hop count for client
			 *	packets sent to the next gateway.
			 */
			if ((code[2] == FR_DHCP_DISCOVER) ||
			    (code[2] == FR_DHCP_REQUEST)) {
				packet->opcode = 1; /* client message */
				packet->hops = request->hops + 1;
			} else {
				packet->opcode = 2; /* server message */
			}

			goto send_reply;
		}

		packet->opcode = 2; /* server message */

		/*
		 *	NAKs are broadcast when there's no giaddr.
		 *
		 *	RFC 2131 page 23.
		 *
		 *	"In all cases, when 'giaddr' is zero, the server
		 *	broadcasts any DHCPNAK messages to 0xffffffff."
		 */
		if (code[2] == FR_DHCP_NAK) {
			DEBUG("Reply will be broadcast due to NAK.");
			address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
			goto send_reply;
		}

		/*
		 *	The original packet has CIADDR, so we unicast
		 *	the reply there.
		 *
		 *	RFC 2131 page 23.
		 *
		 *	"If the 'giaddr' field is zero and the
		 *	'ciaddr' field is nonzero, then the server
		 *	unicasts DHCPOFFER and DHCPACK messages to the
		 *	address in 'ciaddr'."
		 */
		if (request->ciaddr != INADDR_ANY) {
			DEBUG("Reply will be unicast to CIADDR from original packet.");
			memcpy(&address.dst_ipaddr.addr.v4.s_addr, &request->ciaddr, 4);
			goto send_reply;
		}

		/*
		 *	The original packet requested a broadcast
		 *	reply, so we broadcast the reply.
		 *
		 *	RFC 2131 page 23.
		 *
		 *	"If 'giaddr' is zero and 'ciaddr' is zero, and
		 *	the broadcast bit is set, then the server
		 *	broadcasts DHCPOFFER and DHCPACK messages to
		 *	0xffffffff."
		 */
		if ((request->flags & FR_DHCP_FLAGS_VALUE_BROADCAST) != 0) {
			DEBUG("Reply will be broadcast due to client request.");
			address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
			goto send_reply;
		}

		/*
		 *	The original packet was unicast to us, such as
		 *	via a relay.  We have a unicast destination
		 *	address, so we just use that.
		 *
		 *	This extension isn't in the RFC, but we find it useful.
		 */
		if ((packet->yiaddr == htonl(INADDR_ANY)) &&
		    (address.dst_ipaddr.addr.v4.s_addr != htonl(INADDR_BROADCAST))) {
			DEBUG("Reply will be unicast to source IP from original packet.");
			goto send_reply;
		}

		/*
		 *	RFC 2131 page 23.
		 *
		 *	"If the broadcast bit is not set and 'giaddr'
		 *	is zero and 'ciaddr' is zero, then the server
		 *	unicasts DHCPOFFER and DHCPACK messages to the
		 *	client's hardware address and 'yiaddr'
		 *	address."
		 */
		switch (code[2]) {
			/*
			 *	OFFERs are sent to YIADDR if we
			 *	received a unicast packet from YIADDR.
			 *	Otherwise, they are unicast to YIADDR
			 *	(if we can update ARP), otherwise they
			 *	are broadcast.
			 */
		case FR_DHCP_OFFER:
			/*
			 *	If the packet was unicast from the
			 *	client, unicast it back without
			 *	updating the ARP table.  We presume
			 *	that the ARP table has been updated by
			 *	the OS, since we received a unicast
			 *	packet.
			 *
			 *	This check simply makes sure that we
			 *	don't needlessly update the ARP table.
			 */
			if (memcmp(&address.dst_ipaddr.addr.v4.s_addr, &packet->yiaddr, 4) == 0) {
				DEBUG("Reply will be unicast to YIADDR.");

#ifdef SIOCSARP
			} else if (inst->broadcast && inst->interface) {
				uint8_t macaddr[6];
				uint8_t ipaddr[4];

				memcpy(&ipaddr, &packet->yiaddr, 4);
				memcpy(&macaddr, &packet->chaddr, 6);

				/*
				 *	Else the OFFER was broadcast.
				 *	This socket is listening for
				 *	broadcast packets on a
				 *	particular interface.  We're
				 *	too lazy to write raw UDP
				 *	packets, so we update our
				 *	local ARP table and then
				 *	unicast the reply.
				 */
				if (fr_arp_entry_add(thread->sockfd, inst->interface, ipaddr, macaddr) < 0) {
					DEBUG("Failed adding ARP entry.  Reply will be broadcast.");
					address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
				} else {
					DEBUG("Reply will be unicast to YIADDR, done ARP table updates.");
				}

#endif
			} else {
				DEBUG("Reply will be broadcast as we do not create raw UDP sockets.");
				address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
			}
			break;

			/*
			 *	ACKs are unicast to YIADDR
			 */
		case FR_DHCP_ACK:
			DEBUG("Reply will be unicast to YIADDR.");
			memcpy(&address.dst_ipaddr.addr.v4.s_addr, &packet->yiaddr, 4);
			break;

		default:
			DEBUG("WARNING - silently discarding reply due to unimplemented message type %d", code[2]);
			return 0;
		}
	}

send_reply:
	/*
	 *	proto_dhcpv4 takes care of suppressing do-not-respond, etc.
	 */
	data_size = udp_send(thread->sockfd, buffer, buffer_len, flags,
			     &address.src_ipaddr, address.src_port,
			     address.if_index,
			     &address.dst_ipaddr, address.dst_port);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	return data_size;
}


static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_dhcpv4_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv4_udp_thread_t);

	thread->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_dhcpv4_udp_t		*inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}


/** Open a UDP listener for DHCPV4
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_dhcpv4_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv4_udp_t);
	proto_dhcpv4_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv4_udp_thread_t);

	int				sockfd, rcode;
	uint16_t			port = inst->port;

	li->fd = sockfd = fr_socket_server_udp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		PERROR("Failed opening UDP socket");
	error:
		return -1;
	}

	li->app_io_addr = fr_app_io_socket_addr(li, IPPROTO_UDP, &inst->ipaddr, port);

	/*
	 *	Set SO_REUSEPORT before bind, so that all packets can
	 *	listen on the same destination IP address.
	 */
	if (1) {
		int on = 1;

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
			ERROR("Failed to set socket 'reuseport': %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	if (inst->broadcast) {
		int on = 1;

		if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
			ERROR("Failed to set broadcast option: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

	rcode = fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface);
	if (rcode < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_dhcpv4_udp,
					     NULL, 0,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}


/** Set the file descriptor for this socket.
 *
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_dhcpv4_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv4_udp_t);
	proto_dhcpv4_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv4_udp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_dhcpv4_udp,
					     &thread->connection->src_ipaddr, thread->connection->src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}


static void *mod_track_create(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len)
{
	proto_dhcpv4_track_t *track;
	dhcp_packet_t const *dhcp = (dhcp_packet_t const *) packet;
	uint8_t const  *option;

	option = fr_dhcpv4_packet_get_option(dhcp, packet_len, attr_message_type);
	if (!option || (option[1] == 0)) {
		DEBUG("No %s in the packet - ignoring", attr_message_type->name);
		return NULL;
	}

	track = talloc_zero(ctx, proto_dhcpv4_track_t);
	if (!track) return NULL;

	memcpy(&track->xid, &dhcp->xid, sizeof(track->xid));

	track->message_type = option[2];

	/*
	 *	Track most packets by chaddr.  For lease queries, that
	 *	field can be the client address being queried, not the
	 *	address of the system which sent the packet.  So
	 *	instead for lease queries, we use giaddr, which MUST
	 *	exist according to RFC 4388 Section 6.3
	 */
	if (option[2] != FR_DHCP_LEASE_QUERY) {
		if (dhcp->hlen == 6) memcpy(&track->chaddr, &dhcp->chaddr, 6);

	} else {
		memcpy(&track->giaddr, &dhcp->giaddr, sizeof(track->giaddr));
	}
	
	return track;
}

static int mod_compare(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
		       void const *one, void const *two)
{
	int rcode;
	proto_dhcpv4_track_t const *a = one;
	proto_dhcpv4_track_t const *b = two;

	/*
	 *	The tree is ordered by XIDs, which are (hopefully)
	 *	pseudo-randomly distributed.
	 */
	rcode = memcmp(&a->xid, &b->xid, sizeof(a->xid));
	if (rcode != 0) return rcode;

	/*
	 *	Hardware addresses should also be randomly distributed.
	 */
	rcode = memcmp(&a->chaddr, &b->chaddr, sizeof(a->chaddr));
	if (rcode != 0) return rcode;

	/*
	 *	Compare giaddr for lease queries.
	 */
	rcode = memcmp(&a->giaddr, &b->giaddr, sizeof(a->giaddr));
	if (rcode != 0) return rcode;

	return (a->message_type < b->message_type) - (a->message_type > b->message_type);
}

static char const *mod_name(fr_listen_t *li)
{
	proto_dhcpv4_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv4_udp_thread_t);

	return thread->name;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_dhcpv4_udp_t	*inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;
	RADCLIENT		*client;

	inst->cs = cs;

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(cs, "No 'ipaddr' was specified in the 'udp' section");
		return -1;
	}

	if (inst->ipaddr.af != AF_INET) {
		cf_log_err(cs, "DHCPv4 transport cannot use IPv6 for 'ipaddr'");
		return -1;
	}

	/*
	 *	If src_ipaddr is defined, it must be of the same address family as "ipaddr"
	 */
	if ((inst->src_ipaddr.af != AF_UNSPEC) &&
	    (inst->src_ipaddr.af != inst->ipaddr.af)) {
		cf_log_err(cs, "Both 'ipaddr' and 'src_ipaddr' must be from the same address family");
		return -1;
	}

	/*
	 *	Set src_ipaddr to INADDR_NONE if not otherwise specified
	 */
	if (inst->src_ipaddr.af == AF_UNSPEC) {
		memset(&inst->src_ipaddr, 0, sizeof(inst->src_ipaddr));
		inst->src_ipaddr.af = AF_INET;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, MIN_PACKET_SIZE);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

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

#ifdef SIOCSARP
	/*
	 *	If we're listening for broadcast requests, we MUST
	 */
	if (inst->broadcast && !inst->interface) {
		cf_log_warn("You SHOULD set 'interface' if you have set 'broadcast = yes'.");
		cf_log_warn("All replies will be broadcast, as ARP updates require 'interface' to be set.")
	}
#endif

	/*
	 *	Parse and create the trie for dynamic clients, even if
	 *	there's no dynamic clients.
	 */
	num = talloc_array_length(inst->allow);
	if (!num) {
		if (inst->dynamic_clients) {
			cf_log_err(cs, "The 'allow' subsection MUST contain at least one 'network' entry when 'dynamic_clients = true'.");
			return -1;
		}
	} else {
		inst->trie = fr_master_io_network(inst, inst->ipaddr.af, inst->allow, inst->deny);
		if (!inst->trie) {
			cf_log_perr(cs, "Failed creating list of networks");
			return -1;
		}
	}

	ci = cf_parent(inst->cs); /* listen { ... } */
	fr_assert(ci != NULL);
	ci = cf_parent(ci);
	fr_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	/*
	 *	Look up local clients, if they exist.
	 *
	 *	@todo - ensure that we only parse clients which are
	 *	for IPPROTO_UDP, and don't require a "secret".
	 */
	if (cf_section_find_next(server_cs, NULL, "client", CF_IDENT_ANY)) {
		inst->clients = client_list_parse_section(server_cs, IPPROTO_UDP, false);
		if (!inst->clients) {
			cf_log_err(cs, "Failed creating local clients");
			return -1;
		}
	}

	/*
	 *	Create a fake client.
	 */
	client = inst->default_client = talloc_zero(inst, RADCLIENT);
	if (!inst->default_client) return 0;

	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = client->secret = talloc_strdup(client, "default");
	client->nas_type = talloc_strdup(client, "other");

	return 0;
}

static RADCLIENT *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_dhcpv4_udp_t const *inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv4_udp_t);

	/*
	 *	Prefer local clients.
	 */
	if (inst->clients) {
		RADCLIENT *client;

		client = client_find(inst->clients, ipaddr, ipproto);
		if (client) return client;
	}

	return inst->default_client;
}

fr_app_io_t proto_dhcpv4_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "dhcpv4_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_dhcpv4_udp_t),
	.thread_inst_size	= sizeof(proto_dhcpv4_udp_thread_t),
	.bootstrap		= mod_bootstrap,

	.default_message_size	= 4096,
	.track_duplicates	= true,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.track			= mod_track_create,
	.compare		= mod_compare,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
