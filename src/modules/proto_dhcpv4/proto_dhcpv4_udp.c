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
#include <freeradius-devel/server/rad_assert.h>
#include "proto_dhcpv4.h"

typedef struct proto_dhcpv4_udp_t {
	char const			*name;			//!< socket name
	CONF_SECTION			*cs;			//!< our configuration

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request
	fr_network_t			*nr;			//!< for fr_network_listen_read();

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	fr_ipaddr_t			src_ipaddr;    		//!< IP address to source replies

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	fr_stats_t			stats;			//!< statistics for this socket

	uint16_t			port;			//!< Port to listen on.

	bool				broadcast;		//!< whether we listen for broadcast packets

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients

	fr_io_address_t			*connection;		//!< for connected sockets.

} proto_dhcpv4_udp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dhcpv4_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dhcpv4_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_dhcpv4_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_dhcpv4_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_dhcpv4_udp_t, ipaddr) },

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

static fr_dict_t *dict_dhcpv4;

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

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_dhcpv4_udp_t		*inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;
	struct timeval			timestamp;
	uint8_t				message_type;
	uint32_t			xid, ipaddr;
	dhcp_packet_t			*packet;

	fr_time_t			*recv_time_p;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_dhcpv4.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;
	recv_time_p = *recv_time;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (inst->connection != NULL);

	data_size = udp_recv(inst->sockfd, buffer, buffer_len, flags,
			     &address->src_ipaddr, &address->src_port,
			     &address->dst_ipaddr, &address->dst_port,
			     &address->if_index, &timestamp);
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

	// @todo - maybe convert timestamp?
	*recv_time_p = fr_time();

	/*
	 *	proto_dhcpv4 sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_dhcpv4_udp - Received %s XID %04x length %d %s",
	       dhcp_message_types[message_type], xid,
	       (int) packet_len, inst->name);

	return packet_len;
}


static ssize_t mod_write(void *instance, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_dhcpv4_udp_t		*inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);
	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_io_address_t			address;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_dhcpv4
	 *	can update them, too.. <sigh>
	 */
	inst->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (inst->connection != NULL);

	rad_assert(track->reply_len == 0);

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
	if (!inst->connection) {
		uint8_t const *code, *sid;
		uint32_t ipaddr;
		dhcp_packet_t *packet = (dhcp_packet_t *) buffer;
		dhcp_packet_t *request = (dhcp_packet_t *) track->packet; /* only 20 bytes tho! */
#ifdef WITH_IFINDEX_IPADDR_RESOLUTION
		fr_ipaddr_t primary;
#endif

		/*
		 *	This isn't available in the packet header.
		 */
		code = fr_dhcpv4_packet_get_option(packet, buffer_len, attr_message_type);
		if (!code || (code[1] < 1) || (code[2] == 0) || (code[2] >= FR_DHCP_INFORM)) {
			DEBUG("WARNING - silently discarding reply due to invalid or missing message type");
			return 0;
		}

		/*
		 *	Set the source IP of the packet.
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
			   (fr_ipaddr_from_ifindex(&primary, inst->sockfd, &address.dst_ipaddr.af,
						   &address.if_index) == 0)) {
			address.src_ipaddr = primary;
#endif
		} else if (((code[2] == FR_DHCP_OFFER) || (code[2] == FR_DHCP_ACK)) &&
			   ((sid = fr_dhcpv4_packet_get_option(packet, buffer_len, attr_dhcp_server_identifier)) != NULL) &&
			   (sid[1] == 4)) {
			memcpy(&address.src_ipaddr.addr.v4.s_addr, sid + 2, 4);
		}

		/*
		 *	We have GIADDR in the packet, so send it
		 *	there.  The packet is FROM our IP address and
		 *	port, TO the destination IP address, at the
		 *	same (i.e. server) port.
		 */
		memcpy(&ipaddr, &packet->giaddr, 4);
		if (ipaddr != INADDR_ANY) {
			address.dst_ipaddr.addr.v4.s_addr = ipaddr;
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

		/*
		 *	If there's no GIADDR, we don't know where to
		 *	send client packets.
		 */
		if ((code[2] == FR_DHCP_DISCOVER) || (code[2] == FR_DHCP_REQUEST)) {
			DEBUG("WARNING - silently discarding client reply, as there is no GIADDR to send it to.");
			return 0;
		}

		packet->opcode = 2; /* server message */

		/*
		 *	The original packet requested a broadcast
		 *	reply, and CIADDR is empty, go broadcast the
		 *	reply.  RFC 2131 page 23.
		 */
		if (((request->flags & FR_DHCP_FLAGS_VALUE_BROADCAST) != 0) &&
		    (request->ciaddr == INADDR_ANY)) {
			DEBUG("Reply will be broadcast due to client request.");
			address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
			goto send_reply;
		}

		/*
		 *	The original packet has CIADDR, so we unicast
		 *	the reply there.  RFC 2131 page 23.
		 */
		if (request->ciaddr != INADDR_ANY) {
			DEBUG("Reply will be unicast to CIADDR from original packet.");
			memcpy(&address.dst_ipaddr.addr.v4.s_addr, &request->ciaddr, 4);
			goto send_reply;
		}

		/*
		 *	The original packet was unicast to us, such as
		 *	via a relay.  We have a unicast destination
		 *	address, so we just use that.
		 */
		if ((packet->yiaddr == htonl(INADDR_ANY)) &&
		    (address.dst_ipaddr.addr.v4.s_addr != htonl(INADDR_BROADCAST))) {
			DEBUG("Reply will be unicast to source IP from original packet.");
			goto send_reply;
		}

		switch (code[2]) {
			/*
			 *	Offers are sent to YIADDR if we
			 *	received a unicast packet from YIADDR.
			 *	Otherwise, they are unicast to YIADDR
			 *	(if we can update ARP), otherwise they
			 *	are broadcast.
			 */
		case FR_DHCP_OFFER:
			/*
			 *	If the packet was unicast from the
			 *	client, unicast it back.
			 */
			if (memcmp(&address.dst_ipaddr.addr.v4.s_addr, &packet->yiaddr, 4) == 0) {
				DEBUG("Reply will be unicast to YIADDR.");

#ifdef SIOCSARP
			} else if (inst->broadcast && inst->interface) {
				if (fr_dhcpv4_udp_add_arp_entry(inst->sockfd, inst->interface,
								&packet->yiaddr, &packet->chaddr) < 0) {
					DEBUG("Failed adding ARP entry.  Reply will be broadcast.");
					address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
				} else {
					DEBUG("Reply will be unicast to YIADDR after ARP table updates.");
				}

#endif
			} else {
				DEBUG("Reply will be broadcast due to OFFER.");
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

			/*
			 *	NAKs are broadcast.
			 */
		case FR_DHCP_NAK:
			DEBUG("Reply will be broadcast due to NAK.");
			address.dst_ipaddr.addr.v4.s_addr = INADDR_BROADCAST;
			break;

		default:
			DEBUG("WARNING - silently discarding reply due to invalid message type %d", code[2]);
			return 0;
		}
	}

send_reply:
	/*
	 *	proto_radius_dhcpv4 takes care of suppressing do-not-respond, etc.
	 */
	data_size = udp_send(inst->sockfd, buffer, buffer_len, flags,
			     &address.src_ipaddr, address.src_port,
			     address.if_index,
			     &address.dst_ipaddr, address.dst_port);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	return data_size;
}


/** Open a UDP listener for DHCPV4
 *
 * @param[in] instance of the DHCPV4 UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_close(void *instance)
{
	proto_dhcpv4_udp_t *inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);

	close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}


static int mod_connection_set(void *instance, fr_io_address_t *connection)
{
	proto_dhcpv4_udp_t *inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);

	inst->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_dhcpv4_udp_t *inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}


/** Open a UDP listener for DHCPV4
 *
 * @param[in] instance of the DHCPV4 UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_dhcpv4_udp_t *inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);

	int				sockfd = 0;
	uint16_t			port = inst->port;
	CONF_SECTION			*server_cs;
	CONF_ITEM			*ci;

	sockfd = fr_socket_server_udp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		PERROR("Failed opening UDP socket");
	error:
		return -1;
	}

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

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	/*
	 *	Connect to the client for child sockets.
	 */
	if (inst->connection) {
		socklen_t salen;
		struct sockaddr_storage src;

		if (fr_ipaddr_to_sockaddr(&inst->connection->src_ipaddr, inst->connection->src_port,
					  &src, &salen) < 0) {
			close(sockfd);
			ERROR("Failed getting IP address");
			goto error;
		}

		if (connect(sockfd, (struct sockaddr *) &src, salen) < 0) {
			close(sockfd);
			ERROR("Failed in connect: %s", fr_syserror(errno));
			goto error;
		}
	}

	inst->sockfd = sockfd;

	ci = cf_parent(inst->cs); /* listen { ... } */
	rad_assert(ci != NULL);
	ci = cf_parent(ci);
	rad_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	// @todo - also print out auth / acct / coa, etc.
	DEBUG("Listening on dhcpv4 address %s bound to virtual server %s",
	      inst->name, cf_section_name2(server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the DHCPV4 UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_dhcpv4_udp_t const *inst = talloc_get_type_abort_const(instance, proto_dhcpv4_udp_t);

	return inst->sockfd;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_dhcpv4_udp_t *inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);
	char		    dst_buf[128];

	/*
	 *	Get our name.
	 */
	if (fr_ipaddr_is_inaddr_any(&inst->ipaddr)) {
		if (inst->ipaddr.af == AF_INET) {
			strlcpy(dst_buf, "*", sizeof(dst_buf));
		} else {
			rad_assert(inst->ipaddr.af == AF_INET6);
			strlcpy(dst_buf, "::", sizeof(dst_buf));
		}
	} else {
		fr_value_box_snprint(dst_buf, sizeof(dst_buf), fr_box_ipaddr(inst->ipaddr), 0);
	}

	if (!inst->connection) {
		inst->name = talloc_typed_asprintf(inst, "proto udp server %s port %u",
						   dst_buf, inst->port);

	} else {
		char src_buf[128];

		fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(inst->connection->src_ipaddr), 0);

		inst->name = talloc_typed_asprintf(inst, "proto udp from client %s port %u to server %s port %u",
						   src_buf, inst->connection->src_port, dst_buf, inst->port);
	}

	return 0;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_dhcpv4_udp_t	*inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);
	size_t			num;

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
	 *
	 *	@todo - we could use this for source IP filtering?
	 *	e.g. allow clients from a /16, but not from a /24
	 *	within that /16.
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
			cf_log_err(cs, "Failed creating list of networks - %s", fr_strerror());
			return -1;
		}
	}

	return 0;
}

// @todo - allow for "wildcard" clients, which allow anything
// and then rely on "networks" to filter source IPs...
// which means we probably want to filter on "networks" even if there are no dynamic clients
static RADCLIENT *mod_client_find(UNUSED void *instance, fr_ipaddr_t const *ipaddr, int ipproto)
{
	return client_find(NULL, ipaddr, ipproto);
}

#if 0
static int mod_detach(void *instance)
{
	proto_dhcpv4_udp_t	*inst = talloc_get_type_abort(instance, proto_dhcpv4_udp_t);

	if (inst->sockfd >= 0) close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}
#endif

extern fr_app_io_t proto_dhcpv4_udp;
fr_app_io_t proto_dhcpv4_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "dhcpv4_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_dhcpv4_udp_t),
//	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.close			= mod_close,
	.fd			= mod_fd,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
};
