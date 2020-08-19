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
 * @file proto_dhcpv6_udp.c
 * @brief DHCPv6 handler for UDP.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
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
#include <freeradius-devel/protocol/dhcpv6/freeradius.internal.h>
#include "proto_dhcpv6.h"

extern fr_app_io_t proto_dhcpv6_udp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket
}  proto_dhcpv6_udp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	fr_ipaddr_t			src_ipaddr;    		//!< IP address to source replies

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().
	uint8_t				ethernet[6];		//!< ethernet address associated with the interface

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			hop_limit;		//!< for multicast addresses
	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	uint16_t			port;			//!< Port to listen on.

	bool				multicast;		//!< whether or not we listen for multicast packets

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				dynamic_clients;	//!< whether we have dynamic clients

	RADCLIENT_LIST			*clients;		//!< local clients
	RADCLIENT			*default_client;	//!< default 0/0 client

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_dhcpv6_udp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dhcpv6_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dhcpv6_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_IPV6_ADDR, proto_dhcpv6_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_dhcpv6_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_dhcpv6_udp_t, src_ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_dhcpv6_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_dhcpv6_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_dhcpv6_udp_t, port), .dflt = "547"  },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_dhcpv6_udp_t, recv_buff) },

	{ FR_CONF_OFFSET("hop_limit", FR_TYPE_UINT32, proto_dhcpv6_udp_t, hop_limit) },

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_dhcpv6_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_dhcpv6_udp_t, max_packet_size), .dflt = "8192" } ,
	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_dhcpv6_udp_t, max_attributes), .dflt = STRINGIFY(DHCPV4_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_dhcpv6;

extern fr_dict_autoload_t proto_dhcpv6_udp_dict[];
fr_dict_autoload_t proto_dhcpv6_udp_dict[] = {
	{ .out = &dict_dhcpv6, .proto = "dhcpv6" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_client_id;

extern fr_dict_attr_autoload_t proto_dhcpv6_udp_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv6_udp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6},
	{ .out = &attr_client_id, .name = "Client-ID", .type = FR_TYPE_STRUCT, .dict = &dict_dhcpv6},
	{ NULL }
};

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_dhcpv6_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv6_udp_t);
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;
	uint32_t			xid;
	fr_dhcpv6_packet_t		*packet;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_dhcpv6.
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

	if ((size_t) data_size < sizeof(fr_dhcpv6_packet_t)) {
		DEBUG2("proto_dhcpv6_udp got insufficient data: ignoring");
		return 0;
	}

	packet_len = data_size;

	/*
	 *	We've seen a server reply to this port, but the giaddr
	 *	is *not* our address.  Drop it.
	 */
	packet = (fr_dhcpv6_packet_t *) buffer;
	if (!packet->code || (packet->code >= FR_DHCPV6_MAX_CODE)) {
		DEBUG2("proto_dhcpv6_udp got unsupported packet code %d: ignoring", packet->code);
		return 0;
	}

	/*
	 *	RFC 8415 Section 18.4 forbids certain types of packets
	 *	from being received on a unicast address.
	 */
	if (!inst->multicast) {
		if ((packet->code == FR_DHCPV6_SOLICIT) ||
		    (packet->code == FR_DHCPV6_REBIND) ||
		    (packet->code == FR_DHCPV6_CONFIRM)) {
			DEBUG2("proto_dhcpv6_udp got unicast packet %s: ignoring", fr_dhcpv6_packet_types[packet->code]);
			return 0;
		}
	} /* else it was multicast... remember that */

	/*
	 *	proto_dhcpv6 sets the priority
	 */

	xid = (packet->transaction_id[0] << 16) | (packet->transaction_id[1] << 8) | packet->transaction_id[2];

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_dhcpv6_udp - Received %s XID %08x length %d %s",
	       fr_dhcpv6_packet_types[packet->code], xid,
	       (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_dhcpv6_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv6_udp_t);
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_io_address_t			address;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_dhcpv6
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	fr_assert(track->reply_len == 0);

	/*
	 *	Send packets to the originator, EXCEPT that we always
	 *	originate packets from our src_ipaddr.
	 */
	address.src_ipaddr = inst->src_ipaddr;
	address.src_port = track->address->dst_port;
	address.dst_ipaddr = track->address->src_ipaddr;
	address.dst_port = track->address->src_port;
	address.if_index = track->address->if_index;

	/*
	 *	Figure out which kind of packet we're sending.
	 */
	if (!thread->connection) {
		// @todo - figure out where to send the packet
	}

	/*
	 *	proto_dhcpv6 takes care of suppressing do-not-respond, etc.
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
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

	thread->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_dhcpv6_udp_t		*inst = talloc_get_type_abort(instance, proto_dhcpv6_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}


/** Open a UDP listener for DHCPV4
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_dhcpv6_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv6_udp_t);
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

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

	/*
	 *	SUID up is really only needed if interface is set, OR port <1024.
	 */
	rad_suid_up();
	rcode = fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface);
	rad_suid_down();
	if (rcode < 0) {
		PERROR("Failed binding socket");
	close_error:
		close(sockfd);
		goto error;
	}

	/*
	 *	If the user specified a multicast address, then join
	 *	that group.
	 */
	if (inst->multicast) {
		struct ipv6_mreq mreq;

		mreq.ipv6mr_multiaddr = inst->ipaddr.addr.v6;
		mreq.ipv6mr_interface = if_nametoindex(inst->interface);
		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
			PERROR("Failed joining multicast group %pV ", fr_box_ipaddr(inst->ipaddr));
			goto close_error;
		}

		if (inst->hop_limit) {
			int hop_limit = inst->hop_limit;

			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *) &hop_limit, sizeof(hop_limit)) < 0) {
				ERROR("Failed to set multicast hop_limit: %s", fr_syserror(errno));
				goto close_error;
			}
		}
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_dhcpv6_udp,
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
	proto_dhcpv6_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv6_udp_t);
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_dhcpv6_udp,
					     &thread->connection->src_ipaddr, thread->connection->src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static void *mod_track_create(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len)
{
	proto_dhcpv6_track_t *track;
	uint8_t const *option;
	size_t track_size = sizeof(*track);
	size_t option_len = 0;
	
	option = fr_dhcpv6_option_find(packet, packet + packet_len, attr_client_id->attr);
	if (option) {
		option_len = (option[2] << 8) | option[3];
	}

	track = (proto_dhcpv6_track_t *) talloc_zero_array(ctx, uint8_t, track_size + option_len);
	if (!track) return NULL;

	talloc_set_name_const(track, "proto_dhcpv6_track_t");

	memcpy(&track->header, packet, 4); /* packet code + 24-bit transaction ID */
	if (!option) return track;

	memcpy(&track->client_id[0], option + 4, option_len);
	track->client_id_len = option_len;

	return track;
}


static int mod_compare(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
		       void const *one, void const *two)
{
	int rcode;
	proto_dhcpv6_track_t const *a = one;
	proto_dhcpv6_track_t const *b = two;

	rcode = memcmp(&a->header, &b->header, sizeof(a->header));
	if (rcode != 0) return rcode;

	rcode = (a->client_id_len < b->client_id_len) - (a->client_id_len > b->client_id_len);
	if (rcode != 0) return rcode;

	return memcmp(a->client_id, b->client_id, a->client_id_len);
}


static char const *mod_name(fr_listen_t *li)
{
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

	return thread->name;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_dhcpv6_udp_t	*inst = talloc_get_type_abort(instance, proto_dhcpv6_udp_t);
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;
	RADCLIENT		*client;

	inst->cs = cs;

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		if (!inst->interface) {
			cf_log_err(cs, "No 'ipaddr' was specified in the 'udp' section");
			return -1;
		}

		/*
		 *	If there's a named interface, maybe we can
		 *	find a link-local address for it.  If so, just
		 *	use that.
		 */
		if (inst->interface &&
		    (fr_interface_to_ipaddr(inst->interface, &inst->ipaddr, AF_INET6, true) < 0)) {
			cf_log_err(cs, "No 'ipaddr' specified, and we cannot determine one for interface '%s'",
				   inst->interface);
				return -1;
		}
	}

	if (inst->ipaddr.af != AF_INET6) {
		cf_log_err(cs, "DHCPv6 cannot use IPv4 for 'ipaddr'");
		return -1;
	}

	/*
	 *	Remember if we're a multicast socket.
	 */
	inst->multicast = (inst->ipaddr.addr.v6.s6_addr[0] == 0xff);

	/*
	 *	Set src_ipaddr to ipaddr if not otherwise specified
	 */
	if (inst->src_ipaddr.af == AF_UNSPEC) {
		if (!inst->multicast) {
			inst->src_ipaddr = inst->ipaddr;

			/*
			 *	If the admin didn't specify an
			 *	interface, then try to find one
			 *	automatically.  We only do this for
			 *	link-local addresses.
			 */
			if (!inst->interface) {
				inst->interface = fr_ipaddr_to_interface(inst, &inst->ipaddr);
				if (!inst->interface) {
				interface_fail:
					cf_log_err(cs, "No 'interface' specified, and we cannot determine one for 'ipaddr = %pV'",
						   fr_box_ipaddr(inst->ipaddr));
					return -1;
				}
			}

		} else {
			/*
			 *	Multicase addresses MUST specify an interface.
			 */
			if (!inst->interface) goto interface_fail;

			if (fr_interface_to_ipaddr(inst->interface, &inst->src_ipaddr, AF_INET6, true) < 0) {
				cf_log_err(cs, "No 'src_ipaddr' specified, and we cannot determine one for 'ipaddr = %pV and interface '%s'",
				       fr_box_ipaddr(inst->ipaddr), inst->interface);
				return -1;
			}
		}
	}

	/*
	 *	src_ipaddr must be of the same address family as "ipaddr"
	 */
	if (inst->src_ipaddr.af != inst->ipaddr.af) {
		cf_log_err(cs, "Both 'ipaddr' and 'src_ipaddr' must be from the same address family");
		return -1;
	}

	/*
	 *	Get the MAC address associated with this interface.
	 *	It can be used to create a server ID.
	 */
	(void) fr_interface_to_ethernet(inst->interface, inst->ethernet);

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 4);
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

	client->ipaddr = (fr_ipaddr_t ) {
		.af = AF_INET6,
	};

	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = client->secret = talloc_strdup(client, "default");
	client->nas_type = talloc_strdup(client, "other");

	return 0;
}

static RADCLIENT *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_dhcpv6_udp_t const *inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv6_udp_t);

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

fr_app_io_t proto_dhcpv6_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "dhcpv6_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_dhcpv6_udp_t),
	.thread_inst_size	= sizeof(proto_dhcpv6_udp_thread_t),
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
