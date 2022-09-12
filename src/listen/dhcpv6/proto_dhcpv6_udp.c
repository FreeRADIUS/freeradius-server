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
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
#define LOG_PREFIX "proto_dhcpv6_udp"

#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
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
	fr_ethernet_t			ethernet;		//!< ethernet address associated with the interface

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
	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_dhcpv6_udp_t, max_attributes), .dflt = STRINGIFY(DHCPV6_MAX_ATTRIBUTES) } ,

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
static fr_dict_attr_t const *attr_relay_message;

extern fr_dict_attr_autoload_t proto_dhcpv6_udp_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv6_udp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6},
	{ .out = &attr_client_id, .name = "Client-ID", .type = FR_TYPE_STRUCT, .dict = &dict_dhcpv6},
	{ .out = &attr_relay_message, .name = "Relay-Message", .type = FR_TYPE_GROUP, .dict = &dict_dhcpv6 },
	{ NULL }
};

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len,
			size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
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
	address_p = (fr_io_address_t **)packet_ctx;
	address = *address_p;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	data_size = udp_recv(thread->sockfd, flags, &address->socket, buffer, buffer_len, recv_time_p);
	if (data_size < 0) {
		RATE_LIMIT_GLOBAL(PERROR, "Read error (%zd)", data_size);
		return data_size;
	}

	if ((size_t) data_size < sizeof(fr_dhcpv6_packet_t)) {
		RATE_LIMIT_GLOBAL(WARN, "Insufficient data - ignoring");
		return 0;
	}

	packet_len = data_size;

	/*
	 *	We've seen a server reply to this port, but the giaddr
	 *	is *not* our address.  Drop it.
	 */
	packet = (fr_dhcpv6_packet_t *) buffer;
	if (!packet->code || (packet->code >= FR_DHCPV6_CODE_MAX)) {
		RATE_LIMIT_GLOBAL(WARN, "Unsupported packet code %d - ignoring", packet->code);
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
			RATE_LIMIT_GLOBAL(WARN, "Unicast packet %s - ignoring", fr_dhcpv6_packet_types[packet->code]);
			return 0;
		}
	} /* else it was multicast... remember that */

	/*
	 *	proto_dhcpv6 sets the priority
	 */

	xid = fr_nbo_to_uint24(packet->transaction_id);

	/*
	 *	Print out what we received.
	 */
	DEBUG2("Received %s XID %08x length %d %s", fr_dhcpv6_packet_types[packet->code], xid,
	       (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_dhcpv6_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dhcpv6_udp_t);
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_socket_t			socket;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_dhcpv6
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	/*
	 *	Send packets to the originator, EXCEPT that we always
	 *	originate packets from our src_ipaddr.
	 */
	fr_socket_addr_swap(&socket, &track->address->socket);
	if (!fr_ipaddr_is_inaddr_any(&inst->src_ipaddr)) socket.inet.src_ipaddr = inst->src_ipaddr;

	/*
	 *	Figure out which kind of packet we're sending.
	 */
	if (!thread->connection) {
		// @todo - figure out where to send the packet
	}

	/*
	 *	proto_dhcpv6 takes care of suppressing do-not-respond, etc.
	 */
	data_size = udp_send(&socket, flags, buffer, buffer_len);

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


/** Open a UDP listener for DHCPv6
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

	li->app_io_addr = fr_socket_addr_alloc_inet_src(li, IPPROTO_UDP, 0, &inst->ipaddr, port);

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

			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				       (char *) &hop_limit, sizeof(hop_limit)) < 0) {
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
					     &thread->connection->socket.inet.src_ipaddr, thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static void *mod_track_create(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
			      fr_io_track_t *track, uint8_t const *packet, size_t packet_len)
{
	proto_dhcpv6_track_t *t;
	uint8_t const *option;
	size_t t_size = sizeof(*t);
	size_t option_len;

	/*
	 *	Relay packets can be nested to almost any depth.
	 */
	while (packet[0] ==  FR_DHCPV6_RELAY_FORWARD) {
		if (packet_len < (2 + 32)) return NULL;

		/*
		 *	fr_dhcpv6_option_find() ensures that the
		 *	option header and data are contained within
		 *	the given packet.
		 */
		option = fr_dhcpv6_option_find(packet + 2 + 32, packet + packet_len, attr_relay_message->attr);
		if (!option) return NULL;

		option_len = fr_nbo_to_uint16(option + 2);

		packet = option + 4; /* skip option header */
		packet_len = option_len;
	}

	if (packet_len <= 4) return NULL;

	/*
	 *	Search the packet options.
	 */
	option = fr_dhcpv6_option_find(packet + 4, packet + packet_len, attr_client_id->attr);
	if (!option) return NULL;

	option_len = fr_nbo_to_uint16(option + 2);

	if ((option + option_len) > (packet + packet_len)) return NULL;

	t = (proto_dhcpv6_track_t *) talloc_zero_array(track, uint8_t, t_size + option_len);
	if (!t) return NULL;

	talloc_set_name_const(t, "proto_dhcpv6_track_t");

	memcpy(&t->header, packet, 4); /* packet code + 24-bit transaction ID */

	/* coverity[tainted_data] */
	memcpy(&t->client_id[0], option + 4, option_len);
	t->client_id_len = option_len;

	return t;
}


static int mod_track_compare(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
			     void const *one, void const *two)
{
	int ret;
	proto_dhcpv6_track_t const *a = one;
	proto_dhcpv6_track_t const *b = two;

	ret = memcmp(&a->header, &b->header, sizeof(a->header));
	if (ret != 0) return ret;

	ret = (a->client_id_len < b->client_id_len) - (a->client_id_len > b->client_id_len);
	if (ret != 0) return ret;

	return memcmp(a->client_id, b->client_id, a->client_id_len);
}


static char const *mod_name(fr_listen_t *li)
{
	proto_dhcpv6_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dhcpv6_udp_thread_t);

	return thread->name;
}


static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_dhcpv6_udp_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_dhcpv6_udp_t);
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;
	RADCLIENT		*client;
	CONF_SECTION		*conf = mctx->inst->conf;

	inst->cs = conf;

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		if (!inst->interface) {
			cf_log_err(conf, "No 'ipaddr' was specified in the 'udp' section");
			return -1;
		}

		/*
		 *	If there's a named interface, maybe we can
		 *	find a link-local address for it.  If so, just
		 *	use that.
		 */
		if (inst->interface &&
		    (fr_interface_to_ipaddr(inst->interface, &inst->ipaddr, AF_INET6, true) < 0)) {
			cf_log_err(conf, "No 'ipaddr' specified, and we cannot determine one for interface '%s'",
				   inst->interface);
				return -1;
		}
	}

	if (inst->ipaddr.af != AF_INET6) {
		cf_log_err(conf, "DHCPv6 cannot use IPv4 for 'ipaddr'");
		return -1;
	}

	/*
	 *	Remember if we're a multicast socket.
	 */
	inst->multicast = (fr_ipaddr_is_multicast(&inst->ipaddr) == 1);

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
					cf_log_err(conf, "No 'interface' specified, and we cannot "
						   "determine one for 'ipaddr = %pV'",
						   fr_box_ipaddr(inst->ipaddr));
					return -1;
				}
			}

		} else {
			/*
			 *	Multicast addresses MUST specify an interface.
			 */
			if (!inst->interface) goto interface_fail;

			if (fr_interface_to_ipaddr(inst->interface, &inst->src_ipaddr, AF_INET6, true) < 0) {
				cf_log_err(conf, "No 'src_ipaddr' specified, and we cannot determine "
					   "one for 'ipaddr = %pV and interface '%s'",
					   fr_box_ipaddr(inst->ipaddr), inst->interface);
				return -1;
			}
		}
	}

	/*
	 *	src_ipaddr must be of the same address family as "ipaddr"
	 */
	if (inst->src_ipaddr.af != inst->ipaddr.af) {
		cf_log_err(conf, "Both 'ipaddr' and 'src_ipaddr' must be from the same address family");
		return -1;
	}

	/*
	 *	Get the MAC address associated with this interface.
	 *	It can be used to create a server ID.
	 */
	(void) fr_interface_to_ethernet(inst->interface, &inst->ethernet);

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 4);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	if (!inst->port) {
		struct servent *s;

		if (!inst->port_name) {
			cf_log_err(conf, "No 'port' was specified in the 'udp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "udp");
		if (!s) {
			cf_log_err(conf, "Unknown value for 'port_name = %s", inst->port_name);
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
			cf_log_err(conf, "The 'allow' subsection MUST contain at least one 'network' entry when "
				   "'dynamic_clients = true'.");
			return -1;
		}
	} else {
		inst->trie = fr_master_io_network(inst, inst->ipaddr.af, inst->allow, inst->deny);
		if (!inst->trie) {
			cf_log_perr(conf, "Failed creating list of networks");
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
			cf_log_err(conf, "Failed creating local clients");
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
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "dhcpv6_udp",
		.config			= udp_listen_config,
		.inst_size		= sizeof(proto_dhcpv6_udp_t),
		.thread_inst_size	= sizeof(proto_dhcpv6_udp_thread_t),
		.bootstrap		= mod_bootstrap
	},
	.default_message_size	= 4096,
	.track_duplicates	= true,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.track_create  		= mod_track_create,
	.track_compare		= mod_track_compare,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
