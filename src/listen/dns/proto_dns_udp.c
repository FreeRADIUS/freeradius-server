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
 * @file proto_dns_udp.c
 * @brief DHCPv6 handler for UDP.
 *
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
#define LOG_PREFIX "proto_dns_udp"

#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/protocol/dns/freeradius.internal.h>
#include "proto_dns.h"

extern fr_app_io_t proto_dns_udp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket
}  proto_dns_udp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.

	RADCLIENT_LIST			*clients;		//!< local clients
	RADCLIENT			*default_client;	//!< default 0/0 client

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_dns_udp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dns_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_dns_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_dns_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_dns_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_dns_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_dns_udp_t, interface) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_dns_udp_t, port), .dflt = "547"  },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_dns_udp_t, recv_buff) },

	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_dns_udp_t, max_packet_size), .dflt = "576" } ,
	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_dns_udp_t, max_attributes), .dflt = STRINGIFY(DNS_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_dns;

extern fr_dict_autoload_t proto_dns_udp_dict[];
fr_dict_autoload_t proto_dns_udp_dict[] = {
	{ .out = &dict_dns, .proto = "dns" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_dns_udp_dict_attr[];
fr_dict_attr_autoload_t proto_dns_udp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dns},

	{ NULL }
};

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len,
			size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
//	proto_dns_udp_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dns_udp_t);
	proto_dns_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_dns_udp_thread_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;
	uint32_t			xid;
	fr_dns_packet_t			*packet;
	fr_dns_decode_fail_t		reason;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_dns.
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

	if ((size_t) data_size < DNS_HDR_LEN) {
		RATE_LIMIT_GLOBAL(WARN, "Insufficient data - ignoring");
		return 0;
	}

	packet_len = data_size;

	/*
	 *	We've seen a server reply to this port, but the giaddr
	 *	is *not* our address.  Drop it.
	 */
	packet = (fr_dns_packet_t *) buffer;

	if (!fr_dns_packet_ok(buffer, packet_len, true, &reason)) {
		RATE_LIMIT_GLOBAL(WARN, "Invalid DNS packet failed with reason %d - ignoring", reason);
		return 0;
	}

	/*
	 *	check packet code
	 */

	/*
	 *	proto_dns sets the priority
	 */

	xid = fr_nbo_to_uint16(buffer);

	/*
	 *	Print out what we received.
	 */
	DEBUG2("Received %s ID %04x length %d %s", fr_dns_packet_codes[packet->opcode], xid,
	       (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
//	proto_dns_udp_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dns_udp_t);
	proto_dns_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_dns_udp_thread_t);

	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_socket_t			socket;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_dns
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	/*
	 *	Send packets to the originator.
	 */
	fr_socket_addr_swap(&socket, &track->address->socket);

	/*
	 *	Figure out which kind of packet we're sending.
	 */
	if (!thread->connection) {
		// @todo - figure out where to send the packet
	}

	/*
	 *	proto_dns takes care of suppressing do-not-respond, etc.
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
	proto_dns_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dns_udp_thread_t);

	thread->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_dns_udp_t		*inst = talloc_get_type_abort(instance, proto_dns_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = false;
	*trie = inst->trie;
}


/** Open a UDP listener for DHCPv6
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_dns_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dns_udp_t);
	proto_dns_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dns_udp_thread_t);

	int				sockfd, rcode;
	uint16_t			port = inst->port;

	li->fd = sockfd = fr_socket_server_udp(&inst->ipaddr, &port, "domain", true);
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
		close(sockfd);
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_dns_udp,
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
	proto_dns_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_dns_udp_t);
	proto_dns_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dns_udp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_dns_udp,
					     &thread->connection->socket.inet.src_ipaddr, thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}


static char const *mod_name(fr_listen_t *li)
{
	proto_dns_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_dns_udp_thread_t);

	return thread->name;
}


static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_dns_udp_t		*inst = talloc_get_type_abort(mctx->inst->data, proto_dns_udp_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;
	RADCLIENT		*client;

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
		    (fr_interface_to_ipaddr(inst->interface, &inst->ipaddr, AF_INET, true) < 0)) {
			cf_log_err(conf, "No 'ipaddr' specified, and we cannot determine one for interface '%s'",
				   inst->interface);
				return -1;
		}
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	/*
	 *	Parse and create the trie for dynamic clients, even if
	 *	there's no dynamic clients.
	 */
	num = talloc_array_length(inst->allow);
	if (num) {
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
	proto_dns_udp_t const *inst = talloc_get_type_abort_const(li->app_io_instance, proto_dns_udp_t);

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

fr_app_io_t proto_dns_udp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "dns_udp",
		.config			= udp_listen_config,
		.inst_size		= sizeof(proto_dns_udp_t),
		.thread_inst_size	= sizeof(proto_dns_udp_thread_t),
		.bootstrap		= mod_bootstrap
	},
	.default_message_size	= 576,
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
