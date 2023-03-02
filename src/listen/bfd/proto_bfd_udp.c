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
 * @file proto_bfd_udp.c
 * @brief BFD handler for UDP.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/bfd/bfd.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>

#include "session.h"

extern fr_app_io_t proto_bfd_udp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket

} proto_bfd_udp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_event_list_t			*el;

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t			send_buff;		//!< How big the kernel's send buffer should be.

	uint16_t			port;			//!< Port to listen on.

	uint8_t				ttl;			//!< default ttl

	bool				recv_buff_is_set;	//!< Whether we were provided with a recv_buff
	bool				send_buff_is_set;	//!< Whether we were provided with a send_buff
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_rb_tree_t			*peers;			//!< our peers

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_bfd_udp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_bfd_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_bfd_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_bfd_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_bfd_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_bfd_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_bfd_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_bfd_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_bfd_udp_t, port) },

	{ FR_CONF_OFFSET("ttl", FR_TYPE_UINT8, proto_bfd_udp_t, ttl), .dflt = "255" },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_bfd_udp_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, proto_bfd_udp_t, send_buff) },

//	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_bfd_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len,
			size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
//	proto_bfd_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_bfd_udp_t);
	proto_bfd_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;

	bfd_packet_t			*packet;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_bfd.
	 */
	address_p = (fr_io_address_t **)packet_ctx;
	address = *address_p;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	data_size = udp_recv(thread->sockfd, flags, &address->socket, buffer, buffer_len, recv_time_p);
	if (data_size < 0) {
		PDEBUG2("proto_bfd_udp got read error");
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_bfd_udp got no data: ignoring");
		return 0;
	}

	packet_len = data_size;

	if (data_size < FR_BFD_HEADER_LENGTH) {
		DEBUG2("proto_bfd_udp got 'too short' packet size %zd", data_size);
		thread->stats.total_malformed_requests++;
		return 0;
	}

	thread->stats.total_requests++;

	packet = (bfd_packet_t *) buffer;

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_bfd_udp - Received %s ID length %d %s",
	       fr_bfd_packet_names[packet->state],
	       (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_bfd_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);
	fr_io_track_t *track = talloc_get_type_abort(packet_ctx, fr_io_track_t);

	fr_socket_t  			socket;

	int				flags;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_bfd
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	/*
	 *	Swap src/dst address so we send the response to
	 *	the client, not ourselves.
	 */
	fr_socket_addr_swap(&socket, &track->address->socket);

	/*
	 *	We only write RADIUS packets.
	 */
	fr_assert(buffer_len >= FR_BFD_HEADER_LENGTH);

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	return udp_send(&socket, flags, buffer, buffer_len);
}

static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_bfd_udp_t *inst = talloc_get_type_abort(instance, proto_bfd_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}

/** Open a UDP listener for RADIUS
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_bfd_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_bfd_udp_t);
	proto_bfd_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);

	int				sockfd;
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
			return -1;
		}
	}

#ifdef SO_RCVBUF
	if (inst->recv_buff_is_set) {
		int opt;

		opt = inst->recv_buff;
		if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			WARN("Failed setting 'recv_buf': %s", fr_syserror(errno));
		}
	}
#endif

#ifdef SO_SNDBUF
	if (inst->send_buff_is_set) {
		int opt;

		opt = inst->send_buff;
		if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int)) < 0) {
			WARN("Failed setting 'send_buf': %s", fr_syserror(errno));
		}
	}
#endif

#ifdef IP_TTL
	{
		int opt;

		opt = inst->ttl;
		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &opt, sizeof(opt)) < 0) {
			WARN("Failed setting 'ttl': %s", fr_syserror(errno));
		}
	}
#endif

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_bfd_udp,
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
	proto_bfd_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_bfd_udp_t);
	proto_bfd_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_bfd_udp,
					     &thread->connection->socket.inet.src_ipaddr, thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static char const *mod_name(fr_listen_t *li)
{
	proto_bfd_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);

	return thread->name;
}


static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_bfd_udp_t		*inst = talloc_get_type_abort(mctx->inst->data, proto_bfd_udp_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;
	fr_rb_iter_inorder_t	iter;
	proto_bfd_peer_t	*peer;

	inst->cs = conf;

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "No 'ipaddr' was specified in the 'udp' section");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, 256);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, (1 << 30));
	}

	FR_INTEGER_BOUND_CHECK("ttl", inst->ttl, >=, 64);

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
			cf_log_err(conf, "The 'allow' subsection MUST contain at least one 'network' entry when 'dynamic_clients = true'.");
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
	 *	Look up peer list.
	 */
	inst->peers = cf_data_value(cf_data_find(server_cs, fr_rb_tree_t, "peers"));
	if (!inst->peers) {
		cf_log_err(conf, "Failed finding peer list");
		return -1;
	}

	/*
	 *	Walk over the list of peers, associating them with this listener.
	 */
	for (peer = fr_rb_iter_init_inorder(&iter, inst->peers);
	     peer != NULL;
	     peer = fr_rb_iter_next_inorder(&iter)) {
		if (peer->client.ipaddr.af != inst->ipaddr.af) continue;

		if (peer->inst) continue;

		peer->inst = inst;
		if (bfd_session_init(peer) < 0) {
			return -1;
		}
	}

	return 0;
}

static fr_client_t *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_bfd_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_bfd_udp_t);

	if (ipproto != IPPROTO_UDP) return NULL;

	return fr_rb_find(inst->peers, &(fr_client_t) { .ipaddr = *ipaddr, .proto = IPPROTO_UDP });
}

fr_app_io_t proto_bfd_udp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "bfd_udp",
		.config			= udp_listen_config,
		.inst_size		= sizeof(proto_bfd_udp_t),
		.thread_inst_size	= sizeof(proto_bfd_udp_thread_t),
		.bootstrap		= mod_bootstrap
	},
	.default_message_size	= FR_BFD_HEADER_LENGTH + 64, /* enough for some auth packets */
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
