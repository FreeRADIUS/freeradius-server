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
	char const			*server_name;		//!< virtual server name

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t			send_buff;		//!< How big the kernel's send buffer should be.

	uint16_t			port;			//!< Port to listen on.

	uint8_t				ttl;			//!< default ttl

	bool				only_state_changes;	//!< on read(), only send packets which signal a state change

	bool				recv_buff_is_set;	//!< Whether we were provided with a recv_buff
	bool				send_buff_is_set;	//!< Whether we were provided with a send_buff
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_rb_tree_t			*peers;			//!< our peers

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_bfd_udp_t;


static const conf_parser_t networks_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("allow", FR_TYPE_COMBO_IP_PREFIX , CONF_FLAG_MULTI, proto_bfd_udp_t, allow) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("deny", FR_TYPE_COMBO_IP_PREFIX , CONF_FLAG_MULTI, proto_bfd_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const conf_parser_t udp_listen_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, proto_bfd_udp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, proto_bfd_udp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, proto_bfd_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", proto_bfd_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", proto_bfd_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", proto_bfd_udp_t, port) },

	{ FR_CONF_OFFSET("ttl", proto_bfd_udp_t, ttl), .dflt = "255" },

	{ FR_CONF_OFFSET("only_state_changes", proto_bfd_udp_t, only_state_changes), .dflt = "yes" },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, proto_bfd_udp_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, proto_bfd_udp_t, send_buff) },

//	{ FR_CONF_OFFSET("dynamic_clients", proto_bfd_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len,
			size_t *leftover)
{
	proto_bfd_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_bfd_udp_t);
	proto_bfd_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);
	fr_io_address_t			*address, **address_p;
	fr_client_t			*client;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;

	bfd_packet_t	   		*packet;
	char const			*err = NULL;
	bfd_state_change_t		state_change;
	bfd_wrapper_t			*wrapper = (bfd_wrapper_t *) buffer;

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

	data_size = udp_recv(thread->sockfd, flags, &address->socket, wrapper->packet, buffer_len - offsetof(bfd_wrapper_t, packet), recv_time_p);
	if (data_size < 0) {
		PDEBUG2("proto_bfd_udp got read error");
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_bfd_udp got no data: ignoring");
		return 0;
	}

	/*
	 *	Try to find the client before looking at any packet data.
	 */
	client =  fr_rb_find(inst->peers, &(fr_client_t) { .ipaddr = address->socket.inet.src_ipaddr, .proto = IPPROTO_UDP });
	if (!client) {
		DEBUG2("BFD %s - Received invalid packet on %s - unknown client %pV:%u", inst->server_name, thread->name,
		       fr_box_ipaddr(address->socket.inet.src_ipaddr), address->socket.inet.src_port);
		thread->stats.total_packets_dropped++;
		return 0;
	}

	packet_len = data_size;

	if (!fr_bfd_packet_ok(&err, wrapper->packet, packet_len)) {
		DEBUG2("BFD %s - Received invalid packet on %s - %s", inst->server_name, thread->name, err);
		thread->stats.total_malformed_requests++;
		return 0;
	}

	thread->stats.total_requests++;
	packet = (bfd_packet_t *) wrapper->packet;

	/*
	 *	Print out what we received.
	 */
	DEBUG2("BFD %s peer %s received %s", client->shortname, inst->server_name, fr_bfd_packet_names[packet->state]);

	/*
	 *	Run the BFD state machine.  Depending on that result,
	 *	we either send the packet through to unlang, or not.
	 */
	state_change = bfd_session_process((bfd_session_t *) client, packet);

	if ((state_change == BFD_STATE_CHANGE_INVALID) || (state_change == BFD_STATE_CHANGE_ADMIN_DOWN)) return 0;

	if ((state_change == BFD_STATE_CHANGE_NONE) && inst->only_state_changes) return 0;

	wrapper->type = BFD_WRAPPER_RECV_PACKET;
	wrapper->state_change = state_change;

	return sizeof(wrapper) + packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_bfd_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);
	fr_io_track_t		*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	bfd_session_t		*session;
	ssize_t			rcode;
#ifndef NDEBUG
	char const		*err;
#endif

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_bfd
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	session = UNCONST(bfd_session_t *, track->address->radclient);

	fr_assert(buffer_len >= FR_BFD_HEADER_LENGTH);

	fr_assert(fr_bfd_packet_ok(&err, buffer, buffer_len));

	DEBUG("BFD %s peer %s sending %s",
	      session->server_name, session->client.shortname, fr_bfd_packet_names[session->session_state]);

	rcode = sendfromto(session->sockfd, buffer, buffer_len, 0, 0,
			   (struct sockaddr *) &session->local_sockaddr, session->local_salen,
			   (struct sockaddr *) &session->remote_sockaddr, session->remote_salen);
	if (rcode < 0) {
		ERROR("Failed sending packet: %s", fr_syserror(errno));
		bfd_session_admin_down(session);
		return 0;
	}

	return rcode;
}

static void mod_network_get(int *ipproto, bool *dynamic_clients, fr_trie_t const **trie, void *instance)
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
	fr_ipaddr_t			ipaddr = inst->ipaddr;
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

	/*
	 *	@todo - cache ifindex for use with udpfromto.
	 */
	if (fr_socket_bind(sockfd, inst->interface, &ipaddr, &port) < 0) {
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


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_bfd_udp_t		*inst = talloc_get_type_abort(mctx->mi->data, proto_bfd_udp_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;
	fr_rb_iter_inorder_t	iter;
	bfd_session_t	*peer;

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

	ci = cf_section_to_item(mctx->mi->parent->conf); /* listen { ... } */
	fr_assert(ci != NULL);
	ci = cf_parent(ci);
	fr_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);
	inst->server_name = cf_section_name2(server_cs);

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
	for (peer = fr_rb_iter_init_inorder(inst->peers, &iter);
	     peer != NULL;
	     peer = fr_rb_iter_next_inorder(inst->peers, &iter)) {
		if (peer->client.ipaddr.af != inst->ipaddr.af) continue;

		if (peer->inst) continue;

		/*
		 *	unspecified src_ipaddr is us, OR our address
		 *	matches.
		 */
		if (!(fr_ipaddr_is_inaddr_any(&peer->client.src_ipaddr) ||
		      (fr_ipaddr_cmp(&peer->client.src_ipaddr, &inst->ipaddr) == 0))) continue;

		peer->inst = inst;
		peer->client.src_ipaddr = inst->ipaddr; /* override inaddr_any */

		/*
		 *	Cache these so that they don't get recalculated on every packet.
		 */
		fr_ipaddr_to_sockaddr(&peer->remote_sockaddr, &peer->remote_salen, &peer->client.ipaddr, peer->port);
		fr_ipaddr_to_sockaddr(&peer->local_sockaddr, &peer->local_salen, &inst->ipaddr, inst->port);

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

/** Set the event list for a new socket
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	proto_bfd_udp_t const  	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_bfd_udp_t);
	proto_bfd_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_bfd_udp_thread_t);
	fr_rb_iter_inorder_t	iter;
	bfd_session_t		*peer;

	/*
	 *	Walk over the list of peers, associating them with this listener.
	 */
	for (peer = fr_rb_iter_init_inorder(inst->peers, &iter);
	     peer != NULL;
	     peer = fr_rb_iter_next_inorder(inst->peers, &iter)) {
		if (peer->inst != inst) continue;

		peer->el = el;
		peer->listen = li;
		peer->nr = (fr_network_t *) nr;
		peer->sockfd = thread->sockfd;
		peer->server_name = inst->server_name;
		peer->only_state_changes = inst->only_state_changes;

		bfd_session_start(peer);
	}
}


fr_app_io_t proto_bfd_udp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "bfd_udp",
		.config			= udp_listen_config,
		.inst_size		= sizeof(proto_bfd_udp_t),
		.thread_inst_size	= sizeof(proto_bfd_udp_thread_t),
		.instantiate		= mod_instantiate
	},
	.default_message_size	= FR_BFD_HEADER_LENGTH + 64, /* enough for some auth packets */
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.network_get		= mod_network_get,
	.event_list_set		= mod_event_list_set,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
