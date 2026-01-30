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
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>

#include "proto_radius.h"

extern fr_app_io_t proto_radius_udp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket

} proto_radius_udp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.
	fr_ipaddr_t			src_ipaddr;		//!< IP to use for responses, which may be
								///< different from the ipaddr we're listening on
								///< with L3 load balancing setups.
	bool				src_ipaddr_is_set;	//!< Use specified a source ip address.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t			send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a recv_buff
	bool				send_buff_is_set;	//!< Whether we were provided with a send_buff
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_client_list_t		*clients;		//!< local clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients

	bool				read_hexdump;		//!< Do we debug hexdump read packets.
	bool				write_hexdump;		//!< Do we debug hexdump write packets.
} proto_radius_udp_t;


static const conf_parser_t networks_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("allow", FR_TYPE_COMBO_IP_PREFIX , CONF_FLAG_MULTI, proto_radius_udp_t, allow) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("deny", FR_TYPE_COMBO_IP_PREFIX , CONF_FLAG_MULTI, proto_radius_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const conf_parser_t udp_listen_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, proto_radius_udp_t, ipaddr) },

	{ FR_CONF_OFFSET_IS_SET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, proto_radius_udp_t, src_ipaddr) },

	{ FR_CONF_OFFSET("interface", proto_radius_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", proto_radius_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", proto_radius_udp_t, port) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, proto_radius_udp_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, proto_radius_udp_t, send_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", proto_radius_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", proto_radius_udp_t, max_packet_size), .dflt = "4096" } ,
       	{ FR_CONF_OFFSET("max_attributes", proto_radius_udp_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) } ,

	{ FR_CONF_OFFSET("read_hexdump", proto_radius_udp_t, read_hexdump) },
	{ FR_CONF_OFFSET("write_hexdump", proto_radius_udp_t, write_hexdump) },

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len,
			size_t *leftover)
{
	proto_radius_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_udp_t);
	proto_radius_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_udp_thread_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;
	fr_radius_decode_fail_t		reason;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_radius.
	 */
	address_p = (fr_io_address_t **)packet_ctx;
	address = *address_p;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	data_size = udp_recv(thread->sockfd, flags, &address->socket, buffer, buffer_len, recv_time_p);
	if (data_size < 0) {
		proto_radius_log(li, thread->name, FR_RADIUS_FAIL_IO_ERROR, NULL,
				 "%s", fr_strerror());
		return data_size;
	}

	if (!data_size) {
		proto_radius_log(li, thread->name, FR_RADIUS_FAIL_IO_ERROR, NULL,
				 "Received no data");
		return 0;
	}

	packet_len = data_size;

	if (data_size < 20) {
		proto_radius_log(li, thread->name, FR_RADIUS_FAIL_MIN_LENGTH_PACKET, &address->socket,
				 "Received packet length %zu", packet_len);
		thread->stats.total_malformed_requests++;
		return 0;
	}

	if (packet_len > inst->max_packet_size) {
		proto_radius_log(li, thread->name, FR_RADIUS_FAIL_MIN_LENGTH_PACKET, &address->socket,
				 "Received packet length %zu");
		thread->stats.total_malformed_requests++;
		return 0;
	}

	if ((buffer[0] == 0) || (buffer[0] >= FR_RADIUS_CODE_MAX)) {
		proto_radius_log(li, thread->name, FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE, &address->socket,
				 "Received packet code %u", buffer[0]);
		thread->stats.total_unknown_types++;
		return 0;
	}

	/*
	 *      If it's not well-formed, discard it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, inst->max_attributes, false, &reason)) {
		proto_radius_log(li, thread->name, reason, &address->socket,
				 "Received invalid packet");
		thread->stats.total_malformed_requests++;
		return 0;
	}

	/*
	 *	proto_radius sets the priority
	 */
	thread->stats.total_requests++;

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_radius_udp - Received %s ID %d length %d %s",
	       fr_radius_packet_name[buffer[0]], buffer[1],
	       (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_radius_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_udp_t);
	proto_radius_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_udp_thread_t);

	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_socket_t  			socket;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_radius
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
	 *	Override the source ip address in the outbound
	 *	packet.
	 */
	if (inst->src_ipaddr_is_set) socket.inet.src_ipaddr = inst->src_ipaddr;

	/*
	 *	This handles the race condition where we get a DUP,
	 *	but the original packet replies before we're run.
	 *	i.e. this packet isn't marked DUP, so we have to
	 *	discover it's a dup later...
	 *
	 *	As such, if there's already a reply, then we ignore
	 *	the encoded reply (which is probably going to be a
	 *	NAK), and instead reply with the cached reply.
	 */
	if (track->reply_len) {
		if (track->reply_len >= 20) {
			char *packet;

			memcpy(&packet, &track->reply, sizeof(packet)); /* const issues */

			return udp_send(&socket, flags, packet, track->reply_len);
		}

		return buffer_len;
	}

	/*
	 *	We only write RADIUS packets.
	 */
	fr_assert(buffer_len >= 20);

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = udp_send(&socket, flags, buffer, buffer_len);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	/*
	 *	Root through the reply to determine any
	 *	connection-level negotiation data.
	 */
	if (track->packet[0] == FR_RADIUS_CODE_STATUS_SERVER) {
//		status_check_reply(inst, buffer, buffer_len);
	}

	return data_size;
}


static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_radius_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_udp_thread_t);

	thread->connection = connection;
	return 0;
}


static void mod_network_get(int *ipproto, bool *dynamic_clients, fr_trie_t const **trie, void *instance)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}

/** Open a UDP listener for RADIUS
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_radius_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_udp_t);
	proto_radius_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_udp_thread_t);

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

	if (fr_socket_bind(sockfd, inst->interface, &ipaddr, &port) < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_radius_udp,
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
	proto_radius_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_udp_t);
	proto_radius_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_udp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_radius_udp,
					     &thread->connection->socket.inet.src_ipaddr, thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static void *mod_track_create(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED fr_client_t *client,
			      fr_io_track_t *track, uint8_t const *packet, UNUSED size_t packet_len)
{
	return talloc_memdup(track, packet, RADIUS_HEADER_LENGTH);
}

static int mod_track_compare(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED fr_client_t *client,
			     void const *one, void const *two)
{
	int ret;
	uint8_t const *a = one;
	uint8_t const *b = two;

	/*
	 *	The tree is ordered by IDs, which are (hopefully)
	 *	pseudo-randomly distributed.
	 */
	ret = (a[1] < b[1]) - (a[1] > b[1]);
	if (ret != 0) return ret;

	/*
	 *	Then ordered by code, which is usually the same.
	 */
	return (a[0] < b[0]) - (a[0] > b[0]);
}


static char const *mod_name(fr_listen_t *li)
{
	proto_radius_udp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_udp_thread_t);

	return thread->name;
}

static void mod_hexdump_set(fr_listen_t *li, void *data)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(data, proto_radius_udp_t);
	li->read_hexdump = inst->read_hexdump;
	li->write_hexdump = inst->write_hexdump;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(mctx->mi->data, proto_radius_udp_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;

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
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, (1 << 30));
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
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

	/*
	 *	Look up local clients, if they exist.
	 *
	 *	@todo - ensure that we only parse clients which are
	 *	for IPPROTO_UDP, and require a "secret".
	 */
	if (cf_section_find_next(server_cs, NULL, "client", CF_IDENT_ANY)) {
		inst->clients = client_list_parse_section(server_cs, IPPROTO_UDP, false);
		if (!inst->clients) {
			cf_log_err(conf, "Failed creating local clients");
			return -1;
		}
	}

	return 0;
}

static fr_client_t *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_radius_udp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_udp_t);
	fr_client_t		*client;

	/*
	 *	Prefer local clients.
	 */
	if (inst->clients) {
		client = client_find(inst->clients, ipaddr, ipproto);
		if (client) return client;
	}

	return client_find(NULL, ipaddr, ipproto);
}

fr_app_io_t proto_radius_udp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "radius_udp",
		.config			= udp_listen_config,
		.inst_size		= sizeof(proto_radius_udp_t),
		.thread_inst_size	= sizeof(proto_radius_udp_thread_t),
		.instantiate		= mod_instantiate
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
	.hexdump_set		= mod_hexdump_set,
};
