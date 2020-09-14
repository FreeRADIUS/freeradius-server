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
 * @file proto_tftp_udp.c
 * @brief TFTP handler for UDP.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
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

#include <freeradius-devel/protocol/tftp/rfc1350.h>

#include "proto_tftp.h"

extern fr_app_io_t proto_tftp_udp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;
	fr_io_address_t			*connection;		//!< for connected sockets.
	fr_stats_t			stats;			//!< statistics for this socket
} proto_tftp_udp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients

	RADCLIENT_LIST			*clients;		//!< local clients
} proto_tftp_udp_t;

static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_tftp_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_tftp_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_tftp_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_tftp_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_tftp_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_tftp_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_tftp_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_tftp_udp_t, port), .dflt = "69" },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_tftp_udp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_tftp_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_tftp_udp_t, max_packet_size), .dflt = "1024" } ,

	CONF_PARSER_TERMINATOR
};

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_tftp_udp_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tftp_udp_t);
	proto_tftp_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_tftp_udp_thread_t);
	fr_io_address_t			*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;

	uint32_t			id = 0;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_tftp.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	data_size = udp_recv(thread->sockfd, flags, &address->socket, buffer, buffer_len, recv_time_p);
	if (data_size < 0) {
		PDEBUG2("proto_tftp_udp got read error %zd", data_size);
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_tftp_udp got no data: ignoring");
		return 0;
	}

	packet_len = data_size;

	if (data_size < FR_TFTP_HDR_LEN) {
		DEBUG2("proto_tftp_udp got 'too short' packet size %zd", data_size);
		thread->stats.total_malformed_requests++;
		return 0;
	}

	if (packet_len > inst->max_packet_size) {
		DEBUG2("proto_tftp_udp got 'too long' packet size %zd > %u", data_size, inst->max_packet_size);
		thread->stats.total_malformed_requests++;
		return 0;
	}

	if ((buffer[1] != FR_PACKET_TYPE_VALUE_READ_REQUEST) && (buffer[1] != FR_PACKET_TYPE_VALUE_ACKNOWLEDGEMENT)) {
		char const *name = fr_tftp_codes[ buffer[1] ];
		DEBUG("proto_tftp_udp got invalid packet code %d (%s), ignoring.", buffer[1], name ? name : "Unknown");
		thread->stats.total_unknown_types++;
		return 0;
	}

	/*
	 *	proto_tftp sets the priority
	 */
	memcpy(&id, buffer + sizeof(id), sizeof(id));
	id = ntohl(id);

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_tftp_udp - Received %d ID %08x length %d %s", buffer[1], id, (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_tftp_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_tftp_udp_thread_t);
	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_socket_t			socket;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_tftp
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (thread->connection != NULL);

	fr_socket_addr_swap(&socket, &track->address->socket);

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
		if (track->reply_len >= FR_TFTP_HDR_LEN) {
			char *packet;

			memcpy(&packet, &track->reply, sizeof(packet)); /* const issues */

			(void) udp_send(&socket, flags, packet, track->reply_len);
		}

		return buffer_len;
	}

	/*
	 *	We only write TFTP packets.
	 */
	fr_assert(buffer_len >= FR_TFTP_HDR_LEN);

	/*
	 *	Only write replies if they're TFTP packets.
	 *	sometimes we want to NOT send a reply...
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
	proto_tftp_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_tftp_udp_thread_t);

	thread->connection = connection;
	return 0;
}

static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_tftp_udp_t *inst = talloc_get_type_abort(instance, proto_tftp_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}

/**
 *  Open a UDP listener for TFTP
 */
static int mod_open(fr_listen_t *li)
{
	proto_tftp_udp_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tftp_udp_t);
	proto_tftp_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_tftp_udp_thread_t);

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
	{
		int on = 1;
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
			ERROR("Failed to set socket 'reuseport': %s", fr_syserror(errno));
			return -1;
		}
	}

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_tftp_udp,
					     NULL, 0,
					     &inst->ipaddr, inst->port,
					     inst->interface);
	return 0;
}


/**
 *  Set the file descriptor for this socket.
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_tftp_udp_t const		*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tftp_udp_t);
	proto_tftp_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_tftp_udp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_tftp_udp,
					     &thread->connection->socket.inet.src_ipaddr, thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static void *mod_track_create(TALLOC_CTX *ctx, uint8_t const *buffer, size_t buffer_len)
{
	proto_tftp_track_t  *track;

	if (buffer_len < FR_TFTP_HDR_LEN) {
		ERROR("TFTP packet is too small. (%zu < %d)", buffer_len, FR_TFTP_HDR_LEN);
		return NULL;
	}

	track = talloc_zero(ctx, proto_tftp_track_t);

	if (!track) return NULL;

	talloc_set_name_const(track, "proto_tftp_track_t");

	memcpy(&track->transaction_id, buffer, sizeof(track->transaction_id));

	track->opcode = fr_net_to_uint16(&buffer[0]);

	return track;
}

static int mod_compare(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
		       void const *one, void const *two)
{
	proto_tftp_track_t const *a = talloc_get_type_abort_const(one, proto_tftp_track_t);
	proto_tftp_track_t const *b = talloc_get_type_abort_const(two, proto_tftp_track_t);
	int rcode;

	/*
	 *	Order by transaction ID
	 */
	rcode = (a->transaction_id < b->transaction_id) - (a->transaction_id > b->transaction_id);
	if (rcode != 0) return rcode;

	/*
	 *	Then ordered by opcode, which is usally the same.
	 */
	return (a->opcode < b->opcode) - (a->opcode > b->opcode);
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_tftp_udp_t	*inst = talloc_get_type_abort(instance, proto_tftp_udp_t);
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;

	inst->cs = cs;

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

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 32);
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
	 *	for IPPROTO_UDP, and to not require a "secret".
	 */
	if (cf_section_find_next(server_cs, NULL, "client", CF_IDENT_ANY)) {
		inst->clients = client_list_parse_section(server_cs, IPPROTO_UDP, false);
		if (!inst->clients) {
			cf_log_err(cs, "Failed creating local clients");
			return -1;
		}
	}

	return 0;
}

// @todo - allow for "wildcard" clients, which allow anything
// and then rely on "networks" to filter source IPs...
// which means we probably want to filter on "networks" even if there are no dynamic clients
static RADCLIENT *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_tftp_udp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tftp_udp_t);
	RADCLIENT		*client;

	/*
	 *	Prefer local clients.
	 */
	if (inst->clients) {
		client = client_find(inst->clients, ipaddr, ipproto);
		if (client) return client;
	}

	return client_find(NULL, ipaddr, ipproto);
}

static char const *mod_name(fr_listen_t *li)
{
	proto_tftp_udp_thread_t		*thread = talloc_get_type_abort(li->thread_instance, proto_tftp_udp_thread_t);

	return thread->name;
}

fr_app_io_t proto_tftp_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "tftp_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_tftp_udp_t),
	.thread_inst_size	= sizeof(proto_tftp_udp_thread_t),
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
	.get_name		= mod_name,
};
