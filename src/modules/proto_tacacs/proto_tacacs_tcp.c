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
 * @file proto_tacacs_tcp.c
 * @brief TACACS+ handler for TCP.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

#include <netdb.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/tcp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/util/debug.h>
#include "proto_tacacs.h"

extern fr_app_io_t proto_tacacs_tcp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	bool				seen_first_packet;
	bool				single_connection;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket
} proto_tacacs_tcp_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a recv_buff
	bool				dynamic_clients;	//!< whether we have dynamic clients

	RADCLIENT_LIST			*clients;		//!< local clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_tacacs_tcp_t;

static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_tacacs_tcp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_tacacs_tcp_t, deny) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER tcp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_tacacs_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_tacacs_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_tacacs_tcp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_tacacs_tcp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_tacacs_tcp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_tacacs_tcp_t, port), .dflt = "49" },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_tacacs_tcp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_tacacs_tcp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_tacacs_tcp_t, max_packet_size), .dflt = "4096" } ,
	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_tacacs_tcp_t, max_attributes), .dflt = STRINGIFY(TACACS_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};

static const char *packet_name[] = {
	[FR_TAC_PLUS_AUTHEN] = "Authentication",
	[FR_TAC_PLUS_AUTHOR] = "Authorization",
	[FR_TAC_PLUS_ACCT] = "Accounting",
};

static ssize_t mod_read(fr_listen_t *li, UNUSED void **packet_ctx, UNUSED fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	// proto_tacacs_tcp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tacacs_tcp_t);
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);
	ssize_t				data_size;
	size_t				packet_len, in_buffer;

	/*
	 *      Read data into the buffer.
	 */
	data_size = read(thread->sockfd, buffer + *leftover, buffer_len - *leftover);
	if (data_size < 0) {
		PDEBUG2("proto_tacacs_tcp got read error %zd", data_size);
		return data_size;
	}

	/*
	 *	Note that we return ERROR for all bad packets, as
	 *	there's no point in reading TACACS+ packets from a TCP
	 *	connection which isn't sending us TACACS+ packets.
	 */

	/*
	 *	TCP read of zero means the socket is dead.
	 */
	if (!data_size) {
		DEBUG2("proto_tacacs_tcp - other side closed the socket.");
		return -1;
	}

	in_buffer = *leftover + data_size;

	/*
	 *	We don't have a complete TACACS+ packet.  Tell the
	 *	caller that we need to read more.
	 */
	packet_len = fr_tacacs_length(buffer, in_buffer);
	if (in_buffer < packet_len) {
		*leftover = in_buffer;
		return 0;
	}

	/*
	 *	We've read more than one packet.  Tell the caller that
	 *	there's more data available, and return only one packet.
	 */
	if (in_buffer > packet_len) {
		*leftover = in_buffer - packet_len;
	}

	*recv_time_p = fr_time();
	thread->stats.total_requests++;

	/*
	 *	See if we negotiated multiple sessions on a single
	 *	connection.
	 */
	if (!thread->seen_first_packet) {
		fr_tacacs_packet_t *pkt = (fr_tacacs_packet_t *) buffer;

		thread->seen_first_packet = true;
		thread->single_connection = ((pkt->hdr.flags & FR_FLAGS_VALUE_SINGLE_CONNECT) != 0);
	}

	/*
	 *	proto_tacacs sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	FR_PROTO_HEX_DUMP(buffer, packet_len, "tacacs_tcp_recv");

	DEBUG2("proto_tacacs_tcp - Received %s seq_no %d length %d %s",
	       packet_name[buffer[1]], buffer[2],
	       (int) packet_len, thread->name);

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);
	ssize_t				data_size;
	fr_tacacs_packet_t		*pkt;

	/*
	 *	We only write TACACS packets.
	 *
	 *	@todo - if buffer_len ==1, it means "do not respond".
	 *	Which should be suppressed somewhere.  Maybe here...
	 */
	fr_assert(buffer_len >= sizeof(fr_tacacs_packet_hdr_t));
	fr_assert(written < buffer_len);

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_tacacs
	 *	can update them, too.. <sigh>
	 */
	pkt = (fr_tacacs_packet_t *) buffer;
	if (written == 0) {
		thread->stats.total_responses++;
		if (thread->single_connection) pkt->hdr.flags |= FR_FLAGS_VALUE_SINGLE_CONNECT;
	}

	/*
	 *	Only write replies if they're TACACS+ packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = write(thread->sockfd, buffer + written, buffer_len - written);
	if (data_size <= 0) return data_size;

	/*
	 *	If the "use single connection" flag is clear, then we
	 *	are only doing a single session.  In which case,
	 *	return 0, which tells the caller to close the socket.
	 */
	if (((pkt->hdr.flags & FR_FLAGS_VALUE_SINGLE_CONNECT) == 0) &&
	    (data_size + written) >= buffer_len) {
		// @todo - check status for pass / fail / error, which
		// cause the connection to be closed.  Everything else
		// leaves it open.
		return 0;
	}

	return data_size + written;
}

static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);

	thread->connection = connection;

	return 0;
}

static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_tacacs_tcp_t *inst = talloc_get_type_abort(instance, proto_tacacs_tcp_t);

	*ipproto = IPPROTO_TCP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}

/** Open a TCP listener for TACACS+
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_tacacs_tcp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tacacs_tcp_t);
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);

	int				sockfd;
	uint16_t			port = inst->port;

	fr_assert(!thread->connection);

	li->fd = sockfd = fr_socket_server_tcp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		PERROR("Failed opening TCP socket");
	error:
		return -1;
	}

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	if (listen(sockfd, 8) < 0) {
		close(sockfd);
		PERROR("Failed listening on socket");
		goto error;
	}

	thread->sockfd = sockfd;

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = fr_app_io_socket_name(thread, &proto_tacacs_tcp,
					     NULL, 0,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}


/** Set the file descriptor for this socket.
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_tacacs_tcp_t const  *inst = talloc_get_type_abort_const(li->app_io_instance, proto_tacacs_tcp_t);
	proto_tacacs_tcp_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_tacacs_tcp,
					     &thread->connection->socket.inet.src_ipaddr, thread->connection->socket.inet.src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static void *mod_track_create(TALLOC_CTX *ctx, uint8_t const *buffer, UNUSED size_t buffer_len)
{
	fr_tacacs_packet_t const *pkt = (fr_tacacs_packet_t const *) buffer;
	proto_tacacs_track_t     *track;

	track = talloc_zero(ctx, proto_tacacs_track_t);

	if (!track) return NULL;

	talloc_set_name_const(track, "proto_tacacs_track_t");

	switch (pkt->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		if (packet_is_authen_start_request(pkt)) {
			track->type = FR_PACKET_TYPE_VALUE_AUTHENTICATION_START;
		} else {
			track->type = FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE;
		}
		break;

	case FR_TAC_PLUS_AUTHOR:
		track->type = FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST;
		break;

	case FR_TAC_PLUS_ACCT:
		track->type = FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST;
		break;

	default:
		talloc_free(track);
		fr_assert(0);
		return NULL;
	}

	track->session_id = pkt->hdr.session_id;

	return track;
}

static int mod_compare(UNUSED void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
		       void const *one, void const *two)
{
	int ret;
	proto_tacacs_track_t const *a = talloc_get_type_abort_const(one, proto_tacacs_track_t);
	proto_tacacs_track_t const *b = talloc_get_type_abort_const(two, proto_tacacs_track_t);

	/*
	 *	Session IDs SHOULD be random 32-bit integers.
	 */
	ret = (a->session_id < b->session_id) - (a->session_id > b->session_id);
	if (ret != 0) return ret;

	/*
	 *	Then ordered by our synthetic packet type.
	 */
	return (a->type < b->type) - (a->type > b->type);
}

static char const *mod_name(fr_listen_t *li)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);

	return thread->name;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_tacacs_tcp_t	*inst = talloc_get_type_abort(instance, proto_tacacs_tcp_t);
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;

	inst->cs = cs;

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(cs, "No 'ipaddr' was specified in the 'tcp' section");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	if (!inst->port) {
		struct servent *s;

		if (!inst->port_name) {
			cf_log_err(cs, "No 'port' was specified in the 'tcp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "tcp");
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
	 *	for IPPROTO_TCP, and require a "secret".
	 */
	if (cf_section_find_next(server_cs, NULL, "client", CF_IDENT_ANY)) {
		inst->clients = client_list_parse_section(server_cs, IPPROTO_TCP, false);
		if (!inst->clients) {
			cf_log_err(cs, "Failed creating local clients");
			return -1;
		}
	}

	return 0;
}

static RADCLIENT *mod_client_find(UNUSED fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	return client_find(NULL, ipaddr, ipproto);
}

fr_app_io_t proto_tacacs_tcp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "tacacs_tcp",
	.config			= tcp_listen_config,
	.inst_size		= sizeof(proto_tacacs_tcp_t),
	.thread_inst_size	= sizeof(proto_tacacs_tcp_thread_t),
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
