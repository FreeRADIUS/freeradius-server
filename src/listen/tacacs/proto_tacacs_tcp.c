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
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */

#include <netdb.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include "proto_tacacs.h"

extern fr_app_io_t proto_tacacs_tcp;

#define TACACS_MAX_ATTRIBUTES 256

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

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

	fr_client_list_t		*clients;		//!< local clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_tacacs_tcp_t;

static const conf_parser_t networks_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("allow", FR_TYPE_COMBO_IP_PREFIX , CONF_FLAG_MULTI, proto_tacacs_tcp_t, allow) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("deny", FR_TYPE_COMBO_IP_PREFIX , CONF_FLAG_MULTI, proto_tacacs_tcp_t, deny) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t tcp_listen_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, proto_tacacs_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, proto_tacacs_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, proto_tacacs_tcp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", proto_tacacs_tcp_t, interface) },
	{ FR_CONF_OFFSET("port_name", proto_tacacs_tcp_t, port_name) },

	{ FR_CONF_OFFSET("port", proto_tacacs_tcp_t, port), .dflt = "49" },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, proto_tacacs_tcp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", proto_tacacs_tcp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", proto_tacacs_tcp_t, max_packet_size), .dflt = "4096" } ,
	{ FR_CONF_OFFSET("max_attributes", proto_tacacs_tcp_t, max_attributes), .dflt = STRINGIFY(TACACS_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};

static const char *packet_name[] = {
	[FR_TAC_PLUS_AUTHEN] = "Authentication",
	[FR_TAC_PLUS_AUTHOR] = "Authorization",
	[FR_TAC_PLUS_ACCT] = "Accounting",
};

/** Read TACACS data from a TCP connection
 *
 * @param[in] li		representing a client connection.
 * @param[in] packet_ctx	UNUSED.
 * @param[out] recv_time_p	When we read the packet.
 *				For some protocols we get this for free (but not here).
 * @param[out] buffer		to read into.
 * @param[in] buffer_len	Maximum length of the buffer.
 * @param[in,out] leftover	If the previous read didn't yield a complete packet
 *				we will have written how many bytes we read in leftover
 *				and returned 0.  On the next call, we use the
 *				value of leftover to offset the position we start
 *				writing into the buffer.
 *				*leftover must be subtracted from buffer_len when
 *				calculating free space in the buffer.
 * @return
 *	- >0 when a packet was read successfully.
 *	- 0 when we read a partial packet.
 * 	- <0 on error (socket should be closed).
 */
static ssize_t mod_read(fr_listen_t *li, UNUSED void **packet_ctx, fr_time_t *recv_time_p,
			uint8_t *buffer, size_t buffer_len, size_t *leftover)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);
	ssize_t				data_size, packet_len;
	size_t				in_buffer;

	/*
	 *	We may have read multiple packets in the previous read.  In which case the buffer may already
	 *	have packets remaining.  In that case, we can return packets directly from the buffer, and
	 *	skip the read().
	 */
	if (*leftover >= FR_HEADER_LENGTH) {
		packet_len = fr_tacacs_length(buffer, *leftover);
		if (packet_len < 0) goto invalid;

		if (packet_len <= ((ssize_t) *leftover)) {
			data_size = 0;
			goto have_packet;
		}

		/*
		 *	Else we don't have a full packet, try to read more data from the network.
		 */
	}

	/*
	 *      Read data into the buffer.
	 */
	data_size = read(thread->sockfd, buffer + (*leftover), buffer_len - (*leftover));
	if (data_size < 0) {
		switch (errno) {
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			/*
			 *	We didn't read any data leave the buffers alone.
			 *
			 *	i.e. if we had a partial packet in the buffer and we didn't read any data,
			 *	then the partial packet is still left in the buffer.
			 */
			return 0;

		default:
			break;
		}

		ERROR("proto_tacacs_tcp got read error (%zd) - %s", data_size, fr_syserror(errno));
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

have_packet:
	/*
	 *	Represents all the data we've read since we last
	 *	decoded a complete packet.
	 */
	in_buffer = *leftover + data_size;

	/*
	 *	Figure out how big the complete TACACS packet should be.
	 *	If we don't have enough data it'll likely come
	 *	through in the next fragment.
	 */
	packet_len = fr_tacacs_length(buffer, in_buffer);
	if (packet_len < 0) {
	invalid:
		PERROR("Invalid TACACS packet");
		return -1;	/* Malformed, close the socket */
	}

	/*
	 *	We don't have a complete TACACS+ packet.  Tell the
	 *	caller that we need to read more, but record
	 *	how much we read in leftover.
	 */
	if (in_buffer < (size_t) packet_len) {
		DEBUG3("proto_tacacs_tcp - Received packet fragment of %zu bytes (%zu bytes now pending)",
		       packet_len, *leftover);
		*leftover = in_buffer;
		return 0;
	}

	/*
	 *	We've read at least one packet.  Tell the caller that
	 *	there's more data available, and return only one packet.
	 */
	*leftover = in_buffer - packet_len;

	*recv_time_p = fr_time();
	thread->stats.total_requests++;

	/*
	 *	proto_tacacs sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	FR_PROTO_HEX_DUMP(buffer, packet_len, "tacacs_tcp_recv");

	if (DEBUG_ENABLED2) {
		char bogus_type[4];
		char const *type;

		if (buffer[1] && buffer[1] <= FR_TAC_PLUS_ACCT) type = packet_name[buffer[1]];
		else {
			sprintf(bogus_type, "%d", buffer[1]);
			type = bogus_type;
		}
		DEBUG2("proto_tacacs_tcp - Received %s seq_no %d length %zd %s",
		       type, buffer[2],
		       packet_len, thread->name);
	}

	return packet_len;
}

static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);
	ssize_t				data_size;

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
	if (written == 0) {
		thread->stats.total_responses++;
	}

	/*
	 *	Only write replies if they're TACACS+ packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = write(thread->sockfd, buffer + written, buffer_len - written);
	if (data_size <= 0) return data_size;

	/*
	 *	If we're supposed to close the socket, then go do that.
	 */
	if ((data_size + written) == buffer_len) {
		fr_tacacs_packet_t const *pkt = (fr_tacacs_packet_t const *) buffer;

		switch (pkt->hdr.type) {
		case FR_TAC_PLUS_AUTHEN:
			if (pkt->authen_reply.status == FR_TAC_PLUS_AUTHEN_STATUS_ERROR) goto close_it;
			break;


		case FR_TAC_PLUS_AUTHOR:
			if (pkt->author_reply.status == FR_TAC_PLUS_AUTHOR_STATUS_ERROR) {
			close_it:
				DEBUG("Closing connection due to unrecoverable server error response");
				return 0;
			}
			break;

		default:
			break;
		}
	}

	/*
	 *	Return the packet we wrote, plus any bytes previously
	 *	left over from previous packets.
	 */
	/* coverity[return_overflow] */
	return data_size + written;
}

static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);

	thread->connection = connection;

	return 0;
}

static void mod_network_get(int *ipproto, bool *dynamic_clients, fr_trie_t const **trie, void *instance)
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
	fr_ipaddr_t			ipaddr = inst->ipaddr;
	uint16_t			port = inst->port;

	fr_assert(!thread->connection);

	li->fd = sockfd = fr_socket_server_tcp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		PERROR("Failed opening TCP socket");
	error:
		return -1;
	}

	(void) fr_nonblock(sockfd);

	if (fr_socket_bind(sockfd, inst->interface, &ipaddr, &port) < 0) {
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

static char const *mod_name(fr_listen_t *li)
{
	proto_tacacs_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_tacacs_tcp_thread_t);

	return thread->name;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_tacacs_tcp_t	*inst = talloc_get_type_abort(mctx->mi->data, proto_tacacs_tcp_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	size_t			num;
	CONF_ITEM		*ci;
	CONF_SECTION		*server_cs;

	inst->cs = conf;

	/*
	 *	Complain if no "ipaddr" is set.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "No 'ipaddr' was specified in the 'tcp' section");
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
			cf_log_err(conf, "No 'port' was specified in the 'tcp' section");
			return -1;
		}

		s = getservbyname(inst->port_name, "tcp");
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
	 *	for IPPROTO_TCP, and require a "secret".
	 */
	if (cf_section_find_next(server_cs, NULL, "client", CF_IDENT_ANY)) {
		inst->clients = client_list_parse_section(server_cs, IPPROTO_TCP, false);
		if (!inst->clients) {
			cf_log_err(conf, "Failed creating local clients");
			return -1;
		}
	}

	return 0;
}

static fr_client_t *mod_client_find(fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	proto_tacacs_tcp_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_tacacs_tcp_t);

	/*
	 *	Prefer local clients.
	 */
	if (inst->clients) {
		fr_client_t *client;

		client = client_find(inst->clients, ipaddr, ipproto);
		if (client) return client;
	}

	return client_find(NULL, ipaddr, ipproto);
}

fr_app_io_t proto_tacacs_tcp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "tacacs_tcp",
		.config			= tcp_listen_config,
		.inst_size		= sizeof(proto_tacacs_tcp_t),
		.thread_inst_size	= sizeof(proto_tacacs_tcp_thread_t),
		.instantiate		= mod_instantiate,
	},
	.default_message_size	= 4096,
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name		= mod_name,
};
