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
 * @file proto_control_tcp.c
 * @brief Control handler for TCP.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/tcp.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/rad_assert.h>
#include "proto_control.h"

extern fr_app_io_t proto_control_tcp;

typedef struct {
	char const			*name;			//!< socket name
	CONF_SECTION			*cs;			//!< our configuration

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request
	fr_network_t			*nr;			//!< for fr_network_listen_read();

	fr_ipaddr_t			ipaddr;			//!< IP address to listen on.

	char const			*interface;		//!< Interface to bind to.
	char const			*port_name;		//!< Name of the port for getservent().

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.

	fr_stats_t			stats;			//!< statistics for this socket

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients

	fr_io_address_t			*connection;		//!< for connected sockets.

} proto_control_tcp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_control_tcp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_control_tcp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER tcp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_control_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_control_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_control_tcp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_control_tcp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_control_tcp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_control_tcp_t, port) },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_control_tcp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_control_tcp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_control_tcp_t, max_packet_size), .dflt = "4096" } ,

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, UNUSED void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_control_tcp_t		*inst = talloc_get_type_abort(li->thread_instance, proto_control_tcp_t);
	ssize_t				data_size;

	fr_conduit_type_t		conduit;
	bool				want_more;

	/*
	 *      Read data into the buffer.
	 */
	data_size = fr_conduit_read_async(inst->sockfd, &conduit, buffer, buffer_len, leftover, &want_more);
	if (data_size < 0) {
		DEBUG2("proto_control_tcp got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	/*
	 *	Note that we return ERROR for all bad packets, as
	 *	there's no point in reading packets from a TCP
	 *	connection which isn't sending us properly formatted
	 *	packets.
	 */

	/*
	 *	Not enough for a full packet, ask the caller to read more.
	 */
	if (want_more) {
		return 0;
	}

	*recv_time_p = fr_time();

	// @todo - copy the rest of the code from proto_control_unix,
	// or put it into a library and deal with it there...

	/*
	 *	proto_control sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_control_tcp - Received command packet length %d on %s",
	       (int) data_size, inst->name);

	return data_size;
}


static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_control_tcp_t		*inst = talloc_get_type_abort(li->thread_instance, proto_control_tcp_t);
//	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_control
	 *	can update them, too.. <sigh>
	 */
	inst->stats.total_responses++;

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = write(inst->sockfd, buffer + written, buffer_len - written);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	return data_size + written;
}


static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_control_tcp_t *inst = talloc_get_type_abort(li->thread_instance, proto_control_tcp_t);

	inst->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_control_tcp_t *inst = talloc_get_type_abort(instance, proto_control_tcp_t);

	*ipproto = IPPROTO_TCP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}


/** Open a TCP listener for control sockets
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_control_tcp_t *inst = talloc_get_type_abort(li->thread_instance, proto_control_tcp_t);

	int				sockfd;
	uint16_t			port = inst->port;
	CONF_SECTION			*server_cs;
	CONF_ITEM			*ci;

	rad_assert(!inst->connection);

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

	inst->sockfd = sockfd;

	ci = cf_parent(inst->cs); /* listen { ... } */
	rad_assert(ci != NULL);
	ci = cf_parent(ci);
	rad_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	inst->name = fr_app_io_socket_name(inst, &proto_control_tcp,
					   NULL, 0,
					   &inst->ipaddr, inst->port);

	// @todo - also print out auth / acct / coa, etc.
	DEBUG("Listening on control address %s bound to virtual server %s",
	      inst->name, cf_section_name2(server_cs));

	return 0;
}


/** Set the file descriptor for this socket.
 *
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_control_tcp_t *inst = talloc_get_type_abort(li->thread_instance, proto_control_tcp_t);

	inst->sockfd = fd;

	inst->name = fr_app_io_socket_name(inst, &proto_control_tcp,
					   &inst->connection->src_ipaddr, inst->connection->src_port,
					   &inst->ipaddr, inst->port);

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_control_tcp_t	*inst = talloc_get_type_abort(instance, proto_control_tcp_t);
	size_t			i, num;

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
		MEM(inst->trie = fr_trie_alloc(inst));

		for (i = 0; i < num; i++) {
			fr_ipaddr_t *network;
			char buffer[256];

			/*
			 *	Can't add v4 networks to a v6 socket, or vice versa.
			 */
			if (inst->allow[i].af != inst->ipaddr.af) {
				cf_log_err(cs, "Address family in entry %zd - 'allow = %pV' does not match 'ipaddr'",
					   i + 1, fr_box_ipaddr(inst->allow[i]));
				return -1;
			}

			/*
			 *	Duplicates are bad.
			 */
			network = fr_trie_match(inst->trie,
						&inst->allow[i].addr, inst->allow[i].prefix);
			if (network) {
				cf_log_err(cs, "Cannot add duplicate entry 'allow = %pV'",
					   fr_box_ipaddr(inst->allow[i]));
				return -1;
			}

			/*
			 *	Look for overlapping entries.
			 *	i.e. the networks MUST be disjoint.
			 *
			 *	Note that this catches 192.168.1/24
			 *	followed by 192.168/16, but NOT the
			 *	other way around.  The best fix is
			 *	likely to add a flag to
			 *	fr_trie_alloc() saying "we can only
			 *	have terminal fr_trie_user_t nodes"
			 */
			network = fr_trie_lookup(inst->trie,
						 &inst->allow[i].addr, inst->allow[i].prefix);
			if (network && (network->prefix <= inst->allow[i].prefix)) {
				cf_log_err(cs, "Cannot add overlapping entry 'allow = %pV'",
					   fr_box_ipaddr(inst->allow[i]));
				cf_log_err(cs, "Entry is completely enclosed inside of a previously defined network.");
				return -1;
			}

			/*
			 *	Insert the network into the trie.
			 *	Lookups will return the fr_ipaddr_t of
			 *	the network.
			 */
			if (fr_trie_insert(inst->trie,
					   &inst->allow[i].addr, inst->allow[i].prefix,
					   &inst->allow[i]) < 0) {
				cf_log_err(cs, "Failed adding 'allow = %pV' to tracking table",
					   fr_box_ipaddr(inst->allow[i]));
				return -1;
			}
		}

		/*
		 *	And now check denied networks.
		 */
		num = talloc_array_length(inst->deny);
		if (!num) return 0;

		/*
		 *	Since the default is to deny, you can only add
		 *	a "deny" inside of a previous "allow".
		 */
		for (i = 0; i < num; i++) {
			fr_ipaddr_t *network;
			char buffer[256];

			/*
			 *	Can't add v4 networks to a v6 socket, or vice versa.
			 */
			if (inst->deny[i].af != inst->ipaddr.af) {
				cf_log_err(cs, "Address family in entry %zd - 'deny = %pV' does "
					   "not match 'ipaddr'", i + 1, fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	Duplicates are bad.
			 */
			network = fr_trie_match(inst->trie,
						&inst->deny[i].addr, inst->deny[i].prefix);
			if (network) {
				cf_log_err(cs, "Cannot add duplicate entry 'deny = %pV'",
					   fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	A "deny" can only be within a previous "allow".
			 */
			network = fr_trie_lookup(inst->trie,
						&inst->deny[i].addr, inst->deny[i].prefix);
			if (!network) {
				cf_log_err(cs, "The network in entry %zd - 'deny = %pV' is not contained within "
					   "a previous 'allow'", i + 1, fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	We hack the AF in "deny" rules.  If
			 *	the lookup gets AF_UNSPEC, then we're
			 *	adding a "deny" inside of a "deny".
			 */
			if (network->af != inst->ipaddr.af) {
				cf_log_err(cs, "The network in entry %zd - 'deny = %pV' "
					   "overlaps with another 'deny' rule",
					   i + 1, fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	Insert the network into the trie.
			 *	Lookups will return the fr_ipaddr_t of
			 *	the network.
			 */
			if (fr_trie_insert(inst->trie,
					   &inst->deny[i].addr, inst->deny[i].prefix,
					   &inst->deny[i]) < 0) {
				cf_log_err(cs, "Failed adding 'deny = %pV' to tracking table",
					   fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	Hack it to make it a deny rule.
			 */
			inst->deny[i].af = AF_UNSPEC;
		}
	}

	return 0;
}

static RADCLIENT *mod_client_find(UNUSED fr_listen_t *li, fr_ipaddr_t const *ipaddr, int ipproto)
{
	return client_find(NULL, ipaddr, ipproto);
}

fr_app_io_t proto_control_tcp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "control_tcp",
	.config			= tcp_listen_config,
	.inst_size		= sizeof(proto_control_tcp_t),
	.bootstrap		= mod_bootstrap,

	.default_message_size	= 4096,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
};
