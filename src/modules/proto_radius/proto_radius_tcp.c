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
 * @file proto_radius_tcp.c
 * @brief RADIUS handler for TCP.
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
#include <freeradius-devel/util/debug.h>
#include "proto_radius.h"

extern fr_app_io_t proto_radius_tcp;

typedef struct {
	char const			*name;			//!< socket name
	int				sockfd;

	fr_io_address_t			*connection;		//!< for connected sockets.

	fr_stats_t			stats;			//!< statistics for this socket
} proto_radius_tcp_thread_t;

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
	bool				dedup_authenticator;	//!< dedup using the request authenticator

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients
} proto_radius_tcp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_radius_tcp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_radius_tcp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER tcp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_radius_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_radius_tcp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_radius_tcp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_radius_tcp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_radius_tcp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_radius_tcp_t, port) },
	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, proto_radius_tcp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_radius_tcp_t, dynamic_clients) } ,
	{ FR_CONF_OFFSET("accept_conflicting_packets", FR_TYPE_BOOL, proto_radius_tcp_t, dedup_authenticator) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_radius_tcp_t, max_packet_size), .dflt = "4096" } ,
       	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_radius_tcp_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(fr_listen_t *li, UNUSED void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_radius_tcp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_tcp_t);
	proto_radius_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_tcp_thread_t);
	ssize_t				data_size;
	size_t				packet_len;
	decode_fail_t			reason;

	/*
	 *      Read data into the buffer.
	 */
	data_size = read(thread->sockfd, buffer + *leftover, buffer_len - *leftover);
	if (data_size < 0) {
		DEBUG2("proto_radius_tcp got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	/*
	 *	Note that we return ERROR for all bad packets, as
	 *	there's no point in reading RADIUS packets from a TCP
	 *	connection which isn't sending us RADIUS packets.
	 */

	/*
	 *	TCP read of zero means the socket is dead.
	 */
	if (!data_size) {
		DEBUG2("proto_radius_tcp - other side closed the socket.");
		return -1;
	}

	/*
	 *	We MUST always start with a known RADIUS packet.
	 */
	if ((buffer[0] == 0) || (buffer[0] > FR_RADIUS_MAX_PACKET_CODE)) {
		DEBUG("proto_radius_tcp got invalid packet code %d", buffer[0]);
		thread->stats.total_unknown_types++;
		return -1;
	}

	/*
	 *	Not enough for one packet.  Tell the caller that we need to read more.
	 */
	if (data_size < 20) {
		*leftover = data_size;
		return 0;
	}

	/*
	 *	Figure out how large the RADIUS packet is.
	 */
	packet_len = (buffer[2] << 8) | buffer[3];

	/*
	 *	We don't have a complete RADIUS packet.  Tell the
	 *	caller that we need to read more.
	 */
	if ((size_t) data_size < packet_len) {
		*leftover = data_size;
		return 0;
	}

	/*
	 *	We've read more than one packet.  Tell the caller that
	 *	there's more data available, and return only one packet.
	 */
	if ((size_t) data_size > packet_len) {
		*leftover = data_size - packet_len;
	}

	/*
	 *      If it's not a RADIUS packet, ignore it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, inst->max_attributes, false, &reason)) {
		/*
		 *      @todo - check for F5 load balancer packets.  <sigh>
		 */
		DEBUG2("proto_radius_tcp got a packet which isn't RADIUS");
		thread->stats.total_malformed_requests++;
		return -1;
	}

	*recv_time_p = fr_time();

	/*
	 *	proto_radius sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_radius_tcp - Received %s ID %d length %d %s",
	       fr_packet_codes[buffer[0]], buffer[1],
	       (int) packet_len, thread->name);

	return packet_len;
}


static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_radius_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_tcp_thread_t);
	fr_io_track_t			*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_radius
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	/*
	 *	This handles the race condition where we get a DUP,
	 *	but the original packet replies before we're run.
	 *	i.e. this packet isn't marked DUP, so we have to
	 *	discover it's a dup later...
	 *
	 *	As such, if there's already a reply, then we ignore
	 *	the encoded reply (which is probably going to be a
	 *	NAK), and instead just ignore the DUP and don't reply.
	 */
	if (track->reply_len) {
		return buffer_len;
	}

	/*
	 *	We only write RADIUS packets.
	 */
	fr_assert(buffer_len >= 20);
	fr_assert(written < buffer_len);

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = write(thread->sockfd, buffer + written, buffer_len - written);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	/*
	 *	Root through the reply to determine any
	 *	connection-level negotiation data, but only the first
	 *	time the packet is being written.
	 */
	if ((written == 0) && (track->packet[0] == FR_CODE_STATUS_SERVER)) {
//		status_check_reply(inst, buffer, buffer_len);
	}

	/*
	 *	Add in previously written data to the response.
	 */
	return data_size + written;
}


static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_radius_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_tcp_thread_t);

	thread->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_radius_tcp_t *inst = talloc_get_type_abort(instance, proto_radius_tcp_t);

	*ipproto = IPPROTO_TCP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}


/** Open a TCP listener for RADIUS
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_radius_tcp_t const       	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_tcp_t);
	proto_radius_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_tcp_thread_t);

	int				sockfd;
	uint16_t			port = inst->port;
	CONF_ITEM			*ci;

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

	ci = cf_parent(inst->cs); /* listen { ... } */
	fr_assert(ci != NULL);
	ci = cf_parent(ci);
	fr_assert(ci != NULL);

	thread->name = fr_app_io_socket_name(thread, &proto_radius_tcp,
					     NULL, 0,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}


/** Set the file descriptor for this socket.
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_radius_tcp_t const  *inst = talloc_get_type_abort_const(li->app_io_instance, proto_radius_tcp_t);
	proto_radius_tcp_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_radius_tcp_thread_t);

	thread->sockfd = fd;

	thread->name = fr_app_io_socket_name(thread, &proto_radius_tcp,
					     &thread->connection->src_ipaddr, thread->connection->src_port,
					     &inst->ipaddr, inst->port,
					     inst->interface);

	return 0;
}

static int mod_compare(void const *instance, UNUSED void *thread_instance, UNUSED RADCLIENT *client,
		       void const *one, void const *two)
{
	int rcode;
	proto_radius_tcp_t const *inst = talloc_get_type_abort_const(instance, proto_radius_tcp_t);

	uint8_t const *a = one;
	uint8_t const *b = two;

	/*
	 *	Do a better job of deduping input packet.
	 */
	if (inst->dedup_authenticator) {
		rcode = memcmp(a + 4, b + 4, RADIUS_AUTH_VECTOR_LENGTH);
		if (rcode != 0) return rcode;
	}

	/*
	 *	The tree is ordered by IDs, which are (hopefully)
	 *	pseudo-randomly distributed.
	 */
	rcode = (a[1] < b[1]) - (a[1] > b[1]);
	if (rcode != 0) return rcode;

	/*
	 *	Then ordered by code, which is usally the same.
	 */
	return (a[0] < b[0]) - (a[0] > b[0]);
}


static char const *mod_name(fr_listen_t *li)
{
	proto_radius_tcp_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_radius_tcp_thread_t);

	return thread->name;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_radius_tcp_t	*inst = talloc_get_type_abort(instance, proto_radius_tcp_t);
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
				cf_log_err(cs, "Entry is completely enclosed inside of a previously defined network");
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
			fr_ipaddr_t	*network;

			/*
			 *	Can't add v4 networks to a v6 socket, or vice versa.
			 */
			if (inst->deny[i].af != inst->ipaddr.af) {
				cf_log_err(cs, "Address family in entry %zd - 'deny = %pV' does not match 'ipaddr'",
					   i + 1, fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	Duplicates are bad.
			 */
			network = fr_trie_match(inst->trie,
						&inst->deny[i].addr, inst->deny[i].prefix);
			if (network) {
				cf_log_err(cs, "Cannot add duplicate entry 'deny = %pV'", fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	A "deny" can only be within a previous "allow".
			 */
			network = fr_trie_lookup(inst->trie,
						&inst->deny[i].addr, inst->deny[i].prefix);
			if (!network) {
				cf_log_err(cs, "The network in entry %zd - 'deny = %pV' is not contained "
					   "within a previous 'allow'", i + 1, fr_box_ipaddr(inst->deny[i]));
				return -1;
			}

			/*
			 *	We hack the AF in "deny" rules.  If
			 *	the lookup gets AF_UNSPEC, then we're
			 *	adding a "deny" inside of a "deny".
			 */
			if (network->af != inst->ipaddr.af) {
				cf_log_err(cs, "The network in entry %zd - 'deny = %pV' overlaps with "
					   "another 'deny' rule", i + 1, fr_box_ipaddr(inst->deny[i]));
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

fr_app_io_t proto_radius_tcp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_tcp",
	.config			= tcp_listen_config,
	.inst_size		= sizeof(proto_radius_tcp_t),
	.thread_inst_size	= sizeof(proto_radius_tcp_thread_t),
	.bootstrap		= mod_bootstrap,

	.default_message_size	= 4096,
	.track_duplicates	= true,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.compare		= mod_compare,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name		= mod_name,
};
