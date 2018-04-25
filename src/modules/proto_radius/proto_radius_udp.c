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
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"
typedef struct proto_radius_udp_t {
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
	uint32_t			max_attributes;		//!< Limit maximum decodable attributes.

	fr_stats_t			stats;			//!< statistics for this socket

	uint16_t			port;			//!< Port to listen on.

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				dynamic_clients;	//!< whether we have dynamic clients

	fr_trie_t			*trie;			//!< for parsed networks
	fr_ipaddr_t			*allow;			//!< allowed networks for dynamic clients
	fr_ipaddr_t			*deny;			//!< denied networks for dynamic clients

	fr_io_address_t			*connection;		//!< for connected sockets.

} proto_radius_udp_t;


static const CONF_PARSER networks_config[] = {
	{ FR_CONF_OFFSET("allow", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_radius_udp_t, allow) },
	{ FR_CONF_OFFSET("deny", FR_TYPE_COMBO_IP_PREFIX | FR_TYPE_MULTI, proto_radius_udp_t, deny) },

	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER udp_listen_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, proto_radius_udp_t, ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, proto_radius_udp_t, ipaddr) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, proto_radius_udp_t, interface) },
	{ FR_CONF_OFFSET("port_name", FR_TYPE_STRING, proto_radius_udp_t, port_name) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, proto_radius_udp_t, port) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, proto_radius_udp_t, recv_buff) },

	{ FR_CONF_OFFSET("dynamic_clients", FR_TYPE_BOOL, proto_radius_udp_t, dynamic_clients) } ,
	{ FR_CONF_POINTER("networks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) networks_config },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_radius_udp_t, max_packet_size), .dflt = "4096" } ,
       	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_radius_udp_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_radius_udp_t		*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	fr_io_address_t		*address, **address_p;

	int				flags;
	ssize_t				data_size;
	size_t				packet_len;
	struct timeval			timestamp;
	decode_fail_t			reason;

	fr_time_t			*recv_time_p;

	*leftover = 0;		/* always for UDP */

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_radius.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;
	recv_time_p = *recv_time;

	/*
	 *      Tell udp_recv if we're connected or not.
	 */
	flags = UDP_FLAGS_CONNECTED * (inst->connection != NULL);

	data_size = udp_recv(inst->sockfd, buffer, buffer_len, flags,
			     &address->src_ipaddr, &address->src_port,
			     &address->dst_ipaddr, &address->dst_port,
			     &address->if_index, &timestamp);
	if (data_size < 0) {
		DEBUG2("proto_radius_udp got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	if (!data_size) {
		DEBUG2("proto_radius_udp got no data: ignoring");
		return 0;
	}

	packet_len = data_size;

	if (data_size < 20) {
		DEBUG2("proto_radius_udp got 'too short' packet size %zd", data_size);
		inst->stats.total_malformed_requests++;
		return 0;
	}

	if (packet_len > inst->max_packet_size) {
		DEBUG2("proto_radius_udp got 'too long' packet size %zd > %u", data_size, inst->max_packet_size);
		inst->stats.total_malformed_requests++;
		return 0;
	}

	if ((buffer[0] == 0) || (buffer[0] > FR_MAX_PACKET_CODE)) {
		DEBUG("proto_radius_udp got invalid packet code %d", buffer[0]);
		inst->stats.total_unknown_types++;
		return 0;
	}

	/*
	 *      If it's not a RADIUS packet, ignore it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, inst->max_attributes, false, &reason)) {
		/*
		 *      @todo - check for F5 load balancer packets.  <sigh>
		 */
		DEBUG2("proto_radius_udp got a packet which isn't RADIUS");
		inst->stats.total_malformed_requests++;
		return 0;
	}

	// @todo - maybe convert timestamp?
	*recv_time_p = fr_time();

	/*
	 *	proto_radius sets the priority
	 */

	return packet_len;
}


static ssize_t mod_write(void *instance, void *packet_ctx,
			 UNUSED fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_udp_t		*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	fr_io_track_t		*track = talloc_get_type_abort(packet_ctx, fr_io_track_t);
	fr_io_address_t		*address = track->address;

	int				flags;
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_radius
	 *	can update them, too.. <sigh>
	 */
	inst->stats.total_responses++;

	flags = UDP_FLAGS_CONNECTED * (inst->connection != NULL);

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

			(void) udp_send(inst->sockfd, packet, track->reply_len, flags,
					&address->dst_ipaddr, address->dst_port,
					address->if_index,
					&address->src_ipaddr, address->src_port);
		}

		return buffer_len;
	}

	/*
	 *	We only write RADIUS packets.
	 */
	rad_assert(buffer_len >= 20);

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = udp_send(inst->sockfd, buffer, buffer_len, flags,
			     &address->dst_ipaddr, address->dst_port,
			     address->if_index,
			     &address->src_ipaddr, address->src_port);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	/*
	 *	Root through the reply to determine any
	 *	connection-level negotiation data.
	 */
	if (track->packet[0] == FR_CODE_STATUS_SERVER) {
//		status_check_reply(inst, buffer, buffer_len);
	}

	return data_size;
}


/** Open a UDP listener for RADIUS
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_close(void *instance)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}


static int mod_connection_set(void *instance, fr_io_address_t *connection)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	inst->connection = connection;
	return 0;
}


static void mod_network_get(void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	*ipproto = IPPROTO_UDP;
	*dynamic_clients = inst->dynamic_clients;
	*trie = inst->trie;
}


/** Open a UDP listener for RADIUS
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	int				sockfd = 0;
	uint16_t			port = inst->port;
	CONF_SECTION			*server_cs;
	CONF_ITEM			*ci;

	sockfd = fr_socket_server_udp(&inst->ipaddr, &port, inst->port_name, true);
	if (sockfd < 0) {
		PERROR("Failed opening UDP socket");
	error:
		return -1;
	}

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

	if (fr_socket_bind(sockfd, &inst->ipaddr, &port, inst->interface) < 0) {
		close(sockfd);
		PERROR("Failed binding socket");
		goto error;
	}

	/*
	 *	Connect to the client for child sockets.
	 */
	if (inst->connection) {
		socklen_t salen;
		struct sockaddr_storage src;

		if (fr_ipaddr_to_sockaddr(&inst->connection->src_ipaddr, inst->connection->src_port,
					  &src, &salen) < 0) {
			close(sockfd);
			ERROR("Failed getting IP address");
			goto error;
		}

		if (connect(sockfd, (struct sockaddr *) &src, salen) < 0) {
			close(sockfd);
			ERROR("Failed in connect: %s", fr_syserror(errno));
			goto error;
		}
	}

	inst->sockfd = sockfd;

	ci = cf_parent(inst->cs); /* listen { ... } */
	rad_assert(ci != NULL);
	ci = cf_parent(ci);
	rad_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	// @todo - also print out auth / acct / coa, etc.
	DEBUG("Listening on radius address %s bound to virtual server %s",
	      inst->name, cf_section_name2(server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_radius_udp_t const *inst = talloc_get_type_abort_const(instance, proto_radius_udp_t);

	return inst->sockfd;
}

static int mod_compare(UNUSED void const *instance, void const *one, void const *two)
{
	int rcode;

	uint8_t const *a = one;
	uint8_t const *b = two;

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


static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_radius_udp_t *inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	char		    dst_buf[128];

	/*
	 *	Get our name.
	 */
	if (fr_ipaddr_is_inaddr_any(&inst->ipaddr)) {
		if (inst->ipaddr.af == AF_INET) {
			strlcpy(dst_buf, "*", sizeof(dst_buf));
		} else {
			rad_assert(inst->ipaddr.af == AF_INET6);
			strlcpy(dst_buf, "::", sizeof(dst_buf));
		}
	} else {
		fr_value_box_snprint(dst_buf, sizeof(dst_buf), fr_box_ipaddr(inst->ipaddr), 0);
	}

	if (!inst->connection) {
		inst->name = talloc_typed_asprintf(inst, "proto udp server %s port %u",
						   dst_buf, inst->port);

	} else {
		char src_buf[128];

		fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(inst->connection->src_ipaddr), 0);

		inst->name = talloc_typed_asprintf(inst, "proto udp from client %s port %u to server %s port %u",
						   src_buf, inst->connection->src_port, dst_buf, inst->port);
	}

	return 0;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);
	size_t			i, num;

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

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
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
		MEM(inst->trie = fr_trie_alloc(inst));

		for (i = 0; i < num; i++) {
			fr_ipaddr_t *network;
			char buffer[256];

			/*
			 *	Can't add v4 networks to a v6 socket, or vice versa.
			 */
			if (inst->allow[i].af != inst->ipaddr.af) {
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->allow[i]), 0);
				cf_log_err(cs, "Address family in entry %zd - 'allow = %s' does not match 'ipaddr'", i + 1, buffer);
				return -1;
			}

			/*
			 *	Duplicates are bad.
			 */
			network = fr_trie_match(inst->trie,
						&inst->allow[i].addr, inst->allow[i].prefix);
			if (network) {
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->allow[i]), 0);
				cf_log_err(cs, "Cannot add duplicate entry 'allow = %s'", buffer);
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
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->allow[i]), 0);
				cf_log_err(cs, "Cannot add overlapping entry 'allow = %s'", buffer);
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
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->allow[i]), 0);
				cf_log_err(cs, "Failed adding 'allow = %s' to tracking table.", buffer);
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
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->deny[i]), 0);
				cf_log_err(cs, "Address family in entry %zd - 'deny = %s' does not match 'ipaddr'", i + 1, buffer);
				return -1;
			}

			/*
			 *	Duplicates are bad.
			 */
			network = fr_trie_match(inst->trie,
						&inst->deny[i].addr, inst->deny[i].prefix);
			if (network) {
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->deny[i]), 0);
				cf_log_err(cs, "Cannot add duplicate entry 'deny = %s'", buffer);
				return -1;
			}

			/*
			 *	A "deny" can only be within a previous "allow".
			 */
			network = fr_trie_lookup(inst->trie,
						&inst->deny[i].addr, inst->deny[i].prefix);
			if (!network) {
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->deny[i]), 0);
				cf_log_err(cs, "The network in entry %zd - 'deny = %s' is not contained within a previous 'allow'",
					   i + 1, buffer);
				return -1;
			}

			/*
			 *	We hack the AF in "deny" rules.  If
			 *	the lookup gets AF_UNSPEC, then we're
			 *	adding a "deny" inside of a "deny".
			 */
			if (network->af != inst->ipaddr.af) {
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->deny[i]), 0);
				cf_log_err(cs, "The network in entry %zd - 'deny = %s' is overlaps with another 'deny' rule",
					   i + 1, buffer);
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
				fr_value_box_snprint(buffer, sizeof(buffer), fr_box_ipaddr(inst->deny[i]), 0);
				cf_log_err(cs, "Failed adding 'deny = %s' to tracking table.", buffer);
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

#if 0
static int mod_detach(void *instance)
{
	proto_radius_udp_t	*inst = talloc_get_type_abort(instance, proto_radius_udp_t);

	if (inst->sockfd >= 0) close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}
#endif

static proto_radius_app_io_t proto_radius_app_io_private = {
	.network_get		= mod_network_get,
};

extern fr_app_io_t proto_radius_udp;
fr_app_io_t proto_radius_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.config			= udp_listen_config,
	.inst_size		= sizeof(proto_radius_udp_t),
//	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,
	.track_duplicates	= true,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.close			= mod_close,
	.fd			= mod_fd,
	.compare		= mod_compare,
	.connection_set		= mod_connection_set,

	.private		= &proto_radius_app_io_private,
};
