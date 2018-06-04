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
 * @file proto_control_unix.c
 * @brief Control handler for Unix sockets.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_control.h"

typedef struct {
	char const			*name;			//!< socket name
	CONF_SECTION			*cs;			//!< our configuration

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request
	fr_network_t			*nr;			//!< for fr_network_listen_read();

	char const     			*path;			//!< path to socket name

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.

	fr_stats_t			stats;			//!< statistics for this socket

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.

	fr_io_address_t			*connection;		//!< for connected sockets.

} proto_control_unix_t;

static const CONF_PARSER unix_listen_config[] = {
	{ FR_CONF_OFFSET("path", FR_TYPE_STRING, proto_control_unix_t, path) },
	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, proto_control_unix_t, recv_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_control_unix_t, max_packet_size), .dflt = "4096" } ,

	CONF_PARSER_TERMINATOR
};


static ssize_t mod_read(void *instance, UNUSED void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_control_unix_t		*inst = talloc_get_type_abort(instance, proto_control_unix_t);
	ssize_t				data_size;
	size_t				packet_len = -1;

	fr_time_t			*recv_time_p;

	recv_time_p = *recv_time;

	/*
	 *      Read data into the buffer.
	 */
	data_size = read(inst->sockfd, buffer + *leftover, buffer_len - *leftover);
	if (data_size < 0) {
		DEBUG2("proto_control_unix got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	/*
	 *	Note that we return ERROR for all bad packets, as
	 *	there's no point in reading packets from a UNIX
	 *	connection which isn't sending us properly formatted
	 *	packets.
	 */

	/*
	 *	UNIX read of zero means the socket is dead.
	 */
	if (!data_size) {
		DEBUG2("proto_control_unix - other side closed the socket.");
		return -1;
	}

	// @todo - check authentication, etc. on the socket.
	// we will need a state machine for this..

	/*
	 *	Not enough for one packet.  Tell the caller that we need to read more.
	 */
	if (data_size < 20) {
		*leftover = data_size;
		return 0;
	}

#if 0
	/*
	 *      If it's not a RADIUS packet, ignore it.
	 */
	if (!fr_radius_ok(buffer, &packet_len, inst->max_attributes, false, &reason)) {
		/*
		 *      @todo - check for F5 load balancer packets.  <sigh>
		 */
		DEBUG2("proto_control_unix got a packet which isn't RADIUS");
		inst->stats.total_malformed_requests++;
		return -1;
	}
#endif

	// @todo - maybe convert timestamp?
	*recv_time_p = fr_time();

	/*
	 *	proto_control sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_control_unix - Received %s ID %d length %d %s",
	       fr_packet_codes[buffer[0]], buffer[1],
	       (int) packet_len, inst->name);

	return packet_len;
}


static ssize_t mod_write(void *instance, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_control_unix_t		*inst = talloc_get_type_abort(instance, proto_control_unix_t);
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


/** Close a UNIX listener for RADIUS
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_close(void *instance)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}

static int mod_connection_set(void *instance, fr_io_address_t *connection)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	inst->connection = connection;
	return 0;
}


/** Open a UNIX listener for RADIUS
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	int				sockfd = 0;
	CONF_SECTION			*server_cs;
	CONF_ITEM			*ci;

	rad_assert(!inst->connection);

#if 0
	// @todo - open / create the Unix socket
	sockfd = fr_socket_server_unix(&inst->ipaddr, &port, inst->port_name, true);
#else
	sockfd = -1;
#endif
	if (sockfd < 0) {
		PERROR("Failed opening UNIX socket");
	error:
		return -1;
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

	// @todo - also print out auth / acct / coa, etc.
	DEBUG("Listening on control address %s bound to virtual server %s",
	      inst->name, cf_section_name2(server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_control_unix_t const *inst = talloc_get_type_abort_const(instance, proto_control_unix_t);

	return inst->sockfd;
}

/** Set the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @param[in] fd the FD to set
 */
static void mod_fd_set(void *instance, int fd)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	inst->sockfd = fd;
}


static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);
	char		    dst_buf[128];

	if (!inst->connection) {
		inst->name = talloc_typed_asprintf(inst, "proto unix server %s path %s",
						   dst_buf, inst->path);

	} else {
		inst->name = talloc_typed_asprintf(inst, "proto unix from client ??? to server path %s",
						   inst->path);
	}

	return 0;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_control_unix_t	*inst = talloc_get_type_abort(instance, proto_control_unix_t);

	inst->cs = cs;

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	return 0;
}

static RADCLIENT *mod_client_find(UNUSED void *instance, fr_ipaddr_t const *ipaddr, int ipproto)
{
	// @todo - stream sockets?
	return client_find(NULL, ipaddr, ipproto);
}

#if 0
static int mod_detach(void *instance)
{
	proto_control_unix_t	*inst = talloc_get_type_abort(instance, proto_control_unix_t);

	if (inst->sockfd >= 0) close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}
#endif

extern fr_app_io_t proto_control_unix;
fr_app_io_t proto_control_unix = {
	.magic			= RLM_MODULE_INIT,
	.name			= "control_unix",
	.config			= unix_listen_config,
	.inst_size		= sizeof(proto_control_unix_t),
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
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.client_find		= mod_client_find,
};
