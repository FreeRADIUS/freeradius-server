/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_radius_udp.c
 * @brief RADIUS UDP transport
 *
 * @copyright 2017  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_radius.h"

typedef struct rlm_radius_udp_t {
	fr_ipaddr_t	dst_ipaddr;		//!< IP of the home server	
	fr_ipaddr_t	src_ipaddr;		//!< IP we open our socket on
	uint16_t	dst_port;		//!< port of the home server
	char const	*secret;		//!< shared secret

	uint32_t	recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t	send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t	max_packet_size;	//!< maximum packet size

	bool		recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool		send_buff_is_set;	//!< Whether we were provided with a send_buf

	bool		dst_ipaddr_is_set;     	//!< ipaddr config item is set.
	bool		dst_ipv4addr_is_set;	//!< ipv4addr config item is set.
	bool		dst_ipv6addr_is_set;	//!< ipv6addr config item is set.

	bool		src_ipaddr_is_set;     	//!< src_ipaddr config item is set.
	bool		src_ipv4addr_is_set;	//!< src_ipv4addr config item is set.
	bool		src_ipv6addr_is_set;	//!< src_ipv6addr config item is set.

} rlm_radius_udp_t;

typedef struct udp_io_ctx_t {
	rlm_radius_udp_t const	*inst;		//!< our module instance
	uint32_t		max_packet_size; //!< our max packet size. may be different from the parent...
	int			fd;		//!< file descriptor

	// @todo - track status-server, open, signaling, etc.

	// @todo - track outstanding IDs, one per packet code...

	uint8_t			*buffer;	//!< receive buffer
	size_t			buflen;		//!< receive buffer length
} udp_io_ctx_t;


static const CONF_PARSER module_config[] = {
	{ FR_CONF_IS_SET_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, dst_ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, dst_ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_radius_udp_t, dst_port) },

	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, rlm_radius_udp_t, recv_buff) },
	{ FR_CONF_IS_SET_OFFSET("send_buff", FR_TYPE_UINT32, rlm_radius_udp_t, send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, rlm_radius_udp_t, max_packet_size),
	  .dflt = "4096" },

	{ FR_CONF_IS_SET_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("src_ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_IS_SET_OFFSET("src_ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, src_ipaddr) },

	CONF_PARSER_TERMINATOR
};


/** Get a printable name for the socket
 *
 */
static char const *mod_get_name(TALLOC_CTX *ctx, void *io_ctx)
{
	udp_io_ctx_t *io = talloc_get_type_abort(io_ctx, udp_io_ctx_t);
	char src_buf[FR_IPADDR_STRLEN], dst_buf[FR_IPADDR_STRLEN];

	fr_inet_ntop(dst_buf, sizeof(dst_buf), &io->inst->dst_ipaddr);

	// @todo - make sure to get the local port number we're bound to

	if (fr_ipaddr_is_inaddr_any(&io->inst->src_ipaddr)) {
		return talloc_asprintf(ctx, "home server %s port %u", dst_buf, io->inst->dst_port);				      
	}

	fr_inet_ntop(src_buf, sizeof(src_buf), &io->inst->src_ipaddr);
	return talloc_asprintf(ctx, "from %s to home server %s port %u", src_buf, dst_buf, io->inst->dst_port);
}


/** Shutdown/close a file descriptor
 *
 */
static void mod_close(int fd, void *io_ctx)
{
	udp_io_ctx_t *io = talloc_get_type_abort(io_ctx, udp_io_ctx_t);

	if (shutdown(fd, SHUT_RDWR) < 0) DEBUG3("Shutdown on socket (%i) failed: %s", fd, fr_syserror(errno));
	if (close(fd) < 0) DEBUG3("Closing socket (%i) failed: %s", fd, fr_syserror(errno));

	io->fd = -1;
}

/** Do more setup once the connection has been opened
 *
 */
static fr_connection_state_t mod_open(UNUSED int fd, UNUSED fr_event_list_t *el, UNUSED void *io_ctx)
{
//	udp_io_ctx_t_t *io = talloc_get_type_abort(io_ctx, udp_io_ctx_t);

	// @todo - create the initial Status-Server for negotiation and send that

	return FR_CONNECTION_STATE_CONNECTED;
}


/** Initialize the connection.
 *
 */
static fr_connection_state_t mod_init(int *fd_out, void *io_ctx, void const *uctx)
{
	int fd;
	udp_io_ctx_t *io = talloc_get_type_abort(io_ctx, udp_io_ctx_t);
	rlm_radius_udp_t const *inst = talloc_get_type_abort(uctx, rlm_radius_udp_t);

	io->inst = inst;

	io->max_packet_size = inst->max_packet_size;
	io->buflen = io->max_packet_size;
	io->buffer = talloc_array(io, uint8_t, io->buflen);

	if (!io->buffer) {
		return FR_CONNECTION_STATE_FAILED;
	}

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_udp(&inst->src_ipaddr, &inst->dst_ipaddr, inst->dst_port, true);
	if (fd < 0) {
		DEBUG("Failed opening RADIUS client UDP socket: %s", fr_strerror());
		return FR_CONNECTION_STATE_FAILED;
	}

	// @todo - make sure to get the local port number we're bound to

	// @todo - set recv_buff and send_buff socket options

	io->fd = fd;

	// @todo - initialize the tracking memory, etc.

	*fd_out = fd;

	return FR_CONNECTION_STATE_CONNECTING;
}


/** Bootstrap the module
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf    our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(UNUSED void *instance, UNUSED CONF_SECTION *conf)
{
//	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	return 0;
}


/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	/*
	 *	Ensure that we have a destination address.
	 */
	if (!inst->dst_ipaddr_is_set && !inst->dst_ipv4addr_is_set && !inst->dst_ipv6addr_is_set) {
		cf_log_err(conf, "A value must be given for 'ipaddr'");
		return -1;
	}

	/*
	 *	If src_ipaddr isn't set, make sure it's INADDR_ANY, of
	 *	the same address family as dst_ipaddr.
	 */
	if (!inst->src_ipaddr_is_set && !inst->src_ipv4addr_is_set && !inst->src_ipv6addr_is_set) {
		memset(&inst->src_ipaddr, 0, sizeof(inst->src_ipaddr));

		inst->src_ipaddr.af = inst->dst_ipaddr.af;

		if (inst->src_ipaddr.af == AF_INET) {
			inst->src_ipaddr.prefix = 32;
		} else {
			inst->src_ipaddr.prefix = 128;
		}
	}

	if (inst->src_ipaddr.af != inst->dst_ipaddr.af) {
		cf_log_err(conf, "The 'ipaddr' and 'src_ipaddr' configuration items must be both of the same address family");
		return -1;
	}

	if (!inst->dst_port) {
		cf_log_err(conf, "A value must be given for 'port'");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	return 0;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern fr_radius_client_io_t rlm_radius_udp;
fr_radius_client_io_t rlm_radius_udp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_udp",
	.inst_size	= sizeof(rlm_radius_udp_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.init		= mod_init,
	.open		= mod_open,
	.close		= mod_close,
	.get_name	= mod_get_name,
#if 0
	.write		= mod_write,
	.flush		= mod_flush,
	.remove		= mod_remove,
	.read		= mod_read,
#endif
};
