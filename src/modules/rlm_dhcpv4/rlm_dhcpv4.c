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
 * @file src/modules/rlm_dhcpv4/rlm_dhcpv4.c
 * @brief DHCP client and relay
 *
 * @copyright 2012-2018 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#include <ctype.h>

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t rlm_dhcpv4_dict[];
fr_dict_autoload_t rlm_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_transaction_id;
static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_gateway_ip_address;

extern fr_dict_attr_autoload_t rlm_dhcpv4_dict_attr[];
fr_dict_attr_autoload_t rlm_dhcpv4_dict_attr[] = {
	{ .out = &attr_transaction_id, .name = "Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_gateway_ip_address, .name = "Gateway-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_message_type, .name = "Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ NULL }
};


/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	char const		*name;
	char const		*xlat_name;

	int			fd;			//!< only relay, no proxying for now

	fr_ipaddr_t		ipaddr;			//!< socket IP address
	uint16_t		port;			//!< socket port

	char const		*interface;		//!< Interface to bind to.

	uint32_t		recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t		send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t		max_packet_size;	//!< Maximum packet size.

	bool			recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool			send_buff_is_set;	//!< Whether we were provided with a send_buf
} rlm_dhcpv4_t;

typedef struct {
	uint8_t			*buffer;		//!< for encoding packets
	uint32_t		buffer_size;		//!< Maximum packet size.
} rlm_dhcpv4_thread_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_IPV4_ADDR, rlm_dhcpv4_t, ipaddr), },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, rlm_dhcpv4_t, ipaddr) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_dhcpv4_t, port), .dflt = "68" },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, rlm_dhcpv4_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, rlm_dhcpv4_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, rlm_dhcpv4_t, send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, rlm_dhcpv4_t, max_packet_size), .dflt = "576" },

	CONF_PARSER_TERMINATOR
};

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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_dhcpv4_t	*inst = talloc_get_type_abort(instance, rlm_dhcpv4_t);

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);
	inst->name = inst->xlat_name;

	/*
	 *	Ensure that we have a destination address.
	 */
	if (inst->ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "A value must be given for 'ipaddr'");
		return -1;
	}

	if (inst->ipaddr.af != AF_INET) {
		cf_log_err(conf, "DHCPv4 can only use IPv4 addresses in 'ipaddr'");
		return -1;
	}

	if (!inst->port) {
		cf_log_err(conf, "A value must be given for 'port'");
		return -1;
	}

	/*
	 *	Clamp max_packet_size first before checking recv_buff and send_buff
	 */
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, DEFAULT_PACKET_SIZE);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, MAX_PACKET_SIZE);

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, (1 << 30));
	}

	return 0;
}

/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_dhcpv4_t	*inst = talloc_get_type_abort(instance, rlm_dhcpv4_t);

	/*
	 *	Open the outgoing socket.
	 */
	inst->fd = fr_socket_server_udp(&inst->ipaddr, &inst->port, NULL, true);
	if (inst->fd < 0) {
		cf_log_err(conf, "Failed opening socket: %s", fr_strerror());
		return -1;
	}

	/*
	 *	Bind to the interface, if required.
	 */
	if (inst->interface) {
		if (fr_socket_bind(inst->fd, &inst->ipaddr, &inst->port, inst->interface) < 0) {
			cf_log_err(conf, "Failed binding to interface %s: %s", inst->interface, fr_strerror());
			return -1;
		}
	}

	fr_nonblock(inst->fd);

#ifdef SO_RCVBUF
	if (inst->recv_buff_is_set) {
		int opt;

		opt = inst->recv_buff;
		if (setsockopt(inst->fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			cf_log_warn(conf, "Failed setting 'SO_RCVBUF': %s", fr_syserror(errno));
		}
	}
#endif

#ifdef SO_SNDBUF
	if (inst->send_buff_is_set) {
		int opt;

		opt = inst->send_buff;
		if (setsockopt(inst->fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int)) < 0) {
			cf_log_warn(conf, "Failed setting 'SO_SNDBUF', write performance may be sub-optimal: %s",
				    fr_syserror(errno));
		}
	}
#endif

	return 0;
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(CONF_SECTION const *cs, void *instance, UNUSED fr_event_list_t *el, void *thread)
{
	rlm_dhcpv4_t *inst = talloc_get_type_abort(instance, rlm_dhcpv4_t);
	rlm_dhcpv4_thread_t *t = talloc_get_type_abort(thread, rlm_dhcpv4_thread_t);

	t->buffer = talloc_array(t, uint8_t, inst->max_packet_size);
	if (!t->buffer) {
		cf_log_err(cs, "Failed allocating buffer");
		return -1;
	}

	t->buffer_size = inst->max_packet_size;

	return 0;
}

/** Send packets outbound.
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_dhcpv4_t		*inst = talloc_get_type_abort(mctx->instance, rlm_dhcpv4_t);
	rlm_dhcpv4_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_dhcpv4_thread_t);
	ssize_t			data_len;
	dhcp_packet_t		*original = (dhcp_packet_t *) request->packet->data;
	dhcp_packet_t		*packet;
	struct sockaddr_storage	sockaddr;
	socklen_t		socklen;
	uint32_t		xid;
	fr_pair_t		*vp;
	int			code, port;

	/*
	 *	Discard any incoming packets, as we don't care about
	 *	them.
	 *
	 *	@todo - maybe set up a thread listener to do this, if
	 *	we care.
	 */
	while (read(inst->fd, t->buffer, t->buffer_size) > 0) {
		/* do nothing with the data, we don't care */
	}

	/*
	 *	We can only send relayed packets, which have a gateway IP
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_gateway_ip_address, 0);
	if (!vp) {
		REDEBUG("Relayed packets MUST have a Gateway-IP-Address attribute");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Get the transaction ID.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_transaction_id, 0);
	if (vp) {
		xid = vp->vp_uint32;

	} else if (original) {
		xid = ntohl(original->xid);

	} else {
		xid = fr_rand(); /* shouldn't happen, as we're relaying packets, not creating them (yet) */
	}

	/*
	 *	Set the packet type.
	 *
	 *	@todo - make sure it's a client type.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_packet_type, 0);
	if (vp) {
		code = vp->vp_uint32;

	} else if ((vp = fr_pair_find_by_da(&request->request_pairs, attr_message_type, 0)) != NULL) {
		code = vp->vp_uint8;

	} else {
		code = request->packet->code;
	}

	/*
	 *	Set the destination port, defaulting to 67
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_packet_dst_port, 0);
	if (vp) {
		port = vp->vp_uint16;
	} else {
		port = 67;	/* DHCPv4 server port */
	}

	/*
	 *	Get the destination address / port, and unicast it there.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_packet_dst_ip_address, 0);
	if (!vp) {
		RDEBUG("No Packet-Dst-IP-Address, cannot relay packet");
		RETURN_MODULE_NOOP;
	}

	fr_ipaddr_to_sockaddr(&sockaddr, &socklen, &vp->vp_ip, port);

	/*
	 *	Encode the packet using the original information.
	 */
	data_len = fr_dhcpv4_encode(t->buffer, t->buffer_size, original, code, xid, &request->request_pairs);
	if (data_len <= 0) {
		RPEDEBUG("Failed encoding DHCPV4 request");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Enforce some other RFC requirements.
	 */
	packet = (dhcp_packet_t *) t->buffer;
	if (packet->opcode == 1) {
		if (original) {
			if (original->hops < 255) packet->hops = original->hops + 1;
		} else {
			if (packet->hops < 255) packet->hops++;
		}

	} /* else sending a server message?  OK boomer. */

	FR_PROTO_HEX_DUMP(t->buffer, data_len, "DHCPv4");

	/*
	 *	Send the packet, via "fire and forget".
	 */
	if (sendto(inst->fd, t->buffer, data_len, 0, (struct sockaddr *) &sockaddr, socklen) < 0) {
		REDEBUG("Failed sending packet to %pV: %s", &vp->data, fr_syserror(errno));
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
}

extern module_t rlm_dhcpv4;
module_t rlm_dhcpv4 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcpv4",
	.inst_size	= sizeof(rlm_dhcpv4_t),
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,

	.config			= module_config,

	.thread_inst_size = sizeof(rlm_dhcpv4_thread_t),
	.thread_inst_type = "rlm_dhcpv4_thread_t",
	.thread_instantiate = mod_thread_instantiate,

	.methods = {
		[MOD_AUTHORIZE]		= mod_process,
		[MOD_POST_AUTH]		= mod_process,
	},
        .method_names = (module_method_names_t[]){
                { .name1 = CF_IDENT_ANY,	.name2 = CF_IDENT_ANY,	.method = mod_process },
                MODULE_NAME_TERMINATOR
        },
};
