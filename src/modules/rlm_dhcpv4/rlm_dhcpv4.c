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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/util/udp_queue.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#include <freeradius-devel/unlang/module.h>

#include <ctype.h>

static fr_dict_t const *dict_dhcpv4;
static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_dhcpv4_dict[];
fr_dict_autoload_t rlm_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
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
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
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
	fr_udp_queue_config_t	config;		//!< UDP queue config

	uint32_t		max_packet_size;	//!< Maximum packet size.
} rlm_dhcpv4_t;

typedef struct {
	fr_udp_queue_t		*uq;			//!< udp queue handler
	uint8_t			*buffer;		//!< for encoding packets
	uint32_t		buffer_size;		//!< Maximum packet size.
	uint32_t		xid;			//!< XID
} rlm_dhcpv4_thread_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_IPV4_ADDR, rlm_dhcpv4_t, config.ipaddr), },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, rlm_dhcpv4_t, config.ipaddr) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_dhcpv4_t, config.port), .dflt = "68" },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, rlm_dhcpv4_t, config.interface) },

	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, rlm_dhcpv4_t, config.send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, rlm_dhcpv4_t, max_packet_size), .dflt = "576" },
	{ FR_CONF_OFFSET("max_queued_packets", FR_TYPE_UINT32, rlm_dhcpv4_t, config.max_queued_packets), .dflt = "65536" },

	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, rlm_dhcpv4_t, config.max_queued_time), .dflt = "0" },

	CONF_PARSER_TERMINATOR
};

/** Bootstrap the module
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] mctx	data for this module
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_dhcpv4_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_dhcpv4_t);
	CONF_SECTION	*conf = mctx->inst->conf;

	/*
	 *	Ensure that we have a destination address.
	 */
	if (inst->config.ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "A value must be given for 'ipaddr'");
		return -1;
	}

	if (inst->config.ipaddr.af != AF_INET) {
		cf_log_err(conf, "DHCPv4 can only use IPv4 addresses in 'ipaddr'");
		return -1;
	}

	if (!inst->config.port) {
		cf_log_err(conf, "A value must be given for 'port'");
		return -1;
	}

	/*
	 *	Clamp max_packet_size
	 */
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, DEFAULT_PACKET_SIZE);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, MAX_PACKET_SIZE);

	return 0;
}

typedef struct {
	request_t		*request;
	bool			sent;
} rlm_dhcpv4_delay_t;

static void dhcpv4_queue_resume(bool sent, void *rctx)
{
	rlm_dhcpv4_delay_t *d = talloc_get_type_abort(rctx, rlm_dhcpv4_delay_t);

	d->sent = sent;

	unlang_interpret_mark_runnable(d->request);
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_dhcpv4_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_dhcpv4_t);
	rlm_dhcpv4_thread_t 	*t = talloc_get_type_abort(mctx->thread, rlm_dhcpv4_thread_t);
	CONF_SECTION		*conf = mctx->inst->conf;

	t->buffer = talloc_array(t, uint8_t, inst->max_packet_size);
	if (!t->buffer) {
		cf_log_err(conf, "Failed allocating buffer");
		return -1;
	}

	t->buffer_size = inst->max_packet_size;

	t->uq = fr_udp_queue_alloc(t, &inst->config, mctx->el, dhcpv4_queue_resume);
	if (!t->uq) {
		cf_log_err(conf, "Failed allocating outbound udp queue - %s", fr_strerror());
		return -1;
	}

	return 0;
}

static unlang_action_t dhcpv4_resume(rlm_rcode_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	rlm_dhcpv4_delay_t *d = talloc_get_type_abort(mctx->rctx, rlm_dhcpv4_delay_t);

	if (!d->sent) {
		talloc_free(d);
		RETURN_MODULE_FAIL;
	}

	talloc_free(d);
	RETURN_MODULE_OK;
}


/** Send packets outbound.
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_dhcpv4_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_dhcpv4_thread_t);
	ssize_t			data_len;
	dhcp_packet_t		*original = (dhcp_packet_t *) request->packet->data;
	dhcp_packet_t		*packet;

	uint32_t		xid;
	fr_pair_t		*vp;
	int			code, port, rcode;

	rlm_dhcpv4_delay_t	*d;

	/*
	 *	We can only send relayed packets, which have a gateway IP
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_gateway_ip_address);
	if (!vp) {
		REDEBUG("Relayed packets MUST have a Gateway-IP-Address attribute");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Get the transaction ID.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_transaction_id);
	if (vp) {
		xid = vp->vp_uint32;

	} else if (original) {
		xid = ntohl(original->xid);

	} else {
		xid = t->xid++;
	}

	/*
	 *	Set the packet type.
	 *
	 *	@todo - make sure it's a client type.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_packet_type);
	if (vp) {
		code = vp->vp_uint32;

	} else if ((vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_message_type)) != NULL) {
		code = vp->vp_uint8;

	} else {
		code = request->packet->code;
	}

	/*
	 *	Set the destination port, defaulting to 67
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_packet_dst_port);
	if (vp) {
		port = vp->vp_uint16;
	} else {
		port = 67;	/* DHCPv4 server port */
	}

	/*
	 *	Get the destination address / port, and unicast it there.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_packet_dst_ip_address);
	if (!vp) {
		RDEBUG("No Packet-Dst-IP-Address, cannot relay packet");
		RETURN_MODULE_NOOP;
	}

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

	d = talloc_zero(request, rlm_dhcpv4_delay_t);
	if (!d) RETURN_MODULE_FAIL;

	*d = (rlm_dhcpv4_delay_t) {
		.request = request,
		.sent = false,
	};

	rcode = fr_udp_queue_write(d, t->uq, t->buffer, data_len, &vp->vp_ip, port, d);
	if (rcode > 0) {
		talloc_free(d);
		RETURN_MODULE_OK;
	}
	if (rcode < 0) {
		talloc_free(d);
		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield(request, dhcpv4_resume, NULL, d);
}

extern module_rlm_t rlm_dhcpv4;
module_rlm_t rlm_dhcpv4 = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "dhcpv4",
		.inst_size		= sizeof(rlm_dhcpv4_t),
		.bootstrap		= mod_bootstrap,

		.config			= module_config,

		.thread_inst_size	= sizeof(rlm_dhcpv4_thread_t),
		.thread_inst_type	= "rlm_dhcpv4_thread_t",
		.thread_instantiate	= mod_thread_instantiate
	},
        .method_names = (module_method_name_t[]){
                { .name1 = CF_IDENT_ANY,	.name2 = CF_IDENT_ANY,	.method = mod_process },
                MODULE_NAME_TERMINATOR
        },
};
