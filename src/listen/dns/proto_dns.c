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
 * @file proto_dns.c
 * @brief DHCPV6 master protocol handler.
 *
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
#define LOG_PREFIX "proto_dns"

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include "proto_dns.h"

extern fr_app_t proto_dns;
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

static const conf_parser_t priority_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("query", FR_TYPE_VOID, 0, proto_dns_t, priorities[FR_DNS_QUERY]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	CONF_PARSER_TERMINATOR
};


static conf_parser_t const limit_config[] = {
	{ FR_CONF_OFFSET("idle_timeout", proto_dns_t, io.idle_timeout), .dflt = "30.0" } ,

	{ FR_CONF_OFFSET("max_connections", proto_dns_t, io.max_connections), .dflt = "1024" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", proto_dns_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", proto_dns_t, num_messages) } ,
	{ FR_CONF_POINTER("priority", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	CONF_PARSER_TERMINATOR
};

/** How to parse a DNS listen section
 *
 */
static conf_parser_t const proto_dns_config[] = {
	{ FR_CONF_OFFSET_FLAGS("type", CONF_FLAG_NOT_EMPTY, proto_dns_t, allowed_types), .func = type_parse },
	{ FR_CONF_OFFSET_TYPE_FLAGS("transport", FR_TYPE_VOID, 0, proto_dns_t, io.submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("limit", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) limit_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_dns;

extern fr_dict_autoload_t proto_dns_dict[];
fr_dict_autoload_t proto_dns_dict[] = {
	{ .out = &dict_dns, .proto = "dns" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_dns_dict_attr[];
fr_dict_attr_autoload_t proto_dns_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dns},
	{ NULL }
};

/** Translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_dns).
 * @param[out] out	Where to write a module_instance_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
		      CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	proto_dns_t		*inst = talloc_get_type_abort(parent, proto_dns_t);
	fr_dict_enum_value_t		*dv;
	CONF_PAIR		*cp;
	char const		*value;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);

	dv = fr_dict_enum_by_name(attr_packet_type, value, -1);
	if (!dv || (dv->value->vb_uint32 >= FR_DNS_CODE_MAX)) {
		cf_log_err(ci, "Unknown DNS packet type '%s'", value);
		return -1;
	}

	inst->allowed[dv->value->vb_uint32] = true;
	*((char const **) out) = value;

	return 0;
}

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	proto_dns_t		*inst = talloc_get_type_abort(parent, proto_dns_t);
	module_instance_t	*mi;

	if (unlikely(virtual_server_listen_transport_parse(ctx, out, parent, ci, rule) < 0)) {
		return -1;
	}

	mi = talloc_get_type_abort(*(void **)out, module_instance_t);
	inst->io.app_io = (fr_app_io_t const *)mi->exported;
	inst->io.app_io_instance = mi->data;
	inst->io.app_io_conf = mi->conf;

	return 0;
}

/** Decode the packet
 *
 */
static int mod_decode(UNUSED void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const	*address = track->address;
	fr_client_t const		*client;
	fr_dns_packet_t	const	*packet = (fr_dns_packet_t const *) data;
	fr_dns_ctx_t		packet_ctx;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_dns;

	RHEXDUMP3(data, data_len, "proto_dns decode packet");

	client = address->radclient;

	/*
	 *	@todo -
	 */
	request->packet->code = packet->opcode;
	request->packet->id = fr_nbo_to_uint16(data);
	request->reply->id = request->packet->id;

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	packet_ctx.tmp_ctx = talloc(request, uint8_t);
	packet_ctx.packet = request->packet->data;
	packet_ctx.packet_len = data_len;
	packet_ctx.lb = fr_dns_labels_get(request->packet->data, data_len, true);
	fr_assert(packet_ctx.lb != NULL);

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_dns_ok().
	 */
	if (fr_dns_decode(request->request_ctx, &request->request_pairs,
			  request->packet->data, request->packet->data_len, &packet_ctx) < 0) {
		talloc_free(packet_ctx.tmp_ctx);
		RPEDEBUG("Failed decoding packet");
		return -1;
	}
	talloc_free(packet_ctx.tmp_ctx);

	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(fr_client_t *, client);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		RPEDEBUG("Failed decoding 'Net.*' packet");
		return -1;
	}

	REQUEST_VERIFY(request);

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
//	fr_io_track_t		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_dns_packet_t		*reply = (fr_dns_packet_t *) buffer;
	fr_dns_packet_t		*original = (fr_dns_packet_t *) request->packet->data;
	ssize_t			data_len;
	fr_dns_ctx_t	packet_ctx;

	/*
	 *	Process layer NAK, never respond, or "Do not respond".
	 */
	if ((buffer_len == 1) ||
	    (request->reply->code == FR_DNS_DO_NOT_RESPOND) ||
	    (request->reply->code >= FR_DNS_CODE_MAX)) {
//		track->do_not_respond = true;
		return 1;
	}

	if (buffer_len < DNS_HDR_LEN) {
		REDEBUG("Output buffer is too small to hold a DNS packet.");
		return -1;
	}

	packet_ctx.tmp_ctx = talloc(request, uint8_t);
	packet_ctx.packet = buffer;
	packet_ctx.packet_len = buffer_len;

	packet_ctx.lb = fr_dns_labels_get(buffer, buffer_len, false);
	fr_assert(packet_ctx.lb != NULL);

	data_len = fr_dns_encode(&FR_DBUFF_TMP(buffer, buffer_len), &request->reply_pairs, &packet_ctx);
	talloc_free(packet_ctx.tmp_ctx);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding DHCPv6 reply");
		return -1;
	}

	reply->id = original->id;
	request->reply->data_len = data_len;

	RHEXDUMP3(buffer, data_len, "proto_dns encode packet");

	fr_packet_net_from_pairs(request->reply, &request->reply_pairs);

	return data_len;
}

static int mod_priority_set(void const *instance, uint8_t const *buffer, size_t buflen)
{
	int opcode;
	fr_dns_packet_t const	*packet = (fr_dns_packet_t const *) buffer;
	proto_dns_t const	*inst = talloc_get_type_abort_const(instance, proto_dns_t);

	if (buflen < DNS_HDR_LEN) return -1;

	opcode = packet->opcode;

	/*
	 *	Disallowed packet
	 */
	if (!inst->priorities[opcode]) return 0;

	if (!inst->allowed[opcode]) return -1;

	/*
	 *	@todo - if we cared, we could also return -1 for "this
	 *	is a bad packet".  But that's really only for
	 *	mod_inject, as we assume that app_io->read() always
	 *	returns good packets.
	 */

	/*
	 *	Return the configured priority.
	 */
	return inst->priorities[opcode];

}

/** Open listen sockets/connect to external event source
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] sc	to add our file descriptor to.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_open(void *instance, fr_schedule_t *sc, UNUSED CONF_SECTION *conf)
{
	proto_dns_t 	*inst = talloc_get_type_abort(instance, proto_dns_t);

	inst->io.app = &proto_dns;
	inst->io.app_instance = instance;

	return fr_master_io_listen(&inst->io, sc,
				   inst->max_packet_size, inst->num_messages);
}

/** Instantiate the application
 *
 * Instantiate I/O and type submodules.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_dns_t		*inst = talloc_get_type_abort(mctx->mi->data, proto_dns_t);

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_section_find_parent(mctx->mi->conf, "server", CF_IDENT_ANY);

	fr_assert(dict_dns != NULL);
	fr_assert(attr_packet_type != NULL);

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

	/*
	 *	These timers are usually protocol specific.
	 */
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, <=, fr_time_delta_from_sec(600));

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_dns;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.mi = mctx->mi;

	/*
	 *	These configuration items are not printed by default,
	 *	because normal people shouldn't be touching them.
	 */
	if (!inst->max_packet_size && inst->io.app_io) inst->max_packet_size = inst->io.app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	/*
	 *	Instantiate the transport module before calling the
	 *	common instantiation function.
	 */
	if (module_instantiate(inst->io.submodule) < 0) return -1;

	/*
	 *	Instantiate the master io submodule
	 */
	return fr_master_app_io.common.instantiate(MODULE_INST_CTX(inst->io.mi));
}

static int mod_load(void)
{
	if (fr_dns_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}

	return 0;
}

static void mod_unload(void)
{
	fr_dns_global_free();
}

fr_app_t proto_dns = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "dns",
		.config			= proto_dns_config,
		.inst_size		= sizeof(proto_dns_t),

		.onload			= mod_load,
		.unload			= mod_unload,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_dns,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.priority		= mod_priority_set
};
