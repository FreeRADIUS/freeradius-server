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
 * @file proto_load.c
 * @brief Load master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/radius/radius.h>

#include "proto_load.h"

extern fr_app_t proto_load;
static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a Load listen section
 *
 */
static CONF_PARSER const proto_load_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, proto_load_t,
			  type), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_load_t, io.submodule),
	  .func = transport_parse, .dflt = "step" },

	/*
	 *	Add this as a synonym so normal humans can understand it.
	 */
	{ FR_CONF_OFFSET("max_entry_size", FR_TYPE_UINT32, proto_load_t, max_packet_size) } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_load_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_load_t, num_messages) } ,

	{ FR_CONF_OFFSET("priority", FR_TYPE_UINT32, proto_load_t, priority) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t proto_load_dict[];
fr_dict_autoload_t proto_load_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },

	{ NULL }
};

static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_original_timestamp;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_protocol;

extern fr_dict_attr_autoload_t proto_load_dict_attr[];
fr_dict_attr_autoload_t proto_load_dict_attr[] = {
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_original_timestamp, .name = "Packet-Original-Timestamp", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_protocol, .name = "Protocol", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ NULL }
};

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_load).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	proto_load_t		*inst = talloc_get_type_abort(parent, proto_load_t);
	fr_dict_enum_value_t const	*type_enum;
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	char const		*value = cf_pair_value(cp);

	*((char const **) out) = value;

	inst->dict = virtual_server_dict_by_child_ci(ci);
	if (!inst->dict) {
		cf_log_err(ci, "Please define 'namespace' in this virtual server");
		return -1;
	}

	inst->attr_packet_type = fr_dict_attr_by_name(NULL, fr_dict_root(inst->dict), "Packet-Type");
	if (!inst->attr_packet_type) {
		cf_log_err(ci, "Failed to find 'Packet-Type' attribute");
		return -1;
	}

	if (!value) {
		cf_log_err(ci, "No value given for 'type'");
		return -1;
	}

	type_enum = fr_dict_enum_by_name(inst->attr_packet_type, value, -1);
	if (!type_enum) {
		cf_log_err(ci, "Invalid type \"%s\"", value);
		return -1;
	}

	inst->code = type_enum->value->vb_uint32;
	return 0;
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_load).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*name = cf_pair_value(cf_item_to_pair(ci));
	dl_module_inst_t	*parent_inst;
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*transport_cs;
	dl_module_inst_t	*dl_mod_inst;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_load"));
	fr_assert(parent_inst);

	if (dl_module_instance(ctx, &dl_mod_inst, parent_inst,
			       DL_MODULE_TYPE_SUBMODULE, name, dl_module_inst_name_from_conf(transport_cs)) < 0) return -1;
	if (dl_module_conf_parse(dl_mod_inst, transport_cs) < 0) {
		talloc_free(dl_mod_inst);
		return -1;
	}
	*((dl_module_inst_t **)out) = dl_mod_inst;

	return 0;
}

/** Decode the packet, and set the request->process function
 *
 */
static int mod_decode(void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	proto_load_t const	*inst = talloc_get_type_abort_const(instance, proto_load_t);

	request->dict = inst->dict;
	request->packet->code = inst->code;

	/*
	 *	Set default addresses
	 */
	request->packet->socket.fd = -1;
	request->packet->socket.inet.src_ipaddr.af = AF_INET;
	request->packet->socket.inet.src_ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
	request->packet->socket.inet.dst_ipaddr = request->packet->socket.inet.src_ipaddr;

	request->reply->socket.inet.src_ipaddr = request->packet->socket.inet.src_ipaddr;
	request->reply->socket.inet.dst_ipaddr = request->packet->socket.inet.src_ipaddr;

	/*
	 *	The app_io is responsible for decoding all of the data.
	 */
	return inst->io.app_io->decode(inst->io.app_io_instance, request, data, data_len);
}

/*
 *	We don't need to encode any of the replies.  We just go "yeah, it's fine".
 */
static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	if (buffer_len < 1) return -1;

	*buffer = request->reply->code;
	return 1;
}

/** Open listen sockets/connect to external event source
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] sc	to add our file descriptor to.
 * @param[in] conf	Listen section parsed to give us isntance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_open(void *instance, fr_schedule_t *sc, UNUSED CONF_SECTION *conf)
{
	proto_load_t 	*inst = talloc_get_type_abort(instance, proto_load_t);

	inst->io.app = &proto_load;
	inst->io.app_instance = instance;

	/*
	 *	io.app_io should already be set
	 */
	return fr_master_io_listen(inst, &inst->io, sc,
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
	proto_load_t		*inst = talloc_get_type_abort(mctx->inst->data, proto_load_t);

	fr_assert(inst->io.submodule);

	/*
	 *	These configuration items are not printed by default,
	 *	because normal people shouldn't be touching them.
	 */
	if (!inst->max_packet_size && inst->io.app_io) inst->max_packet_size = inst->io.app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	/*
	 *	Instantiate the master io submodule
	 */
	return fr_master_app_io.common.instantiate(MODULE_INST_CTX(inst->io.dl_inst));
}

/** Bootstrap the application
 *
 * Bootstrap I/O and type submodules.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_load_t 		*inst = talloc_get_type_abort(mctx->inst->data, proto_load_t);
	CONF_SECTION		*conf = mctx->inst->conf;

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(conf));

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) {
		cf_log_err(conf, "The load generator MUST have a 'transport = ...' set");
		return -1;
	}

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_load;
	inst->io.app_instance = inst;

	/*
	 *	The listener is inside of a virtual server.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));
	inst->cs = conf;
	inst->self = &proto_load;


	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.dl_inst = dl_module_instance_by_data(inst);
	fr_assert(inst != NULL);

	/*
	 *	Bootstrap the master IO handler.
	 */
	return fr_master_app_io.common.bootstrap(MODULE_INST_CTX(inst->io.dl_inst));
}


fr_app_t proto_load = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "load",
		.config			= proto_load_config,
		.inst_size		= sizeof(proto_load_t),

		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate
	},
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
};
