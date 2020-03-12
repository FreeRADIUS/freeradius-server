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
 * @file proto_radius.c
 * @brief RADIUS master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include "proto_radius.h"

extern fr_app_t proto_radius;

static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static CONF_PARSER const limit_config[] = {
	{ FR_CONF_OFFSET("cleanup_delay", FR_TYPE_TIME_DELTA, proto_radius_t, io.cleanup_delay), .dflt = "5.0" } ,
	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIME_DELTA, proto_radius_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("nak_lifetime", FR_TYPE_TIME_DELTA, proto_radius_t, io.nak_lifetime), .dflt = "30.0" } ,

	{ FR_CONF_OFFSET("max_connections", FR_TYPE_UINT32, proto_radius_t, io.max_connections), .dflt = "1024" } ,
	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, proto_radius_t, io.max_clients), .dflt = "256" } ,
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, proto_radius_t, io.max_pending_packets), .dflt = "256" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_radius_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_radius_t, num_messages) } ,

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER priority_config[] = {
	{ FR_CONF_OFFSET("Access-Request", FR_TYPE_UINT32, proto_radius_t, priorities[FR_CODE_ACCESS_REQUEST]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "high" },
	{ FR_CONF_OFFSET("Accounting-Request", FR_TYPE_UINT32, proto_radius_t, priorities[FR_CODE_ACCOUNTING_REQUEST]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },
	{ FR_CONF_OFFSET("CoA-Request", FR_TYPE_UINT32, proto_radius_t, priorities[FR_CODE_COA_REQUEST]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Disconnect-Request", FR_TYPE_UINT32, proto_radius_t, priorities[FR_CODE_DISCONNECT_REQUEST]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },
	{ FR_CONF_OFFSET("Status-Server", FR_TYPE_UINT32, proto_radius_t, priorities[FR_CODE_STATUS_SERVER]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "now" },

	CONF_PARSER_TERMINATOR
};

/** How to parse a RADIUS listen section
 *
 */
static CONF_PARSER const proto_radius_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_radius_t,
			  type_submodule), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_radius_t, io.submodule),
	  .func = transport_parse },

	/*
	 *	Check whether or not the *trailing* bits of a
	 *	Tunnel-Password are zero, as they should be.
	 */
	{ FR_CONF_OFFSET("tunnel_password_zeros", FR_TYPE_BOOL, proto_radius_t, tunnel_password_zeros) } ,

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	{ FR_CONF_POINTER("priority", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t proto_radius_dict[];
fr_dict_autoload_t proto_radius_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t proto_radius_dict_attr[];
fr_dict_attr_autoload_t proto_radius_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius},
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius},
	{ NULL }
};

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * If we found a Packet-Type = Access-Request CONF_PAIR for example, here's we'd load
 * the proto_radius_auth module.
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	static char const *type_lib_table[FR_RADIUS_MAX_PACKET_CODE] = {
		[FR_CODE_ACCESS_REQUEST]	= "auth",
		[FR_CODE_ACCOUNTING_REQUEST]	= "acct",
		[FR_CODE_COA_REQUEST]		= "coa",
		[FR_CODE_DISCONNECT_REQUEST]	= "coa",
		[FR_CODE_STATUS_SERVER]		= "status",
	};

	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*server = cf_item_to_section(cf_parent(listen_cs));
	CONF_SECTION		*process_app_cs;
	proto_radius_t		*inst;
	dl_module_inst_t		*parent_inst;
	char const		*name = NULL;
	fr_dict_enum_t const	*type_enum;
	uint32_t		code;

	rad_assert(listen_cs && (strcmp(cf_section_name1(listen_cs), "listen") == 0));

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_name(attr_packet_type, type_str, -1);
	if (!type_enum) {
		size_t i;

		for (i = 0; i < (NUM_ELEMENTS(type_lib_table)); i++) {
			name = type_lib_table[i];
			if (name && (strcmp(name, type_str) == 0)) {
				type_enum = fr_dict_dict_enum_by_value(dict_radius, attr_packet_type, fr_box_uint32(i));
				break;
			}
		}

		if (!type_enum) {
			cf_log_err(ci, "Invalid type \"%s\"", type_str);
			return -1;
		}
	}

	cf_data_add(ci, type_enum, NULL, false);

	code = type_enum->value->vb_uint32;
	if (code >= FR_RADIUS_MAX_PACKET_CODE) {
	invalid_type:
		cf_log_err(ci, "Unsupported 'type = %s'", type_str);
		return -1;
	}

	if (!fr_request_packets[code]) {
		cf_log_err(ci, "Cannot listen for 'type = %s'.  The packet MUST be a request.", type_str);
		return -1;
	}

	/*
	 *	Setting 'type = foo' means you MUST have at least a
	 *	'recv foo' section.
	 */
	if (!cf_section_find(server, "recv", type_enum->name)) {
		cf_log_err(ci, "Failed finding 'recv %s {...} section of virtual server %s",
			   type_enum->name, cf_section_name2(server));
		return -1;
	}

	name = type_lib_table[code];
	if (!name) goto invalid_type;

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_radius"));
	rad_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_radius_t);
	inst->code_allowed[code] = true;

	/*
	 *	Hacks for CoA, which also means Disconnect.  And
	 *	they're both processed by the same handler.
	 */
	if (code == FR_CODE_COA_REQUEST) {
		inst->code_allowed[FR_CODE_DISCONNECT_REQUEST] = true;
	}

	process_app_cs = cf_section_find(listen_cs, type_enum->name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!process_app_cs) {
		MEM(process_app_cs = cf_section_alloc(listen_cs, listen_cs, type_enum->name, NULL));
	}

	/*
	 *	Parent dl_module_inst_t added in virtual_servers.c (listen_parse)
	 */
	return dl_module_instance(ctx, out, process_app_cs, parent_inst, name, DL_MODULE_TYPE_SUBMODULE);
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	dl_module_inst_t	*parent_inst;
	proto_radius_t	*inst;
	CONF_SECTION	*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_radius"));
	rad_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_radius_t);
	inst->io.transport = name;

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) {
		transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);
		cf_section_add(listen_cs, transport_cs);
		inst->io.app_io_conf = transport_cs;
	}

	return dl_module_instance(ctx, out, transport_cs, parent_inst, name, DL_MODULE_TYPE_SUBMODULE);
}

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	proto_radius_t const	*inst = talloc_get_type_abort_const(instance, proto_radius_t);
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t		*address = track->address;
	RADCLIENT const		*client;

	rad_assert(data[0] < FR_RADIUS_MAX_PACKET_CODE);

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_radius;

	client = address->radclient;

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->code = data[0];
	request->packet->id = data[1];
	request->reply->id = data[1];
	memcpy(request->packet->vector, data + 4, sizeof(request->packet->vector));

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_radius_ok().
	 */
	if (fr_radius_decode(request->packet, request->packet->data, request->packet->data_len,
			     NULL, client->secret, talloc_array_length(client->secret) - 1,
			     &request->packet->vps) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	/*
	 *	Set the rest of the fields.
	 */
	memcpy(&request->client, &client, sizeof(client)); /* const issues */

	request->packet->if_index = address->if_index;
	request->packet->src_ipaddr = address->src_ipaddr;
	request->packet->src_port = address->src_port;
	request->packet->dst_ipaddr = address->dst_ipaddr;
	request->packet->dst_port = address->dst_port;

	request->reply->if_index = address->if_index;
	request->reply->src_ipaddr = address->dst_ipaddr;
	request->reply->src_port = address->dst_port;
	request->reply->dst_ipaddr = address->src_ipaddr;
	request->reply->dst_port = address->src_port;

	request->config = main_config;
	REQUEST_VERIFY(request);

	/*
	 *	If we're defining a dynamic client, this packet is
	 *	fake.  We don't have a secret, so we mash all of the
	 *	encrypted attributes to sane (i.e. non-hurtful)
	 *	values.
	 */
	if (!client->active) {
		fr_cursor_t cursor;
		VALUE_PAIR *vp;

		rad_assert(client->dynamic);

		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp != NULL;
		     vp = fr_cursor_next(&cursor)) {
			if (vp->da->flags.subtype != FLAG_ENCRYPT_NONE) {
				switch (vp->da->type) {
				default:
					break;

				case FR_TYPE_UINT32:
					vp->vp_uint32 = 0;
					break;

				case FR_TYPE_IPV4_ADDR:
					vp->vp_ipv4addr = INADDR_ANY;
					break;

				case FR_TYPE_OCTETS:
					fr_pair_value_memcpy(vp, (uint8_t const *) "", 1, true);
					break;

				case FR_TYPE_STRING:
					fr_pair_value_strcpy(vp, "");
					break;
				}
			}
		}
	}

	if (RDEBUG_ENABLED) {
		RDEBUG("Received %s ID %i from %pV:%i to %pV:%i length %zu via socket %s",
		       fr_packet_codes[request->packet->code],
		       request->packet->id,
		       fr_box_ipaddr(request->packet->src_ipaddr),
		       request->packet->src_port,
		       fr_box_ipaddr(request->packet->dst_ipaddr),
		       request->packet->dst_port,
		       request->packet->data_len,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
	}

	if (!inst->io.app_io->decode) return 0;

	/*
	 *	Let the app_io do anything it needs to do.
	 */
	return inst->io.app_io->decode(inst->io.app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	proto_radius_t const	*inst = talloc_get_type_abort_const(instance, proto_radius_t);
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t		*address = track->address;
	ssize_t			data_len;
	RADCLIENT const		*client;

	/*
	 *	The packet timed out.  Tell the network side that the packet is dead.
	 */
	if (buffer_len == 1) {
		*buffer = true;
		return 1;
	}

	/*
	 *	"Do not respond"
	 */
	if ((request->reply->code == FR_CODE_DO_NOT_RESPOND) ||
	    (request->reply->code == 0) || (request->reply->code >= FR_RADIUS_MAX_PACKET_CODE)) {
		*buffer = false;
		return 1;
	}

	client = address->radclient;
	rad_assert(client);

	/*
	 *	Dynamic client stuff
	 */
	if (client->dynamic && !client->active) {
		RADCLIENT *new_client;

		rad_assert(buffer_len >= sizeof(client));

		/*
		 *	We don't accept the new client, so don't do
		 *	anything.
		 */
		if (request->reply->code != FR_CODE_ACCESS_ACCEPT) {
			*buffer = true;
			return 1;
		}

		/*
		 *	Allocate the client.  If that fails, send back a NAK.
		 *
		 *	@todo - deal with NUMA zones?  Or just deal with this
		 *	client being in different memory.
		 *
		 *	Maybe we should create a CONF_SECTION from the client,
		 *	and pass *that* back to mod_write(), which can then
		 *	parse it to create the actual client....
		 */
		new_client = client_afrom_request(NULL, request);
		if (!new_client) {
			PERROR("Failed creating new client");
			*buffer = true;
			return 1;
		}

		memcpy(buffer, &new_client, sizeof(new_client));
		return sizeof(new_client);
	}

	/*
	 *	If the app_io encodes the packet, then we don't need
	 *	to do that.
	 */
	if (inst->io.app_io->encode) {
		data_len = inst->io.app_io->encode(inst->io.app_io_instance, request, buffer, buffer_len);
		if (data_len > 0) return data_len;
	}

#ifdef WITH_UDPFROMTO
	/*
	 *	Overwrite the src ip address on the outbound packet
	 *	with the one specified by the client.  This is useful
	 *	to work around broken DSR implementations and other
	 *	routing issues.
	 */
	if (client->src_ipaddr.af != AF_UNSPEC) {
		request->reply->src_ipaddr = client->src_ipaddr;
	}
#endif

	data_len = fr_radius_encode(buffer, buffer_len, request->packet->data,
				    client->secret, talloc_array_length(client->secret) - 1,
				    request->reply->code, request->reply->id, request->reply->vps);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding RADIUS reply");
		return -1;
	}

	if (fr_radius_sign(buffer, request->packet->data,
			   (uint8_t const *) client->secret, talloc_array_length(client->secret) - 1) < 0) {
		RPEDEBUG("Failed signing RADIUS reply");
		return -1;
	}

	if (RDEBUG_ENABLED) {
		RDEBUG("Sending %s ID %i from %pV:%i to %pV:%i length %zu via socket %s",
		       fr_packet_codes[request->reply->code],
		       request->reply->id,
		       fr_box_ipaddr(request->reply->src_ipaddr),
		       request->reply->src_port,
		       fr_box_ipaddr(request->reply->dst_ipaddr),
		       request->reply->dst_port,
		       data_len,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
	}

	return data_len;
}

static void mod_entry_point_set(void const *instance, REQUEST *request)
{
	proto_radius_t const	*inst = talloc_get_type_abort_const(instance, proto_radius_t);
	dl_module_inst_t	*type_submodule;
	fr_io_track_t		*track = request->async->packet_ctx;

	rad_assert(request->packet->code != 0);
	rad_assert(request->packet->code <= FR_RADIUS_MAX_PACKET_CODE);

	request->server_cs = inst->io.server_cs;

	/*
	 *	'track' can be NULL when there's no network listener.
	 */
	if (inst->io.app_io && (track->dynamic == request->async->recv_time)) {
		fr_app_worker_t const	*app_process;

		app_process = (fr_app_worker_t const *) inst->io.dynamic_submodule->module->common;

		request->async->process = app_process->entry_point;
		request->async->process_inst = inst->io.dynamic_submodule;
		track->dynamic = 0;
		return;
	}

	type_submodule = inst->type_submodule_by_code[request->packet->code];
	if (!type_submodule) {
		REDEBUG("The server is not configured to accept 'type = %s'", fr_packet_codes[request->packet->code]);
		return;
	}

	request->async->process = ((fr_app_worker_t const *)type_submodule->module->common)->entry_point;
	request->async->process_inst = type_submodule->data;
}


static int mod_priority_set(void const *instance, uint8_t const *buffer, UNUSED size_t buflen)
{
	proto_radius_t const *inst = talloc_get_type_abort_const(instance, proto_radius_t);

	rad_assert(buffer[0] > 0);
	rad_assert(buffer[0] < FR_RADIUS_MAX_PACKET_CODE);

	/*
	 *	Disallowed packet
	 */
	if (!inst->priorities[buffer[0]]) return 0;

	if (!inst->type_submodule_by_code[buffer[0]]) return -1;

	/*
	 *	@todo - if we cared, we could also return -1 for "this
	 *	is a bad packet".  But that's really only for
	 *	mod_inject, as we assume that app_io->read() always
	 *	returns good packets.
	 */

	/*
	 *	Return the configured priority.
	 */
	return inst->priorities[buffer[0]];
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
	proto_radius_t 	*inst = talloc_get_type_abort(instance, proto_radius_t);

	inst->io.app = &proto_radius;
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
 * @param[in] instance	Ctx data for this application.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	proto_radius_t		*inst = talloc_get_type_abort(instance, proto_radius_t);

	/*
	 *	Instantiate the process modules
	 */
	if (fr_app_process_instantiate(inst->io.server_cs, inst->type_submodule, inst->type_submodule_by_code,
				       NUM_ELEMENTS(inst->type_submodule_by_code),
				       conf) < 0) {
		return -1;
	}

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

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
	return fr_master_app_io.instantiate(&inst->io, conf);
}


/** Bootstrap the application
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	proto_radius_t 		*inst = talloc_get_type_abort(instance, proto_radius_t);

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(conf));

	/*
	 *	Bootstrap the app_process modules.
	 */
	if (fr_app_process_bootstrap(inst->io.server_cs, inst->type_submodule, conf) < 0) return -1;

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

	/*
	 *	These timers are usually protocol specific.
	 */
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("cleanup_delay", inst->io.cleanup_delay, <=, fr_time_delta_from_sec(30));

	/*
	 *	No Access-Request packets, then no cleanup delay.
	 */
	if (!inst->code_allowed[FR_CODE_ACCESS_REQUEST]) {
		inst->io.cleanup_delay = 0;
	}

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_radius;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.dl_inst = dl_module_instance_by_data(inst);
	rad_assert(inst != NULL);

	/*
	 *	Bootstrap the master IO handler.
	 */
	return fr_master_app_io.bootstrap(&inst->io, conf);
}

static int mod_load(void)
{
	if (fr_radius_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_radius_free();
}

fr_app_t proto_radius = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius",
	.config			= proto_radius_config,
	.inst_size		= sizeof(proto_radius_t),
	.dict			= &dict_radius,

	.onload			= mod_load,
	.unload			= mod_unload,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.entry_point_set	= mod_entry_point_set,
	.priority		= mod_priority_set
};
