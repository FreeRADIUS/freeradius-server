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
 * @file proto_dhcpv6.c
 * @brief DHCPV6 master protocol handler.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
#define LOG_PREFIX "proto_dhcpv6 - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>
#include "proto_dhcpv6.h"

extern fr_app_t proto_dhcpv6;
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static const CONF_PARSER priority_config[] = {
	{ FR_CONF_OFFSET("Solicit", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_SOLICIT]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Request", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_REQUEST]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Renew", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_RENEW]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Rebind", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_REBIND]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Release", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_RELEASE]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Decline", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_DECLINE]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Information-Request", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_INFORMATION_REQUEST]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Relay-Forward", FR_TYPE_UINT32, proto_dhcpv6_t, priorities[FR_DHCPV6_RELAY_FORWARD]),
	  .func = cf_table_parse_uint32, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const limit_config[] = {
	{ FR_CONF_OFFSET("cleanup_delay", FR_TYPE_TIME_DELTA, proto_dhcpv6_t, io.cleanup_delay), .dflt = "5.0" } ,
	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIME_DELTA, proto_dhcpv6_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("nak_lifetime", FR_TYPE_TIME_DELTA, proto_dhcpv6_t, io.nak_lifetime), .dflt = "30.0" } ,

	{ FR_CONF_OFFSET("max_connections", FR_TYPE_UINT32, proto_dhcpv6_t, io.max_connections), .dflt = "1024" } ,
	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, proto_dhcpv6_t, io.max_clients), .dflt = "256" } ,
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, proto_dhcpv6_t, io.max_pending_packets), .dflt = "256" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_dhcpv6_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_dhcpv6_t, num_messages) } ,
	{ FR_CONF_POINTER("priority", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	CONF_PARSER_TERMINATOR
};

/** How to parse a DHCPV6 listen section
 *
 */
static CONF_PARSER const proto_dhcpv6_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_dhcpv6_t,
			  type_submodule), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_dhcpv6_t, io.submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_dhcpv6;

extern fr_dict_autoload_t proto_dhcpv6_dict[];
fr_dict_autoload_t proto_dhcpv6_dict[] = {
	{ .out = &dict_dhcpv6, .proto = "dhcpv6" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_client_id;

extern fr_dict_attr_autoload_t proto_dhcpv6_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv6_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6},
	{ .out = &attr_client_id, .name = "Client-Id", .type = FR_TYPE_STRUCT, .dict = &dict_dhcpv6},
	{ NULL }
};

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_dhcpv6).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent,
		      CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	static char const *type_lib_table[FR_DHCPV6_MAX_CODE] = {
		[FR_DHCPV6_SOLICIT]	= "process",
		[FR_DHCPV6_REQUEST]	= "process",
		[FR_DHCPV6_RENEW]	= "process",
		[FR_DHCPV6_REBIND]	= "process",
		[FR_DHCPV6_RELEASE]	= "process",
		[FR_DHCPV6_DECLINE]	= "process",
		[FR_DHCPV6_INFORMATION_REQUEST]	= "process",
		[FR_DHCPV6_RELAY_FORWARD] = "process"
	};
	proto_dhcpv6_t		*inst = talloc_get_type_abort(parent, proto_dhcpv6_t);

	return fr_app_process_type_parse(ctx, out, ci, attr_packet_type, "proto_dhcpv6",
					 type_lib_table, NUM_ELEMENTS(type_lib_table),
					 inst->type_submodule_by_code, NUM_ELEMENTS(inst->type_submodule_by_code));
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_dhcpv6).
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
	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	dl_module_inst_t	*parent_inst;
	proto_dhcpv6_t	*inst;
	CONF_SECTION	*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_dhcpv6"));
	fr_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_dhcpv6_t);
	inst->io.transport = name;

	return dl_module_instance(ctx, out, transport_cs, parent_inst, name, DL_MODULE_TYPE_SUBMODULE);
}

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	proto_dhcpv6_t const	*inst = talloc_get_type_abort_const(instance, proto_dhcpv6_t);
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const	*address = track->address;
	RADCLIENT const		*client;
	fr_radius_packet_t	*packet = request->packet;
	fr_dcursor_t		cursor;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_dhcpv6;

	RHEXDUMP3(data, data_len, "proto_dhcpv6 decode packet");

	client = address->radclient;

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->code = data[0];
	request->packet->id = (data[1] << 16) | (data[2] << 8) | data[3];
	request->reply->id = request->packet->id;

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_dhcpv6_ok().
	 */
	fr_dcursor_init(&cursor, &request->request_pairs);
	if (fr_dhcpv6_decode(request->request_ctx, packet->data, packet->data_len, &cursor) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	/*
	 *	Set the rest of the fields.
	 */
	memcpy(&request->client, &client, sizeof(client)); /* const issues */

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	REQUEST_VERIFY(request);

	if (!inst->io.app_io->decode) return 0;

	/*
	 *	Let the app_io do anything it needs to do.
	 */
	return inst->io.app_io->decode(inst->io.app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	proto_dhcpv6_t const	*inst = talloc_get_type_abort_const(instance, proto_dhcpv6_t);
	fr_io_track_t		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const	*address = track->address;
	fr_dhcpv6_packet_t	*reply = (fr_dhcpv6_packet_t *) buffer;
	fr_dhcpv6_packet_t	*original = (fr_dhcpv6_packet_t *) request->packet->data;
	ssize_t			data_len;
	RADCLIENT const		*client;

	/*
	 *	Process layer NAK, never respond, or "Do not respond".
	 */
	if ((buffer_len == 1) ||
	    (request->reply->code == FR_DHCPV6_DO_NOT_RESPOND) ||
	    (request->reply->code == 0) || (request->reply->code >= FR_DHCPV6_MAX_CODE)) {
		track->do_not_respond = true;
		return 1;
	}

	client = address->radclient;
	fr_assert(client);

	/*
	 *	Dynamic client stuff
	 */
	if (client->dynamic && !client->active) {
		RADCLIENT *new_client;

		fr_assert(buffer_len >= sizeof(client));

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
			buffer[0] = true;
			return 1;
		}

		memcpy(buffer, &new_client, sizeof(new_client));
		return sizeof(new_client);
	}

	if (buffer_len < 4) {
		REDEBUG("Output buffer is too small to hold a DHCPv6 packet.");
		return -1;
	}

	memset(buffer, 0, buffer_len);
	memcpy(&reply->transaction_id, &original->transaction_id, sizeof(reply->transaction_id));

	/*
	 *	If the app_io encodes the packet, then we don't need
	 *	to do that.
	 */
	if (inst->io.app_io->encode) {
		data_len = inst->io.app_io->encode(inst->io.app_io_instance, request, buffer, buffer_len);
		if (data_len > 0) return data_len;
	}

	data_len = fr_dhcpv6_encode(&FR_DBUFF_TMP(buffer, buffer_len),
				    request->packet->data, request->packet->data_len,
				    request->reply->code, &request->reply_pairs);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding DHCPv6 reply");
		return -1;
	}

	/*
	 *	ACK the client ID.
	 */
	if (!fr_dhcpv6_option_find(buffer + 4, buffer + data_len, attr_client_id->attr)) {
		uint8_t const *client_id;

		client_id = fr_dhcpv6_option_find(request->packet->data + 4, request->packet->data + request->packet->data_len, attr_client_id->attr);
		if (client_id) {
			size_t len = (client_id[2] << 8) | client_id[3];
			if ((data_len + 4 + len) <= buffer_len) {
				memcpy(buffer + data_len, client_id, 4 + len);
				data_len += 4 + len;
			}
		}
	}

	RHEXDUMP3(buffer, data_len, "proto_dhcpv6 encode packet");

	request->reply->data_len = data_len;
	return data_len;
}

static void mod_entry_point_set(void const *instance, request_t *request)
{
	proto_dhcpv6_t const	*inst = talloc_get_type_abort_const(instance, proto_dhcpv6_t);
	dl_module_inst_t	*type_submodule;
	fr_io_track_t		*track = request->async->packet_ctx;

	fr_assert(request->packet->code != 0);
	fr_assert(request->packet->code < FR_DHCPV6_MAX_CODE);

	request->server_cs = inst->io.server_cs;

	/*
	 *	'track' can be NULL when there's no network listener.
	 */
	if (inst->io.app_io && (track->dynamic == request->async->recv_time)) {
		fr_app_worker_t const	*app_process;

		app_process = (fr_app_worker_t const *) inst->io.dynamic_submodule->module->common;

		request->async->process = app_process->entry_point;
		track->dynamic = 0;
		return;
	}

	type_submodule = inst->type_submodule_by_code[request->packet->code];
	if (!type_submodule) {
		REDEBUG("The server is not configured to accept 'type = %s'", fr_dhcpv6_packet_types[request->packet->code]);
		return;
	}

	request->async->process = ((fr_app_worker_t const *)type_submodule->module->common)->entry_point;
	request->async->process_inst = type_submodule->data;
}

static int mod_priority_set(void const *instance, uint8_t const *buffer, UNUSED size_t buflen)
{
	proto_dhcpv6_t const *inst = talloc_get_type_abort_const(instance, proto_dhcpv6_t);

	fr_assert(buffer[0] > 0);
	fr_assert(buffer[0] < FR_DHCPV6_MAX_CODE);

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
 * @param[in] conf	Listen section parsed to give us isntance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_open(void *instance, fr_schedule_t *sc, UNUSED CONF_SECTION *conf)
{
	proto_dhcpv6_t 	*inst = talloc_get_type_abort(instance, proto_dhcpv6_t);

	inst->io.app = &proto_dhcpv6;
	inst->io.app_instance = instance;

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
	proto_dhcpv6_t		*inst = talloc_get_type_abort(instance, proto_dhcpv6_t);

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
	proto_dhcpv6_t 		*inst = talloc_get_type_abort(instance, proto_dhcpv6_t);

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(conf));

	fr_assert(dict_dhcpv6 != NULL);
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

	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("cleanup_delay", inst->io.cleanup_delay, <=, fr_time_delta_from_sec(30));
	FR_TIME_DELTA_BOUND_CHECK("cleanup_delay", inst->io.cleanup_delay, >, fr_time_delta_from_sec(0));

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_dhcpv6;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.dl_inst = dl_module_instance_by_data(inst);
	fr_assert(inst != NULL);

	/*
	 *	Bootstrap the master IO handler.
	 */
	return fr_master_app_io.bootstrap(&inst->io, conf);
}

static int mod_load(void)
{
	if (fr_dhcpv6_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}

	return 0;
}

static void mod_unload(void)
{
	fr_dhcpv6_global_free();
}

fr_app_t proto_dhcpv6 = {
	.magic			= RLM_MODULE_INIT,
	.name			= "dhcpv6",
	.config			= proto_dhcpv6_config,
	.inst_size		= sizeof(proto_dhcpv6_t),
	.dict			= &dict_dhcpv6,

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
