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
 * @file proto_dhcpv4.c
 * @brief DHCPV4 master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#define LOG_PREFIX "proto_dhcpv4"

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include "proto_dhcpv4.h"

extern fr_app_t proto_dhcpv4;
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static const CONF_PARSER priority_config[] = {
	{ FR_CONF_OFFSET("Discover", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_DISCOVER]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Request", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_REQUEST]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Decline", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_DECLINE]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Release", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_RELEASE]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Inform", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_INFORM]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Lease-Query", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_LEASE_QUERY]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },
	{ FR_CONF_OFFSET("Bulk-Lease-Query", FR_TYPE_VOID, proto_dhcpv4_t, priorities[FR_DHCP_BULK_LEASE_QUERY]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const limit_config[] = {
	{ FR_CONF_OFFSET("cleanup_delay", FR_TYPE_TIME_DELTA, proto_dhcpv4_t, io.cleanup_delay), .dflt = "5.0" } ,
	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIME_DELTA, proto_dhcpv4_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("nak_lifetime", FR_TYPE_TIME_DELTA, proto_dhcpv4_t, io.nak_lifetime), .dflt = "30.0" } ,

	{ FR_CONF_OFFSET("max_connections", FR_TYPE_UINT32, proto_dhcpv4_t, io.max_connections), .dflt = "1024" } ,
	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, proto_dhcpv4_t, io.max_clients), .dflt = "256" } ,
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, proto_dhcpv4_t, io.max_pending_packets), .dflt = "256" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_dhcpv4_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_dhcpv4_t, num_messages) } ,
	{ FR_CONF_POINTER("priority", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	CONF_PARSER_TERMINATOR
};

/** How to parse a DHCPV4 listen section
 *
 */
static CONF_PARSER const proto_dhcpv4_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_dhcpv4_t,
			  allowed_types), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_dhcpv4_t, io.submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },

	CONF_PARSER_TERMINATOR
};


static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t proto_dhcpv4_dict[];
fr_dict_autoload_t proto_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_dhcpv4_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv4_dict_attr[] = {
	{ .out = &attr_message_type, .name = "Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4},
	{ NULL }
};

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_dhcpv4).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
		      CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	proto_dhcpv4_t		*inst = talloc_get_type_abort(parent, proto_dhcpv4_t);
	fr_dict_enum_value_t		*dv;
	CONF_PAIR		*cp;
	char const		*value;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);

	dv = fr_dict_enum_by_name(attr_packet_type, value, -1);
	if (!dv || (dv->value->vb_uint32 >= FR_DHCP_CODE_MAX)) {
		cf_log_err(ci, "Unknown DHCPv4 packet type '%s'", value);
		return -1;
	}

	inst->allowed[dv->value->vb_uint32] = true;
	*((char const **) out) = value;

	return 0;
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_dhcpv4).
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
	proto_dhcpv4_t		*inst;
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*transport_cs;
	dl_module_inst_t	*dl_mod_inst;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_dhcpv4"));
	fr_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_dhcpv4_t);
	inst->io.transport = name;

	if (dl_module_instance(ctx, &dl_mod_inst, parent_inst,
			       DL_MODULE_TYPE_SUBMODULE, name, dl_module_inst_name_from_conf(transport_cs)) < 0) return -1;
	if (dl_module_conf_parse(dl_mod_inst, transport_cs) < 0) {
		talloc_free(dl_mod_inst);
		return -1;
	}
	*((dl_module_inst_t **)out) = dl_mod_inst;

	return 0;
}

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	proto_dhcpv4_t const *inst = talloc_get_type_abort_const(instance, proto_dhcpv4_t);
	fr_io_track_t const *track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const *address = track->address;
	RADCLIENT const *client;
	fr_radius_packet_t *packet = request->packet;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_dhcpv4;

	RHEXDUMP3(data, data_len, "proto_dhcpv4 decode packet");

	client = address->radclient;

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->id = fr_nbo_to_uint32(data + 4);
	request->reply->id = request->packet->id;
	memcpy(request->packet->vector, data + 4, sizeof(request->packet->vector));

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_dhcpv4_ok().
	 */
	if (fr_dhcpv4_decode(request->request_ctx, &request->request_pairs,
			     packet->data, packet->data_len, &packet->code) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(RADCLIENT *, client);

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
	proto_dhcpv4_t const *inst = talloc_get_type_abort_const(instance, proto_dhcpv4_t);
	fr_io_track_t	*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const *address = track->address;
	dhcp_packet_t *reply = (dhcp_packet_t *) buffer;
	dhcp_packet_t *original = (dhcp_packet_t *) request->packet->data;
	ssize_t data_len;
	RADCLIENT const *client;

	/*
	 *	process layer NAK, or "Do not respond".  We also never
	 *	send replies to a release.
	 */
	if ((buffer_len == 1) ||
	    (request->reply->code == FR_DHCP_DO_NOT_RESPOND) ||
	    (request->reply->code == 0) || (request->reply->code >= FR_DHCP_CODE_MAX) ||
	    (request->packet->code == FR_DHCP_RELEASE)) {
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

	if (buffer_len < MIN_PACKET_SIZE) {
		REDEBUG("Output buffer is too small to hold a DHCPv4 packet.");
		return -1;
	}

	memset(buffer, 0, buffer_len);

	/*
	 *	Initialize the output packet from the input packet.
	 */
#define COPY(_x) reply->_x = original->_x
#define MEMCPY(_x) memcpy(&reply->_x, &original->_x, sizeof(reply->_x))

	COPY(htype);
	COPY(hlen);
	COPY(xid);
	MEMCPY(chaddr);

	/*
	 *	If the app_io encodes the packet, then we don't need
	 *	to do that.
	 */
	if (inst->io.app_io->encode) {
		data_len = inst->io.app_io->encode(inst->io.app_io_instance, request, buffer, buffer_len);
		if (data_len > 0) return data_len;
	}

	data_len = fr_dhcpv4_encode(buffer, buffer_len, original, request->reply->code,
				    ntohl(original->xid), &request->reply_pairs);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding DHCPV4 reply");
		return -1;
	}

	RHEXDUMP3(buffer, data_len, "proto_dhcpv4 encode packet");

	request->reply->data_len = data_len;
	return data_len;
}

static int mod_priority_set(void const *instance, uint8_t const *buffer, size_t buflen)
{
	proto_dhcpv4_t const *inst = talloc_get_type_abort_const(instance, proto_dhcpv4_t);
	uint8_t const *code;

	if (buflen < MIN_PACKET_SIZE) return -1;

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) buffer, buflen, attr_message_type);
	fr_assert(code != NULL);
	fr_assert(code[1] == 1);
	fr_assert(code[2] != 0);
	fr_assert(code[2] < FR_DHCP_CODE_MAX);

	/*
	 *	Disallowed packet
	 */
	if (!inst->priorities[code[2]]) return 0;

	if (!inst->allowed[code[2]]) return -1;

	/*
	 *	@todo - if we cared, we could also return -1 for "this
	 *	is a bad packet".  But that's really only for
	 *	mod_inject, as we assume that app_io->read() always
	 *	returns good packets.
	 */

	/*
	 *	Return the configured priority.
	 */
	return inst->priorities[code[2]];
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
	proto_dhcpv4_t 	*inst = talloc_get_type_abort(instance, proto_dhcpv4_t);

	inst->io.app = &proto_dhcpv4;
	inst->io.app_instance = instance;

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
	proto_dhcpv4_t		*inst = talloc_get_type_abort(mctx->inst->data, proto_dhcpv4_t);

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
	proto_dhcpv4_t 		*inst = talloc_get_type_abort(mctx->inst->data, proto_dhcpv4_t);

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(mctx->inst->conf));

	fr_assert(dict_dhcpv4 != NULL);
	fr_assert(attr_message_type != NULL);

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
	inst->io.app = &proto_dhcpv4;
	inst->io.app_instance = inst;

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

static int mod_load(void)
{
	if (fr_dhcpv4_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}

	return 0;
}

static void mod_unload(void)
{
	fr_dhcpv4_global_free();
}

fr_app_t proto_dhcpv4 = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "dhcpv4",
		.config			= proto_dhcpv4_config,
		.inst_size		= sizeof(proto_dhcpv4_t),

		.onload			= mod_load,
		.unload			= mod_unload,

		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_dhcpv4,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.priority		= mod_priority_set
};
