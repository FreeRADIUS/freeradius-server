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
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/unlang.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

extern fr_app_t proto_radius;
static int type_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a RADIUS listen section
 *
 */
static CONF_PARSER const proto_radius_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_radius_t,
			  type_submodule), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_radius_t, io_submodule),
	  .func = transport_parse },

	/*
	 *	Security
	 */
	{ FR_CONF_OFFSET("tunnel_password_zeros", FR_TYPE_BOOL, proto_radius_t, tunnel_password_zeros) } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_radius_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_radius_t, num_messages) } ,
	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, proto_radius_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) } ,

	CONF_PARSER_TERMINATOR
};

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	static char const *type_lib_table[] = {
		[FR_CODE_ACCESS_REQUEST]	= "auth",
		[FR_CODE_ACCOUNTING_REQUEST]	= "acct",
		[FR_CODE_COA_REQUEST]		= "coa",
		[FR_CODE_DISCONNECT_REQUEST]	= "coa",
		[FR_CODE_STATUS_SERVER]		= "status",
		[FR_CODE_MAX] 			= NULL
	};

	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*server = cf_item_to_section(cf_parent(listen_cs));
	proto_radius_t		*inst;
	dl_instance_t		*parent_inst;
	char const		*name = NULL;
	fr_dict_attr_t const	*da;
	fr_dict_enum_t const	*type_enum;
	uint32_t		code;

	rad_assert(listen_cs && (strcmp(cf_section_name1(listen_cs), "listen") == 0));

	da = fr_dict_attr_by_name(NULL, "Packet-Type");
	if (!da) {
		ERROR("Missing definiton for Packet-Type");
		return -1;
	}

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_alias(NULL, da, type_str);
	if (!type_enum) {
		size_t i;

		for (i = 0; i < (sizeof(type_lib_table) / sizeof(*type_lib_table)); i++) {
			name = type_lib_table[i];
			if (name && (strcmp(name, type_str) == 0)) {
				type_enum = fr_dict_enum_by_value(NULL, da, fr_box_uint32(i));
				break;
			}
		}

		if (!name || !type_enum) {
			cf_log_err(ci, "Invalid type \"%s\"", type_str);
			return -1;
		}
	}

	cf_data_add(ci, type_enum, NULL, false);

	code = type_enum->value->vb_uint32;
	if (code > FR_CODE_MAX) {
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
	if (!cf_section_find(server, "recv", type_enum->alias)) {
		cf_log_err(ci, "Failed finding 'recv %s {...} section of virtual server %s",
			   type_enum->alias, cf_section_name2(server));
		return -1;
	}

	name = type_lib_table[code];
	if (!name) goto invalid_type;

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_radius"));
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

	/*
	 *	Parent dl_instance_t added in virtual_servers.c (listen_parse)
	 */
	return dl_instance(ctx, out, listen_cs,	parent_inst, name, DL_TYPE_SUBMODULE);
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	dl_instance_t	*parent_inst;
	CONF_SECTION	*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_radius"));
	rad_assert(parent_inst);

	return dl_instance(ctx, out, transport_cs, parent_inst, name, DL_TYPE_SUBMODULE);
}

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	proto_radius_t const *inst = talloc_get_type_abort_const(instance, proto_radius_t);
	RADCLIENT *client;

	rad_assert(data[0] < FR_MAX_PACKET_CODE);

	if (DEBUG_ENABLED3) {
		RDEBUG("proto_radius decode packet");
		fr_radius_print_hex(fr_log_fp, data, data_len);
	}

	client = inst->app_io_private->client(inst->app_io, request->async->packet_ctx);
	if (!client) {
		RPEDEBUG("Failed getting client from packet");
		return -1;
	}

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->code = data[0];
	request->packet->id = data[1];
	request->reply->id = data[1];
	memcpy(request->packet->vector, data + 4, sizeof(request->packet->vector));

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	if (fr_radius_packet_decode(request->packet, NULL,
				    inst->max_attributes, inst->tunnel_password_zeros, client->secret) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	/*
	 *	Let the app_io take care of populating additional fields in the request
	 */
	return inst->app_io->decode(inst->app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_len;

	proto_radius_t const *inst = talloc_get_type_abort_const(instance, proto_radius_t);
	RADCLIENT *client;

	/*
	 *	If the app_io encodes the packet, then we don't need
	 *	to do that.
	 */
	if (inst->app_io->encode) {
		data_len = inst->app_io->encode(inst->app_io_instance, request, buffer, buffer_len);
		if (data_len > 0) return data_len;
	}

	/*
	 *	"Do not respond"
	 */
	if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
		*buffer = 0;
		return 1;
	}

	client = inst->app_io_private->client(inst->app_io, request->async->packet_ctx);
	rad_assert(client);

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

	if (DEBUG_ENABLED3) {
		RDEBUG("proto_radius encode packet");
		fr_radius_print_hex(fr_log_fp, buffer, data_len);
	}

	return data_len;
}

static void mod_process_set(void const *instance, REQUEST *request)
{
	proto_radius_t const *inst = talloc_get_type_abort_const(instance, proto_radius_t);
	fr_io_process_t process;

	rad_assert(request->packet->code != 0);
	rad_assert(request->packet->code <= FR_CODE_MAX);

	request->server_cs = inst->server_cs;

	/*
	 *	New packets get processed through proto_radius_dynamic_client
	 */
	if (request->client->dynamic && !request->client->active) {
		rad_assert(request->async->process != NULL);
		return;
	}

	process = inst->process_by_code[request->packet->code];
	if (!process) {
		REDEBUG("No module available to handle packet code %i", request->packet->code);
		return;
	}

	request->async->process = process;
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
static int mod_open(void *instance, fr_schedule_t *sc, CONF_SECTION *conf)
{
	fr_listen_t	*listen;
	proto_radius_t 	*inst = talloc_get_type_abort(instance, proto_radius_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	listen = talloc_zero(inst, fr_listen_t);

	listen->app_io = inst->app_io;
	listen->app_io_instance = inst->app_io_instance;

	listen->app = &proto_radius;
	listen->app_instance = instance;
	listen->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	listen->default_message_size = inst->max_packet_size;
	listen->num_messages = inst->num_messages;

	/*
	 *	Open the socket, and add it to the scheduler.
	 */
	if (inst->app_io) {
		if (inst->app_io->open(inst->app_io_instance) < 0) {
			cf_log_err(conf, "Failed opening %s interface", inst->app_io->name);
			talloc_free(listen);
			return -1;
		}

		if (!fr_schedule_socket_add(sc, listen)) {
			talloc_free(listen);
			return -1;
		}
	}

	inst->listen = listen;	/* Probably won't need it, but doesn't hurt */
	inst->sc = sc;

	return 0;
}

static rlm_components_t code2component[FR_CODE_DO_NOT_RESPOND + 1] = {
	[FR_CODE_ACCESS_REQUEST] = MOD_AUTHORIZE,
	[FR_CODE_ACCESS_ACCEPT] = MOD_POST_AUTH,
	[FR_CODE_ACCESS_REJECT] = MOD_POST_AUTH,
	[FR_CODE_ACCESS_CHALLENGE] = MOD_POST_AUTH,

	[FR_CODE_STATUS_SERVER] = MOD_AUTHORIZE,

	[FR_CODE_ACCOUNTING_REQUEST] = MOD_PREACCT,
	[FR_CODE_ACCOUNTING_RESPONSE] = MOD_ACCOUNTING,

	[FR_CODE_COA_REQUEST] = MOD_RECV_COA,
	[FR_CODE_COA_ACK] = MOD_SEND_COA,
	[FR_CODE_COA_NAK] = MOD_SEND_COA,

	[FR_CODE_DISCONNECT_REQUEST] = MOD_RECV_COA,
	[FR_CODE_DISCONNECT_ACK] = MOD_SEND_COA,
	[FR_CODE_DISCONNECT_NAK] = MOD_SEND_COA,

	[FR_CODE_PROTOCOL_ERROR] = MOD_POST_AUTH,
	[FR_CODE_DO_NOT_RESPOND] = MOD_POST_AUTH,
};

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
	size_t			i;

	fr_dict_attr_t const	*da;
	CONF_PAIR		*cp = NULL;
	CONF_ITEM		*ci;
	CONF_SECTION		*server = cf_item_to_section(cf_parent(conf));

	/*
	 *	Instantiate the I/O module
	 */
	if (inst->app_io && inst->app_io->instantiate &&
	    (inst->app_io->instantiate(inst->app_io_instance,
				       inst->app_io_conf) < 0)) {
		cf_log_err(conf, "Instantiation failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	/*
	 *	Needed to populate the code array
	 */
	da = fr_dict_attr_by_name(NULL, "Packet-Type");
	if (!da) {
		ERROR("Missing definiton for Packet-Type");
		return -1;
	}

	/*
	 *	Compile each "send/recv + RADIUS packet type" section.
	 *	This is so that the submodules don't need to do this.
	 *
	 *	@todo - this loop is run on the virtual server for
	 *	every "listen" section in it.  Which isn't efficient.
	 */
	i = 0;
	for (ci = cf_item_next(server, NULL);
	     ci != NULL;
	     ci = cf_item_next(server, ci)) {
		fr_dict_enum_t const *dv;
		char const *name, *packet_type;
		CONF_SECTION *subcs;

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);
		name = cf_section_name1(subcs);

		/*
		 *	We only process recv/send sections.
		 *	proto_radius_auth will handle the
		 *	"authenticate" sections.
		 */
		if ((strcmp(name, "recv") != 0) &&
		    (strcmp(name, "send") != 0)) {
			continue;
		}

		i++;

		/*
		 *	Skip a section if it was already compiled.
		 */
		if (cf_data_find(subcs, unlang_group_t, NULL) != NULL) continue;

		/*
		 *	Check that the packet type is known.
		 */
		packet_type = cf_section_name2(subcs);
		dv = fr_dict_enum_by_alias(NULL, da, packet_type);
		if (!dv || (dv->value->vb_uint32 > FR_CODE_DO_NOT_RESPOND) ||
		    !code2component[dv->value->vb_uint32]) {
			cf_log_err(subcs, "Invalid RADIUS packet type in '%s %s {...}'",
				   name, packet_type);
			return -1;
		}

		/*
		 *	Skip 'recv foo' when it's a request packet
		 *	that isn't used by this instance.  Note that
		 *	we DO compile things like 'recv
		 *	Access-Accept', so that rlm_radius can use it.
		 */
		if ((strcmp(name, "recv") == 0) && (dv->value->vb_uint32 <= FR_CODE_MAX) &&
		    fr_request_packets[dv->value->vb_uint32] &&
		    !inst->code_allowed[dv->value->vb_uint32]) {
			cf_log_warn(subcs, "Skipping %s %s { ...}", name, packet_type);
			continue;
		}

		/*
		 *	Try to compile it, and fail if it doesn't work.
		 */
		cf_log_debug(subcs, "compiling - %s %s {...}", name, packet_type);

		if (unlang_compile(subcs, code2component[dv->value->vb_uint32]) < 0) {
			cf_log_err(subcs, "Failed compiling '%s %s { ... }' section", name, packet_type);
			return -1;
		}
	}

	/*
	 *	No 'recv' or 'send' sections.  That's an error.
	 */
	if (!i) {
		cf_log_err(server, "Virtual servers cannot be empty.");
		return -1;
	}

	/*
	 *	Instantiate the process modules
	 */
	i = 0;
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		fr_app_process_t const	*app_process;
		fr_dict_enum_t const	*enumv;
		int code;

		app_process = (fr_app_process_t const *)inst->type_submodule[i]->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->type_submodule[i]->data,
									  inst->type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}

		/*
		 *	We've already done bounds checking in the type_parse function
		 */
		enumv = cf_data_value(cf_data_find(cp, fr_dict_enum_t, NULL));
		if (!fr_cond_assert(enumv)) return -1;

		code = enumv->value->vb_uint32;
		inst->process_by_code[code] = app_process->process;	/* Store the process function */

		rad_assert(inst->code_allowed[code] == true);
		i++;
	}

	/*
	 *	These configuration items are not printed by default,
	 *	because normal people shouldn't be touching them.
	 */
	if (!inst->max_packet_size && inst->app_io) inst->max_packet_size = inst->app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	return 0;
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
	size_t			i = 0;
	CONF_PAIR		*cp = NULL;

	/*
	 *	The listener is inside of a virtual server.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));

	/*
	 *	Bootstrap the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		char const		*value;
		dl_t const		*module = talloc_get_type_abort_const(inst->type_submodule[i]->module, dl_t);
		fr_app_process_t const	*app_process = (fr_app_process_t const *)module->common;

		if (app_process->bootstrap && (app_process->bootstrap(inst->type_submodule[i]->data,
								      inst->type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
			return -1;
		}

		value = cf_pair_value(cp);

		/*
		 *	Add handlers for the virtual server calls.
		 *	This is so that when one virtual server wants
		 *	to call another, it just looks up the data
		 *	here by packet name, and doesn't need to troll
		 *	through all of the listeners.
		 */
		if (!cf_data_find(inst->server_cs, fr_io_process_t, value)) {
			fr_io_process_t *process_p;

			process_p = talloc(inst->server_cs, fr_io_process_t);
			*process_p = app_process->process;

			(void) cf_data_add(inst->server_cs, process_p, value, NULL);
		}

		i++;
	}

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io_submodule) return 0;

	/*
	 *	Bootstrap the I/O module
	 */
	inst->app_io = (fr_app_io_t const *) inst->io_submodule->module->common;
	inst->app_io_instance = inst->io_submodule->data;
	inst->app_io_conf = inst->io_submodule->conf;
	inst->app_io_private = dl_instance_symbol(dl_instance_find(inst->app_io_instance),
						  "proto_radius_app_io_private");
	rad_assert(inst->app_io_private);

	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->app_io_instance,
								inst->app_io_conf) < 0)) {
		cf_log_err(inst->app_io_conf, "Bootstrap failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	return 0;
}

fr_app_t proto_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.config		= proto_radius_config,
	.inst_size	= sizeof(proto_radius_t),

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.open		= mod_open,
	.decode		= mod_decode,
	.encode		= mod_encode,
	.process_set	= mod_process_set
};
