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
 * @file proto_control.c
 * @brief CONTROL master protocol handler.
 *
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/unlang.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_control.h"

extern fr_app_t proto_control;
static int type_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

static CONF_PARSER const limit_config[] = {
	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIMEVAL, proto_control_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("nak_lifetime", FR_TYPE_TIMEVAL, proto_control_t, io.nak_lifetime), .dflt = "30.0" } ,

	{ FR_CONF_OFFSET("max_connections", FR_TYPE_UINT32, proto_control_t, io.max_connections), .dflt = "1024" } ,
	{ FR_CONF_OFFSET("max_clients", FR_TYPE_UINT32, proto_control_t, io.max_clients), .dflt = "256" } ,
	{ FR_CONF_OFFSET("max_pending_packets", FR_TYPE_UINT32, proto_control_t, io.max_pending_packets), .dflt = "256" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_control_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_control_t, num_messages) } ,

	CONF_PARSER_TERMINATOR
};

/** How to parse a CONTROL listen section
 *
 */
static CONF_PARSER const proto_control_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_control_t,
			  type_submodule), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_control_t, io.submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_control;

extern fr_dict_autoload_t proto_control_dict[];
fr_dict_autoload_t proto_control_dict[] = {
	{ .out = &dict_control, .proto = "internal" },
	{ NULL }
};

#if 0
static fr_dict_attr_t const *attr_control_packet_type;

extern fr_dict_attr_autoload_t proto_control_dict_attr[];
fr_dict_attr_autoload_t proto_control_dict_attr[] = {
	{ .out = &attr_control_packet_type, .name = "CONTROL-Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_control},
	{ NULL }
};
#endif

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_control).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
//	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
//	CONF_SECTION		*server = cf_item_to_section(cf_parent(listen_cs));
//	proto_control_t		*inst;
	dl_instance_t		*parent_inst;
//	fr_dict_enum_t const	*type_enum;

	rad_assert(listen_cs && (strcmp(cf_section_name1(listen_cs), "listen") == 0));

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_control"));
	rad_assert(parent_inst);

//	inst = talloc_get_type_abort(parent_inst->data, proto_control_t);

	/*
	 *	Parent dl_instance_t added in virtual_servers.c (listen_parse)
	 *
	 *	We just load proto_control_all.a
	 *
	 *	Future changes may allow different types of control access?
	 */
	return dl_instance(ctx, out, listen_cs,	parent_inst, "all", DL_TYPE_SUBMODULE);
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_control).
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
	proto_control_t	*inst;
	CONF_SECTION	*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_control"));
	rad_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_control_t);
	inst->io.transport = name;

	return dl_instance(ctx, out, transport_cs, parent_inst, name, DL_TYPE_SUBMODULE);
}

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	proto_control_t const *inst = talloc_get_type_abort_const(instance, proto_control_t);
	fr_io_track_t const *track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t *address = track->address;
	RADCLIENT const *client;

	rad_assert(data[0] < FR_MAX_PACKET_CODE);

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_control;

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
	 *	transport.
	 *
	 *	@todo - decode the input control packet, instead of
	 *	this temporary hack.
	 */
	if (data_len > 0) {
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

	request->root = &main_config;
	REQUEST_VERIFY(request);

	if (!inst->io.app_io->decode) return 0;

	/*
	 *	Let the app_io do anything it needs to do.
	 */
	return inst->io.app_io->decode(inst->io.app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	proto_control_t const *inst = talloc_get_type_abort_const(instance, proto_control_t);
	fr_io_track_t const *track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t *address = track->address;
	ssize_t data_len;
	RADCLIENT const *client;

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
	    (request->reply->code == 0) || (request->reply->code >= FR_MAX_PACKET_CODE)) {
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

	/*
	 *	@todo - encode the reply.
	 *
	 *	If the reply is too large, find a way to gradually
	 *	write it to the network side?
	 */
#if 0
	data_len = fr_control_encode(buffer, buffer_len, request->packet->data,
				  request->reply->code, request->reply->id, request->reply->vps);
#else
	data_len = -1;
#endif
	if (data_len < 0) {
		RPEDEBUG("Failed encoding CONTROL reply");
		return -1;
	}

	return data_len;
}

static void mod_entry_point_set(void const *instance, REQUEST *request)
{
	proto_control_t const *inst = talloc_get_type_abort_const(instance, proto_control_t);
	fr_io_track_t *track = request->async->packet_ctx;

	request->server_cs = inst->io.server_cs;

	/*
	 *	'track' can be NULL when there's no network listener.
	 */
	if (inst->io.app_io && (track->dynamic == request->async->recv_time)) {
		fr_app_worker_t const	*app_process;

		app_process = (fr_app_worker_t const *) inst->dynamic_submodule->module->common;

		request->async->process = app_process->entry_point;
		track->dynamic = 0;
		return;
	}

	rad_assert(inst->process != NULL);
	request->async->process = inst->process;
}


static int mod_priority_set(UNUSED void const *instance, UNUSED uint8_t const *buffer, UNUSED size_t buflen)
{
	return PRIORITY_NOW;
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
	proto_control_t 	*inst = talloc_get_type_abort(instance, proto_control_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	listen = talloc_zero(inst, fr_listen_t);

	listen->app = &proto_control;
	listen->app_instance = instance;
	listen->server_cs = inst->io.server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	listen->default_message_size = inst->max_packet_size;
	listen->num_messages = inst->num_messages;

	/*
	 *	Open the socket, and add it to the scheduler.
	 */
	if (inst->io.app_io) {
		/*
		 *	Set the listener to call our master trampoline function.
		 */
		listen->app_io = &fr_master_app_io;
		listen->app_io_instance = inst;

		/*
		 *	Don't set the connection for the main socket.  It's not connected.
		 */
		if (inst->io.app_io->open(inst->io.app_io_instance) < 0) {
			cf_log_err(conf, "Failed opening %s interface", inst->io.app_io->name);
			talloc_free(listen);
			return -1;
		}

		/*
		 *	Add the socket to the scheduler, which might
		 *	end up in a different thread.
		 */
		if (!fr_schedule_socket_add(sc, listen)) {
			talloc_free(listen);
			return -1;
		}
	} else {
		rad_assert(!inst->io.dynamic_clients);
	}

	inst->io.listen = listen;	/* Probably won't need it, but doesn't hurt */
	inst->io.sc = sc;

	return 0;
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
	proto_control_t		*inst = talloc_get_type_abort(instance, proto_control_t);
	size_t			i;

	CONF_PAIR		*cp = NULL;
	CONF_ITEM		*ci;
	CONF_SECTION		*server = cf_item_to_section(cf_parent(conf));

	/*
	 *	Compile each "send/recv + CONTROL packet type" section.
	 *	This is so that the submodules don't need to do this.
	 */
	i = 0;
	for (ci = cf_item_next(server, NULL);
	     ci != NULL;
	     ci = cf_item_next(server, ci)) {
		char const *name, *packet_type;
		CONF_SECTION *subcs;
		rlm_components_t component = MOD_AUTHORIZE;

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);
		name = cf_section_name1(subcs);

		/*
		 *	We only process recv/send sections.
		 *	proto_control_auth will handle the
		 *	"authenticate" sections.
		 */
		if ((strcmp(name, "recv") != 0) &&
		    (strcmp(name, "send") != 0)) {
			continue;
		}

		/*
		 *	One more "recv" or "send" section has been
		 *	found.
		 */
		i++;

		/*
		 *	Skip a section if it was already compiled.
		 */
		if (cf_data_find(subcs, unlang_group_t, NULL) != NULL) continue;

		/*
		 *	Check that the packet type is known.
		 */
		packet_type = cf_section_name2(subcs);
		if (packet_type) {
			cf_log_err(subcs, "Invalid control packet type in '%s %s {...}'",
				   name, packet_type);
			return -1;
		}

		/*
		 *	Try to compile it, and fail if it doesn't work.
		 */
		cf_log_debug(subcs, "compiling - %s {...}", name);

		if (strcmp(name, "send") == 0) component = MOD_POST_AUTH;

		if (unlang_compile(subcs, component) < 0) {
			cf_log_err(subcs, "Failed compiling '%s { ... }' section", name);
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
		fr_app_worker_t const	*app_process;
		fr_dict_enum_t const	*enumv;

		app_process = (fr_app_worker_t const *)inst->type_submodule[i]->module->common;
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

		inst->process = app_process->entry_point;		/* Store the state function */
		i++;
	}

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!i || !inst->io.submodule) return 0;

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
	 *	Set talloc ctx for master IO.
	 */
	inst->io.ctx = inst;

	/*
	 *	Instantiate the master io submodule
	 */
	if (fr_master_app_io.instantiate(&inst->io, conf) < 0) {
		return -1;

	}

	/*
	 *	No dynamic clients, nothing more to do.
	 */
	if (!inst->io.dynamic_clients) return 0;

	/*
	 *	Instantiate proto_control_dynamic_client
	 */
	{
		fr_app_worker_t const	*app_process;

		app_process = (fr_app_worker_t const *)inst->dynamic_submodule->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->dynamic_submodule->data, conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}
	}

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
	proto_control_t 		*inst = talloc_get_type_abort(instance, proto_control_t);
	size_t			i = 0;
	CONF_PAIR		*cp = NULL;

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(conf));

	/*
	 *	Bootstrap the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		char const		*value;
		dl_t const		*module = talloc_get_type_abort_const(inst->type_submodule[i]->module, dl_t);
		fr_app_worker_t const	*app_process = (fr_app_worker_t const *)module->common;

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
		if (!cf_data_find(inst->io.server_cs, fr_io_process_t, value)) {
			fr_io_process_t *process_p;

			rad_assert(inst->io.server_cs);	/* Ensure we don't leak memory */

			process_p = talloc(inst->io.server_cs, fr_io_process_t);
			*process_p = app_process->entry_point;

			(void) cf_data_add(inst->io.server_cs, process_p, value, NULL);
		}

		i++;
	}

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

	/*
	 *	These timers are usually protocol specific.
	 */
	FR_TIMEVAL_BOUND_CHECK("idle_timeout", &inst->io.idle_timeout, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("idle_timeout", &inst->io.idle_timeout, <=, 600, 0);

	FR_TIMEVAL_BOUND_CHECK("nak_lifetime", &inst->io.nak_lifetime, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("nak_lifetime", &inst->io.nak_lifetime, <=, 600, 0);

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_control;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.dl_inst = dl_instance_find(inst);
	rad_assert(inst != NULL);

	/*
	 *	Bootstrap the master IO handler.
	 */
	if (fr_master_app_io.bootstrap(&inst->io, conf) < 0) {
		return -1;
	}

	/*
	 *	proto_control_udp determines if we have dynamic clients
	 *	or not.
	 */
	if (!inst->io.dynamic_clients) return 0;

	/*
	 *	Load proto_control_dynamic_client
	 */
	if (dl_instance(inst, &inst->dynamic_submodule,
			conf, inst->io.dl_inst, "dynamic_client", DL_TYPE_SUBMODULE) < 0) {
		cf_log_err(conf, "Failed finding proto_control_dynamic_client");
		return -1;
	}

	/*
	 *	Don't bootstrap the dynamic submodule.  We're
	 *	not even sure what that means...
	 */

	return 0;
}

static int mod_load(void)
{
	// load stuff?

	return 0;
}

static void mod_unload(void)
{
	// unload stuff?
}

fr_app_t proto_control = {
	.magic			= RLM_MODULE_INIT,
	.name			= "control",
	.config			= proto_control_config,
	.inst_size		= sizeof(proto_control_t),

	.load			= mod_load,
	.unload			= mod_unload,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.entry_point_set	= mod_entry_point_set,
	.priority		= mod_priority_set
};
