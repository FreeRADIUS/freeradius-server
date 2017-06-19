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
 * @brief RAIDUS master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

/** An instance of a proto_radius listen section
 *
 */
typedef struct {
	CONF_SECTION		*server_cs;			//!< server CS for this listener

	dl_instance_t		*io_submodule;			//!< As provided by the transport_parse callback.
								///< Broken out into the app_io_* fields below for
								//!< convenience.

	fr_app_io_t const	*app_io;			//!< Easy access to the app_io handle.
	void			*app_io_instance;		//!< Easy access to the app_io instance.
	CONF_SECTION		*app_io_conf;			//!< Easy access to the app_io's config section.


	dl_instance_t		**process_submodule;		//!< Instance of the various types
								//!< only one instance per type allowed.
	fr_io_process_t		process_by_code[FR_CODE_MAX];	//!< Lookup process entry point by code.

	bool			code_allowed[FR_CODE_MAX];	//!< Lookup allowed packet codes.

	fr_listen_t const	*listen;			//!< The listener structure which describes
								//!< the I/O path.
} proto_radius_t;

extern fr_app_t proto_radius;
static int process_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a RADIUS listen section
 *
 */
static CONF_PARSER const proto_radius_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_radius_t,
			  process_submodule), .dflt = "Status-Server", .func = process_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, proto_radius_t, io_submodule),
			 .dflt = "udp", .func = transport_parse },

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
static int process_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
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
	dl_instance_t		*parent_inst;
	char const		*name;
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
	 *	Look the type up using the Packet-Type enumv
	 */
	type_enum = fr_dict_enum_by_alias(NULL, da, type_str);
	if (!type_enum) {
	invalid_type:
		cf_log_err(ci, "Invalid type \"%s\"", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;
	if (code >= FR_CODE_MAX) goto invalid_type;

	name = type_lib_table[code];
	if (!name) {
		cf_log_err(ci, "No module associated with Packet-Type = '%s'", type_str);
		return -1;
	}

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_radius"));
	rad_assert(parent_inst);

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
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_radius"));
	rad_assert(parent_inst);

	return dl_instance(ctx, out, transport_cs, parent_inst, name, DL_TYPE_SUBMODULE);
}

/** Decode the packet, and set the request->process function
 *
 */
static int mod_decode(UNUSED void const *instance, REQUEST *request,
		      uint8_t *const data, size_t data_len)
{
//	proto_radius_t *ctx = instance;
	char *secret;

	if (fr_radius_verify(data, NULL, (uint8_t const *) "testing123", 10) < 0) return -1;

	rad_assert(data[0] < FR_MAX_PACKET_CODE);

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->code = data[0];
	request->packet->id = data[1];
	request->reply->id = data[1];
	memcpy(request->packet->vector, data + 4, sizeof(request->packet->vector));

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;


	secret = talloc_strdup(request, "testing123");

	if (fr_radius_packet_decode(request->packet, NULL, secret) < 0) {
		RDEBUG("Failed decoding packet: %s", fr_strerror());
		return -1;
	}

//	request->async_process = ctx->process[data[0]];

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, REQUEST *request,
			  uint8_t *buffer, size_t buffer_len)
{
//	proto_radius_ctx_t *inst = instance;
	size_t len;
	char *secret = talloc_strdup(request, "testing123");

	if (fr_radius_packet_encode(request->reply, request->packet, secret) < 0) {
		RDEBUG("Failed encoding RADIUS reply: %s", fr_strerror());
		return -1;
	}

	if (fr_radius_packet_sign(request->reply, request->packet, secret) < 0) {
		RDEBUG("Failed signing RADIUS reply: %s", fr_strerror());
		return -1;
	}

	len = request->reply->data_len;
	if (buffer_len < len) len = buffer_len;

	memcpy(buffer, request->reply->data, len);

	return len;
}

static void mod_set_process(void const *instance, REQUEST *request)
{
	proto_radius_t const *inst = talloc_get_type_abort(instance, proto_radius_t);
	fr_io_process_t process;

	rad_assert(request->packet->code != 0);
	rad_assert(request->packet->code < FR_CODE_MAX);

	request->server_cs = inst->server_cs;

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
	int		fd;
	fr_listen_t	*listen;
	proto_radius_t 	*inst = talloc_get_type_abort(instance, proto_radius_t);

	/*
	 *	Open the listen socket
	 */
	if (inst->app_io->open(inst->app_io_instance) < 0) {
		cf_log_err(conf, "Failed opening %s interface", inst->app_io->name);
		return -1;
	}

	fd = inst->app_io->fd(inst->app_io_instance);
	if (!rad_cond_assert(fd >= 0)) return -1;

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

	listen->encode = mod_encode;
	listen->decode = mod_decode;

	/*
	 *	Add the listener to the scheduler.
	 */
	if (!fr_schedule_socket_add(sc, listen)) {
		talloc_free(listen);
		return -1;
	}

	inst->listen = listen;	/* Probably won't need it, but doesn't hurt */

	return 0;
}

/** Instantiate the application
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] conf	Listen section parsed to give us isntance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	proto_radius_t		*inst = talloc_get_type_abort(instance, proto_radius_t);
	size_t			i = 0;

	fr_dict_attr_t const	*da;
	CONF_PAIR		*cp = NULL;

	/*
	 *	The listener is inside of a virtual server.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));

	/*
	 *	Instantiate the I/O module
	 */
	if (inst->app_io->instantiate && (inst->app_io->instantiate(inst->app_io_instance,
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
	 *	Instantiate the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		fr_app_process_t const *app_process;
		int code;

		app_process = (fr_app_process_t const *)inst->process_submodule[i]->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->process_submodule[i]->data,
									  inst->process_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}

		/*
		 *	We've already done bounds checking in the process_parse function
		 */
		code = fr_dict_enum_by_alias(NULL, da, cf_pair_value(cp))->value->vb_uint32;
		inst->process_by_code[code] = app_process->process;	/* Store the process function */
		inst->code_allowed[code] = true;

		i++;
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
	proto_radius_t 	*inst = talloc_get_type_abort(instance, proto_radius_t);
	size_t			i = 0;
	CONF_PAIR		*cp = NULL;

	/*
	 *	Bootstrap the I/O module
	 */
	inst->app_io = (fr_app_io_t const *) inst->io_submodule->module->common;
	inst->app_io_instance = inst->io_submodule->data;
	inst->app_io_conf = inst->io_submodule->conf;
	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->app_io_instance,
								inst->app_io_conf) < 0)) {
		cf_log_err(inst->app_io_conf, "Bootstrap failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	/*
	 *	Bootstrap the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		dl_t const	       *module = talloc_get_type_abort(inst->process_submodule[i]->module, dl_t);
		fr_app_process_t const *app_process = (fr_app_process_t const *)module->common;

		if (app_process->bootstrap && (app_process->bootstrap(inst->process_submodule[i]->data,
								      inst->process_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
			return -1;
		}
		i++;
	}

	return 0;
}

fr_app_t proto_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.config		= proto_radius_config,
	.inst_size	= sizeof(proto_radius_t),
	.inst_type	= "proto_radius_t",

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.open		= mod_open,
	.set_process	= mod_set_process
};
