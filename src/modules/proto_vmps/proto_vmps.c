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
 * @file proto_vmps.c
 * @brief VMPS master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_vmps.h"

extern fr_app_t proto_vmps;
static int process_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a RADIUS listen section
 *
 */
static CONF_PARSER const proto_vmps_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_vmps_t,
			  process_submodule), .dflt = "all", .func = process_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_vmps_t, io_submodule),
	  .func = transport_parse },

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("default_message_size", FR_TYPE_UINT32, proto_vmps_t, default_message_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_vmps_t, num_messages) } ,

	CONF_PARSER_TERMINATOR
};

fr_dict_t const *dict_vqp;

extern fr_dict_autoload_t proto_vmps_dict[];
fr_dict_autoload_t proto_vmps_dict[] = {
	{ .out = &dict_vqp, .proto = "vqp" },
	{ NULL }
};

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_vmps).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int process_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
	dl_instance_t		*parent_inst;

	if (strcmp(type_str, "all") != 0) {
		ERROR("VMPS only supports 'type = all'");
		return -1;
	}

	rad_assert(listen_cs && (strcmp(cf_section_name1(listen_cs), "listen") == 0));

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_vmps"));
	rad_assert(parent_inst);

	/*
	 *	Parent dl_instance_t added in virtual_servers.c (listen_parse)
	 */
	return dl_instance(ctx, out, listen_cs,	parent_inst, type_str, DL_TYPE_SUBMODULE);
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_vmps).
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

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_instance_t, "proto_vmps"));
	rad_assert(parent_inst);

	return dl_instance(ctx, out, transport_cs, parent_inst, name, DL_TYPE_SUBMODULE);
}

/** Decode the packet.
 *
 */
static int mod_decode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	proto_vmps_t const *inst = talloc_get_type_abort_const(instance, proto_vmps_t);

	return inst->app_io->decode(inst->app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	proto_vmps_t const *inst = talloc_get_type_abort_const(instance, proto_vmps_t);

	return inst->app_io->encode(inst->app_io_instance, request, buffer, buffer_len);
}

static void mod_process_set(void const *instance, REQUEST *request)
{
	proto_vmps_t const *inst = talloc_get_type_abort_const(instance, proto_vmps_t);
	fr_io_process_t process;

	rad_assert(request->packet->code != 0);
	rad_assert(request->packet->code < FR_CODE_MAX);

	request->server_cs = inst->server_cs;

	process = inst->process;
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
	proto_vmps_t 	*inst = talloc_get_type_abort(instance, proto_vmps_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	listen = talloc_zero(inst, fr_listen_t);

	listen->app_io = inst->app_io;
	listen->app_io_instance = inst->app_io_instance;

	listen->app = &proto_vmps;
	listen->app_instance = instance;
	listen->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	listen->default_message_size = inst->default_message_size;
	listen->num_messages = inst->default_message_size;

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
	proto_vmps_t		*inst = talloc_get_type_abort(instance, proto_vmps_t);
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
	 *	Instantiate the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		fr_app_process_t const *app_process;

		app_process = (fr_app_process_t const *)inst->process_submodule[i]->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->process_submodule[i]->data,
									  inst->process_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}

		/*
		 *	We've already done bounds checking in the process_parse function
		 */
		inst->process = app_process->process;	/* Store the process function */

		i++;
	}

	/*
	 *	These configuration items are not printed by default,
	 *	because normal people shouldn't be touching them.
	 */
	if (!inst->default_message_size && inst->app_io) inst->default_message_size = inst->app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("default_message_size", inst->default_message_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("default_message_size", inst->default_message_size, <=, 65535);

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
	proto_vmps_t 		*inst = talloc_get_type_abort(instance, proto_vmps_t);
	size_t			i = 0;
	CONF_PAIR		*cp = NULL;

	/*
	 *	Bootstrap the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		dl_t const	       *module = talloc_get_type_abort_const(inst->process_submodule[i]->module, dl_t);
		fr_app_process_t const *app_process = (fr_app_process_t const *)module->common;

		if (app_process->bootstrap && (app_process->bootstrap(inst->process_submodule[i]->data,
								      inst->process_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
			return -1;
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
						  "proto_vmps_app_io_private");
	rad_assert(inst->app_io_private);

	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->app_io_instance,
								inst->app_io_conf) < 0)) {
		cf_log_err(inst->app_io_conf, "Bootstrap failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	return 0;
}

fr_app_t proto_vmps = {
	.magic		= RLM_MODULE_INIT,
	.name		= "vmps",
	.config		= proto_vmps_config,
	.inst_size	= sizeof(proto_vmps_t),

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.open		= mod_open,
	.decode		= mod_decode,
	.encode		= mod_encode,
	.process_set	= mod_process_set
};
