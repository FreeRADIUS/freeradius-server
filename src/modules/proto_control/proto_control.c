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
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>
#include "proto_control.h"

extern fr_app_t proto_control;
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static CONF_PARSER const limit_config[] = {
	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIME_DELTA, proto_control_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("nak_lifetime", FR_TYPE_TIME_DELTA, proto_control_t, io.nak_lifetime), .dflt = "30.0" } ,

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
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_control_t, io.submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_control;

extern fr_dict_autoload_t proto_control_dict[];
fr_dict_autoload_t proto_control_dict[] = {
	{ .out = &dict_control, .proto = "freeradius" },
	{ NULL }
};

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_control).
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
	proto_control_t	*inst;
	CONF_SECTION	*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_control"));
	fr_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_control_t);
	inst->io.transport = name;

	return dl_module_instance(ctx, out, transport_cs, parent_inst, name, DL_MODULE_TYPE_SUBMODULE);
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
	proto_control_t 	*inst = talloc_get_type_abort(instance, proto_control_t);

	inst->io.app = &proto_control;
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
	proto_control_t		*inst = talloc_get_type_abort(instance, proto_control_t);

	fr_assert(inst->io.submodule != NULL);

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
	proto_control_t 		*inst = talloc_get_type_abort(instance, proto_control_t);

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(conf));

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) {
		cf_log_err(conf, "The control server MUST have a 'listener' section.");
		return -1;
	}

	/*
	 *	These timers are usually protocol specific.
	 */
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, <=, fr_time_delta_from_sec(600));

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_control;
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

fr_app_t proto_control = {
	.magic			= RLM_MODULE_INIT,
	.name			= "control",
	.config			= proto_control_config,
	.inst_size		= sizeof(proto_control_t),

	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.open			= mod_open,
};
