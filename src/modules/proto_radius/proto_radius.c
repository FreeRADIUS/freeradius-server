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
	dl_submodule_t		*io_submodule;		//!< I/O module's instance.
	dl_submodule_t		**type_submodule;	//!< Instance of the various types
							//!< only one instance per type allowed.

	fr_io_t const		*io;

	fr_app_io_t const	*app_io;		//!< Easy access to the app_io handle.
	fr_app_subtype_t const	*app_by_code[FR_CODE_MAX];	//!< Lookup submodule by code.
} proto_radius_ctx_t;

extern fr_app_t proto_radius;
static int subtype_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a RADIUS listen section
 *
 */
static CONF_PARSER const proto_radius_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY, proto_radius_ctx_t, type_submodule),
			 .dflt = "Status-Server", .func = subtype_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, proto_radius_ctx_t, io_submodule),
			 .dflt = "udp", .func = transport_parse },

	CONF_PARSER_TERMINATOR
};

/** Wrapper around dl_submodule which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_submodule_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int subtype_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
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
	char const		*name;
	fr_dict_attr_t const	*da;
	fr_dict_enum_t const	*type_enum;
	uint32_t		code;

	rad_assert(listen_cs);

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

	return dl_submodule(ctx, out, listen_cs, dl_by_symbol(&proto_radius), name);
}

/** Wrapper around dl_submodule
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_submodule_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*name = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*parent_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*transport_cs;

	transport_cs = cf_section_find(parent_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(parent_cs, name, NULL);

	return dl_submodule(ctx, out, transport_cs, dl_by_symbol(&proto_radius), name);
}

/** Decode the packet, and set the request->process function
 *
 */
static int mod_decode(UNUSED void const *io_ctx, REQUEST *request,
		      uint8_t *const data, size_t data_len)
{
//	proto_radius_ctx_t *ctx = io_ctx;
	char *secret;

	if (fr_radius_verify(data, NULL, (uint8_t const *) "testing123", 10) < 0) {
		return -1;
	}

	rad_assert(data[0] < FR_MAX_PACKET_CODE);

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->code = data[0];
	request->packet->id = data[1];
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

static ssize_t mod_encode(UNUSED void const *io_ctx, UNUSED REQUEST *request,
			  UNUSED uint8_t *buffer, UNUSED size_t buffer_len)
{
	return -1;
}

static void mod_set_process(UNUSED REQUEST *request, UNUSED void const *uctx)
{
//	proto_radius_ctx_t const *inst = talloc_get_type_abort(uctx, proto_radius_ctx_t);

	/*
	 *	- Figure out the request code
	 *	- Look it up in the app_by_code array
	 *	- Set the state machine entry point to the one provided by the subtype
	 */
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
	int			fd;
	fr_io_t			*io;
	proto_radius_ctx_t 	*inst = talloc_get_type_abort(instance, proto_radius_ctx_t);

	/*
	 *	Open the listen socket
	 */
	if (inst->app_io->op.open(inst->io_submodule->inst) < 0) {
		cf_log_err(conf, "Failed opening I/O interface");
		return -1;
	}

	fd = inst->app_io->op.fd(inst->io_submodule->inst);
	if (!rad_cond_assert(fd >= 0)) return -1;

	/*
	 *	Build the fr_io_t from the op array of the transport and its
	 *	instance data.
	 */
	io = talloc_zero(inst, fr_io_t);

	io->ctx = inst->io_submodule->inst;
	io->op = &inst->app_io->op;

	io->set_process = mod_set_process;
	io->app_ctx = instance;
	io->encode = mod_encode;
	io->decode = mod_decode;

	/*
	 *	Add it to the scheduler.  Note that we add our context
	 *	instead of the transport one, as we need to swap out
	 *	the process function.
	 */
	if (!fr_schedule_socket_add(sc, io)) {
		talloc_free(io);
		return -1;
	}

	inst->io = io;	/* Probably won't need it, but doesn't hurt */

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
	proto_radius_ctx_t 	*inst = talloc_get_type_abort(instance, proto_radius_ctx_t);
	size_t			i = 0;

	fr_dict_attr_t const	*da;
	CONF_PAIR		*cp = NULL;

	/*
	 *	Instantiate the IO module
	 */
	if (inst->app_io->instantiate && (inst->app_io->instantiate(inst->io_submodule->inst,
								    inst->io_submodule->conf) < 0)) {
		cf_log_err(conf, "I/O instantiation failed");
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
	 *	Instantiate the subtypes
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		fr_app_subtype_t const *subtype = (fr_app_subtype_t const *)inst->type_submodule[i]->module->common;

		if (subtype->instantiate && (subtype->instantiate(inst->type_submodule[i]->inst,
								  inst->type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Subtype instantiation failed");
			return -1;
		}

		/*
		 *	We've already done bounds checking in the subtype_parse function
		 */
		inst->app_by_code[fr_dict_enum_by_alias(NULL, da, cf_pair_value(cp))->value->vb_uint32] = subtype;

		i++;
	}

	return 0;
}

/** Bootstrap the application
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] conf	Listen section parsed to give us isntance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	proto_radius_ctx_t 	*inst = talloc_get_type_abort(instance, proto_radius_ctx_t);
	size_t			i = 0;
	CONF_PAIR		*cp = NULL;

	/*
	 *	Bootstrap the IO module
	 */
	inst->app_io = (fr_app_io_t const *) inst->io_submodule	->module->common;
	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->io_submodule->inst,
								inst->io_submodule->conf) < 0)) {
		cf_log_err(inst->io_submodule->conf, "I/O bootstrap failed");
		return -1;
	}

	/*
	 *	Bootstrap the subtypes
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		dl_t const	       *module = talloc_get_type_abort(inst->type_submodule[i]->module, dl_t);
		fr_app_subtype_t const *subtype = (fr_app_subtype_t const *)module->common;

		if (subtype->bootstrap && (subtype->bootstrap(inst->type_submodule[i]->inst,
							      inst->type_submodule[i]->conf) < 0)) {
			cf_log_err(inst->type_submodule[i]->conf, "Subtype bootstrap failed");
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
	.inst_size	= sizeof(proto_radius_ctx_t),
	.inst_type	= "proto_radius_ctx_t",

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.open		= mod_open,
	.set_process	= mod_set_process
};
