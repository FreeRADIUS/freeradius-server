/*
 * proto_radius.c	RADIUS master protocol handler
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2016 The FreeRADIUS server project
 * Copyright 2016 Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_radius.h"

/** Decode the packet, and set the request->process function
 *
 */
static int mod_decode(void *io_ctx, uint8_t *const data, UNUSED size_t data_len, REQUEST *request)
{
	proto_radius_ctx_t *ctx = io_ctx;

	if (fr_radius_verify(data, NULL, (uint8_t const *) ctx->secret, ctx->secret_len) < 0) {
		return -1;
	}

	rad_assert(data[0] < FR_MAX_PACKET_CODE);

	if (fr_radius_packet_decode(request->packet, NULL, ctx->secret) < 0) {
		return -1;
	}

//	request->async_process = ctx->process[data[0]];

	return 0;
}

static ssize_t mod_encode(UNUSED void *io_ctx, UNUSED REQUEST *request, UNUSED uint8_t *buffer, UNUSED size_t buffer_len)
{
	return -1;
}


/** Load the RADIUS protocol
 *
 * Typically loads dictionaries, etc.
 */
static int mod_load(void)
{
	/*
	 *	@todo - load the RADIUS dictionaries
	 */

	return 0;
}

/** Bootstrap the RADIUS protocol in a particular virtual server.
 *
 */
static int mod_bootstrap(UNUSED CONF_SECTION *cs)
{
	return 0;
}

typedef struct type2lib_t {
	char const *type;
	char const *lib;
	char const *port_name;
} type2lib_t;

static const type2lib_t type2lib[] = {
	{ "Access-Request", "radius_auth", "radius" },
	{ "Accounting-Request", "radius_acct", "radius-acct" },
	{ "CoA-Request", "coa", "radius-dynauth" },
	{ "Disconnect-Request", "radius_coa", "radius-dynauth" },
	{ "Status-Server", "radius_status", NULL },
	{ NULL, NULL }
};

typedef struct pr_config_t {
	char const	**types;
	char const	*transport;
} pr_config_t;


static const CONF_PARSER mod_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_STRING | FR_TYPE_MULTI, pr_config_t, types), .dflt = "Status-Server" },
	{ FR_CONF_OFFSET("transport", FR_TYPE_STRING, pr_config_t, transport), .dflt = "udp" },

	CONF_PARSER_PARTIAL_TERMINATOR
};


static int compile_type(proto_radius_ctx_t *ctx, CONF_SECTION *server, CONF_SECTION *cs, char const *value)
{
	int i, code;
	char const *lib, *port_name;
	dl_t const *module;
	fr_app_subtype_t const *app;

	if (!value || !*value) {
		cf_log_err_cs(cs, "Must specify a value for 'type'");
		return -1;
	}

	code = 0;
	for (i = 1; i < FR_MAX_PACKET_CODE; i++) {
		if (strcmp(value, fr_packet_codes[i]) == 0) {
			code = i;
			break;
		}
	}

	if (!code) {
		cf_log_err_cs(cs, "Unknown 'type = %s'", value);
		return -1;
	}

	if (ctx->process[i]) {
		cf_log_err_cs(cs, "Duplicate 'type = %s'", value);
		return -1;
	}

	/*
	 *	Already loaded the module in this virtual
	 *	server, don't do anything more.
	 */
	if (cf_data_find(server, dl_t, value)) return 0;

	/*
	 *	Convert "Access-Request" -> "auth"
	 */
	port_name = lib = NULL;
	for (i = 0; type2lib[i].type != NULL; i++) {
		if (strcmp(type2lib[i].type, value) == 0) {
			lib = type2lib[i].lib;
			port_name = type2lib[i].port_name;
			break;
		}
	}

	if (!lib) {
		cf_log_err_cs(cs, "Unknown 'type = %s'", value);
		return -1;
	}

	/*
	 *	Add the default port name, if it exists.
	 */
	if (port_name) {
		CONF_PAIR *cp;

		cp = cf_pair_find(cs, "port_name");
		if (!cp) {
			cp = cf_pair_alloc(cs, "port_name", port_name,
					   T_OP_SET, T_BARE_WORD, T_BARE_WORD);
			if (!cp) {
				cf_log_err_cs(cs, "Out of memory");
				return -1;
			}

			(void) cf_pair_add(cs, cp);
		}
	}


	/*
	 *	Load the module.
	 */
	module = dl_module(server, NULL, lib, DL_TYPE_PROTO);
	if (!module) {
		cf_log_err_cs(cs, "Failed finding submodule library for 'type = %s'", value);
		return -1;
	}

	app = (fr_app_subtype_t const *) module->common;
	ctx->process[i] = app->process;

	/*
	 *	Remember that we loaded the module in the server.
	 */
	cf_data_add(server, module, value, false);

	return 0;
}


static int open_transport(proto_radius_ctx_t *ctx, UNUSED fr_schedule_t *handle,
			  CONF_SECTION *server, CONF_SECTION *cs, char const *value,
			  bool verify_config)
{
	dl_t const		*module;
	fr_app_io_t const	*app_io;
	CONF_SECTION		*io_cs;
	void			*io_ctx;
	CONF_PAIR		*cp;
	char			buffer[256];

	if (!value || !*value) {
		cf_log_err_cs(cs, "Must specify a value for 'transport'");
		return -1;
	}

	snprintf(buffer, sizeof(buffer), "radius_%s", value);

	module = dl_module(server, NULL, buffer, DL_TYPE_PROTO);
	if (!module) {
		cf_log_err_cs(cs, "Failed finding submodule library for 'transport = %s'", value);
		return -1;
	}

	/*
	 *	Lookup io section.
	 */
	io_cs = cf_subsection_find(cs, value);
	if (!io_cs) {
		cf_log_err_cs(cs, "Must contain a '%s' section", value);
		return -1;
	}

	if (dl_instance_data_alloc(&io_ctx, NULL, module, io_cs) < 0) {
		PERROR("Failed io_ctx data");
		return -1;
	}

	cp = cf_pair_find(cs, "port_name");
	if (cp) {
		cp = cf_pair_alloc(io_cs, "port_name", cf_pair_value(cp),
				   T_OP_SET, T_BARE_WORD, T_BARE_WORD);
		if (!cp) {
			cf_log_err_cs(cs, "Out of memory");
			return -1;
		}

		(void) cf_pair_add(io_cs, cp);
	}

	app_io = (fr_app_io_t const *) module->common;
	if (app_io->instantiate(io_cs, io_ctx) < 0) {
		cf_log_err_cs(cs, "Failed instantiating 'transport = %s'", value);
		talloc_free(io_ctx);
		return -1;
	}

	if (verify_config) return 0;

	if (app_io->op.open(io_ctx) < 0) {
		cf_log_err_cs(cs, "Failed compiling unlang for 'transport = %s'", value);
		return -1;
	}

	/*
	 *	Set to the function which will decode the packet and
	 *	set request->process to the correct entry.
	 *
	 *	@note - could also do this in the recv_request function?
	 */
	ctx->transport = app_io->op;
	ctx->transport.decode = mod_decode;
	ctx->transport.encode = mod_encode;


	/*
	 *	Don't do this until we actually have a scheduler
	 */
#if 0
	/*
	 *	Add it to the scheduler.  Note that we add our context
	 *	instead of the transport one, as we need to swap out
	 *	the process function.
	 *
	 *	@todo - more cleanup on error.
	 */
	if (!fr_schedule_socket_add(handle, ctx->sockfd, ctx, &ctx->transport)) {
		talloc_free(ctx);
		return -1;
	}
#endif

	/*
	 *	Remember that we loaded the transport library in the server.
	 */
	cf_data_add(server, module, value, false);

	return 0;
}

static int open_listen(fr_schedule_t *handle, CONF_SECTION *server, CONF_SECTION *cs, bool verify_config)
{
	size_t i;
	pr_config_t config;
	proto_radius_ctx_t *ctx;

	if ((cf_section_parse(cs, &config, cs, mod_config) < 0) ||
	    (cf_section_parse_pass2(&config, cs, mod_config) < 0)) {
		cf_log_err_cs(cs, "Failed parsing listen { ...}");
		return -1;
	}

	if (!config.types) {
		cf_log_err_cs(cs, "type MUST be specified");
		return -1;
	}

	if (!config.transport) {
		cf_log_err_cs(cs, "transport MUST be specified");
		return -1;
	}

	ctx = talloc_zero(NULL, proto_radius_ctx_t);
	if (!ctx) {
		cf_log_err_cs(cs, "Failed allocating memory");
		return -1;
	}

	/*
	 *	Compile one or more types.
	 */
	for (i = 0; i < talloc_array_length(config.types); i++) {
		if (compile_type(ctx, server, cs, config.types[i]) < 0) {
			cf_log_err_cs(server, "Failed compiling unlang for 'type = %s'",
				      config.types[i]);
			return -1;
		}
	}

	/*
	 *	Call transport-specific library to open the socket.
	 */
	if (open_transport(ctx, handle, server, cs, config.transport, verify_config) < 0) {
		cf_log_err_cs(server, "Failed opening connection for 'transport = %s'",
				      config.transport);
		return -1;
	}

	/*
	 *	Print out the final "}" for debugging.
	 */
	(void) cf_section_parse(cs, &config, cs, NULL);

	return 0;
}


/** Open a RADIUS application in a virtual server,
 *
 */
static int mod_parse(fr_schedule_t *handle, CONF_SECTION *cs, bool verify_config)
{
	CONF_SECTION *subcs;

	/*
	 *	Load all of the listen sections.  They do all of the
	 *	dirty work.
	 */
	for (subcs = cf_subsection_find_next(cs, NULL, "listen");
	     subcs != NULL;
	     subcs = cf_subsection_find_next(cs, cs, "listen")) {
		if (open_listen(handle, cs, subcs, verify_config) < 0) {
			return -1;
		}
	}

	/*
	 *	Compile the sub-sections AFTER parsing all of the
	 *	listen sections.  This is mainly for nice debugging
	 *	output.  It's inefficient as heck, but it's pretty.
	 */
	for (subcs = cf_subsection_find_next(cs, NULL, "listen");
	     subcs != NULL;
	     subcs = cf_subsection_find_next(cs, cs, "listen")) {
		CONF_PAIR *cp;

		for (cp = cf_pair_find(subcs, "type");
		     cp != NULL;
		     cp = cf_pair_find_next(subcs, cp, "type")) {
			char const		*value;
			dl_t const		*module;
			fr_app_subtype_t	const *app;

			value = cf_pair_value(cp);

			module = cf_data_find(cs, dl_t, value);
			if (!module) {
				cf_log_err_cs(cs, "Section missing module data");
				return -1;
			}
			if (cf_data_find(cs, char const *, value)) continue;

			app = (fr_app_subtype_t const *) module->common;
			if (app->instantiate(cs) < 0) {
				cf_log_err_cs(cs, "Failed compiling unlang for 'type = %s'", value);
				return -1;
			}

			cf_data_add(cs, value, value, false);
		}
	}

	return 0;
}

extern fr_app_t proto_radius;
fr_app_t proto_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.load		= mod_load,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_parse,
};
