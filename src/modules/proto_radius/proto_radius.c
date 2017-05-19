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
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/transport.h>
#include <freeradius-devel/rad_assert.h>

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
} type2lib_t;

static const type2lib_t type2lib[] = {
	{ "Access-Request", "radius_auth" },
	{ "Accounting-Request", "radius_acct" },
	{ "CoA-Request", "coa" },
	{ "Disconnect-Request", "radius_coa" },
	{ "Status-Server", "radius_status" },
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


static int compile_type(CONF_SECTION *server, CONF_SECTION *cs, char const *value, uint8_t *allowed_packets)
{
	int i, code;
	char const *lib;
	dl_t const *module;

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

	if (allowed_packets[i]) {
		cf_log_err_cs(cs, "Duplicate 'type = %s'", value);
		return -1;
	}
	allowed_packets[i] = 1;

	/*
	 *	Already loaded the module in this virtual
	 *	server, don't do anything more.
	 */
	if (cf_data_find(server, dl_t, value)) return 0;

	/*
	 *	Convert "Access-Request" -> "auth"
	 */
	lib = NULL;
	for (i = 0; type2lib[i].type != NULL; i++) {
		if (strcmp(type2lib[i].type, value) == 0) {
			lib = type2lib[i].lib;
			break;
		}
	}

	if (!lib) {
		cf_log_err_cs(cs, "Unknown 'type = %s'", value);
		return -1;
	}

	/*
	 *	Load the module.
	 */
	module = dl_module(server, NULL, lib, DL_TYPE_PROTO);
	if (!module) {
		cf_log_err_cs(cs, "Failed finding submodule library for 'type = %s'", value);
		return -1;
	}

	/*
	 *	Remember that we loaded the module in the server.
	 */
	cf_data_add(server, module, value, false);

	return 0;
}


static int compile_transport(CONF_SECTION *server, CONF_SECTION *cs, char const *value, UNUSED uint8_t *allowed_packets)
{
	dl_t const *module;
	char buffer[256];

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
	 *	Remember that we loaded the transport in the server.
	 */
	cf_data_add(server, module, value, false);

	/*
	 *	@todo - load proto_radius_udp, and have it parse it's stuff
	 *
	 *	- call app->compile, which returns a tuple:
	 *	  - sockfd, ctx, transport
	 *
	 * - the proto_radius code will then take care of replacing
	 * 	the "process" function with ones specific to the
	 * 	method? and duplicating the transport for every packet
	 * 	type.  which then lets us change the transport write()
	 * 	functions, too.. which gets rid of multiple code paths
	 *
	 * - so we have radius udp transport, which has a "process" function
	 *   the just returns an error
	 *
	 * - each proto_radius_foo has it's own transport (so we can
         *  just use that if necessary, and it's used for testing)
	 *
	 *  transport->read needs to take "process" pointer and then
	 *  update it if needed.
	 *
	 *  and get rid of ID, and put "process" into the channel
	 *  messages
	 *
	 *  probably need a generic proto_radius_transport, which contains the generic
	 *  functions encode / decode, nak, send_reply, etc.
	 *
	 *  OR, split up fr_transport_t into multiple things:
	 *  - IO layer (read/write)
	 *  - protocol (encode, decode)
	 *  - management (recv_request, send_reply)
	 *  - process, which is a thing unto itself
	 *    - tho IO read/write have some overlap here, too...
	 */

	return 1;
}

static int compile_listen(CONF_SECTION *server, CONF_SECTION *cs)
{
	size_t i;
	pr_config_t config;
	uint8_t allowed_packets[FR_MAX_PACKET_CODE];

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

	memset(allowed_packets, 0, sizeof(allowed_packets));

	for (i = 0; i < talloc_array_length(config.types); i++) {
		if (compile_type(server, cs, config.types[i], allowed_packets) < 0) {
			cf_log_err_cs(server, "Failed compiling unlang for 'type = %s'",
				      config.types[i]);
			return -1;
		}
	}

	/*
	 *	Call transport-specific library to open the socket.
	 */
	if (compile_transport(server, cs, config.transport, allowed_packets) < 0) {
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


/** Compile the RADIUS protocol in a particular virtual server.
 *
 */
static fr_app_io_t *mod_compile(CONF_SECTION *cs)
{
//	CONF_PAIR *cp;
	CONF_SECTION *subcs;

	/*
	 *	Load all of the listen sections.  They do all of the
	 *	dirty work.
	 */
	for (subcs = cf_subsection_find_next(cs, NULL, "listen");
	     subcs != NULL;
	     subcs = cf_subsection_find_next(cs, cs, "listen")) {
		if (compile_listen(cs, subcs) < 0) {
			return NULL;
		}
	}

	/*
	 *	@todo - actually get the listeners, and add them to an
	 *	array. And what to do for virtual servers which don't
	 *	have a "listen" section?
	 */

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
			char const *value;
			dl_t const *module;
			fr_app_subtype_t const *app;

			value = cf_pair_value(cp);

			module = cf_data_find(cs, dl_t, value);
			if (cf_data_find(cs, char const *, value)) continue;

			app = (fr_app_subtype_t const *) module->common;
			if (app->compile(cs) < 0) {
				cf_log_err_cs(cs, "Failed compiling unlang for 'type = %s'", value);
				return NULL;
			}

			cf_data_add(cs, value, value, false);
		}
	}

	return NULL;
}

extern fr_app_t proto_radius;
fr_app_t proto_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.load		= mod_load,
	.bootstrap	= mod_bootstrap,
	.compile	= mod_compile,
};
