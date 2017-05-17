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
static int proto_radius_load(void)
{
	/*
	 *	@todo - load the RADIUS dictionaries
	 */

	return 0;
}

/** Bootstrap the RADIUS protocol in a particular virtual server.
 *
 */
static int proto_radius_bootstrap(UNUSED CONF_SECTION *cs)
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


/** Compile the RADIUS protocol in a particular virtual server.
 *
 */
static fr_app_io_t *proto_radius_compile(CONF_SECTION *cs)
{
	int i;
	char const *value, *lib;
	dl_t const *module;
	fr_app_subtype_t const *app;
	CONF_PAIR *cp;

	cp = cf_pair_find(cs, "type");
	if (!cp) {
		cf_log_err_cs(cs, "Failed to find 'type'");
		return NULL;
	}

	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err_cs(cs, "Invalid value for 'type'");
		return NULL;
	}

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
		cf_log_err_cs(cs, "Unknown packet type %s", value);
		return NULL;
	}

	module = dl_module(cs, NULL, lib, DL_TYPE_PROTO);
	if (!module) {
		cf_log_err_cs(cs, "Failed finding submodule library for %s", value);
		return NULL;
	}

	app = (fr_app_subtype_t const *) module->common;

	if (app->compile(cs) < 0) {
		cf_log_err_cs(cs, "Failed compiling unlang for 'type = %s'", value);
		return NULL;
	}

	/*
	 *	cf_data_add?
	 */

	return NULL;
}

extern fr_app_t proto_radius;
fr_app_t proto_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.load		= proto_radius_load,
	.bootstrap	= proto_radius_bootstrap,
	.compile	= proto_radius_compile,
};
