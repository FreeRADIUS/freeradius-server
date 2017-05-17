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


/** Compile the RADIUS protocol in a particular virtual server.
 *
 */
static fr_app_io_t *proto_radius_compile(UNUSED CONF_SECTION *cs)
{

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
