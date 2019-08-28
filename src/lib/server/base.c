/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file src/lib/server/base.c
 * @brief Functions to bootstrap this library
 *
 * @copyright 2019 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>

/** Initialize src/lib/server/
 *
 *  This is just so that the callers don't need to call a million functions.
 *
 *  @param cs The root configuration section.
 *  @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int server_init(CONF_SECTION *cs)
{
	/*
	 *	Initialise the trigger rate limiting tree
	 */
	if (trigger_exec_init(cs) < 0) return -1;

	/*
	 *	Explicitly initialise the xlat tree, and perform dictionary lookups.
	 */
	if (xlat_init() < 0) return -1;

	/*
	 *	Instantiate "permanent" paircmps
	 */
	if (paircmp_init() < 0) return -1;

	/*
	 *	Set up dictionaries and attributes for password comparisons
	 */
	if (password_init() < 0) return -1;

	/*
	 *	Initialize Auth-Type, etc. in the virtual servers
	 *	before loading the modules.  Some modules need those
	 *	to be defined.
	 */
	if (virtual_servers_bootstrap(cs) < 0) return -1;

	/*
	 *	Bootstrap the modules.  This links to them, and runs
	 *	their "bootstrap" routines.
	 *
	 *	After this step, all dynamic attributes, xlats, etc. are defined.
	 */
	if (modules_bootstrap(cs) < 0) return -1;

	/*
	 *	And then load the virtual servers.
	 */
	if (virtual_servers_instantiate() < 0) return -1;

	/*
	 *	Instantiate the modules
	 */
	if (modules_instantiate() < 0) return -1;

	/*
	 *	Call xlat instantiation functions (after the xlats have been compiled)
	 */
	if (xlat_instantiate() < 0) return -1;

	return 0;
}

/** Free src/lib/server/
 *
 *  This is just so that the callers don't need to call a million functions.
 */
void server_free(void)
{
	/*
	 *	Free password dictionaries
	 */
	password_free();

	/*
	 *	Free xlat instance data, and call any detach methods
	 */
	xlat_instances_free();

	/*
	 *	Detach modules, connection pools, registered xlats / paircmps / maps.
	 */
	modules_free();

	/*
	 *	The only paircmps remaining are the ones registered by the server core.
	 */
	paircmp_free();

	/*
	 *	The only xlats remaining are the ones registered by the server core.
	 */
	xlat_free();

	/*
	 *	The only maps remaining are the ones registered by the server core.
	 */
	map_proc_free();

	/*
	 *	Free information associated with the virtual servers.
	 */
	virtual_servers_free();
}
