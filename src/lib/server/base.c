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
#include <freeradius-devel/server/module_rlm.h>

/** Initialize src/lib/server/
 *
 *  This is just so that the callers don't need to call a million functions.
 *
 *  @param[in] cs 	 The root configuration section.
 *  @param[in] conf_dir	 The path to the main configuration directory.
 *  @param[in] dict	 the main dictionary, usually the internal dictionary.
 *  @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int server_init(CONF_SECTION *cs, char const *conf_dir, fr_dict_t *dict)
{
	/*
	 *	Initialize the dictionary attributes needed by the tmpl code.
	 */
	if (tmpl_global_init() < 0) return -1;

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
	if (modules_rlm_bootstrap(cs) < 0) return -1;

	/*
	 *	Now all the modules and virtual servers have been bootstrapped,
	 *	we have all the dictionaries we're going to use in the server.
	 *
	 *	We can now register xlats for any protocol encoders/decoders.
	 *
	 *	Note: These xlats get freed automatically, so no explicit cleanup
	 *	is required.
	 */
	if (xlat_protocols_register() < 0) return -1;

	/*
	 *	Load in the custom dictionary.  We do this after the listeners
	 *	have loaded their relevant dictionaries, and after the modules
	 *	have created any attributes they need to, so that we can define
	 *	additional protocol attributes, and add
	 */
	switch (fr_dict_read(dict, conf_dir, FR_DICTIONARY_FILE)) {
	case -1:
		PERROR("Failed reading site-local dictionary");
		return -1;
	case 0:
		DEBUG2("Including dictionary file \"%s/%s\"", conf_dir, FR_DICTIONARY_FILE);
		break;

	default:
		break;
	}

	/*
	 *	Initialise the trigger rate limiting tree.
	 *
	 *	This must be done after the modules have been bootstrapped, so that
	 *	any xlat functions/dictionary attributes have been registered and
	 *	before the modules actually want to use triggers or open connections.
	 */
	if (trigger_init(cs) < 0) return -1;

	/*
	 *	And then load the virtual servers.
	 */
	if (virtual_servers_instantiate() < 0) return -1;

	/*
	 *	Instantiate the modules
	 */
	if (modules_rlm_instantiate() < 0) return -1;

	/*
	 *	Call xlat instantiation functions (after the xlats have been compiled)
	 */
	if (xlat_instantiate() < 0) return -1;

	/*
	 *	load the 'Net.' packet attributes.
	 */
	if (packet_global_init() < 0) return -1;

	fr_suid_up = rad_suid_up;
	fr_suid_down = rad_suid_down;

	return 0;
}

/** Free src/lib/server/
 *
 *  This is just so that the callers don't need to call a million functions.
 */
void server_free(void)
{
	/*
	 *	Free xlat instance data, and call any detach methods
	 */
	xlat_instances_free();

	fr_suid_up = fr_suid_noop;
	fr_suid_down = fr_suid_noop;
}
