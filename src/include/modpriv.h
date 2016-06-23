/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef _FR_MODPRIV_H
#define _FR_MODPRIV_H
/**
 * $Id$
 *
 * @file modpriv.h
 * @brief Stuff needed by both modules.c and modcall.c, but should not be
 *	accessed from anywhere else.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(modpriv_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifndef HAVE_DLFCN_H
#error FreeRADIUS needs a working dlopen()
#else
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Module handle
 *
 * Contains module's dlhandle, and the functions it exports.
 */
typedef struct module_handle {
	char const			*name;		//!< Name of the module e.g. sql.
	module_t const			*module;	//!< Symbol exported by the module, containing its public
							//!< functions, name and behaviour control flags.
	void				*handle;	//!< Handle returned by dlopen.
} module_dl_t;

typedef struct fr_module_hup_t fr_module_hup_t;

/** Per instance data
 *
 * Per-instance data structure, to correlate the modules with the
 * instance names (may NOT be the module names!), and the per-instance
 * data structures.
 */
typedef struct module_instance_t {
	char const			*name;		//!< Instance name e.g. user_database.

	module_t const			*module;	//!< Module this is an instance of.

	void				*data;		//!< The module's private instance data, containing.
							//!< its parsed configuration and static state.
	pthread_mutex_t			*mutex;

	CONF_SECTION			*cs;		//!< Configuration section in modules {}.

	time_t				last_hup;	//!< Last time the module was 'hupped'.

	bool				instantiated;	//!< Whether the module has been instantiated yet.

	bool				force;		//!< Force the module to return a specific code.
							//!< Usually set via an administrative interface.

	rlm_rcode_t			code;		//!< Code module will return when 'force' has
							//!< has been set to true.
	fr_module_hup_t	       		*hup;		//!< Previous versions of the module's
							//!< instance data.
} module_instance_t;

void			*module_dlopen_by_name(char const *name);
module_instance_t	*module_instantiate(CONF_SECTION *modules, char const *asked_name);
module_instance_t	*module_instantiate_method(CONF_SECTION *modules, char const *asked_name,
						   rlm_components_t *method);
module_instance_t	*module_find(CONF_SECTION *modules, char const *asked_name);
int			module_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name);
int			module_hup(CONF_SECTION *cs, module_instance_t *node, time_t when);

#ifdef __cplusplus
}
#endif

#endif	/* _FR_MODPRIV_H */
