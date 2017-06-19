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

#ifdef __cplusplus
extern "C" {
#endif

/** Per instance data
 *
 * Per-instance data structure, to correlate the modules with the
 * instance names (may NOT be the module names!), and the per-instance
 * data structures.
 */
typedef struct {
	char const			*name;		//!< Instance name e.g. user_database.

	dl_instance_t			*dl_inst;	//!< Structure containing the module's instance data,
							//!< configuration, and dl handle.

	rad_module_t const		*module;	//!< Public module structure.  Cached for convenience.

	pthread_mutex_t			*mutex;

	bool				instantiated;	//!< Whether the module has been instantiated yet.

	bool				force;		//!< Force the module to return a specific code.
							//!< Usually set via an administrative interface.

	rlm_rcode_t			code;		//!< Code module will return when 'force' has
							//!< has been set to true.
} module_instance_t;

/** Per thread per instance data
 *
 * Stores module and thread specific data.
 */
typedef struct {
	module_instance_t		*inst;		//!< Non-thread local instance of this

	void				*data;		//!< Thread specific instance data.

	uint64_t			total_calls;	//! total number of times we've been called
	uint64_t			active_callers; //! number of active callers.  i.e. number of current yields
} module_thread_instance_t;

module_instance_t	*module_find_with_method(rlm_components_t *method,
						 CONF_SECTION *modules, char const *asked_name);
module_instance_t	*module_find(CONF_SECTION *modules, char const *asked_name);
int			module_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name);
int			unlang_fixup_update(vp_map_t *map, void *ctx);

#ifdef __cplusplus
}
#endif

#endif	/* _FR_MODPRIV_H */
