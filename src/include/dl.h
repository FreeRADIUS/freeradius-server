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
#ifndef _RAD_DL_H
#define _RAD_DL_H
/**
 * $Id$
 *
 * @file dl.h
 * @brief Wrappers around dlopen.
 *
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(dl_h, "$Id$")

#ifndef HAVE_DLFCN_H
#  error FreeRADIUS needs a working dlopen()
#else
#  include <dlfcn.h>
#endif

#include <freeradius-devel/version.h>
#include <freeradius-devel/conffile.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stop people using different module/library/server versions together
 *
 */
#define RLM_MODULE_INIT RADIUSD_MAGIC_NUMBER

/** Called when a module is first loaded
 *
 * Used to perform global library initialisation.
 *
 * If any handles are required for the call to module_unload they should be
 * stored as static variables within the module.
 *
 * @note module_unload will not be called unless this callback returns 0.
 *	The callback should free any resources allocated if it errors out.
 *
 * @return
 *	- 0 on success.
 *	- -1 if initialisation failed.
 */
typedef int (*module_load_t)(void);

/** Called when the module is about to be unloaded (all instances destroyed)
 *
 * Used to perform global library unload.
 *
 * Should free any memory allocated by the library during the call to on_load.
 */
typedef void (*module_unload_t)(void);

/** Common fields for the interface struct modules export
 *
 */
#define RAD_MODULE_COMMON \
	struct { \
		uint64_t 		magic;		\
		char const		*name;		\
		size_t			inst_size;	\
		CONF_PARSER const	*config;        \
		module_load_t		load;           \
		module_unload_t		unload;		\
	}

/** Fields common to all types of loadable modules
 *
 */
typedef struct dl_module_common {
	RAD_MODULE_COMMON;
} dl_module_common_t;

/** Module handle
 *
 * Contains module's dlhandle, and the functions it exports.
 */
typedef struct dl_module {
	char const			*name;		//!< Name of the module e.g. sql.
	CONF_SECTION			*conf;		//!< Module's configuration section.
	dl_module_common_t const	*common;	//!< Symbol exported by the module, containing its public
							//!< functions, name and behaviour control flags.
	void				*handle;	//!< Handle returned by dlopen.
} dl_module_t;

dl_module_t const	*dl_module(CONF_SECTION *conf, char const *name, char const *prefix);

#ifdef __cplusplus
}
#endif

#endif	/* _RAD_DL_H */
