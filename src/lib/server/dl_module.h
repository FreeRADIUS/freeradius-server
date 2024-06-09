#pragma once
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

/**
 * $Id$
 *
 * @file dl_module.h
 * @brief Wrappers around dlopen to manage loading modules at runtime.
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 */
RCSIDH(dl_module_h, "$Id$")

#ifndef HAVE_DLFCN_H
#  error FreeRADIUS needs a working dlopen()
#else
#  include <dlfcn.h>
#endif

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _DL_MODULE_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

#ifdef __APPLE__
#  define DL_EXTENSION ".dylib"
#elif defined (WIN32)
#  define DL_EXTENSION ".dll"
#else
#  define DL_EXTENSION ".so"
#endif

/** Stop people using different module/library/server versions together
 *
 */
#define MODULE_MAGIC_INIT RADIUSD_MAGIC_NUMBER

typedef enum {
	DL_MODULE_TYPE_MODULE = 0,	//!< Standard loadable module.
	DL_MODULE_TYPE_PROTO,		//!< Protocol module.
	DL_MODULE_TYPE_PROCESS,		//!< protocol processor.
	DL_MODULE_TYPE_SUBMODULE	//!< Driver (or method in the case of EAP)
} dl_module_type_t;

/** Callback priorities
 *
 * The higher the priority, the earlier in callback gets called.
 */
#define DL_PRIORITY_DICT	30		//!< Callback priority for dictionary autoloading
#define DL_PRIORITY_DICT_ATTR	29		//!< Callback priority for attribute resolution
#define DL_PRIORITY_DICT_ENUM	28		//!< Callback priority for enum resolution
#define DL_PRIORITY_LIB		20		//!< Callback priority for library config
#define DL_PRIORITY_BOOTSTRAP	10		//!< Callback priority for bootstrap callback

typedef struct dl_module_loader_s dl_module_loader_t;

/** Callback to call when a module is first loaded
 *
 */
typedef int (*dl_module_onload_t)(void);

/** Callback when a module is destroyed
 *
 */
typedef void (*dl_module_unload_t)(void);

/** Common fields for the interface struct modules export
 *
 * These are just enough for the loader to be able to load and unload the module.
 */
#define DL_MODULE_COMMON \
	struct { \
		uint64_t 			magic;		\
		char const			*name;		\
		dl_module_onload_t		onload;         \
		dl_module_unload_t		unload;		\
	}

/** Fields common to all types of loadable modules
 */
typedef struct {
	DL_MODULE_COMMON;
} dl_module_common_t;

/** Module handle
 *
 * Contains module's dlhandle, and the functions it exports.
 */
typedef struct dl_module_s dl_module_t;
struct dl_module_s {
	char const			* _CONST name;		//!< Name of the module. The name passed to dl_module_alloc.

	dl_module_loader_t		* _CONST loader;	//!< Loader that owns this dl.

	dl_t				* _CONST dl;		//!< Dynamic loader handle.

	dl_module_t const		* _CONST parent;	//!< of this module.

	dl_module_type_t		_CONST type;		//!< of this module.

	dl_module_common_t		*exported;		//!< Symbol exported by the module, containing its public
								//!< functions, name and behaviour control flags.

	CONF_SECTION			* _CONST conf;		//!< The module's global configuration
								///< (as opposed to the instance, configuration).
								///< May be NULL.

	unsigned int			refs;			//!< Number of references to this module.
								///< This is maintained as a separate counter
								///< (instead of using talloc refs) because it needs
								///< to be thread safe.
								///< The talloc code accesses the chunk after calling
								///< the destructor, so we can't lock the loader mutex
								///< inside the destructor and expect things to work
								///< correctly.
	bool				_CONST in_tree;
};

extern fr_table_num_sorted_t const dl_module_type_prefix[];
extern size_t dl_module_type_prefix_len;

int 			dl_module_free(dl_module_t *dl_module);

dl_module_t		*dl_module_alloc(dl_module_t const *parent, char const *name, dl_module_type_t type);

char const		*dl_module_search_path(void);

dl_loader_t		*dl_loader_from_module_loader(dl_module_loader_t *dl_module_loader);

dl_module_loader_t	*dl_module_loader_init(char const *lib_dir);

#undef _CONST

#ifdef __cplusplus
}
#endif
