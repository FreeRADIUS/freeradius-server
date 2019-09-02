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

#include <freeradius-devel/util/version.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/server/cf_parse.h>

#ifdef __cplusplus
extern "C" {
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
#define RLM_MODULE_INIT RADIUSD_MAGIC_NUMBER

typedef enum {
	DL_MODULE_TYPE_MODULE = 0,	//!< Standard loadable module.
	DL_MODULE_TYPE_PROTO,		//!< Protocol module.
	DL_MODULE_TYPE_SUBMODULE	//!< Driver (or method in the case of EAP)
} dl_module_type_t;

/** Callback priorities
 *
 * The higher the priority, the earlier in callback gets called.
 */
#define DL_PRIORITY_DICT	30		//!< Callback priority for dictionary autoloading
#define DL_PRIORITY_DICT_ATTR	20		//!< Callback priority for attribute resolution
#define DL_PRIORITY_BOOTSTRAP	10		//!< Callback priority for bootstrap callback

typedef struct dl_module_loader_s dl_module_loader_t;

/** Module detach callback
 *
 * Is called just before the server exits, and after re-instantiation on HUP,
 * to free the old module instance.
 *
 * Detach should close all handles associated with the module instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] instance to free.
 * @return
 *	- 0 on success.
 *	- -1 if detach failed.
 */
typedef int (*module_detach_t)(void *instance);

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
 */
#define DL_MODULE_COMMON \
	struct { \
		uint64_t 			magic;		\
		char const			*name;		\
		size_t				inst_size;	\
		char const			*inst_type;	\
		CONF_PARSER const		*config;        \
		dl_module_onload_t		onload;         \
		dl_module_unload_t		unload;		\
		module_detach_t			detach;		\
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
	dl_t				*dl;		//!< Dynamic loader handle.

	dl_module_t const		*parent;	//!< of this module.

	dl_module_type_t		type;		//!< of this module.

	dl_module_common_t const	*common;	//!< Symbol exported by the module, containing its public
							//!< functions, name and behaviour control flags.

	CONF_SECTION			*conf;		//!< The module's global configuration
							///< (as opposed to the instance, configuration).
							///< May be NULL.
	bool				in_tree;
};

/** A module/inst tuple
 *
 * Used to pass data back from dl_module_instance_parse_func
 */
typedef struct dl_module_instance_s dl_module_inst_t;
struct dl_module_instance_s {
	char const		*name;			//!< Instance name.
	dl_module_t const	*module;		//!< Module
	void			*data;			//!< Module instance's parsed configuration.
	CONF_SECTION		*conf;			//!< Module's instance configuration.
	dl_module_inst_t const	*parent;		//!< Parent module's instance (if any).
};

/** Callback priorities
 *
 * The higher the priority, the earlier in callback gets called.
 */
#define DL_PRIORITY_DICT	30			//!< Callback priority for dictionary autoloading
#define DL_PRIORITY_DICT_ATTR	20			//!< Callback priority for attribute resolution
#define DL_PRIORITY_BOOTSTRAP	10			//!< Callback priority for bootstrap callback

dl_module_t const	*dl_module(CONF_SECTION *conf, dl_module_t const *parent,
				   char const *name, dl_module_type_t type);

dl_module_inst_t const	*dl_module_instance_by_data(void const *data);

char const		*dl_module_instance_name_by_data(void const *data);

void			*dl_module_parent_data_by_child_data(void const *data);

void			*dl_module_instance_symbol(dl_module_inst_t const *instance, char const *sym_name);

int			dl_module_instance(TALLOC_CTX *ctx, dl_module_inst_t **out,
					   CONF_SECTION *conf, dl_module_inst_t const *parent,
					   char const *name, dl_module_type_t type);

char const		*dl_module_search_path(void);

dl_loader_t		*dl_loader_from_module_loader(dl_module_loader_t *dl_module_loader);

dl_module_loader_t	*dl_module_loader_init(char const *lib_dir);

#ifdef __cplusplus
}
#endif
