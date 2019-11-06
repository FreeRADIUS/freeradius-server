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
#include <freeradius-devel/util/version.h>

#include <talloc.h>
#include <stdbool.h>

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

typedef struct dl_loader_s dl_loader_t;

/** Module handle
 *
 * Contains module's dlhandle, and the functions it exports.
 */
typedef struct dl_s {
	char const		*name;		//!< Name of the module e.g. sql.
	void			*handle;	//!< Handle returned by dlopen.
	dl_loader_t		*loader;	//!< Loader that owns this dl.

	void			*uctx;		//!< API client's opaque data.
	bool			uctx_free;	//!< Free opaque data on dl_t free (usually false).
	bool			in_tree;	//!< Whether this dl is registered in the dl_tree.
} dl_t;

/** Callback to call when a module is first loaded
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	which, if present, will trigger this callback.
 * @param[in] user_ctx	passed to dl_loader_init_register.
 * @return
 *	- 0 on success.
 *	- -1 on failure
 */
typedef int (*dl_onload_t)(dl_t const *module, void *symbol, void *user_ctx);


/** Callback when a module is destroyed
 *
 * @param[in] module	being loaded.
 * @param[in] symbol	which, if present, will trigger this callback.
 * @param[in] user_ctx	passed to dl_loader_init_register
 */
typedef void (*dl_unload_t)(dl_t const *module, void *symbol, void *user_ctx);

/*
 *	Functions
 */
void			*dl_open_by_sym(char const *sym_name, int flags);

int			dl_symbol_init(dl_loader_t *dl_loader, dl_t const *dl);

int			dl_symbol_init_cb_register(dl_loader_t *dl_loader,
						   unsigned int priority, char const *symbol,
						   dl_onload_t func, void *ctx);

void			dl_symbol_init_cb_unregister(dl_loader_t *dl_loader,
						     char const *symbol, dl_onload_t func);

int			dl_symbol_free_cb_register(dl_loader_t *dl_loader,
						   unsigned int priority, char const *symbol,
						   dl_unload_t func, void *ctx);

void			dl_symbol_free_cb_unregister(dl_loader_t *dl_loader,
						     char const *symbol, dl_unload_t func);

dl_t			*dl_by_name(dl_loader_t *dl_loader, char const *name,
				    void *uctx, bool uctx_free);

int			dl_free(dl_t const **dl);

char const		*dl_search_path(dl_loader_t *dl_loader);

int			dl_search_path_set(dl_loader_t *dl_loader, char const *lib_dir) CC_HINT(nonnull);

void			*dl_loader_uctx(dl_loader_t *dl_loader);

dl_loader_t		*dl_loader_init(TALLOC_CTX *ctx, char const *lib_dir,
					void *uctx, bool uctx_free, bool defer_symbol_init);
#ifdef __cplusplus
}
#endif
