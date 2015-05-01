/*
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
 */
#ifndef MAP_PROC_H
#define MAP_PROC_H
/**
 * $Id$
 *
 * @file map_proc.h
 * @brief Structures and prototypes for map functions
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Arran Cudbard-bell <a.cudbardb@freeradius.org>
 */

RCSIDH(map_proc_h, "$Id$")

#include <freeradius-devel/conffile.h>
#include <freeradius-devel/tmpl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_proc map_proc_t;

/** Map processor instance
 *
 * Every time a map processor is called in the virtual server config
 * a new instance structure should be allocated.
 */
typedef struct map_proc_inst {
	map_proc_t const	*proc;		//!< Map processor.
	vp_tmpl_t const		*src;		//!< Evaluated to provide source value for map processor.
	vp_map_t const		*maps;		//!< Head of the map list.
	void			*cache;		//!< Cache structure passed to the map processor.
} map_proc_inst_t;

/** Function to evaluate the src string and map the result to server attributes
 *
 * @param[in] request The current request.
 * @param[in] src Talloced buffer, the result of evaluating the src #vp_tmpl_t.
 * @param[in] maps Head of the list of maps to process.
 * @param[in] cache structure created by the #map_proc_cache_cb_t, or NULL if no cache cb was
 *	provided.
 * @param[in] func_ctx passed to #map_proc_register.
 */
typedef rlm_rcode_t (*map_proc_func_t)(REQUEST *request, char const *src,
				       vp_map_t const *maps, void *cache, void *func_ctx);

/** Allocate new instance data for a map processor
 *
 * @param[in,out] ctx to allocate cache structure in.
 * @param[out] out Where to write pointer to new cache struct.
 * @param[in] src template.
 * @param[in] maps Head of the list of maps.
 * @param[in] func_ctx passed to #map_proc_register.
 */
typedef int (*map_proc_cache_alloc_t)(TALLOC_CTX *ctx, void **out,
				      vp_tmpl_t const *src, vp_map_t const *maps, void *func_ctx);

map_proc_t	*map_proc_find(char const *name);
int		map_proc_register(TALLOC_CTX *ctx, char const *name, map_proc_func_t func,
				  void *func_ctx, RADIUS_ESCAPE_STRING escape, void *escape_ctx,
				  map_proc_cache_alloc_t cache_alloc);
map_proc_inst_t *map_proc_instantiate(TALLOC_CTX *ctx, map_proc_t const *proc,
				      vp_tmpl_t const *src, vp_map_t const *maps);
rlm_rcode_t	map_proc(REQUEST *request, map_proc_inst_t const *inst);

#ifdef __cplusplus
}
#endif
#endif	/* MAP_PROC_H */
