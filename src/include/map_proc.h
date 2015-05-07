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
typedef struct map_proc_inst map_proc_inst_t;

/** Function to evaluate the src string and map the result to server attributes
 *
 * @param[in] mod_inst Instance of the module that registered the map_proc.
 * @param[in] proc_inst Map proc data created by #map_proc_instantiate_t.
 * @param[in] request The current request.
 * @param[in] src Talloced buffer, the result of evaluating the src #vp_tmpl_t.
 * @param[in] maps Head of the list of maps to process.
 * @return
 *	- #RLM_MODULE_NOOP - If no data available for given src, or no mappings matched available data.
 *	- #RLM_MODULE_UPDATED - If new pairs were added to the request.
 *	- #RLM_MODULE_FAIL - If an error occurred performing the mapping.
 */
typedef rlm_rcode_t (*map_proc_func_t)(void *mod_inst, void *proc_inst, REQUEST *request,
				       char const *src, vp_map_t const *maps);

/** Allocate new instance data for a map processor
 *
 * @param[out] proc_inst Structure to populate. Allocated by #map_proc_instantiate.
 * @param[in] mod_inst Module instance that registered the #map_proc_t.
 * @param[in] src template.
 * @param[in] maps Head of the list of maps to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*map_proc_instantiate_t)(void *proc_inst, void *mod_inst, vp_tmpl_t const *src, vp_map_t const *maps);

map_proc_t	*map_proc_find(char const *name);

int		map_proc_register(void *mod_inst, char const *name,
				  map_proc_func_t evaluate,
				  xlat_escape_t escape,
				  map_proc_instantiate_t instantiate, size_t inst_size);

map_proc_inst_t *map_proc_instantiate(TALLOC_CTX *ctx, map_proc_t const *proc,
				      vp_tmpl_t const *src, vp_map_t const *maps);

rlm_rcode_t	map_proc(REQUEST *request, map_proc_inst_t const *inst);

#ifdef __cplusplus
}
#endif
#endif	/* MAP_PROC_H */
