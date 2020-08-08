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
 * @file lib/server/map_proc.h
 * @brief Structures and prototypes for map functions
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Arran Cudbard-bell (a.cudbardb@freeradius.org)
 */
RCSIDH(map_proc_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_proc map_proc_t;
typedef struct map_proc_inst map_proc_inst_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/map.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Function to evaluate the src string and map the result to server attributes
 *
 * @param[in] mod_inst		Instance of the module that registered the map_proc.
 * @param[in] proc_inst		Map proc data created by #map_proc_instantiate_t.
 * @param[in] request		The current request.
 * @param[in,out] result	Input data for the map processor.  May be consumed by the
 *				map processor.
 * @param[in] maps		Head of the list of maps to process.
 * @return
 *	- #RLM_MODULE_NOOP - If no data available for given src, or no mappings matched available data.
 *	- #RLM_MODULE_UPDATED - If new pairs were added to the request.
 *	- #RLM_MODULE_FAIL - If an error occurred performing the mapping.
 */
typedef rlm_rcode_t (*map_proc_func_t)(void *mod_inst, void *proc_inst, REQUEST *request,
				       fr_value_box_t **result, vp_map_t const *maps);

/** Allocate new instance data for a map processor
 *
 * @param[in] cs		#CONF_SECTION representing this instance of a map processor.
 * @param[in] mod_inst		Module instance that registered the #map_proc_t.
 * @param[in] proc_inst		Structure to populate. Allocated by #map_proc_instantiate.
 * @param[in] src		template.
 * @param[in] maps		Head of the list of maps to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*map_proc_instantiate_t)(CONF_SECTION *cs, void *mod_inst, void *proc_inst,
				      tmpl_t const *src, vp_map_t const *maps);

map_proc_t	*map_proc_find(char const *name);

void		map_proc_free(void);
int		map_proc_register(void *mod_inst, char const *name,
				  map_proc_func_t evaluate,
				  map_proc_instantiate_t instantiate, size_t inst_size);

map_proc_inst_t *map_proc_instantiate(TALLOC_CTX *ctx, map_proc_t const *proc,
				      CONF_SECTION *cs, tmpl_t const *src, vp_map_t const *maps);

rlm_rcode_t	map_proc(REQUEST *request, map_proc_inst_t const *inst, fr_value_box_t **src);

#ifdef __cplusplus
}
#endif
