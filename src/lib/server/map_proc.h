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
#include <freeradius-devel/util/value.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Function to evaluate the src string and map the result to server attributes
 *
 * @param[out] p_result		Result of applying the map:
 *	- #RLM_MODULE_NOOP - If no data available for given src, or no mappings matched available data.
 *	- #RLM_MODULE_UPDATED - If new pairs were added to the request.
 *	- #RLM_MODULE_FAIL - If an error occurred performing the mapping.
 * @param[in] mod_inst		Instance of the module that registered the map_proc.
 * @param[in] proc_inst		Map proc data created by #map_proc_instantiate_t.
 * @param[in] request		The current request.
 * @param[in,out] result	Input data for the map processor.  May be consumed by the
 *				map processor.
 * @param[in] maps		Head of the list of maps to process.
 * @return one of UNLANG_ACTION_*
 */
typedef unlang_action_t (*map_proc_func_t)(rlm_rcode_t *p_result, void const *mod_inst, void *proc_inst, request_t *request,
					   fr_value_box_list_t *result, map_list_t const *maps);

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
typedef int (*map_proc_instantiate_t)(CONF_SECTION *cs, void const *mod_inst, void *proc_inst,
				      tmpl_t const *src, map_list_t const *maps);

fr_value_box_safe_for_t	map_proc_literals_safe_for(map_proc_t const *proc);

map_proc_t	*map_proc_find(char const *name);

int		map_proc_register(TALLOC_CTX *ctx, void const *mod_inst, char const *name,
				  map_proc_func_t evaluate,
				  map_proc_instantiate_t instantiate, size_t inst_size, fr_value_box_safe_for_t safe_for);

int		map_proc_unregister(char const *name);

map_proc_inst_t *map_proc_instantiate(TALLOC_CTX *ctx, map_proc_t const *proc,
				      CONF_SECTION *cs, tmpl_t const *src, map_list_t const *maps);

unlang_action_t	map_proc(rlm_rcode_t *p_result, request_t *request, map_proc_inst_t const *inst, fr_value_box_list_t *src);

#ifdef __cplusplus
}
#endif
