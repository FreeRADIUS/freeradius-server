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

/**
 * $Id$
 *
 * @file map_builtin.c
 * @brief Built in map expansions.
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */


RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include "map.h"

static TALLOC_CTX *map_ctx;

static int list_map_verify(CONF_SECTION *cs, UNUSED void const *mod_inst, UNUSED void *proc_inst,
			   tmpl_t const *src, UNUSED map_list_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing source of value list");
		return -1;
	}

	return 0;
}

static int _list_map_proc_get_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
				    request_t *request, map_t const *map, void *uctx)
{
	fr_pair_t	*vp;
	fr_value_box_t	*value = talloc_get_type_abort(uctx, fr_value_box_t);

	vp = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs));
	if (!vp) return -1;

	if (fr_value_box_cast(vp, &vp->data, vp->data.type, vp->da, value) < 0) {
		RPEDEBUG("Failed casting %pR for attribute %s", value, vp->da->name);
		talloc_free(vp);
		return -1;
	}
	fr_pair_append(out, vp);

	return 0;
}

/** Map a list of value boxes to attributes using the index number in the list.
 */
static unlang_action_t mod_list_map_proc(unlang_result_t *p_result, UNUSED map_ctx_t const *mpctx, request_t *request,
					 fr_value_box_list_t *in, map_list_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	fr_value_box_t		*vb = NULL;
	fr_value_box_t		**values;
	uint32_t		index, i = 0, value_count = fr_value_box_list_num_elements(in);
	TALLOC_CTX		*local = talloc_new(NULL);
	map_t			*map = NULL;

	if (value_count == 0) goto finish;
	/*
	 *	Use an array to point to the list entries so we don't
	 *	repeatedly walk the list to find each index in the map.
	 */
	MEM(values = talloc_array(local, fr_value_box_t *, value_count));
	while ((vb = fr_value_box_list_next(in, vb))) values[i++] = vb;

	/*
	 *	Indexes are zero offset - so reduce value_count to the max index.
	 */
	value_count --;

	while ((map = map_list_next(maps, map))) {
		if (tmpl_aexpand(local, &index, request, map->rhs, NULL, NULL) < 0) {
			RPERROR("Failed expanding map RHS");
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
		if (index > value_count) {
			RWARN("Asked for index %d when max is %d.", index, value_count);
			continue;
		}
		if (values[index]->type == FR_TYPE_NULL) {
			RDEBUG2("Skipping null value for index %d.", index);
			continue;
		}

		if (map_to_request(request, map, _list_map_proc_get_value, values[index]) < 0) {
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
		rcode = RLM_MODULE_UPDATED;
	}

finish:
	talloc_free(local);

	RETURN_UNLANG_RCODE(rcode);
}

static int _map_global_init(UNUSED void *uctx)
{
	map_ctx = talloc_init("map");
	map_proc_register(map_ctx, NULL, "list", mod_list_map_proc, list_map_verify, 0, FR_VALUE_BOX_SAFE_FOR_ANY);
	return 0;
}

static int _map_global_free(UNUSED void *uctx)
{
	talloc_free(map_ctx);
	return 0;
}

int map_global_init(void)
{
	int ret;
	fr_atexit_global_once_ret(&ret, _map_global_init, _map_global_free, NULL);
	return ret;
}
