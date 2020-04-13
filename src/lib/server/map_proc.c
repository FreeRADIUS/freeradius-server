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

/*
 * $Id$
 *
 * @brief Map processor functions
 * @file src/lib/server/map_proc.c
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Arran Cudbard-bell (a.cudbardb@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map_proc_priv.h>
#include <freeradius-devel/util/debug.h>

static rbtree_t *map_proc_root = NULL;

/** Compare two map_proc_t structs, based ONLY on the name
 *
 * @param[in] one First map struct.
 * @param[in] two Second map struct.
 * @return Integer specifying order of map func instances.
 */
static int map_proc_cmp(void const *one, void const *two)
{
	map_proc_t const *a = one, *b = two;

	if (a->length != b->length) return a->length - b->length;

	return memcmp(a->name, b->name, a->length);
}

/** Unregister a map processor
 *
 * @param[in] proc to unregister.
 */
static int _map_proc_talloc_free(map_proc_t *proc)
{
	map_proc_t find;
	map_proc_t *found;

	if (!map_proc_root) return 0;

	strlcpy(find.name, proc->name, sizeof(find.name));
	find.length = strlen(find.name);

	found = rbtree_finddata(map_proc_root, &find);
	if (!found) return 0;

	rbtree_deletebydata(map_proc_root, found);

	return 0;
}

static void _map_proc_tree_free(void *proc)
{
	talloc_free(proc);
}

/** Find a map processor by name
 *
 * @param[in] name of map processor.
 * @return
 *	- #map_proc matching name.
 *	- NULL if none was found.
 */
map_proc_t *map_proc_find(char const *name)
{
	map_proc_t find;

	if (!map_proc_root) return NULL;

	strlcpy(find.name, name, sizeof(find.name));
	find.length = strlen(find.name);

	return rbtree_finddata(map_proc_root, &find);
}

/** Register a map processor
 *
 * This should be called by every module that provides a map processing function.
 *
 * @param[in] mod_inst		of module registering the map_proc.
 * @param[in] name		of map processor. If processor already exists, it is replaced.
 * @param[in] evaluate		Module's map processor function.
 * @param[in] instantiate	function (optional).
 * @param[in] inst_size		of talloc chunk to allocate for instance data (optional).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_proc_register(void *mod_inst, char const *name,
		      map_proc_func_t evaluate,
		      map_proc_instantiate_t instantiate, size_t inst_size)
{
	map_proc_t *proc;

	fr_assert(name && name[0]);

	if (!map_proc_root) {
		map_proc_root = rbtree_talloc_create(NULL, map_proc_cmp, map_proc_t,
						     _map_proc_tree_free, RBTREE_FLAG_REPLACE);
		if (!map_proc_root) {
			DEBUG("map_proc: Failed to create tree");
			return -1;
		}
	}

	/*
	 *	If it already exists, replace it.
	 */
	proc = map_proc_find(name);
	if (!proc) {
		rbnode_t *node;

		proc = talloc_zero(mod_inst, map_proc_t);
		strlcpy(proc->name, name, sizeof(proc->name));
		proc->length = strlen(proc->name);

		node = rbtree_insert_node(map_proc_root, proc);
		if (!node) {
			talloc_free(proc);
			return -1;
		}

		talloc_set_destructor(proc, _map_proc_talloc_free);
	}

	DEBUG3("map_proc_register: %s", proc->name);

	proc->mod_inst = mod_inst;
	proc->evaluate = evaluate;
	proc->instantiate = instantiate;
	proc->inst_size = inst_size;

	return 0;
}

/** Create a new map proc instance
 *
 * This should be called for every map {} section in the configuration.
 *
 * @param[in] ctx	to allocate proc instance in.
 * @param[in] proc	resolved with #map_proc_find.
 * @param[in] cs	#CONF_SECTION representing this instance of a map processor.
 * @param[in] src	template.
 * @param[in] maps	Head of the list of maps.
 * @return
 *	- New #map_proc_inst_t on success.
 *	- NULL on error.
 */
map_proc_inst_t *map_proc_instantiate(TALLOC_CTX *ctx, map_proc_t const *proc,
				      CONF_SECTION *cs, vp_tmpl_t const *src, vp_map_t const *maps)
{
	map_proc_inst_t *inst;

	inst = talloc_zero(ctx, map_proc_inst_t);
	inst->proc = proc;
	inst->src = src;
	inst->maps = maps;

	if (proc->instantiate) {
		if (proc->inst_size > 0) {
			inst->data = talloc_zero_array(inst, uint8_t, proc->inst_size);
			if (!inst->data) return NULL;
		}

		if (proc->instantiate(cs, proc->mod_inst, inst->data, src, maps) < 0) {
			talloc_free(inst);
			return NULL;
		}
	}

	return inst;
}

/** Evaluate a set of maps using the specified map processor
 *
 * Evaluate the map processor src template, then call a map processor function to do
 * something with the expanded src template and map the result to attributes in the request.
 *
 * @param[in] request		The current request.
 * @param[in] inst		of a map processor.
 * @param[in,out] result	Result of expanding the map input.  May be consumed
 *				by the map processor.
 */
rlm_rcode_t map_proc(REQUEST *request, map_proc_inst_t const *inst, fr_value_box_t **result)
{
	return inst->proc->evaluate(inst->proc->mod_inst, inst->data, request, result, inst->maps);
}

/** Free all map_processors unregistering them
 *
 */
void map_proc_free(void)
{
	rbtree_t *mpr = map_proc_root;

	map_proc_root = NULL;
	talloc_free(mpr);
}
