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
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/map_proc_priv.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/talloc.h>

static fr_rb_tree_t *map_proc_root = NULL;

/** Compare two map_proc_t structs, based ONLY on the name
 *
 * @param[in] one First map struct.
 * @param[in] two Second map struct.
 * @return Integer specifying order of map func instances.
 */
static int8_t map_proc_cmp(void const *one, void const *two)
{
	map_proc_t const *a = one, *b = two;

	MEMCMP_RETURN(a, b, name, length);
	return 0;
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

	found = fr_rb_find(map_proc_root, &find);
	if (!found) return 0;

	fr_rb_delete(map_proc_root, found);

	return 0;
}

fr_value_box_safe_for_t map_proc_literals_safe_for(map_proc_t const *proc)
{
	return proc->literals_safe_for;
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

	return fr_rb_find(map_proc_root, &find);
}

static int _map_proc_tree_init(UNUSED void *uctx)
{
	MEM(map_proc_root = fr_rb_inline_talloc_alloc(NULL, map_proc_t, node, map_proc_cmp, NULL));
	return 0;
}

static int _map_proc_tree_free(UNUSED void *uctx)
{
	fr_rb_tree_t *mpr = map_proc_root;

	fr_assert_msg(fr_rb_num_elements(mpr) == 0, "map_proc_t still registered");

	map_proc_root = NULL;
	talloc_free(mpr);
	return 0;
}

/** Register a map processor
 *
 * This should be called by every module that provides a map processing function.
 *
 * @param[in] ctx		if non-null, the ctx to bind this map processor to.
 * @param[in] mod_inst		of module registering the map_proc.
 * @param[in] name		of map processor. If processor already exists, it is replaced.
 * @param[in] evaluate		Module's map processor function.
 * @param[in] instantiate	function (optional).
 * @param[in] inst_size		of talloc chunk to allocate for instance data (optional).
 * @param[in] literals_safe_for	What safe_for value to assign to literals.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int map_proc_register(TALLOC_CTX *ctx, void const *mod_inst, char const *name,
		      map_proc_func_t evaluate,
		      map_proc_instantiate_t instantiate, size_t inst_size, fr_value_box_safe_for_t literals_safe_for)
{
	map_proc_t *proc;

	fr_assert(name && name[0]);

	fr_atexit_global_once(_map_proc_tree_init, _map_proc_tree_free, NULL);

	/*
	 *	If it already exists, replace it.
	 */
	proc = map_proc_find(name);
	if (!proc) {
		/*
		*	Don't allocate directly in the parent ctx, it might be mprotected
		*	later, and that'll cause segfaults if any of the map_proc_t are still
		*	protected when we start shuffling the contents of the rbtree.
		*/
		proc = talloc_zero(NULL, map_proc_t);
		if (ctx) talloc_link_ctx(ctx, proc);

		strlcpy(proc->name, name, sizeof(proc->name));
		proc->length = strlen(proc->name);

		if (fr_rb_replace(NULL, map_proc_root, proc) < 0) {
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
	proc->literals_safe_for = literals_safe_for;

	return 0;
}

/** Unregister a map processor by name
 *
 * @param[in] name	of map processor to unregister.
 * @return
 *	- 0 if map processor was found and unregistered.
 *	- -1 if map processor was not found.
 */
int map_proc_unregister(char const *name)
{
	map_proc_t *proc;

	proc = map_proc_find(name);
	if (proc) {
		talloc_free(proc);
		return 0;
	}

	return -1;
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
				      CONF_SECTION *cs, tmpl_t const *src, map_list_t const *maps)
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
 * @param[out] p_result		Result code of evaluating the map.
 * @param[in] request		The current request.
 * @param[in] inst		of a map processor.
 * @param[in,out] result	Result of expanding the map input.  May be consumed
 *				by the map processor.
 * @return one of UNLANG_ACTION_*
 */
unlang_action_t map_proc(rlm_rcode_t *p_result, request_t *request, map_proc_inst_t const *inst, fr_value_box_list_t *result)
{
	return inst->proc->evaluate(p_result, inst->proc->mod_inst, inst->data, request, result, inst->maps);
}
