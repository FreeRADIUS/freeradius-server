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
 * @file main/map_proc.c
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Arran Cudbard-bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/map_proc.h>

static rbtree_t *map_proc_root = NULL;

/** Describes a single map processor
 */
struct map_proc {
	char			name[MAX_STRING_LEN];	//!< Name of the map function.
	int			length;			//!< Length of name.

	map_proc_func_t		func;			//!< Module's map processor function.
	map_proc_cache_alloc_t	cache_alloc;		//!< Callback to create new cache structure on
							//!< instantiate.
	RADIUS_ESCAPE_STRING	escape;			//!< Escape function to apply to expansions in the map
							//!< query string.
	void			*escape_ctx;		//!< Context data from the escape function.
	void			*func_ctx;		//!< Context data for the map function.
};

/** Compare two map_proc_t structs, based ONLY on the name
 *
 * @param[in] one First map struct.
 * @param[in] two Second map struct.
 * @return Integer specifying order of map func instances.
 */
static int map_proc_cmp(void const *one, void const *two)
{
	map_proc_t const *a = one;
	map_proc_t const *b = two;

	if (a->length != b->length) return a->length - b->length;

	return memcmp(a->name, b->name, a->length);
}

/** Unregister a map processor
 *
 * @param[in] proc to unregister.
 */
static int _map_proc_unregister(map_proc_t *proc)
{
	map_proc_t find;
	map_proc_t *found;

	strlcpy(find.name, proc->name, sizeof(find.name));
	find.length = strlen(find.name);

	found = rbtree_finddata(map_proc_root, &find);
	if (!found) return 0;

	rbtree_deletebydata(map_proc_root, found);

	return 0;
}

/** Find a map processor by name
 *
 * @param[in] name of map processor.
 * @return a map_proc matching name, or NULL if none was found.
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
 * @param[in] ctx To allocate new map_proc_t in. Must be specified. Usually the module instance.
 *	If ctx is freed map_proc_t is automatically unregistered.
 * @param[in] name of map processor. If processor already exists, it is replaced.
 * @param[in] func Module's map processor function.
 * @param[in] func_ctx to pass to the map function when it's called.
 * @param[in] escape function to sanitize any sub expansions in the map source query.
 * @param[in] escape_ctx to pass to sanitization functions.
 * @param[in] cache_alloc function (optional).
 * @return 0 on success, -1 on failure
 */
int map_proc_register(TALLOC_CTX *ctx, char const *name, map_proc_func_t func,
		      void *func_ctx, RADIUS_ESCAPE_STRING escape, void *escape_ctx,
		      map_proc_cache_alloc_t cache_alloc)
{
	map_proc_t *proc;

	rad_assert(name && name[0]);

	if (!map_proc_root) {
		map_proc_root = rbtree_create(NULL, map_proc_cmp, NULL, RBTREE_FLAG_REPLACE);
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

		proc = talloc_zero(ctx, map_proc_t);
		strlcpy(proc->name, name, sizeof(proc->name));
		proc->length = strlen(proc->name);

		node = rbtree_insert_node(map_proc_root, proc);
		if (!node) {
			talloc_free(proc);
			return -1;
		}

		talloc_set_destructor(proc, _map_proc_unregister);
	}

	proc->func = func;
	proc->func_ctx = func_ctx;
	proc->escape = escape;
	proc->escape_ctx = escape_ctx;
	proc->cache_alloc = cache_alloc;

	return 0;
}

/** Create a new map proc instance
 *
 * This should be called for every map {} section in the configuration.
 *
 * @param ctx to allocate proc instance in.
 * @param proc resolved with #map_proc_find.
 * @param src template.
 * @param maps Head of the list of maps.
 * @return a new map_proc_inst_t on success, else NULL on error.
 */
map_proc_inst_t *map_proc_instantiate(TALLOC_CTX *ctx, map_proc_t const *proc,
				      vp_tmpl_t const *src, vp_map_t const *maps)
{
	map_proc_inst_t *inst;

	inst = talloc_zero(ctx, map_proc_inst_t);
	inst->proc = proc;
	inst->src = src;
	inst->maps = maps;

	if (proc->cache_alloc) {
		TALLOC_CTX *ctx_link;

		/*
		 *	Creates a threadsafe context, that will be freed
		 *	at the same time as the map_proc_inst_t structure.
		 */
		ctx_link = talloc_new(NULL);
		fr_link_talloc_ctx_free(inst, ctx_link);

		if (proc->cache_alloc(ctx_link, &inst->cache, src, maps, proc->func_ctx) < 0) {
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
 * @param request The current request.
 * @param inst of a map processor.
 */
rlm_rcode_t map_proc(REQUEST *request, map_proc_inst_t const *inst)
{
	char		*value;
	rlm_rcode_t	rcode;

	if (tmpl_aexpand(request, &value, request, inst->src, inst->proc->escape, inst->proc->escape_ctx) < 0) {
		return RLM_MODULE_FAIL;
	}

	rcode = inst->proc->func(request, value, inst->maps, inst->cache, inst->proc->func_ctx);
	talloc_free(value);

	return rcode;
}
