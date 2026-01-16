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
 * @file src/lib/server/module.c
 * @brief Defines functions for module initialisation
 *
 * @copyright 2016,2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2003,2006,2016 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Alan Curry (pacman@world.std.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <sys/mman.h>

static void module_thread_detach(module_thread_instance_t *ti);

/** Heap of all lists/modules used to get a common index with mlg_thread->inst_list
 */
static fr_heap_t *mlg_index;

/** An array of thread-local module lists
*
* The indexes in this array are identical to module_list_global, allowing
* O(1) lookups.  Arrays are used here as there's no performance penalty
* once they're populated.
*/
static _Thread_local module_thread_instance_t **mlg_thread_inst_list;

static int cmd_show_module_config(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info);
static int module_name_tab_expand(UNUSED TALLOC_CTX *talloc_ctx, UNUSED void *uctx, fr_cmd_info_t *info, int max_expansions, char const **expansions);
static int cmd_show_module_list(FILE *fp, UNUSED FILE *fp_err, UNUSED void *uctx, UNUSED fr_cmd_info_t const *info);
static int cmd_show_module_status(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info);
static int cmd_set_module_status(UNUSED FILE *fp, FILE *fp_err, void *ctx, fr_cmd_info_t const *info);

fr_cmd_table_t module_cmd_table[] = {
	{
		.parent = "show module",
		.add_name = true,
		.name = "status",
		.func = cmd_show_module_status,
		.help = "Show the status of a particular module.",
		.read_only = true,
	},

	{
		.parent = "show module",
		.add_name = true,
		.name = "config",
		.func = cmd_show_module_config,
		.help = "Show configuration for a module",
		// @todo - do tab expand, by walking over the whole module list...
		.read_only = true,
	},

	{
		.parent = "set module",
		.add_name = true,
		.name = "status",
		.syntax = "(alive|disallow|fail|reject|handled|invalid|notfound|noop|ok|updated)",
		.func = cmd_set_module_status,
		.help = "Change module status to fixed value.",
		.read_only = false,
	},

	CMD_TABLE_END
};

fr_cmd_table_t module_cmd_list_table[] = {
	{
		.parent = "show",
		.name = "module",
		.help = "Show information about modules.",
		.tab_expand = module_name_tab_expand,
		.read_only = true,
	},

	// @todo - what if there's a module called "list" ?
	{
		.parent = "show module",
		.name = "list",
		.func = cmd_show_module_list,
		.help = "Show the list of modules loaded in the server.",
		.read_only = true,
	},

	{
		.parent = "set",
		.name = "module",
		.help = "Change module settings.",
		.tab_expand = module_name_tab_expand,
		.read_only = false,
	},


	CMD_TABLE_END
};

static int cmd_show_module_config(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;

	fr_assert(mi->conf != NULL);

	(void) cf_section_write(fp, mi->conf, 0);

	return 0;
}

static int module_name_tab_expand(UNUSED TALLOC_CTX *talloc_ctx, UNUSED void *uctx,
				  fr_cmd_info_t *info, int max_expansions, char const **expansions)
{
	char const		*text;
	int			count;

	if (info->argc <= 0) return 0;

	text = info->argv[info->argc - 1];
	count = 0;

	fr_heap_foreach(mlg_index, module_instance_t, instance) {
		module_instance_t       *mi = talloc_get_type_abort(instance, module_instance_t);

		if (count >= max_expansions) {
			break;
		}
		if (fr_command_strncmp(text, mi->name)) {
			expansions[count] = strdup(mi->name);
			count++;
		}
	}}

	return count;
}

static int cmd_show_module_list(FILE *fp, UNUSED FILE *fp_err, UNUSED void *uctx, UNUSED fr_cmd_info_t const *info)
{
	fr_heap_foreach(mlg_index, module_instance_t, instance) {
		module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);

		fprintf(fp, "\t%s\n", mi->name);
	}}

	return 0;
}

static int cmd_show_module_status(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;

	if (!mi->force) {
		fprintf(fp, "alive\n");
		return 0;
	}

	fprintf(fp, "%s\n", fr_table_str_by_value(rcode_table, mi->code, "<invalid>"));

	return 0;
}

static int cmd_set_module_status(UNUSED FILE *fp, FILE *fp_err, void *ctx, fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;
	rlm_rcode_t rcode;

	if (strcmp(info->argv[0], "alive") == 0) {
		mi->force = false;
		return 0;
	}

	rcode = fr_table_value_by_str(rcode_table, info->argv[0], RLM_MODULE_NOT_SET);
	if (rcode == RLM_MODULE_NOT_SET) {
		fprintf(fp_err, "Unknown status '%s'\n", info->argv[0]);
		return -1;
	}

	mi->code = rcode;
	mi->force = true;

	return 0;
}

/** Chars that are allowed in a module instance name
 *
 */
bool const module_instance_allowed_chars[UINT8_MAX + 1] = {
	['-'] = true, ['/'] = true, ['_'] = true, ['.'] = true,
	['0'] = true, ['1'] = true, ['2'] = true, ['3'] = true, ['4'] = true,
	['5'] = true, ['6'] = true, ['7'] = true, ['8'] = true, ['9'] = true,
	['A'] = true, ['B'] = true, ['C'] = true, ['D'] = true, ['E'] = true,
	['F'] = true, ['G'] = true, ['H'] = true, ['I'] = true, ['J'] = true,
	['K'] = true, ['L'] = true, ['M'] = true, ['N'] = true, ['O'] = true,
	['P'] = true, ['Q'] = true, ['R'] = true, ['S'] = true, ['T'] = true,
	['U'] = true, ['V'] = true, ['W'] = true, ['X'] = true, ['Y'] = true,
	['Z'] = true,
	['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true,
	['f'] = true, ['g'] = true, ['h'] = true, ['i'] = true, ['j'] = true,
	['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true, ['o'] = true,
	['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = true,
	['u'] = true, ['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true,
	['z'] = true
};

/** dl module tracking
 *
 * This is used by all module lists, irrespecitve of their type, and is thread safe.
 */
static dl_module_loader_t	*dl_modules = NULL;

/** Callback to initialise any global structures required for the module list
 *
 * @param[in] ml	to initialise global data for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*module_list_init_t)(module_list_t *ml);

/** Callback to free any global structures associated with the module list
 *
 * @param[in] ml	to free.
 */
typedef void (*module_list_free_t)(module_list_t *ml);

/** Callback to add data for a module
 *
 * @param[in] mi	to add data for.
 *			Use mi->ml for the module list.
 *			Use mi->data to access the data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*module_list_data_add_t)(module_instance_t *mi);

/** Callback to del data for a module
 *
 * @param[in] mi	to add data to (use mi->ml for the module list).
 *
 */
typedef void (*module_list_data_del_t)(module_instance_t *mi);

/** Callback to initialise a list for thread-local data, called once per thread
 *
 * @param[in] ctx	talloc context for thread-local data.
 *			May be modified by the init function if the
 *			module_thread_instance_t need to be parented
 *			by another ctx.
 * @param[in] ml	to initialise thread-local data for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*module_list_thread_init_t)(TALLOC_CTX **ctx, module_list_t const *ml);

/** Callback to free thread-local structures, called once per thread as the thread is being destroyed
 *
 * @param[in] ml	to free thread-local data for.
 */
typedef void (*module_list_thread_free_t)(module_list_t *ml);

/** Callback to add thread-local data for a module
 *
 * @param[in] ti	to add data for.
 *			Use `ti->mi->ml` for the module list.
 *			Use `ti->mi` for the module instance.
 *			Use `ti->data` for the thread specific data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*module_list_thread_data_add_t)(module_thread_instance_t *ti);

/** Callback to remove thread-local data for a module
 *
 * @param[in] ti	to del data for.
 *			Use `ti->mi->ml` for the module list.
 *			Use `ti->mi` for the module instance.
 *			Use `ti->data` for the thread specific data.
 */
typedef void (*module_list_thread_data_del_t)(module_thread_instance_t *ti);

/** Structure to hold callbacks for a module list type
 *
 * We care about performance for module lists, as they're used heavily at runtime.
 *
 * As much as possible we try to avoid jumping through unecessary functions and
 * unecessary switch statements.
 *
 * This structure contains callbacks which change how the module list operates,
 * making it either a global module list, or a thread-local module list, i.e. one
 * which only be used by a single thread.
 *
 * Instances of this structure are created in this compilation unit, and exported
 * for the caller to pass into module_list_alloc().
 */
struct module_list_type_s {
	size_t					list_size;		//!< Size of talloc_chunk to allocate for the module_list_t.

	module_list_init_t			init;			//!< Initialise any global structures required for thread-local lookups.
	module_list_free_t			free;			//!< Free any global structures required for thread-local lookups.

	size_t					inst_size;		//!< Size of talloc chunk to allocate for the module_instance_t.
									///< allows over-allocation if list types want to append fields.
	module_list_data_add_t			data_add;		//!< Record that module data has been added.
	module_list_data_del_t			data_del;		//!< Record that module data has been removed.

	/** Callbacks to manage thread-local data
	 */
	struct {
		module_list_thread_init_t		init;			//!< Initialise any thread-local structures required for thread-local lookups.
		module_list_thread_free_t		free;			//!< Free any thread-local structures.

		module_list_thread_data_add_t		data_add;		//!< Add thread-local data for a module.
		module_list_thread_data_get_t		data_get;		//!< Retrieve thread local-data for a module.
		module_list_thread_data_del_t		data_del;		//!< Remove (but not free) thread-local data for a module.

		void					*data;			//!< Pointer to hold any global resources for the thread-local implementation.
	} thread;
};

typedef struct {
	module_instance_t		mi;		//!< Common module instance fields.  Must come first.

	fr_heap_index_t			inst_idx;	//!< Entry in the bootstrap/instantiation heap.
							//!< should be an identical value to the thread-specific
							///< data for this module.
} mlg_module_instance_t;

/** Sort module instance data first by list then by number
 *
 * The module's position in the global instance heap informs of us
 * of its position in the thread-specific heap, which allows for
 * O(1) lookups.
 */
static int8_t _mlg_module_instance_cmp(void const *one, void const *two)
{
	module_instance_t const *a = talloc_get_type_abort_const(one, module_instance_t);
	module_instance_t const *b = talloc_get_type_abort_const(two, module_instance_t);
	int8_t ret;

	fr_assert(a->ml && b->ml);

	ret = CMP(a->ml, b->ml);
	if (ret != 0) return 0;

	return CMP(a->number, b->number);
}

/** Free the global module index
 *
 */
static int _mlg_global_free(UNUSED void *uctx)
{
	return talloc_free(mlg_index);
}

/** Initialise the global module index
 *
 */
static int _mlg_global_init(UNUSED void *uctx)
{
	MEM(mlg_index = fr_heap_alloc(NULL, _mlg_module_instance_cmp, mlg_module_instance_t, inst_idx, 256));
	return 0;
}

/** Global initialisation for index heap and module array
 *
 */
static int mlg_init(UNUSED module_list_t *ml)
{
       /*
	*	Create the global module heap we use for
	*	common indexes in the thread-specific
	*	heaps.
	*/
	fr_atexit_global_once(_mlg_global_init, _mlg_global_free, NULL);

	return 0;
}

/** Add the unique index value so we can do thread local lookups
 *
 */
static int mlg_data_add(module_instance_t *mi)
{
	/*
	 *	Insert the module into the global heap so
	 *	we can get common thread-local indexes.
	 */
	if (fr_heap_insert(&mlg_index, mi) < 0) {
		ERROR("Failed inserting into global module index");
		return -1;
	}

	return 0;
}

static void mlg_data_del(module_instance_t *mi)
{
	mlg_module_instance_t	*mlg_mi = (mlg_module_instance_t *)talloc_get_type_abort(mi, module_instance_t);

	if (!fr_heap_entry_inserted(mlg_mi->inst_idx)) return;

	if (fr_heap_extract(&mlg_index, mi) == 0) return;

	fr_assert(0);
}

/** Free the thread local heap on exit
 *
 * All thread local module lists should have been destroyed by this point
 */
static int _module_thread_inst_list_free(void *tilp)
{
	module_thread_instance_t **til = talloc_get_type_abort(tilp, module_thread_instance_t *);
	size_t i, len = talloc_array_length(til);
	unsigned int found = 0;

	for (i = 0; i < len; i++) if (til[i]) found++;

	if (!fr_cond_assert_msg(found == 0,
				"Thread local array has %u non-null elements remaining on exit.  This is a leak",
				found)) {
		return -1;
	}

	return talloc_free(til);
}

/** Allocate a thread-local array to hold thread data for each module thats been instantiated
 *
 * @param[in] ctx	Talloc context for the thread-local data.
 *			Mutated by this function so that thread local data is allocated
 *			beneath the array.
 * @param[in] ml	Module list to initialise the thread-local data for.
 */
static int mlg_thread_init(UNUSED TALLOC_CTX **ctx, UNUSED module_list_t const *ml)
{
	/*
	 *	Initialise the thread specific tree if this is the
	 *	first time through or if everything else was
	 *	de-initialised.
	 */
	if (!mlg_thread_inst_list) {
		module_thread_instance_t **arr;

		MEM(arr = talloc_zero_array(NULL, module_thread_instance_t *, fr_heap_num_elements(mlg_index)));

		fr_atexit_thread_local(mlg_thread_inst_list, _module_thread_inst_list_free, arr);
	}

	return 0;
}

/** Retrieve the thread-specific data for a module from the thread-local array of instance data
 *
 * This looks complex, but it's just asserts for sanity.  This is really only returning an array offset.
 *
 * @param[in] mi	Module instance to get the thread-specific data for.
 */
static module_thread_instance_t *mlg_thread_data_get(module_instance_t const *mi)
{
	mlg_module_instance_t const	*mlg_mi = (mlg_module_instance_t const *)talloc_get_type_abort_const(mi, module_instance_t);
	module_thread_instance_t	*ti;
	void				*ti_p;

	fr_assert_msg(mlg_mi->inst_idx <= talloc_array_length(mlg_thread_inst_list),
		      "module instance index %u must be <= thread local array %zu",
		      mlg_mi->inst_idx, talloc_array_length(mlg_thread_inst_list));

	fr_assert_msg(fr_heap_num_elements(mlg_index) == talloc_array_length(mlg_thread_inst_list),
		      "mismatch between global module heap (%u entries) and thread local (%zu entries)",
		      fr_heap_num_elements(mlg_index), talloc_array_length(mlg_thread_inst_list));

	/*
	 *	Check for a NULL entry.  This can happen when a module's
	 *	thread instantiate callback fails, and we try and cleanup
	 *	a partially instantiated thread.
	 */
	ti_p = mlg_thread_inst_list[mlg_mi->inst_idx - 1];
	if (unlikely(!ti_p)) return NULL;

	ti = talloc_get_type_abort(ti_p, module_thread_instance_t);
	fr_assert_msg(ti->mi == mi, "thread/module mismatch thread %s (%p), module %s (%p)",
		      ti->mi->name, ti->mi, mi->name, mi);

	return ti;
}

static int mlg_thread_data_add(module_thread_instance_t *ti)
{
	mlg_module_instance_t const *mlg_mi = (mlg_module_instance_t const *)talloc_get_type_abort_const(ti->mi, module_instance_t);
	mlg_thread_inst_list[mlg_mi->inst_idx - 1] = ti;
	return 0;
}

static void mlg_thread_data_del(module_thread_instance_t *ti)
{
	mlg_module_instance_t const *mlg_mi = (mlg_module_instance_t const *)talloc_get_type_abort_const(ti->mi, module_instance_t);
	mlg_thread_inst_list[mlg_mi->inst_idx - 1] = NULL;
}

/** Callbacks for a global module list
 */
module_list_type_t const module_list_type_global = {
	.init = mlg_init,

	.inst_size = sizeof(mlg_module_instance_t),
	.data_add = mlg_data_add,
	.data_del = mlg_data_del,

	.thread = {
		.init = mlg_thread_init,
		.data_add = mlg_thread_data_add,
		.data_get = mlg_thread_data_get,
		.data_del = mlg_thread_data_del
	}
};

/** A slightly larger module_instance structure to hold the module instance and thread instance
 */
typedef struct {
	module_instance_t		mi;			//!< Common module instance fields.  Must come first.
	module_thread_instance_t	*ti;			//!< Thread-specific data.  Still in its own structure
								///< for talloc reasons.
} mltl_module_instance_t;

static void mltl_mlg_data_del(module_instance_t *mi)
{
	mltl_module_instance_t *mltl_mi = (mltl_module_instance_t *)talloc_get_type_abort(mi, module_instance_t);

	/*
	 *	Only free thread instance data we allocated...
	 */
	if (mltl_mi->ti) module_thread_detach(mltl_mi->ti);
}

static module_thread_instance_t *mltl_thread_data_get(module_instance_t const *mi)
{
	mltl_module_instance_t const *mltl_mi = (mltl_module_instance_t const *)talloc_get_type_abort_const(mi, module_instance_t);
	return mltl_mi->ti;
}

static int mltl_thread_data_add(module_thread_instance_t *ti)
{
	mltl_module_instance_t *mltl_mi = (mltl_module_instance_t *)talloc_get_type_abort(ti->mi, module_instance_t);
	mltl_mi->ti = ti;
	return 0;
}

static void mltl_thread_data_del(module_thread_instance_t *ti)
{
	mltl_module_instance_t *mltl_mi = (mltl_module_instance_t *)talloc_get_type_abort(ti->mi, module_instance_t);
	mltl_mi->ti = NULL;
}

/** Callbacks for a thread local list
 */
module_list_type_t const module_list_type_thread_local = {
	.inst_size = sizeof(mltl_module_instance_t),
	.data_del = mltl_mlg_data_del,

	.thread = {
		.data_add = mltl_thread_data_add,
		.data_get = mltl_thread_data_get,
		.data_del = mltl_thread_data_del
	}
};

/** Print debugging information for a module
 *
 * @param[in] mi	Module instance to print.
 */
void module_instance_debug(module_instance_t const *mi)
{
	FR_FAULT_LOG("%s (%p) {", mi->name, mi);
	FR_FAULT_LOG("  type         : %s", fr_table_str_by_value(dl_module_type_prefix, mi->module->type, "<invalid>"));
	if (mi->parent) {
		FR_FAULT_LOG("  parent       : \"%s\" (%p)", mi->parent->name, mi->parent);
	}
	FR_FAULT_LOG("  bootstrapped : %s", mi->state & MODULE_INSTANCE_BOOTSTRAPPED ? "yes" : "no");
	FR_FAULT_LOG("  instantiated : %s", mi->state & MODULE_INSTANCE_INSTANTIATED ? "yes" : "no");
	FR_FAULT_LOG("  boot         : %p", mi->boot);
	FR_FAULT_LOG("  data         : %p", mi->data);
	FR_FAULT_LOG("  conf         : %p", mi->conf);
	FR_FAULT_LOG("}");
}

/** Print the contents of a module list
 *
 */
void module_list_debug(module_list_t const *ml)
{
	module_instance_t const *inst;
	fr_rb_iter_inorder_t	iter;

	FR_FAULT_LOG("Module list \"%s\" (%p) {", ml->name, ml);
	FR_FAULT_LOG("  phase masked:");
	FR_FAULT_LOG("    bootstrap   : %s", ml->mask & MODULE_INSTANCE_BOOTSTRAPPED ? "yes" : "no");
	FR_FAULT_LOG("    instantiate : %s", ml->mask & MODULE_INSTANCE_INSTANTIATED ? "yes" : "no");
	FR_FAULT_LOG("    thread      : %s", ml->mask & MODULE_INSTANCE_INSTANTIATED ? "yes" : "no");
	FR_FAULT_LOG("}");
	/*
	 *	Modules are printed in the same order
	 *	they would be bootstrapped or inserted
	 *	into the tree.
	 */
	for (inst = fr_rb_iter_init_inorder(ml->name_tree, &iter);
	     inst;
	     inst = fr_rb_iter_next_inorder(ml->name_tree, &iter)) {
		module_instance_debug(inst);
	}
}

/** Protect module data
 *
 * @param[in] mi module instance.
 * @param[in] pool to protect
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline)
int module_data_protect(module_instance_t *mi, module_data_pool_t *pool)
{
	if ((pool->start == NULL) || !mi->ml->write_protect) return 0; /* noop */

	DEBUG3("Protecting data for module \"%s\" %p-%p",
	       mi->name, pool->start, ((uint8_t *)pool->start + pool->len - 1));

	if (unlikely(mprotect(pool->start, pool->len, PROT_READ) < 0)) {
		fr_strerror_printf("Protecting \"%s\" module data failed: %s", mi->name, fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Unprotect module data
 *
 * @param[in] mi module instance.
 * @param[in] pool to protect
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline)
int module_data_unprotect(module_instance_t const *mi, module_data_pool_t const *pool)
{
	if ((pool->start == NULL) || !mi->ml->write_protect) return 0; /* noop */

	DEBUG3("Unprotecting data for module \"%s\" %p-%p",
	       mi->name, pool->start, ((uint8_t *)pool->start + pool->len - 1));

	if (unlikely(mprotect(pool->start, pool->len, PROT_READ | PROT_WRITE) < 0)) {
		fr_strerror_printf("Unprotecting \"%s\" data failed: %s", mi->name, fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Mark module data as read only
 *
 * @param[in] mi	Instance data to protect (mark as read only).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int module_instance_data_protect(module_instance_t const *mi)
{
	return module_data_unprotect(mi, &mi->inst_pool);
}

/** Mark module data as read/write
 *
 * @param[in] mi	Instance data to unprotect (mark as read/write).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int module_instance_data_unprotect(module_instance_t const *mi)
{
	return module_data_unprotect(mi, &mi->inst_pool);
}

/** Return the prefix string for the deepest module
 *
 * This is useful for submodules which don't have a prefix of their own.
 * In this case we need to use the prefix of the shallowest module, which
 * will be a proto or rlm module.
 *
 * @param[in] mi	Instance to get the prefix for.
 * @return The prefix string for the shallowest module.
 */
char const *module_instance_root_prefix_str(module_instance_t const *mi)
{
	module_instance_t const *root = module_instance_root(mi);

	return fr_table_str_by_value(dl_module_type_prefix, root->module->type, "<INVALID>");
}

/** Avoid boilerplate when setting the module instance name
 *
 */
fr_slen_t module_instance_name_from_conf(char const **name, CONF_SECTION *conf)
{
	char const	*name2;
	char const	*inst_name;
	fr_slen_t	slen;

	name2 = cf_section_name2(conf);
	if (name2) {
		inst_name = name2;
		goto done;
	}

	inst_name = cf_section_name1(conf);
done:
	slen = module_instance_name_valid(inst_name);
	if (slen < 0) {
		cf_log_perr(conf, "Invalid module configuration");
		*name = NULL;
		return slen;
	}

	*name = inst_name;

	return 0;
}

/** Covert a CONF_SECTION into parsed module instance data
 *
 */
int module_instance_conf_parse(module_instance_t *mi, CONF_SECTION *conf)
{
	/*
	 *	Associate the module instance with the conf section
	 *	*before* executing any parse rules that might need it.
	 */
	cf_data_add(conf, mi, mi->module->dl->name, false);
	mi->conf = conf;

	if (mi->exported->config && mi->conf) {
		if ((cf_section_rules_push(mi->conf, mi->exported->config)) < 0 ||
		    (cf_section_parse(mi->data, mi->data, mi->conf) < 0)) {
			cf_log_err(mi->conf, "Failed evaluating configuration for module \"%s\"",
				   mi->module->dl->name);
			return -1;
		}
	}

	return 0;
}

/** Compare module instances by parent and name
 *
 * The reason why we need parent, is because we could have submodules with names
 * that conflict with their parent.
 */
static int8_t module_instance_name_cmp(void const *one, void const *two)
{
	module_instance_t const *a = one;
	module_instance_t const *b = two;
	module_instance_t const	*mi;
	int a_depth = 0, b_depth = 0;
	int ret;

#ifdef STATIC_ANALYZER
	if (!fr_cond_assert(a)) return +1;
	if (!fr_cond_assert(b)) return -1;
#endif

	/*
	 *	Sort by depth, so for tree walking we start
	 *	at the shallowest node, and finish with
	 *	the deepest child.
	 */
	for (mi = a; mi; mi = mi->parent) a_depth++;
	for (mi = b; mi; mi = mi->parent) b_depth++;

	ret = CMP(a_depth, b_depth);
	if (ret != 0) return ret;

	ret = CMP(a->parent, b->parent);
	if (ret != 0) return ret;

	ret = strcmp(a->name, b->name);
	return CMP(ret, 0);
}

/** Compare module's by their private instance data
 *
 */
static int8_t module_instance_data_cmp(void const *one, void const *two)
{
	void const *a = ((module_instance_t const *)one)->data;
	void const *b = ((module_instance_t const *)two)->data;

	return CMP(a, b);
}

/** Generic callback for conf_parser_t to load a submodule
 *
 * conf_parser_t entry should point to a module_instance_t field in the instance data
 *
 * @param[in] ctx	unused.
 * @param[out] out	A pointer to a pointer to a module_instance_t.
 * @param[in] parent	This _must_ point to the instance data of the parent
 *			module.
 * @param[in] ci	The CONF_PAIR containing the name of the submodule to load.
 * @param[in] rule	uctx pointer must be a pointer to a module_list_t **
 *			containing the list to search in.
 * @return
 *	- 0 on success.
 *	- -1 if we failed to load the submodule.
 */
int module_submodule_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
			   CONF_ITEM *ci, conf_parser_t const *rule)
{
	char const		*name = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*submodule_cs;
	module_instance_t	*mi;
	module_list_t		*ml = talloc_get_type_abort(*((void * const *)rule->uctx), module_list_t);

	/*
	 *	We assume the submodule's config is the
	 *	in a section with the same name as
	 *	the submodule.
	 */
	submodule_cs = cf_section_find(cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!submodule_cs) submodule_cs = cf_section_alloc(cs, cs, name, NULL);

	/*
	 *	The submodule name dictates the module loaded
	 *	the instance name is always the submodule name
	 *	and will be appended to the parent's instance
	 *	name.
	 */
	mi = module_instance_alloc(ml, module_instance_by_data(ml, parent), DL_MODULE_TYPE_SUBMODULE, name, name, 0);
	if (unlikely(mi == NULL)) {
		cf_log_err(submodule_cs, "Failed loading submodule");
		return -1;
	}

	if (unlikely(module_instance_conf_parse(mi, submodule_cs) < 0)) {
		cf_log_err(submodule_cs, "Failed parsing submodule config");
		talloc_free(mi);
		return -1;
	}

	*((module_instance_t **)out) = mi;

	return 0;
}

/** Find an existing module instance by its name and parent
 *
 * @param[in] ml		to search in.
 * @param[in] parent		to qualify search with.
 * @param[in] asked_name 	The name of the module we're attempting to find.
 *				May include '-' which indicates that it's ok for
 *				the module not to be loaded.
 * @return
 *	- Module instance matching name.
 *	- NULL if no such module exists.
 */
module_instance_t *module_instance_by_name(module_list_t const *ml, module_instance_t const *parent, char const *asked_name)
{
	char const		*inst_name;
	void			*inst;

	if (!ml->name_tree) return NULL;

	/*
	 *	Look for the real name.  Ignore the first character,
	 *	which tells the server "it's OK for this module to not
	 *	exist."
	 */
	inst_name = asked_name;
	if (inst_name[0] == '-') inst_name++;

	inst = fr_rb_find(ml->name_tree,
			  &(module_instance_t){
				.parent = UNCONST(module_instance_t *, parent),
				.name = inst_name
			  });
	if (!inst) return NULL;

	return talloc_get_type_abort(inst, module_instance_t);
}

/** Find the module's shallowest parent
 *
 * @param[in] child	to locate the root for.
 * @return
 *	- The module's shallowest parent.
 *	- NULL on error.
 */
module_instance_t *module_instance_root(module_instance_t const *child)
{
	module_instance_t const *next;

	for (;;) {
		next = child->parent;
		if (!next) break;

		child = next;
	}

	return UNCONST(module_instance_t *, child);
}

/** Find an existing module instance by its private instance data
 *
 * @param[in] ml	to search in.
 * @param[in] data	to resolve to module_instance_t.
 * @return
 *	- Module instance matching data.
 *	- NULL if no such module exists.
 */
module_instance_t *module_instance_by_data(module_list_t const *ml, void const *data)
{
	module_instance_t *mi;

	mi = fr_rb_find(ml->data_tree,
			&(module_instance_t){
				.data = UNCONST(void *, data)
			});
	if (!mi) return NULL;

	return talloc_get_type_abort(mi, module_instance_t);
}

/** Retrieve module/thread specific instance data for a module
 *
 * @param[in] ml	Module list module belongs to.
 * @param[in] data	Private instance data of the module.
 *			Same as what would be provided by
 *			#module_instance_by_data.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
module_thread_instance_t *module_thread_by_data(module_list_t const *ml, void const *data)
{
	module_instance_t		*mi = module_instance_by_data(ml, data);

	if (!mi) return NULL;

	return module_thread(mi);
}

static void module_thread_detach(module_thread_instance_t *ti)
{
	module_list_t *ml;

	/*
	 *	This can happen when a module's thread instantiate
	 *	callback fails, and we try and cleanup a partially
	 *	instantiated thread.
	 */
	if (unlikely(!ti)) return;

	ml = ti->mi->ml;
	ml->type->thread.data_del(ti);
	talloc_free(ti);
}

/** Remove thread-specific data for a given module list
 *
 * Removes all module thread data for the
 */
void modules_thread_detach(module_list_t *ml)
{
	fr_rb_iter_inorder_t		iter;
	void				*inst;

	/*
	 *	Loop over all the modules in the module list
	 *	finding and extracting their thread specific
	 *	data, and calling their detach methods.
	 */
	for (inst = fr_rb_iter_init_inorder(ml->name_tree, &iter);
	     inst;
	     inst = fr_rb_iter_next_inorder(ml->name_tree, &iter)) {
	     	module_instance_t		*mi = talloc_get_type_abort(inst, module_instance_t);
		module_thread_instance_t	*ti = module_thread(mi);

		module_thread_detach(ti);
	}

	/*
	 *	Cleanup any lists the module list added to this thread
	 */
	if (ml->type->thread.free) ml->type->thread.free(ml);
}

/** Callback to free thread local data
 *
 * ti->data is allocated in the context of ti, so will be freed too.
 *
 * Calls the detach function for thread local data, and removes the data from the
 * thread local list.
 *
 * @param[in] ti	to free.
 */
static int _module_thread_inst_free(module_thread_instance_t *ti)
{
	module_instance_t const *mi = ti->mi;

	/*
	 *	Never allocated a thread instance, so we don't need
	 *	to clean it up...
	 */
	if (mi->state & MODULE_INSTANCE_NO_THREAD_INSTANTIATE) return 0;

	DEBUG4("Cleaning up %s thread instance data (%p/%p)",
	       mi->exported->name, ti, ti->data);

	if (mi->exported->thread_detach) {
		mi->exported->thread_detach(&(module_thread_inst_ctx_t const ){
						.mi = ti->mi,
						.thread = ti->data,
						.el = ti->el
					  });
	}

	ti->mi->ml->type->thread.data_del(ti);

	return 0;
}

/** Allocate thread-local instance data for a module
 *
 * The majority of modules will have a single set of thread-specific instance data.
 *
 * An exception is dynamic modules, which may have multiple sets of thread-specific instance data tied to
 * a specific dynamic use of that module.
 *
 * @param[in] ctx	Talloc ctx to bind thread specific data to.
 * @param[in] mi	Module instance to perform thread instantiation for.
 * @param[in] el	Event list serviced by this thread.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int module_thread_instantiate(TALLOC_CTX *ctx, module_instance_t *mi, fr_event_list_t *el)
{
	module_list_t			*ml = mi->ml;
	module_thread_instance_t	*ti;

	/*
	 *	Allows the caller of module_instance_alloc to
	 *	skip thread instantiation for certain modules instances
	 *	whilst allowing modules to still register thread
	 *	instantiation callbacks.
	 *
	 *	This is mainly there for the single global instance of
	 *	a module, which will only have run-time thread-specific
	 *	instances, like dynamic/keyed modules.
	 */
	if (module_instance_skip_thread_instantiate(mi)) return 0;

	/*
	 *	Check the list pointers are ok
	 */
	(void)talloc_get_type_abort(mi->ml, module_list_t);

	MEM(ti = talloc_zero(ctx, module_thread_instance_t));
	talloc_set_destructor(ti, _module_thread_inst_free);
	ti->el = el;
	ti->mi = mi;

	if (mi->exported->thread_inst_size) {
		MEM(ti->data = talloc_zero_array(ti, uint8_t, mi->exported->thread_inst_size));

		/*
		 *	Fixup the type name, in case something calls
		 *	talloc_get_type_abort() on it...
		 */
		if (!mi->exported->thread_inst_type) {
			talloc_set_name(ti->data, "%s_%s_thread_t",
					module_instance_root_prefix_str(mi),
					mi->exported->name);
		} else {
			talloc_set_name_const(ti->data, mi->exported->thread_inst_type);
		}
	}

	if (ml->type->thread.data_add(ti) < 0) {
		PERROR("Failed adding thread data for module \"%s\"", mi->name);
	error:
		ml->type->thread.data_del(ti);
		talloc_free(ti);
		return -1;
	}

	/*
	 *	So we don't get spurious errors
	 */
	fr_strerror_clear();

	DEBUG4("Alloced %s thread instance data (%p/%p)", ti->mi->exported->name, ti, ti->data);
	if (mi->exported->thread_instantiate &&
	    mi->exported->thread_instantiate(MODULE_THREAD_INST_CTX(mi, ti->data, el)) < 0) {
		PERROR("Thread instantiation failed for module \"%s\"", mi->name);
		goto error;
	}

	return 0;
}

/** Creates per-thread instance data for modules which need it
 *
 * Must be called by any new threads before attempting to execute unlang sections.
 *
 * @param[in] ctx	Talloc ctx to bind thread specific data to.
 * @param[in] ml	Module list to perform thread instantiation for.
 * @param[in] el	Event list serviced by this thread.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_thread_instantiate(TALLOC_CTX *ctx, module_list_t const *ml, fr_event_list_t *el)
{
	void			*inst;
	fr_rb_iter_inorder_t	iter;
	int ret;

	/*
	 *	Do any thread-local instantiation necessary
	 */
	if (ml->type->thread.init) {
		ret = ml->type->thread.init(&ctx, ml);
		if (unlikely(ret < 0)) return ret;
	}

	for (inst = fr_rb_iter_init_inorder(ml->name_tree, &iter);
	     inst;
	     inst = fr_rb_iter_next_inorder(ml->name_tree, &iter)) {
		module_instance_t		*mi = talloc_get_type_abort(inst, module_instance_t); /* Sanity check*/

		if (module_thread_instantiate(ctx, mi, el) < 0) {
			modules_thread_detach(UNCONST(module_list_t *, ml));
			return -1;
		}
	}

	return 0;
}

/** Manually complete module setup by calling its instantiate function
 *
 * @param[in] instance	of module to complete instantiation for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int module_instantiate(module_instance_t *instance)
{
	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);
	CONF_SECTION *cs = mi->conf;

	/*
	 *	If we're instantiating, then nothing should be able to
	 *	modify the boot data for this module.
	 *
	 *	mprotect is thread-safe, so we don't need to worry about
	 *	synchronisation.  There is the overhead of a system call
	 *	but dynamic module instantiation is relatively rare.
	 *
	 *	We need to wait until all modules have registered things
	 *	like xlat functions, as the xlat functions themselves may
	 *	end up being allocated in boot pool data, and have inline
	 *	rbtree node structures, which may be modified as additional
	 *	xlat functions are registered.
	 */
	if (unlikely(module_data_protect(mi, &mi->boot_pool) < 0)) {
		cf_log_perr(mi->conf, "\"%s\"", mi->name);
		return -1;
	}

	/*
	 *	We only instantiate modules in the bootstrapped state
	 */
	if (module_instance_skip_instantiate(mi)) return 0;

	if (mi->module->type == DL_MODULE_TYPE_MODULE) {
		if (fr_command_register_hook(NULL, mi->name, mi, module_cmd_table) < 0) {
			PERROR("Failed registering radmin commands for module %s", mi->name);
			return -1;
		}
	}

	/*
	 *	Now that ALL modules are instantiated, and ALL xlats
	 *	are defined, go compile the config items marked as XLAT.
	 */
	if (mi->exported->config && (cf_section_parse_pass2(mi->data,
							    mi->conf) < 0)) return -1;

	/*
	 *	Call the instantiate method, if any.
	 */
	if (mi->exported->instantiate) {
		cf_log_debug(cs, "Instantiating %s_%s \"%s\"",
			     module_instance_root_prefix_str(mi),
			     mi->module->exported->name,
			     mi->name);

		/*
		 *	Call the module's instantiation routine.
		 */
		if (mi->exported->instantiate(MODULE_INST_CTX(mi)) < 0) {
			cf_log_err(mi->conf, "Instantiation failed for module \"%s\"", mi->name);

			return -1;
		}
	}

	/*
	 *	Instantiate shouldn't modify any global resources
	 *	so we can protect the data now without the side
	 *	effects we might see with boot data.
	 */
	if (unlikely(module_data_protect(mi, &mi->inst_pool) < 0)) {
		cf_log_perr(mi->conf, "\"%s\"", mi->name);
		return -1;
	}
	mi->state |= MODULE_INSTANCE_INSTANTIATED;

	return 0;
}

/** Completes instantiation of modules
 *
 * Allows the module to initialise connection pools, and complete any registrations that depend on
 * attributes created during the bootstrap phase.
 *
 * @param[in] ml containing modules to instantiate.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_instantiate(module_list_t const *ml)
{
	void			*inst;
	fr_rb_iter_inorder_t	iter;

	DEBUG2("#### Instantiating %s modules ####", ml->name);

	for (inst = fr_rb_iter_init_inorder(ml->name_tree, &iter);
	     inst;
	     inst = fr_rb_iter_next_inorder(ml->name_tree, &iter)) {
	     	module_instance_t *mi = talloc_get_type_abort(inst, module_instance_t);
		if (module_instantiate(mi) < 0) return -1;
	}

	return 0;
}

/** Manually complete module bootstrap by calling its instantiate function
 *
 * - Parse the module configuration.
 * - Call the modules "bootstrap" method.
 *
 * @param[in] mi	Module instance to bootstrap.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int module_bootstrap(module_instance_t *mi)
{
	/*
	 *	We only bootstrap modules in the init state
	 */
	if (module_instance_skip_bootstrap(mi)) return 0;

	/*
	 *	Bootstrap the module.
	 *	This must be done last so that the
	 *	module can find its module_instance_t
	 *	in the trees if it needs to bootstrap
	 *	submodules.
	 */
	if (mi->exported->bootstrap) {
		CONF_SECTION *cs = mi->conf;

		cf_log_debug(cs, "Bootstrapping %s_%s \"%s\"",
			     module_instance_root_prefix_str(mi),
			     mi->module->exported->name,
			     mi->name);

		/*
		 *	Modules MUST NOT modify their instance data during
		 *	bootstrap.  This is because dynamic (runtime) modules
		 *	don't run their boostrap callbacks, and MUST re-resolve
		 *	any resources added during bootstrap in the
		 *	instantiate callback.
		 *
		 *	Bootstrap is ONLY there for adding global,
		 *	module-specific resources.
		 *
		 *	If the module has MODULE_TYPE_DYNAMIC_UNSAFE is set,
		 *	then we don't need the restriction.
		 */
		if ((!(mi->exported->flags & MODULE_TYPE_DYNAMIC_UNSAFE)) &&
		    unlikely(module_data_protect(mi, &mi->inst_pool) < 0)) {
			cf_log_perr(cs, "\"%s\"", mi->name);
			return -1;
		}
		if (mi->exported->bootstrap(MODULE_INST_CTX(mi)) < 0) {
			cf_log_err(cs, "Bootstrap failed for module \"%s\"", mi->name);
			return -1;
		}
		if (unlikely(module_data_unprotect(mi, &mi->inst_pool) < 0)) {
			cf_log_perr(cs, "\"%s\"", mi->name);
			return -1;
		}
	}
	mi->state |= MODULE_INSTANCE_BOOTSTRAPPED;

	return 0;
}

/** Bootstrap any modules which have not been bootstrapped already
 *
 * Allows the module to initialise connection pools, and complete any registrations that depend on
 * attributes created during the bootstrap phase.
 *
 * @param[in] ml containing modules to bootstrap.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_bootstrap(module_list_t const *ml)
{
	void			*instance;
	fr_rb_iter_inorder_t	iter;

	DEBUG2("#### Bootstrapping %s modules ####", ml->name);

	for (instance = fr_rb_iter_init_inorder(ml->name_tree, &iter);
	     instance;
	     instance = fr_rb_iter_next_inorder(ml->name_tree, &iter)) {
	     	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);
		if (module_bootstrap(mi) < 0) return -1;
	}

	return 0;
}

/** Generate a module name from the module's name and its parents
 *
 * @param[in] ctx		Where to allocate the module name.
 * @param[out] out		Where to write a pointer to the instance name.
 * @param[in] parent		of the module.
 * @param[in] inst_name		module's instance name.
 */
static fr_slen_t module_instance_name(TALLOC_CTX *ctx, char **out,
				      module_instance_t const *parent, char const *inst_name)
{
	fr_sbuff_t *agg;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 64, MODULE_INSTANCE_LEN_MAX);

	/*
	 *	Parent has all of the qualifiers of its ancestors
	 *	already in the name, so we just need to concatenate.
	 */
	if (parent) {
		FR_SBUFF_IN_STRCPY_RETURN(agg, parent->name);
		FR_SBUFF_IN_CHAR_RETURN(agg, '.');
	}
	FR_SBUFF_IN_STRCPY_RETURN(agg, inst_name);

	MEM(*out = talloc_bstrndup(ctx, fr_sbuff_start(agg), fr_sbuff_used(agg)));

	return fr_sbuff_used(agg);
}

/** Detach the shallowest parent first
 *
 * This ensures that the module's parent is detached before it is.
 *
 * Generally parents reach into their children and not the other way
 * around.  Calling the parent's detach method first ensures that
 * there's no code that access the child module's instance data or
 * reach into its symbol space if it's being unloaded.
 *
 * @note If you don't want to detach the parent, maybe because its children
 *	are ephemeral, consider using a seaprate thread-local module list
 *	to hold the children instead.
 *
 * @param[in] mi	to detach.
 */
static void module_detach_parent(module_instance_t *mi)
{
	if (!(mi->state & (MODULE_INSTANCE_BOOTSTRAPPED | MODULE_INSTANCE_BOOTSTRAPPED))) return;

	if (mi->parent) module_detach_parent(UNCONST(module_instance_t *, mi->parent));

	if (mi->state & MODULE_INSTANCE_INSTANTIATED) {
		if (mi->exported && mi->exported->detach) {
			mi->exported->detach(MODULE_DETACH_CTX(mi));
		}
		mi->state ^= MODULE_INSTANCE_INSTANTIATED;
	}

	if (mi->state & MODULE_INSTANCE_BOOTSTRAPPED) {
		if (mi->exported && mi->exported->unstrap) {
			mi->exported->unstrap(MODULE_DETACH_CTX(mi));
		}
		mi->state ^= MODULE_INSTANCE_BOOTSTRAPPED;
	}
}

/** Free module's instance data, and any xlats or paircmps
 *
 * @param[in] mi to free.
 * @return 0
 */
static int _module_instance_free(module_instance_t *mi)
{
	module_list_t *ml = mi->ml;

	DEBUG3("Freeing %s (%p)", mi->name, mi);

	/*
	 *	Allow writing to instance and bootstrap data again
	 *	so we can clean up without segving.
	 */
	if (unlikely(module_data_unprotect(mi, &mi->inst_pool) < 0)) {
		cf_log_perr(mi->conf, "\"%s\"", mi->name);
		return -1;
	}
	if (unlikely(module_data_unprotect(mi, &mi->boot_pool) < 0)) {
		cf_log_perr(mi->conf, "\"%s\"", mi->name);
		return -1;
	}

	if (fr_rb_node_inline_in_tree(&mi->name_node) && !fr_cond_assert(fr_rb_delete(ml->name_tree, mi))) return 1;
	if (fr_rb_node_inline_in_tree(&mi->data_node) && !fr_cond_assert(fr_rb_delete(ml->data_tree, mi))) return 1;
	if (ml->type->data_del) ml->type->data_del(mi);

	/*
	 *	mi->exported may be NULL if we failed loading the module
	 */
	if (mi->exported && ((mi->exported->flags & MODULE_TYPE_THREAD_UNSAFE) != 0)) {
#ifndef NDEBUG
		int ret;

		/*
		 *	If the mutex is locked that means
		 *	the server exited without cleaning
		 *	up requests.
		 *
		 *	Assert that the mutex is not held.
		 */
		ret = pthread_mutex_trylock(&mi->mutex);
		fr_assert_msg(ret == 0, "Failed locking module mutex during exit: %s", fr_syserror(ret));
		pthread_mutex_unlock(&mi->mutex);
#endif
		pthread_mutex_destroy(&mi->mutex);
	}

	/*
	 *	Remove all xlat's registered to module instance.
	 */
	if (mi->data) {
		xlat_func_unregister(mi->name);
		xlat_func_unregister_module(mi);
	}

	module_detach_parent(mi);

	/*
	 *	We need to explicitly free all children, so the module instance
	 *	destructors get executed before we unload the bytecode for the
	 *	module.
	 *
	 *	If we don't do this, we get a SEGV deep inside the talloc code
	 *	when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(mi);

	dl_module_free(mi->module);

	return 0;
}

/** Duplicate a module instance, placing it in a new module list
 *
 * @param[in] dst	list to place the new module instance in.
 * @param[in] src	to duplicate.
 * @param[in] inst_name	new instance name.  If null, src->name will be used.
 */
module_instance_t *module_instance_copy(module_list_t *dst, module_instance_t const *src, char const *inst_name)
{
	module_instance_t *mi = module_instance_alloc(dst, src->parent, src->module->type,
						      src->module->name,
						      inst_name ? inst_name : src->name, 0);
	if (!mi) return NULL;

	return mi;
}

/** Allocate module instance data
 *
 * @param[in] ctx		talloc context to allocate data in.
 * @param[out] pool_out		where to write pool details.
 * @param[out] out		where to write data pointer.
 * @param[in] mi		module instance.
 * @param[in] size		of data to allocate.
 * @param[in] type		talloc type to assign.
 */
static inline CC_HINT(always_inline)
void module_instance_data_alloc(TALLOC_CTX *ctx, module_data_pool_t *pool_out, void **out,
				module_instance_t *mi, size_t size, char const *type)
{
	dl_module_t const	*module = mi->module;
	void			*data;

	/*
	 *	If there is supposed to be instance data, allocate it now.
	 *
	 *      If the structure is zero length then allocation will still
	 *	succeed, and will create a talloc chunk header.
	 *
	 *      This is needed so we can resolve instance data back to
	 *	module_instance_t/dl_module_t/dl_t.
	 */
	pool_out->ctx = talloc_page_aligned_pool(ctx,
						 &pool_out->start, &pool_out->len,
						 1, size);
	MEM(data = talloc_zero_array(pool_out->ctx, uint8_t, size));
	if (!type) {
		talloc_set_name(data, "%s_t", module->dl->name ? module->dl->name : "config");
	} else {
		talloc_set_name_const(data, type);
	}
	*out = data;
}

/** Check to see if a module instance name is valid
 *
 * @note On failure the error message may be retrieved with fr_strerror().
 *
 * @param[in] inst_name		to check.
 *
 * @return
 *	- 0 on success.
 *	- Negative value on error indicating the position of the bad char.
 */
fr_slen_t module_instance_name_valid(char const *inst_name)
{
	/*
	 *	[] are used for dynamic module selection.
	 *	. is used as a method and submodule separator.
	 *	Quoting and other characters would just confuse the parser in too many
	 *	instances so they're disallowed too.
	 */
	{
		size_t len = strlen(inst_name);

		for (size_t i = 0; i < len; i++) {
			if (!module_instance_allowed_chars[(uint8_t)inst_name[i]]) {
				fr_strerror_printf("Instance name \"%s\" contains an invalid character.  "
						   "Valid characters are [0-9a-zA-Z/_-]", inst_name);
				return -(i + 1);
			}
		}
	}

	return 0;
}

/** Set the uctx pointer for a module instance
 *
 * @param[in] mi	to set the uctx for.
 * @param[in] uctx	to set.
 */
void module_instance_uctx_set(module_instance_t *mi, void *uctx)
{
	mi->uctx = uctx;
}

/** Allocate a new module and add it to a module list for later bootstrap/instantiation
 *
 * - Load the module shared library.
 * - Allocate instance data for it.
 *
 * @param[in] ml		To add module to.
 * @param[in] parent		of the module being bootstrapped, if this is a submodule.
 *				If this is not a submodule parent must be NULL.
 * @param[in] type		What type of module we're loading.  Determines the prefix
 *				added to the library name.  Should be one of:
 *				- DL_MODULE_TYPE_MODULE - Standard backend module.
 *				- DL_MODULE_TYPE_SUBMODULE - Usually a driver for a backend module.
 *				- DL_MODULE_TYPE_PROTO - A module associated with a listen section.
 *				- DL_MODULE_TYPE_PROCESS - Protocol state machine bound to a virtual server.
 * @param[in] mod_name		The name of this module, i.e. 'redis' for 'rlm_redis'.
 * @param[in] inst_name		Instance name for this module, i.e. "aws_redis_01".
 *				The notable exception is if this is a submodule, in which case
 *				inst_name is usually the mod_name.
 * @param[in] init_state	The state the module "starts" in.  Can be used to prevent
 *				bootstrapping, instantiation, or thread instantiation of the module,
 *				by passing one or more of the MODULE_INSTANCE_* flags.
 *				Should usually be 0, unless special behaviour is required.
 * @return
 *	- A new module instance handle, containing the module's public interface,
 *	  and private instance data.
 *	- NULL on error.
 */
module_instance_t *module_instance_alloc(module_list_t *ml,
					 module_instance_t const *parent,
					 dl_module_type_t type, char const *mod_name, char const *inst_name,
					 module_instance_state_t init_state)
{
	char			*qual_inst_name = NULL;
	module_instance_t	*mi;

	fr_assert((type == DL_MODULE_TYPE_MODULE) ||
	          (parent && (type == DL_MODULE_TYPE_SUBMODULE)) ||
	          (type == DL_MODULE_TYPE_PROTO) ||
	          (type == DL_MODULE_TYPE_PROCESS));

	/*
	 *	Takes the inst_name and adds qualifiers
	 *	if this is a submodule.
	 */
	if (module_instance_name(NULL, &qual_inst_name, parent, inst_name) < 0) {
		ERROR("Module name too long");
		return NULL;
	}

	/*
	 *	See if the module already exists.
	 */
	mi = module_instance_by_name(ml, parent, qual_inst_name);
	if (mi) {
		/*
		 *	We may not have configuration data yet
		 *	for the duplicate module.
		 */
		if (mi->conf) {
			ERROR("Duplicate %s_%s instance \"%s\", previous instance defined at %s[%d]",
			      fr_table_str_by_value(dl_module_type_prefix, mi->module->type, "<INVALID>"),
			      mi->module->exported->name,
			      qual_inst_name,
			      cf_filename(mi->conf),
			      cf_lineno(mi->conf));

		} else {
			ERROR("Duplicate %s_%s instance \"%s\"",
			      fr_table_str_by_value(dl_module_type_prefix, mi->module->type, "<INVALID>"),
			      mi->module->exported->name,
			      qual_inst_name);
		}
		talloc_free(qual_inst_name);
		return NULL;
	}

	/*
	 *	Overallocate the module instance, so we can add
	 *	some module list type specific data to it.
	 */
	MEM(mi = (module_instance_t *)talloc_zero_array(parent ? (void const *)parent : (void const *)ml, uint8_t, ml->type->inst_size));
	talloc_set_name_const(mi, "module_instance_t");
	mi->name = talloc_typed_strdup(mi, qual_inst_name);
	talloc_free(qual_inst_name);	/* Avoid stealing */

	mi->ml = ml;
	mi->parent = parent;
	mi->state = init_state;

	/*
	 *	Increment the reference count on an already loaded module,
	 *	or load the .so or .dylib, and run all the global callbacks.
	 */
	mi->module = dl_module_alloc(parent ? parent->module : NULL, mod_name, type);
	if (!mi->module) {
	error:
		talloc_free(mi);
		return NULL;
	}

	/*
	 *	We have no way of checking if this is correct... so we hope...
	 */
	mi->exported = (module_t *)mi->module->exported;
	if (unlikely(mi->exported == NULL)) {
		ERROR("Missing public structure for \"%s\"", qual_inst_name);
		goto error;
	}

	/*
	 *	Allocate bootstrap data.
	 */
	if (mi->exported->bootstrap) {
		module_instance_data_alloc(mi, &mi->boot_pool, &mi->boot,
				   	   mi, mi->exported->boot_size, mi->exported->boot_type);
	}
	/*
	 *	Allocate the module instance data.  We always allocate
	 *	this so the module can use it for lookup.
	 */
	module_instance_data_alloc(mi, &mi->inst_pool, &mi->data,
				   mi, mi->exported->inst_size, mi->exported->inst_type);
	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we init the mutex.
	 *
	 *	Do this here so the destructor can trylock the mutex
	 *	correctly even if bootstrap/instantiation fails.
	 */
	if ((mi->exported->flags & MODULE_TYPE_THREAD_UNSAFE) != 0) pthread_mutex_init(&mi->mutex, NULL);
	talloc_set_destructor(mi, _module_instance_free);	/* Set late intentionally */
	mi->number = ml->last_number++;

	/*
	 *	Remember the module for later.
	 */
	if (!fr_cond_assert(fr_rb_insert(ml->name_tree, mi))) goto error;
	if (!fr_cond_assert(fr_rb_insert(ml->data_tree, mi))) goto error;
	if (ml->type->data_add && unlikely(ml->type->data_add(mi) < 0)) goto error;

	return mi;
}

/** Free all modules loaded by the server
 *
 * @param[in] ml	Module list being freed.
 * @return 0
 */
static int _module_list_free(module_list_t *ml)
{
	fr_rb_iter_inorder_t	iter;
	module_instance_t	*mi;

	/*
	 *	Re-initialize the iterator after freeing each module.
	 *	The module may have children which are also in the
	 *	tree.  It can cause problems when we delete children
	 *	without the iterator knowing about it.
	 */
	while ((mi = fr_rb_iter_init_inorder(ml->name_tree, &iter)) != NULL) {
		fr_rb_iter_delete_inorder(ml->name_tree, &iter);	/* Keeps the iterator sane */
		talloc_free(mi);
	}

	if (ml->type->free) ml->type->free(ml);

	return 0;
}

/** Should we bootstrap this module instance?
 *
 * @param[in] mi	to check.
 * @return
 *	- true if the module instance should be bootstrapped.
 *	- false if the module instance has already been bootstrapped.
 */
bool module_instance_skip_bootstrap(module_instance_t *mi)
{
	return ((mi->state | mi->ml->mask) & MODULE_INSTANCE_BOOTSTRAPPED);
}

/** Should we instantiate this module instance?
 *
 * @param[in] mi	to check.
 * @return
 *	- true if the module instance should be instantiated.
 *	- false if the module instance has already been instantiated.
 */
bool module_instance_skip_instantiate(module_instance_t *mi)
{
	return ((mi->state | mi->ml->mask) & MODULE_INSTANCE_INSTANTIATED);
}

/** Should we instantiate this module instance in a new thread?
 *
 * @param[in] mi	to check.
 * @return
 *	- true if the module instance should be instantiated in a new thread.
 *	- false if the module instance has already been instantiated in a new thread.
 */
bool module_instance_skip_thread_instantiate(module_instance_t *mi)
{
	return ((mi->state | mi->ml->mask) & MODULE_INSTANCE_NO_THREAD_INSTANTIATE);
}

/** Set a new bootstrap/instantiate state for a list
 *
 * @param[in] ml		To set the state for.
 * @param[in] mask		New state.
 */
void module_list_mask_set(module_list_t *ml, module_instance_state_t mask)
{
	ml->mask = mask;
}

/** Allocate a new module list
 *
 * This is used to instantiate and destroy modules in distinct phases
 * for example, we may need to load all proto modules before rlm modules.
 *
 * If the list is freed all module instance data will be freed.
 * If no more instances of the module exist the module be unloaded.
 *
 * @param[in] ctx		To allocate the list in.
 * @param[in] type		of the list.  Controls whether this is a global
 *				module list, or a per-thread list containing
 *				variants of an existing module.
 * @param[in] name		of the list.  Used for debugging.
 * @param[in] write_protect	Whether to write protect the module data
 *				after instantiation and bootstrapping.
 * @return A new module list.
 */
module_list_t *module_list_alloc(TALLOC_CTX *ctx, module_list_type_t const *type,
				 char const *name, bool write_protect)
{
	module_list_t *ml;

	/*
	 *	These callbacks are NOT optional, the rest are.
	 */
	fr_assert(type->thread.data_add);
	fr_assert(type->thread.data_get);
	fr_assert(type->thread.data_del);

	MEM(ml = talloc_zero(ctx, module_list_t));
	ml->type = type;

	ml->thread_data_get = type->thread.data_get;	/* Cache for access outside of the compilation unit */
	MEM(ml->name = talloc_typed_strdup(ml, name));
	MEM(ml->name_tree = fr_rb_inline_alloc(ml, module_instance_t, name_node, module_instance_name_cmp, NULL));
	MEM(ml->data_tree = fr_rb_inline_alloc(ml, module_instance_t, data_node, module_instance_data_cmp, NULL));
	talloc_set_destructor(ml, _module_list_free);

	if (ml->type->init && (ml->type->init(ml) < 0)) {
		talloc_free(ml);
		return NULL;
	}
	ml->write_protect = write_protect;

	return ml;
}

static int _module_dl_loader_init(void *uctx)
{
	dl_modules = dl_module_loader_init(uctx);

	/*
	 *	Ensure the common library tracking
	 *	tree is in place...
	 */
	global_lib_init();

	return 0;
}

static int _module_dl_loader_free(UNUSED void *uctx)
{
	if (talloc_free(dl_modules) < 0) return -1;
	dl_modules = NULL;
	return 0;
}

/** Perform global initialisation for modules
 *
 */
void modules_init(char const *lib_dir)
{
	/*
	 *	Create the global module heap we use for
	 *	common indexes in the thread-specific
	 *	heaps.
	 */
	fr_atexit_global_once(_module_dl_loader_init, _module_dl_loader_free, UNCONST(char *, lib_dir));
}
