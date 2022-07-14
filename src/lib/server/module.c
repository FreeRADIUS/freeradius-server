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
 * @brief Defines functions for module (re-)initialisation.
 *
 * @copyright 2003,2006,2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Alan Curry (pacman@world.std.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/server/request_data.h>

/** Heap of all lists/modules used to get a common index with module_thread_inst_list
 *
 */
static fr_heap_t *module_global_inst_list;

/** An array of thread-local module lists
 *
 * The indexes in this array are identical to module_list_global, allowing
 * O(1) lookups.  Arrays are used here as there's no performance penalty
 * once they're populated.
 */
static _Thread_local module_thread_instance_t **module_thread_inst_list;

/** Toggle used to determine if it's safe to use index based lookups
 *
 * Index based heap lookups are significantly more efficient than binary
 * searches, but they can only be performed when all module data is inserted
 * into both the global module list and the thread local module list.
 *
 * When we start removing module lists or modules from the thread local
 * heap those heaps no longer have a common index with the global module
 * list so we need to revert back to doing binary searches instead of using
 * common indexes.
 */
static _Thread_local bool module_list_in_sync = true;

/** dl module tracking
 *
 */
static dl_module_loader_t	*dl_modules = NULL;

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

	fr_assert(mi->dl_inst->conf != NULL);

	(void) cf_section_write(fp, mi->dl_inst->conf, 0);

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

	fr_heap_foreach(module_global_inst_list, module_instance_t, instance) {
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
	fr_heap_foreach(module_global_inst_list, module_instance_t, instance) {
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

/** Sort module instance data first by list then by number
 *
 * The module's position in the global instance heap informs of us
 * of its position in the thread-specific heap, which allows for
 * O(1) lookups.
 */
static int8_t _module_instance_global_cmp(void const *one, void const *two)
{
	module_instance_t const *a = talloc_get_type_abort_const(one, module_instance_t);
	module_instance_t const *b = talloc_get_type_abort_const(two, module_instance_t);
	int8_t ret;

	fr_assert(a->ml && b->ml);

	ret = CMP(a->ml, b->ml);
	if (ret != 0) return 0;

	return CMP(a->number, b->number);
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
	dl_module_inst_t const	*dl_inst;
	int a_depth = 0, b_depth = 0;
	int ret;

	/*
	 *	Sort by depth, so for tree walking we start
	 *	at the shallowest node, and finish with
	 *	the deepest child.
	 */
	for (dl_inst = a->dl_inst; dl_inst; dl_inst = dl_inst->parent) a_depth++;
	for (dl_inst = b->dl_inst; dl_inst; dl_inst = dl_inst->parent) b_depth++;

	ret = CMP(a_depth, b_depth);
	if (ret != 0) return ret;

	/*
	 *	This happens, as dl_inst is is used in
	 *	as the loop condition above.
	 */
#ifdef STATIC_ANALYZER
	if (!fr_cond_assert(a->dl_inst)) return +1;
	if (!fr_cond_assert(b->dl_inst)) return -1;
#endif

	ret = CMP(a->dl_inst->parent, b->dl_inst->parent);
	if (ret != 0) return ret;

	ret = strcmp(a->name, b->name);
	return CMP(ret, 0);
}

/** Compare module's by their private instance data
 *
 */
static int8_t module_instance_data_cmp(void const *one, void const *two)
{
	void const *a = (((module_instance_t const *)one)->dl_inst)->data;
	void const *b = (((module_instance_t const *)two)->dl_inst)->data;

	return CMP(a, b);
}

/** Generic callback for CONF_PARSER to load a submodule
 *
 * CONF_PARSER entry should point to a module_instance_t field in the instance data
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
			   CONF_ITEM *ci, CONF_PARSER const *rule)
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
	mi = module_alloc(ml, module_by_data(ml, parent), DL_MODULE_TYPE_SUBMODULE, name, name);
	if (unlikely(mi == NULL)) {
		cf_log_err(submodule_cs, "Failed loading submodule");
		return -1;
	}

	if (unlikely(module_conf_parse(mi, submodule_cs) < 0)) {
		cf_log_err(submodule_cs, "Failed parsing submodule config");
	error:
		talloc_free(mi);
		return -1;
	}

	if (unlikely(module_bootstrap(mi) < 0)) {
		cf_log_err(submodule_cs, "Failed bootstrapping submodule");
		goto error;

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
module_instance_t *module_by_name(module_list_t const *ml, module_instance_t const *parent, char const *asked_name)
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
				.dl_inst = &(dl_module_inst_t){ .parent = parent ? parent->dl_inst : NULL },
				.name = inst_name
			  });
	if (!inst) return NULL;

	return talloc_get_type_abort(inst, module_instance_t);
}

/** Find the module's parent (if any)
 *
 * @param[in] child	to locate the parent for.
 * @return
 *	- The module's parent.
 *	- NULL on error.
 */
module_instance_t *module_parent(module_instance_t const *child)
{
	dl_module_inst_t const *parent;

	parent = dl_module_parent_instance(child->dl_inst);
	if (!parent) return NULL;

	return module_by_data(child->ml, parent->data);
}

/** Find the module's shallowest parent
 *
 * @param[in] child	to locate the root for.
 * @return
 *	- The module's shallowest parent.
 *	- NULL on error.
 */
module_instance_t *module_root(module_instance_t const *child)
{
	module_instance_t *next;

	for (;;) {
		next = module_parent(child);
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
module_instance_t *module_by_data(module_list_t const *ml, void const *data)
{
	module_instance_t *mi;

	mi = fr_rb_find(ml->data_tree,
			&(module_instance_t){
				.dl_inst = &(dl_module_inst_t){ .data = UNCONST(void *, data) },
			});
	if (!mi) return NULL;

	return talloc_get_type_abort(mi, module_instance_t);
}


/** Retrieve module/thread specific instance for a module
 *
 * @param[in] mi	to find thread specific data for.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
module_thread_instance_t *module_thread(module_instance_t *mi)
{
	module_thread_instance_t	 *ti;

	fr_assert(mi->number < talloc_array_length(module_thread_inst_list));
	fr_assert(module_list_in_sync);
	fr_assert_msg(fr_heap_num_elements(module_global_inst_list) == talloc_array_length(module_thread_inst_list),
		      "mismatch between global module heap (%u entries) and thread local (%zu entries)",
		      fr_heap_num_elements(module_global_inst_list), talloc_array_length(module_thread_inst_list));

	ti = talloc_get_type_abort(module_thread_inst_list[mi->inst_idx - 1], module_thread_instance_t);
	fr_assert_msg(ti->mi == mi, "thread/module mismatch thread %s (%p), module %s (%p)",
		      ti->mi->name, ti->mi, mi->name, mi);
	return ti;
}

/** Retrieve module/thread specific instance data for a module
 *
 * @param[in] ml	Module list module belongs to.
 * @param[in] data	Private instance data of the module.
 *			Same as what would be provided by
 *			#module_by_data.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
module_thread_instance_t *module_thread_by_data(module_list_t const *ml, void const *data)
{
	module_instance_t		*mi = module_by_data(ml, data);
	module_thread_instance_t 	*ti;
	if (!mi) return NULL;

	fr_assert(mi->number < ml->last_number);
	fr_assert(module_list_in_sync);
	fr_assert_msg(fr_heap_num_elements(module_global_inst_list) == talloc_array_length(module_thread_inst_list),
		      "mismatch between global module heap (%u entries) and thread local (%zu entries)",
		      fr_heap_num_elements(module_global_inst_list), talloc_array_length(module_thread_inst_list));

	ti = talloc_get_type_abort(module_thread_inst_list[mi->inst_idx - 1], module_thread_instance_t);
	fr_assert_msg(ti->mi == mi, "thread/module mismatch thread %s (%p), module %s (%p)",
		      ti->mi->name, ti->mi, mi->name, mi);
	return ti;
}

/** Explicitly free a module if a fatal error occurs during bootstrap
 *
 * @param[in] mi	to free.
 */
void module_free(module_instance_t *mi)
{
	talloc_free(mi);
}

/** Remove thread-specific data for a given module list
 *
 * Removes all module thread data for the
 */
void modules_thread_detach(module_list_t const *ml)
{
	fr_rb_iter_inorder_t		iter;
	void				*instance;

	/*
	 *	Loop over all the modules in the module list
	 *	finding and extracting their thread specific
	 *	data, and calling their detach methods.
	 */
	for (instance = fr_rb_iter_init_inorder(&iter, ml->name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
	     	module_instance_t		*mi = talloc_get_type_abort(instance, module_instance_t);

	     	talloc_free(module_thread_inst_list[mi->inst_idx - 1]);
	}
}

static int _module_thread_inst_free(module_thread_instance_t *ti)
{
	module_instance_t const *mi = ti->mi;

	module_list_in_sync = false;	/* Help catch anything attempting to do lookups */

	DEBUG4("Worker cleaning up %s thread instance data (%p/%p)",
	       mi->module->name, ti, ti->data);

	if (mi->module->thread_detach) {
		mi->module->thread_detach(&(module_thread_inst_ctx_t const ){
						.inst = ti->mi->dl_inst,
						.thread = ti->data,
						.el = ti->el
					  });
	}

	/*
	 *	Pull the thread instance out of the tree
	 */
	module_thread_inst_list[ti->mi->inst_idx - 1] = NULL;
	return 0;
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

/** Creates per-thread instance data for modules which need it
 *
 * Must be called by any new threads before attempting to execute unlang sections.
 *
 * @param[in] ctx	Talloc ctx to bind thread specific data to.
 * @param[in] ml	Module list to perform thread instantiation for.
 * @param[in] el	Event list servived by this thread.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_thread_instantiate(TALLOC_CTX *ctx, module_list_t const *ml, fr_event_list_t *el)
{
	void			*instance;
	fr_rb_iter_inorder_t	iter;

	/*
	 *	Initialise the thread specific tree if this is the
	 *	first time through or if everything else was
	 *	de-initialised.
	 */
	if (!module_thread_inst_list) {
		module_thread_instance_t **arr;

		arr = talloc_zero_array(NULL, module_thread_instance_t *,
					fr_heap_num_elements(module_global_inst_list));

		fr_atexit_thread_local(module_thread_inst_list, _module_thread_inst_list_free, arr);
	}

	for (instance = fr_rb_iter_init_inorder(&iter, ml->name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
		module_instance_t		*mi = talloc_get_type_abort(instance, module_instance_t), *rmi;
		module_thread_instance_t	*ti;
		TALLOC_CTX			*our_ctx = ctx;

		/*
		 *	Check the list pointers are ok
		 */
		(void)talloc_get_type_abort(mi->ml, module_list_t);

		MEM(ti = talloc_zero(our_ctx, module_thread_instance_t));
		talloc_set_destructor(ti, _module_thread_inst_free);
		ti->el = el;
		ti->mi = mi;

		if (mi->module->thread_inst_size) {
			MEM(ti->data = talloc_zero_array(ti, uint8_t, mi->module->thread_inst_size));

			rmi = module_root(mi);

			/*
			 *	Fixup the type name, incase something calls
			 *	talloc_get_type_abort() on it...
			 */
			if (!mi->module->thread_inst_type) {
				talloc_set_name(ti->data, "%s_%s_thread_t",
						fr_table_str_by_value(dl_module_type_prefix,
								      rmi ? rmi->dl_inst->module->type :
								            mi->dl_inst->module->type,
								      "<INVALID>"),
						mi->module->name);
			} else {
				talloc_set_name_const(ti->data, mi->module->thread_inst_type);
			}
		}

		DEBUG4("Worker alloced %s thread instance data (%p/%p)", ti->mi->module->name, ti, ti->data);
		if (mi->module->thread_instantiate &&
		    mi->module->thread_instantiate(MODULE_THREAD_INST_CTX(mi->dl_inst, ti->data, el)) < 0) {
			PERROR("Thread instantiation failed for module \"%s\"", mi->name);
			/* Leave module_thread_inst_list intact, other modules may need to clean up */
			modules_thread_detach(ml);
			return -1;
		}

		module_thread_inst_list[ti->mi->inst_idx - 1] = ti;
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
	CONF_SECTION *cs = mi->dl_inst->conf;

	/*
	 *	We only instantiate modules in the bootstrapped state
	 */
	if (mi->state != MODULE_INSTANCE_BOOTSTRAPPED) return 0;

	if (fr_command_register_hook(NULL, mi->name, mi, module_cmd_table) < 0) {
		PERROR("Failed registering radmin commands for module %s", mi->name);
		return -1;
	}

	/*
	 *	Now that ALL modules are instantiated, and ALL xlats
	 *	are defined, go compile the config items marked as XLAT.
	 */
	if (mi->module->config && (cf_section_parse_pass2(mi->dl_inst->data,
							  mi->dl_inst->conf) < 0)) return -1;

	/*
	 *	Call the instantiate method, if any.
	 */
	if (mi->module->instantiate) {
		cf_log_debug(cs, "Instantiating %s_%s \"%s\"",
			     fr_table_str_by_value(dl_module_type_prefix, mi->dl_inst->module->type, "<INVALID>"),
			     mi->dl_inst->module->common->name,
			     mi->name);

		/*
		 *	Call the module's instantiation routine.
		 */
		if (mi->module->instantiate(MODULE_INST_CTX(mi->dl_inst)) < 0) {
			cf_log_err(mi->dl_inst->conf, "Instantiation failed for module \"%s\"", mi->name);

			return -1;
		}
	}
	mi->state = MODULE_INSTANCE_INSTANTIATED;

	return 0;
}

/** Completes instantiation of modules
 *
 * Allows the module to initialise connection pools, and complete any registrations that depend on
 * attributes created during the bootstrap phase.
 *
 * @param[in] ml containing modules ot instantiate.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_instantiate(module_list_t const *ml)
{
	void			*instance;
	fr_rb_iter_inorder_t	iter;

	DEBUG2("#### Instantiating %s modules ####", ml->name);

	for (instance = fr_rb_iter_init_inorder(&iter, ml->name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
	     	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);
		if (mi->state != MODULE_INSTANCE_BOOTSTRAPPED) continue;

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
	if (mi->state != MODULE_INSTANCE_INIT) return 0;

	/*
	 *	Bootstrap the module.
	 *	This must be done last so that the
	 *	module can find its module_instance_t
	 *	in the trees if it needs to bootstrap
	 *	submodules.
	 */
	if (mi->module->bootstrap) {
		CONF_SECTION *cs = mi->dl_inst->conf;

		cf_log_debug(cs, "Bootstrapping %s_%s \"%s\"",
			     fr_table_str_by_value(dl_module_type_prefix, mi->dl_inst->module->type, "<INVALID>"),
			     mi->dl_inst->module->common->name,
			     mi->name);

		if (mi->module->bootstrap(MODULE_INST_CTX(mi->dl_inst)) < 0) {
			cf_log_err(cs, "Bootstrap failed for module \"%s\"", mi->name);
			return -1;
		}
	}
	mi->state = MODULE_INSTANCE_BOOTSTRAPPED;

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

	for (instance = fr_rb_iter_init_inorder(&iter, ml->name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
	     	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);
		if (mi->state != MODULE_INSTANCE_INIT) continue;

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
static fr_slen_t module_instance_name(TALLOC_CTX *ctx, char **out, module_list_t const *ml,
				      module_instance_t const *parent, char const *inst_name)
{
	fr_sbuff_t *agg;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 64, 256);

	while (parent) {
		FR_SBUFF_IN_STRCPY_RETURN(agg, parent->name);
		FR_SBUFF_IN_CHAR_RETURN(agg, '.');

		if (!parent->dl_inst->parent) break;

		parent = module_by_data(ml, parent->dl_inst->parent->data);
	}

	FR_SBUFF_IN_STRCPY_RETURN(agg, inst_name);

	MEM(*out = talloc_bstrndup(ctx, fr_sbuff_start(agg), fr_sbuff_used(agg)));

	return fr_sbuff_used(agg);

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

	if (fr_heap_entry_inserted(mi->inst_idx) && !fr_cond_assert(fr_heap_extract(&module_global_inst_list, mi) == 0)) return 1;
	if (fr_rb_node_inline_in_tree(&mi->name_node) && !fr_cond_assert(fr_rb_delete(ml->name_tree, mi))) return 1;
	if (fr_rb_node_inline_in_tree(&mi->data_node) && !fr_cond_assert(fr_rb_delete(ml->data_tree, mi))) return 1;

	/*
	 *	mi->module may be NULL if we failed loading the module
	 */
	if (mi->module && ((mi->module->type & MODULE_TYPE_THREAD_UNSAFE) != 0)) {
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
	if (mi->dl_inst && mi->dl_inst->data) {
		xlat_unregister(mi->name);
		/*
		 *	Remove any registered paircmps.
		 */
		paircmp_unregister_instance(mi->dl_inst->data);
		xlat_unregister_module(mi->dl_inst);
	}

	/*
	 *	We need to explicitly free all children, so the module instance
	 *	destructors get executed before we unload the bytecode for the
	 *	module.
	 *
	 *	If we don't do this, we get a SEGV deep inside the talloc code
	 *	when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(mi);

	return 0;
}

/** Parse the configuration associated with a module
 *
 * @param[in] mi	To parse the configuration for.
 * @param[in] mod_conf	To parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int module_conf_parse(module_instance_t *mi, CONF_SECTION *mod_conf)
{
	if (dl_module_conf_parse(mi->dl_inst, mod_conf) < 0) return -1;

	return 0;
}

/** Allocate a new module and add it to a module list for later bootstrap/instantiation
 *
 * - Load the module shared library.
 * - Allocate instance data for it.
 *
 * @param[in] ml	To add module to.
 * @param[in] parent	of the module being bootstrapped, if this is a submodule.
 *			If this is not a submodule parent must be NULL.
 * @param[in] type	What type of module we're loading.  Determines the prefix
 *			added to the library name.  Should be one of:
 *			- DL_MODULE_TYPE_MODULE - Standard backend module.
 *			- DL_MODULE_TYPE_SUBMODULE - Usually a driver for a backend module.
 *			- DL_MODULE_TYPE_PROTO - A module associated with a listen section.
 *			- DL_MODULE_TYPE_PROCESS - Protocol state machine bound to a virtual server.
 * @param[in] mod_name	The name of this module, i.e. 'redis' for 'rlm_redis'.
 * @param[in] inst_name	Instance name for this module, i.e. "aws_redis_01".
 *			The notable exception is if this is a submodule, in which case
 *			inst_name is usually the mod_name.
 * @return
 *	- A new module instance handle, containing the module's public interface,
 *	  and private instance data.
 *	- NULL on error.
 */
module_instance_t *module_alloc(module_list_t *ml,
			        module_instance_t const *parent,
			        dl_module_type_t type, char const *mod_name, char const *inst_name)
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
	if (module_instance_name(NULL, &qual_inst_name, ml, parent, inst_name) < 0) {
		ERROR("Module name too long");
		return NULL;
	}

	/*
	 *	See if the module already exists.
	 */
	mi = module_by_name(ml, parent, qual_inst_name);
	if (mi) {
		/*
		 *	We may not have configuration data yet
		 *	for the duplicate module.
		 */
		if (mi->dl_inst->conf) {
			ERROR("Duplicate %s_%s instance \"%s\", previous instance defined at %s[%d]",
			      fr_table_str_by_value(dl_module_type_prefix, mi->dl_inst->module->type, "<INVALID>"),
			      mi->dl_inst->module->common->name,
			      qual_inst_name,
			      cf_filename(mi->dl_inst->conf),
			      cf_lineno(mi->dl_inst->conf));

		} else {
			ERROR("Duplicate %s_%s instance \"%s\"",
			      fr_table_str_by_value(dl_module_type_prefix, mi->dl_inst->module->type, "<INVALID>"),
			      mi->dl_inst->module->common->name,
			      qual_inst_name);
		}
		talloc_free(qual_inst_name);
		return NULL;
	}

	MEM(mi = talloc_zero(parent ? (void const *)parent : (void const *)ml, module_instance_t));
	if (dl_module_instance(mi, &mi->dl_inst, parent ? parent->dl_inst : NULL,
			       type, mod_name, qual_inst_name) < 0) {
	error:
		mi->name = qual_inst_name;	/* Assigned purely for debug log output when mi is freed */
		talloc_free(mi);
		talloc_free(qual_inst_name);
		return NULL;
	}
	fr_assert(mi->dl_inst);

	mi->module = (module_t const *)mi->dl_inst->module->common;
	if (!mi->module) {
		ERROR("Missing public structure for \"%s\"", qual_inst_name);
		talloc_free(mi);
		return NULL;
	}

	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we init the mutex.
	 *
	 *	Do this here so the destructor can trylock the mutex
	 *	correctly even if bootstrap/instantiation fails.
	 */
	if ((mi->module->type & MODULE_TYPE_THREAD_UNSAFE) != 0) pthread_mutex_init(&mi->mutex, NULL);
	talloc_set_destructor(mi, _module_instance_free);

	mi->name = talloc_typed_strdup(mi, qual_inst_name);
	talloc_free(qual_inst_name);	/* Avoid stealing */

	mi->number = ml->last_number++;
	mi->ml = ml;

	/*
	 *	Remember the module for later.
	 */
	if (!fr_cond_assert(fr_rb_insert(ml->name_tree, mi))) goto error;

	/*
	 *	Allow modules to get at their own
	 *	module_instance_t data, for
	 *	looking up thread specific data
	 *	and for bootstrapping submodules.
	 */
	if (mi->dl_inst->data && !fr_cond_assert(fr_rb_insert(ml->data_tree, mi))) goto error;

	/*
	 *	...and finally insert the module
	 *	into the global heap so we can
	 *	get common thread-local indexes.
	 */
	if (fr_heap_insert(&module_global_inst_list, mi) < 0) goto error;

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
	 *	We explicitly free modules so that
	 *	they're done in a stable order.
	 */
	for (mi = fr_rb_iter_init_inorder(&iter, ml->name_tree);
	     mi;
	     mi = fr_rb_iter_next_inorder(&iter)) {
		fr_rb_iter_delete_inorder(&iter);	/* Keeps the iterator sane */
		talloc_free(mi);
	}

	return 0;
}

/** Allocate a new module list
 *
 * This is used to instantiate and destroy modules in distinct phases
 * for example, we may need to load all proto modules before rlm modules.
 *
 * If the list is freed all module instance data will be freed.
 * If no more instances of the module exist the module be unloaded.
 *
 * @param[in] ctx	To allocate the list in.
 * @return A new module list.
 */
module_list_t *module_list_alloc(TALLOC_CTX *ctx, char const *name)
{
	module_list_t *ml;

	MEM(ml = talloc_zero(ctx, module_list_t));
	talloc_set_destructor(ml, _module_list_free);

	MEM(ml->name = talloc_typed_strdup(ml, name));
	MEM(ml->name_tree = fr_rb_inline_alloc(ml, module_instance_t, name_node, module_instance_name_cmp, NULL));
	MEM(ml->data_tree = fr_rb_inline_alloc(ml, module_instance_t, data_node, module_instance_data_cmp, NULL));

	return ml;
}

static void _module_global_list_init(void *uctx)
{
	dl_modules = dl_module_loader_init(uctx);
	MEM(module_global_inst_list = fr_heap_alloc(NULL, _module_instance_global_cmp, module_instance_t, inst_idx, 256));

	/*
	 *	Ensure the common library tracking
	 *	tree is in place...
	 */
	global_lib_init();
}

static int _module_global_list_free(UNUSED void *uctx)
{

	if (!fr_cond_assert_msg(fr_heap_num_elements(module_global_inst_list) == 0,
				"Global module heap has %u elements remaining on exit.  This is a leak",
				fr_heap_num_elements(module_global_inst_list))) return -1;
	if (talloc_free(module_global_inst_list) < 0) return -1;
	module_global_inst_list = NULL;

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
	fr_atexit_global_once(_module_global_list_init, _module_global_list_free, UNCONST(char *, lib_dir));
}
