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
 * @copyright 2003,2006,2016  The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000 Alan DeKok <aland@ox.org>
 * @copyright 2000 Alan Curry <pacman@world.std.com>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/server/cf_file.h>

static _Thread_local rbtree_t *module_thread_inst_tree;

static TALLOC_CTX *instance_ctx = NULL;

static int module_instantiate(CONF_SECTION *root, char const *name);
static fr_cmd_table_t cmd_module_table[];

/** Initialise a module specific exfile handle
 *
 * @see exfile_init
 *
 * @param[in] ctx		to bind the lifetime of the exfile handle to.
 * @param[in] module		section.
 * @param[in] max_entries	Max file descriptors to cache, and manage locks for.
 * @param[in] max_idle		Maximum time a file descriptor can be idle before it's closed.
 * @param[in] locking		Whether	or not to lock the files.
 * @param[in] trigger_prefix	if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
exfile_t *module_exfile_init(TALLOC_CTX *ctx,
			     CONF_SECTION *module,
			     uint32_t max_entries,
			     uint32_t max_idle,
			     bool locking,
			     char const *trigger_prefix,
			     VALUE_PAIR *trigger_args)
{
	char		trigger_prefix_buff[128];
	exfile_t	*handle;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.file", cf_section_name1(module));
		trigger_prefix = trigger_prefix_buff;
	}

	handle = exfile_init(ctx, max_entries, max_idle, locking);
	if (!handle) return NULL;

	exfile_enable_triggers(handle, cf_section_find(module, "file", NULL), trigger_prefix, trigger_args);

	return handle;
}

/** Resolve polymorphic item's from a module's #CONF_SECTION to a subsection in another module
 *
 * This allows certain module sections to reference module sections in other instances
 * of the same module and share #CONF_DATA associated with them.
 *
 * @verbatim
   example {
   	data {
   		...
   	}
   }

   example inst {
   	data = example
   }
 * @endverbatim
 *
 * @param[out] out where to write the pointer to a module's config section.  May be NULL on success,
 *	indicating the config item was not found within the module #CONF_SECTION
 *	or the chain of module references was followed and the module at the end of the chain
 *	did not a subsection.
 * @param[in] module #CONF_SECTION.
 * @param[in] name of the polymorphic sub-section.
 * @return
 *	- 0 on success with referenced section.
 *	- 1 on success with local section.
 *	- -1 on failure.
 */
int module_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name)
{
	CONF_PAIR		*cp;
	CONF_SECTION		*cs;
	CONF_DATA const		*cd;


	module_instance_t	*mi;
	char const		*inst_name;

#define FIND_SIBLING_CF_KEY "find_sibling"

	*out = NULL;

	/*
	 *	Is a real section (not referencing sibling module).
	 */
	cs = cf_section_find(module, name, NULL);
	if (cs) {
		*out = cs;

		return 0;
	}

	/*
	 *	Item omitted completely from module config.
	 */
	cp = cf_pair_find(module, name);
	if (!cp) return 0;

	if (cf_data_find(module, CONF_SECTION, FIND_SIBLING_CF_KEY)) {
		cf_log_err(cp, "Module reference loop found");

		return -1;
	}
	cd = cf_data_add(module, module, FIND_SIBLING_CF_KEY, false);

	/*
	 *	Item found, resolve it to a module instance.
	 *	This triggers module loading, so we don't have
	 *	instantiation order issues.
	 */
	inst_name = cf_pair_value(cp);
	mi = module_find(cf_item_to_section(cf_parent(module)), inst_name);
	if (!mi) {
		cf_log_err(cp, "Unknown module instance \"%s\"", inst_name);

		return -1;
	}

	if (!mi->instantiated) {
		CONF_SECTION *parent = module;

		/*
		 *	Find the root of the config...
		 */
		do {
			CONF_SECTION *tmp;

			tmp = cf_item_to_section(cf_parent(parent));
			if (!tmp) break;

			parent = tmp;
		} while (true);

		module_instantiate(parent, inst_name);
	}

	/*
	 *	Remove the config data we added for loop
	 *	detection.
	 */
	cf_data_remove(module, cd);

	/*
	 *	Check the module instances are of the same type.
	 */
	if (strcmp(cf_section_name1(mi->dl_inst->conf), cf_section_name1(module)) != 0) {
		cf_log_err(cp, "Referenced module is a rlm_%s instance, must be a rlm_%s instance",
			      cf_section_name1(mi->dl_inst->conf), cf_section_name1(module));

		return -1;
	}

	*out = cf_section_find(mi->dl_inst->conf, name, NULL);

	return 1;
}

/** Initialise a module specific connection pool
 *
 * @see fr_pool_init
 *
 * @param[in] module		section.
 * @param[in] opaque		data pointer to pass to callbacks.
 * @param[in] c			Callback to create new connections.
 * @param[in] a			Callback to check the status of connections.
 * @param[in] log_prefix	override, if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_prefix	if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_pool_t *module_connection_pool_init(CONF_SECTION *module,
				       void *opaque,
				       fr_pool_connection_create_t c,
				       fr_pool_connection_alive_t a,
				       char const *log_prefix,
				       char const *trigger_prefix,
				       VALUE_PAIR *trigger_args)
{
	CONF_SECTION *cs, *mycs;
	char log_prefix_buff[128];
	char trigger_prefix_buff[128];

	fr_pool_t *pool;
	char const *cs_name1, *cs_name2;

	int ret;

#define parent_name(_x) cf_section_name(cf_item_to_section(cf_parent(_x)))

	cs_name1 = cf_section_name1(module);
	cs_name2 = cf_section_name2(module);
	if (!cs_name2) cs_name2 = cs_name1;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.pool", cs_name1);
		trigger_prefix = trigger_prefix_buff;
	}

	if (!log_prefix) {
		snprintf(log_prefix_buff, sizeof(log_prefix_buff), "rlm_%s (%s)", cs_name1, cs_name2);
		log_prefix = log_prefix_buff;
	}

	/*
	 *	Get sibling's pool config section
	 */
	ret = module_sibling_section_find(&cs, module, "pool");
	switch (ret) {
	case -1:
		return NULL;

	case 1:
		DEBUG4("%s: Using pool section from \"%s\"", log_prefix, parent_name(cs));
		break;

	case 0:
		DEBUG4("%s: Using local pool section", log_prefix);
		break;
	}

	/*
	 *	Get our pool config section
	 */
	mycs = cf_section_find(module, "pool", NULL);
	if (!mycs) {
		DEBUG4("%s: Adding pool section to config item \"%s\" to store pool references", log_prefix,
		       cf_section_name(module));

		mycs = cf_section_alloc(module, module, "pool", NULL);
	}

	/*
	 *	Sibling didn't have a pool config section
	 *	Use our own local pool.
	 */
	if (!cs) {
		DEBUG4("%s: \"%s.pool\" section not found, using \"%s.pool\"", log_prefix,
		       parent_name(cs), parent_name(mycs));
		cs = mycs;
	}

	/*
	 *	If fr_pool_init has already been called
	 *	for this config section, reuse the previous instance.
	 *
	 *	This allows modules to pass in the config sections
	 *	they would like to use the connection pool from.
	 */
	pool = cf_data_value(cf_data_find(cs, fr_pool_t, NULL));
	if (!pool) {
		DEBUG4("%s: No pool reference found for config item \"%s.pool\"", log_prefix, parent_name(cs));
		pool = fr_pool_init(cs, cs, opaque, c, a, log_prefix);
		if (!pool) return NULL;

		fr_pool_enable_triggers(pool, trigger_prefix, trigger_args);

		DEBUG4("%s: Adding pool reference %p to config item \"%s.pool\"", log_prefix, pool, parent_name(cs));
		cf_data_add(cs, pool, NULL, false);
		return pool;
	}
	fr_pool_ref(pool);

	DEBUG4("%s: Found pool reference %p in config item \"%s.pool\"", log_prefix, pool, parent_name(cs));

	/*
	 *	We're reusing pool data add it to our local config
	 *	section. This allows other modules to transitively
	 *	re-use a pool through this module.
	 */
	if (mycs != cs) {
		DEBUG4("%s: Copying pool reference %p from config item \"%s.pool\" to config item \"%s.pool\"",
		       log_prefix, pool, parent_name(cs), parent_name(mycs));
		cf_data_add(mycs, pool, NULL, false);
	}

	return pool;
}

/** Set the next section type if it's not already set
 *
 * @param[in] request		The current request.
 * @param[in] type_da		to use.  Usually attr_auth_type.
 * @param[in] enumv		Enumeration value of the specified type_da.
 */
bool module_section_type_set(REQUEST *request, fr_dict_attr_t const *type_da, fr_dict_enum_t const *enumv)
{
	VALUE_PAIR *vp;

	switch (pair_update_control(&vp, type_da)) {
	case 0:
		fr_value_box_copy(vp, &vp->data, enumv->value);
		vp->data.enumv = vp->da;	/* So we get the correct string alias */
		RDEBUG("Setting &control:%pP", vp);
		return true;

	case 1:
		RDEBUG2("&control:%s already set.  Not setting to %s", vp->da->name, enumv->alias);
		return false;

	default:
		MEM(0);
		return false;
	}
}

/** Mark module instance data as being read only
 *
 * This still allows memory to be modified, but not allocated
 */
int module_instance_read_only(TALLOC_CTX *ctx, char const *name)
{
	int rcode;
	size_t size;

	size = talloc_total_size(ctx);

	rcode = talloc_set_memlimit(ctx, size);
	if (rcode < 0) {
		ERROR("Failed setting memory limit for module %s", name);
	} else {
		DEBUG3("Memory limit for module %s is set to %zd bytes", name, size);
	}

	return rcode;
}

/** Find an existing module instance
 *
 * @param[in] modules		section in the main config.
 * @param[in] asked_name 	The name of the module we're attempting to find.
 *				May include '-' which indicates that it's ok for
 *				the module not to be loaded.
 * @return
 *	- Module instance matching name.
 *	- NULL if not such module exists.
 */
module_instance_t *module_find(CONF_SECTION *modules, char const *asked_name)
{
	char const *inst_name;
	void *inst;

	if (!modules) return NULL;

	/*
	 *	Look for the real name.  Ignore the first character,
	 *	which tells the server "it's OK for this module to not
	 *	exist."
	 */
	inst_name = asked_name;
	if (inst_name[0] == '-') inst_name++;

	inst = cf_data_value(cf_data_find(modules, module_instance_t, inst_name));
	if (!inst) return NULL;

	return talloc_get_type_abort(inst, module_instance_t);
}

/** Free all modules loaded by the server
 *
 * @return 0.
 */
int modules_free(void)
{
	/*
	 *	Free instances first, then dynamic libraries.
	 */
	TALLOC_FREE(instance_ctx);

	return 0;
}

/** Find an existing module instance and verify it implements the specified method
 *
 * Extracts the method from the module name where the format is @verbatim <module>.<method> @endverbatim
 * and ensures the module implements the specified method.
 *
 * @param[out] method		the method component we found associated with the module. May be NULL.
 * @param[in] modules		section in the main config.
 * @param[in] name 		The name of the module we're attempting to find, concatenated with
 *				the method.
 * @return
 *	- The module instance on success.
 *	- NULL on error (or not found).
 */
module_instance_t *module_find_with_method(rlm_components_t *method, CONF_SECTION *modules, char const *name)
{
	char			*p;
	rlm_components_t	i;
	module_instance_t	*mi;

	/*
	 *	Module names are allowed to contain '.'
	 *	so we search for the bare module name first.
	 */
	mi = module_find(modules, name);
	if (mi) return mi;

	/*
	 *	Find out if the instance name contains
	 *	a method, if it doesn't, then the module
	 *	doesn't exist.
	 */
	p = strrchr(name, '.');
	if (!p) return NULL;

	/*
	 *	Find the component.
	 */
	for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
		if (strcmp(p + 1, section_type_value[i].section) == 0) {
			char *inst_name;

			inst_name = talloc_bstrndup(NULL, name, p - name);
			mi = module_find(modules, inst_name);
			talloc_free(inst_name);
			if (!mi) return NULL;

			/*
			 *	Verify the module actually implements
			 *	the specified method.
			 */
			if (!mi->module->methods[i]) {
				cf_log_debug(modules, "%s does not implement method \"%s\"",
					     mi->module->name, p + 1);
				return NULL;
			}
			if (method) *method = i;

			return mi;
		}
	}

	return mi;
}

/** Retrieve module/thread specific instance data for a module
 *
 * @param[in] mi		to find thread specific data for.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
module_thread_instance_t *module_thread_instance_find(module_instance_t *mi)
{
	rbtree_t			*tree = module_thread_inst_tree;
	module_thread_instance_t	find = { .mod_inst = mi->dl_inst->data };

	return rbtree_finddata(tree, &find);
}

/** Retrieve module/thread specific instance data for a module
 *
 * @param[in] mod_inst		Module specific instance to find thread_data for.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
void *module_thread_instance_by_data(void *mod_inst)
{
	rbtree_t			*tree = module_thread_inst_tree;
	module_thread_instance_t	find = { .mod_inst = mod_inst }, *found;

	found = rbtree_finddata(tree, &find);
	if (!found) return NULL;

	return found->data;
}

/** Destructor for module_thread_instance_t
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static void _module_thread_instance_free(void *to_free)
{
	module_thread_instance_t *ti = talloc_get_type_abort(to_free, module_thread_instance_t);

	DEBUG4("Worker cleaning up %s thread instance data (%p/%p)", ti->module->name, ti, ti->data);
	if (ti->module->thread_detach) (void) ti->module->thread_detach(ti->el, ti->data);

	talloc_free(ti);
}

/** Compare two thread instances based on inst pointer
 *
 * @param[in] a		First thread specific module instance.
 * @param[in] b		Second thread specific module instance.
 * @return
 *	- +1 if a > b.
 *	- -1 if a < b.
 *	- 0 if a == b.
 */
static int _module_thread_inst_tree_cmp(void const *a, void const *b)
{
	module_thread_instance_t const *my_a = a, *my_b = b;

	return (my_a->mod_inst > my_b->mod_inst) - (my_a->mod_inst < my_b->mod_inst);
}

typedef struct {
	rbtree_t	*tree;		//!< Containing the thread instances.
	fr_event_list_t *el;		//!< Event list for this thread.
} _thread_intantiate_ctx_t;

/** Setup thread specific instance data for a module
 *
 * @param[in] instance	of module to perform thread instantiation for.
 * @param[in] ctx	additional arguments to pass to a module's thread_instantiate function.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _module_thread_instantiate(void *instance, void *ctx)
{
	module_instance_t		*mi = talloc_get_type_abort(instance, module_instance_t);
	module_thread_instance_t	*ti;
	_thread_intantiate_ctx_t	*thread_inst_ctx = ctx;
	int				ret;

	MEM(ti = talloc_zero(thread_inst_ctx->tree, module_thread_instance_t));
	ti->el = thread_inst_ctx->el;
	ti->module = mi->module;
	ti->mod_inst = mi->dl_inst->data;	/* For efficient lookups */

	if (mi->module->thread_inst_size) {
		char *type_name;

		MEM(ti->data = talloc_zero_array(ti, uint8_t, mi->module->thread_inst_size));

		/*
		 *	Fixup the type name, incase something calls
		 *	talloc_get_type_abort() on it...
		 */
		MEM(type_name = talloc_typed_asprintf(NULL, "rlm_%s_thread_t", mi->module->name));
		talloc_set_name(ti->data, "%s", type_name);
		talloc_free(type_name);
	}

	DEBUG4("Worker alloced %s thread instance data (%p/%p)", ti->module->name, ti, ti->data);
	if (mi->module->thread_instantiate) {
		ret = mi->module->thread_instantiate(mi->dl_inst->conf, mi->dl_inst->data,
						     thread_inst_ctx->el, ti->data);
		if (ret < 0) {
			ERROR("Thread instantiation failed for module \"%s\"", mi->name);
			return -1;
		}
	}

	rbtree_insert(thread_inst_ctx->tree, ti);

	return 0;
}

/** Creates per-thread instance data for modules which need it
 *
 * Must be called by any new threads before attempting to execute unlang sections.
 *
 * @param[in] ctx	to bind instance tree lifetime to.  Must not be
 *			shared between multiple threads.
 * @param[in] root	Configuration root.
 * @param[in] el	Event list servived by this thread.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_thread_instantiate(TALLOC_CTX *ctx, CONF_SECTION *root, fr_event_list_t *el)
{
	CONF_SECTION			*modules;
	_thread_intantiate_ctx_t	uctx;

	modules = cf_section_find(root, "modules", NULL);
	if (!modules) return 0;

	if (!module_thread_inst_tree) {
		MEM(module_thread_inst_tree = rbtree_talloc_create(ctx, _module_thread_inst_tree_cmp,
							    	   module_thread_instance_t,
							    	   _module_thread_instance_free, 0));
	}

	uctx.el = el;
	uctx.tree = module_thread_inst_tree;

	if (cf_data_walk(modules, module_instance_t, _module_thread_instantiate, &uctx) < 0) {
		TALLOC_FREE(module_thread_inst_tree);
		return -1;
	}

	return 0;
}


/** Complete module setup by calling its instantiate function
 *
 * @param[in] instance	of module to complete instantiation for.
 * @param[in] ctx	modules section, containing instance data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _module_instantiate(void *instance, UNUSED void *ctx)
{
	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);

	if (mi->instantiated) return 0;

	if (fr_command_register_hook(NULL, mi->name, mi, cmd_module_table) < 0) {
		ERROR("Failed registering radmin commands for module %s - %s",
		      mi->name, fr_strerror());
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
		cf_log_debug(mi->dl_inst->conf, "Instantiating module \"%s\"", mi->name);

		/*
		 *	Call the module's instantiation routine.
		 */
		if ((mi->module->instantiate)(mi->dl_inst->data, mi->dl_inst->conf) < 0) {
			cf_log_err(mi->dl_inst->conf, "Instantiation failed for module \"%s\"",
				   mi->name);

			return -1;
		}
	}

	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we create a mutex.
	 */
	if ((mi->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) {
		mi->mutex = talloc_zero(mi, pthread_mutex_t);

		/*
		 *	Initialize the mutex.
		 */
		pthread_mutex_init(mi->mutex, NULL);
	}

#ifndef NDEBUG
	if (mi->dl_inst->data) module_instance_read_only(mi->dl_inst->data, mi->name);
#endif

	mi->instantiated = true;

	return 0;
}

/** Force instantiation of a module
 *
 * Occasionally modules may share resources such as connection pools.
 * The only way for this to work reliably, and without introducing ordering
 * requirements for the user, for the module referenced to be instantiated
 * before (or during) the referencer being instantiated.
 *
 * In all other cases this function should not be used, and implicit
 * instantiation should be relied upon to instantiate modules.
 *
 * @param[in] root	Configuration root.
 * @param[in] name	of module to instantiate.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int module_instantiate(CONF_SECTION *root, char const *name)
{
	module_instance_t	*mi;
	CONF_SECTION		*modules;

	modules = cf_section_find(root, "modules", NULL);
	if (!modules) return 0;

	mi = cf_data_value(cf_data_find(modules, module_instance_t, name));
	if (!mi) return -1;

	return _module_instantiate(mi, NULL);
}


static int cmd_show_module_config(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;

	rad_assert(mi->dl_inst->conf != NULL);

	(void) cf_section_write(fp, mi->dl_inst->conf, 0);

	return 0;
}

typedef struct module_tab_expand_t {
	char const *text;
	int count;
	int max_expansions;
	char const **expansions;
} module_tab_expand_t;


static int _module_tab_expand(void *instance, void *ctx)
{
	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);
	module_tab_expand_t *mt = ctx;

	if (mt->count >= mt->max_expansions) return 1;

	if (fr_command_strncmp(mt->text, mi->name)) {
		mt->expansions[mt->count] = strdup(mi->name);
		mt->count++;
	}

	return 0;
}

static int module_name_tab_expand(UNUSED TALLOC_CTX *talloc_ctx, void *ctx, fr_cmd_info_t *info, int max_expansions, char const **expansions)
{
	module_tab_expand_t mt;
	CONF_SECTION *modules = (CONF_SECTION *) ctx;

	if (info->argc <= 0) return 0;

	mt.text = info->argv[info->argc - 1];
	mt.count = 0;
	mt.max_expansions = max_expansions;
	mt.expansions = expansions;

	(void) cf_data_walk(modules, module_instance_t, _module_tab_expand, &mt);

	return mt.count;
}


static int _module_list(void *instance, void *ctx)
{
	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);
	FILE *fp = ctx;

	fprintf(fp, "\t%s\n", mi->name);

	return 0;
}

static int cmd_show_module_list(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	CONF_SECTION *modules = (CONF_SECTION *) ctx;

	(void) cf_data_walk(modules, module_instance_t, _module_list, fp);

	return 0;
}

static int cmd_show_module_status(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;

	if (!mi->force) {
		fprintf(fp, "alive\n");
		return 0;
	}

	fprintf(fp, "%s\n", fr_int2str(modreturn_table, mi->code, "<invalid>"));

	return 0;
}

static int cmd_set_module_status(UNUSED FILE *fp, UNUSED FILE *fp_err, void *ctx, fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;
	rlm_rcode_t rcode;

	if (strcmp(info->argv[1], "alive") == 0) {
		mi->force = false;
		return 0;
	}

	rcode = fr_str2int(modreturn_table, info->argv[1], RLM_MODULE_UNKNOWN);
	rad_assert(rcode != RLM_MODULE_UNKNOWN);

	mi->code = rcode;
	mi->force = true;

	return 0;
}


static fr_cmd_table_t cmd_module_table[] = {
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
		.syntax = "(alive|ok|fail|reject|handled|invalid|userlock|notfound|noop|updated)",
		.func = cmd_set_module_status,
		.help = "Change module status to fixed value.",
		.read_only = false,
	},

	CMD_TABLE_END
};


static fr_cmd_table_t cmd_table[] = {
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

/** Completes instantiation of modules
 *
 * Allows the module to initialise connection pools, and complete any registrations that depend on
 * attributes created during the bootstrap phase.
 *
 * @param[in] root	Configuration root.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_instantiate(CONF_SECTION *root)
{
	CONF_SECTION *modules;

	modules = cf_section_find(root, "modules", NULL);
	if (!modules) return 0;

	DEBUG2("#### Instantiating modules ####");

	if (fr_command_register_hook(NULL, NULL, modules, cmd_table) < 0) {
		ERROR("Failed registering radmin commands for modules - %s",
		      fr_strerror());
		return -1;
	}

	if (cf_data_walk(modules, module_instance_t, _module_instantiate, NULL) < 0) return -1;

#ifndef NDEBUG
	{
		size_t size;

		size = talloc_total_size(instance_ctx);

		if (talloc_set_memlimit(instance_ctx, size)) {
			ERROR("Failed setting memory limit for all modules");
		} else {
			DEBUG3("Memory limit for all modules is set to %zd bytes", size);
		}
	}
#endif

	return 0;
}

/** Free module's instance data, and any xlats or paircmps
 *
 * @param[in] mi to free.
 * @return 0
 */
static int _module_instance_free(module_instance_t *mi)
{
	if (mi->mutex) {
		/*
		 *	FIXME
		 *	The mutex MIGHT be locked...
		 *	we'll check for that later, I guess.
		 */
		pthread_mutex_destroy(mi->mutex);
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
		xlat_unregister_module(mi->dl_inst->data);
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

/** Bootstrap a module
 *
 * Load the module shared library, allocate instance data for it,
 * parse the module configuration, and call the modules "bootstrap" method.
 *
 * @note Adds module instance data to the specified CONF_SECTION.  Module will be
 *	freed if CONF_SECTION is freed.
 *
 * @param modules section from the main config.
 * @param cs A child of the modules section, specifying this specific instance of a module.
 * @return
 *	- A new module instance handle, containing the module's public interface,
 *	  and private instance data.
 *	- NULL on error.
 */
static module_instance_t *module_bootstrap(CONF_SECTION *modules, CONF_SECTION *cs)
{
	char const		*name1, *inst_name;
	module_instance_t	*mi;

	/*
	 *	Figure out which module we want to load.
	 */
	name1 = cf_section_name1(cs);
	inst_name = cf_section_name2(cs);
	if (!inst_name) inst_name = name1;

	if (unlang_keyword(inst_name)) {
		ERROR("Module names cannot use a reserved word \"%s\"", inst_name);
		return NULL;
	}

	/*
	 *	See if the module already exists.
	 */
	mi = module_find(modules, inst_name);
	if (mi) {
		ERROR("Duplicate module \"%s\", in file %s:%d and file %s:%d",
		      inst_name,
		      cf_filename(cs),
		      cf_lineno(cs),
		      cf_filename(mi->dl_inst->conf),
		      cf_lineno(mi->dl_inst->conf));
		return NULL;
	}

	MEM(mi = talloc_zero(instance_ctx, module_instance_t));
	talloc_set_destructor(mi, _module_instance_free);

	if (dl_instance(mi, &mi->dl_inst, cs, NULL, name1, DL_TYPE_MODULE) < 0) {
		talloc_free(mi);
		return NULL;
	}

	mi->module = (rad_module_t const *)mi->dl_inst->module->common;
	if (!mi->module) {
		cf_log_err(cs, "Missing module public structure for \"%s\"", inst_name);
		talloc_free(mi);
		return NULL;
	}

	/*
	 *	Bootstrap the module.
	 */
	if (mi->module->bootstrap &&
	    ((mi->module->bootstrap)(mi->dl_inst->data, cs) < 0)) {
		cf_log_err(cs, "Bootstrap failed for module \"%s\"", inst_name);
		talloc_free(mi);
		return NULL;
	}

	mi->name = talloc_typed_strdup(mi, inst_name);

	/*
	 *	Remember the module for later.
	 */
	cf_data_add(modules, mi, mi->name, false);

	return mi;
}

/** Bootstrap a virtual module from an instantiate section
 *
 * @param[in] modules	section.
 * @param[in] vm_cs	that defines the virtual module.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int virtual_module_bootstrap(CONF_SECTION *modules, CONF_SECTION *vm_cs)
{
	char const		*name;
	bool			all_same = true;
	rad_module_t const 	*last = NULL;
	CONF_ITEM 		*sub_ci = NULL;
	CONF_PAIR		*cp;
	module_instance_t	*instance;

	name = cf_section_name1(vm_cs);

	/*
	 *	Groups, etc. must have a name.
	 */
	if ((strcmp(name, "group") == 0) ||
	    (strcmp(name, "redundant") == 0) ||
	    (strcmp(name, "redundant-load-balance") == 0) ||
	    (strcmp(name, "load-balance") == 0)) {
		name = cf_section_name2(vm_cs);
		if (!name) {
			cf_log_err(vm_cs, "Subsection must have a name");
			return -1;
		}

		if (unlang_keyword(name)) {
		is_reserved:
			cf_log_err(vm_cs, "Virtual modules cannot overload unlang keywords");
			return -1;
		}
	} else {
		goto is_reserved;
	}

	/*
	 *	Ensure that the modules we reference here exist.
	 */
	while ((sub_ci = cf_item_next(vm_cs, sub_ci))) {
		if (cf_item_is_pair(sub_ci)) {
			cp = cf_item_to_pair(sub_ci);
			if (cf_pair_value(cp)) {
				cf_log_err(sub_ci, "Cannot set return codes in a %s block", cf_section_name1(vm_cs));
				return -1;
			}

			/*
			 *	Allow "foo.authorize" in subsections.
			 */
			instance = module_find_with_method(NULL, modules, cf_pair_attr(cp));
			if (!instance) {
				cf_log_err(sub_ci, "Module instance \"%s\" referenced in %s block, does not exist",
					   cf_pair_attr(cp), cf_section_name1(vm_cs));
				return -1;
			}

			if (all_same) {
				if (!last) {
					last = instance->module;
				} else if (last != instance->module) {
					last = NULL;
					all_same = false;
				}
			}
		} else {
			all_same = false;
		}

		/*
		 *	Don't check subsections for now.
		 */
	} /* loop over modules in a "redundant foo" section */

	/*
	 *	Register a redundant xlat
	 */
	if (all_same && (xlat_register_redundant(vm_cs) < 0)) return -1;

	return 0;
}


/** Bootstrap modules and virtual modules
 *
 * Parse the module config sections, and load and call each module's init() function.
 *
 * @param[in] root of the server configuration.
 * @return
 *	- 0 if all modules were bootstrapped successfully.
 *	- -1 if a module/virtual module failed to boostrap.
 */
int modules_bootstrap(CONF_SECTION *root)
{
	CONF_ITEM *ci, *next;
	CONF_SECTION *cs, *modules;

	instance_ctx = talloc_init("module instance context");

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_find(root, "modules", NULL);
	if (!modules) {
		WARN("Cannot find a \"modules\" section in the configuration file!");
		return 0;
	}

	DEBUG2("#### Bootstrapping modules ####");

	cf_log_debug(modules, " modules {");

	/*
	 *	Loop over module definitions, looking for duplicates.
	 *
	 *	This is O(N^2) in the number of modules, but most
	 *	systems should have less than 100 modules.
	 */
	for (ci = cf_item_next(modules, NULL);
	     ci != NULL;
	     ci = next) {
		char const *name1;
		CONF_SECTION *subcs;
		module_instance_t *instance;

		next = cf_item_next(modules, ci);

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);

		instance = module_bootstrap(modules, subcs);
		if (!instance) return -1;

		if (!next || !cf_item_is_section(next)) continue;

		name1 = cf_section_name1(subcs);

		if (unlang_keyword(name1)) {
			cf_log_err(subcs, "Modules cannot overload unlang keywords");
			return -1;
		}
	}

	/*
	 *	Look for the 'instantiate' section, which tells us
	 *	the instantiation order of the modules, and also allows
	 *	us to load modules with no authorize/authenticate/etc.
	 *	sections.
	 */
	cs = cf_section_find(root, "instantiate", NULL);
	if (cs) {
		cf_log_debug(cs, "  instantiate {");
		ci = NULL;

		/*
		 *  Loop over the items in the 'instantiate' section.
		 */
		while ((ci = cf_item_next(cs, ci))) {
			CONF_SECTION *vm_cs;

			/*
			 *	Skip sections and "other" stuff.
			 *	Sections will be handled later, if
			 *	they're referenced at all...
			 */
			if (cf_item_is_pair(ci)) {
				cf_log_warn(ci, "Only virtual modules can be instantiated "
					    "with the instantiate section");
				continue;
			}

			/*
			 *	Skip section
			 */
			if (!cf_item_is_section(ci)) continue;

			vm_cs = cf_item_to_section(ci);
			cf_log_debug(ci, "Instantiating virtual module \"%s %s\"",
				     cf_section_name1(vm_cs), cf_section_name2(vm_cs));

			/*
			 *	Can only be "redundant" or
			 *	"load-balance" or
			 *	"redundant-load-balance"
			 */
			if (virtual_module_bootstrap(modules, cf_item_to_section(ci)) < 0) return -1;
		}

		cf_log_debug(cs, "  }");
	}

	cf_log_debug(modules, " } # modules");

	return 0;
}
