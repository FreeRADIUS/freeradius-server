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
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/unlang/base.h>

static TALLOC_CTX *instance_ctx = NULL;
static size_t instance_num = 1;

/*
 *	For simplicity, this is just array[instance_num].  Once we
 *	finish with modules_bootstrap(), the "instance_num" above MUST
 *	NOT change.
 */
static _Thread_local module_thread_instance_t **module_thread_inst_array;

/** Lookup module instances by name and lineage
 */
static fr_rb_tree_t *module_instance_name_tree;

/** Lookup module by instance data
 */
static fr_rb_tree_t *module_instance_data_tree;

/** Module command table
 */
static fr_cmd_table_t cmd_module_table[];

static int _module_instantiate(void *instance);

static int virtual_module_instantiate(CONF_SECTION *vm_cs);

/*
 *	Ordered by component
 */
const char *section_type_value[MOD_COUNT] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"post-auth"
};


static int cmd_show_module_config(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	module_instance_t *mi = ctx;

	fr_assert(mi->dl_inst->conf != NULL);

	(void) cf_section_write(fp, mi->dl_inst->conf, 0);

	return 0;
}

static int module_name_tab_expand(UNUSED TALLOC_CTX *talloc_ctx, UNUSED void *uctx, fr_cmd_info_t *info, int max_expansions, char const **expansions)
{
	fr_rb_iter_inorder_t	iter;
	void				*instance;
	char const			*text;
	int				count;

	if (info->argc <= 0) return 0;

	text = info->argv[info->argc - 1];
	count = 0;

	for (instance = fr_rb_iter_init_inorder(&iter, module_instance_name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
		module_instance_t       *mi = talloc_get_type_abort(instance, module_instance_t);

		if (count >= max_expansions) {
			break;
		}
		if (fr_command_strncmp(text, mi->name)) {
			expansions[count] = strdup(mi->name);
			count++;
		}
	}

	return count;
}


static int cmd_show_module_list(FILE *fp, UNUSED FILE *fp_err, UNUSED void *uctx, UNUSED fr_cmd_info_t const *info)
{
	fr_rb_iter_inorder_t	iter;
	void				*instance;

	for (instance = fr_rb_iter_init_inorder(&iter, module_instance_name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
		module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);

		fprintf(fp, "\t%s\n", mi->name);
	}

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
		.syntax = "(alive|disallow|fail|reject|handled|invalid|notfound|noop|ok|updated)",
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
#ifdef __clang_analyzer__
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
			     fr_time_delta_t max_idle,
			     bool locking,
			     char const *trigger_prefix,
			     fr_pair_list_t *trigger_args)
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
	mi = module_by_name(NULL, inst_name);
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

		_module_instantiate(module_by_name(NULL, inst_name));
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
				       fr_pair_list_t *trigger_args)
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

		if (fr_pool_start(pool) < 0) {
			ERROR("%s: Starting initial connections failed", log_prefix);
			return NULL;
		}

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


/*
 *	Convert a string to an integer
 */
module_method_t module_state_str_to_method(module_state_func_table_t const *table,
					   char const *name, module_method_t def)
{
	module_state_func_table_t const *this;

	if (!name) return def;

	for (this = table; this->name != NULL; this++) {
		if (strcasecmp(this->name, name) == 0) return this->func;
	}

	return def;
}

/*
 *	Convert an integer to a string.
 */
char const *module_state_method_to_str(module_state_func_table_t const *table,
				       module_method_t method, char const *def)
{
	module_state_func_table_t const *this;

	for (this = table; this->name != NULL; this++) if (this->func == method) return this->name;

	return def;
}

/** Set the next section type if it's not already set
 *
 * @param[in] request		The current request.
 * @param[in] type_da		to use.  Usually attr_auth_type.
 * @param[in] enumv		Enumeration value of the specified type_da.
 */
bool module_section_type_set(request_t *request, fr_dict_attr_t const *type_da, fr_dict_enum_value_t const *enumv)
{
	fr_pair_t *vp;

	switch (pair_update_control(&vp, type_da)) {
	case 0:
		fr_value_box_copy(vp, &vp->data, enumv->value);
		vp->data.enumv = vp->da;	/* So we get the correct string alias */
		RDEBUG2("Setting &control.%pP", vp);
		return true;

	case 1:
		RDEBUG2("&control.%s already set.  Not setting to %s", vp->da->name, enumv->name);
		return false;

	default:
		return false;
	}
}

/** Find an existing module instance by its name and parent
 *
 * @param[in] parent		to qualify search with.
 * @param[in] asked_name 	The name of the module we're attempting to find.
 *				May include '-' which indicates that it's ok for
 *				the module not to be loaded.
 * @return
 *	- Module instance matching name.
 *	- NULL if no such module exists.
 */
module_instance_t *module_by_name(module_instance_t const *parent, char const *asked_name)
{
	char const		*inst_name;
	void			*inst;

	if (!module_instance_name_tree) return NULL;

	/*
	 *	Look for the real name.  Ignore the first character,
	 *	which tells the server "it's OK for this module to not
	 *	exist."
	 */
	inst_name = asked_name;
	if (inst_name[0] == '-') inst_name++;

	inst = fr_rb_find(module_instance_name_tree,
			       &(module_instance_t){
					.dl_inst = &(dl_module_inst_t){ .parent = parent ? parent->dl_inst : NULL },
					.name = inst_name
			       });
	if (!inst) return NULL;

	return talloc_get_type_abort(inst, module_instance_t);
}

/** Find an existing module instance and verify it implements the specified method
 *
 * Extracts the method from the module name where the format is @verbatim <module>.<method> @endverbatim
 * and ensures the module implements the specified method.
 *
 * @param[out] method		the method function we will call
 * @param[in,out] component	the default component to use.  Updated to be the found component
 * @param[out] name1		name1 of the method being called
 * @param[out] name2		name2 of the method being called
 * @param[in] name 		The name of the module we're attempting to find, possibly concatenated with the method
 * @return
 *	- The module instance on success.
 *	- NULL on not found
 *
 *  If the module exists but the method doesn't exist, then `method` is set to NULL.
 */
module_instance_t *module_by_name_and_method(module_method_t *method, rlm_components_t *component,
					     char const **name1, char const **name2,
					     char const *name)
{
	char				*p, *q, *inst_name;
	size_t				len;
	int				j;
	rlm_components_t		i;
	module_instance_t		*mi;
	module_method_names_t const	*methods;
	char const			*method_name1, *method_name2;

	if (method) *method = NULL;

	method_name1 = method_name2 = NULL;
	if (name1) {
		method_name1 = *name1;
		*name1 = NULL;
	}
	if (name2) {
		method_name2 = *name2;
		*name2 = NULL;
	}

	/*
	 *	Module names are allowed to contain '.'
	 *	so we search for the bare module name first.
	 */
	mi = module_by_name(NULL, name);
	if (mi) {
		virtual_server_method_t const *allowed_list;

		if (!method) return mi;

		/*
		 *	We're not searching for a named method, OR the
		 *	module has no named methods.  Try to return a
		 *	method based on the component.
		 */
		if (!method_name1 || !mi->module->method_names) goto return_component;

		/*
		 *	Walk through the module, finding a matching
		 *	method.
		 */
		for (j = 0; mi->module->method_names[j].name1 != NULL; j++) {
			methods = &mi->module->method_names[j];

			/*
			 *	Wildcard match name1, we're
			 *	done.
			 */
			if (methods->name1 == CF_IDENT_ANY) {
			found:
				*method = methods->method;
				if (name1) *name1 = method_name1;
				if (name2) *name2 = method_name2;
				return mi;
			}

			/*
			 *	If name1 doesn't match, skip it.
			 */
			if (strcmp(methods->name1, method_name1) != 0) continue;

			/*
			 *	The module can declare a
			 *	wildcard for name2, in which
			 *	case it's a match.
			 */
			if (methods->name2 == CF_IDENT_ANY) goto found;

			/*
			 *	No name2 is also a match to no name2.
			 */
			if (!methods->name2 && !method_name2) goto found;

			/*
			 *	Don't do strcmp on NULLs
			 */
			if (!methods->name2 || !method_name2) continue;

			if (strcmp(methods->name2, method_name2) == 0) goto found;
		}

		/*
		 *	No match for "recv Access-Request", or
		 *	whatever else the section is.  Let's see if
		 *	the section has a list of allowed methods.
		 */
		allowed_list = virtual_server_section_methods(method_name1, method_name2);
		if (!allowed_list) goto return_component;

		/*
		 *	Walk over allowed methods for this section,
		 *	(implicitly ordered by priority), and see if
		 *	the allowed method matches any of the module
		 *	methods.  This process lets us reference a
		 *	module as "foo" in the configuration.  If the
		 *	module exports a "recv bar" method, and the
		 *	virtual server has a "recv bar" processing
		 *	section, then they shoul match.
		 *
		 *	Unfortunately, this process is O(N*M).
		 *	Luckily, we only do it if all else fails, so
		 *	it's mostly OK.
		 *
		 *	Note that the "allowed" list CANNOT include
		 *	CF_IDENT_ANY.  Only the module can do that.
		 *	If the "allowed" list exported CF_IDENT_ANY,
		 *	then any module method would match, which is
		 *	bad.
		 */
		for (j = 0; allowed_list[j].name != NULL; j++) {
			int k;
			virtual_server_method_t const *allowed = &allowed_list[j];

			for (k = 0; mi->module->method_names[k].name1 != NULL; k++) {
				methods = &mi->module->method_names[k];

				fr_assert(methods->name1 != CF_IDENT_ANY); /* should have been caught above */

				if (strcmp(methods->name1, allowed->name) != 0) continue;

				/*
				 *	The module matches "recv *",
				 *	call this method.
				 */
				if (methods->name2 == CF_IDENT_ANY) {
				found_allowed:
					*method = methods->method;
					return mi;
				}

				/*
				 *	No name2 is also a match to no name2.
				 */
				if (!methods->name2 && !allowed->name2) goto found_allowed;

				/*
				 *	Don't do strcmp on NULLs
				 */
				if (!methods->name2 || !allowed->name2) continue;

				if (strcmp(methods->name2, allowed->name2) == 0) goto found_allowed;
			}
		}

	return_component:
		/*
		 *	No matching method.  Just return a method
		 *	based on the component.
		 */
		if (component && mi->module->methods[*component]) {
			*method = mi->module->methods[*component];
		}

		/*
		 *	Didn't find a matching method.  Just return
		 *	the module.
		 */
		return mi;
	}

	/*
	 *	Find out if the instance name contains
	 *	a method, if it doesn't, then the module
	 *	doesn't exist.
	 */
	p = strchr(name, '.');
	if (!p) return NULL;

	/*
	 *	The module name may have a '.' in it, AND it may have
	 *	a method <sigh> So we try to find out which is which.
	 */
	inst_name = talloc_strdup(NULL, name);
	p = inst_name + (p - name);

	/*
	 *	Loop over the '.' portions, gradually looking up a
	 *	longer string, in order to find the full module name.
	 */
	do {
		*p = '\0';

		mi = module_by_name(NULL, inst_name);
		if (mi) break;

		/*
		 *	Find the next '.'
		 */
		*p = '.';
		p = strchr(p + 1, '.');
	} while (p);

	/*
	 *	No such module, we're done.
	 */
	if (!mi) {
		talloc_free(inst_name);
		return NULL;
	}

	/*
	 *	We have a module, but the caller doesn't care about
	 *	method or names, so just return the module.
	 */
	if (!method || !method_name1 || !method_name2) {
		talloc_free(inst_name);
		return mi;
	}

	/*
	 *	We MAY have two names.
	 */
	p++;
	q = strchr(p, '.');

	/*
	 *	If there's only one component, look for it in the
	 *	"authorize", etc. list first.
	 */
	if (!q) {
		for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
			if (strcmp(section_type_value[i], p) != 0) continue;

			/*
			 *	Tell the caller which component was
			 *	referenced, and set the method to the found
			 *	function.
			 */
			if (component) {
				*component = i;
				if (method) *method = mi->module->methods[*component];
			}

			/*
			 *	The string matched.  Return it.  Also set the
			 *	names so that the caller gets told the method
			 *	name being used.
			 */
			*name1 = name + (p - inst_name);
			*name2 = NULL;
			talloc_free(inst_name);
			return mi;
		}
	}

	/*
	 *	We've found the module, but it has no named methods.
	 */
	if (!mi->module->method_names) {
		*name1 = name + (p - inst_name);
		*name2 = NULL;
		talloc_free(inst_name);
		return mi;
	}

	/*
	 *	We have "module.METHOD", but METHOD doesn't match
	 *	"authorize", "authenticate", etc.  Let's see if it
	 *	matches anything else.
	 */
	if (!q) {
		for (j = 0; mi->module->method_names[j].name1 != NULL; j++) {
			methods = &mi->module->method_names[j];

			/*
			 *	If we do not have the second $method, then ignore it!
			 */
			if (methods->name2 && (methods->name2 != CF_IDENT_ANY)) continue;

			/*
			 *	Wildcard match name1, we're
			 *	done.
			 */
			if (!methods->name1 || (methods->name1 == CF_IDENT_ANY)) goto found_name1;

			/*
			 *	If name1 doesn't match, skip it.
			 */
			if (strcmp(methods->name1, p) != 0) continue;

		found_name1:
			/*
			 *	We've matched "*", or "name1" or
			 *	"name1 *".  Return that.
			 */
			*name1 = p;
			*name2 = NULL;
			*method = methods->method;
			break;
		}

		/*
		 *	Return the found module.
		 */
		talloc_free(inst_name);
		return mi;
	}

	/*
	 *	We CANNOT have '.' in method names.
	 */
	if (strchr(q + 1, '.') != 0) {
		talloc_free(inst_name);
		return mi;
	}

	len = q - p;

	/*
	 *	Trim the '.'.
	 */
	if (*q == '.' && *(q + 1)) q++;

	/*
	 *	We have "module.METHOD1.METHOD2".
	 *
	 *	Loop over the method names, seeing if we have a match.
	 */
	for (j = 0; mi->module->method_names[j].name1 != NULL; j++) {
		methods = &mi->module->method_names[j];

		/*
		 *	If name1 doesn't match, skip it.
		 */
		if (strncmp(methods->name1, p, len) != 0) continue;

		/*
		 *	It may have been a partial match, like "rec",
		 *	instead of "recv".  In which case check if it
		 *	was a FULL match.
		 */
		if (strlen(methods->name1) != len) continue;

		/*
		 *	The module can declare a
		 *	wildcard for name2, in which
		 *	case it's a match.
		 */
		if (!methods->name2 || (methods->name2 == CF_IDENT_ANY)) goto found_name2;

		/*
		 *	Don't do strcmp on NULLs
		 */
		if (!methods->name2) continue;

		if (strcmp(methods->name2, q) != 0) continue;

	found_name2:
		/*
		 *	Update name1/name2 with the methods
		 *	that were found.
		 */
		*name1 = methods->name1;
		*name2 = name + (q - inst_name);
		*method = methods->method;
		break;
	}

	*name1 = name + (p - inst_name);
	*name2 = NULL;

	talloc_free(inst_name);
	return mi;
}

/** Find an existing module instance by its private instance data
 *
 * @param[in] data	to resolve to module_instance_t.
 * @return
 *	- Module instance matching data.
 *	- NULL if no such module exists.
 */
module_instance_t *module_by_data(void const *data)
{
	module_instance_t *mi;

	mi = fr_rb_find(module_instance_data_tree,
			     &(module_instance_t){
				.dl_inst = &(dl_module_inst_t){ .data = UNCONST(void *, data) },
			     });
	if (!mi) return NULL;

	return talloc_get_type_abort(mi, module_instance_t);
}


/** Retrieve module/thread specific instance data for a module
 *
 * @param[in] mi	to find thread specific data for.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
module_thread_instance_t *module_thread(module_instance_t *mi)
{
	module_thread_instance_t **array = module_thread_inst_array;

	if (!mi) return NULL;

	fr_assert(mi->number < talloc_array_length(array));

	return array[mi->number];
}

/** Retrieve module/thread specific instance data for a module
 *
 * @param[in] data	Private instance data of the module.
 *			Same as what would be provided by
 *			#module_by_data.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
module_thread_instance_t *module_thread_by_data(void const *data)
{
	module_thread_instance_t	**array = module_thread_inst_array;
	module_instance_t		*mi = module_by_data(data);

	if (!mi) return NULL;

	fr_assert(mi->number < talloc_array_length(array));

	return array[mi->number];
}

/** Explicitly free a module if a fatal error occurs during bootstrap
 *
 * @param[in] mi	to free.
 */
void module_free(module_instance_t *mi)
{
	talloc_free(mi);
}


/** Free all modules loaded by the server
 */
void modules_free(void)
{
	if (module_instance_name_tree) {
		fr_rb_iter_inorder_t	iter;
		module_instance_t		*mi;

		for (mi = fr_rb_iter_init_inorder(&iter, module_instance_name_tree);
		     mi;
		     mi = fr_rb_iter_next_inorder(&iter)) {
			mi->in_name_tree = false; /* about to be deleted */
			mi->in_data_tree = false;

			fr_rb_iter_delete_inorder(&iter);
			fr_rb_remove(module_instance_data_tree, mi);

			talloc_free(mi);
		}
		TALLOC_FREE(module_instance_name_tree);
	}

	TALLOC_FREE(module_instance_data_tree);
	TALLOC_FREE(instance_ctx);
}

int modules_init(void)
{
	MEM(module_instance_name_tree = fr_rb_inline_alloc(NULL, module_instance_t, name_node,
							   module_instance_name_cmp, NULL));
	MEM(module_instance_data_tree = fr_rb_inline_alloc(NULL, module_instance_t, data_node,
							   module_instance_data_cmp, NULL));
	instance_ctx = talloc_init("module instance context");

	return 0;
}

/** Destructor for module_thread_instance_t array
 */
static int _module_thread_inst_array_free(module_thread_instance_t **array)
{
	size_t i, len;

	len = talloc_array_length(array);
	for (i = 0; i < len; i++) {
		module_thread_instance_t *ti;

		if (!array[i]) continue;

		ti = talloc_get_type_abort(array[i], module_thread_instance_t);

		if (ti->module) DEBUG4("Worker cleaning up %s thread instance data (%p/%p)", ti->module->name, ti, ti->data);

		/*
		 *	Check for ti->module is a hack
		 *	and should be removed along with
		 *	starting the instance number at 0
		 */
		if (ti->module && ti->module->thread_detach) (void) ti->module->thread_detach(ti->el, ti->data);

		talloc_free(ti);
	}

	return 0;
}

/** Creates per-thread instance data for modules which need it
 *
 * Must be called by any new threads before attempting to execute unlang sections.
 *
 * @param[in] ctx	to bind instance tree lifetime to.  Must not be
 *			shared between multiple threads.
 * @param[in] el	Event list servived by this thread.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	void				*instance;
	fr_rb_iter_inorder_t	iter;

	/*
	 *	Initialise the thread specific tree if this is the first time through
	 */
	if (!module_thread_inst_array) {
		MEM(module_thread_inst_array = talloc_zero_array(ctx, module_thread_instance_t *, instance_num + 1));
		talloc_set_destructor(module_thread_inst_array, _module_thread_inst_array_free);
	}

	/*
	 *	Index 0 is populated with a catchall entry
	 *	FIXME - This is only required so we can
	 *      fake out module instance data.  As soon
	 *	as we have multiple module lists this can
	 *	be removed.
	 */
	MEM(module_thread_inst_array[0] = talloc_zero(module_thread_inst_array, module_thread_instance_t));

	for (instance = fr_rb_iter_init_inorder(&iter, module_instance_name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
		module_instance_t		*mi = talloc_get_type_abort(instance, module_instance_t);
		module_thread_instance_t	*ti;

		MEM(ti = talloc_zero(module_thread_inst_array, module_thread_instance_t));
		ti->el = el;
		ti->module = mi->module;
		ti->mod_inst = mi->dl_inst->data;	/* For efficient lookups */

		if (mi->module->thread_inst_size) {
			MEM(ti->data = talloc_zero_array(ti, uint8_t, mi->module->thread_inst_size));

			/*
			 *	Fixup the type name, incase something calls
			 *	talloc_get_type_abort() on it...
			 */
			if (!mi->module->thread_inst_type) {
				talloc_set_name(ti->data, "rlm_%s_thread_t", mi->module->name);
			} else {
				talloc_set_name(ti->data, "%s", mi->module->thread_inst_type);
			}
		}

		DEBUG4("Worker alloced %s thread instance data (%p/%p)", ti->module->name, ti, ti->data);
		if (mi->module->thread_instantiate) {
			if (mi->module->thread_instantiate(mi->dl_inst->conf, mi->dl_inst->data, el, ti->data) < 0) {
				PERROR("Thread instantiation failed for module \"%s\"", mi->name);
				TALLOC_FREE(module_thread_inst_array);
				return -1;
			}
		}

		fr_assert(mi->number < talloc_array_length(module_thread_inst_array));
		module_thread_inst_array[mi->number] = ti;
	}

	return 0;
}

/** Explicitly call thread_detach and free any module thread instances
 *
 * Call this function if the module thread instances need to be free explicitly before
 * another resource like the even loop is freed.
 */
void modules_thread_detach(void)
{
	if (!module_thread_inst_array) return;
	TALLOC_FREE(module_thread_inst_array);
}

/** Complete module setup by calling its instantiate function
 *
 * @param[in] instance	of module to complete instantiation for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _module_instantiate(void *instance)
{
	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);

	if (mi->instantiated) return 0;

	if (fr_command_register_hook(NULL, mi->name, mi, cmd_module_table) < 0) {
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

	mi->instantiated = true;

	return 0;
}

/** Completes instantiation of modules
 *
 * Allows the module to initialise connection pools, and complete any registrations that depend on
 * attributes created during the bootstrap phase.
 *
 * @param[in] root of the server configuration.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_instantiate(CONF_SECTION *root)
{
	void			*instance;
	CONF_ITEM		*ci;
	CONF_SECTION		*modules;
	fr_rb_iter_inorder_t	iter;

	DEBUG2("#### Instantiating modules ####");

	for (instance = fr_rb_iter_init_inorder(&iter, module_instance_name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
		if (_module_instantiate(instance) < 0) {
			return -1;
		}
	}

	modules = cf_section_find(root, "modules", NULL);
	if (!modules) return 0;

	/*
	 *	Instantiate the virtual modules.
	 */
	for (ci = cf_item_next(modules, NULL);
	     ci != NULL;
	     ci = cf_item_next(modules, ci)) {
		char const *name;
		CONF_SECTION *subcs;

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);

		/*
		 *	If it's not an unlang keyword, then skip it.
		 *	It must be a module we already checked.
		 */
		name = cf_section_name1(subcs);
		if (!unlang_compile_is_keyword(name)) continue;

		if (virtual_module_instantiate(subcs) < 0) return -1;
	}

	return 0;
}

/** Recursive component of module_instance_name
 *
 */
static size_t _module_instance_name(TALLOC_CTX *ctx, char **out, module_instance_t const *parent, size_t need)
{
	if (parent) {
		size_t	our_len = talloc_array_length(parent->name) - 1;
		char 	*p, *end;
		size_t	used;

		used = _module_instance_name(ctx, out,
					     parent->dl_inst->parent ?
					     module_by_data(parent->dl_inst->parent->data) : NULL,
					     (need + our_len + 1));	/* +1 for '.' */
		p = (*out) + used;
		end = (*out) + talloc_array_length(*out);

		strlcpy(p, parent->name, end - p);
		p += our_len;

		*p++ = '.';	/* Add the separator */

		return (p - (*out));
	}

	/*
	 *	Head on back up the stack
	 */
	*out = talloc_array(ctx, char, need + 1);

	return 0;
}

/** Generate a module name from the module's section name and its parents
 *
 * @param[in] ctx	Where to allocate the module name.
 * @param[out] out	Where to write a pointer to the instance name.
 * @param[in] parent	of the module.
 * @param[in] cs	module's configuration section.
 */
static size_t module_instance_name(TALLOC_CTX *ctx, char **out, module_instance_t const *parent, CONF_SECTION *cs)
{
	char const	*name1, *inst_name;
	size_t		our_len;
	char		*p, *end;
	size_t		used;

	name1 = cf_section_name1(cs);
	inst_name = cf_section_name2(cs);
	if (!inst_name) inst_name = name1;

	our_len = talloc_array_length(inst_name) - 1;

	used = _module_instance_name(ctx, out, parent, our_len);
	p = (*out) + used;
	end = (*out) + talloc_array_length(*out);

	strlcpy(p, inst_name, end - p);	/* \0 terminates */
	p += our_len;

	/*
	 *	Check we used the entire buffer
	 *	...because recursive code still makes
	 *	my head hurt.
	 */
	fr_assert((size_t)(p - (*out)) == (talloc_array_length(*out) - 1));

	return (p - (*out));

}

/** Free module's instance data, and any xlats or paircmps
 *
 * @param[in] mi to free.
 * @return 0
 */
static int _module_instance_free(module_instance_t *mi)
{
	DEBUG3("Freeing %s (%p)", mi->name, mi);

	if (mi->in_name_tree) if (!fr_cond_assert(fr_rb_delete(module_instance_name_tree, mi))) return 1;
	if (mi->in_data_tree) if (!fr_cond_assert(fr_rb_delete(module_instance_data_tree, mi))) return 1;
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
 * @param[in] parent	of the module being bootstrapped, if this is a submodule.
 *			If this is not a submodule parent must be NULL.
 * @param[in] cs	containing the configuration for this module or submodule.
 * @return
 *	- A new module instance handle, containing the module's public interface,
 *	  and private instance data.
 *	- NULL on error.
 */
module_instance_t *module_bootstrap(module_instance_t const *parent, CONF_SECTION *cs)
{
	char			*inst_name = NULL;
	module_instance_t	*mi;
	char const		*name1 = cf_section_name1(cs);
	CONF_SECTION		*actions;

	module_instance_name(NULL, &inst_name, parent, cs);

	/*
	 *	See if the module already exists.
	 */
	mi = module_by_name(parent, inst_name);
	if (mi) {
		ERROR("Duplicate module \"%s\" in file %s[%d] and file %s[%d]",
		      inst_name,
		      cf_filename(cs),
		      cf_lineno(cs),
		      cf_filename(mi->dl_inst->conf),
		      cf_lineno(mi->dl_inst->conf));
		talloc_free(inst_name);
		return NULL;
	}

	MEM(mi = talloc_zero(parent ? parent : instance_ctx, module_instance_t));
	talloc_set_destructor(mi, _module_instance_free);

	if (dl_module_instance(mi, &mi->dl_inst, cs,
			parent ? parent->dl_inst : NULL,
			name1,
			parent ? DL_MODULE_TYPE_SUBMODULE : DL_MODULE_TYPE_MODULE) < 0) {
	error:
		mi->name = inst_name;	/* Assigned purely for debug log output when mi is freed */
		talloc_free(mi);
		talloc_free(inst_name);
		return NULL;
	}
	fr_assert(mi->dl_inst);

	mi->name = talloc_typed_strdup(mi, inst_name);
	talloc_free(inst_name);	/* Avoid stealing */

	mi->module = (module_t const *)mi->dl_inst->module->common;
	if (!mi->module) {
		cf_log_err(cs, "Missing public structure for \"%s\"", inst_name);
		talloc_free(mi);
		return NULL;
	}
	mi->number = instance_num++;

	/*
	 *	Remember the module for later.
	 */
	if (!fr_cond_assert(fr_rb_insert(module_instance_name_tree, mi))) goto error;
	mi->in_name_tree = true;

	/*
	 *	Allow modules to get at their own
	 *	module_instance_t data, for
	 *	looking up thread specific data
	 *	and for bootstrapping submodules.
	 */
	if (mi->dl_inst->data) {
		if (!fr_cond_assert(fr_rb_insert(module_instance_data_tree, mi))) goto error;
		mi->in_data_tree = true;
	}

	/*
	 *	Bootstrap the module.
	 *	This must be done last so that the
	 *	module can find its module_instance_t
	 *	in the trees if it needs to bootstrap
	 *	submodules.
	 */
	if (mi->module->bootstrap) {
		cf_log_debug(mi->dl_inst->conf, "Bootstrapping module \"%s\"", mi->name);

	    	if ((mi->module->bootstrap)(mi->dl_inst->data, cs) < 0) {
			cf_log_err(cs, "Bootstrap failed for module \"%s\"", mi->name);
			talloc_free(mi);
			return NULL;
		}
	}

	/*
	 *	Compile the default "actions" subsection, which includes retries.
	 */
	actions = cf_section_find(cs, "actions", NULL);
	if (actions && unlang_compile_actions(&mi->actions, actions, (mi->module->type & RLM_TYPE_RETRY) != 0)) {
		talloc_free(mi);
		return NULL;
	}

	return mi;
}

/** Instantiate a virtual module from an instantiate section
 *
 * @param[in] cs	that defines the virtual module.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int virtual_module_instantiate(CONF_SECTION *cs)
{
	char const		*name;
	bool			all_same = true;
	module_t const 	*last = NULL;
	CONF_ITEM 		*sub_ci = NULL;
	CONF_PAIR		*cp;
	module_instance_t	*mi;

	name = cf_section_name1(cs);

	/*
	 *	Groups, etc. must have a name.
	 */
	if ((strcmp(name, "group") == 0) ||
	    (strcmp(name, "redundant") == 0) ||
	    (strcmp(name, "redundant-load-balance") == 0) ||
	    (strcmp(name, "load-balance") == 0)) {
		name = cf_section_name2(cs);
		if (!name) {
			cf_log_err(cs, "Keyword module must have a second name");
			return -1;
		}

		/*
		 *	name2 was already checked in modules_bootstrap()
		 */
		fr_assert(!unlang_compile_is_keyword(name));
	} else {
		cf_log_err(cs, "Module names cannot be unlang keywords '%s'", name);
		return -1;
	}

	/*
	 *	Ensure that the module doesn't exist.
	 */
	mi = module_by_name(NULL, name);
	if (mi) {
		ERROR("Duplicate module \"%s\" in file %s[%d] and file %s[%d]",
		      name,
		      cf_filename(cs),
		      cf_lineno(cs),
		      cf_filename(mi->dl_inst->conf),
		      cf_lineno(mi->dl_inst->conf));
		return -1;
	}

	/*
	 *	Ensure that the modules we reference here exist.
	 */
	while ((sub_ci = cf_item_next(cs, sub_ci))) {
		if (cf_item_is_pair(sub_ci)) {
			cp = cf_item_to_pair(sub_ci);
			if (cf_pair_value(cp)) {
				cf_log_err(sub_ci, "Cannot set return codes in a %s block", cf_section_name1(cs));
				return -1;
			}

			/*
			 *	Allow "foo.authorize" in subsections.
			 *
			 *	Note that we don't care what the method is, just that it exists.
			 */
			mi = module_by_name_and_method(NULL, NULL, NULL, NULL, cf_pair_attr(cp));
			if (!mi) {
				cf_log_err(sub_ci, "Module instance \"%s\" referenced in %s block, does not exist",
					   cf_pair_attr(cp), cf_section_name1(cs));
				return -1;
			}

			if (all_same) {
				if (!last) {
					last = mi->module;
				} else if (last != mi->module) {
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
	if (all_same && (xlat_register_legacy_redundant(cs) < 0)) return -1;

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
	CONF_ITEM *ci;
	CONF_SECTION *cs, *modules;

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
	     ci = cf_item_next(modules, ci)) {
		char const *name;
		CONF_SECTION *subcs;
		module_instance_t *instance;

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);

		/*
		 *	name2 can't be a keyword
		 */
		name = cf_section_name2(subcs);
		if (name && unlang_compile_is_keyword(name)) {
		invalid_name:
			cf_log_err(subcs, "Module names cannot be unlang keywords '%s'", name);
			return -1;
		}

		name = cf_section_name1(subcs);

		/*
		 *	For now, ignore name1 which is a keyword.
		 */
		if (unlang_compile_is_keyword(name)) {
			if (!cf_section_name2(subcs)) {
				cf_log_err(subcs, "Missing second name at '%s'", name);
				return -1;
			}
			continue;
		}

		/*
		 *	Skip inline templates, and disallow "template { ... }"
		 */
		if (strcmp(name, "template") == 0) {
			if (!cf_section_name2(subcs)) goto invalid_name;
			continue;
		}

		instance = module_bootstrap(NULL, subcs);
		if (!instance) return -1;
	}

	cf_log_debug(modules, " } # modules");

	if (fr_command_register_hook(NULL, NULL, modules, cmd_table) < 0) {
		PERROR("Failed registering radmin commands for modules");
		return -1;
	}

	/*
	 *	Check for duplicate policies.  They're treated as
	 *	modules, so we might as well check them here.
	 */
	cs = cf_section_find(root, "policy", NULL);
	if (cs) {
		while ((ci = cf_item_next(cs, ci))) {
			CONF_SECTION *subcs, *problemcs;
			char const *name1;

			/*
			 *	Skip anything that isn't a section.
			 */
			if (!cf_item_is_section(ci)) continue;

			subcs = cf_item_to_section(ci);
			name1 = cf_section_name1(subcs);

			if (unlang_compile_is_keyword(name1)) {
				cf_log_err(subcs, "Policy name '%s' cannot be an unlang keyword", name1);
				return -1;
			}

			if (cf_section_name2(subcs)) {
				cf_log_err(subcs, "Policies cannot have two names");
				return -1;
			}

			problemcs = cf_section_find_next(cs, subcs, name1, CF_IDENT_ANY);
			if (!problemcs) continue;

			cf_log_err(problemcs, "Duplicate policy '%s' is forbidden.",
				   cf_section_name1(subcs));
			return -1;
		}
	}

	return 0;
}
