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

static TALLOC_CTX *instance_ctx = NULL;
static size_t instance_num = 1;

/*
 *	For simplicity, this is just array[instance_num].  Once we
 *	finish with modules_rlm_bootstrap(), the "instance_num" above MUST
 *	NOT change.
 */
static _Thread_local module_thread_instance_t **module_thread_inst_array;

/** Lookup module instances by name and lineage
 */
static fr_rb_tree_t *module_instance_name_tree;

/** Lookup module by instance data
 */
static fr_rb_tree_t *module_instance_data_tree;

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


/** Retrieve module/thread specific instance for a module
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

		if (ti->mi) DEBUG4("Worker cleaning up %s thread instance data (%p/%p)",
				   ti->mi->module->name, ti, ti->data);

		/*
		 *	Check for ti->module is a hack
		 *	and should be removed along with
		 *	starting the instance number at 0
		 */
		if (ti->mi && ti->mi->module->thread_detach) {
			ti->mi->module->thread_detach(&(module_thread_inst_ctx_t const ){
							.inst = ti->mi->dl_inst,
							.thread = ti->data,
							.el = ti->el
						      });
		}
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
	void			*instance;
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
		ti->mi = mi;

		if (mi->module->thread_inst_size) {
			MEM(ti->data = talloc_zero_array(ti, uint8_t, mi->module->thread_inst_size));

			/*
			 *	Fixup the type name, incase something calls
			 *	talloc_get_type_abort() on it...
			 */
			if (!mi->module->thread_inst_type) {
				talloc_set_name(ti->data, "rlm_%s_thread_t", mi->module->name);
			} else {
				talloc_set_name_const(ti->data, mi->module->thread_inst_type);
			}
		}

		DEBUG4("Worker alloced %s thread instance data (%p/%p)", ti->mi->module->name, ti, ti->data);
		if (mi->module->thread_instantiate &&
		    mi->module->thread_instantiate(MODULE_THREAD_INST_CTX(mi->dl_inst, ti->data, el)) < 0) {
			PERROR("Thread instantiation failed for module \"%s\"", mi->name);
			TALLOC_FREE(module_thread_inst_array);
			return -1;
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
int module_instantiate(void *instance)
{
	module_instance_t *mi = talloc_get_type_abort(instance, module_instance_t);

	if (mi->instantiated) return 0;

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
		cf_log_debug(mi->dl_inst->conf, "Instantiating module \"%s\"", mi->name);

		/*
		 *	Call the module's instantiation routine.
		 */
		if (mi->module->instantiate(MODULE_INST_CTX(mi->dl_inst)) < 0) {
			cf_log_err(mi->dl_inst->conf, "Instantiation failed for module \"%s\"", mi->name);

			return -1;
		}
	}

	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we create a mutex.
	 */
	if ((mi->module->type & MODULE_TYPE_THREAD_UNSAFE) != 0) {
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
int modules_instantiate(UNUSED CONF_SECTION *root)
{
	void			*instance;
	fr_rb_iter_inorder_t	iter;

	DEBUG2("#### Instantiating modules ####");

	for (instance = fr_rb_iter_init_inorder(&iter, module_instance_name_tree);
	     instance;
	     instance = fr_rb_iter_next_inorder(&iter)) {
		if (module_instantiate(instance) < 0) return -1;
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

/** Bootstrap a module
 *
 * Load the module shared library, allocate instance data for it,
 * parse the module configuration, and call the modules "bootstrap" method.
 *
 * @param[in] type	What type of module we're loading.  Determines the prefix
 *			added to the library name.  Should be one of:
 *			- DL_MODULE_TYPE_MODULE - Standard backend module.
 *			- DL_MODULE_TYPE_SUBMODULE - Usually a driver for a backend module.
 *			- DL_MODULE_TYPE_PROCESS - Protocol state machine bound to a virtual server.
 * @param[in] parent	of the module being bootstrapped, if this is a submodule.
 *			If this is not a submodule parent must be NULL.
 * @param[in] cs	containing the configuration for this module or submodule.
 * @return
 *	- A new module instance handle, containing the module's public interface,
 *	  and private instance data.
 *	- NULL on error.
 */
module_instance_t *module_bootstrap(dl_module_type_t type, module_instance_t const *parent, CONF_SECTION *cs)
{
	char			*inst_name = NULL;
	module_instance_t	*mi;
	char const		*name1 = cf_section_name1(cs);

	fr_assert((type == DL_MODULE_TYPE_MODULE) ||
	          (parent && (type == DL_MODULE_TYPE_SUBMODULE)) ||
	          (type == DL_MODULE_TYPE_PROCESS));

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
			       type) < 0) {
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

		if (mi->module->bootstrap(MODULE_INST_CTX(mi->dl_inst)) < 0) {
			cf_log_err(cs, "Bootstrap failed for module \"%s\"", mi->name);
			talloc_free(mi);
			return NULL;
		}
	}

	return mi;
}

/** Free all modules loaded by the server
 */
void modules_free(void)
{
	if (module_instance_name_tree) {
		fr_rb_iter_inorder_t	iter;
		module_instance_t	*mi;

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
	modules_rlm_free();
	TALLOC_FREE(instance_ctx);
}

/** Allocate the global module tree
 *
 * This allocates all the trees necessary to hold module name and module instance data,
 * as well as the main ctx all module data gets allocated in.
 */
int modules_init(void)
{
	MEM(module_instance_name_tree = fr_rb_inline_alloc(NULL, module_instance_t, name_node,
							   module_instance_name_cmp, NULL));
	MEM(module_instance_data_tree = fr_rb_inline_alloc(NULL, module_instance_t, data_node,
							   module_instance_data_cmp, NULL));
	modules_rlm_init();
	instance_ctx = talloc_init("module instance context");

	return 0;
}
