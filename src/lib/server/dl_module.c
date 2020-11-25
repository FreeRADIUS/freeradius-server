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
 * @file src/lib/server/dl_module.c
 * @brief Wrappers around dlopen to manage loading modules at runtime.
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 * @copyright 2016-2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/syserror.h>

#include <ctype.h>
#include <unistd.h>

#define DL_INIT_CHECK fr_assert(dl_module_loader)

/** Wrapper struct around dl_loader_t
 *
 * Provides space to store instance data.
 */
struct dl_module_loader_s {
	rbtree_t	*module_tree;
	rbtree_t	*inst_data_tree;
	dl_loader_t	*dl_loader;
};

static dl_module_loader_t	*dl_module_loader;

/** Make data to instance name resolution more efficient
 *
 */
typedef struct {
	void			*data;		//!< Module's data.
	dl_module_inst_t	*inst;		//!< Instance wrapper struct.
} dl_module_inst_cache_t;

static _Thread_local dl_module_inst_cache_t	dl_inst_cache;

/** Name prefixes matching the types of loadable module
 */
static fr_table_num_sorted_t const dl_module_type_prefix[] = {
	{ L(""),		DL_MODULE_TYPE_SUBMODULE	},
	{ L("proto"),	DL_MODULE_TYPE_PROTO		},
	{ L("rlm"),	DL_MODULE_TYPE_MODULE		}
};
static size_t dl_module_type_prefix_len = NUM_ELEMENTS(dl_module_type_prefix);

static int dl_module_inst_data_cmp(void const *one, void const *two)
{
	dl_module_inst_t const *a = one, *b = two;

	fr_assert(a->data);
	fr_assert(b->data);

	return (a->data > b->data) - (a->data < b->data);
}

static int dl_module_cmp(void const *one, void const *two)
{
	dl_module_t const *a = one, *b = two;

	fr_assert(a->dl);
	fr_assert(b->dl);

	return strcmp(a->dl->name, b->dl->name);
}

/** Call the load() function in a module's exported structure
 *
 * @param[in] dl	to call the load function for.
 * @param[in] symbol	UNUSED.
 * @param[in] ctx	UNUSED.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dl_module_onload_func(dl_t const *dl, UNUSED void *symbol, UNUSED void *ctx)
{
	dl_module_t *dl_module = talloc_get_type_abort(dl->uctx, dl_module_t);

	/*
	 *	Clear pre-existing errors.
	 */
	fr_strerror();

	if (dl_module->common->onload) {
		int ret;

		ret = dl_module->common->onload();
		if (ret < 0) {
#ifndef NDEBUG
			PERROR("Initialisation failed for module \"%s\" - onload() returned %i",
			       dl_module->common->name, ret);
#else
			PERROR("Initialisation failed for module \"%s\"", dl_module->common->name);
#endif
			return -1;
		}
	}

	return 0;
}

/** Call the unload() function in a module's exported structure
 *
 * @param[in] dl	to call the unload function for.
 * @param[in] symbol	UNUSED.
 * @param[in] ctx	UNUSED.
 */
static void dl_module_unload_func(dl_t const *dl, UNUSED void *symbol, UNUSED void *ctx)
{
	dl_module_t *dl_module = talloc_get_type_abort(dl->uctx, dl_module_t);

	if (dl_module->common->unload) dl_module->common->unload();
}

/** Check if the magic number in the module matches the one in the library
 *
 * This is used to detect potential ABI issues caused by running with modules which
 * were built for a different version of the server.
 *
 * @param[in] cs	being parsed.
 * @param[in] module	Common fields from module's exported interface struct.
 * @returns
 *	- 0 on success.
 *	- -1 if prefix mismatch.
 *	- -2 if version mismatch.
 *	- -3 if commit mismatch.
 */
static int dl_module_magic_verify(CONF_SECTION const *cs, dl_module_common_t const *module)
{
#ifdef HAVE_DLADDR
	Dl_info dl_info;
	dladdr(module, &dl_info);
#endif

	if (MAGIC_PREFIX(module->magic) != MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err(cs, "Application and rlm_%s magic number (prefix) mismatch."
			      "  application: %x module: %x", module->name,
			      MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER),
			      MAGIC_PREFIX(module->magic));
		return -1;
	}

	if (MAGIC_VERSION(module->magic) != MAGIC_VERSION(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err(cs, "Application and rlm_%s magic number (version) mismatch."
			      "  application: %lx module: %lx", module->name,
			      (unsigned long) MAGIC_VERSION(RADIUSD_MAGIC_NUMBER),
			      (unsigned long) MAGIC_VERSION(module->magic));
		return -2;
	}

	if (MAGIC_COMMIT(module->magic) != MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err(cs, "Application and rlm_%s magic number (commit) mismatch."
			      "  application: %lx module: %lx", module->name,
			      (unsigned long) MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER),
			      (unsigned long) MAGIC_COMMIT(module->magic));
		return -3;
	}

	return 0;
}

/** Lookup a dl_module_inst_t via instance data
 *
 */
dl_module_inst_t const *dl_module_instance_by_data(void const *data)
{
	void *mutable;

	DL_INIT_CHECK;

	memcpy(&mutable, &data, sizeof(mutable));

	if (dl_inst_cache.data == data) return dl_inst_cache.inst;

	return rbtree_finddata(dl_module_loader->inst_data_tree, &(dl_module_inst_t){ .data = mutable });
}

/** Lookup instance name via instance data
 *
 */
char const *dl_module_instance_name_by_data(void const *data)
{
	dl_module_inst_t const *inst;

	inst = dl_module_instance_by_data(data);
	if (!inst) return NULL;

	return inst->name;
}

/** A convenience function for returning a parent's private data
 *
 * @param[in] data	Private instance data for child.
 * @return
 *	- Parent's private instance data.
 *	- NULL if no parent
 */
void *dl_module_parent_data_by_child_data(void const *data)
{
	dl_module_inst_t const *dl_inst;

	DL_INIT_CHECK;

	dl_inst = dl_module_instance_by_data(data);
	if (!dl_inst) return NULL;

	if (!dl_inst->parent) return NULL;

	return dl_inst->parent->data;
}

static int _dl_module_instance_data_free(void *data)
{
        dl_module_inst_t const *dl_inst = dl_module_instance_by_data(data);

        if (!dl_inst) {
                ERROR("Failed resolving data %p, to dl_module_inst_t, refusing to free", data);
                return -1;
        }

        if (dl_inst->module->common->detach) dl_inst->module->common->detach(dl_inst->data);

        return 0;
}

/** Allocate module instance data, and parse the module's configuration
 *
 * @param[in] dl_inst	to allocate this instance data in.
 * @param[in] module	to alloc instance data for.
 */
static void dl_module_instance_data_alloc(dl_module_inst_t *dl_inst, dl_module_t const *module)
{
        void *data;

	/*
	 *	If there is supposed to be instance data, allocate it now.
	 *
	 *      If the structure is zero length then allocation will still
	 *	succeed, and will create a talloc chunk header.
	 *
	 *      This is needed so we can resolve instance data back to
	 *	dl_module_instance_t/dl_module_t/dl_t.
	 */
	MEM(data = talloc_zero_array(dl_inst, uint8_t, module->common->inst_size));

	if (!module->common->inst_type) {
		talloc_set_name(data, "%s_t", module->dl->name ? module->dl->name : "config");
	} else {
		talloc_set_name(data, "%s", module->common->inst_type);
	}
	dl_inst->data = data;

        /*
         *      Must be done before setting the destructor to ensure the
         *      destructor can find the dl_module_inst_t associated
         *      with the data.
         */
	fr_assert(dl_module_loader != NULL);
	rbtree_insert(dl_module_loader->inst_data_tree, dl_inst);	/* Duplicates not possible */

	talloc_set_destructor(data, _dl_module_instance_data_free);
}

/** Decrement the reference count of the dl, eventually freeing it
 *
 */
static int _dl_module_free(dl_module_t *dl_module)
{
	/*
	 *	dl is empty if we tried to load it and failed.
	 */
	if (dl_module->dl) {
		if (DEBUG_ENABLED4) {
			DEBUG4("%s unloaded.  Handle address %p, symbol address %p", dl_module->dl->name,
			       dl_module->dl->handle, dl_module->common);
		} else {
			DEBUG3("%s unloaded", dl_module->dl->name);
		}
	}

	if (dl_module->in_tree) {
		rbtree_deletebydata(dl_module_loader->module_tree, dl_module);
		dl_module->in_tree = false;
	}

	dl_free(dl_module->dl);

	return 0;
}

/** Load a module library using dlopen() or return a previously loaded module from the cache
 *
 * When the dl_module_t is no longer used, talloc_free() may be used to free it.
 *
 * When all references to the original dlhandle are freed, dlclose() will be called on the
 * dlhandle to unload the module.
 *
 * @param[in] conf	section describing the module's configuration.  This is only used
 *			to give error messages context, and for initialization.
 * @param[in] parent	The dl_module_t of the parent module, e.g. rlm_sql for rlm_sql_postgresql.
 * @param[in] name	of the module e.g. sql for rlm_sql.
 * @param[in] type	Used to determine module name prefixes.  Must be one of:
 *			- DL_MODULE_TYPE_MODULE
 *			- DL_MODULE_TYPE_PROTO
 *			- DL_MODULE_TYPE_SUBMODULE
 * @return
 *	- Module handle holding dlhandle, and module's public interface structure.
 *	- NULL if module couldn't be loaded, or some other error occurred.
 */
dl_module_t const *dl_module(CONF_SECTION *conf, dl_module_t const *parent, char const *name, dl_module_type_t type)
{
	dl_module_t			*dl_module = NULL;
	dl_t				*dl = NULL;
	char				*module_name = NULL;
	char				*p, *q;
	dl_module_common_t const	*common;

	DL_INIT_CHECK;

	if (parent) {
		module_name = talloc_typed_asprintf(NULL, "%s_%s_%s",
						    fr_table_str_by_value(dl_module_type_prefix,
						    			  parent->type, "<INVALID>"),
						    parent->common->name, name);
	} else {
		module_name = talloc_typed_asprintf(NULL, "%s_%s",
						    fr_table_str_by_value(dl_module_type_prefix, type, "<INVALID>"),
						    name);
	}

	if (!module_name) return NULL;

	for (p = module_name, q = p + talloc_array_length(p) - 1; p < q; p++) *p = tolower(*p);

	/*
	 *	If the module's already been loaded, increment the reference count.
	 */
	dl_module = rbtree_finddata(dl_module_loader->module_tree,
				    &(dl_module_t){ .dl = &(dl_t){ .name = module_name }});
	if (dl_module) {
		talloc_free(module_name);
		talloc_increase_ref_count(dl_module);
		return dl_module;
	}

	dl_module = talloc_zero(dl_module_loader, dl_module_t);
	dl_module->parent = parent;
	dl_module->type = type;
	talloc_set_destructor(dl_module, _dl_module_free);	/* Do this late */

	/*
	 *	Pass in dl_module as the uctx so that
	 *	we can get at it in any callbacks.
	 */
	dl = dl_by_name(dl_module_loader->dl_loader, module_name, dl_module, false);
	if (!dl) {
		cf_log_perr(conf, "Failed to link to module \"%s\"", module_name);
		cf_log_err(conf, "Make sure it (and all its dependent libraries!) are in the search path"
			   " of your system's ld");
	error:
		talloc_free(module_name);
		talloc_free(dl_module);		/* Do not free dl explicitly, it's handled by the destructor */
		return NULL;
	}
	dl_module->dl = dl;

	DEBUG3("%s loaded, checking if it's valid", module_name);

	common = dlsym(dl->handle, module_name);
	if (!common) {
		cf_log_err(conf, "Could not find \"%s\" symbol in module: %s", module_name, dlerror());
		goto error;
	}
	dl_module->common = common;

	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (dl_module_magic_verify(conf, common) < 0) goto error;

	DEBUG3("%s validated.  Handle address %p, symbol address %p", module_name, dl, common);

	if (dl_symbol_init(dl_module_loader->dl_loader, dl) < 0) {
		cf_log_perr(conf, "Failed calling initializers for module \"%s\"", module_name);
		goto error;
	}

	cf_log_info(conf, "Loaded module \"%s\"", module_name);

	/*
	 *	Add the module to the dl cache
	 */
	dl_module->in_tree = rbtree_insert(dl_module_loader->module_tree, dl_module);
	if (!dl_module->in_tree) {
		cf_log_err(conf, "Failed caching module \"%s\"", module_name);
		goto error;
	}

	talloc_free(module_name);

	return dl_module;
}

/** Free a module instance, removing it from the instance tree
 *
 * Also decrements the reference count of the module potentially unloading it.
 *
 * @param[in] dl_inst to free.
 * @return 0.
 */
static int _dl_module_instance_free(dl_module_inst_t *dl_inst)
{
        /*
         *	Ensure sane free order, and that all destructors
         *	run before the .so/.dylib is unloaded.
         *
         *      This *MUST* be done *BEFORE* decrementing the
         *      reference count on the module.
         *
         *      It also *MUST* be done before removing this struct
         *      from the inst_data_tree, so the detach destructor
         *      can find the dl_module_inst_t associated with
         *      the opaque data.
         */
        talloc_free_children(dl_inst);

        /*
         *	Remove this instance from the tracking tree.
         */
        fr_assert(dl_module_loader != NULL);
        rbtree_deletebydata(dl_module_loader->inst_data_tree, dl_inst);

        /*
         *	Decrements the reference count. The module object
         *	won't be unloaded until all instances of that module
         *	have been destroyed.
         */
        talloc_decrease_ref_count(dl_inst->module);

	return 0;
}

/** Retrieve a public symbol from a module using dlsym
 *
 * Convenience function to lookup/return public symbols from modules loaded
 * with #dl_module_instance.
 *
 * @param[in] dl_inst   	Instance who's module we're looking for the symbol in.
 * @param[in] sym_name		to lookup.
 * @return
 *	- Pointer to the public data structure.
 * 	- NULL if no matching symbol was found.
 */
void *dl_module_instance_symbol(dl_module_inst_t const *dl_inst, char const *sym_name)
{
	if (!sym_name) return NULL;

 	return dlsym(dl_inst->module->dl->handle, sym_name);
}

/** Load a module and parse its #CONF_SECTION in one operation
 *
 * When this instance is no longer needed, it should be freed with talloc_free().
 * When all instances of a particular module are unloaded, the dl handle will be closed,
 * unloading the module.
 *
 * @param[in] ctx	to allocate structures in.
 * @param[out] out	where to write our #dl_module_inst_t containing the module
 *			handle and instance.
 * @param[in] conf	section to parse.
 * @param[in] parent	of module instance.
 * @param[in] name	of the module to load .e.g. 'udp' for 'proto_radius_udp'
 *			if the parent were 'proto_radius'.
 * @param[in] type	of module to load.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dl_module_instance(TALLOC_CTX *ctx, dl_module_inst_t **out,
		       CONF_SECTION *conf, dl_module_inst_t const *parent,
		       char const *name, dl_module_type_t type)
{
	dl_module_inst_t	*dl_inst;
	char const		*name2;

	DL_INIT_CHECK;

	MEM(dl_inst = talloc_zero(ctx, dl_module_inst_t));

	/*
	 *	Find a section with the same name as the module
	 */
	dl_inst->module = dl_module(conf, parent ? parent->module : NULL, name, type);
	if (!dl_inst->module) {
		talloc_free(dl_inst);
		return -1;
	}

	/*
	 *	ctx here is the main module's instance data
	 */
	dl_module_instance_data_alloc(dl_inst, dl_inst->module);

	talloc_set_destructor(dl_inst, _dl_module_instance_free);

	/*
	 *	Associate the module instance with the conf section
	 *	*before* executing any parse rules that might need it.
	 */
	cf_data_add(conf, dl_inst, dl_inst->module->dl->name, false);

	if (dl_inst->module->common->config && conf) {
		if ((cf_section_rules_push(conf, dl_inst->module->common->config)) < 0 ||
		    (cf_section_parse(dl_inst->data, dl_inst->data, conf) < 0)) {
			cf_log_err(conf, "Failed evaluating configuration for module \"%s\"",
				   dl_inst->module->dl->name);
			talloc_free(dl_inst);
			return -1;
		}
	}

	name2 = cf_section_name2(conf);
	if (name2) {
		dl_inst->name = talloc_typed_strdup(dl_inst, name2);
	} else {
		dl_inst->name = talloc_typed_strdup(dl_inst, cf_section_name1(conf));
	}

	dl_inst->conf = conf;
	dl_inst->parent = parent;

	*out = dl_inst;

	return 0;
}

#ifndef NDEBUG
static int _dl_inst_walk_print(void *data, UNUSED void *uctx)
{
	dl_module_inst_t *dl_inst = talloc_get_type_abort(data, dl_module_inst_t);

	WARN("  %s (%s)", dl_inst->module->dl->name, dl_inst->name);

	return 0;
}
#endif

static int _dl_module_loader_free(dl_module_loader_t *dl_module_l)
{
	int ret = 0;

	if (rbtree_num_elements(dl_module_l->inst_data_tree) > 0) {
		ret = -1;
#ifndef NDEBUG
		WARN("Refusing to cleanup dl loader, the following module instances are still in use:");
		rbtree_walk(dl_module_l->inst_data_tree, RBTREE_IN_ORDER, _dl_inst_walk_print, NULL);
#endif
		goto finish;
	}

	/*
	 *	Do this as an explicit step, as this free can fail
	 */
	ret = talloc_free(dl_module_l->dl_loader);
	if (ret != 0) {
		PWARN("dl loader not freed");
	}

finish:
	if (ret != 0) {
#ifndef NDEBUG
		WARN("This may appear as a leak in talloc memory reports");
#endif
	} else {
		dl_module_loader = NULL;
	}

	return ret;
}

char const *dl_module_search_path(void)
{
	return dl_search_path(dl_module_loader->dl_loader);
}

dl_loader_t *dl_loader_from_module_loader(dl_module_loader_t *dl_module_l)
{
	return dl_module_l->dl_loader;
}

/** Initialise structures needed by the dynamic linker
 *
 */
dl_module_loader_t *dl_module_loader_init(char const *lib_dir)
{
	if (dl_module_loader) {
		/*
		 *	Allow it to update the search path.
		 */
		if (dl_search_path_set(dl_module_loader->dl_loader, lib_dir) < 0) {
			return NULL;
		}

		return dl_module_loader;
	}

	dl_module_loader = talloc_zero(NULL, dl_module_loader_t);
	if (!dl_module_loader) {
		ERROR("Failed initialising uctx for dl_loader");
		return NULL;
	}

	dl_module_loader->dl_loader = dl_loader_init(NULL, dl_module_loader, false, true);
	if (!dl_module_loader) {
		PERROR("Failed initialising dl_loader");
	error:
		TALLOC_FREE(dl_module_loader);
		return NULL;
	}
	dl_search_path_prepend(dl_module_loader->dl_loader, lib_dir);

	dl_module_loader->inst_data_tree = rbtree_talloc_alloc(dl_module_loader,
							        dl_module_inst_data_cmp, dl_module_inst_t, NULL, 0);
	if (!dl_module_loader->inst_data_tree) {
		ERROR("Failed initialising dl->inst_data_tree");
		goto error;
	}

	dl_module_loader->module_tree = rbtree_talloc_alloc(dl_module_loader,
							     dl_module_cmp, dl_module_t, NULL, 0);
	if (!dl_module_loader->inst_data_tree) {
		ERROR("Failed initialising dl->module_tree");
		goto error;
	}

	if (dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				       DL_PRIORITY_BOOTSTRAP, NULL, dl_module_onload_func, NULL) < 0) {
		ERROR("Failed registering load() callback");
		goto error;
	}

	if (dl_symbol_free_cb_register(dl_module_loader->dl_loader,
				       DL_PRIORITY_BOOTSTRAP, NULL, dl_module_unload_func, NULL) < 0) {
		ERROR("Failed registering unload() callback");
		goto error;
	}

	/*
	 *	Register dictionary autoload callbacks
	 */
	dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT_ATTR, "dict_enum", fr_dl_dict_enum_autoload, NULL);
	dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT_ATTR, "dict_attr", fr_dl_dict_attr_autoload, NULL);
	dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT, "dict", fr_dl_dict_autoload, NULL);
	dl_symbol_free_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT, "dict", fr_dl_dict_autofree, NULL);

	talloc_set_destructor(dl_module_loader, _dl_module_loader_free);

	DEBUG4("Module linker search path(s)");
	if (DEBUG_ENABLED4) {
		char const	*env;

#ifdef __APPLE__
		char		buffer[PATH_MAX];

		env = getenv("LD_LIBRARY_PATH");
		if (env) {
			DEBUG4("LD_LIBRARY_PATH            : %s", env);
		}
		env = getenv("DYLD_LIBRARY_PATH");
		if (env) {
			DEBUG4("DYLB_LIBRARY_PATH          : %s", env);
		}
		env = getenv("DYLD_FALLBACK_LIBRARY_PATH");
		if (env) {
			DEBUG4("DYLD_FALLBACK_LIBRARY_PATH : %s", env);
		}
		env = getcwd(buffer, sizeof(buffer));
		if (env) {
			DEBUG4("Current directory          : %s", env);
		}
#else
		env = getenv("LD_LIBRARY_PATH");
		if (env) {
			DEBUG4("LD_LIBRARY_PATH  : %s", env);
		}
		DEBUG4("Defaults         : /lib:/usr/lib");
#endif
	}

	return dl_module_loader;
}
