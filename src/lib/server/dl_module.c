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
#define _DL_MODULE_PRIVATE 1
#include <freeradius-devel/server/dl_module.h>

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/syserror.h>

#include <pthread.h>

#define DL_INIT_CHECK fr_assert(dl_module_loader)

/** Wrapper struct around dl_loader_t
 *
 * Provides space to store instance data.
 */
struct dl_module_loader_s {
	pthread_mutex_t 	lock;			//!< Protects the module tree when multiple threads are loading modules simultaneously.
	fr_rb_tree_t		*module_tree;		//!< Module's dl handles.
	dl_loader_t		*dl_loader;		//!< A list of loaded libraries, and symbol to callback mappings.
};

static dl_module_loader_t	*dl_module_loader;

/** Name prefixes matching the types of loadable module
 */
fr_table_num_sorted_t const dl_module_type_prefix[] = {
	{ L(""),	DL_MODULE_TYPE_SUBMODULE	},
	{ L("process"),	DL_MODULE_TYPE_PROCESS		},
	{ L("proto"),	DL_MODULE_TYPE_PROTO		},
	{ L("rlm"),	DL_MODULE_TYPE_MODULE		}
};
size_t dl_module_type_prefix_len = NUM_ELEMENTS(dl_module_type_prefix);

static int8_t dl_module_cmp(void const *one, void const *two)
{
	dl_module_t const *a = one, *b = two;
	int ret;

	fr_assert(a->dl);
	fr_assert(b->dl);

	ret = strcmp(a->dl->name, b->dl->name);
	return CMP(ret, 0);
}

/** Find the module's shallowest parent, or the child if no parents are found
 *
 * @param[in] child	to locate the root for.
 * @return
 *	- The module's shallowest parent.
 *	- NULL on error.
 */
static dl_module_t const *dl_module_root(dl_module_t const *child)
{
	dl_module_t const *next;

	for (;;) {
		next = child->parent;
		if (!next) break;

		child = next;
	}

	return child;
}

/** Return the prefix string for the deepest module
 *
 * This is useful for submodules which don't have a prefix of their own.
 * In this case we need to use the prefix of the shallowest module, which
 * will be a proto or rlm module.
 *
 * @param[in] module	to get the prefix for.
 * @return The prefix string for the shallowest module.
 */
static inline CC_HINT(always_inline)
char const *dl_module_root_prefix_str(dl_module_t const *module)
{
	dl_module_t const *root = dl_module_root(module);

	return fr_table_str_by_value(dl_module_type_prefix, root->type, "<INVALID>");
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
	fr_strerror_clear();

	if (dl_module->exported->onload) {
		int ret;

		ret = dl_module->exported->onload();
		if (ret < 0) {
#ifndef NDEBUG
			PERROR("Initialisation failed for module \"%s\" - onload() returned %i",
			       dl_module->exported->name, ret);
#else
			PERROR("Initialisation failed for module \"%s\"", dl_module->exported->name);
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

	/*
	 *	common is NULL if we couldn't find the
	 *	symbol and are erroring out.
	 */
	if (dl_module->exported && dl_module->exported->unload) dl_module->exported->unload();
}

/** Check if the magic number in the module matches the one in the library
 *
 * This is used to detect potential ABI issues caused by running with modules which
 * were built for a different version of the server.
 *
 * @param[in] module	Common fields from module's exported interface struct.
 * @returns
 *	- 0 on success.
 *	- -1 if prefix mismatch.
 *	- -2 if version mismatch.
 *	- -3 if commit mismatch.
 */
static int dl_module_magic_verify(dl_module_common_t const *module)
{
#ifdef HAVE_DLADDR
	Dl_info dl_info;
	dladdr(module, &dl_info);
#endif

	if (MAGIC_PREFIX(module->magic) != MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		ERROR("Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		ERROR("Application and rlm_%s magic number (prefix) mismatch."
		      "  application: %x module: %x", module->name,
			      MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER),
			      MAGIC_PREFIX(module->magic));
		return -1;
	}

	if (MAGIC_VERSION(module->magic) != MAGIC_VERSION(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		ERROR("Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		ERROR("Application and rlm_%s magic number (version) mismatch."
		      "  application: %lx module: %lx", module->name,
		      (unsigned long) MAGIC_VERSION(RADIUSD_MAGIC_NUMBER),
		      (unsigned long) MAGIC_VERSION(module->magic));
		return -2;
	}

	if (MAGIC_COMMIT(module->magic) != MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		ERROR("Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		ERROR("Application and rlm_%s magic number (commit) mismatch."
		      "  application: %lx module: %lx", module->name,
		      (unsigned long) MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER),
		      (unsigned long) MAGIC_COMMIT(module->magic));
		return -3;
	}

	return 0;
}

/** Decrement the reference count of the dl, eventually freeing it
 *
 */
static int _dl_module_free(dl_module_t *dl_module)
{
	/*
	 *	Talloc destructors access the talloc chunk after
	 *	calling the destructor, which could lead to a race
	 *	if the mutex is acquired within the destructor
	 *	itself.  This unfortunately means that we have to
	 *	free modules using a dedicated free function which
	 *	locks the dl_module_loader mutex.
	 *
	 *	Ensure this module is not being freed using the
	 *	normal talloc hierarchy, or with talloc_free().
	 */
	fr_assert_msg(pthread_mutex_trylock(&dl_module->loader->lock) != 0,
		      "dl_module_loader->lock not held when freeing module, "
		      "use dl_module_free() to free modules, not talloc_free");

	/*
	 *	Decrement refcounts, freeing at zero
	 */
	if (--dl_module->refs > 0) return -1;

	/*
	 *	dl is empty if we tried to load it and failed.
	 */
	if (dl_module->dl) {
		if (DEBUG_ENABLED4) {
			DEBUG4("%s unloaded.  Handle address %p, symbol address %p", dl_module->dl->name,
			       dl_module->dl->handle, dl_module->exported);
		} else {
			DEBUG3("%s unloaded", dl_module->dl->name);
		}
	}

	if (dl_module->in_tree) {
		fr_rb_delete(dl_module_loader->module_tree, dl_module);
		dl_module->in_tree = false;
	}

	dl_free(dl_module->dl);

	return 0;
}

/** Free a dl_module (when there are no more references to it)
 *
 * Decrement the reference count for a module, freeing it and unloading the module if there are no
 * more references.
 *
 * @note This must be used to free modules, not talloc_free().
 *
 * @return
 *	- 0 on success.
 *	- -1 if the module wasn't freed.  This likely means there are more ferences held to it.
 */
int dl_module_free(dl_module_t *dl_module)
{
	int ret;
	dl_module_loader_t *dl_module_l = dl_module->loader; /* Save this, as dl_module will be free'd */

	pthread_mutex_lock(&dl_module_l->lock);
	ret = talloc_free(dl_module);
	pthread_mutex_unlock(&dl_module_l->lock);

	return ret;
}

/** Load a module library using dlopen() or return a previously loaded module from the cache
 *
 * When the dl_module_t is no longer used, talloc_free() may be used to free it.
 *
 * When all references to the original dlhandle are freed, dlclose() will be called on the
 * dlhandle to unload the module.
 *
 * @note This function is threadsafe.  Multiple callers may attempt to load the same module
 *	at the same time, and the module will only be loaded once, and will not be freed
 *	until all callers have released their references to it.  This is useful for dynamic/runtime
 *	loading of modules.
 *
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
dl_module_t *dl_module_alloc(dl_module_t const *parent, char const *name, dl_module_type_t type)
{
	dl_module_t			*dl_module = NULL;
	dl_t				*dl = NULL;
	char				*module_name = NULL;
	dl_module_common_t		*common;

	DL_INIT_CHECK;

	if (parent) {
		module_name = talloc_typed_asprintf(NULL, "%s_%s_%s",
						    dl_module_root_prefix_str(parent),
						    parent->exported->name, name);
	} else {
		module_name = talloc_typed_asprintf(NULL, "%s_%s",
						    fr_table_str_by_value(dl_module_type_prefix, type, "<INVALID>"),
						    name);
	}

	if (!module_name) {
		fr_strerror_const("Out of memory");
		return NULL;
	}

	talloc_bstr_tolower(module_name);

	pthread_mutex_lock(&dl_module_loader->lock);
	/*
	 *	If the module's already been loaded, increment the reference count.
	 */
	dl_module = fr_rb_find(dl_module_loader->module_tree,
			       &(dl_module_t){ .dl = &(dl_t){ .name = module_name }});
	if (dl_module) {
		dl_module->refs++;

		/*
		 *	Release the lock, the caller is guaranteed to have a completely
		 *	loaded module, which won't be freed out from underneath them until
		 *	the reference count drops to zero.
		 */
		pthread_mutex_unlock(&dl_module_loader->lock);
		talloc_free(module_name);

		return dl_module;
	}

	MEM(dl_module = talloc_zero(dl_module_loader, dl_module_t));
	dl_module->name = talloc_strdup(dl_module, name);
	dl_module->loader = dl_module_loader;
	dl_module->parent = parent;
	dl_module->type = type;
	dl_module->refs = 1;
	talloc_set_destructor(dl_module, _dl_module_free);	/* Do this late */

	/*
	 *	Pass in dl_module as the uctx so that
	 *	we can get at it in any callbacks.
	 */
	dl = dl_by_name(dl_module_loader->dl_loader, module_name, dl_module, false);
	if (!dl) {
		PERROR("Failed to link to module \"%s\"", module_name);
		ERROR("Make sure it (and all its dependent libraries!) are in the search path"
		      " of your system's ld");
	error:
		talloc_free(module_name);
		talloc_free(dl_module);		/* Do not free dl explicitly, it's handled by the destructor */
		pthread_mutex_unlock(&dl_module_loader->lock);
		return NULL;
	}
	dl_module->dl = dl;

	DEBUG3("%s loaded, checking if it's valid", module_name);

	common = dlsym(dl->handle, module_name);
	if (!common) {
		ERROR("Could not find \"%s\" symbol in module: %s", module_name, dlerror());
		goto error;
	}
	dl_module->exported = common;

	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (dl_module_magic_verify(common) < 0) goto error;

	DEBUG3("%s validated.  Handle address %p, symbol address %p", module_name, dl, common);

	if (dl_symbol_init(dl_module_loader->dl_loader, dl) < 0) {
		PERROR("Failed calling initializers for module \"%s\"", module_name);
		goto error;
	}

	DEBUG2("Loaded module %s", module_name);

	/*
	 *	Add the module to the dl cache
	 */
	dl_module->in_tree = fr_rb_insert(dl_module_loader->module_tree, dl_module);
	if (!dl_module->in_tree) {
		ERROR("Failed caching module \"%s\"", module_name);
		goto error;
	}

	/*
	 *	Hold the lock for the entire module loading process.
	 *
	 *	This ensures that all the global resources the module has symbol callbacks
	 *	registered for, are fully populated, before something else attempts to use
	 *	it.
	 */
	pthread_mutex_unlock(&dl_module_loader->lock);

	talloc_free(module_name);

	return dl_module;
}

static int _dl_module_loader_free(dl_module_loader_t *dl_module_l)
{
	int ret = 0;

	/*
	 *	Lock must not be held when freeing the loader list.
	 */
	fr_assert_msg(pthread_mutex_trylock(&dl_module_l->lock) == 0,
		      "dl_module_loader->lock held when attempting to free dL_module_loader_t");

	if (fr_rb_num_elements(dl_module_l->module_tree) > 0) {
#ifndef NDEBUG
		fr_rb_iter_inorder_t	iter;
		void			*data;

		WARN("Refusing to cleanup dl loader, the following modules are still in use:");
		for (data = fr_rb_iter_init_inorder(dl_module_l->module_tree, &iter);
		     data;
		     data = fr_rb_iter_next_inorder(dl_module_l->module_tree, &iter)) {
			dl_module_t *module = talloc_get_type_abort(data, dl_module_t);

			WARN("  %s", module->exported->name);
		}
#endif
		ret = -1;
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

	pthread_mutex_unlock(&dl_module_l->lock);
	pthread_mutex_destroy(&dl_module_l->lock);

	return ret;
}

char const *dl_module_search_path(void)
{
	return dl_search_path(dl_module_loader->dl_loader);
}

/** Wrapper to log errors
 */
static int dl_dict_enum_autoload(dl_t const *module, void *symbol, void *user_ctx)
{
	int ret;

	ret = fr_dl_dict_enum_autoload(module, symbol, user_ctx);
	if (ret < 0) PERROR("Failed autoloading enum value for \"%s\"", module->name);

	return ret;
}

/** Wrapper to log errors
 */
static int dl_dict_attr_autoload(dl_t const *module, void *symbol, void *user_ctx)
{
	int ret;

	ret = fr_dl_dict_attr_autoload(module, symbol, user_ctx);
	if (ret < 0) PERROR("Failed autoloading attribute for \"%s\"", module->name);

	return ret;
}

/** Wrapper to log errors
 */
static int dl_dict_autoload(dl_t const *module, void *symbol, void *user_ctx)
{
	int ret;

	ret = fr_dl_dict_autoload(module, symbol, user_ctx);
	if (ret < 0) PERROR("Failed autoloading dictionary for \"%s\"", module->name);

	return ret;
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
	pthread_mutex_init(&dl_module_loader->lock, NULL);

	dl_module_loader->dl_loader = dl_loader_init(NULL, dl_module_loader, false, true);
	if (!dl_module_loader) {
		PERROR("Failed initialising dl_loader");
	error:
		TALLOC_FREE(dl_module_loader);
		return NULL;
	}
	if (lib_dir) dl_search_path_prepend(dl_module_loader->dl_loader, lib_dir);

	dl_module_loader->module_tree = fr_rb_talloc_alloc(dl_module_loader, dl_module_t,
							   dl_module_cmp, NULL);
	if (!dl_module_loader->module_tree) {
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
				   DL_PRIORITY_DICT_ENUM, "dict_enum", dl_dict_enum_autoload, NULL);
	dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT_ATTR, "dict_attr", dl_dict_attr_autoload, NULL);
	dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT, "dict", dl_dict_autoload, NULL);
	dl_symbol_free_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_DICT, "dict", fr_dl_dict_autofree, NULL);

	/*
	 *	Register library autoload callbacks for registering
	 *	global configuration sections.
	 */
	dl_symbol_init_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_LIB, "lib", global_lib_auto_instantiate, NULL);
	dl_symbol_free_cb_register(dl_module_loader->dl_loader,
				   DL_PRIORITY_LIB, "lib", global_lib_autofree, NULL);

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
