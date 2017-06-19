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
 * @file src/main/dl.c
 * @brief Wrappers around dlopen to manage loading shared objects at runtime.
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <ctype.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/cursor.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/radiusd.h>

#ifdef HAVE_VALGRIND_H
#  include <valgrind.h>
#else
#  define RUNNING_ON_VALGRIND 0
#endif

#ifndef RTLD_NOW
#  define RTLD_NOW (0)
#endif
#ifndef RTLD_LOCAL
#  define RTLD_LOCAL (0)
#endif

#ifdef __APPLE__
#  define DL_EXTENSION ".dylib"
#elif defined (WIN32)
#  define DL_EXTENSION ".dll"
#else
#  define DL_EXTENSION ".so"
#endif

char const	*radlib_dir;

/** Symbol dependent initialisation callback
 *
 * Call this function when the module is loaded for the first time.
 */
typedef struct dl_symbol_init dl_symbol_init_t;
struct dl_symbol_init {
	char const		*symbol;	//!< to search for.  May be NULL in which case func is always called.
	dl_init_t		func;		//!< to call when symbol is found in a module's symbol table.
	void			*ctx;		//!< User data to pass to func.
	dl_symbol_init_t	*next;
};

/** Symbol dependent free callback
 *
 * Call this function before the module is unloaded.
 */
typedef struct dl_symbol_free dl_symbol_free_t;
struct dl_symbol_free {
	char const		*symbol;	//!< to search for.  May be NULL in which case func is always called.
	dl_free_t		func;		//!< to call when symbol is found in a module's symbol table.
	void			*ctx;		//!< User data to pass to func.
	dl_symbol_free_t	*next;
};

/** A dynamic loader
 *
 */
typedef struct dl_loader {
	/** Linked list of symbol init callbacks
	 *
	 * @note Is linked list to retain insertion order.  We don't expect huge numbers
	 *	of callbacks so there shouldn't be efficiency issues.
	 */
	dl_symbol_init_t	*sym_init;

	/** Linked list of symbol free callbacks
	 *
	 * @note Is linked list to retain insertion order.  We don't expect huge numbers
	 *	of callbacks so there shouldn't be efficiency issues.
	 */
	dl_symbol_free_t	*sym_free;

	/** Tree to map instance to dl_handle_t
	 *
	 * Used by modules to get their own dl_handle_t for loading submodules.
	 */
	rbtree_t		*inst_tree;

	/** Tree of shared objects loaded
	 */
	rbtree_t		*tree;
} dl_loader_t;
static dl_loader_t *dl;

/** Name prefixes matching the types of loadable module
 */
static FR_NAME_NUMBER const dl_type_prefix[] = {
	{ "rlm",	DL_TYPE_MODULE },
	{ "proto",	DL_TYPE_PROTO },
	{ "",		DL_TYPE_SUBMODULE },
	{  NULL , -1 },
};

static int dl_init(void);

static int dl_symbol_init_cmp(void const *one, void const *two)
{
	dl_symbol_init_t const *a = one;
	dl_symbol_init_t const *b = two;

	rad_assert(a && b);

	if ((void *)a->func > (void *)b->func) return +1;
	if ((void *)a->func < (void *)b->func) return -1;

	if (a->symbol && !b->symbol) return +1;
	if (!a->symbol && b->symbol) return -1;
	if (a->symbol && b->symbol) return strcmp(a->symbol, b->symbol);

	return 0;
}

static int dl_symbol_free_cmp(void const *one, void const *two)
{
	dl_symbol_free_t const *a = one;
	dl_symbol_free_t const *b = two;

	rad_assert(a && b);

	if ((void *)a->func > (void *)b->func) return +1;
	if ((void *)a->func < (void *)b->func) return -1;

	if (a->symbol && !b->symbol) return +1;
	if (!a->symbol && b->symbol) return -1;
	if (a->symbol && b->symbol) return strcmp(a->symbol, b->symbol);

	return 0;
}

static int dl_inst_cmp(void const *one, void const *two)
{
	dl_instance_t const *a = one;
	dl_instance_t const *b = two;

	if (a->data > b->data) return +1;
	if (a->data < b->data) return -1;

	return 0;
}

/** Compare the name of two dl_t
 *
 */
static int dl_handle_cmp(void const *one, void const *two)
{
	return strcmp(((dl_t const *)one)->name, ((dl_t const *)two)->name);
}

/* Call the load() function in a module's exported structure
 *
 * @param[in] dl_module	to call the load function for.
 * @param[in] symbol	UNUSED.
 * @param[in] ctx	UNUSED.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dl_load_func(dl_t const *dl_module, UNUSED void *symbol, UNUSED void *ctx)
{
	if (dl_module->common->load && (dl_module->common->load() < 0)) {
		ERROR("Initialisation failed for module \"%s\"", dl_module->common->name);
		return -1;
	}

	return 0;
}

/* Call the unload() function in a module's exported structure
 *
 * @param[in] dl_module	to call the unload function for.
 * @param[in] symbol	UNUSED.
 * @param[in] ctx	UNUSED.
 */
static void dl_unload_func(dl_t const *dl_module, UNUSED void *symbol, UNUSED void *ctx)
{
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
static int dl_magic_verify(CONF_SECTION const *cs, dl_common_t const *module)
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

/** Search for a module's shared object in various locations
 *
 * @param name of module to load.
 */
static void *dl_by_name(char const *name)
{
	int		flags = RTLD_NOW;
	void		*handle;
	char		buffer[2048];
	char		*env;
	char const	*search_path;

#ifdef RTLD_GLOBAL
	if (strcmp(name, "rlm_perl") == 0) {
		flags |= RTLD_GLOBAL;
	} else
#endif
		flags |= RTLD_LOCAL;

#ifndef NDEBUG
	/*
	 *	Bind all the symbols *NOW* so we don't hit errors later
	 */
	flags |= RTLD_NOW;
#endif

	/*
	 *	Apple removed support for DYLD_LIBRARY_PATH in rootless mode.
	 */
	env = getenv("FR_LIBRARY_PATH");
	if (env) {
		DEBUG3("Ignoring libdir as FR_LIBRARY_PATH set.  Module search path will be: %s", env);
		search_path = env;
	} else {
		search_path = radlib_dir;
	}

	/*
	 *	Prefer loading our libraries by absolute path.
	 */
	if (search_path) {
		char *error;
		char *ctx, *paths, *path;
		char *p;

		fr_strerror();

		ctx = paths = talloc_strdup(NULL, search_path);
		while ((path = strsep(&paths, ":")) != NULL) {
			/*
			 *	Trim the trailing slash
			 */
			p = strrchr(path, '/');
			if (p && ((p[1] == '\0') || (p[1] == ':'))) *p = '\0';

			path = talloc_asprintf(ctx, "%s/%s%s", path, name, DL_EXTENSION);

			DEBUG4("Loading %s with path: %s", name, path);

			handle = dlopen(path, flags);
			if (handle) {
				talloc_free(ctx);
				return handle;
			}
			error = dlerror();

			fr_strerror_printf("%s%s\n", fr_strerror(), error);
#ifndef __COVERITY__
			/*
			 *	There's no version of dlopen() which takes
			 *	a file descriptor, so no way of fixing
			 *	this TOCTOU.
			 */
			DEBUG4("Loading %s failed: %s - %s", name, error,
			       (access(path, R_OK) < 0) ? fr_syserror(errno) : "No access errors");
			talloc_free(path);
#endif
		}
		talloc_free(ctx);
	}

	DEBUG4("Loading library using linker search path(s)");
	if (DEBUG_ENABLED4) {
#ifdef __APPLE__

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

	strlcpy(buffer, name, sizeof(buffer));
	/*
	 *	FIXME: Make this configurable...
	 */
	strlcat(buffer, DL_EXTENSION, sizeof(buffer));

	handle = dlopen(buffer, flags);
	if (!handle) {
		char *error = dlerror();

		DEBUG4("Failed with error: %s", error);
		/*
		 *	Append the error
		 */
		fr_strerror_printf("%s: %s", fr_strerror(), error);
		return NULL;
	}
	return handle;
}

/** Walk over the registered init callbacks, searching for the symbols they depend on
 *
 * Allows code outside of the dl API to register initialisation functions that get
 * executed depending on whether the module exports a particular symbol.
 *
 * This cuts down the amount of boilerplate code in 'mod_load' functions.
 *
 * @param[in] dl_module	to search for symbols in.
 * @return
 *	- 0 continue walking.
 *	- -1 error.
 */
static int dl_symbol_init_walk(dl_t const *dl_module)
{
	dl_symbol_init_t	*init;
	fr_cursor_t		cursor;
	void			*sym = NULL;

	for (init = fr_cursor_init(&cursor, &dl->sym_init);
	     init;
	     init = fr_cursor_next(&cursor)) {
		if (init->symbol) {
			char *sym_name = NULL;

			MEM(sym_name = talloc_asprintf(NULL, "%s_%s", dl_module->name, init->symbol));
			sym = dlsym(dl_module->handle, sym_name);
			talloc_free(sym_name);

			if (!sym) continue;
		}

		if (init->func(dl_module, sym, init->ctx) < 0) return -1;
	}

	return 0;
}

/** Walk over the registered init callbacks, searching for the symbols they depend on
 *
 * Allows code outside of the dl API to register free functions that get
 * executed depending on whether the module exports a particular symbol.
 *
 * This cuts down the amount of boilerplate code in 'mod_unload' functions.
 *
 * @param[in] dl_module	to search for symbols in.
 */
static void dl_symbol_free_walk(dl_t const *dl_module)
{
	dl_symbol_free_t	*free;
	fr_cursor_t		cursor;
	void			*sym = NULL;

	for (free = fr_cursor_init(&cursor, &dl->sym_free);
	     free;
	     free = fr_cursor_next(&cursor)) {
		if (free->symbol) {
			char *sym_name = NULL;

			MEM(sym_name = talloc_asprintf(NULL, "%s_%s", dl_module->name, free->symbol));
			sym = dlsym(dl_module->handle, sym_name);
			talloc_free(sym_name);

			if (!sym) continue;
		}

		free->func(dl_module, sym, free->ctx);
	}
}

/** Free a module
 *
 * Close module's dlhandle, unloading it.
 *
 * @param[in] module to close.
 * @return 0.
 */
static int _dl_free(dl_t *module)
{
	module = talloc_get_type_abort(module, dl_t);

	if (DEBUG_ENABLED4) {
		DEBUG4("%s unloaded.  Handle address %p, symbol address %p",
		       module->name, module->handle, module->common);
	} else {
		DEBUG3("%s unloaded", module->name);
	}
	dl_symbol_free_walk(module);

	/*
	 *	Only dlclose() handle if we're *NOT* running under valgrind
	 *	as it unloads the symbols valgrind needs.
	 */
	if (!RUNNING_ON_VALGRIND) dlclose(module->handle);        /* ignore any errors */

	module->handle = NULL;

	rbtree_deletebydata(dl->tree, module);
	if (rbtree_num_elements(dl->tree) == 0) talloc_free(dl);

	return 0;
}

/** Register a callback to execute when a module with a particular symbol is first loaded
 *
 * @note Will replace ctx data for callbacks with the same symbol/func.
 *
 * @param[in] symbol	that determines whether func should be called. "<modname>_" is
 *			added as a prefix to the symbol.  The prefix is added because
 *			some modules are loaded with RTLD_GLOBAL into the global symbol
 *			space, so the symbols they export must be unique.
 *			May be NULL to always call the function.
 * @param[in] func	to register.  Called when module is loaded.
 * @param[in] ctx	to pass to func.
 * @return
 *	- 0 on success (or already registered).
 *	- -1 on failure.
 */
int dl_symbol_init_cb_register(char const *symbol, dl_init_t func, void *ctx)
{
	dl_symbol_init_t	*new;
	fr_cursor_t		cursor;

	dl_symbol_init_cb_unregister(symbol, func);

	MEM(new = talloc(NULL, dl_symbol_init_t));
	new->symbol = symbol;
	new->func = func;
	new->ctx = ctx;

	fr_cursor_init(&cursor, &dl->sym_init);
	fr_cursor_append(&cursor, new);

	return 0;
}

/** Unregister an callback that was to be executed when a module was first loaded
 *
 * @param[in] symbol	the callback is attached to.
 * @param[in] func	the callback.
 */
void dl_symbol_init_cb_unregister(char const *symbol, dl_init_t func)
{
	dl_symbol_init_t	*found, find;
	fr_cursor_t	cursor;

	find.symbol = symbol;
	find.func = func;

	for (found = fr_cursor_init(&cursor, &dl->sym_init);
	     found && (dl_symbol_init_cmp(&find, found) != 0);
	     found = fr_cursor_next(&cursor));

	if (found) talloc_free(fr_cursor_remove(&cursor));
}

/** Register a callback to execute when a module with a particular symbol is unloaded
 *
 * @note Will replace ctx data for callbacks with the same symbol/func.
 *
 * @param[in] symbol	that determines whether func should be called. "<modname>_" is
 *			added as a prefix to the symbol.  The prefix is added because
 *			some modules are loaded with RTLD_GLOBAL into the global symbol
 *			space, so the symbols they export must be unique.
 *			May be NULL to always call the function.
 * @param[in] func	to register.  Called then module is unloaded.
 * @param[in] ctx	to pass to func.
 * @return
 *	- 0 on success (or already registered).
 *	- -1 on failure.
 */
int dl_symbol_free_cb_register(char const *symbol, dl_free_t func, void *ctx)
{
	dl_symbol_free_t	*new;
	fr_cursor_t		cursor;

	dl_symbol_free_cb_unregister(symbol, func);

	MEM(new = talloc(NULL, dl_symbol_free_t));
	new->symbol = symbol;
	new->func = func;
	new->ctx = ctx;
	fr_cursor_init(&cursor, &dl->sym_free);
	fr_cursor_append(&cursor, new);

	return 0;
}

/** Unregister an callback that was to be executed when a module was unloaded
 *
 * @param[in] symbol	the callback is attached to.
 * @param[in] func	the callback.
 */
void dl_symbol_free_cb_unregister(char const *symbol, dl_free_t func)
{
	dl_symbol_free_t	*found, find;
	fr_cursor_t		cursor;

	find.symbol = symbol;
	find.func = func;

	for (found = fr_cursor_init(&cursor, &dl->sym_free);
	     found && (dl_symbol_free_cmp(&find, found) != 0);
	     found = fr_cursor_next(&cursor));

	if (found) talloc_free(fr_cursor_remove(&cursor));
}

/** Lookup a dl_instance_t via instance data
 *
 */
dl_instance_t const *dl_instance_find(void *data)
{
	dl_instance_t find = { .data = data };

	return rbtree_finddata(dl->inst_tree, &find);
}

/** Allocate module instance data, and parse the module's configuration
 *
 * @param[in] ctx	to allocate this instance data in.
 * @param[out] data	Module's private data, the result of parsing the config.
 * @param[in] module	to alloc instance data for.
 * @param[in] cs	module's config section.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dl_instance_data_alloc(TALLOC_CTX *ctx, void **data, dl_t const *module, CONF_SECTION *cs)
{
	*data = NULL;

	if (module->common->inst_size == 0) return 0;

	/*
	 *	If there is supposed to be instance data, allocate it now.
	 *	Also parse the configuration data, if required.
	 */
	MEM(*data = talloc_zero_array(ctx, uint8_t, module->common->inst_size));

	if (!module->common->inst_type) {
		talloc_set_name(*data, "%s_t", module->name ? module->name : "config");
	} else {
		talloc_set_name(*data, "%s", module->common->inst_type);
	}

	if (module->common->config) {
		if ((cf_section_rules_push(cs, module->common->config)) < 0 ||
		    (cf_section_parse(*data, *data, cs) < 0)) {
			cf_log_err(cs, "Invalid configuration for module \"%s\"", module->name);
			talloc_free(*data);
			return -1;
		}
	}

	return 0;
}

/** Load a module library using dlopen() or return a previously loaded module from the cache
 *
 * When the dl_t is no longer used, talloc_free() may be used to free it.
 *
 * When all references to the original dlhandle are freed, dlclose() will be called on the
 * dlhandle to unload the module.
 *
 * @param[in] conf	section describing the module's configuration.  This is only used
 *			to give error messages context, and for initialization.
 * @param[in] parent	The dl_t of the parent module, e.g. rlm_sql for rlm_sql_postgresql.
 * @param[in] name	of the module e.g. sql for rlm_sql.
 * @param[in] type	Used to determine module name prefixes.  Must be one of:
 *			- DL_TYPE_MODULE
 *			- DL_TYPE_PROTO
 *			- DL_TYPE_SUBMODULE
 * @return
 *	- Module handle holding dlhandle, and module's public interface structure.
 *	- NULL if module couldn't be loaded, or some other error occurred.
 */
dl_t const *dl_module(CONF_SECTION *conf, dl_t const *parent, char const *name, dl_type_t type)
{
	dl_t			to_find;
	dl_t			*dl_module = NULL;
	void			*handle = NULL;
	char			*module_name = NULL;
	char			*p, *q;
	dl_common_t const	*module;

	if (!dl) dl_init();

	if (parent) {
		to_find.name = module_name = talloc_asprintf(NULL, "%s_%s_%s",
							     fr_int2str(dl_type_prefix, parent->type, "<INVALID>"),
							     parent->common->name, name);
	} else {
		to_find.name = module_name = talloc_asprintf(NULL, "%s_%s",
							     fr_int2str(dl_type_prefix, type, "<INVALID>"),
							     name);
	}

	for (p = module_name, q = p + talloc_array_length(p) - 1; p < q; p++) *p = tolower(*p);

	/*
	 *	If the module's already been loaded, increment the reference count.
	 */
	dl_module = rbtree_finddata(dl->tree, &to_find);
	if (dl_module) {
		talloc_free(module_name);
		talloc_increase_ref_count(dl_module);
		return dl_module;
	}

	/*
	 *	Keep the dlhandle around so we can dlclose() it.
	 */
	handle = dl_by_name(module_name);
	if (!handle) {
		cf_log_err(conf, "Failed to link to module \"%s\": %s", module_name, fr_strerror());
		cf_log_err(conf, "Make sure it (and all its dependent libraries!) are in the search path"
			      " of your system's ld");
	error:
		talloc_free(module_name);
		if (handle) dlclose(handle);
		talloc_free(dl_module);
		return NULL;
	}

	DEBUG3("%s loaded, checking if it's valid", module_name);

	module = dlsym(handle, module_name);
	if (!module) {
		cf_log_err(conf, "Failed linking to \"%s\" structure: %s", module_name, dlerror());
		goto error;
	}

	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (dl_magic_verify(conf, module) < 0) goto error;

	DEBUG3("%s validated.  Handle address %p, symbol address %p", module_name, handle, module);

	/* make room for the module type */
	dl_module = talloc_zero(dl->tree, dl_t);
	dl_module->parent = parent;
	dl_module->common = module;
	dl_module->handle = handle;
	dl_module->type = type;
	dl_module->name = talloc_steal(dl_module, module_name);

	/*
	 *	Call initialisation functions
	 */
	if (dl_symbol_init_walk(dl_module) < 0) {
		cf_log_err(conf, "Module initialisation failed \"%s\"", module_name);
		goto error;
	}

	cf_log_info(conf, "Loaded module \"%s\"", module_name);

	/*
	 *	Add the module to the dlhandle cache
	 */
	if (!rbtree_insert(dl->tree, dl_module)) {
		cf_log_err(conf, "Failed to cache module \"%s\"", module_name);
		goto error;
	}

	talloc_set_destructor(dl_module, _dl_free);	/* Do this late */

	return dl_module;
}


/** Free a module instance, removing it from the instance tree
 *
 * Also decrements the reference count of the module potentially unloading it.
 *
 * @param[in] dl_inst to free.
 * @return 0.
 */
static int _dl_instance_free(dl_instance_t *dl_inst)
{
	if (dl_inst->module && dl_inst->module->common->detach) {
		dl_inst->module->common->detach(dl_inst->data);
	}

	/*
	 *	Remove this instance from the tracking tree.
	 */
	rbtree_deletebydata(dl->inst_tree, dl_inst);

	/*
	 *	Ensure sane free order, and that all destructors
	 *	run before the .so/.dylib is unloaded.
	 */
	talloc_free_children(dl_inst);

	/*
	 *	Decrements the reference count. The module object
	 *	won't be unloaded until all instances of that module
	 *	have been destroyed.
	 */
	talloc_decrease_ref_count(dl_inst->module);

	return 0;
}

/** Load a module and parse its #CONF_SECTION in one operation
 *
 *
 * When this instance is no longer needed, it should be freed with talloc_free().
 * When all instances of a particular module are unloaded, the dl handle will be closed,
 * unloading the module.
 *
 * @param[in] ctx	to allocate structures in.
 * @param[out] out	where to write our #dl_instance_t containing the module
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
int dl_instance(TALLOC_CTX *ctx, dl_instance_t **out,
		CONF_SECTION *conf, dl_instance_t const *parent,
		char const *name, dl_type_t type)
{
	dl_instance_t	*dl_inst;

	MEM(dl_inst = talloc_zero(ctx, dl_instance_t));
	talloc_set_destructor(dl_inst, _dl_instance_free);

	/*
	 *	Find a section with the same name as the module
	 */
	dl_inst->module = dl_module(conf, parent ? parent->module : NULL, name, type);
	if (!dl_inst->module) {
		cf_log_err(conf, "Failed finding dl_instance library for '%s_%s'", parent->module->common->name, name);
		talloc_free(dl_inst);
		return -1;
	}

	/*
	 *	ctx here is the main module's instance data
	 */
	if (dl_instance_data_alloc(dl_inst, &dl_inst->data, dl_inst->module, conf) < 0) {
		cf_log_perr(conf, "Failed allocating instance data for '%s_%s'", parent->module->common->name, name);
		return -1;
	}

	dl_inst->conf = conf;
	dl_inst->parent = parent;

	rbtree_insert(dl->inst_tree, dl_inst);	/* Duplicates not possible */

	*out = dl_inst;

	return 0;
}

/** Initialise structures needed by the dynamic linker
 *
 */
static int dl_init(void)
{
	if (dl) return 0;

	dl = talloc_zero(NULL, dl_loader_t);
	dl->tree = rbtree_create(dl, dl_handle_cmp, NULL, 0);
	if (!dl->tree) {
		ERROR("Failed initialising dl->tree");
		return -1;
	}

	dl->inst_tree = rbtree_create(dl, dl_inst_cmp, NULL, 0);
	if (!dl->inst_tree) {
		ERROR("Failed initialising dl->inst_tree");
		return -1;
	}

	if (dl_symbol_init_cb_register(NULL, dl_load_func, NULL) < 0) {
		ERROR("Failed registering load() callback");
		return -1;
	}

	if (dl_symbol_free_cb_register(NULL, dl_unload_func, NULL) < 0) {
		ERROR("Failed registering unload() callback");
		return -1;
	}

	return 0;
}
