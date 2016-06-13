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
 * @file dl.c
 * @brief Wrappers around dlopen to manage loading shared objects at runtime.
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <ctype.h>
#include <freeradius-devel/dl.h>
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

/** Path to search for modules in
 *
 */
char const *radlib_dir = NULL;

static rbtree_t *dl_handle_tree = NULL;

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
static int dl_module_verify_magic(CONF_SECTION const *cs, dl_module_common_t const *module)
{
#ifdef HAVE_DLADDR
	Dl_info dl_info;
	dladdr(module, &dl_info);
#endif

	if (MAGIC_PREFIX(module->magic) != MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err_cs(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err_cs(cs, "Application and rlm_%s magic number (prefix) mismatch."
			      "  application: %x module: %x", module->name,
			      MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER),
			      MAGIC_PREFIX(module->magic));
		return -1;
	}

	if (MAGIC_VERSION(module->magic) != MAGIC_VERSION(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err_cs(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err_cs(cs, "Application and rlm_%s magic number (version) mismatch."
			      "  application: %lx module: %lx", module->name,
			      (unsigned long) MAGIC_VERSION(RADIUSD_MAGIC_NUMBER),
			      (unsigned long) MAGIC_VERSION(module->magic));
		return -2;
	}

	if (MAGIC_COMMIT(module->magic) != MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err_cs(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err_cs(cs, "Application and rlm_%s magic number (commit) mismatch."
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
			DEBUG4("Loading %s failed: %s - %s", name, error,
			       (access(path, R_OK) < 0) ? fr_syserror(errno) : "No access errors");
			talloc_free(path);
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

/** Compare the name of two dl_module_t
 *
 */
static int dl_handle_cmp(void const *one, void const *two)
{
	dl_module_t const *a = one;
	dl_module_t const *b = two;

	return strcmp(a->name, b->name);
}

/** Free a module
 *
 * Close module's dlhandle, unloading it.
 */
static int _dl_module_free(dl_module_t *dl_module)
{
	dl_module = talloc_get_type_abort(dl_module, dl_module_t);

	DEBUG3("Unloading module \"%s\" (%p/%p)", dl_module->name, dl_module->handle, dl_module->common);

	if (dl_module->common->unload) dl_module->common->unload();

	/*
	 *	Only dlclose() handle if we're *NOT* running under valgrind
	 *	as it unloads the symbols valgrind needs.
	 */
	if (!RUNNING_ON_VALGRIND) dlclose(dl_module->handle);        /* ignore any errors */

	dl_module->handle = NULL;

	rbtree_deletebydata(dl_handle_tree, dl_module);

	/*
	 *	Final cleanup...
	 */
	if (rbtree_num_elements(dl_handle_tree) == 0) rbtree_free(dl_handle_tree);

	return 0;
}

/** Load a module library using dlopen() or return a previously loaded module from the cache
 *
 * When the dl_module_t is no longer used, talloc_free() may be used to free it.
 *
 * When all references to the original dlhandle are freed, dlclose() wiill be called on the
 * dlhandle to unload the module.
 *
 * @param[in] conf	section describing the module's configuration.
 * @param[in] name	of the module.
 * @param[in] prefix	appropriate for the module type ('rlm_', 'rlm_<mod>_', 'proto_').
 * @return
 *	- Module handle holding dlhandle, and module's public interface structure.
 *	- NULL if module couldn't be loaded, or some other error occurred.
 */
dl_module_t const *dl_module(CONF_SECTION *conf, char const *name, char const *prefix)
{
	dl_module_t			to_find;
	dl_module_t			*dl_module = NULL;
	void				*handle = NULL;
	char				*module_name;
	char				*p, *q;
	dl_module_common_t const	*module;

	to_find.name = module_name = talloc_asprintf(NULL, "%s%s", prefix, name);

	for (p = module_name, q = p + talloc_array_length(p) - 1; p < q; p++) *p = tolower(*p);

	/*
	 *	Because we're lazy and initialization functions are a pain.
	 */
	if (!dl_handle_tree) {
		dl_handle_tree = rbtree_create(NULL, dl_handle_cmp, NULL, 0);
		if (!dl_handle_tree) {
			ERROR("Failed initialising dl_handle_tree");
		error:
			talloc_free(module_name);
			if (handle) dlclose(handle);
			talloc_free(dl_module);
			return NULL;
		}
	} else {
		dl_module = rbtree_finddata(dl_handle_tree, &to_find);
		if (dl_module) {
			talloc_increase_ref_count(dl_module);
			return dl_module;
		}
	}

	/*
	 *	Keep the dlhandle around so we can dlclose() it.
	 */
	handle = dl_by_name(module_name);
	if (!handle) {
		cf_log_err_cs(conf, "Failed to link to module \"%s\": %s", module_name, fr_strerror());
		goto error;
	}

	DEBUG3("Loaded \"%s\", checking if it's valid", module_name);

	module = dlsym(handle, module_name);
	if (!module) {
		cf_log_err_cs(conf, "Failed linking to \"%s\" structure: %s", module_name, dlerror());
		goto error;
	}

	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (dl_module_verify_magic(conf, module) < 0) goto error;

	DEBUG3("Validated \"%s\" (%p/%p)", module_name, handle, module);

	/* make room for the module type */
	dl_module = talloc_zero(dl_handle_tree, dl_module_t);
	dl_module->common = module;
	dl_module->handle = handle;
	dl_module->name = talloc_steal(dl_module, module_name);
	dl_module->conf = conf;

	/*
	 *	Perform global library initialisation
	 */
	if (dl_module->common->load && (dl_module->common->load() < 0)) {
		cf_log_err_cs(conf, "Initialisation failed for module \"%s\"", dl_module->common->name);
		goto error;
	}

	cf_log_module(conf, "Loaded module \"%s\"", module_name);

	/*
	 *	Add the module as "rlm_foo-version" to the configuration
	 *	section.
	 */
	if (!rbtree_insert(dl_handle_tree, dl_module)) {
		ERROR("Failed to cache module \"%s\"", module_name);
		goto error;
	}

	talloc_set_destructor(dl_module, _dl_module_free);	/* Do this late */

	return dl_module;
}
