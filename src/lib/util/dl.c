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
 * @file src/lib/util/dl.c
 * @brief Wrappers around dlopen to manage loading shared objects at runtime.
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 * @copyright 2016-2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/syserror.h>

#include <ctype.h>
#include <unistd.h>

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



/** Symbol dependent initialisation callback
 *
 * Call this function when the dl is loaded for the first time.
 */
typedef struct dl_symbol_init_s dl_symbol_init_t;
struct dl_symbol_init_s {
	unsigned int		priority;	//!< Call priority
	char const		*symbol;	//!< to search for.  May be NULL in which case func is always called.
	dl_onload_t		func;		//!< to call when symbol is found in a dl's symbol table.
	void			*ctx;		//!< User data to pass to func.
	dl_symbol_init_t	*next;
};

/** Symbol dependent free callback
 *
 * Call this function before the dl is unloaded.
 */
typedef struct dl_symbol_free_s dl_symbol_free_t;
struct dl_symbol_free_s {
	unsigned int		priority;	//!< Call priority
	char const		*symbol;	//!< to search for.  May be NULL in which case func is always called.
	dl_unload_t		func;		//!< to call when symbol is found in a dl's symbol table.
	void			*ctx;		//!< User data to pass to func.
	dl_symbol_free_t	*next;
};

/** A dynamic loader
 *
 */
struct dl_loader_s {
	char const		*lib_dir;	//!< Where the libraries live.

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

	bool			do_dlclose;	//!< dlclose modules when we're done with them.

	rbtree_t		*tree;		//!< Tree of shared objects loaded.

	void			*uctx;		//!< dl private extension data.

	bool			uctx_free;	//!< Free uctx when dl_loader_t is freed.

	bool			defer_symbol_init;	//!< Do not call dl_symbol_init in dl_loader_init.
};

static int dl_symbol_init_cmp(void const *one, void const *two)
{
	dl_symbol_init_t const *a = one, *b = two;
	int ret;

	rad_assert(a && b);

	ret = ((void *)a->func > (void *)b->func) - ((void *)a->func < (void *)b->func);
	if (ret != 0) return ret;

	ret = (a->symbol && !b->symbol) - (!a->symbol && b->symbol);
	if (ret != 0) return ret;

	if (!a->symbol && !b->symbol) return 0;

#ifdef __clang_analyzer__
	if (!fr_cond_assert(a->symbol && b->symbol)) return 0;	/* Bug in clang scan ? */
#endif

	return strcmp(a->symbol, b->symbol);
}

static int dl_symbol_free_cmp(void const *one, void const *two)
{
	dl_symbol_free_t const *a = one, *b = two;
	int ret;

	rad_assert(a && b);

	ret = ((void *)a->func > (void *)b->func) - ((void *)a->func < (void *)b->func);
	if (ret != 0) return ret;

	ret = (a->symbol && !b->symbol) - (!a->symbol && b->symbol);
	if (ret != 0) return ret;

	if (!a->symbol && !b->symbol) return 0;

#ifdef __clang_analyzer__
	if (!fr_cond_assert(a->symbol && b->symbol)) return 0;	/* Bug in clang scan ? */
#endif

	return strcmp(a->symbol, b->symbol);
}

/** Compare the name of two dl_t
 *
 */
static int dl_handle_cmp(void const *one, void const *two)
{
	return strcmp(((dl_t const *)one)->name, ((dl_t const *)two)->name);
}

/** Utility function to dlopen the library containing a particular symbol
 *
 * @note Not really part of our 'dl' API, just a convenience function.
 *
 * @param[in] sym_name	to resolve.
 * @param[in] flags	to pass to dlopen.
 * @return
 *	- NULL on error.
 *      - A new handle on success.
 */
void *dl_open_by_sym(char const *sym_name, int flags)
{
	Dl_info		info;
	void		*sym;
	void		*handle;

	/*
	 *	Resolve the test symbol in our own symbol space by
	 *	iterating through all the libraries.
	 *	This might be slow.  Don't do this at runtime!
	 */
	sym = dlsym(RTLD_DEFAULT, sym_name);
	if (!sym) {
		fr_strerror_printf("Can't resolve symbol %s", sym_name);
		return NULL;
	}

	/*
	 *	Lookup the library the symbol belongs to
	 */
	if (dladdr(sym, &info) == 0) {
		fr_strerror_printf("Failed retrieving info for \"%s\" (%p)", sym_name, sym);
		return NULL;
	}

	handle = dlopen(info.dli_fname, flags);
	if (!handle) {
		fr_strerror_printf("Failed loading \"%s\": %s", info.dli_fname, dlerror());
		return NULL;
	}

	return handle;
}

/** Walk over the registered init callbacks, searching for the symbols they depend on
 *
 * Allows code outside of the dl API to register initialisation functions that get
 * executed depending on whether the dl exports a particular symbol.
 *
 * This cuts down the amount of boilerplate code in 'mod_load' functions.
 *
 * @param[in] dl_loader	Tree of dynamically loaded libraries, and callbacks.
 * @param[in] dl	to search for symbols in.
 * @return
 *	- 0 continue walking.
 *	- -1 error.
 */
int dl_symbol_init(dl_loader_t *dl_loader, dl_t const *dl)
{
	dl_symbol_init_t	*init;
	fr_cursor_t		cursor;
	void			*sym = NULL;
	char			buffer[256];

	for (init = fr_cursor_init(&cursor, &dl_loader->sym_init);
	     init;
	     init = fr_cursor_next(&cursor)) {
		if (init->symbol) {
			char *p;

			snprintf(buffer, sizeof(buffer), "%s_%s", dl->name, init->symbol);

			/*
			 *	'-' is not a valid symbol character in
			 *	C.  But "libfreeradius-radius" is a
			 *	valid library name.  So we hash things together.
			 */
			for (p = buffer; *p != '\0'; p++) {
				if (*p == '-') *p = '_';
			}

			sym = dlsym(dl->handle, buffer);
			if (!sym) {
				continue;
			}
		}

		if (init->func(dl, sym, init->ctx) < 0) return -1;
	}

	return 0;
}

/** Walk over the registered init callbacks, searching for the symbols they depend on
 *
 * Allows code outside of the dl API to register free functions that get
 * executed depending on whether the dl exports a particular symbol.
 *
 * This cuts down the amount of boilerplate code in 'mod_unload' functions.
 *
 * @param[in] dl_loader	Tree of dynamically loaded libraries, and callbacks.
 * @param[in] dl	to search for symbols in.
 */
static int dl_symbol_free(dl_loader_t *dl_loader, dl_t const *dl)
{
	dl_symbol_free_t	*free;
	fr_cursor_t		cursor;
	void			*sym = NULL;

	for (free = fr_cursor_init(&cursor, &dl_loader->sym_free);
	     free;
	     free = fr_cursor_next(&cursor)) {
		if (free->symbol) {
			char *sym_name = NULL;

			sym_name = talloc_typed_asprintf(NULL, "%s_%s", dl->name, free->symbol);
			if (!sym_name) return -1;

			sym = dlsym(dl->handle, sym_name);
			talloc_free(sym_name);

			if (!sym) continue;
		}

		free->func(dl, sym, free->ctx);
	}

	return 0;
}

/** Register a callback to execute when a dl with a particular symbol is first loaded
 *
 * @note Will replace ctx data for callbacks with the same symbol/func.
 *
 * @param[in] dl_loader	Tree of dynamically loaded libraries, and callbacks.
 * @param[in] priority	Execution priority.  Callbacks with a higher priority get
 *			called first.
 * @param[in] symbol	that determines whether func should be called. "<modname>_" is
 *			added as a prefix to the symbol.  The prefix is added because
 *			some dls are loaded with RTLD_GLOBAL into the global symbol
 *			space, so the symbols they export must be unique.
 *			May be NULL to always call the function.
 * @param[in] func	to register.  Called when dl is loaded.
 * @param[in] ctx	to pass to func.
 * @return
 *	- 0 on success (or already registered).
 *	- -1 on failure.
 */
int dl_symbol_init_cb_register(dl_loader_t *dl_loader, unsigned int priority,
			       char const *symbol, dl_onload_t func, void *ctx)
{
	dl_symbol_init_t	*n, *p;
	fr_cursor_t		cursor;

	dl_symbol_init_cb_unregister(dl_loader, symbol, func);

	n = talloc(dl_loader, dl_symbol_init_t);
	if (!n) return -1;

	n->priority = priority;
	n->symbol = symbol;
	n->func = func;
	n->ctx = ctx;

	for (p = fr_cursor_init(&cursor, &dl_loader->sym_init);
	     p && (p->priority >= priority);
	     fr_cursor_next(&cursor));
	fr_cursor_insert(&cursor, n);

	return 0;
}

/** Unregister an callback that was to be executed when a dl was first loaded
 *
 * @param[in] dl_loader	Tree of dynamically loaded libraries, and callbacks.
 * @param[in] symbol	the callback is attached to.
 * @param[in] func	the callback.
 */
void dl_symbol_init_cb_unregister(dl_loader_t *dl_loader, char const *symbol, dl_onload_t func)
{
	dl_symbol_init_t	*found, find = { .symbol = symbol, .func = func };
	fr_cursor_t		cursor;

	for (found = fr_cursor_init(&cursor, &dl_loader->sym_init);
	     found && (dl_symbol_init_cmp(&find, found) != 0);
	     found = fr_cursor_next(&cursor));

	if (found) talloc_free(fr_cursor_remove(&cursor));
}

/** Register a callback to execute when a dl with a particular symbol is unloaded
 *
 * @note Will replace ctx data for callbacks with the same symbol/func.
 *
 * @param[in] dl_loader	Tree of dynamically loaded libraries, and callbacks.
 * @param[in] priority	Execution priority.  Callbacks with a higher priority get
 *			called first.
 * @param[in] symbol	that determines whether func should be called. "<modname>_" is
 *			added as a prefix to the symbol.  The prefix is added because
 *			some dls are loaded with RTLD_GLOBAL into the global symbol
 *			space, so the symbols they export must be unique.
 *			May be NULL to always call the function.
 * @param[in] func	to register.  Called then dl is unloaded.
 * @param[in] ctx	to pass to func.
 * @return
 *	- 0 on success (or already registered).
 *	- -1 on failure.
 */
int dl_symbol_free_cb_register(dl_loader_t *dl_loader, unsigned int priority,
			       char const *symbol, dl_unload_t func, void *ctx)
{
	dl_symbol_free_t	*n, *p;
	fr_cursor_t		cursor;

	dl_symbol_free_cb_unregister(dl_loader, symbol, func);

	n = talloc(dl_loader, dl_symbol_free_t);
	if (!n) return -1;

	n->priority = priority;
	n->symbol = symbol;
	n->func = func;
	n->ctx = ctx;

	for (p = fr_cursor_init(&cursor, &dl_loader->sym_free); p && (p->priority >= priority); fr_cursor_next(&cursor));
	fr_cursor_insert(&cursor, n);

	return 0;
}

/** Unregister an callback that was to be executed when a dl was unloaded
 *
 * @param[in] dl_loader	Tree of dynamically loaded libraries, and callbacks.
 * @param[in] symbol	the callback is attached to.
 * @param[in] func	the callback.
 */
void dl_symbol_free_cb_unregister(dl_loader_t *dl_loader, char const *symbol, dl_unload_t func)
{
	dl_symbol_free_t	*found, find = { .symbol = symbol, .func = func };
	fr_cursor_t		cursor;

	for (found = fr_cursor_init(&cursor, &dl_loader->sym_free);
	     found && (dl_symbol_free_cmp(&find, found) != 0);
	     found = fr_cursor_next(&cursor));

	if (found) talloc_free(fr_cursor_remove(&cursor));
}

/** Free a dl
 *
 * Close dl's dlhandle, unloading it.
 *
 * @param[in] dl to close.
 * @return 0.
 */
static int _dl_free(dl_t *dl)
{
	dl = talloc_get_type_abort(dl, dl_t);

	dl_symbol_free(dl->loader, dl);

	/*
	 *	Only dlclose() handle if we're *NOT* running under valgrind
	 *	as it unloads the symbols valgrind needs.
	 */
	if (dl->loader->do_dlclose) dlclose(dl->handle);        /* ignore any errors */

	dl->handle = NULL;

	if (dl->in_tree) rbtree_deletebydata(dl->loader->tree, dl);

	return 0;
}

/** Search for a dl's shared object in various locations
 *
 * @note You must call dl_symbol_init when ready to call autoloader callbacks.
 *
 * @param[in] dl_loader		Tree of dynamically loaded libraries, and callbacks.
 * @param[in] name		of library to load.  May be a relative path.
 * @param[in] uctx		Data to store within the dl_t.
 * @param[in] uctx_free		talloc_free the passed in uctx data if this
 *				dl_t is freed.
 * @return
 *	- A new dl_t on success, or a pointer to an existing
 *	  one with the reference count increased.
 *	- NULL on error.
 */
dl_t *dl_by_name(dl_loader_t *dl_loader, char const *name, void *uctx, bool uctx_free)
{
	int		flags = RTLD_NOW;
	void		*handle = NULL;
	char const	*search_path;
	dl_t		*dl;

	/*
	 *	There's already something in the tree,
	 *	just return that instead.
	 */
	dl = rbtree_finddata(dl_loader->tree, &(dl_t){ .name = name });
	if (dl) {
		talloc_increase_ref_count(dl);
		return dl;
	}

	flags |= RTLD_LOCAL;

	/*
	 *	Forces dlopened libraries to resolve symbols within
	 *	their local symbol tables instead of the global symbol
	 *	table.
	 *
	 *	May help resolve issues with symbol conflicts.
	 */
#if defined(RTLD_DEEPBIND) && !defined(__SANITIZE_ADDRESS__)
	flags |= RTLD_DEEPBIND;
	fr_strerror();	/* clear error buffer */
#endif

	/*
	 *	Bind all the symbols *NOW* so we don't hit errors later
	 */
	flags |= RTLD_NOW;

	search_path = dl_search_path(dl_loader);

	/*
	 *	Prefer loading our libraries by absolute path.
	 */
	if (search_path) {
		char *ctx, *paths, *path;
		char *p;

		fr_strerror();

		ctx = paths = talloc_typed_strdup(NULL, search_path);
		while ((path = strsep(&paths, ":")) != NULL) {
			int access_mode = R_OK | X_OK;

			/*
			 *	Trim the trailing slash
			 */
			p = strrchr(path, '/');
			if (p && ((p[1] == '\0') || (p[1] == ':'))) *p = '\0';

			path = talloc_typed_asprintf(ctx, "%s/%s%s", path, name, DL_EXTENSION);
			handle = dlopen(path, flags);
			if (handle) {
				talloc_free(path);
				break;
			}

#ifdef AT_ACCESS
			access_mode |= AT_ACCESS;
#endif

			/*
			 *	Check if the dlopen() failed
			 *	because of access permissions.
			 */
			if (access(path, access_mode) < 0) {
				/*
				 *	It doesn't exist,
				 *	continue with the next
				 *	element of "path".
				 */
				if (errno == ENOENT) continue;

				/*
				 *	Stop looking for more
				 *	libraries, and instead
				 *	complain about access
				 *	permissions.
				 */
				fr_strerror_printf("Access check failed for %s - %s", path, fr_syserror(errno));
				talloc_free(path);
				break;
			}

			talloc_free(path);
		}

		/*
		 *	No element of "path" had the library.  Return
		 *	the error from the last dlopen().
		 */
		if (!handle) {
			talloc_free(ctx);
			fr_strerror_printf("%s", dlerror());
			return NULL;
		}

		talloc_free(ctx);
	} else {
		char	buffer[2048];

		strlcpy(buffer, name, sizeof(buffer));
		/*
		 *	FIXME: Make this configurable...
		 */
		strlcat(buffer, DL_EXTENSION, sizeof(buffer));

		handle = dlopen(buffer, flags);
		if (!handle) {
			char *error = dlerror();

			/*
			 *	Append the error
			 */
			fr_strerror_printf("%s", error);
			return NULL;
		}
	}

	dl = talloc_zero(dl_loader, dl_t);
	if (!dl) {
		if(handle) dlclose(handle);
		return NULL;
	}

	dl->name = talloc_typed_strdup(dl, name);
	dl->handle = handle;
	dl->loader = dl_loader;
	dl->uctx = uctx;
	dl->uctx_free = uctx_free;
	talloc_set_destructor(dl, _dl_free);

	dl->in_tree = rbtree_insert(dl_loader->tree, dl);
	if (!dl->in_tree) {
		talloc_free(dl);
		return NULL;
	}

	if (!dl_loader->defer_symbol_init) dl_symbol_init(dl_loader, dl);

	return dl;
}

/** "free" a dl handle, possibly actually freeing it, and unloading the library
 *
 * This function should be used to explicitly free a dl.
 *
 * Because dls are reference counted, it may not actually free the memory
 * or unload the library, but it will reduce the reference count.
 *
 * @return
 *	- 0	if the dl was actually freed.
 *	- >0	the number of remaining references.
 */
int dl_free(dl_t const *dl)
{
	return talloc_decrease_ref_count(talloc_get_type_abort(dl, dl_t));
}

#ifndef NDEBUG
static int _dl_walk_print(void *data, UNUSED void *uctx)
{
	dl_t *dl = talloc_get_type_abort(data, dl_t);

	fr_strerror_printf_push("  %s (%zu)", dl->name, talloc_reference_count(dl));

	return 0;
}
#endif

static int _dl_loader_free(dl_loader_t *dl_loader)
{
	int ret = 0;

	if (dl_loader->uctx_free) {
		ret = talloc_free(dl_loader->uctx);
		if (ret != 0) goto finish;
	}

	/*
	 *	Prevent freeing if we still have dls loaded
	 *	We do reference counting, we know exactly what
	 *	should still be active.
	 */
	if (rbtree_num_elements(dl_loader->tree) > 0) {
		ret = -1;
#ifndef NDEBUG
		/*
		 *	Yes, this is the correct call order
		 */
		rbtree_walk(dl_loader->tree, RBTREE_IN_ORDER, _dl_walk_print, NULL);
		fr_strerror_printf_push("Refusing to cleanup dl loader, the following dynamically loaded "
					"libraries are still in use:");
#endif
		goto finish;
	}

finish:
	return ret;
}

/** Return current library path
 *
 */
char const *dl_search_path(dl_loader_t *dl_loader)
{
	char		*env;
	char const	*search_path;

	/*
	 *	Apple removed support for DYLD_LIBRARY_PATH in rootless mode.
	 */
	env = getenv("FR_LIBRARY_PATH");
	if (env) {
		search_path = env;
	} else {
		search_path = dl_loader->lib_dir;
	}

	return search_path;
}

/** Set the current library path
 *
 */
int dl_search_path_set(dl_loader_t *dl_loader, char const *lib_dir)
{
	if (dl_loader->lib_dir) return -1;

	dl_loader->lib_dir = lib_dir;

	return 0;
}

/** Retrieve the uctx from a dl_loader
 *
 */
void *dl_loader_uctx(dl_loader_t *dl_loader)
{
	return dl_loader->uctx;
}

/** Initialise structures needed by the dynamic linker
 *
 * @param[in] ctx		To bind lifetime of dl_loader_t too.
 * @param[in] lib_dir		Where to search for modules.
 * @param[in] uctx		API client opaque data to store in dl_loader_t.
 * @param[in] uctx_free		Call talloc_free() on uctx when the dl_loader_t
 *				is freed.
 * @param[in] defer_symbol_init	If true, it is up to the caller to call
 *				#dl_symbol_init after calling #dl_by_name.
 *				This prevents any of the registered callbacks
 *				from executing until #dl_symbol_init is
 *				called explicitly.
 */
dl_loader_t *dl_loader_init(TALLOC_CTX *ctx, char const *lib_dir, void *uctx, bool uctx_free, bool defer_symbol_init)
{
	dl_loader_t *dl_loader;

	dl_loader = talloc_zero(NULL, dl_loader_t);
	if (!dl_loader) {
		fr_strerror_printf("Failed allocating dl_loader");
		return NULL;
	}

	dl_loader->tree = rbtree_talloc_create(dl_loader, dl_handle_cmp, dl_t, NULL, 0);
	if (!dl_loader->tree) {
		fr_strerror_printf("Failed initialising dl->tree");
	error:
		TALLOC_FREE(dl_loader);
		return NULL;
	}

	talloc_link_ctx(ctx, dl_loader);

	if (lib_dir) {
		dl_loader->lib_dir = talloc_strdup(dl_loader, lib_dir);
		if (!dl_loader->lib_dir) {
			fr_strerror_printf("Failed recording lb dir");
			goto error;
		}
	}

	talloc_set_destructor(dl_loader, _dl_loader_free);

	/*
	 *	Run this now to avoid bizarre issues
	 *	with the talloc atexit handlers firing
	 *	in the child, and that causing issues.
	 */
	dl_loader->do_dlclose = (!RUNNING_ON_VALGRIND && (fr_get_lsan_state() != 1));
	dl_loader->uctx = uctx;
	dl_loader->uctx_free = uctx_free;
	dl_loader->defer_symbol_init = defer_symbol_init;

	return dl_loader;
}
