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
 * @file build/dlopen.c
 * @brief GNU make plugin to run dlopen()
 *
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
RCSIDH(time_h, "$Id$")

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <dlfcn.h>
#include <gnumake.h>

#ifdef __linux__
#include <link.h>
#endif

#ifdef __APPLE__
/*
 *	<link.h> is buried somewhere.  The fields below are known to
 *	be correct.
 */
struct link_map {
	void *l_addr;
	char *l_name;
	/* ... ignore the remaining fields */
};

#  define DL_EXTENSION ".dylib"
#else
#  define DL_EXTENSION ".so"
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 1
#endif
#include <limits.h>

/*
 *	The only exported symbol
 */
int	dlopen_gmk_setup(void);

/*
 * GNU make insists on this in a loadable object.
 */
extern int plugin_is_GPL_compatible;
int plugin_is_GPL_compatible;

typedef struct fr_lib_s {
	struct fr_lib_s	*next;
	char		*filename;
	char		*name;
	void		*handle;
} fr_lib_t;

static fr_lib_t	*libs = NULL;

static char *my_dlerror = NULL;

/** Convert GNU make argument to a filename and library name.
 *
 *  We want to be able to load the library both by relative path, and
 *  by absolute path.  Then later invocations of dlclose() or dlsym()
 *  can just use the relative path.
 */
static char *argv2lib(char const *argv, char **filename, char **libname)
{
	size_t len;
	char *p, *name;

	len = strlen(argv);

	name = malloc(len + sizeof(DL_EXTENSION)); /* sizeof includes the trailing NULL */
	if (!name) return NULL;

	memcpy(name, argv, len);
	memcpy(name + len, DL_EXTENSION, sizeof(DL_EXTENSION));

	/*
	 *	We want to be flexible, and allow loading by absolute
	 *	path, or just by the library name.
	 *
	 *	Either way, we want "libfoo" to refer to the same
	 *	library, when it's either referenced as "libfoo", or
	 *	as "/path/to/libfoo".
	 */
	p = strrchr(name, '/');
	if (p) {
		*libname = p + 1;
		*filename = name;
	} else {
		*libname = name;
		*filename = NULL;
	}

	return name;
}

static fr_lib_t *find_lib(char const *libname, fr_lib_t ***prev)
{
	fr_lib_t *lib, **last;

	last = &libs;
	for (lib = libs; lib != NULL; lib = lib->next) {
		if (strcmp(lib->name, libname) == 0) {
			if (prev) *prev = last;
			return lib;
		}

		last = &lib->next;
	}

	return NULL;
}

static void *check_symbol(void *handle, char const *symbol)
{
	if (dlsym(handle, symbol)) return handle;

	dlclose(handle);
	return NULL;
}

static void *check_path(char *filename, char const *name, size_t namelen,
			int mode, char const *symbol, char const *path)
{
	size_t len;
	char const *p;
	void *handle;

	p = path;
	while (isspace((int) *p)) p++; /* GNU make is fanatical about spaces */

	len = strlen(p);
	if ((len + 1 + namelen + 1) > PATH_MAX) return NULL;

	memcpy(filename, p, len);
	filename[len] = '/';
	memcpy(filename + len + 1, name, namelen + 1); /* '/' + trailing NIL character */

	handle = dlopen(filename, mode);
	if (!handle) return NULL;

	return check_symbol(handle, symbol);
}

/** Call dlopen as a GNU make function
 *
 *	$(dlopen libfoo)
 *		open it, letting the dynamic linker figure it out
 *
 *	$(dlopen libfoo,symbol)
 *		as above, but also check for presence of "symbol"
 *
 *	$(dlopen libfoo,symbol,/path/to/dir,...)
 *		as above, but if the dynamic linker doesn't find
 *		the libraries, also search the given paths.
 *
 *	$(dlopen /path/to/libfoo)
 *		open it, at the specified path.  Don't let the
 *		dynamic linker make any automatic decisions.
 *
 *	$(dlopen /path/to/libfoo,symbol)
 *		as above, but check for presence of "symbol"
 *
 *	$(dlopen /path/to/libfoo,symbol,/path/to/dir,...)
 *		search specified directories for libfoo,
 *		starting with "/path/to/libfoo".
 *		If a library exists, but does NOT contain
 *     		"symbol", it is skipped.
 *
 *  Library handles are cached across calls to $(dlopen ...).  So they
 *  should be closed with $(dlclose ...)
 *
 *  If a library "libfoo" was found, then any subsequent call to
 *  $(dlopen libfoo,symbol,/path...) will IGNORE both "symbol" and
 *  directory paths.  The way to avoid this caching is to call
 *  $(dlclose ...) first.  That call clears the cached entry, and
 *  allows the search to start from scratch again.
 *
 * @param nm the name of the function
 * @param argc argument count
 * @param argv NULL-terminated array of pointers to arguments
 * @return a string
 *
 * @note the prototype of gmk_add_function() requires argc to be unsigned int
 *       to avoid a warning; this differs from the GNU make docs example.
 * @note argv[0] is really the first argument--if this followed C conventions
 *       for main(), argv[0] would be what's passed here in nm.
 */
static char *make_dlopen(UNUSED char const *nm, unsigned int argc, char **argv)
{
	void *handle;
	int mode = RTLD_NOW;
	char *p, *name, *libname, *filename;
	char const *error = NULL;
	fr_lib_t *lib;

	name = argv2lib(argv[0], &filename, &libname);
	if (!name) return NULL;

	lib = find_lib(libname, NULL);
	if (lib) {
		free(name);
		goto found;
	}

	/*
	 *	@todo - if getenv(LD_LIBRARY_PATH) exists, search that first.
	 *
	 *	Though TBH, the caller can do
	 *
	 *		$(dlopen libfoo,symbol,$(subst :, ,$(LD_LIBRARY_PATH)))
	 */

	/*
	 *	We didn't find it in the list of cached librarys.  Call dlopen().
	 */
	handle = dlopen(name, mode);
	/*
	 *	If we require a particular symbol, check the library
	 *	for it.
	 */
	if (handle && (argc >= 2)) handle = check_symbol(handle, argv[1]);

	if (!handle) {
		unsigned int i;
		size_t len, namelen;

		/*
		 *	Only the library specified specified, OR the
		 *	caller is already trying to load
		 *	`/path/libfoo`, return an error.
		 */
		if (argc == 1) {
		set_dlerror:
			error = dlerror();

		fail:
			if (my_dlerror) {
				free(my_dlerror);
				my_dlerror = NULL;
			}

			if (error) {
				my_dlerror = strdup(error);
			}

			if (name) free(name);
			return NULL;
		}

		/*
		 *	Only Library + symbol, return an error.
		 */
		if (argc == 2) goto set_dlerror;

		filename = malloc(PATH_MAX);
		if (!filename) {
		oom:
			error = "Out of memory";
			goto fail;
		}

		namelen = strlen(libname);

		/*
		 *	Loop through the supplied directories, trying
		 *	to open the full path name.
		 */
		for (i = 2; i < argc; i++) {
			handle = check_path(filename, libname, namelen, mode,
					    argv[1], argv[i]);
			len = strlen(argv[i]);
			if (handle) break;
		}

		/*
		 *	We've found the library with full name in
		 *	"filename".  So we don't need the original
		 *	"name" any more.
		 */
		free(name);
		name = NULL;
		if (!handle) {
			free(filename);
			goto set_dlerror;
		}

		/*
		 *	Point to the library name we previously copied
		 *	over.  This hack is so that the later code can
		 *	assign filename / libname to the "lib"
		 *	structure.
		 */
		libname = filename + len + 1;
	}

	lib = calloc(sizeof(*lib), 1);
	if (!lib) {
		dlclose(handle);
		goto oom;
	}

	/*
	 *	Add the library to the list of libraries we know about.
	 */
	lib->next = libs;
	lib->handle = handle;

	/*
	 *	Ensure that both fields will be dynamically allocated
	 *	strings.
	 */
	if (filename) {
		lib->name = strdup(libname);
		lib->filename = filename;
	} else {
		struct link_map *link_map = NULL;

		lib->name = libname;

#ifdef __linux__
		/*
		 *	RTLD_DI_ORIGIN returns the folder.  This
		 *	function returns the full pathname.  And,
		 *	returns a "struct link_map" which
		 *	coincidentally is also what's available on
		 *	OSX.
		 */
		(void) dlinfo(handle, RTLD_DI_LINKMAP, &link_map);
#else

		/*
		 *	On OSX, the handle is just a `struct link_map`
		 *	pointer.  So we cast the handle to that, and
		 *	access the fields directly.
		 */
		link_map = (struct link_map *) handle;
#endif

		if (link_map) lib->filename = strdup(link_map->l_name);
        }

	libs = lib;

found:
	if (!lib->filename) {
no_file:
		p = gmk_alloc(strlen(lib->name));
		if (!p) goto oom;

		p[0] = '1';
		p[1] = '\0';
		return p;
	}

	p = strrchr(lib->filename, '/');
	if (!p) goto no_file;

	/*
	 *	Return the name of the enclosing directoryto the
	 *	caller.
	 */
	filename = gmk_alloc((p - lib->filename) + 1);
	if (!filename) goto no_file;

	memcpy(filename, lib->filename, p - lib->filename);
	filename[p - lib->filename] = '\0';

	return filename;
}


/** Call dlclose as a GNU make function
 *
 * @param nm the name of the function
 * @param argc argument count
 * @param argv NULL-terminated array of pointers to arguments
 * @return a string
 *
 * @note the prototype of gmk_add_function() requires argc to be unsigned int
 *       to avoid a warning; this differs from the GNU make docs example.
 * @note argv[0] is really the first argument--if this followed C conventions
 *       for main(), argv[0] would be what's passed here in nm.
 */
static char *make_dlclose(UNUSED char const *nm, UNUSED unsigned int argc, char **argv)
{
	char *p, *name, *libname, *filename;
	fr_lib_t *lib, **last;

	name = argv2lib(argv[0], &filename, &libname);
	if (!name) return NULL;

	lib = find_lib(name, &last);
	free(name);

	if (!lib) return NULL;

	/*
	 *	Free whatever is necessary to be freed.
	 */
	if (lib->filename) free(lib->filename);
	free(lib->name);

	(void) dlclose(lib->handle);

	*last = lib->next;
	free(lib);

	/*
	 *	If we've closed all open libraries, then free the
	 *	error string, too.
	 */
	if (!libs && my_dlerror) {
		free(my_dlerror);
		my_dlerror = NULL;
	}

	p = gmk_alloc(2);
	if (!p) return NULL;

	p[0] = '1';
	p[1] = '\0';

	return p;
}

/** Call dlsym as a GNU make function
 *
 * @param nm the name of the function
 * @param argc argument count
 * @param argv NULL-terminated array of pointers to arguments
 * @return a string
 *
 * @note the prototype of gmk_add_function() requires argc to be unsigned int
 *       to avoid a warning; this differs from the GNU make docs example.
 * @note argv[0] is really the first argument--if this followed C conventions
 *       for main(), argv[0] would be what's passed here in nm.
 */
static char *make_dlsym(UNUSED char const *nm, UNUSED unsigned int argc, char **argv)
{
	char *p, *name, *libname, *filename;
	fr_lib_t *lib;
	void *symbol;

	name = argv2lib(argv[0], &filename, &libname);
	if (!name) return NULL;

	lib = find_lib(libname, NULL);
	free(name);
	if (!lib) return NULL;

	p = argv[1];
	while (isspace((int) *p)) p++;

	symbol = dlsym(lib->handle, p);
	if (!symbol) return NULL;

	p = gmk_alloc(2);
	if (!p) return NULL;

	p[0] = '1';
	p[1] = '\0';

	return p;
}


/** Call dlerror as a GNU make function
 *
 * @param nm the name of the function
 * @param argc argument count
 * @param argv NULL-terminated array of pointers to arguments
 * @return a string
 *
 * @note the prototype of gmk_add_function() requires argc to be unsigned int
 *       to avoid a warning; this differs from the GNU make docs example.
 * @note argv[0] is really the first argument--if this followed C conventions
 *       for main(), argv[0] would be what's passed here in nm.
 */
static char *make_dlerror(UNUSED char const *nm, UNUSED unsigned int argc, UNUSED char **argv)
{
	char *p;
	size_t len;

	if (!my_dlerror) return NULL;

	len = strlen(my_dlerror);
	p = gmk_alloc(len + 1);
	if (!p) return NULL;

	memcpy(p, my_dlerror, len + 1);
	return p;
}

/** Register function(s) with make.
 * 
 * @return non-zero value on success, or zero on failure.
 * @note gmk_add_function() "returns" void, so we can't really say whether it
 *       succeeded or failed. Thus the return of the constant 1.
 */
int dlopen_gmk_setup(void)
{
	gmk_add_function("dlopen", &make_dlopen, 1, 0, 0); /* min 1, max 1, please expand the input string */
	gmk_add_function("dlclose", &make_dlclose, 1, 1, 0); /* min 1, max 1, please expand the input string */
	gmk_add_function("dlsym", &make_dlsym, 2, 2, 0); /* min 2, max 2, please expand the input string */
	gmk_add_function("dlerror", &make_dlerror, 0, 0, 0); /* no arguments */

	return 1;
}
