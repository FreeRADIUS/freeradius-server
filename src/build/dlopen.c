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
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
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

#define FREE(_p) \
do { \
	free(_p); \
	(_p) = NULL; \
} while(0)

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
static char *argv2lib(char const *argv, char **libname)
{
	size_t len;
	char *p, *name;

	len = strlen(argv);

	if ((len > 3) && (memcmp(argv, "lib", 3) == 0)) {
		name = malloc(len + sizeof(DL_EXTENSION)); /* sizeof includes the trailing NULL */
		if (!name) return NULL;

		memcpy(name, argv, len);
		memcpy(name + len, DL_EXTENSION, sizeof(DL_EXTENSION));
	} else {
		name = malloc(len + 3 + sizeof(DL_EXTENSION)); /* sizeof includes the trailing NULL */
		if (!name) return NULL;

		memcpy(name, "lib", 3);
		memcpy(name + 3, argv, len);
		memcpy(name + 3 + len, DL_EXTENSION, sizeof(DL_EXTENSION));

	}

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
	} else {
		*libname = name;
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

/*
 *	Get the filename from the linker information.  We don't care
 *	about the filename we used to open the library.  If the linker
 *	information differs from the filename we used, well, there's
 *	little we can do about that.
 */
static char *get_filename(void *handle)
{
	struct link_map *link_map = NULL;

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

	if (!link_map) return NULL;

	return strdup(link_map->l_name);
}


/** Call dlopen as a GNU make function
 *
 *  This function opens a library (without extension!), and returns
 *  the directory where the library was found.
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
 *  The function returns the full pathname where the library was
 *  found, if the full pathname is available.  If no path is
 *  available, it returns the library name. "libfoo".
 *
 *  If the dlopen() call fails, or the symbol isn't found, then the
 *  function returns an empty string "".
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
	char *p, *name, *libname;
	char const *error = NULL;
	fr_lib_t *lib;

	name = argv2lib(argv[0], &libname);
	if (!name) return NULL;

	lib = find_lib(libname, NULL);
	if (lib) {
		FREE(name);
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
	 *	We didn't find it in the list of cached librarys.
	 *	Call dlopen().
	 *
	 *	"name" here can either be the full filename, or just
	 *	the libname.
	 */
	handle = dlopen(name, mode);

	/*
	 *	If we require a particular symbol, check the library
	 *	for it.
	 */
	if (handle && (argc >= 2)) handle = check_symbol(handle, argv[1]);

	if (!handle) {
		unsigned int i;
		size_t liblen;
		char *filename;

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
				FREE(my_dlerror);
			}

			if (error) {
				my_dlerror = strdup(error);
			}

			if (name) {
				FREE(name);
			}
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

		liblen = strlen(libname);

		/*
		 *	Loop through the supplied directories, trying
		 *	to open the full path name.
		 */
		for (i = 2; i < argc; i++) {
			handle = check_path(filename, libname, liblen, mode,
					    argv[1], argv[i]);
			if (handle) break;
		}

		FREE(filename);
		if (!handle) goto set_dlerror;
	}

	/*
	 *	Ensure that "libname" is always dynamically allocated.
	 */
	if (libname != name) {
		libname = strdup(libname);
		FREE(name);
		if (!libname) goto oom;

	} else {
		/*
		 *	We don't need this any more.  "libname" points
		 *	to the memory.
		 */
		name = NULL;
	}

	lib = calloc(sizeof(*lib), 1);
	if (!lib) {
		FREE(libname);
		dlclose(handle);
		goto oom;
	}

	/*
	 *	Add the library to the list of libraries we know about.
	 */
	lib->next = libs;
	lib->handle = handle;
	lib->name = libname;

	lib->filename = get_filename(handle);

	libs = lib;

found:
	if (!lib->filename) {
no_file:
		p = gmk_alloc(1);
		if (!p) goto oom;

		p[0] = '\0';
		return p;
	}

	p = strrchr(lib->filename, '/');
	if (!p) goto no_file;

	/*
	 *	Return the name of the enclosing directory to the
	 *	caller.
	 */
	name = gmk_alloc((p - lib->filename) + 1);
	if (!name) goto no_file;

	memcpy(name, lib->filename, p - lib->filename);
	name[p - lib->filename] = '\0';

	return name;
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
	char *p, *name, *libname;
	fr_lib_t *lib, **last;

	name = argv2lib(argv[0], &libname);
	if (!name) return NULL;

	lib = find_lib(name, &last);
	FREE(name);

	if (!lib) return NULL;

	/*
	 *	Free whatever is necessary to be freed.
	 */
	FREE(lib->filename);
	FREE(lib->name);

	(void) dlclose(lib->handle);

	*last = lib->next;
	FREE(lib);

	/*
	 *	If we've closed all open libraries, then free the
	 *	error string, too.
	 */
	if (!libs && my_dlerror) FREE(my_dlerror);

	p = gmk_alloc(2);
	if (!p) return NULL;

	p[0] = '1';
	p[1] = '\0';

	return p;
}

/** Call dlsym as a GNU make function
 *
 *  This function opens a library (without extension!), and returns
 *  the directory where the library was found.
 *
 *	$(dlsymb libfoo,symbol)
 *		Checks a library previously opened with $(dlopen ...)
 *		for the existence of "symbol"
 *
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
	char *p, *name, *libname;
	fr_lib_t *lib;
	void *symbol;

	name = argv2lib(argv[0], &libname);
	if (!name) return NULL;

	lib = find_lib(libname, NULL);
	FREE(name);
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


#if 0
#define DEBUG(...) fprintf(stderr, ## __VA_ARGS__ )
#else
#define DEBUG(...)
#endif

typedef struct ad_define_s {
	struct ad_define_s *next;
	size_t		    len;
	char		    name[0];
} ad_define_t;

static ad_define_t *ad_define_head = NULL;

static void ad_have_feature(char const *symbol)
{
	char *p;
	ad_define_t *def, **last;
	size_t len;

	len = strlen(symbol);

	def = malloc(sizeof(ad_define_t) + len + 5 + 2 + 1);
	if (!def) return;

	memcpy(def->name, "HAVE_", 5);
	memcpy(def->name + 5, symbol, len);
	strcpy(def->name + 5 + len, "=1");

	for (p = def->name + 5; *p != '\0'; p++) {
		if (islower((int) *p)) {
			*p = toupper((int) *p);

		} else if ((*p == '/') || (*p == '.')) {
			*p = '_';

		} else if (*p == '-') {
			*p = '_';
		}
	}

	gmk_eval(def->name, NULL);

	/*
	 *	O(N^2) is OK if we're not doing 1000's of definitions.
	 */
	for (last = &ad_define_head; *last != NULL; last = &(*last)->next) {
		if (def->name[5] > (*last)->name[5]) continue; /* avoid strcmp() for the common case */

		if (strcmp(def->name + 5, (*last)->name + 5) > 0) continue;
		break;
	}

	/*
	 *	Remember which definitions we printed.
	 */
	def->next = *last;
	def->len = len;
	*last = def;
}


static void ad_update_variable(char const *name, char *value)
{
	size_t name_len, value_len;
	char *old, *p, *expand;

	DEBUG("Update %s with %s\n", name, value);

	if (!value || !*value || (*value == ' ')) return;

	name_len = strlen(name);

	expand = gmk_alloc(name_len + 4);
	if (!expand) return;

	/*
	 *	Expand the variable.
	 */
	expand[0] = '$';
	expand[1] = '(';
	memcpy(expand + 2, name, name_len);
	expand[2 + name_len] = ')';
	expand[2 + name_len + 1] = '\0';

	old = gmk_expand(expand);
	gmk_free(expand);
	if (!old) return;

	/*
	 *	It already contains "value", so that's OK.
	 *
	 *	But check for the *whole* value.  i.e. if there's
	 *	"-lfoo", and we're asked to add "-lfood", then we need
	 *	to add "-lfood".
	 */
	value_len = strlen(value);

	p = strstr(old, value);
	if (p) {
		if (!p[value_len] || isspace((int) p[value_len])) {
			gmk_free(old);
			return;
		}

		gmk_free(old);
	}

	expand = gmk_alloc(name_len + 4 + name_len + 2 + value_len + 1);
	if (!expand) return;

	/*
	 *	Because sprintf() is for weenies :)
	 */
	p = expand;
	memcpy(p, name, name_len);
	p += name_len;
	*p++ = ':';
	*p++ = '=';
	*p++ = '$';
	*p++ = '(';
	memcpy(p, name, name_len);
	p += name_len;
	*p++ = ')';
	*p++ = ' ';
	strcpy(p, value);

	DEBUG("RESULT ASKED TO EVAL - %s\n", expand);
	gmk_eval(expand, NULL);
	gmk_free(expand);
}


static void *ad_try_dlopen(char const *name, char const *dir, void **handle)
{
	void *symbol;
	char *path, *libname;

	DEBUG("\tchecking ::%s::\n", dir);
	*handle = NULL;

	if (*dir == '\0') {
		symbol = dlsym(RTLD_DEFAULT, name);
		if (symbol) {
			DEBUG("\tfound in RTLD_DEFAULT\n");
			return symbol;
		}

		DEBUG("\tdid not find in RTLD_DEFAULT\n");
		return NULL;
	}

	/*
	 *	Get the full path name
	 *
	 *	libfoo -> /path/libfoo.so
	 */
	path = argv2lib(dir, &libname);
	if (!path) {
		DEBUG("\tfailed getting path from %s\n", dir);
		return NULL;
	}

	/*
	 *	If this succeeds, we can get the full
	 *	pathname from the handle.
	 */
	*handle = dlopen(path, RTLD_NOW);
	if (!*handle) {
		DEBUG("\tdlopen failed for %s\n", path);
		FREE(path);
		return NULL;
	}
	FREE(path);

	/*
	 *	Not found, oh well.
	 */
	symbol = dlsym(*handle, name);
	if (!symbol) {
		DEBUG("\tsymbol not found");
		dlclose(*handle);
		*handle = NULL;
		return NULL;
	}

	DEBUG("\tfound in %s\n", dir);
	return symbol;
}

/** Search libraries without using $(dlopen ...)
 *
 *  The output is empty if the symbol wasn't found.
 *
 *  Otherwise, the output is the LDFLAGS changes needed
 *  to link to the symbol.  If no LDFLAGS are necessary,
 *  then the output is a space character.
 *
 *	$(ad_search_libs symbol)
 *		to to find a symbol in a library already loaded
 *
 *	$(ad_search_libs symbol,libfoo)
 *		to to find a symbol in a specific library which
 *
 *	$(ad_search_libs symbol,libfoo,/path/to/libbar)
 *		to to find a symbol in a specific set of libraries
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
static char *make_ad_search_libs(UNUSED char const *nm, unsigned int argc, char **argv)
{
	char *p, *q, *r;
	char const *name;
	void *symbol = NULL;
	void *handle;

	/*
	 *	Get the symbol name
	 */
	name = argv[0];
	while (isspace((int) *name)) name++;

	DEBUG("Searching for symbol %s\n", name);

	if (argc == 1 ) {
		symbol = dlsym(RTLD_DEFAULT, name);
		handle = NULL;

		DEBUG("\tSearching in application\n");

	} else {
		unsigned int i;

		for (i = 1; i < argc; i++) {
			bool has_dash_l = false;

			r = argv[i] + strlen(argv[i]);

			/*
			 *	As a special case, we allow the caller
			 *	to pass in $(LDFLAGS).  We look for
			 *	"-Lfoo", and pass "foo" to the
			 *	ad_try_dlopen() function.  Any other
			 *	options are ignored.
			 *
			 *	This functionality means that there is
			 *	a _lot_ less magic inside of GNU Make
			 *	macros.
			 */
			p = argv[i];
			while (p < r) {
				while (isspace((int) *p)) p++;

				if ((p[0] == '-') && (p[1] == 'L')) {
					has_dash_l = true;

					/*
					 *	-L  /path/to/foo is OK
					 */
					q = p + 2;
					while (isspace((int) *q)) q++;

					/*
					 *	@todo - deal with
					 *	quotes and backslashes
					 *	in file names.
					 */
					while (*q && !isspace((int) *q)) q++;

					*q = '\0';

					symbol = ad_try_dlopen(name, p + 2, &handle);
					if (symbol) {
						name = p;
						goto found;
					}

					/*
					 *	Go to the character *after* the -L /path/to/foo
					 */
					p = q + 1;
					continue;
				}

				/*
				 *	The argument isn't -L foo, skip it.
				 */
				while (*p && !isspace((int) *p)) p++;
			}

			/*
			 *	If the argument has -L/path/to/foo, then ignore
			 *	everything in it that *isn't* -L/path/to/foo
			 */
			if (has_dash_l) continue;

			symbol = ad_try_dlopen(name, argv[i], &handle);
			if (!symbol) continue;

			name = argv[i];
			break;
		}
	}

	if (!symbol) {
		DEBUG("\tnot found\n");
		return NULL;
	}

found:
	/*
	 *	Define HAVE_foo = 1
	 */
	ad_have_feature(argv[0]);

	/*
	 *	Found in the application. The search path is " ".
	 */
	if (!handle) {
		p = gmk_alloc(2);
		if (!p) return NULL;

		p[0] = ' ';
		p[1] = '\0';
		return p;
	}

	DEBUG("\tfound symbol '%s' in '%s'\n", argv[0], name);

	/*
	 *	Convert "libfoo" to "-lfoo"
	 */
	if (strncmp(name, "lib", 3) == 0) {
		dlclose(handle);

		p = gmk_alloc(strlen(name));
		if (!p) return NULL;

		p[0] = '-';
		p[1] = 'l';
		strcpy(p + 2, name + 3);

		ad_update_variable("LIBS", p);
		ad_have_feature(name);

		return p;
	}

	/*
	 *	If the library is just "m" instead of "libm", allow
	 *	it.
	 */
	q = strrchr(name, '/');
	if (!q) {
		size_t len = strlen(name);

		dlclose(handle);

		p = gmk_alloc(len + 4);
		if (!p) return NULL;

		memcpy(p, "lib", 3);
		memcpy(p + 3, name, len + 1);
		ad_have_feature(p);

		p[0] = '-';
		p[1] = 'l';
		memcpy(p + 2, name, len + 1);

		ad_update_variable("LIBS", p);

		return p;
	}

	/*
	 *	foo/bar ??? what the heck is that?
	 */
	if (strncmp(q, "/lib", 4) != 0) {
		dlclose(handle);
		return NULL;
	}


	/*
	 *	path/to/libfoo
	 *	/path/to/libfoo
	 *
	 *	Convert to "-Lpath/to -lfoo"
	 */
	p = gmk_alloc(strlen(name) + 5);
	p[0] = '-';
	p[1] = 'L';

	memcpy(p + 2, name , (q - name));
	r = p + 2 + (q - name);

	r[0] = '\0';
	ad_update_variable("LDFLAGS", p);
	ad_have_feature(p);

	r[0] = ' ';
	r[1] = '-';
	r[2] = 'l';
	strcpy(r + 3, q + 4);

	ad_update_variable("LIBS", r);
	dlclose(handle);

	return p;
}

/**  Dump definitions for Make or CPP
 *
 *	$(ad_dump_definess )
 *		dump to stdout.  Note the final space!
 *		$(ad_dump_defs) is a variable expansion, not a function call.
 *
 *	$(ad_dump_defines foo.mak)
 *		dump definitions in Makefile format	HAVE_FOO=1
 *
 *	$(ad_dump_defines foo.h)
 *		dump definitions in CPP format		#define HAVE_FOO (1)
 *
 *	@todo - allow multiple filenames?
 */
static char *make_ad_dump_defines(UNUSED char const *nm, unsigned int argc, char **argv)
{
	ad_define_t *def;
	FILE *fp;

	if ((argc == 0) || !*argv[0] || isspace((int) *argv[0])) {
		fp = stdout;

	} else {
		char *p;

		fp = fopen(argv[0], "w");
		if (!fp) {
			fprintf(stderr, "ad_dump_defs: Failed opening %s - %s\n",
				argv[0], strerror(errno));
		}

		/*
		 *	If the file ends in ".h", it's a header file.
		 *	So dump the definitions in C preprocessor
		 *	format.
		 */
		p = strrchr(argv[0], '.');
		if (p && (p[1] == 'h') && !p[2]) {
			for (def = ad_define_head; def != NULL; def = def->next) {
				fprintf(fp, "#define %.*s (1)\n", (int) def->len + 5, def->name);
			}

			fclose(fp);
			return NULL;
		}
	}

	/*
	 *	Print Makefile rules to redefine the variables we've created.
	 */
	for (def = ad_define_head; def != NULL; def = def->next) {
		fprintf(fp, "%s\n", def->name);
	}

	if (fp != stdout) fclose(fp);

	return NULL;
}

/*
 *	If the error file has non-zero size, then rewrite it
 *	by removing all lines which are only spaces.
 *
 *	Log the command which was run, and the error status.
 *
 *	If the command returned 0, and CPPFLAGS is not using
 *	-Werror, then return success.  Otherwise, if CPPFLAGS
 *	is using -Werror and the argv[0].err file is
 *	non-empty, then that's a success too.
 *
 *
 *	try_compile has exactly the same checks, but it also
 *	checks for a non-zero object file.
 *
 */
static char *run_cmd(char const *cmd, char *filename)
{
	size_t len1, len2;
	char *str, *result;

	len1 = strlen(cmd);
	len2 = strlen(filename);

	/*
	 *	This is a lot more CPU time than running fork / exec /
	 *	waitpid ourselves.  But it's less work for the programmer. :)
	 */
	str = malloc(8 + len1 + 1 + len2 + 2 + len2 + 7 + len2 + 15);
	if (!str) return NULL;

	sprintf(str, "$(shell %s %s >%s.out 2>%s.err;echo $$?)", cmd, filename, filename, filename);

	/*
	 *	Expand it, running the shell.
	 */
	result = gmk_expand(str);
	free(str);

	return result;
}

static void ad_unlink(char const *filename, char const *ext)
{
	size_t len, len2;
	char *str;

	len = strlen(filename);

	if (ext) {
		len2 = strlen(ext) + 1;
		if (len2 < 5) len2 = 5;
	} else {
		len2 = 5;
	}

	str = malloc(len + len2);
	if (!str) return;

	memcpy(str, filename, len);
	strcpy(str + len, ".out");
	(void) unlink(str);
	strcpy(str + len, ".err");
	(void) unlink(str);

	/*
	 *	Maybe unlink a ".o" or a ".dylib" file, too.
	 */
	if (ext) {
		strcpy(str + len, ext);
		(void) unlink(str);
	}

	free(str);
}

static char const *ad_includes_default = \
"#include <stdio.h>\n"
"#ifdef HAVE_SYS_TYPES_H\n"
"# include <sys/types.h>\n"
"#endif\n"
"#ifdef HAVE_SYS_STAT_H\n"
"# include <sys/stat.h>\n"
"#endif\n"
"#ifdef STDC_HEADERS\n"
"# include <stdlib.h>\n"
"# include <stddef.h>\n"
"#else\n"
"# ifdef HAVE_STDLIB_H\n"
"#  include <stdlib.h>\n"
"# endif\n"
"#endif\n"
"#ifdef HAVE_STRING_H\n"
"# if !defined STDC_HEADERS && defined HAVE_MEMORY_H\n"
"#  include <memory.h>\n"
"# endif\n"
"# include <string.h>\n"
"#endif\n"
"#ifdef HAVE_STRINGS_H\n"
"# include <strings.h>\n"
"#endif\n"
"#ifdef HAVE_INTTYPES_H\n"
"# include <inttypes.h>\n"
"#endif\n"
"#ifdef HAVE_STDINT_H\n"
"# include <stdint.h>\n"
"#endif\n"
"#ifdef HAVE_UNISTD_H\n"
"# include <unistd.h>\n"
"#endif\n";

static char *make_ad_fn_c_try_cpp(UNUSED char const *nm, UNUSED unsigned int argc, char **argv)
{
	char *result;

	result = run_cmd("${CPP} ${CPPFLAGS} %s", argv[0]);
	ad_unlink(argv[0], NULL);
	return result;
}


/*
 *	filename, include [, includes ]
 */
static char *make_ad_fn_c_check_header_compile(UNUSED char const *nm, unsigned int argc, char **argv)
{
	unsigned int i;
	char *result;
	FILE *fp;

	fp = fopen(argv[0], "w+");
	if (!fp) {
		/* @todo - error */
		return NULL;
	}

	/*
	 *	@todo - pull in common confdefs.h ?
	 */

	for (i = 2; i < argc; i++) {
		if (!strchr(argv[i], '\n')) {
			fprintf(fp, "#include <%s>\n", argv[i]);
		} else {
			fprintf(fp, "%s\n", argv[i]);
		}
	}

	fprintf(fp, "#include <%s>\n", argv[1]);
	fclose(fp);

	result = run_cmd("${CC} -c ${CFLAGS} ${CPPFLAGS}", argv[0]);
	if (!result) goto done;

	/*
	 *	Define HAVE_FOO_H for foo.h
	 */
	if (strcmp(result, "0") == 0) {
		ad_have_feature(argv[1]);
	}
	gmk_free(result);

done:
	(void) unlink(argv[0]);
	ad_unlink(argv[0], DL_EXTENSION);

	/*
	 *	Return the empty string, so that make doesn't get
	 *	excited over the use of the bare function.
	 */
	result = gmk_alloc(1);
	if (!result) return NULL;
	*result = '\0';
	return result;
}

static char *next_word(char **in)
{
	char *p;

	if (!in || !*in) return NULL;

	p = *in;

	while (*p && !isspace((int) *p)) p++;
	if (!*p) {
		*in = NULL;
	} else {
		*(p++) = '\0';
		*in = p;
	}

	return *in;
}

static char *make_ad_check_headers(char const *nm, unsigned int argc, char **argv)
{
	unsigned int i;
	char *result;
	char *my_argv[3];

	my_argv[0] = strdup("conftest.c");
	my_argv[2] = strdup(ad_includes_default);

	for (i = 0; i < argc; i++) {
		char *p;

		/*
		 *	Allow spaces.  Because Make uses "," to
		 *	separate arguments to functions *but* also
		 *	uses spaces for similar things.
		 *
		 *	Instead of punishing the poor admin with GNU
		 *	Make stupidities, we just do the Right Thing.
		 */
		p = argv[i];
		while (p) {
			my_argv[1] = next_word(&p);
			(void) make_ad_fn_c_check_header_compile(nm, 3, my_argv);
		}
	}

	free(my_argv[0]);
	free(my_argv[2]);

	result = gmk_alloc(1);
	if (!result) return NULL;

	*result = '\0';
	return result;
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
	gmk_add_function("ad_search_libs", &make_ad_search_libs, 1, 0, 0);
	gmk_add_function("ad_dump_defines", &make_ad_dump_defines, 0,1, 0);

	gmk_add_function("ad_fn_c_try_cpp", &make_ad_fn_c_try_cpp, 1, 1, 0);
	gmk_add_function("ad_fn_c_check_header_compile", &make_ad_fn_c_check_header_compile, 2, 0, 0);
	gmk_add_function("ad_check_headers", &make_ad_check_headers, 1, 0, 0);

	return 1;
}
