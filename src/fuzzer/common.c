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
 * @file src/fuzzer/common.c
 * @brief Common initialization for fuzzers
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>

TALLOC_CTX		*autofree = NULL;

fr_dict_t		*dict = NULL;
fr_dict_attr_t const	*root_da = NULL;

fr_dict_protocol_t	*dl_proto = NULL;


static void exitHandler(void)
{
	if (dl_proto && dl_proto->free) dl_proto->free();

	fr_dict_free(&dict, __FILE__);

	talloc_free(autofree);

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();
}

/**  Perform all bootstrapping for the fuzzer.
 *
 */
int fuzzer_common_init(int *argc, char ***argv, bool load_proto)
{
	char const		*lib_dir  	= getenv("FR_LIBRARY_PATH");
	char const		*dict_dir	= getenv("FR_DICTIONARY_DIR");
	char const		*debug_lvl_str	= getenv("FR_DEBUG_LVL");
	char const		*panic_action	= getenv("PANIC_ACTION");

	char const		*proto    	= getenv("FR_LIBRARY_FUZZ_PROTOCOL");
	char const		*root_attr	= getenv("FR_FUZZER_ROOT_ATTR");

	char			*p, buffer[256];

	if (!argc || !argv || !*argv) return -1; /* shut up clang scan */

	if (debug_lvl_str) {
		fr_debug_lvl = atoi(debug_lvl_str);

		if (fr_debug_lvl) fr_time_start();
	}

	autofree = talloc_autofree_context();
	if (fr_fault_setup(autofree, panic_action, (*argv)[0]) < 0) {
		fr_perror("fuzzer: Failed to register fault handler: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	Setup atexit handlers to free any thread local
	 *	memory on exit
	 */
	fr_atexit_global_setup();

	/*
	 *	Initialise the talloc fault handlers.
	 */
	fr_talloc_fault_setup();

	/*
	 *	Initialise the error stack _before_ we run any
	 *	tests so there's no chance of the memory
	 *	appearing as a leak the first time an error
	 *	is generated.
	 */
	fr_strerror_const("fuzz"); /* allocate the pools */
	fr_strerror_clear(); /* clears the message, leaves the pools */

	/*
	 *	Setup our own internal atexit handler
	 */
	if (atexit(exitHandler)) {
		fr_perror("fuzzer: Failed to register exit handler: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	Disable hostname lookups, so we don't produce spurious DNS
	 *	queries, and there's no chance of spurious failures if
	 *	it takes a long time to get a response.
	 */
	fr_hostname_lookups = fr_reverse_lookups = false;

	/*
	 *	Look for -D dir
	 *
	 *	If found, nuke it from the argument list.
	 */
	if (!dict_dir) {
		int i, j;

		for (i = 0; i < *argc - 1; i++) {
			p = (*argv)[i];

			if ((p[0] == '-') && (p[1] == 'D')) {
				dict_dir = (*argv)[i + 1];

				for (j = i + 2; j < *argc; i++, j++) {
					(*argv)[i] = (*argv)[j];
				}

				*argc -= 2;
				break;
			}
		}
	}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/*
	 *	oss-fuzz puts the dictionaries, etc. into subdirectories named after the location of the
	 *	binary.  So we find the directory of the binary, and append "/dict" or "/lib" to find
	 *	dictionaries and libraries.
	 */
	p = strrchr((*argv)[0], '/');
	if (p) {
		if (!dict_dir) {
			dict_dir = talloc_asprintf(autofree, "%.*s/dict", (int) (p - (*argv)[0]), (*argv)[0]);
			if (!dict_dir) return -1;
		}

		if (!lib_dir) {
			lib_dir = talloc_asprintf(autofree, "%.*s/lib", (int) (p - (*argv)[0]), (*argv)[0]);
			if (!lib_dir) return -1;
		}
	}
#endif

	if (!dict_dir) dict_dir = DICTDIR;
	if (!lib_dir) lib_dir = LIBDIR;

	/*
	 *	Set the global search path for all dynamic libraries we load.
	 */
	if (dl_search_global_path_set(lib_dir) < 0) {
		fr_perror("fuzzer: Failed setting library path");
		return -1;
	}

	/*
	 *	When jobs=N is specified the fuzzer spawns worker processes via
	 *	a shell. We have removed any -D dictdir argument that were
	 *	supplied, so we pass it to our children via the environment.
	 */
	if (setenv("FR_DICTIONARY_DIR", dict_dir, 1)) {
		fprintf(stderr, "Failed to set FR_DICTIONARY_DIR env variable\n");
		return -1;
	}

	if (!fr_dict_global_ctx_init(NULL, true, dict_dir)) {
		fr_perror("fuzzer: Failed initializing global dictionary context");
		return -1;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("fuzzer: Failed initializing internal dictionary");
		return -1;
	}

	if (!load_proto) return 0;

	/*
	 *	Get the name from the binary name of fuzzer_foo
	 */
	if (!proto) {
		proto = strrchr((*argv)[0], '_');
		if (proto) proto++;
	}

	if (!proto) {
		fr_perror("Failed to find protocol for fuzzer");
		return -1;
	}

	if (root_attr) {
		root_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict), root_attr);
		if (!root_da) {
			fr_perror("Failed to find root attribute '%s'", root_attr);
			return -1;
		}
	}

	/*
	 *	Search in our symbol space first.  We may have been dynamically
	 *	or statically linked to the library we're fuzzing...
	 */
	snprintf(buffer, sizeof(buffer), "libfreeradius_%s_dict_protocol", proto);

	dl_proto = dlsym(RTLD_DEFAULT, buffer);
	if (!dl_proto) return 0;

	if (dl_proto->init && (dl_proto->init() < 0)) {
		fr_perror("fuzzer: Failed initializing library %s", buffer);
		return -1;
	}

	return 0;
}
