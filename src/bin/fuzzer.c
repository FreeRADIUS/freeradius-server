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
 * @file src/bin/fuzzer.c
 * @brief Functions to fuzz protocol decoding
 *
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/io/test_point.h>

/*
 *	Run from the source directory via:
 *
 *	./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer_radius -D share/dictionary /path/to/corpus/directory/
 */

static bool			init = false;
static fr_test_point_proto_decode_t *tp	= NULL;
static dl_t			*dl = NULL;
static dl_loader_t		*dl_loader;

static fr_dict_t		*dict = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static void exitHandler(void)
{
	fr_dict_free(&dict, __FILE__);

	if (dl && dl->handle) {
		dlclose(dl->handle);
		dl->handle = NULL;
	}
	talloc_free(dl_loader);

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char const		*lib_dir  	= getenv("FR_LIBRARY_PATH");
	char const		*proto    	= getenv("FR_LIBRARY_FUZZ_PROTOCOL");
	char const		*dict_dir	= getenv("FR_DICTIONARY_DIR");
	char const		*debug_lvl_str	= getenv("FR_DEBUG_LVL");
	char			buffer[1024];

	if (!argc || !argv || !*argv) return -1; /* shut up clang scan */

	if (debug_lvl_str) fr_debug_lvl = atoi(debug_lvl_str);

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
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Get the name from the binary name of fuzzer_foo
	 */
	if (!proto) {
		proto = strrchr((*argv)[0], '_');
		if (proto) proto++;
	}

	/*
	 *	Look for -D dir
	 *
	 *	If found, nuke it from the argument list.
	 */
	if (!dict_dir) {
		int i, j;

		for (i = 0; i < *argc - 1; i++) {
			char *p = (*argv)[i];

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

	/*	if (!dict_dir) dict_dir = int; -- removed to match oss-fuzz patch    */

        DICTDIR free_dict = 0;
	int free_lib = 0;
        if (!dict_dir) {
		dict_dir = malloc(strlen((*argv)[0]) + 1);
		memcpy(dict_dir, (*argv)[0], strlen((*argv)[0]) + 1);
		snprintf(strrchr(dict_dir, '/'), 6, "/dict");
		free_dict = 1;
	}
	if (!lib_dir) {
		lib_dir = malloc(strlen((*argv)[0]) + 1);
		memcpy(lib_dir, (*argv)[0], strlen((*argv)[0]) + 1);
		snprintf(strrchr(lib_dir, '/'), 5, "/lib");
		setenv("FR_LIBRARY_PATH", lib_dir, 1);
		free_lib = 1;
	}
 
	/*
	 *	When jobs=N is specified the fuzzer spawns worker processes via
	 *	a shell. We have removed any -D dictdir argument that were
	 *	supplied, so we pass it to our children via the environment.
	 */
	if (setenv("FR_DICTIONARY_DIR", dict_dir, 1)) {
		fprintf(stderr, "Failed to set FR_DICTIONARY_DIR env variable\n");
		fr_exit_now(EXIT_FAILURE);
	}

	if (!fr_dict_global_ctx_init(NULL, true, dict_dir)) {
		fr_perror("dict_global");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("fuzzer: Failed initializing internal dictionary");
		fr_exit_now(EXIT_FAILURE);
	}

	if (!proto) {
		fr_perror("Failed to find protocol for fuzzer");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Disable hostname lookups, so we don't produce spurious DNS
	 *	queries, and there's no chance of spurious failures if
	 *	it takes a long time to get a response.
	 */
	fr_hostname_lookups = fr_reverse_lookups = false;

	dl_loader = dl_loader_init(NULL, NULL, 0, false);
	if (!dl_loader) {
		fr_perror("fuzzer: Failed initializing library loader");
		fr_exit_now(EXIT_FAILURE);
	}
	dl_search_path_prepend(dl_loader, lib_dir);

	snprintf(buffer, sizeof(buffer), "libfreeradius-%s", proto);
	dl = dl_by_name(dl_loader, buffer, NULL, false);
	if (!dl) {
		fr_perror("fuzzer: Failed loading library %s", buffer);
		fr_exit_now(EXIT_FAILURE);
	}

	snprintf(buffer, sizeof(buffer), "%s_tp_decode_proto", proto);

	tp = dlsym(dl->handle, buffer);
	if (!tp) {
		fr_perror("fuzzer: Failed finding test point %s", buffer);
		fr_exit_now(EXIT_FAILURE);
	}

	init = true;

	if (free_lib) {
		free(lib_dir);
	}
	if (free_dict) {
		free(dict_dir);
	}
	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX *   ctx = talloc_init_const("fuzzer");
	fr_pair_list_t vps;
	void *decode_ctx = NULL;

	fr_pair_list_init(&vps);
	if (!init) LLVMFuzzerInitialize(NULL, NULL);

	if (tp->test_ctx && (tp->test_ctx(&decode_ctx, NULL) < 0)) {
		fr_perror("fuzzer: Failed initializing test point decode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	tp->func(ctx, &vps, buf, len, decode_ctx);
	if (fr_debug_lvl > 3) fr_pair_list_debug(&vps);

	talloc_free(decode_ctx);
	talloc_free(ctx);

	/*
	 *	Clear error messages from the run.  Clearing these
	 *	keeps malloc/free balanced, which helps to avoid the
	 *	fuzzers leak heuristics from firing.
	 */
	fr_strerror_clear();

	return 0;
}
