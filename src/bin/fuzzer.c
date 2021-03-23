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

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/io/test_point.h>

/*
 *	Run from the source directory via:
 *
 *	./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer_radius -D share/dictionary /path/to/corpus/directory/
 */

static bool			     init	= false;
static void *			     decode_ctx = NULL;
static fr_test_point_proto_decode_t *tp		= NULL;
static fr_dict_t *		     dict	= NULL;

static dl_t *	    dl = NULL;
static dl_loader_t *dl_loader;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static void exitHandler()
{
	if (dl && dl->handle) {
		dlclose(dl->handle);
		dl->handle = NULL;
	}
	talloc_free(dl_loader);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char const *lib_dir  = getenv("FR_LIBRARY_PATH");
	char const *proto    = getenv("FR_LIBRARY_FUZZ_PROTOCOL");
	char const *dict_dir = getenv("FR_DICTIONARY_DIR");
	char	    buffer[1024];

	if (!argc || !argv || !*argv) return -1; /* shut up clang scan */

	/*
	 *	Setup atexit handlers to free any thread local
	 *	memory on exit
	 */
	fr_thread_local_atexit_setup();

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

	if (!dict_dir) dict_dir = DICTDIR;

	/*
	 *	When jobs=N is specified the fuzzer spawns worker processes via
	 *	a shell. We have removed any -D dictdir argument that were
	 *	supplied, so we pass it to our children via the environment.
	 */
	if (setenv("FR_DICTIONARY_DIR", dict_dir, 1)) {
		fprintf(stderr, "Failed to set FR_DICTIONARY_DIR env variable\n");
		fr_exit_now(EXIT_FAILURE);
	}

	if (!fr_dict_global_ctx_init(NULL, dict_dir)) {
		fr_perror("dict_global");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR) < 0) {
		fr_perror("fuzzer: Failed initializing internal dictionary");
		fr_exit_now(EXIT_FAILURE);
	}

	if (!proto) {
		fr_perror("Failed to find protocol for fuzzer");
		fr_exit_now(EXIT_FAILURE);
	}

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

	if (tp->test_ctx(&decode_ctx, NULL) < 0) {
		fr_perror("fuzzer: Failed finding test point %s", buffer);
		fr_exit_now(EXIT_FAILURE);
	}

	init = true;

	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX *   ctx = talloc_init_const("fuzzer");
	fr_pair_list_t vps;

	fr_pair_list_init(&vps);
	if (!init) LLVMFuzzerInitialize(NULL, NULL);

	tp->func(ctx, &vps, buf, len, decode_ctx);
	talloc_free(ctx);

	/*
	 *	Clear error messages from the run.  Clearing these
	 *	keeps malloc/free balanced, which helps to avoid the
	 *	fuzzers leak heuristics from firing.
	 */
	fr_strerror_clear();

	return 0;
}
