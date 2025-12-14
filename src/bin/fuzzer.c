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
 * @copyright 2019 Network RADIUS SAS (legal@networkradius.com)
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
static dl_t			*dl = NULL;
static dl_loader_t		*dl_loader;
static fr_dict_protocol_t	*dl_proto;
static TALLOC_CTX		*autofree = NULL;
static bool			do_encode = false;

static fr_dict_t		*dict = NULL;

extern fr_test_point_proto_decode_t XX_PROTOCOL_XX_tp_decode_proto;
extern fr_test_point_proto_encode_t XX_PROTOCOL_XX_tp_encode_proto;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static void exitHandler(void)
{
	if (dl_proto && dl_proto->free) dl_proto->free();

	fr_dict_free(&dict, __FILE__);

	if (dl && dl->handle) {
		dlclose(dl->handle);
		dl->handle = NULL;
	}
	talloc_free(dl_loader);

	talloc_free(autofree);

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();
}

static inline
fr_dict_protocol_t *fuzzer_dict_init(void *dl_handle, char const *proto)
{
	char			buffer[256];
	fr_dict_protocol_t	*our_dl_proto;

	snprintf(buffer, sizeof(buffer), "libfreeradius_%s_dict_protocol", proto);

	our_dl_proto = dlsym(dl_handle, buffer);
	if (our_dl_proto && our_dl_proto->init() && (our_dl_proto->init() < 0)) {
		fr_perror("fuzzer: Failed initializing library %s", buffer);
		fr_exit_now(EXIT_FAILURE);
	}

	return our_dl_proto;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char const		*lib_dir  	= getenv("FR_LIBRARY_PATH");
	char const		*proto    	= getenv("FR_LIBRARY_FUZZ_PROTOCOL");
	char const		*dict_dir	= getenv("FR_DICTIONARY_DIR");
	char const		*debug_lvl_str	= getenv("FR_DEBUG_LVL");
	char const		*panic_action	= getenv("PANIC_ACTION");
	char const		*p;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	char			*dict_dir_to_free = NULL;
	char			*lib_dir_to_free = NULL;
#endif

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
			dict_dir = dict_dir_to_free = talloc_asprintf(NULL, "%.*s/dict", (int) (p - (*argv)[0]), (*argv)[0]);
			if (!dict_dir_to_free) fr_exit_now(EXIT_FAILURE);
		}

		if (!lib_dir) {
			lib_dir = lib_dir_to_free = talloc_asprintf(NULL, "%.*s/lib", (int) (p - (*argv)[0]), (*argv)[0]);
			if (!lib_dir_to_free) fr_exit_now(EXIT_FAILURE);
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
		fr_exit_now(EXIT_FAILURE);
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

	/*
	 *	Search in our symbol space first.  We may have been dynamically
	 *	or statically linked to the library we're fuzzing...
	 */
	dl_proto = fuzzer_dict_init(RTLD_DEFAULT, proto);

	if (panic_action) {
		autofree = talloc_autofree_context();

		if (fr_fault_setup(autofree, panic_action, (*argv)[0]) < 0) {
			fr_perror("Failed initializing panic action");
			fr_exit_now(EXIT_FAILURE);
		}
	}

	init = true;

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	talloc_free(dict_dir_to_free);
	talloc_free(lib_dir_to_free);
#endif

	return 1;
}

static uint8_t encoded_data[65536];

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX *   ctx = talloc_init_const("fuzzer");
	fr_pair_list_t vps;
	void *decode_ctx = NULL;
	void *encode_ctx = NULL;
	fr_test_point_proto_decode_t *tp_decode = &XX_PROTOCOL_XX_tp_decode_proto;
	fr_test_point_proto_encode_t *tp_encode = &XX_PROTOCOL_XX_tp_encode_proto;

	fr_pair_list_init(&vps);
	if (!init) LLVMFuzzerInitialize(NULL, NULL);

	if (tp_decode->test_ctx && (tp_decode->test_ctx(&decode_ctx, NULL, dict, NULL) < 0)) {
		fr_perror("fuzzer: Failed initializing test point decode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	if (tp_encode->test_ctx && (tp_encode->test_ctx(&encode_ctx, NULL, dict, NULL) < 0)) {
		fr_perror("fuzzer: Failed initializing test point encode_ctx");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Decode the input, and print the resulting data if we
	 *	decoded it successfully.
	 *
	 *	If we have successfully decoded the data, then encode
	 *	it again, too.
	 */
	if (tp_decode->func(ctx, &vps, buf, len, decode_ctx) > 0) {
		PAIR_LIST_VERIFY_WITH_CTX(ctx, &vps);

		if (fr_debug_lvl > 3) fr_pair_list_debug(stderr, &vps);

		if (do_encode) (void) tp_encode->func(ctx, &vps, encoded_data, sizeof(encoded_data), encode_ctx);
	}

	talloc_free(decode_ctx);
	talloc_free(encode_ctx);
	talloc_free(ctx);

	/*
	 *	Clear error messages from the run.  Clearing these
	 *	keeps malloc/free balanced, which helps to avoid the
	 *	fuzzers leak heuristics from firing.
	 */
	fr_strerror_clear();

	return 0;
}
