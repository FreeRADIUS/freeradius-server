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
 * @copyright 2019 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/io/test_point.h>

/*
 *	Run from the source via:
 *
 *	FR_LIBRARY_PATH=./build/lib/ FR_LIBRARY_FUZZ_PROTOCOL=radius FR_DICTIONARY_DIR=./share/dictionary/ ./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer /path/to/corpus/directory/
 */

static bool init = false;
static void *decode_ctx = NULL;
static fr_test_point_proto_decode_t *tp = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(UNUSED int *argc, UNUSED char ***argv)
{
	dl_t *dl;
	dl_loader_t *dl_loader;
	char const *lib_dir = getenv("FR_LIBRARY_PATH");
	char const *proto = getenv("FR_LIBRARY_FUZZ_PROTOCOL");
	char const *dict_dir = getenv("FR_DICTIONARY_DIR");
	char buffer[1024];


	fprintf(stderr, "INITIALIZED\n");


	if (!dict_dir) dict_dir = DICTDIR;

	if (fr_dict_global_init(NULL, dict_dir) < 0) {
		fr_perror("dict_global");
		return 0;
	}

	if (!proto) {
		fprintf(stderr, "Failed to find FR_LIBRARY_FUZZ_PROTOCOL\n");
		exit(1);
	}

	dl_loader = dl_loader_init(NULL, lib_dir, NULL, 0, false);
	if (!dl_loader) {
		fprintf(stderr, "fuzzer: Failed initializing library loader: %s\n",
			fr_strerror());
		exit(1);
	}

	snprintf(buffer, sizeof(buffer), "libfreeradius-%s", proto);
	dl = dl_by_name(dl_loader, buffer, NULL, false);
	if (!dl) {
		fprintf(stderr, "fuzzer: Failed loading library %s: %s\n",
			buffer, fr_strerror());
		exit(1);
	}

	snprintf(buffer, sizeof(buffer), "%s_tp_decode_proto", proto);

	tp = dlsym(dl->handle, buffer);
	if (!tp) {
		fprintf(stderr, "fuzzer: Failed finding test point %s: %s\n",
			buffer, fr_strerror());
		exit(1);
	}

	if (tp->test_ctx(&decode_ctx, NULL) < 0) {
		fprintf(stderr, "fuzzer: Failed finding test point %s: %s\n",
			buffer, fr_strerror());
		exit(1);
	}

	init = true;

	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	if (!init) LLVMFuzzerInitialize(0, NULL);

	tp->func(decode_ctx, buf, len);

	return 0;
}
