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
 * @file src/main/fuzzer.c
 * @brief Functions to fuzz protocol decoding
 *
 * @copyright 2019 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

/*
 *	Run from the source directory via:
 *
 *	./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer_radius -D share/dictionary /path/to/corpus/directory/
 */

static bool			init = false;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static void exitHandler(void)
{
	dict_free();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char const		*dict_dir	= getenv("FR_DICTIONARY_DIR");
	char const		*debug_lvl_str	= getenv("FR_DEBUG_LVL");
	char const		*p;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	char			*dict_dir_to_free = NULL;
#endif

	if (!argc || !argv || !*argv) return -1; /* shut up clang scan */

	if (debug_lvl_str) fr_debug_lvl = atoi(debug_lvl_str);

	/*
	 *	Initialise the error stack _before_ we run any
	 *	tests so there's no chance of the memory
	 *	appearing as a leak the first time an error
	 *	is generated.
	 */
	fr_strerror_printf("fuzz"); /* allocate the pools */
	fr_strerror_printf(NULL); /* clears the message, leaves the pools */

	/*
	 *	Setup our own internal atexit handler
	 */
	if (atexit(exitHandler)) {
		fr_perror("fuzzer: Failed to register exit handler: %s", strerror(errno));
		exit(EXIT_FAILURE);
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
	}
#endif

	if (!dict_dir) dict_dir = DICTDIR;

	/*
	 *	When jobs=N is specified the fuzzer spawns worker processes via
	 *	a shell. We have removed any -D dictdir argument that were
	 *	supplied, so we pass it to our children via the environment.
	 */
	if (setenv("FR_DICTIONARY_DIR", dict_dir, 1)) {
		fprintf(stderr, "Failed to set FR_DICTIONARY_DIR env variable\n");
		exit(EXIT_FAILURE);
	}

	if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("fuzzer");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Disable hostname lookups, so we don't produce spurious DNS
	 *	queries, and there's no chance of spurious failures if
	 *	it takes a long time to get a response.
	 */
	fr_hostname_lookups = fr_dns_lookups = false;

	init = true;

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	talloc_free(dict_dir_to_free);
#endif

	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	RADIUS_PACKET		*packet;

	if (!init) LLVMFuzzerInitialize(NULL, NULL);

	packet = rad_alloc(NULL, false);

	memcpy(&packet->data, &buf, sizeof(buf)); /* const issues */
	packet->data_len = len;

	if (rad_packet_ok(packet, 0, NULL)) {
		(void) rad_decode(packet, NULL, "testing123");
		if (fr_debug_lvl > 3) vp_printlist(stdout, packet->vps);
	}

	packet->data = NULL;
	packet->data_len = 0;
	talloc_free(packet);

	/*
	 *	Clear error messages from the run.  Clearing these
	 *	keeps malloc/free balanced, which helps to avoid the
	 *	fuzzers leak heuristics from firing.
	 */
	fr_strerror_printf(NULL);

	return 0;
}
