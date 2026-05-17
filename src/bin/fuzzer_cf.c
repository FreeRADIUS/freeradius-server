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
 * @file src/bin/fuzzer_cf.c
 * @brief Functions to fuzz the FreeRADIUS config-file parser
 *
 * Targets cf_file_read() and the section/pair tokenisers it drives
 * (cf_file.c, cf_util.c, cf_parse.c). The full configuration grammar -
 * sections, pairs, quoting, line continuation, $INCLUDE / $-INCLUDE
 * resolution, operators, and xlat expansions - is exercised through
 * this single entry point.
 *
 * The harness writes each fuzzer input to a per-process file under the
 * system temporary directory because cf_file_read() is path-based and
 * resolves $INCLUDE relative to the directory of the file being parsed.
 * A pid-suffixed name keeps the harness safe under libFuzzer's -jobs=N.
 */
RCSID("$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static char fuzz_path[64];

int LLVMFuzzerInitialize(UNUSED int *argc, UNUSED char ***argv)
{
	/*
	 *	Each fuzzer worker (libFuzzer -jobs=N) gets its own pid,
	 *	so a pid-suffixed path avoids races between workers.
	 */
	snprintf(fuzz_path, sizeof(fuzz_path), "/tmp/fuzzer_cf_input.%d.conf",
		 (int) getpid());
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int		fd;
	main_config_t	*config;
	size_t		depth = 0, max_depth = 0;

	/*
	 *	cap input size: the parser is line-oriented and a
	 *	pathological input can cost a great deal of time without
	 *	exposing new states.
	 */
	if (size > 16 * 1024) return 0;

	/*
	 *	Pre-filter on brace nesting depth. The config parser
	 *	recurses via C function calls on '{'-introduced
	 *	sub-sections (parse_subrequest, parse_foreach,
	 *	parse_switch, etc., and cf_section_pass2 walking the
	 *	section tree). libFuzzer trivially discovers inputs of
	 *	the form "{{{{ ... }}}}" that exhaust the C stack without
	 *	revealing any new parser states. Real configs nest fewer
	 *	than ten levels deep; the cap is set generously here so
	 *	that any legitimate nesting still reaches the parser.
	 *
	 *	Quoting is intentionally ignored: a conservative count
	 *	can only over-reject, never under-reject, and the cost of
	 *	dropping a few well-formed inputs with '{' embedded in
	 *	strings is negligible compared with the cost of burning
	 *	every fuzz cycle on the same recursion failure.
	 */
	for (size_t i = 0; i < size; i++) {
		if (data[i] == '{') {
			depth++;
			if (depth > max_depth) max_depth = depth;
		} else if ((data[i] == '}') && (depth > 0)) {
			depth--;
		}
	}
	if (max_depth > 64) return 0;

	/*
	 *	cf_file_read() takes a path; mirror the input to disk.
	 */
	fd = open(fuzz_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) return 0;
	if (size && write(fd, data, size) != (ssize_t) size) {
		close(fd);
		unlink(fuzz_path);
		return 0;
	}
	close(fd);

	config = main_config_alloc(NULL);
	if (!config) {
		unlink(fuzz_path);
		return 0;
	}

	config->root_cs = cf_section_alloc(config, NULL, "main", NULL);
	if (!config->root_cs) {
		talloc_free(config);
		unlink(fuzz_path);
		return 0;
	}
	cf_section_set_unlang(config->root_cs);

	(void) cf_file_read(config->root_cs, fuzz_path, true);

	talloc_free(config);
	unlink(fuzz_path);

	/*
	 *	Clear error messages from the run, keeping malloc/free
	 *	balanced so the fuzzer's leak heuristics do not fire.
	 */
	fr_strerror_clear();

	return 0;
}
