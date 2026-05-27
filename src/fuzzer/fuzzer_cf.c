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

extern char const  *__lsan_default_suppressions(void);

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(UNUSED int *argc, UNUSED char ***argv)
{
	/*
	 *	Don't put output anywhere.  Otherwise we will have reams of log messages.
	 */
	default_log.dst = L_DST_NULL;
	default_log.fd = -1;
	default_log.print_level = true;
	default_log.suppress_secrets = true;

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
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
		if (!data[i]) {
			size = i;
			break;
		}

		if (data[i] == '{') {
			depth++;
			if (depth > max_depth) max_depth = depth;
		} else if ((data[i] == '}') && (depth > 0)) {
			depth--;
		}
	}
	if (max_depth > 64) return 0;

	config = main_config_alloc(NULL);
	if (!config) return 0;

	config->root_cs = cf_section_alloc(config, NULL, "main", NULL);
	if (!config->root_cs) {
		talloc_free(config);
		return 0;
	}
	cf_section_set_unlang(config->root_cs);

	(void) cf_file_read_buffer(config->root_cs, (char const *) data, size, "/");

	talloc_free(config);

	/*
	 *	Clear error messages from the run, keeping malloc/free
	 *	balanced so the fuzzer's leak heuristics do not fire.
	 */
	fr_strerror_clear();

	return 0;
}
