/*
 * unit_test_map.c	Map debugging tool.
 *
 * Version:	$Id$
 *
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
 *
 * @copyright 2015 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")


#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module.h>

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/base.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

#include <freeradius-devel/server/log.h>

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t unit_test_module_dict[];
fr_dict_autoload_t unit_test_module_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};


static NEVER_RETURNS void usage(char *argv[])
{
	fprintf(stderr, "usage: %s [OPTS] filename ...\n", argv[0]);
	fprintf(stderr, "  -d <raddb>         Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>       Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -x                 Debugging mode.\n");
	fprintf(stderr, "  -M                 Show program version information.\n");
	fprintf(stderr, "  -r <receipt_file>  Create the <receipt_file> as a 'success' exit.\n");

	fr_exit_now(EXIT_SUCCESS);
}

static int process_file(char const *filename)
{
	int		rcode;
	char const	*name1, *name2;
	CONF_SECTION	*cs;
	fr_map_list_t	list;
	map_t		*map = NULL;
	char		buffer[8192];

	main_config_t	*config;

	tmpl_rules_t	parse_rules = {
		.dict_def = dict_radius,
		.allow_foreign = true	/* Because we don't know what protocol we're operating with */
	};

	fr_map_list_init(&list);
	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	config = main_config_alloc(NULL);
	if (!config) {
		fprintf(stderr, "Failed allocating main config");
		return EXIT_FAILURE;
	}
	config->root_cs = cf_section_alloc(config, NULL, "main", NULL);
	if ((cf_file_read(config->root_cs, filename) < 0) || (cf_section_pass2(config->root_cs) < 0)) {
		fprintf(stderr, "unit_test_map: Failed parsing %s\n", filename);
		return EXIT_FAILURE;
	}

	main_config_name_set_default(config, "unit_test_map", false);

	/*
	 *	Always has to be an "update" section.
	 */
	cs = cf_section_find(config->root_cs, "update", CF_IDENT_ANY);
	if (!cs) {
		talloc_free(config->root_cs);
		return EXIT_FAILURE;
	}

	/*
	 *	Convert the update section to a list of maps.
	 */
	rcode = map_afrom_cs(cs, &list, cs, &parse_rules, &parse_rules, unlang_fixup_update, NULL, 128);
	if (rcode < 0) {
		cf_log_perr(cs, "map_afrom_cs failed");
		return EXIT_FAILURE; /* message already printed */
	}
	if (fr_dlist_empty(&list)) {
		cf_log_err(cs, "'update' sections cannot be empty");
		return EXIT_FAILURE;
	}

	buffer[0] = '\t';

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	/*
	 *	And print it all out.
	 */
	if (!name2) {
		printf("%s {\n", name1);
	} else {
		printf("%s %s {\n", name1, name2);
	}

	while ((map = fr_dlist_next(&list, map))) {
		map_print(&FR_SBUFF_OUT(buffer + 1, sizeof(buffer) - 1), map);
		puts(buffer);
	}
	printf("}\n");

	talloc_free(config->root_cs);
	talloc_free(config);

	return EXIT_SUCCESS;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	int			c, ret = EXIT_SUCCESS;
	char const		*raddb_dir = RADDBDIR;
	char const		*dict_dir = DICTDIR;
	fr_dict_t		*dict = NULL;
	char const		*receipt_file = NULL;

	TALLOC_CTX		*autofree;
	fr_dict_gctx_t const	*dict_gctx = NULL;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	autofree = talloc_autofree_context();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unit_test_map");
		fr_exit(EXIT_FAILURE);
	}
#else
	fr_disable_null_tracking_on_free(autofree);
#endif

	/*
	 *	Sync wallclock and cpu time so that we can find
	 *	uses of fr_time_[to|from]_* where
	 *	fr_unix_time_[to|from]_* should be used.
	 *
	 *	If the wallclock/cpu offset is 0, then both sets
	 *	of macros produce the same result.
	 */
	fr_time_start();

	while ((c = getopt(argc, argv, "d:D:xMhr:")) != -1) switch (c) {
		case 'd':
			raddb_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'x':
			fr_debug_lvl++;
			break;

		case 'M':
			talloc_enable_leak_report();
			break;

		case 'r':
			receipt_file = optarg;
			break;

		case 'h':
		default:
			usage(argv);
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (receipt_file && (fr_unlink(receipt_file) < 0)) {
		fr_perror("unit_test_map");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("unit_test_map");
		EXIT_WITH_FAILURE;
	}

	dict_gctx = fr_dict_global_ctx_init(autofree, dict_dir);
	if (!dict_gctx) {
		fr_perror("unit_test_map");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("unit_test_map");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Load the custom dictionary
	 */
	if (fr_dict_read(dict, raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_strerror_const_push("Failed to initialize the dictionaries");
		fr_perror("unit_test_map");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_autoload(unit_test_module_dict) < 0) {
		fr_perror("unit_test_map");
		EXIT_WITH_FAILURE;
	}

	if (argc < 2) {
		ret = process_file("-");

	} else {
		ret = process_file(argv[1]);
	}

	if (ret < 0) ret = 1; /* internal to Unix process return code */

cleanup:
	/*
	 *	Try really hard to free any allocated
	 *	memory, so we get clean talloc reports.
	 */
	xlat_free();

	/*
	 *	Free any autoload dictionaries
	 */
	if (fr_dict_autofree(unit_test_module_dict) < 0) {
		fr_perror("unit_test_map");
		ret = EXIT_FAILURE;
	}

	if (fr_dict_free(&dict, __FILE__) < 0) {
		fr_perror("unit_test_map");
		ret = EXIT_FAILURE;
	}

	if (fr_dict_global_ctx_free(dict_gctx) < 0) {
		fr_perror("unit_test_map");
		ret = EXIT_FAILURE;
	}

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fr_perror("unit_test_map");
		ret = EXIT_FAILURE;
	}

	return ret;
}
