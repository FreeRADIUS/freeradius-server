/*
 * unit_test_attribute.c	Map debugging tool.
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
 * Copyright 2015  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <freeradius-devel/conf.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

#include <freeradius-devel/log.h>

/* Linker hacks */
char const *get_radius_dir(void)
{
	return NULL;
}

module_instance_t *module_find_with_method(UNUSED rlm_components_t *method,
					   UNUSED CONF_SECTION *modules, UNUSED char const *name)
{
	return NULL;
}

main_config_t		main_config;				//!< Main server configuration.

void *module_thread_instance_find(UNUSED void *inst)
{
	return NULL;
}

/* Linker hacks */

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: unit_test_map [OPTS] filename ...\n");
	fprintf(stderr, "  -d <raddb>             Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -O <output_dir>	  Set output directory\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");
	fprintf(stderr, "  -M                     Show program version information.\n");

	exit(1);
}

static int process_file(char const *filename)
{
	int rcode;
	char const *name1, *name2;
	CONF_SECTION *cs;
	vp_map_t *head, *map;
	char buffer[8192];

	memset(&main_config, 0, sizeof(main_config));

	main_config.config = cf_section_alloc(NULL, "main", NULL);
	if (cf_file_read(main_config.config, filename) < 0) {
		fprintf(stderr, "unit_test_map: Failed parsing %s\n",
			filename);
		exit(1);
	}

	/*
	 *	Always has to be an "update" section.
	 */
	cs = cf_subsection_find(main_config.config, "update");
	if (!cs) {
		talloc_free(main_config.config);
		return -1;
	}

	/*
	 *	Convert the update section to a list of maps.
	 */
	rcode = map_afrom_cs(&head, cs, PAIR_LIST_REQUEST, PAIR_LIST_REQUEST, unlang_fixup_update, NULL, 128);
	if (rcode < 0) return -1; /* message already printed */
	if (!head) {
		cf_log_err_cs(cs, "'update' sections cannot be empty");
		return -1;
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

	for (map = head; map != NULL; map = map->next) {
		map_snprint(buffer + 1, sizeof(buffer) - 1, map);
		puts(buffer);
	}
	printf("}\n");

	talloc_free(main_config.config);
	return 0;
}

int main(int argc, char *argv[])
{
	int			c, rcode = 0;
	bool			report = false;
	char const		*radius_dir = RADDBDIR;
	char const		*dict_dir = DICTDIR;
	fr_dict_t		*dict = NULL;

	TALLOC_CTX		*autofree = talloc_init("main");

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unit_test_attribute");
		exit(EXIT_FAILURE);
	}
#endif

	while ((c = getopt(argc, argv, "d:D:xMh")) != EOF) switch (c) {
		case 'd':
			radius_dir = optarg;
			break;
		case 'D':
			dict_dir = optarg;
			break;
		case 'x':
			fr_debug_lvl++;
			rad_debug_lvl = fr_debug_lvl;
			break;
		case 'M':
			report = true;
			break;
		case 'h':
		default:
			usage();
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("unit_test_attribute");
		exit(1);
	}

	if (fr_dict_from_file(NULL, &dict, dict_dir, FR_DICTIONARY_FILE, "radius") < 0) {
		fr_perror("unit_test_attribute");
		exit(1);
	}

	if (fr_dict_read(dict, radius_dir, FR_DICTIONARY_FILE) == -1) {
		fr_perror("unit_test_attribute");
		exit(1);
	}

	if (argc < 2) {
		rcode = process_file("-");

	} else {
		rcode = process_file(argv[1]);
	}

	if (report) {
		talloc_free(dict);
		fr_log_talloc_report(NULL);
	}

	if (rcode < 0) rcode = 1; /* internal to Unix process return code */

	talloc_free(autofree);

	return rcode;
}
