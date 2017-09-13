/*
 * radattr.c	Map debugging tool.
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
#include <freeradius-devel/modcall.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

#include <freeradius-devel/log.h>

#include <sys/wait.h>

/* Linker hacks */

#ifdef HAVE_PTHREAD_H
pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}
#endif

rlm_rcode_t indexed_modcall(UNUSED rlm_components_t comp, UNUSED int idx, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

char const *get_radius_dir(void)
{
	return NULL;
}

module_instance_t *module_instantiate(UNUSED CONF_SECTION *modules, UNUSED char const *askedname)
{
	return NULL;
}

module_instance_t *module_instantiate_method(UNUSED CONF_SECTION *modules, UNUSED char const *name, UNUSED rlm_components_t *method)
{
	return NULL;
}

/* Linker hacks */

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: map_unit [OPTS] filename ...\n");
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
	CONF_SECTION *cs, *main_cs;
	vp_map_t *head, *map;
	char buffer[8192];

	main_cs = cf_section_alloc(NULL, "main", NULL);
	if (cf_file_read(main_cs, filename) < 0) {
		fprintf(stderr, "map_unit: Failed parsing %s\n",
			filename);
		exit(1);
	}

	/*
	 *	Always has to be an "update" section.
	 */
	cs = cf_section_sub_find(main_cs, "update");
	if (!cs) {
		talloc_free(main_cs);
		return -1;
	}

	/*
	 *	Convert the update section to a list of maps.
	 */
	rcode = map_afrom_cs(&head, cs, PAIR_LIST_REQUEST, PAIR_LIST_REQUEST, modcall_fixup_update, NULL, 128);
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
		map_prints(buffer + 1, sizeof(buffer) - 1, map);
		puts(buffer);
	}
	printf("}\n");

	talloc_free(main_cs);
	return 0;
}

int main(int argc, char *argv[])
{
	int c, rcode = 0;
	bool report = false;
	char const *radius_dir = RADDBDIR;
	char const *dict_dir = DICTDIR;

	cf_new_escape = true;	/* fix the tests */

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radattr");
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
		fr_perror("radattr");
		return 1;
	}

	if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("radattr");
		return 1;
	}

	if (dict_read(radius_dir, RADIUS_DICTIONARY) == -1) {
		fr_perror("radattr");
		return 1;
	}

	if (argc < 2) {
		rcode = process_file("-");

	} else {
		rcode = process_file(argv[1]);
	}

	if (report) {
		dict_free();
		fr_log_talloc_report(NULL);
	}

	if (rcode < 0) rcode = 1; /* internal to Unix process return code */

	return rcode;
}
