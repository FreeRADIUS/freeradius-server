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
 * @file radict.c
 * @brief Utility to print attribute data in CSV format
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/autoconf.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdbool.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <assert.h>

static fr_dict_t *dicts[255];
static fr_dict_t **dict_end = dicts;

DIAG_OFF(unused-macros)
#define DEBUG2(fmt, ...)	if (fr_log_fp && (fr_debug_lvl > 2)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#define DEBUG(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 1)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#define INFO(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 0)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
DIAG_ON(unused-macros)

static void usage(void)
{
	fprintf(stderr, "usage: radict [OPTS] <attribute> [attribute...]\n");
	fprintf(stderr, "  -E               Export dictionary definitions.\n");
	fprintf(stderr, "  -D <dictdir>     Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -x               Debugging mode.\n");
	fprintf(stderr, "");
	fprintf(stderr, "Very simple interface to extract attribute definitions from FreeRADIUS dictionaries\n");
}

static int load_dicts(TALLOC_CTX *ctx, char const *dict_dir)
{
	DIR		*dir;
	struct dirent	*dp;

	dir = opendir(dict_dir);
	if (!dir) {
		fr_strerror_printf("Failed opening \"%s\": %s", dict_dir, fr_syserror(errno));
		return -1;
	}

	while ((dp = readdir(dir)) != NULL) {
		struct stat stat_buff;
		char *file_str;

		if (dp->d_name[0] == '.') continue;

		file_str = talloc_asprintf(NULL, "%s/%s", dict_dir, dp->d_name);

		if (stat(file_str, &stat_buff) == -1) {
			fr_strerror_printf("Failed stating file \"%s\": %s", file_str, fr_syserror(errno));
		error:
			closedir(dir);
			talloc_free(file_str);
			return -1;
		}

		/*
		 *	Only process directories
		 */
		if ((stat_buff.st_mode & S_IFMT) == S_IFDIR) {
			char		*dict_file;
			struct stat	dict_stat_buff;
			int ret;

			dict_file = talloc_asprintf(NULL, "%s/dictionary", file_str);
			ret = stat(dict_file, &dict_stat_buff);
			talloc_free(dict_file);

			/*
			 *	If the directory contains a dictionary file,
			 *	load it as a dictionary.
			 */
			if (ret == 0) {
				if (dict_end >= (dicts + (sizeof(dicts) / sizeof(*dicts)))) {
					fr_strerror_printf("Reached maximum number of dictionaries");
					goto error;
				}
				INFO("Loading dictionary: %s/%s", dict_dir, dp->d_name);
				if (fr_dict_protocol_afrom_file(dict_end++, dp->d_name) < 0) goto error;
			/*
			 *	...otherwise recurse to process sub-protocols (maybe?)
			 */
			} else {
				if (load_dicts(ctx, file_str) < 0) goto error;
			}
		}
		talloc_free(file_str);
	}
	closedir(dir);

	return 0;
}

static void da_print_info_td(fr_dict_t const *dict, fr_dict_attr_t const *da)
{
	char oid_str[512];
	char flags[256];

	(void)fr_dict_print_attr_oid(oid_str, sizeof(oid_str), NULL, da);

	fr_dict_snprint_flags(flags, sizeof(flags), &da->flags);

	/* Protocol Name Type */
	printf("%s\t%s\t%s\t%s\t%s\n", fr_dict_root(dict)->name, oid_str, da->name,
	       fr_int2str(dict_attr_types, da->type, "?Unknown?"), flags);
}

static void _fr_dict_export(uint64_t *count, uintptr_t *low, uintptr_t *high, fr_dict_attr_t const *da, unsigned int lvl)
{
	unsigned int		i;
	size_t			len;
	fr_dict_attr_t const	*p;
	char			flags[256];

	fr_dict_snprint_flags(flags, sizeof(flags), &da->flags);

	/*
	 *	Root attributes are allocated outside of the pool
	 *	so it's not helpful to include them in the calculation.
	 */
	if (!da->flags.is_root) {
		if (low && ((uintptr_t)da < *low)) {
			*low = (uintptr_t)da;
		}
		if (high && ((uintptr_t)da > *high)) {
			*high = (uintptr_t)da;
		}

		da_print_info_td(fr_dict_by_da(da), da);
	}

	if (count) (*count)++;

	len = talloc_array_length(da->children);
	for (i = 0; i < len; i++) {
		for (p = da->children[i]; p; p = p->next) {
			_fr_dict_export(count, low, high, p, lvl + 1);
		}
	}
}

static void fr_dict_export(uint64_t *count, uintptr_t *low, uintptr_t *high, fr_dict_t *dict)
{
	if (count) *count = 0;
	if (low) *low = UINTPTR_MAX;
	if (high) *high = 0;

	_fr_dict_export(count, low, high, fr_dict_root(dict), 0);
}

int main(int argc, char *argv[])
{
	char const	*dict_dir = DICTDIR;
	char		c;
	int		ret = 0;
	bool		found = false;
	bool		export = false;

	TALLOC_CTX	*autofree = talloc_autofree_context();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radict");
		exit(EXIT_FAILURE);
	}
#endif

	fr_debug_lvl = 1;

	while ((c = getopt(argc, argv, "ED:xh")) != EOF) switch (c) {
		case 'E':
			export = true;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'x':
			fr_log_fp = stdout;
			fr_debug_lvl++;
			break;

		case 'h':
		default:
			usage();
			goto finish;
	}
	argc -= optind;
	argv += optind;

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radict");
		ret = 1;
		goto finish;
	}

	if (fr_dict_global_init(autofree, dict_dir) < 0) {
		fr_perror("radict");
		ret = 1;
		goto finish;
	}

	INFO("Loading dictionary: %s/%s", dict_dir, FR_DICTIONARY_FILE);

	if (fr_dict_internal_afrom_file(dict_end++, NULL) < 0) {
		fr_perror("radict");
		ret = 1;
		goto finish;
	}

	if (load_dicts(autofree, dict_dir) < 0) {
		fr_perror("radict");
		ret = 1;
		goto finish;
	}

	if (dict_end == dicts) {
		fr_perror("radict: No dictionaries loaded");
		ret = 1;
		goto finish;
	}

	if (export) {
		fr_dict_t	**dict_p = dicts;

		do {
			uint64_t	count;
			uintptr_t	high;
			uintptr_t	low;

			fr_dict_export(&count, &low, &high, *dict_p);
			DEBUG2("Attribute count %" PRIu64, count);
			DEBUG2("Memory allocd %zu (bytes)", talloc_total_size(*dict_p));
			DEBUG2("Memory spread %zu (bytes)", (high - low));
		} while (++dict_p < dict_end);
	}

	while (argc-- > 0) {
		char			*attr;
		fr_dict_attr_t const	*da;
		fr_dict_t		**dict_p = dicts;

		attr = *argv++;


		/*
		 *	Loop through all the dicts.  An attribute may
		 *	exist in multiple dictionaries.
		 */
		do {
			DEBUG2("Looking for \"%s\" in dict \"%s\"", attr, fr_dict_root(*dict_p)->name);

			da = fr_dict_attr_by_name(*dict_p, attr);
			if (da) {
				da_print_info_td(*dict_p, da);
				found = true;
			}
		} while (++dict_p < dict_end);
	}

finish:
	return found ? ret : 64;
}
