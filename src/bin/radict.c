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
 * @brief Utility to print attribute data in tab delimited format
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/dict_priv.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdbool.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

typedef enum {
	RADICT_OUT_FANCY = 1,
	RADICT_OUT_CSV
} radict_out_t;

static fr_dict_t *dicts[255];
static bool print_values = false;
static bool print_headers = false;
static bool print_recursive = false;
static radict_out_t output_format = RADICT_OUT_FANCY;
static fr_dict_t **dict_end = dicts;

DIAG_OFF(unused-macros)
#define DEBUG2(fmt, ...)	if (fr_log_fp && (fr_debug_lvl > 2)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#define DEBUG(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 1)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#define INFO(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 0)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
DIAG_ON(unused-macros)

static void usage(void)
{
	fprintf(stderr, "usage: radict [OPTS] <attribute> [attribute...]\n");
	fprintf(stderr, "  -A               Export aliases.\n");
	fprintf(stderr, "  -c               Print out in CSV format.\n");
	fprintf(stderr, "  -D <dictdir>     Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -f               Export dictionary definitions in the normal dictionary format\n");
	fprintf(stderr, "  -E               Export dictionary definitions.\n");
	fprintf(stderr, "  -h               Print help text.\n");
	fprintf(stderr, "  -H               Show the headers of each field.\n");
	fprintf(stderr, "  -p <protocol>    Set protocol by name\n");
	fprintf(stderr, "  -r               Write out attributes recursively.\n");
	fprintf(stderr, "  -V               Write out all attribute values.\n");
	fprintf(stderr, "  -x               Debugging mode.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Very simple interface to extract attribute definitions from FreeRADIUS dictionaries\n");
}

static int load_dicts(char const *dict_dir, char const *protocol)
{
	int		loaded = 0;
	DIR		*dir;
	struct dirent	*dp;

	INFO("Reading directory %s", dict_dir);

	dir = opendir(dict_dir);
	if (!dir) {
		fr_strerror_printf("Failed opening \"%s\": %s", dict_dir, fr_syserror(errno));
		return -1;
	}

	while ((dp = readdir(dir)) != NULL) {
		struct stat stat_buff;
		char *file_str;

		if (dp->d_name[0] == '.') continue;

		/*
		 *	We only want to load one...
		 */
		if (protocol && (strcmp(dp->d_name, protocol) != 0)) continue;

		/*
		 *	Skip the internal FreeRADIUS dictionary.
		 */
		if (strcmp(dp->d_name, "freeradius") == 0) continue;

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
				if (dict_end >= (dicts + (NUM_ELEMENTS(dicts)))) {
					fr_strerror_const("Reached maximum number of dictionaries");
					goto error;
				}

				INFO("Loading dictionary: %s/dictionary", file_str);
				if (fr_dict_protocol_afrom_file(dict_end, dp->d_name, NULL, __FILE__) < 0) {
					goto error;
				}
				dict_end++;
				loaded++;
			}

			/*
			 *	For now, don't do sub-protocols.
			 */
		}
		talloc_free(file_str);
	}
	closedir(dir);

	if (!loaded) {
		if (!protocol) {
			fr_strerror_printf("Failed to load any dictionaries");
		} else {
			fr_strerror_printf("Failed to load dictionary for protocol %s", protocol);
		}

		return -1;
	}

	return 0;
}

static const char *spaces = "                                                                                ";

static void da_print_info_td(fr_dict_t const *dict, fr_dict_attr_t const *da, int depth)
{
	char 			oid_str[512];
	char			flags[256];
	fr_hash_iter_t		iter;
	fr_dict_enum_value_t	*enumv;
	fr_sbuff_t		old_str_sbuff = FR_SBUFF_OUT(oid_str, sizeof(oid_str));
	fr_sbuff_t		flags_sbuff = FR_SBUFF_OUT(flags, sizeof(flags));

	char const		*type;
	fr_dict_attr_t const	*child;
	fr_hash_table_t		*namespace;

	if (fr_dict_attr_oid_print(&old_str_sbuff, NULL, da, false) <= 0) {
		fr_strerror_printf("OID string too long");
		fr_exit(EXIT_FAILURE);
	}

	fr_dict_attr_flags_print(&flags_sbuff, dict, da->type, &da->flags);

	if (!da->flags.is_alias) {
		type = fr_type_to_str(da->type);
	} else {
		fr_assert(da->type == FR_TYPE_VOID);
		type = "ALIAS";
	}

	printf("%.*s", depth, spaces);

	/* Protocol Name Type */

	switch(output_format) {
		case RADICT_OUT_CSV:
			printf("%s,%s,%s,%d,%s,%s\n",
			       depth == 0 ? fr_dict_root(dict)->name : "",
			       fr_sbuff_start(&old_str_sbuff),
			       da->name,
			       da->attr,
			       type,
			       fr_sbuff_start(&flags_sbuff));
			break;

		case RADICT_OUT_FANCY:
		default:
			printf("%s\t%s\t%s\t%d\t%s\t%s\n",
			       depth == 0 ? fr_dict_root(dict)->name : "",
			       fr_sbuff_start(&old_str_sbuff),
			       da->name,
			       da->attr,
			       type,
			       fr_sbuff_start(&flags_sbuff));
	}

	if (print_values) {
		fr_dict_attr_ext_enumv_t	*ext;

		ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
		if (!ext || !ext->value_by_name) return;

		for (enumv = fr_hash_table_iter_init(ext->value_by_name, &iter);
		     enumv;
		     enumv = fr_hash_table_iter_next(ext->value_by_name, &iter)) {
		     	char *str;

			switch(output_format) {
				case RADICT_OUT_CSV:
					str = fr_asprintf(NULL, "%s,%s,%s,%d,%s,%s,%s,%pV",
								depth == 0 ? fr_dict_root(dict)->name : "",
								fr_sbuff_start(&old_str_sbuff),
								da->name,
								da->attr,
								type,
								fr_sbuff_start(&flags_sbuff),
								enumv->name,
								enumv->value);
					break;

				case RADICT_OUT_FANCY:
				default:
					str = fr_asprintf(NULL, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%pV",
								depth == 0 ? fr_dict_root(dict)->name : "",
								fr_sbuff_start(&old_str_sbuff),
								da->name,
								da->attr,
								type,
								fr_sbuff_start(&flags_sbuff),
								enumv->name,
								enumv->value);
			}

			printf("%.*s%s\n", depth, spaces, str);
			talloc_free(str);
		}
	}

	/*
	 *	Print definitions recursively.
	 */
	if (!print_recursive || !fr_type_is_structural(da->type)) return;

	namespace = dict_attr_namespace(da);
	fr_assert(namespace != NULL);

	for (child = fr_hash_table_iter_init(namespace, &iter);
	     child != NULL;
	     child = fr_hash_table_iter_next(namespace, &iter)) {
		da_print_info_td(dict, child, depth + 1);
	}
}

static void _raddict_export(fr_dict_t const *dict, uint64_t *count, uintptr_t *low, uintptr_t *high, fr_dict_attr_t const *da, unsigned int lvl)
{
	unsigned int		i;
	size_t			len;
	fr_dict_attr_t const	*p;
	char			flags[256];
	fr_dict_attr_t const	**children;

	fr_dict_attr_flags_print(&FR_SBUFF_OUT(flags, sizeof(flags)), dict, da->type, &da->flags);

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

		da_print_info_td(fr_dict_by_da(da), da, 0);
	}

	if (count) (*count)++;

	/*
	 *	Todo - Should be fixed to use attribute walking API
	 */
	children = dict_attr_children(da);
	if (children) {
		len = talloc_array_length(children);
		for (i = 0; i < len; i++) {
			for (p = children[i]; p; p = p->next) {
				_raddict_export(dict, count, low, high, p, lvl + 1);
			}
		}
	}
}

static void raddict_export(uint64_t *count, uintptr_t *low, uintptr_t *high, fr_dict_t *dict)
{
	if (count) *count = 0;
	if (low) *low = UINTPTR_MAX;
	if (high) *high = 0;

	_raddict_export(dict, count, low, high, fr_dict_root(dict), 0);
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	char const		*dict_dir = DICTDIR;
	int			c;
	int			ret = 0;
	bool			found = false;
	bool			export = false;
	bool			file_export = false;
	bool			alias = false;
	char const		*protocol = NULL;

	TALLOC_CTX		*autofree;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	autofree = talloc_autofree_context();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radict - Fault setup");
		fr_exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	fr_debug_lvl = 1;
	fr_log_fp = stdout;

	while ((c = getopt(argc, argv, "AcfED:p:rVxhH")) != -1) switch (c) {
		case 'A':
			alias = true;
			break;

		case 'c':
			output_format = RADICT_OUT_CSV;
			break;

		case 'H':
			print_headers = true;
			break;

		case 'f':
			file_export = true;
			break;

		case 'E':
			export = true;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'p':
			protocol = optarg;
			break;

		case 'r':
			print_recursive = true;
			break;

		case 'V':
			print_values = true;
			break;

		case 'x':
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
		fr_perror("radict - library mismatch");
		ret = 1;
		goto finish;
	}

	if (!fr_dict_global_ctx_init(NULL, true, dict_dir)) {
		fr_perror("radict - Global context init failed");
		ret = 1;
		goto finish;
	}

	INFO("Loading dictionary: %s/%s", dict_dir, FR_DICTIONARY_FILE);

	if (fr_dict_internal_afrom_file(dict_end++, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("radict - Loading internal dictionary failed");
		ret = 1;
		goto finish;
	}

	/*
	 *	Don't emit spurious errors...
	 */
	fr_strerror_clear();
	if (load_dicts(dict_dir, protocol) < 0) {
		fr_perror("radict - Loading dictionaries failed");
		ret = 1;
		goto finish;
	}

	if (dict_end == dicts) {
		fr_perror("radict - No dictionaries loaded");
		ret = 1;

	}

	if (print_headers) switch(output_format) {
		case RADICT_OUT_CSV:
			printf("Dictionary,OID,Attribute,ID,Type,Flags\n");
			break;

		case RADICT_OUT_FANCY:
		default:
			printf("Dictionary\tOID\tAttribute\tID\tType\tFlags\n");
	}

	if (file_export) {
		fr_dict_t	**dict_p = dicts;

		do {
			if (protocol && (strcasecmp(fr_dict_root(*dict_p)->name, protocol) == 0)) {
				fr_dict_export(fr_log_fp, *dict_p);
			}
		} while (++dict_p < dict_end);
	}

	if (export) {
		fr_dict_t	**dict_p = dicts;

		do {
			uint64_t	count;
			uintptr_t	high;
			uintptr_t	low;

			raddict_export(&count, &low, &high, *dict_p);
			DEBUG2("Attribute count %" PRIu64, count);
			DEBUG2("Memory allocd %zu (bytes)", talloc_total_size(*dict_p));
			DEBUG2("Memory spread %zu (bytes)", (size_t) (high - low));
		} while (++dict_p < dict_end);

		goto finish;
	}

	if (alias) {
		fr_dict_t	**dict_p = dicts;

		do {
			if (protocol && (strcasecmp(fr_dict_root(*dict_p)->name, protocol) == 0)) {
				fr_dict_alias_export(fr_log_fp, fr_dict_root(*dict_p));
			}
		} while (++dict_p < dict_end);

		goto finish;
	}

	if (argc == 0) {
		fprintf(stderr, "Missing attribute argument\n");
		fr_exit(EXIT_FAILURE);
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

			da = fr_dict_attr_by_oid(NULL, fr_dict_root(*dict_p), attr);
			if (da) {
				da_print_info_td(*dict_p, da, 0);
				found = true;
			} else {
				fprintf(stderr, "Dictionary %s does not contain attribute %s\n",
					fr_dict_root(*dict_p)->name, attr);
			}
		} while (++dict_p < dict_end);
	}

	if (!found) ret = 64;

finish:
	/*
	 *	Release our references on all the dicts
	 *	we loaded.
	 */
	{
		fr_dict_t	**dict_p = dicts;

		do {
			fr_dict_free(dict_p, __FILE__);
		} while (++dict_p < dict_end);
	}
	if (talloc_free(autofree) < 0) fr_perror("radict - Error freeing dictionaries");

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	return ret;
}
