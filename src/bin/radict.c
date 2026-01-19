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
	RADICT_OUT_INVALID = 0,
	RADICT_OUT_FANCY,
	RADICT_OUT_CSV,
	RADICT_OUT_DICT,
	RADICT_OUT_STRUCT,
	RADICT_OUT_STATS_LINK,
	RADICT_OUT_BASE_C_DA_DEF,
	RADICT_OUT_ATTR_AUTOLOAD,
	RADICT_OUT_STATS_H,
} radict_out_t;

static fr_dict_t *dicts[255];
static bool print_values = false;
static bool print_headers = false;
static bool print_recursive = false;
static char const *mib = NULL;
static char const *parent_oid = NULL;
static radict_out_t output_format = RADICT_OUT_FANCY;
static fr_dict_t **dict_end = dicts;

DIAG_OFF(unused-macros)
#define DEBUG2(fmt, ...)	if (fr_log_fp && (fr_debug_lvl > 2)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#define DEBUG(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 1)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#define INFO(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 0)) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
DIAG_ON(unused-macros)

static void usage(void)
{
	fprintf(stderr, "usage: radict [OPTS] [attribute...]\n");
	fprintf(stderr, "  -A               Export aliases.\n");
	fprintf(stderr, "  -c               Print out in CSV format.\n");
	fprintf(stderr, "  -D <dictdir>     Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -f               Export dictionary definitions in the normal dictionary format\n");
	fprintf(stderr, "  -F <format>      Set output format.  Use 'csv', 'full', or 'dictionary'\n");
	fprintf(stderr, "  -E               Export dictionary definitions.\n");
	fprintf(stderr, "  -h               Print help text.\n");
	fprintf(stderr, "  -H               Show the headers of each field.\n");
	fprintf(stderr, "  -M <name>        Mangle names for MIB, and set MIB root.\n");
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

	DEBUG("Reading directory %s", dict_dir);

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

				DEBUG("Loading dictionary: %s/dictionary", file_str);
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

static void da_print_info(fr_dict_t const *dict, fr_dict_attr_t const *da, int depth)
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
		da_print_info(dict, child, depth + 1);
	}
}

static char const *type_to_c_type[] = {
	[FR_TYPE_STRING]			= "char",
	[FR_TYPE_OCTETS]			= "uint8_t",

	[FR_TYPE_IPV4_ADDR]			= "struct in_addr",
	[FR_TYPE_IPV6_ADDR]			= "struct in6_addr",

//	[FR_TYPE_IFID]				= "fr_ifid_t",
//	[FR_TYPE_ETHERNET]			= "fr_ethernet_t",

	[FR_TYPE_UINT8]				= "uint8_t",
	[FR_TYPE_UINT16]			= "uint16_t",
	[FR_TYPE_UINT32]			= "uint32_t",
	[FR_TYPE_UINT64]			= "uint64_t",

	[FR_TYPE_INT8]				= "int8_t",
	[FR_TYPE_INT16]				= "int16_t",
	[FR_TYPE_INT32]				= "int32_t",
	[FR_TYPE_INT64]				= "int64_t",

	[FR_TYPE_DATE]				= "fr_time_t",
	[FR_TYPE_TIME_DELTA]		       	= "fr_time_delta_t",

	[FR_TYPE_MAX]				= 0	//!< Ensure array covers all types.
};

static char const *length_to_c_type[] = {
	[2] = "uint16_t",
	[4] = "uint32_t",
	[8] = "uint64_t",
};

static void da_normalize_name(fr_dict_attr_t const *da, char buffer[static FR_DICT_ATTR_MAX_NAME_LEN + 1])
{
	char const *start = da->name;
	char const *p;
	char	*q;
	bool	mangle = false;

	/*
	 *	The RADIUS MIBs have lots of repetition.  So we do some simple mangling of the names to make
	 *	them easier to understand.
	 */
	if (mib && da->parent) {
		size_t	len;

		len = strlen(da->parent->name);
       
		/*
		 *	"radiusAuthServer" and "radiusAuthServTotalAccessRejects"
		 *	to "total_access_rejects"
		 *
		 *	Otherwise "radiusAuthServer" in the "RADIUS" dictionary, to "auth_server"
		 */
		mangle = (strncmp(da->parent->name, da->name, len) == 0);
		if (!mangle) {
			fr_dict_attr_t const *root = fr_dict_root(da->dict);

			len = strlen(root->name);
			mangle = (strncasecmp(root->name, da->name, len) == 0);
		}

		if (mangle) start += len;
	}

	q = buffer;

	for (p = start; *p != '\0'; p++) {
		if ((*p >= '0') && (*p <= '9')) {
			*q++ = *p;
			continue;
		}

		if (islower((unsigned int) *p)) {
			*q++ = *p;
			continue;
		}

		if (isupper((unsigned int) *p)) {
			if (mangle && (p > start)) {
				*(q++) = '_';
			}

			*q++ = tolower((unsigned int)*p);
			continue;
		}

		*q++ = '_';
	}

	*q = '\0';
}

static void da_print_name(FILE *fp, fr_dict_attr_t const *da)
{
	char buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	da_normalize_name(da, buffer);
	fprintf(fp, "%s", buffer);
}

static const bool type_allowed[FR_TYPE_MAX] = {
	[FR_TYPE_STRING] = true,
	[FR_TYPE_OCTETS] = true,

	[FR_TYPE_UINT16] = true,
	[FR_TYPE_UINT32] = true,
	[FR_TYPE_UINT64] = true,

	[FR_TYPE_IPV4_ADDR] = true,
	[FR_TYPE_IPV6_ADDR] = true,

	[FR_TYPE_DATE] = true,
	[FR_TYPE_TIME_DELTA] = true,

};

static bool children_ok(fr_dict_attr_t const *parent)
{
	int i;
	fr_dict_attr_t const *da;

	for (i = 1; (da = fr_dict_attr_child_by_num(parent, i)) != NULL; i++) {
		if (!type_allowed[da->type]) return false;
	}

	return true;
}

#define CHECK_TYPE(_parent) \
do { \
	if ((parent->type != FR_TYPE_STRUCT) && (parent->type != FR_TYPE_TLV)) { \
		fprintf(stderr, "%s is not a struct or tlv\n", parent->name); \
		return; \
	} \
	if (!children_ok(parent)) fr_exit(EXIT_FAILURE); \
} while (0)

/** Print structures and mappings, mainly for statistics.
 */
static void da_print_struct(FILE *fp, fr_dict_attr_t const *parent)
{
	int i;
	fr_dict_attr_t const *da;

	CHECK_TYPE(parent);

	/*
	 *	@todo - print full OID path and filename?
	 */
	fprintf(fp, "/*\n *\t%s\n */\n", parent->name);
	fprintf(fp, "typedef struct {\n");

	for (i = 1; (da = fr_dict_attr_child_by_num(parent, i)) != NULL; i++) {
		unsigned int length = 0;

		/*
		 *	@todo - if the last field is a union, print out the union definitions first.
		 */
		fr_assert(!da->flags.array);

		if (da_is_bit_field(da)) {
			/*
			 *	@todo - this is all big endian.  for little endian, we print out the bytes in
			 *	order, but the bits in each byte are reversed.  Likely the easiest way to do
			 *	this is via a separate function that we call.  But this shouldn't be necessary
			 *	for statistics structures, as they shouldn't contain bitfields.
			 */
			fprintf(fp, "\tunsigned int : %u\t", da->flags.length);

		} else switch (da->type) {
			case FR_TYPE_STRING:
				if ((parent->type == FR_TYPE_TLV) && !da->flags.length) {
					fprintf(fp, "\t%s\t*", type_to_c_type[da->type]);
					break;
				}
				FALL_THROUGH;

			case FR_TYPE_OCTETS:
				fr_assert(da->flags.length > 0);
				length = da->flags.length;
				fprintf(fp, "\t%s\t", type_to_c_type[da->type]);
				break;

			case FR_TYPE_DATE:
				fr_assert(da->flags.length <= 8);
				fr_assert(length_to_c_type[da->flags.length] != NULL);
				fprintf(fp, "\t%s\t", length_to_c_type[da->flags.length]);
				break;

			default:
				fr_assert(type_to_c_type[da->type] != NULL);
				fprintf(fp, "\t%s\t", type_to_c_type[da->type]);
				break;
		}

		da_print_name(fp, da);

		if (length) {
			fprintf(fp, "[%u]", length);
		}

		fprintf(fp, ";\n");
	}

	fprintf(fp, "} ");

	fprintf(fp, "fr_stats_");
	da_print_name(fp, fr_dict_root(parent->dict));
	fprintf(fp, "_");
	da_print_name(fp, parent);
	fprintf(fp, "_t;\n");
}

static void da_print_base_c_da_def(FILE *fp, fr_dict_attr_t const *parent)
{
	int i;
	fr_dict_attr_t const *da;
	char parent_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	CHECK_TYPE(parent);

	da_normalize_name(parent, parent_name);

	fprintf(fp, "static fr_dict_attr_t const *attr_%s;\n", parent_name);

	for (i = 1; (da = fr_dict_attr_child_by_num(parent, i)) != NULL; i++) {
		fprintf(fp, "static fr_dict_attr_t const *attr_%s_", parent_name);
		da_print_name(fp, da);
		fprintf(fp, ";\n");
	}

	fprintf(fp, "\n\n");
}


/** Map data types to enum names representing those types
 */
#define ENUM_NAME(_x) [_x] = STRINGIFY(_x)

static char const *fr_type_to_enum_name[] = {
	ENUM_NAME(FR_TYPE_NULL),
	ENUM_NAME(FR_TYPE_STRING),
	ENUM_NAME(FR_TYPE_OCTETS),

	ENUM_NAME(FR_TYPE_IPV4_ADDR),
	ENUM_NAME(FR_TYPE_IPV4_PREFIX),
	ENUM_NAME(FR_TYPE_IPV6_ADDR),
	ENUM_NAME(FR_TYPE_IPV6_PREFIX),
	ENUM_NAME(FR_TYPE_IFID),
	ENUM_NAME(FR_TYPE_COMBO_IP_ADDR),
	ENUM_NAME(FR_TYPE_COMBO_IP_PREFIX),
	ENUM_NAME(FR_TYPE_ETHERNET),

	ENUM_NAME(FR_TYPE_BOOL),

	ENUM_NAME(FR_TYPE_UINT8),
	ENUM_NAME(FR_TYPE_UINT16),
	ENUM_NAME(FR_TYPE_UINT32),
	ENUM_NAME(FR_TYPE_UINT64),

	ENUM_NAME(FR_TYPE_INT8),
	ENUM_NAME(FR_TYPE_INT16),
	ENUM_NAME(FR_TYPE_INT32),
	ENUM_NAME(FR_TYPE_INT64),

	ENUM_NAME(FR_TYPE_FLOAT32),
	ENUM_NAME(FR_TYPE_FLOAT64),

	ENUM_NAME(FR_TYPE_DATE),
	ENUM_NAME(FR_TYPE_TIME_DELTA),

	ENUM_NAME(FR_TYPE_SIZE),

	ENUM_NAME(FR_TYPE_TLV),
	ENUM_NAME(FR_TYPE_STRUCT),

	ENUM_NAME(FR_TYPE_VSA),
	ENUM_NAME(FR_TYPE_VENDOR),
	ENUM_NAME(FR_TYPE_GROUP),
	ENUM_NAME(FR_TYPE_UNION),

	ENUM_NAME(FR_TYPE_ATTR),
};

static void da_print_stats_link(FILE *fp, fr_dict_attr_t const *parent)
{
	int i, num_elements = 0;
	fr_dict_attr_t const *da;
	char dict_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];
	char parent_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	CHECK_TYPE(parent);

	da_normalize_name(fr_dict_root(parent->dict), dict_name);
	da_normalize_name(parent, parent_name);

	fprintf(fp, "fr_stats_link_t const fr_stats_link_%s_%s = {\n", dict_name, parent_name);

	fprintf(fp, "\t.name = \"fr_stats_%s_%s_t\",\n", dict_name, parent_name);
	fprintf(fp, "\t.root_p = &attr_%s,\n", parent_name);
	if (mib) fprintf(fp, "\t.mib = \"%s\",\n", mib);
	fprintf(fp, "\t.size = sizeof(fr_stats_%s_%s_t),\n", dict_name, parent_name);

	for (i = 1; fr_dict_attr_child_by_num(parent, i) != NULL; i++) {
		num_elements = i;
	}
	fprintf(fp, "\t.num_elements = %d,\n", num_elements);

	fprintf(fp, "\t.entry = {\n");

	/*
	 *	For locality, also print out data type and size.  That way we _can_ dereference the da, but we
	 *	don't _need_ to.
	 */
	for (i = 1; (da = fr_dict_attr_child_by_num(parent, i)) != NULL; i++) {
		fprintf(fp, "\t\t{\n");
		fprintf(fp, "\t\t\t.da_p = &attr_%s_", parent_name);
		da_print_name(fp, da);
		fprintf(fp, ",\n");

		fprintf(fp, "\t\t\t.type = %s,\n", fr_type_to_enum_name[da->type]);

		fprintf(fp, "\t\t\t.offset = offsetof(fr_stats_%s_%s_t, ", dict_name, parent_name);
		da_print_name(fp, da);
		fprintf(fp, "),\n");

		fprintf(fp, "\t\t\t.size = %u,\n", da->flags.length);

		fprintf(fp, "\t\t},\n");
	}

	fprintf(fp, "\t},\n");
	fprintf(fp, "};\n\n");
}

static void da_print_attr_autoload(FILE *fp, fr_dict_attr_t const *parent)
{
	int i;
	fr_dict_attr_t const *da;
	char dict_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];
	char parent_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	CHECK_TYPE(parent);

	da_normalize_name(fr_dict_root(parent->dict), dict_name);
	da_normalize_name(parent, parent_name);

	/*
	 *	Define the parent.
	 */
	fprintf(fp, "{ .out = &attr_%s, .name = \"%s\", .type = %s, .dict = &dict_%s },\n",
	       parent_name, parent_oid, fr_type_to_enum_name[parent->type], dict_name);

	/*
	 *	And each child
	 */
	for (i = 1; (da = fr_dict_attr_child_by_num(parent, i)) != NULL; i++) {
		fprintf(fp, "{ .out = &attr_%s_", parent_name);
		da_print_name(fp, da);
		fprintf(fp, ", .name = \".%s\", .type = %s, .dict = &dict_%s },\n",
		       da->name, fr_type_to_enum_name[da->type], dict_name);
	}

	fprintf(fp, "\n\n");
}

static void da_print_stats_h(FILE *fp, fr_dict_attr_t const *parent)
{
	char dict_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];
	char parent_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];

	CHECK_TYPE(parent);

	da_normalize_name(fr_dict_root(parent->dict), dict_name);
	da_normalize_name(parent, parent_name);

	da_print_struct(fp, parent);

	fprintf(fp, "\n");

	fprintf(fp, "/*\n * fr_stats_%s_%s_instance_t\n */\n", dict_name, parent_name);
	fprintf(fp, "FR_STATS_TYPEDEF(%s_%s);\n\n", dict_name, parent_name);

	fprintf(fp, "extern fr_stats_link_t const fr_stats_link_%s_%s;\n\n", dict_name, parent_name);
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

		da_print_info(fr_dict_by_da(da), da, 0);
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

static fr_table_num_ordered_t const format_table[] = {
	{ L("fancy"),		RADICT_OUT_FANCY },
	{ L("csv"),		RADICT_OUT_CSV },
	{ L("dict"),		RADICT_OUT_DICT },
	{ L("struct"),		RADICT_OUT_STRUCT },
	{ L("stats_link"),	RADICT_OUT_STATS_LINK },
	{ L("da_def"),		RADICT_OUT_BASE_C_DA_DEF },
	{ L("attr_autoload"),	RADICT_OUT_ATTR_AUTOLOAD },
	{ L("stats.h"),		RADICT_OUT_STATS_H },
};
static size_t format_table_len = NUM_ELEMENTS(format_table);

static fr_table_ptr_ordered_t const function_table[] = {
	{ L("fancy"),		NULL },
	{ L("csv"),		NULL },
	{ L("dict"),		NULL },
	{ L("struct"),		(void *) da_print_struct },
	{ L("stats_link"),	(void *) da_print_stats_link },
	{ L("da_def"),		(void *) da_print_base_c_da_def },
	{ L("attr_autoload"),	(void *) da_print_attr_autoload },
	{ L("stats.h"),		(void *) da_print_stats_h },
};
static size_t function_table_len = NUM_ELEMENTS(function_table);

typedef void (*da_print_func_t)(FILE *fp, fr_dict_attr_t const *da);


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
	da_print_func_t	func = NULL;

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

	while ((c = getopt(argc, argv, "AcfF:ED:M:p:rVxhH")) != -1) switch (c) {
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

		case 'F':
			output_format = fr_table_value_by_str(format_table, optarg, RADICT_OUT_INVALID);
			if (output_format == RADICT_OUT_INVALID) {
				fprintf(stderr, "Invalid output format '%s'\n", optarg);
				fr_exit(EXIT_FAILURE);
			}

			func = (da_print_func_t) fr_table_value_by_str(function_table, optarg, NULL);
			break;

		case 'E':
			export = true;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'M':
			mib = optarg;
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

	DEBUG("Loading dictionary: %s/%s", dict_dir, FR_DICTIONARY_FILE);

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

	if (argc == 0) goto finish;

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
			if (!da) {
				DEBUG2("Dictionary %s does not contain attribute %s\n",
				       fr_dict_root(*dict_p)->name, attr);
				continue;
			}

			if (!func) {
				da_print_info(*dict_p, da, 0);
			} else {
				parent_oid = attr;
				func(stdout, da);
			}
			found = true;
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
