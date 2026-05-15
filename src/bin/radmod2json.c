/*
 * radmod2json.c   Dump FreeRADIUS v4 module conf_parser_t and call_env_parser_t
 *                 definitions as JSON.
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
 * Copyright (C) 2026 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/section.h>
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/types.h>

#include <json-c/json.h>

#include <dirent.h>
#include <dlfcn.h>
#include <sys/wait.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

char const *radiusd_version = RADIUSD_VERSION_BUILD("radmod2json");

static inline char const *quote_name(fr_token_t t)
{
	static char const *const quote_names[T_TOKEN_LAST] = {
		[T_BARE_WORD]		  = "T_BARE_WORD",
		[T_DOUBLE_QUOTED_STRING]  = "T_DOUBLE_QUOTED_STRING",
		[T_SINGLE_QUOTED_STRING]  = "T_SINGLE_QUOTED_STRING",
		[T_BACK_QUOTED_STRING]	  = "T_BACK_QUOTED_STRING",
		[T_SOLIDUS_QUOTED_STRING] = "T_SOLIDUS_QUOTED_STRING",
	};

	char const *s;

	if ((unsigned int)t >= T_TOKEN_LAST) return "T_BARE_WORD";
	s = quote_names[t];
	if (!s) return "T_BARE_WORD";
	return s;
}

static inline char const *fr_type_full_name(fr_type_t t)
{
	static char const *const fr_type_enum_str[FR_TYPE_MAX + 1] = {
		[FR_TYPE_NULL]		   = "FR_TYPE_NULL",
		[FR_TYPE_STRING]	   = "FR_TYPE_STRING",
		[FR_TYPE_OCTETS]	   = "FR_TYPE_OCTETS",
		[FR_TYPE_IPV4_ADDR]	   = "FR_TYPE_IPV4_ADDR",
		[FR_TYPE_IPV4_PREFIX]	   = "FR_TYPE_IPV4_PREFIX",
		[FR_TYPE_IPV6_ADDR]	   = "FR_TYPE_IPV6_ADDR",
		[FR_TYPE_IPV6_PREFIX]	   = "FR_TYPE_IPV6_PREFIX",
		[FR_TYPE_IFID]		   = "FR_TYPE_IFID",
		[FR_TYPE_COMBO_IP_ADDR]	   = "FR_TYPE_COMBO_IP_ADDR",
		[FR_TYPE_COMBO_IP_PREFIX]  = "FR_TYPE_COMBO_IP_PREFIX",
		[FR_TYPE_ETHERNET]	   = "FR_TYPE_ETHERNET",
		[FR_TYPE_BOOL]		   = "FR_TYPE_BOOL",
		[FR_TYPE_UINT8]		   = "FR_TYPE_UINT8",
		[FR_TYPE_UINT16]	   = "FR_TYPE_UINT16",
		[FR_TYPE_UINT32]	   = "FR_TYPE_UINT32",
		[FR_TYPE_UINT64]	   = "FR_TYPE_UINT64",
		[FR_TYPE_INT8]		   = "FR_TYPE_INT8",
		[FR_TYPE_INT16]		   = "FR_TYPE_INT16",
		[FR_TYPE_INT32]		   = "FR_TYPE_INT32",
		[FR_TYPE_INT64]		   = "FR_TYPE_INT64",
		[FR_TYPE_FLOAT32]	   = "FR_TYPE_FLOAT32",
		[FR_TYPE_FLOAT64]	   = "FR_TYPE_FLOAT64",
		[FR_TYPE_DATE]		   = "FR_TYPE_DATE",
		[FR_TYPE_TIME_DELTA]	   = "FR_TYPE_TIME_DELTA",
		[FR_TYPE_SIZE]		   = "FR_TYPE_SIZE",
		[FR_TYPE_TLV]		   = "FR_TYPE_TLV",
		[FR_TYPE_STRUCT]	   = "FR_TYPE_STRUCT",
		[FR_TYPE_VSA]		   = "FR_TYPE_VSA",
		[FR_TYPE_VENDOR]	   = "FR_TYPE_VENDOR",
		[FR_TYPE_GROUP]		   = "FR_TYPE_GROUP",
		[FR_TYPE_UNION]		   = "FR_TYPE_UNION",
		[FR_TYPE_VALUE_BOX]	   = "FR_TYPE_VALUE_BOX",
		[FR_TYPE_ATTR]		   = "FR_TYPE_ATTR",
		[FR_TYPE_VOID]		   = "FR_TYPE_VOID",
		[FR_TYPE_VALUE_BOX_CURSOR] = "FR_TYPE_VALUE_BOX_CURSOR",
		[FR_TYPE_PAIR_CURSOR]	   = "FR_TYPE_PAIR_CURSOR",
	};

	char const *s;

	if ((unsigned int)t >= NUM_ELEMENTS(fr_type_enum_str)) return "FR_TYPE_INVALID";
	s = fr_type_enum_str[t];
	if (!s) return "FR_TYPE_NULL";
	return s;
}

/*
 *	Resolve a function pointer back to its source symbol name via dladdr().
 *	macOS C symbols get a leading '_' from the linker - strip that before
 *	emitting.
 */
static struct json_object *func_symbol(void const *fn)
{
	Dl_info	    info;
	char const *name;

	if (!fn) return NULL;
	if (dladdr(fn, &info) == 0) return NULL;
	if (!info.dli_sname) return NULL;

	name = info.dli_sname;
	if (name[0] == '_') name++;
	return json_object_new_string(name);
}

static struct json_object *build_dflt(char const *value, fr_token_t quote)
{
	struct json_object *o;

	if (!value) return NULL;
	o = json_object_new_object();
	json_object_object_add(o, "value", json_object_new_string(value));
	json_object_object_add(o, "quote", json_object_new_string(quote_name(quote)));
	return o;
}

/*
 *	Walk every set bit of `flags`; for each one, look the single-bit
 *	mask up in `table` via fr_table_str_by_value (the _Generic
 *	dispatch routes a bit-pos table through fr_table_indexed_str_by_bit_field).
 *	Push matches into a new JSON array in bit-order.
 */
static struct json_object *flags_to_json(fr_table_num_indexed_bit_pos_t const *table, size_t table_len, uint64_t flags)
{
	struct json_object *a = json_object_new_array();

	for (size_t bit = 0; bit < 64; bit++) {
		uint64_t    mask = UINT64_C(1) << bit;
		char const *name;

		if (!(flags & mask)) continue;
		name = fr_table_str_by_value(table, mask, NULL);
		if (!name) continue;
		json_object_array_add(a, json_object_new_string(name));
	}
	return a;
}

static struct json_object *build_conf_parser_flags(conf_parser_flags_t flags)
{
	static fr_table_num_indexed_bit_pos_t const conf_flag_table[] = {
		[2]  = { L("CONF_FLAG_SUBSECTION"), CONF_FLAG_SUBSECTION },
		[11] = { L("CONF_FLAG_DEPRECATED"), CONF_FLAG_DEPRECATED },
		[12] = { L("CONF_FLAG_REQUIRED"), CONF_FLAG_REQUIRED },
		[13] = { L("CONF_FLAG_ATTRIBUTE"), CONF_FLAG_ATTRIBUTE },
		[14] = { L("CONF_FLAG_SECRET"), CONF_FLAG_SECRET },
		[15] = { L("CONF_FLAG_FILE_READABLE"), CONF_FLAG_FILE_READABLE },
		[16] = { L("CONF_FLAG_FILE_WRITABLE"), CONF_FLAG_FILE_WRITABLE },
		[17] = { L("CONF_FLAG_FILE_SOCKET"), CONF_FLAG_FILE_SOCKET },
		[18] = { L("CONF_FLAG_FILE_EXISTS"), CONF_FLAG_FILE_EXISTS },
		[19] = { L("CONF_FLAG_XLAT"), CONF_FLAG_XLAT },
		[20] = { L("CONF_FLAG_TMPL"), CONF_FLAG_TMPL },
		[21] = { L("CONF_FLAG_MULTI"), CONF_FLAG_MULTI },
		[22] = { L("CONF_FLAG_NOT_EMPTY"), CONF_FLAG_NOT_EMPTY },
		[23] = { L("CONF_FLAG_IS_SET"), CONF_FLAG_IS_SET },
		[24] = { L("CONF_FLAG_OK_MISSING"), CONF_FLAG_OK_MISSING },
		[25] = { L("CONF_FLAG_HIDDEN"), CONF_FLAG_HIDDEN },
		[26] = { L("CONF_FLAG_REF"), CONF_FLAG_REF },
		[27] = { L("CONF_FLAG_OPTIONAL"), CONF_FLAG_OPTIONAL },
		[28] = { L("CONF_FLAG_ALWAYS_PARSE"), CONF_FLAG_ALWAYS_PARSE },
		[29] = { L("CONF_FLAG_NO_OUTPUT"), CONF_FLAG_NO_OUTPUT },
	};
	static size_t conf_flag_table_len = NUM_ELEMENTS(conf_flag_table);

	return flags_to_json(conf_flag_table, conf_flag_table_len, flags);
}

static struct json_object *build_conf_parser_rules(conf_parser_t const *rules);

static struct json_object *build_conf_parser_rule(conf_parser_t const *r)
{
	struct json_object *o	   = json_object_new_object();
	bool		    is_sub = (r->flags & CONF_FLAG_SUBSECTION) != 0;

	json_object_object_add(o, "name1", r->name1 ? json_object_new_string(r->name1) : NULL);
	json_object_object_add(o, "name2", r->name2 ? json_object_new_string(r->name2) : NULL);
	json_object_object_add(o, "type", json_object_new_string(fr_type_full_name(r->type)));
	json_object_object_add(o, "flags", build_conf_parser_flags(r->flags));
	json_object_object_add(o, "func", func_symbol((void const *)r->func));
	json_object_object_add(o, "on_read", func_symbol((void const *)r->on_read));

	if (is_sub) {
		json_object_object_add(o, "subcs",
				       r->subcs ? build_conf_parser_rules(r->subcs) : json_object_new_array());
	} else {
		json_object_object_add(o, "dflt", build_dflt(r->dflt, r->quote));
	}

	return o;
}

static struct json_object *build_conf_parser_rules(conf_parser_t const *rules)
{
	struct json_object *a = json_object_new_array();

	if (rules) {
		for (conf_parser_t const *r = rules; r->name1; r++) {
			json_object_array_add(a, build_conf_parser_rule(r));
		}
	}
	return a;
}

/*
 *	Symbolic names for each `CALL_ENV_FLAG_*` bit.  Same shape as
 *	`conf_flag_table` - bit-pos-indexed `fr_table_num_indexed_bit_pos_t`,
 *	walked via `flags_to_json`.
 */
static fr_table_num_indexed_bit_pos_t const call_env_flag_table[] = {
	[1]  = { L("CALL_ENV_FLAG_REQUIRED"), CALL_ENV_FLAG_REQUIRED },
	[2]  = { L("CALL_ENV_FLAG_CONCAT"), CALL_ENV_FLAG_CONCAT },
	[3]  = { L("CALL_ENV_FLAG_SINGLE"), CALL_ENV_FLAG_SINGLE },
	[4]  = { L("CALL_ENV_FLAG_MULTI"), CALL_ENV_FLAG_MULTI },
	[5]  = { L("CALL_ENV_FLAG_NULLABLE"), CALL_ENV_FLAG_NULLABLE },
	[6]  = { L("CALL_ENV_FLAG_FORCE_QUOTE"), CALL_ENV_FLAG_FORCE_QUOTE },
	[7]  = { L("CALL_ENV_FLAG_PARSE_ONLY"), CALL_ENV_FLAG_PARSE_ONLY },
	[8]  = { L("CALL_ENV_FLAG_ATTRIBUTE"), CALL_ENV_FLAG_ATTRIBUTE },
	[9]  = { L("CALL_ENV_FLAG_SUBSECTION"), CALL_ENV_FLAG_SUBSECTION },
	[10] = { L("CALL_ENV_FLAG_PARSE_MISSING"), CALL_ENV_FLAG_PARSE_MISSING },
	[11] = { L("CALL_ENV_FLAG_SECRET"), CALL_ENV_FLAG_SECRET },
	[12] = { L("CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE"), CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE },
};
static size_t call_env_flag_table_len = NUM_ELEMENTS(call_env_flag_table);

static struct json_object *build_call_env_flags(call_env_flags_t flags)
{
	return flags_to_json(call_env_flag_table, call_env_flag_table_len, flags);
}

/*
 *	Symbolic names for the call_env parse / result type enums,
 *	indexed by enum value.  Both enums start at 1, so index 0 is a
 *	NULL placeholder that the lookup falls back to the default for.
 */
static char const *const call_env_parse_type_names[] = {
	[CALL_ENV_PARSE_TYPE_TMPL]	= "CALL_ENV_PARSE_TYPE_TMPL",
	[CALL_ENV_PARSE_TYPE_VALUE_BOX] = "CALL_ENV_PARSE_TYPE_VALUE_BOX",
	[CALL_ENV_PARSE_TYPE_VOID]	= "CALL_ENV_PARSE_TYPE_VOID",
};

static inline char const *call_env_parse_type_name(call_env_parse_type_t t)
{
	char const *s;

	if ((unsigned int)t >= NUM_ELEMENTS(call_env_parse_type_names)) return "CALL_ENV_PARSE_TYPE_VOID";
	s = call_env_parse_type_names[t];
	if (!s) return "CALL_ENV_PARSE_TYPE_VOID";
	return s;
}

static char const *const call_env_result_type_names[] = {
	[CALL_ENV_RESULT_TYPE_VALUE_BOX]      = "CALL_ENV_RESULT_TYPE_VALUE_BOX",
	[CALL_ENV_RESULT_TYPE_VALUE_BOX_LIST] = "CALL_ENV_RESULT_TYPE_VALUE_BOX_LIST",
};

static inline char const *call_env_result_type_name(call_env_result_type_t t)
{
	char const *s;

	if ((unsigned int)t >= NUM_ELEMENTS(call_env_result_type_names)) return "CALL_ENV_RESULT_TYPE_VALUE_BOX";
	s = call_env_result_type_names[t];
	if (!s) return "CALL_ENV_RESULT_TYPE_VALUE_BOX";
	return s;
}

static char const *section_ident(char const *name)
{
	if (name == CF_IDENT_ANY) return "*";
	return name;
}

static struct json_object *json_section_ident(char const *name)
{
	char const *s = section_ident(name);
	return s ? json_object_new_string(s) : NULL;
}

static struct json_object *build_call_env_rules(call_env_parser_t const *rules);

static struct json_object *build_call_env_rule(call_env_parser_t const *r)
{
	struct json_object *o	   = json_object_new_object();
	bool		    is_sub = (r->flags & CALL_ENV_FLAG_SUBSECTION) != 0;

	json_object_object_add(o, "name", json_section_ident(r->name));
	json_object_object_add(o, "flags", build_call_env_flags(r->flags));

	if (is_sub) {
		struct json_object *s = json_object_new_object();
		json_object_object_add(s, "name2", json_section_ident(r->section.name2));
		json_object_object_add(s, "func", func_symbol((void const *)r->section.func));
		json_object_object_add(s, "subcs",
				       r->section.subcs ? build_call_env_rules(r->section.subcs) :
							  json_object_new_array());
		json_object_object_add(o, "section", s);
	} else {
		struct json_object *p	   = json_object_new_object();
		struct json_object *parsed = json_object_new_object();

		/*
		 *	FR_TYPE_NULL / FR_TYPE_VOID both mean "no cast" - the
		 *	framework hands the parsed value through without
		 *	coercion.  Collapse to a JSON null so the converter
		 *	only has to check one sentinel.
		 */
		json_object_object_add(p, "cast_type",
				       ((r->pair.cast_type == FR_TYPE_NULL) || (r->pair.cast_type == FR_TYPE_VOID)) ?
					       NULL :
					       json_object_new_string(fr_type_full_name(r->pair.cast_type)));
		json_object_object_add(p, "type", json_object_new_string(call_env_result_type_name(r->pair.type)));
		json_object_object_add(p, "dflt", build_dflt(r->pair.dflt, r->pair.dflt_quote));
		json_object_object_add(p, "func", func_symbol((void const *)r->pair.func));

		json_object_object_add(parsed, "type",
				       json_object_new_string(call_env_parse_type_name(r->pair.parsed.type)));
		json_object_object_add(p, "parsed", parsed);

		json_object_object_add(o, "pair", p);
	}

	return o;
}

static struct json_object *build_call_env_rules(call_env_parser_t const *rules)
{
	struct json_object *a = json_object_new_array();

	if (rules) {
		for (call_env_parser_t const *r = rules; r->name; r++) {
			json_object_array_add(a, build_call_env_rule(r));
		}
	}
	return a;
}

static struct json_object *build_method_bindings(module_method_binding_t const *bindings)
{
	struct json_object *a = json_object_new_array();

	if (bindings) {
		for (module_method_binding_t const *b = bindings; b->section; b++) {
			struct json_object *entry   = json_object_new_object();
			struct json_object *section = json_object_new_object();

			json_object_object_add(section, "name1", json_section_ident(b->section->name1));
			json_object_object_add(section, "name2", json_section_ident(b->section->name2));
			json_object_object_add(entry, "section", section);
			json_object_object_add(entry, "method", func_symbol((void const *)b->method));
			json_object_object_add(entry, "env",
					       (b->method_env && b->method_env->env) ?
						       build_call_env_rules(b->method_env->env) :
						       json_object_new_array());

			json_object_array_add(a, entry);
		}
	}

	return a;
}

/*
 *	Build the JSON for one module using the server's normal dl loader.
 *	`bare_name` is the module name without the "rlm_" prefix (so "files"
 *	for rlm_files).  Returns the json object or NULL on error.
 */
static struct json_object *build_module(char const *bare_name)
{
	dl_module_t	   *dl_module;
	module_rlm_t	   *m;
	struct json_object *entry;

	dl_module = dl_module_alloc(NULL, bare_name, DL_MODULE_TYPE_MODULE);
	if (!dl_module) {
		fr_perror("rlm_%s", bare_name);
		return NULL;
	}

	m = (module_rlm_t *)dl_module->exported;
	if (!m) return NULL;

	entry = json_object_new_object();
	json_object_object_add(entry, "module", json_object_new_string(m->common.name ? m->common.name : bare_name));
	json_object_object_add(entry, "config", build_conf_parser_rules(m->common.config));
	json_object_object_add(entry, "call_env", build_method_bindings(m->method_group.bindings));
	return entry;
}

static int dump_module(struct json_object *modules, char const *bare_name)
{
	int   fds[2];
	pid_t pid;
	int   status;

	if (pipe(fds) < 0) {
		fprintf(stderr, "rlm_%s: pipe failed: %s\n", bare_name, fr_syserror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		fprintf(stderr, "rlm_%s: fork failed: %s\n", bare_name, fr_syserror(errno));
		return -1;
	}

	if (pid == 0) {
		struct json_object *entry;

		close(fds[0]);
		entry = build_module(bare_name);
		if (entry) {
			char const *s = json_object_to_json_string_ext(entry, JSON_C_TO_STRING_PLAIN |
										      JSON_C_TO_STRING_NOSLASHESCAPE);
			(void)write(fds[1], s, strlen(s));
			json_object_put(entry);
		}
		close(fds[1]);
		_exit(entry ? 0 : 1);
	}

	close(fds[1]);
	{
		char	buf[262144];
		size_t	used = 0;
		ssize_t n;
		while ((n = read(fds[0], buf + used, sizeof(buf) - 1 - used)) > 0) {
			used += n;
			if (used >= sizeof(buf) - 1) break;
		}
		close(fds[0]);
		buf[used] = '\0';

		waitpid(pid, &status, 0);

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "rlm_%s: child %s (status=0x%x), skipping\n", bare_name,
				WIFEXITED(status) ? "exited non-zero" : "crashed", status);
			return -1;
		}

		if (used > 0) {
			struct json_object *entry = json_tokener_parse(buf);
			if (entry) {
				json_object_array_add(modules, entry);
				return 0;
			}
			fprintf(stderr, "rlm_%s: failed to parse child JSON\n", bare_name);
			return -1;
		}
	}

	return -1;
}

/*
 *	Discover top-level rlm_*.dylib (or .so) files in a directory, returning
 *	the bare module names (no "rlm_" prefix, no extension).  The dl loader
 *	will re-prefix and resolve the full path itself.
 */
static int discover_modules(char const *dir, char ***out_names, size_t *out_count)
{
	DIR	      *d;
	struct dirent *e;
	char	     **names = NULL;
	size_t	       n = 0, alloc = 0;
	size_t	       extlen = strlen(DL_EXTENSION);

	d = opendir(dir);
	if (!d) {
		fprintf(stderr, "Failed opening module dir %s: %s\n", dir, fr_syserror(errno));
		return -1;
	}

	while ((e = readdir(d)) != NULL) {
		size_t nlen = strlen(e->d_name);
		char  *name;

		if (nlen <= extlen) continue;
		if (strcmp(e->d_name + nlen - extlen, DL_EXTENSION) != 0) continue;
		if (strncmp(e->d_name, "rlm_", 4) != 0) continue;

		if (n == alloc) {
			alloc = alloc ? alloc * 2 : 16;
			names = realloc(names, alloc * sizeof(*names));
		}

		/* Strip "rlm_" prefix and DL_EXTENSION suffix */
		name			= strdup(e->d_name + 4);
		name[nlen - 4 - extlen] = '\0';
		names[n++]		= name;
	}

	closedir(d);

	*out_names = names;
	*out_count = n;
	return 0;
}

static int compare_str(void const *a, void const *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static NEVER_RETURNS void usage(int rcode)
{
	FILE *fp = (rcode == 0) ? stdout : stderr;

	fprintf(fp, "Usage: radmod2json [options]\n"
		    "  -m <list>     Comma-separated list of module names without rlm_ prefix\n"
		    "                (default: all rlm_*.dylib in -M dir).\n"
		    "  -M <dir>      Module directory to load from.\n"
		    "  -D <dict>     Dictionary directory (autoload uses this).\n"
		    "  -o <file>     Write JSON to <file> (default stdout).\n"
		    "  -x            Enable debug output (repeatable).\n"
		    "  -h            This help.\n");
	exit(rcode);
}

int main(int argc, char *argv[])
{
	int		    c;
	int		    rcode	= EXIT_SUCCESS;
	char const	   *modules_arg = NULL;
	char const	   *output_file = NULL;
	char const	   *module_dir	= NULL;
	char const	   *dict_dir	= NULL;
	char		  **names	= NULL;
	size_t		    n_names	= 0;
	char		   *owned_list	= NULL;
	fr_dict_t	   *internal	= NULL;
	struct json_object *root, *modules;

	fr_debug_lvl	= 0;
	default_log.dst = L_DST_STDERR;
	default_log.fd	= STDERR_FILENO;

	while ((c = getopt(argc, argv, "D:hm:M:o:x")) != -1) {
		switch (c) {
		case 'D':
			dict_dir = optarg;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
		case 'm':
			modules_arg = optarg;
			break;
		case 'M':
			module_dir = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'x':
			fr_debug_lvl++;
			break;
		default:
			usage(EXIT_FAILURE);
		}
	}

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radmod2json");
		exit(EXIT_FAILURE);
	}

	if (!module_dir) {
		fprintf(stderr, "Need -M <dir>\n");
		exit(EXIT_FAILURE);
	}

	/* Init the dl loader against the requested module dir. */
	modules_init(module_dir);

	/*
	 *	dl_module_alloc triggers fr_dict_autoload on the loaded
	 *	module, which needs a global dict ctx to exist.  Some
	 *	modules also autoload internal-protocol attributes that
	 *	are in the dictionary tree, so load it up front.
	 */
	if (!fr_dict_global_ctx_init(NULL, true, dict_dir)) {
		fr_perror("radmod2json");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_internal_afrom_file(&internal, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("radmod2json");
		exit(EXIT_FAILURE);
	}

	if (modules_arg) {
		char  *list = strdup(modules_arg);
		char  *p, *tok;
		size_t alloc = 0;

		owned_list = list;
		for (p = list; (tok = strsep(&p, ",")) != NULL;) {
			char const *bare = tok;

			if (!*bare) continue;
			if (strncmp(bare, "rlm_", 4) == 0) bare += 4;
			if (n_names == alloc) {
				alloc = alloc ? alloc * 2 : 16;
				names = realloc(names, alloc * sizeof(*names));
			}
			names[n_names++] = (char *)bare;
		}
	} else {
		if (discover_modules(module_dir, &names, &n_names) < 0) {
			exit(EXIT_FAILURE);
		}
		qsort(names, n_names, sizeof(names[0]), compare_str);
	}

	root	= json_object_new_object();
	modules = json_object_new_array();
	json_object_object_add(root, "modules", modules);

	for (size_t i = 0; i < n_names; i++) {
		if (dump_module(modules, names[i]) < 0) rcode = EXIT_FAILURE;
	}

	{
		char const *json_str =
			json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

		if (output_file) {
			FILE *out = fopen(output_file, "w");
			if (!out) {
				fprintf(stderr, "Failed opening %s: %s\n", output_file, fr_syserror(errno));
				exit(EXIT_FAILURE);
			}
			fputs(json_str, out);
			fputc('\n', out);
			fclose(out);
		} else {
			fputs(json_str, stdout);
			fputc('\n', stdout);
		}
	}

	json_object_put(root);
	if (owned_list) free(owned_list);
	if (!modules_arg)
		for (size_t i = 0; i < n_names; i++) free(names[i]);
	free(names);

	return rcode;
}
