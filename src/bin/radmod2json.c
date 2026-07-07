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

#include <freeradius-devel/json/base.h>

#include <dirent.h>
#include <dlfcn.h>
#include <sys/wait.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

char const *radiusd_version = RADIUSD_VERSION_BUILD("radmod2json");

/*
 *	Symbolic names for the five quote tokens, keyed by `fr_token_t`.
 *	fr_table_str_by_value() routes us through fr_table_indexed_str_by_num
 *	via the _Generic dispatch on the table type.
 */
/*
 *	`fr_token_to_enum_str()` (src/lib/util/token.c) returns the
 *	source-identifier form of the token ("T_BARE_WORD" etc.) which
 *	is what the converter's rule layer greps for.
 */
#define quote_name(_t) fr_token_to_enum_str(_t)

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
 *	Walk every set bit of `flags`; resolve each single-bit mask
 *	through the library's `*_flag_to_enum_str()` lookup.  Bits with
 *	no symbolic name are skipped.  The result preserves bit-order.
 */
static struct json_object *build_conf_parser_flags(conf_parser_flags_t flags)
{
	struct json_object *a = json_object_new_array();

	for (size_t bit = 0; bit < 32; bit++) {
		uint64_t    mask = UINT64_C(1) << bit;
		char const *name;

		if (!(flags & mask)) continue;
		name = cf_parser_flag_to_enum_str(mask);
		if (!name) continue;
		json_object_array_add(a, json_object_new_string(name));
	}
	return a;
}

static struct json_object *build_conf_parser_rules(conf_parser_t const *rules);

static struct json_object *build_conf_parser_rule(conf_parser_t const *r)
{
	struct json_object *o	   = json_object_new_object();
	bool		    is_sub = (r->flags & CONF_FLAG_SUBSECTION) != 0;

	json_object_object_add(o, "name1", r->name1 ? json_object_new_string(r->name1) : NULL);
	json_object_object_add(o, "name2", r->name2 ? json_object_new_string(r->name2) : NULL);
	json_object_object_add(o, "type", json_object_new_string(fr_type_to_enum_str(r->type)));
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

static struct json_object *build_call_env_flags(call_env_flags_t flags)
{
	struct json_object *a = json_object_new_array();

	for (size_t bit = 0; bit < 32; bit++) {
		uint64_t    mask = UINT64_C(1) << bit;
		char const *name;

		if (!(flags & mask)) continue;
		name = call_env_flag_to_enum_str(mask);
		if (!name) continue;
		json_object_array_add(a, json_object_new_string(name));
	}
	return a;
}

static struct json_object *json_section_ident(char const *name)
{
	if (!name) return NULL;
	if (name == CF_IDENT_ANY) return json_object_new_string("*");
	return json_object_new_string(name);
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
					       json_object_new_string(fr_type_to_enum_str(r->pair.cast_type)));
		json_object_object_add(p, "type",
				       json_object_new_string(call_env_result_type_to_enum_str(r->pair.type)));
		json_object_object_add(p, "dflt", build_dflt(r->pair.dflt, r->pair.dflt_quote));
		json_object_object_add(p, "func", func_symbol((void const *)r->pair.func));

		json_object_object_add(parsed, "type",
				       json_object_new_string(call_env_parse_type_to_enum_str(r->pair.parsed.type)));
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
		if (!entry) {
			fprintf(stderr, "rlm_%s: build_module failed\n", bare_name);
			_exit(1);
		}

		{
			char const *s = json_object_to_json_string_ext(entry, JSON_C_TO_STRING_PLAIN |
										      JSON_C_TO_STRING_NOSLASHESCAPE);
			size_t	remaining = strlen(s);
			ssize_t	n;

			while (remaining > 0) {
				n = write(fds[1], s, remaining);
				if (n < 0) {
					fprintf(stderr, "rlm_%s: write to pipe failed: %s\n",
						bare_name, fr_syserror(errno));
					_exit(1);
				}
				s += n;
				remaining -= n;
			}
		}
		json_object_put(entry);
		close(fds[1]);
		_exit(0);
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
static int discover_modules(TALLOC_CTX *ctx, char const *dir, char ***out_names, size_t *out_count)
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

		if (nlen <= extlen) continue;
		if (strcmp(e->d_name + nlen - extlen, DL_EXTENSION) != 0) continue;
		if (strncmp(e->d_name, "rlm_", 4) != 0) continue;

		if (n == alloc) {
			alloc = alloc ? alloc * 2 : 16;
			MEM(names = talloc_realloc(ctx, names, char *, alloc));
		}

		/* Strip "rlm_" prefix and DL_EXTENSION suffix */
		MEM(names[n++] = talloc_strndup(names, e->d_name + 4, nlen - 4 - extlen));
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

	fprintf(fp,
		"Usage: radmod2json [options]\n"
		"  -m <list>     Comma-separated list of module names without rlm_ prefix\n"
		"                (default: every rlm_*" DL_EXTENSION " under the module directory).\n"
		"  -M <dir>      Module directory to load from (default: " LIBDIR ").\n"
		"  -D <dict>     Dictionary directory (default: " DICTDIR ").\n"
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
	char const	   *module_dir	= LIBDIR;
	char const	   *dict_dir	= DICTDIR;
	char		  **names	= NULL;
	size_t		    n_names	= 0;
	fr_dict_t	   *internal	= NULL;
	TALLOC_CTX	   *autofree;

	autofree = talloc_autofree_context();

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
		char  *list = talloc_strdup(autofree, modules_arg);
		char  *p, *tok;
		size_t alloc = 0;

		for (p = list; (tok = strsep(&p, ",")) != NULL;) {
			char const *bare = tok;

			if (!*bare) continue;
			if (strncmp(bare, "rlm_", 4) == 0) bare += 4;
			if (n_names == alloc) {
				alloc = alloc ? alloc * 2 : 16;
				MEM(names = talloc_realloc(autofree, names, char *, alloc));
			}
			names[n_names++] = UNCONST(char *, bare);
		}
	} else {
		if (discover_modules(autofree, module_dir, &names, &n_names) < 0) {
			exit(EXIT_FAILURE);
		}
		if (n_names > 0) qsort(names, n_names, sizeof(names[0]), compare_str);
	}

	{
		struct json_object *root = json_object_new_object();
		struct json_object *modules = json_object_new_array();
		char const *json_str;

		json_object_object_add(root, "modules", modules);

		for (size_t i = 0; i < n_names; i++) {
			if (dump_module(modules, names[i]) < 0) rcode = EXIT_FAILURE;
		}

		json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
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

		json_object_put(root);
	}

	return rcode;
}
