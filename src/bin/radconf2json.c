/*
 * radconf2json.c   Dump a parsed FreeRADIUS v4 configuration tree as JSON.
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
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/syserror.h>

#ifdef WITH_TLS
#  include <freeradius-devel/tls/base.h>
#  include <freeradius-devel/tls/version.h>
#endif

#include <freeradius-devel/json/base.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define EXIT_WITH_FAILURE             \
	do {                          \
		rcode = EXIT_FAILURE; \
		goto finish;          \
	} while (0)

char const *radiusd_version = RADIUSD_VERSION_BUILD("radconf2json");

/*
 *	Token-name look-ups.  `fr_token_to_enum_str()` (src/lib/util/token.c)
 *	returns the source-identifier form ("T_BARE_WORD", "T_OP_SET", ...)
 *	which is what the converter's rule layer greps for.  `fr_tokens[]`
 *	gives the operator-character form (":=", "=", "==", ...) for the
 *	operator side; we emit that as `op`.
 */
#define quote_name(_t) fr_token_to_enum_str(_t)
#define op_name(_op) (((unsigned int)(_op) < T_TOKEN_LAST && fr_tokens[(_op)]) ? fr_tokens[(_op)] : "?")

static struct json_object *build_location(char const *filename, int lineno)
{
	struct json_object *loc;

	if (!filename && lineno == 0) return NULL;

	loc = json_object_new_object();
	json_object_object_add(loc, "filename", filename ? json_object_new_string(filename) : NULL);
	json_object_object_add(loc, "lineno", json_object_new_int(lineno));
	return loc;
}

static struct json_object *build_comment(CONF_COMMENT const *c)
{
	struct json_object *o	     = json_object_new_object();
	char const	   *filename = cf_filename(c);
	int		    lineno   = cf_lineno(c);

	json_object_object_add(o, "type", json_object_new_string("comment"));
	json_object_object_add(o, "text", cf_comment_text(c) ? json_object_new_string(cf_comment_text(c)) : NULL);
	json_object_object_add(o, "location", build_location(filename, lineno));
	return o;
}

static struct json_object *build_pair(CONF_PAIR const *cp)
{
	struct json_object *o	  = json_object_new_object();
	char const	   *value = cf_pair_value(cp);

	json_object_object_add(o, "type", json_object_new_string("pair"));
	json_object_object_add(o, "attr", cf_pair_attr(cp) ? json_object_new_string(cf_pair_attr(cp)) : NULL);
	json_object_object_add(o, "lhs_quote", json_object_new_string(quote_name(cf_pair_attr_quote(cp))));
	json_object_object_add(o, "op", json_object_new_string(op_name(cf_pair_operator(cp))));
	json_object_object_add(o, "value", value ? json_object_new_string(value) : NULL);
	json_object_object_add(o, "rhs_quote", json_object_new_string(quote_name(cf_pair_value_quote(cp))));
	json_object_object_add(o, "location", build_location(cf_filename(cp), cf_lineno(cp)));

	return o;
}

static struct json_object *build_section(CONF_SECTION const *cs)
{
	struct json_object *o	     = json_object_new_object();
	struct json_object *children = json_object_new_array();
	char const	   *name2    = cf_section_name2(cs);

	json_object_object_add(o, "type", json_object_new_string("section"));
	json_object_object_add(o, "name1", cf_section_name1(cs) ? json_object_new_string(cf_section_name1(cs)) : NULL);
	json_object_object_add(o, "name2", name2 ? json_object_new_string(name2) : NULL);
	json_object_object_add(o, "name2_quote", json_object_new_string(quote_name(cf_section_name2_quote(cs))));
	json_object_object_add(o, "location", build_location(cf_filename(cs), cf_lineno(cs)));

	cf_item_foreach(cs, ci)
	{
		if (cf_item_is_section(ci)) {
			json_object_array_add(children, build_section(cf_item_to_section(UNCONST(CONF_ITEM *, ci))));
		} else if (cf_item_is_pair(ci)) {
			json_object_array_add(children, build_pair(cf_item_to_pair(UNCONST(CONF_ITEM *, ci))));
		} else if (cf_item_is_comment(ci)) {
			json_object_array_add(children, build_comment(cf_item_to_comment(UNCONST(CONF_ITEM *, ci))));
		}
	}

	json_object_object_add(o, "children", children);
	return o;
}

static NEVER_RETURNS void usage(int rcode)
{
	FILE *fp = (rcode == 0) ? stdout : stderr;

	fprintf(fp, "Usage: radconf2json [options]\n"
		    "  -d <raddb>    Set raddb directory.\n"
		    "  -D <dict>     Set dictionary directory.\n"
		    "  -n <name>     Read <name>.conf instead of radiusd.conf.\n"
		    "  -o <file>     Write JSON to <file> (default stdout).\n"
		    "  -x            Enable debug output (repeatable).\n"
		    "  -X            Verbose debug output.\n"
		    "  -h            This help.\n");
	exit(rcode);
}

int main(int argc, char *argv[])
{
	int		    c;
	int		    rcode	= EXIT_SUCCESS;
	char const	   *output_file = NULL;
	TALLOC_CTX	   *autofree;
	main_config_t	   *config = NULL;
	fr_dict_t	   *dict   = NULL;
	struct json_object *root   = NULL;

	autofree = talloc_autofree_context();

	config = main_config_alloc(autofree);
	if (!config) {
		fr_perror("radconf2json");
		fr_exit_now(EXIT_FAILURE);
	}

	main_config_name_set_default(config, "radiusd", false);

	fr_talloc_fault_setup();
	fr_debug_lvl = 0;
	fr_time_start();

	default_log.dst		= L_DST_STDERR;
	default_log.fd		= STDERR_FILENO;
	default_log.print_level = true;

	while ((c = getopt(argc, argv, "d:D:hn:o:xX")) != -1) {
		switch (c) {
		case 'd':
			main_config_confdir_set(config, optarg);
			break;

		case 'D':
			main_config_dict_dir_set(config, optarg);
			break;

		case 'h':
			usage(EXIT_SUCCESS);

		case 'n':
			config->name = optarg;
			break;

		case 'o':
			output_file = optarg;
			break;

		case 'X':
			fr_debug_lvl += 2;
			break;

		case 'x':
			fr_debug_lvl++;
			break;

		default:
			usage(EXIT_FAILURE);
		}
	}

#ifdef WITH_TLS
	if (fr_openssl_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}
#endif

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Opt in to comment preservation - the runtime server parser
	 *	drops them, but we want a faithful round-trip through JSON.
	 */
	cf_preserve_comments_set(true);

	modules_init(config->lib_dir);

	if (!fr_dict_global_ctx_init(NULL, true, config->dict_dir)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

#ifdef WITH_TLS
	if (fr_tls_dict_init() < 0) EXIT_WITH_FAILURE;
#endif

	if (fr_dict_read(dict, config->confdir, FR_DICTIONARY_FILE) == -1) {
		PERROR("Failed to initialize the dictionaries");
		EXIT_WITH_FAILURE;
	}

	if (request_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (unlang_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (modules_rlm_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (virtual_servers_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (main_config_init(config) < 0) {
		EXIT_WITH_FAILURE;
	}

	root = build_section(config->root_cs);

	{
		char const *json_str =
			json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

		if (output_file) {
			FILE *out = fopen(output_file, "w");
			if (!out) {
				fprintf(stderr, "Failed opening %s: %s\n", output_file, fr_syserror(errno));
				EXIT_WITH_FAILURE;
			}
			fputs(json_str, out);
			fputc('\n', out);
			fclose(out);
		} else {
			fputs(json_str, stdout);
			fputc('\n', stdout);
		}
	}

finish:
	if (root) json_object_put(root);
	main_config_free(&config);
	return rcode;
}
