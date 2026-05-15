/*
 * radconf2json.c   Dump a parsed FreeRADIUS v3 configuration tree as JSON.
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

#include <freeradius-devel/libradius.h>

/*
 *	log.h references REQUEST in function signatures.  Forward-declare
 *	it opaquely so we don't have to drag in radiusd.h (and the whole
 *	server-side world) just to get default_log / L_DST_STDERR.
 */
typedef struct rad_request REQUEST;

#include <freeradius-devel/conf.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/log.h>
#include <freeradius-devel/radpaths.h>

#include <json-c/json.h>

/*
 *	JSON_C_TO_STRING_NOSLASHESCAPE arrived in json-c 0.13.  CentOS 7
 *	ships 0.11; map to a no-op there so the call site stays uniform.
 *	The only effect is "/" coming out as "\/" - still valid JSON.
 */
#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#  define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#include <sys/wait.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

/*
 *	exec.c in libfreeradius-server.a uses these; satisfy the link
 *	without dragging threads.c in.  Same trick radattr / radwho use.
 */
#ifdef HAVE_PTHREAD_H
pid_t rad_fork(void);
pid_t rad_waitpid(pid_t pid, int *status);

pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}
#endif

/*
 *	Token names use the v4-style identifier set so the converter
 *	sees a single schema across both versions.  T_INVALID is the
 *	sentinel for "no quoting recorded", which round-trips back to
 *	an unquoted bare word.
 */
static char const *quote_name(FR_TOKEN t)
{
	static char const * const names[T_TOKEN_LAST] = {
		[T_DOUBLE_QUOTED_STRING] = "T_DOUBLE_QUOTED_STRING",
		[T_SINGLE_QUOTED_STRING] = "T_SINGLE_QUOTED_STRING",
		[T_BACK_QUOTED_STRING]   = "T_BACK_QUOTED_STRING",
	};

	if ((unsigned int)t < T_TOKEN_LAST && names[t]) return names[t];
	return "T_BARE_WORD";
}

static char const *op_name(FR_TOKEN op)
{
	static char const * const names[T_TOKEN_LAST] = {
		[T_OP_ADD]       = "+=",
		[T_OP_SUB]       = "-=",
		[T_OP_SET]       = ":=",
		[T_OP_EQ]        = "=",
		[T_OP_NE]        = "!=",
		[T_OP_GE]        = ">=",
		[T_OP_GT]        = ">",
		[T_OP_LE]        = "<=",
		[T_OP_LT]        = "<",
		[T_OP_REG_EQ]    = "=~",
		[T_OP_REG_NE]    = "!~",
		[T_OP_CMP_TRUE]  = "=*",
		[T_OP_CMP_FALSE] = "!*",
		[T_OP_CMP_EQ]    = "==",
		[T_OP_PREPEND]   = "^=",
		[T_OP_INCRM]     = "++",
	};

	if ((unsigned int)op < T_TOKEN_LAST && names[op]) return names[op];
	return "?";
}

static struct json_object *build_location(char const *filename, int lineno)
{
	struct json_object *loc;

	if (!filename && lineno == 0) return NULL;

	loc = json_object_new_object();
	json_object_object_add(loc, "filename", filename ? json_object_new_string(filename) : NULL);
	json_object_object_add(loc, "lineno", json_object_new_int(lineno));
	return loc;
}

static struct json_object *build_section(CONF_SECTION const *cs);

static struct json_object *build_comment(CONF_COMMENT const *c)
{
	struct json_object *o	     = json_object_new_object();
	char const	   *text     = cf_comment_text(c);
	char const	   *filename = cf_comment_filename(c);
	int		    lineno   = cf_comment_lineno(c);
	struct json_object *loc	     = NULL;

	if (filename || lineno) {
		loc = json_object_new_object();
		json_object_object_add(loc, "filename", filename ? json_object_new_string(filename) : NULL);
		json_object_object_add(loc, "lineno", json_object_new_int(lineno));
	}

	json_object_object_add(o, "type", json_object_new_string("comment"));
	json_object_object_add(o, "text", text ? json_object_new_string(text) : NULL);
	json_object_object_add(o, "location", loc);
	return o;
}

static struct json_object *build_pair(CONF_PAIR const *cp)
{
	struct json_object *o	  = json_object_new_object();
	char const	   *value = cf_pair_value(cp);

	json_object_object_add(o, "type", json_object_new_string("pair"));
	json_object_object_add(o, "attr", cf_pair_attr(cp) ? json_object_new_string(cf_pair_attr(cp)) : NULL);
	json_object_object_add(o, "lhs_quote", json_object_new_string(quote_name(cf_pair_attr_type(cp))));
	json_object_object_add(o, "op", json_object_new_string(op_name(cf_pair_operator(cp))));
	json_object_object_add(o, "value", value ? json_object_new_string(value) : NULL);
	json_object_object_add(o, "rhs_quote", json_object_new_string(quote_name(cf_pair_value_type(cp))));
	json_object_object_add(o, "location", build_location(cf_pair_filename(cp), cf_pair_lineno(cp)));

	return o;
}

static struct json_object *build_section(CONF_SECTION const *cs)
{
	struct json_object *o	     = json_object_new_object();
	struct json_object *children = json_object_new_array();
	char const	   *name2    = cf_section_name2(cs);
	CONF_ITEM	   *ci;

	json_object_object_add(o, "type", json_object_new_string("section"));
	json_object_object_add(o, "name1", cf_section_name1(cs) ? json_object_new_string(cf_section_name1(cs)) : NULL);
	json_object_object_add(o, "name2", name2 ? json_object_new_string(name2) : NULL);
	json_object_object_add(o, "name2_quote", json_object_new_string(quote_name(cf_section_name2_type(cs))));
	json_object_object_add(o, "location", build_location(cf_section_filename(cs), cf_section_lineno(cs)));

	for (ci = cf_item_find_next(cs, NULL); ci != NULL; ci = cf_item_find_next(cs, ci)) {
		if (cf_item_is_section(ci)) {
			json_object_array_add(children, build_section(cf_item_to_section(ci)));
		} else if (cf_item_is_pair(ci)) {
			json_object_array_add(children, build_pair(cf_item_to_pair(ci)));
		} else if (cf_item_is_comment(ci)) {
			json_object_array_add(children, build_comment(cf_item_to_comment(ci)));
		}
	}

	json_object_object_add(o, "children", children);
	return o;
}

static NEVER_RETURNS void usage(int rcode)
{
	FILE *fp = (rcode == 0) ? stdout : stderr;

	fprintf(fp,
		"Usage: radconf2json [options]\n"
		"  -d <raddb>    Set raddb directory (default %s).\n"
		"  -E            Keep `${var}` references verbatim in the JSON instead of\n"
		"                resolving them at conversion time.  `$INCLUDE` still fires.\n"
		"  -n <name>     Read <name>.conf instead of radiusd.conf.\n"
		"  -o <file>     Write JSON to <file> (default stdout).\n"
		"  -x            Enable debug output (repeatable).\n"
		"  -X            Verbose debug output.\n"
		"  -h            This help.\n",
		RADIUS_DIR);
	exit(rcode);
}

int main(int argc, char *argv[])
{
	int		    argval;
	int		    rcode	= EXIT_SUCCESS;
	char const	   *raddb_dir	= RADIUS_DIR;
	char const	   *name	= "radiusd";
	char const	   *output_file = NULL;
	char		    filename[PATH_MAX];
	CONF_SECTION	   *cs	 = NULL;
	struct json_object *root = NULL;

	fr_log_fp	= stderr;
	default_log.dst = L_DST_STDERR;
	default_log.fd	= STDERR_FILENO;

	while ((argval = getopt(argc, argv, "d:Ehn:o:xX")) != EOF) {
		switch (argval) {
		case 'd':
			raddb_dir = optarg;
			break;
		case 'E':
			cf_expand_variables_set(false);
			break;
		case 'h':
			usage(0);
		case 'n':
			name = optarg;
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
			usage(1);
		}
	}

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radconf2json");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Opt in to comment preservation so `# ...` lines round-trip
	 *	through JSON.  The runtime server parser leaves this off.
	 */
	cf_preserve_comments_set(true);

	snprintf(filename, sizeof(filename), "%s/%s.conf", raddb_dir, name);

	cs = cf_section_alloc(NULL, "main", NULL);
	if (!cs || (cf_file_read(cs, filename) < 0)) {
		fr_perror("radconf2json");
		rcode = EXIT_FAILURE;
		goto finish;
	}

	root = build_section(cs);

	{
		char const *json_str =
			json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

		if (output_file) {
			FILE *out = fopen(output_file, "w");
			if (!out) {
				fprintf(stderr, "Failed opening %s: %s\n", output_file, fr_syserror(errno));
				rcode = EXIT_FAILURE;
				goto finish;
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
	if (cs) talloc_free(cs);
	return rcode;
}
