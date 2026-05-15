/*
 * radjson2conf.c  Render a FreeRADIUS v4 config JSON tree back to a .conf file.
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
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/syserror.h>

#include <json-c/json.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

char const *radiusd_version = RADIUSD_VERSION_BUILD("radjson2conf");

/*
 *	Symbolic quote-token names (the strings radconf2json emits).  A
 *	small sorted table - fr_table_value_by_str is happy with five
 *	entries and lets us inherit the rest of v4's table machinery.
 */
static fr_table_num_sorted_t const quote_names_table[] = {
	{ L("T_BACK_QUOTED_STRING"), T_BACK_QUOTED_STRING },
	{ L("T_BARE_WORD"), T_BARE_WORD },
	{ L("T_DOUBLE_QUOTED_STRING"), T_DOUBLE_QUOTED_STRING },
	{ L("T_SINGLE_QUOTED_STRING"), T_SINGLE_QUOTED_STRING },
	{ L("T_SOLIDUS_QUOTED_STRING"), T_SOLIDUS_QUOTED_STRING },
};
static size_t quote_names_table_len = NUM_ELEMENTS(quote_names_table);

static inline fr_token_t quote_token(char const *s)
{
	if (!s) return T_BARE_WORD;
	return fr_table_value_by_str(quote_names_table, s, T_BARE_WORD);
}

/*
 *	v4's `fr_tokens_table` already maps operator strings to their
 *	fr_token_t value (it's what the CF parser itself uses).  Reuse
 *	instead of rolling our own.
 */
static inline fr_token_t op_token(char const *s)
{
	if (!s) return T_OP_EQ;
	return fr_table_value_by_str(fr_tokens_table, s, T_OP_EQ);
}

static char const *json_get_str(struct json_object *o, char const *key)
{
	struct json_object *v;
	if (!json_object_object_get_ex(o, key, &v)) return NULL;
	if (!v || json_object_is_type(v, json_type_null)) return NULL;
	return json_object_get_string(v);
}

static int json_get_int(struct json_object *o, char const *key, int dflt)
{
	struct json_object *v;
	if (!json_object_object_get_ex(o, key, &v)) return dflt;
	if (!v || json_object_is_type(v, json_type_null)) return dflt;
	return json_object_get_int(v);
}

/*
 *	Pull `location.filename` / `location.lineno` out of a nested object.
 *	The location object is itself optional - emit nothing if absent.
 */
static void json_get_location(struct json_object *item, char const **filename, int *lineno)
{
	struct json_object *loc;

	if (!json_object_object_get_ex(item, "location", &loc)) {
	error:
		*filename = NULL;
		*lineno	  = 0;
		return;
	}
	if (!loc || json_object_is_type(loc, json_type_null)) goto error;

	*filename = json_get_str(loc, "filename");
	*lineno	  = json_get_int(loc, "lineno", 0);
}

static int build_item(CONF_SECTION *parent, struct json_object *item);

static int build_pair(CONF_SECTION *parent, struct json_object *item)
{
	CONF_PAIR  *cp;
	char const *attr    = json_get_str(item, "attr");
	char const *value   = json_get_str(item, "value");
	char const *op_s    = json_get_str(item, "op");
	char const *lhs_q_s = json_get_str(item, "lhs_quote");
	char const *rhs_q_s = json_get_str(item, "rhs_quote");
	char const *filename;
	int	    lineno;

	json_get_location(item, &filename, &lineno);

	if (!attr) {
		fprintf(stderr, "pair without attr (line %d)\n", lineno);
		return -1;
	}

	cp = cf_pair_alloc(parent, attr, value, op_token(op_s), quote_token(lhs_q_s), quote_token(rhs_q_s));
	if (!cp) return -1;

	/*
	 *	cf_section_write skips pairs whose filename is NULL or
	 *	starts with '<' (the marker for synthetic items).  Default
	 *	to "converted" when the JSON has no location so converter-
	 *	added pairs survive the round-trip.
	 */
	cf_filename_set(cp, (filename && filename[0] != '<') ? filename : "converted");
	cf_lineno_set(cp, lineno > 0 ? lineno : 1);

	return 0;
}

static int build_section_into(CONF_SECTION *parent, struct json_object *item)
{
	CONF_SECTION	   *cs;
	struct json_object *children;
	char const	   *name1 = json_get_str(item, "name1");
	char const	   *name2 = json_get_str(item, "name2");
	char const	   *filename;
	int		    lineno;

	json_get_location(item, &filename, &lineno);

	if (!name1) {
		fprintf(stderr, "section without name1 (line %d)\n", lineno);
		return -1;
	}

	cs = cf_section_alloc(parent, parent, name1, name2);
	if (!cs) return -1;

	if (filename) cf_filename_set(cs, filename);
	if (lineno) cf_lineno_set(cs, lineno);

	if (json_object_object_get_ex(item, "children", &children) && children) {
		size_t n = json_object_array_length(children);
		for (size_t i = 0; i < n; i++) {
			struct json_object *child = json_object_array_get_idx(children, i);
			if (build_item(cs, child) < 0) return -1;
		}
	}

	return 0;
}

static int build_comment(CONF_SECTION *parent, struct json_object *item)
{
	CONF_COMMENT *c;
	char const   *text = json_get_str(item, "text");
	char const   *filename;
	int	      lineno;

	json_get_location(item, &filename, &lineno);

	c = cf_comment_alloc(parent, text);
	if (!c) return -1;

	cf_filename_set(c, (filename && filename[0] != '<') ? filename : "converted");
	cf_lineno_set(c, lineno > 0 ? lineno : 1);
	return 0;
}

/*
 *	JSON `type` -> builder dispatch.  Keep alphabetically sorted so
 *	the fr_table_value_by_str binary search lookup works.
 */
typedef int (*build_fn_t)(CONF_SECTION *parent, struct json_object *item);

static int build_item(CONF_SECTION *parent, struct json_object *item)
{
	static fr_table_ptr_sorted_t const item_builders[] = {
		{ L("comment"), build_comment },
		{ L("pair"), build_pair },
		{ L("section"), build_section_into },
	};
	static size_t item_builders_len = NUM_ELEMENTS(item_builders);

	char const *type = json_get_str(item, "type");
	build_fn_t  build;

	if (!type) {
		fprintf(stderr, "item without type field\n");
		return -1;
	}

	build = (build_fn_t)(uintptr_t)fr_table_value_by_str(item_builders, type, NULL);
	if (!build) {
		fprintf(stderr, "unknown item type %s\n", type);
		return -1;
	}
	return build(parent, item);
}

/*
 *	Build a top-level CONF_SECTION from a JSON object that represents
 *	the root section.  Returns the allocated CONF_SECTION on success,
 *	NULL on failure.
 */
static CONF_SECTION *build_root_section(TALLOC_CTX *ctx, struct json_object *root)
{
	CONF_SECTION	   *cs;
	struct json_object *children;
	char const	   *name1 = json_get_str(root, "name1");
	char const	   *name2 = json_get_str(root, "name2");
	char const	   *filename;
	int		    lineno;

	json_get_location(root, &filename, &lineno);

	if (!name1) name1 = "main";

	cs = cf_section_alloc(ctx, NULL, name1, name2);
	if (!cs) return NULL;

	if (filename) cf_filename_set(cs, filename);
	if (lineno) cf_lineno_set(cs, lineno);

	if (json_object_object_get_ex(root, "children", &children) && children) {
		size_t n = json_object_array_length(children);
		for (size_t i = 0; i < n; i++) {
			struct json_object *child = json_object_array_get_idx(children, i);
			if (build_item(cs, child) < 0) {
				talloc_free(cs);
				return NULL;
			}
		}
	}

	return cs;
}

static NEVER_RETURNS void usage(int rcode)
{
	FILE *fp = (rcode == 0) ? stdout : stderr;

	fprintf(fp, "Usage: radjson2conf [options]\n"
		    "  -i <file>     Read JSON from <file> (default stdin).\n"
		    "  -o <file>     Write conf to <file> (default stdout).\n"
		    "  -r            Strip the root section wrapper, emit children at file scope.\n"
		    "                Use this to produce a radiusd.conf-style top-level file.\n"
		    "  -h            This help.\n");
	exit(rcode);
}

int main(int argc, char *argv[])
{
	int		    c;
	char const	   *input_file	= NULL;
	char const	   *output_file = NULL;
	bool		    strip_root	= false;
	FILE		   *out;
	TALLOC_CTX	   *autofree;
	struct json_object *root_json;
	CONF_SECTION	   *root_cs;
	int		    rcode = EXIT_SUCCESS;

	autofree = talloc_autofree_context();

	/*
	 *	We're rebuilding a CF tree out of JSON, fragment by fragment,
	 *	to emit it back to disk.  Resolving `${var}` references would
	 *	either fail (the variable lives in a sibling fragment, not in
	 *	the one we're parsing) or silently bake values in - both
	 *	wrong for the round-trip.  Keep variables verbatim.
	 */
	cf_expand_variables_set(false);

	while ((c = getopt(argc, argv, "hi:o:r")) != -1) {
		switch (c) {
		case 'h':
			usage(EXIT_SUCCESS);

		case 'i':
			input_file = optarg;
			break;

		case 'o':
			output_file = optarg;
			break;

		case 'r':
			strip_root = true;
			break;

		default:
			usage(EXIT_FAILURE);
		}
	}

	if (input_file) {
		root_json = json_object_from_file(input_file);
		if (!root_json) {
			fprintf(stderr, "Failed to parse %s: %s\n", input_file, json_util_get_last_err());
			return EXIT_FAILURE;
		}
	} else {
		/* Slurp stdin and parse */
		char		     buf[65536];
		size_t		     used = 0;
		ssize_t		     n;
		struct json_tokener *tok = json_tokener_new();

		while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
			root_json = json_tokener_parse_ex(tok, buf, n);
			if (json_tokener_get_error(tok) == json_tokener_continue) continue;
			if (json_tokener_get_error(tok) != json_tokener_success) {
				fprintf(stderr, "JSON parse error: %s\n",
					json_tokener_error_desc(json_tokener_get_error(tok)));
				json_tokener_free(tok);
				return EXIT_FAILURE;
			}
			break;
		}
		(void)used;
		json_tokener_free(tok);

		if (!root_json) {
			fprintf(stderr, "No JSON read from stdin\n");
			return EXIT_FAILURE;
		}
	}

	root_cs = build_root_section(autofree, root_json);
	if (!root_cs) {
		fprintf(stderr, "Failed to build conf tree\n");
		json_object_put(root_json);
		return EXIT_FAILURE;
	}

	if (output_file) {
		out = fopen(output_file, "w");
		if (!out) {
			fprintf(stderr, "Failed opening %s: %s\n", output_file, fr_syserror(errno));
			rcode = EXIT_FAILURE;
			goto finish;
		}
	} else {
		out = stdout;
	}

	/*
	 *	Strip-root: write each child of the synthetic root at file
	 *	scope, no outer `{ ... }`.  cf_section_write_children handles
	 *	the same section/pair/comment dispatch (and blank-run
	 *	collapsing) that cf_section_write does internally; we just
	 *	skip the wrapper.
	 */
	if (strip_root) {
		if (cf_section_write_children(out, root_cs, 0) < 0) {
			fprintf(stderr, "cf_section_write_children failed\n");
			rcode = EXIT_FAILURE;
		}
	} else {
		if (cf_section_write(out, root_cs, 0) < 0) {
			fprintf(stderr, "cf_section_write failed\n");
			rcode = EXIT_FAILURE;
		}
	}
	if (out != stdout) fclose(out);

finish:
	talloc_free(root_cs);
	json_object_put(root_json);
	return rcode;
}
