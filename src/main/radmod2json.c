/*
 * radmod2json.c   Dump FreeRADIUS v3 module CONF_PARSER definitions as JSON.
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
 *	log.h / modules.h reference REQUEST and rlm_rcode_t.  Both live in
 *	radiusd.h, which drags the whole server-side world along; forward-
 *	declare the bare minimum so the dependent headers parse without
 *	that include.  We only ever read mod->config, never call any of
 *	the method pointers, so opaque definitions are safe.
 */
typedef struct rad_request REQUEST;
typedef int rlm_rcode_t;

#include <freeradius-devel/conf.h>		/* LT_SHREXT */
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/log.h>		/* default_log, L_DST_STDERR */
#include <freeradius-devel/modules.h>		/* module_t */

#include <json-c/json.h>

/*
 *	JSON_C_TO_STRING_NOSLASHESCAPE arrived in json-c 0.13.  CentOS 7
 *	ships 0.11; map to a no-op there so the call site stays uniform.
 *	The only effect is "/" coming out as "\/" - still valid JSON.
 */
#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#  define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#include <dirent.h>
#include <dlfcn.h>
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
 *	Normalise v3 PW_TYPE_* base types into v4's FR_TYPE_* vocabulary so
 *	both dumpers emit the same schema.  Where there is no v4 equivalent
 *	we keep the PW_TYPE_* name verbatim.
 */
static char const *type_name(int type)
{
	/*
	 *	Base-type lookup.  v3 packs flags into the upper bits of `type`
	 *	(PW_TYPE_SUBSECTION etc.); mask to 0xff to get the base PW_TYPE
	 *	value used as the array index.  PW_TYPE_ABINARY has no v4
	 *	equivalent so we keep its v3 spelling.
	 */
	static char const * const names[PW_TYPE_MAX] = {
		[PW_TYPE_INVALID]         = "FR_TYPE_NULL",
		[PW_TYPE_STRING]          = "FR_TYPE_STRING",
		[PW_TYPE_INTEGER]         = "FR_TYPE_UINT32",
		[PW_TYPE_IPV4_ADDR]       = "FR_TYPE_IPV4_ADDR",
		[PW_TYPE_DATE]            = "FR_TYPE_DATE",
		[PW_TYPE_ABINARY]         = "PW_TYPE_ABINARY",
		[PW_TYPE_OCTETS]          = "FR_TYPE_OCTETS",
		[PW_TYPE_IFID]            = "FR_TYPE_IFID",
		[PW_TYPE_IPV6_ADDR]       = "FR_TYPE_IPV6_ADDR",
		[PW_TYPE_IPV6_PREFIX]     = "FR_TYPE_IPV6_PREFIX",
		[PW_TYPE_BYTE]            = "FR_TYPE_UINT8",
		[PW_TYPE_SHORT]           = "FR_TYPE_UINT16",
		[PW_TYPE_ETHERNET]        = "FR_TYPE_ETHERNET",
		[PW_TYPE_SIGNED]          = "FR_TYPE_INT32",
		[PW_TYPE_COMBO_IP_ADDR]   = "FR_TYPE_COMBO_IP_ADDR",
		[PW_TYPE_INTEGER64]       = "FR_TYPE_UINT64",
		[PW_TYPE_IPV4_PREFIX]     = "FR_TYPE_IPV4_PREFIX",
		[PW_TYPE_TIMEVAL]         = "FR_TYPE_TIME_DELTA",
		[PW_TYPE_BOOLEAN]         = "FR_TYPE_BOOL",
		[PW_TYPE_COMBO_IP_PREFIX] = "FR_TYPE_COMBO_IP_PREFIX",
	};
	unsigned int idx = (unsigned int)(type & 0xff);

	if (idx < PW_TYPE_MAX && names[idx]) return names[idx];
	return "FR_TYPE_NULL";
}

static struct json_object *build_flags(int type)
{
	struct json_object *a = json_object_new_array();

#define FLAG(_bit, _name)                                                                   \
	do {                                                                                \
		if (type & (_bit)) json_object_array_add(a, json_object_new_string(_name)); \
	} while (0)

	if ((type & 0xff) == PW_TYPE_SUBSECTION) {
		json_object_array_add(a, json_object_new_string("CONF_FLAG_SUBSECTION"));
	}

	FLAG(PW_TYPE_DEPRECATED, "CONF_FLAG_DEPRECATED");
	FLAG(PW_TYPE_REQUIRED, "CONF_FLAG_REQUIRED");
	FLAG(PW_TYPE_ATTRIBUTE, "CONF_FLAG_ATTRIBUTE");
	FLAG(PW_TYPE_SECRET, "CONF_FLAG_SECRET");
	FLAG(PW_TYPE_XLAT, "CONF_FLAG_XLAT");
	FLAG(PW_TYPE_TMPL, "CONF_FLAG_TMPL");
	FLAG(PW_TYPE_MULTI, "CONF_FLAG_MULTI");
	FLAG(PW_TYPE_NOT_EMPTY, "CONF_FLAG_NOT_EMPTY");
	FLAG(PW_TYPE_IGNORE_DEFAULT, "PW_TYPE_IGNORE_DEFAULT"); /* v3-only */

	if ((type & PW_TYPE_FILE_INPUT) == PW_TYPE_FILE_INPUT)
		json_object_array_add(a, json_object_new_string("CONF_FLAG_FILE_READABLE"));
	if ((type & PW_TYPE_FILE_OUTPUT) == PW_TYPE_FILE_OUTPUT)
		json_object_array_add(a, json_object_new_string("CONF_FLAG_FILE_WRITABLE"));
	if ((type & PW_TYPE_FILE_EXISTS) == PW_TYPE_FILE_EXISTS)
		json_object_array_add(a, json_object_new_string("CONF_FLAG_FILE_EXISTS"));
#undef FLAG
	return a;
}

static struct json_object *build_rules(CONF_PARSER const *rules);

static struct json_object *build_dflt(char const *dflt_str)
{
	struct json_object *o;

	if (!dflt_str) return NULL;
	o = json_object_new_object();
	json_object_object_add(o, "value", json_object_new_string(dflt_str));
	/*
	 *	v3 CONF_PARSER has no per-rule quoting for defaults; the
	 *	parser interprets the dflt string as a bare word unless
	 *	the type or %{...} content says otherwise.
	 */
	json_object_object_add(o, "quote", json_object_new_string("T_BARE_WORD"));
	return o;
}

static struct json_object *build_rule(CONF_PARSER const *r)
{
	struct json_object *o	   = json_object_new_object();
	bool		    is_sub = (r->type & 0xff) == PW_TYPE_SUBSECTION;

	json_object_object_add(o, "name1", r->name ? json_object_new_string(r->name) : NULL);
	json_object_object_add(o, "name2", NULL);
	json_object_object_add(o, "type", json_object_new_string(type_name(r->type)));
	json_object_object_add(o, "flags", build_flags(r->type));

	if (is_sub) {
		json_object_object_add(o, "subcs",
				       r->dflt ? build_rules((CONF_PARSER const *)r->dflt) : json_object_new_array());
	} else {
		json_object_object_add(o, "dflt", build_dflt((char const *)r->dflt));
	}

	return o;
}

static struct json_object *build_rules(CONF_PARSER const *rules)
{
	struct json_object *a = json_object_new_array();

	if (rules) {
		for (CONF_PARSER const *r = rules; r->name; r++) {
			json_object_array_add(a, build_rule(r));
		}
	}
	return a;
}

static char const *module_dir = NULL;

static struct json_object *build_module(char const *name)
{
	void		   *handle;
	module_t const	   *mod;
	struct json_object *m;
	char		    path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s" LT_SHREXT, module_dir, name);

	handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		fprintf(stderr, "%s: dlopen %s: %s\n", name, path, dlerror());
		return NULL;
	}

	mod = dlsym(handle, name);
	if (!mod) {
		fprintf(stderr, "%s: no module symbol exported (%s)\n", name, dlerror());
		dlclose(handle);
		return NULL;
	}

	m = json_object_new_object();
	json_object_object_add(m, "module", json_object_new_string(name));
	json_object_object_add(m, "config", build_rules(mod->config));
	return m;
}

static int dump_module(struct json_object *modules, char const *name)
{
	int   fds[2];
	pid_t pid;
	int   status;

	if (pipe(fds) < 0) {
		fprintf(stderr, "%s: pipe failed: %s\n", name, fr_syserror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		fprintf(stderr, "%s: fork failed: %s\n", name, fr_syserror(errno));
		return -1;
	}

	if (pid == 0) {
		struct json_object *entry;

		close(fds[0]);
		entry = build_module(name);
		if (!entry) {
			fprintf(stderr, "%s: build_module failed\n", name);
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
					fprintf(stderr, "%s: write to pipe failed: %s\n",
						name, fr_syserror(errno));
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
		char	buf[65536];
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
			fprintf(stderr, "%s: child %s (status=0x%x), skipping\n", name,
				WIFEXITED(status) ? "exited non-zero" : "crashed", status);
			return -1;
		}

		if (used > 0) {
			struct json_object *entry = json_tokener_parse(buf);
			if (entry) {
				json_object_array_add(modules, entry);
				return 0;
			}
			fprintf(stderr, "%s: failed to parse child JSON\n", name);
			return -1;
		}
	}

	return -1;
}

static int discover_modules(char const *dir, char ***out_names, size_t *out_count)
{
	DIR	      *d;
	struct dirent *e;
	char	     **names = NULL;
	size_t	       n = 0, alloc = 0;
	size_t	       extlen = strlen(LT_SHREXT);

	d = opendir(dir);
	if (!d) {
		fprintf(stderr, "Failed opening module dir %s: %s\n", dir, fr_syserror(errno));
		return -1;
	}

	while ((e = readdir(d)) != NULL) {
		size_t nlen = strlen(e->d_name);
		char  *name;

		if (nlen <= extlen) continue;
		if (strcmp(e->d_name + nlen - extlen, LT_SHREXT) != 0) continue;
		if (strncmp(e->d_name, "rlm_", 4) != 0 && strncmp(e->d_name, "proto_", 6) != 0) continue;

		if (n == alloc) {
			alloc = alloc ? alloc * 2 : 16;
			names = realloc(names, alloc * sizeof(*names));
		}

		name		    = strdup(e->d_name);
		name[nlen - extlen] = '\0';
		names[n++]	    = name;
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
		    "  -m <list>     Comma-separated list of module names (default: all in -M dir).\n"
		    "  -M <dir>      Module directory to scan.\n"
		    "  -o <file>     Write JSON to <file> (default stdout).\n"
		    "  -x            Enable debug output (repeatable).\n"
		    "  -h            This help.\n");
	exit(rcode);
}

int main(int argc, char *argv[])
{
	int		    argval;
	int		    rcode	= EXIT_SUCCESS;
	char const	   *modules_arg = NULL;
	char const	   *output_file = NULL;
	char		  **names	= NULL;
	size_t		    n_names	= 0;
	char		   *owned_list	= NULL;
	struct json_object *root, *modules;

	default_log.dst = L_DST_STDERR;
	default_log.fd	= STDERR_FILENO;

	while ((argval = getopt(argc, argv, "hm:M:o:x")) != EOF) {
		switch (argval) {
		case 'h':
			usage(0);
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
			usage(1);
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

	if (modules_arg) {
		char  *list = strdup(modules_arg);
		char  *p, *tok;
		size_t alloc = 0;

		owned_list = list;
		for (p = list; (tok = strsep(&p, ",")) != NULL;) {
			if (!*tok) continue;
			if (n_names == alloc) {
				alloc = alloc ? alloc * 2 : 16;
				names = realloc(names, alloc * sizeof(*names));
			}
			names[n_names++] = tok;
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
