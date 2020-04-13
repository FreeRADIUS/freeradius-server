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
 * @file src/bin/radmin.c
 * @brief Internal implementation of radmin
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/radmin.h>

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/socket.h>

#ifdef HAVE_LIBREADLINE

/*
 *	Readline headers aren't compliant
 */
DIAG_OFF(strict-prototypes)
# include <stdio.h>
#if defined(HAVE_READLINE_READLINE_H)
#  include <readline/readline.h>
#  define USE_READLINE (1)
#elif defined(HAVE_READLINE_H)
#  include <readline.h>
#  define USE_READLINE (1)
#endif /* !defined(HAVE_READLINE_H) */

#ifdef HAVE_READLINE_HISTORY
#  if defined(HAVE_READLINE_HISTORY_H)
#    include <readline/history.h>
#    define USE_READLINE_HISTORY (1)
#  elif defined(HAVE_HISTORY_H)
#    include <history.h>
#    define USE_READLINE_HISTORY (1)
#endif /* defined(HAVE_READLINE_HISTORY_H) */
#endif /* HAVE_READLINE_HISTORY */
#endif /* HAVE_LIBREADLINE */
DIAG_ON(strict-prototypes)

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#include <gperftools/profiler.h>
#endif

static pthread_t cli_pthread_id;
static bool cli_started = false;
static bool stop = false;
static int context = 0;
static fr_cmd_info_t radmin_info;
static TALLOC_CTX *radmin_ctx = NULL;

#ifndef USE_READLINE
/*
 *	@todo - use thread-local storage
 */
static char readline_buffer[1024];

static char *readline(char const *prompt)
{
	char *line, *p;

	if (prompt && *prompt) puts(prompt);
	fflush(stdout);

	line = fgets(readline_buffer, sizeof(readline_buffer), stdin);
	if (!line) return NULL;

	p = strchr(line, '\n');
	if (!p) {
		fprintf(stderr, "Input line too long\n");
		fr_exit_now(EXIT_FAILURE);
	}

	*p = '\0';

	/*
	 *	Strip off leading spaces.
	 */
	for (p = line; *p != '\0'; p++) {
		if ((p[0] == ' ') ||
		    (p[0] == '\t')) {
			line = p + 1;
			continue;
		}

		if (p[0] == '#') {
			line = NULL;
			break;
		}

		break;
	}

	/*
	 *	Comments: keep going.
	 */
	if (!line) return line;

	/*
	 *	Strip off CR / LF
	 */
	for (p = line; *p != '\0'; p++) {
		if ((p[0] == '\r') ||
		    (p[0] == '\n')) {
			p[0] = '\0';
			break;
		}
	}

	return line;
}
#define radmin_free(_x)
#else
#define radmin_free free
#endif

#ifndef USE_READLINE_HISTORY
static void add_history(UNUSED char *line)
{
}
#endif

static fr_cmd_t *radmin_cmd = NULL;
static char *radmin_partial_line = NULL;
static char *radmin_buffer = NULL;

#define CMD_MAX_ARGV (32)
#define CMD_MAX_EXPANSIONS (128)

static int cmd_exit(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info);
static main_config_t *radmin_main_config = NULL;

#ifdef USE_READLINE
/*
 *	Global variables because readline() is stupid.
 */
static int radmin_num_expansions;
static char *radmin_expansions[CMD_MAX_EXPANSIONS] = {0};

static char *
radmin_expansion_walk(UNUSED const char *text, int state)
{
    static int current;
    char *name;

    if (!state) {
	    current = 0;
    }

    /*
     *	fr_command_completions() takes care of comparing things to
     *	suppress expansions which don't match "text"
     */
    if (current >= radmin_num_expansions) return NULL;

    name = radmin_expansions[current];
    radmin_expansions[current++] = NULL;
    return name;
}


static char **
radmin_completion(const char *text, int start, UNUSED int end)
{
	int num;
	size_t offset;
	char **expansions = &radmin_expansions[0];
	char const **expansions_const;

	rl_attempted_completion_over = 1;

	fr_assert(radmin_buffer != NULL);
	fr_assert(radmin_partial_line != NULL);
	fr_assert(radmin_partial_line >= radmin_buffer);
	fr_assert(radmin_partial_line < (radmin_buffer + 8192));

	offset = (radmin_partial_line - radmin_buffer);

	strlcpy(radmin_partial_line, rl_line_buffer, 8192 - offset);

	memcpy(&expansions_const, &expansions, sizeof(expansions)); /* const issues */
	num = fr_command_complete(radmin_cmd, radmin_buffer, start + offset,
				  CMD_MAX_EXPANSIONS, expansions_const);
	if (num <= 0) return NULL;

	radmin_num_expansions = num;

	return rl_completion_matches(text, radmin_expansion_walk);
}

static int radmin_help(UNUSED int count, UNUSED int key)
{
	size_t offset;
	printf("\n");

	offset = (radmin_partial_line - radmin_buffer);
	strlcpy(radmin_partial_line, rl_line_buffer, 8192 - offset);

	(void) fr_command_print_help(stdout, radmin_cmd, radmin_buffer);
	rl_on_new_line();
	return 0;
}

#endif	/* USE_READLINE */


static void *fr_radmin(UNUSED void *input_ctx)
{
	int argc = 0;
	int *context_exit, *context_offset;
	char const *prompt;
	size_t size;
	TALLOC_CTX *ctx;
	fr_cmd_info_t *info = &radmin_info;

	context = 0;
	prompt = "radmin> ";

	ctx = talloc_init("radmin");

	size = 8192;
	radmin_buffer = talloc_zero_array(ctx, char, size);

	fr_command_info_init(ctx, info);

	context_exit = talloc_zero_array(ctx, int, CMD_MAX_ARGV + 1);
	context_offset = talloc_zero_array(ctx, int, CMD_MAX_ARGV + 1);
	context_offset[0] = 0;

	fflush(stdout);

#ifdef USE_READLINE
	rl_attempted_completion_function = radmin_completion;

	(void) rl_bind_key('?', radmin_help);
#endif

	while (true) {
		char *line;

		fr_assert(context >= 0);
		fr_assert(context_offset[context] >= 0);
		radmin_partial_line = radmin_buffer + context_offset[context];
		line = readline(prompt);
		if (stop) break;

		if (!line) continue;

		if (!*line) {
			radmin_free(line);
			continue;
		}

		/*
		 *	Special-case commands in sub-contexts.
		 */
		if (context > 0) {
			/*
			 *	Special-case "quit", which works everywhere.
			 *	It closes the CLI immediately.
			 */
			if (strcmp(line, "quit") == 0) {
				cmd_exit(stdout, stderr, NULL, info);
				goto next;
			}

			/*
			 *	Allow exiting from the current context.
			 */
			if (strcmp(line, "exit") == 0) {
				talloc_const_free(prompt);
				context = context_exit[context];
				if (context == 0) {
					prompt = "radmin> ";
				} else {
					prompt = talloc_asprintf(ctx, "... %s> ", info->argv[context - 1]);
				}
				info->runnable = false;
				goto next;
			}
		}

		/*
		 *	"line" is dynamically allocated and we don't
		 *	want argv[] pointing to it.  Also, splitting
		 *	the line mangles it in-place.  So we need to
		 *	copy the line to "current_str" for splitting.
		 *	We also copy it to "current_line" for adding
		 *	to the history.
		 *
		 *	@todo - we need a smart history which adds the
		 *	FULL line to the history, and then on
		 *	up-arrow, only produces the RELEVANT line from
		 *	the current context.
		 */
		strlcpy(radmin_buffer + context_offset[context], line,
			size - context_offset[context]);
		argc = fr_command_str_to_argv(radmin_cmd, info, radmin_buffer);

		/*
		 *	Parse error!  Oops..
		 */
		if (argc < 0) {
			fprintf(stderr, "Failed parsing line: %s\n", fr_strerror());
			add_history(line); /* let them up-arrow and retype it */
			goto next;
		}

		/*
		 *	Skip blank lines.
		 */
		if (argc == context) continue;

		/*
		 *	It's a partial command.  Add it to the context
		 *	and continue.
		 *
		 *	Note that we have to update `current_str`, because
		 *	argv[context] currently points there...
		 */
		if (!info->runnable) {
			size_t len;

			fr_assert(argc > 0);
			len = strlen(line);

			/*
			 *	Not enough room for more commands, refuse to do it.
			 */
			if ((context_offset[context] + len + 80) >= size) {
				fprintf(stderr, "Too many commands!\n");
				goto next;
			}

			/*
			 *	Move the pointer down the buffer and
			 *	keep reading more.
			 */

			if (context > 0) {
				talloc_const_free(prompt);
			}

			/*
			 *	Remember how many arguments we
			 *	added in this context, and go back up
			 *	that number of arguments when entering
			 *	'exit'.
			 *
			 *	Otherwise, entering a partial command
			 *	"foo bar baz" would require you to
			 *	type "exit" 3 times in order to get
			 *	back to the root.
			 */
			context_exit[argc] = context;
			context_offset[argc] = context_offset[context] + len + 1;
			radmin_buffer[context_offset[context] + len] = ' ';
			context = argc;
			prompt = talloc_asprintf(ctx, "... %s> ", info->argv[context - 1]);
			goto next;
		}

		/*
		 *	Else it's a info->runnable command.  Add it to the
		 *	history.
		 */
		add_history(line);

		if (fr_command_run(stdout, stderr, info, false) < 0) {
			fprintf(stderr, "Failed running command.\n");
		}

	next:
		/*
		 *	Reset this to the current context.
		 */
		if (fr_command_clear(context, info) < 0) {
			fprintf(stderr, "Failing clearing buffers: %s\n", fr_strerror());
			break;
		}

		radmin_free(line);

		if (stop) break;
	}

	talloc_free(ctx);
	radmin_buffer = NULL;
	radmin_partial_line = NULL;

	return NULL;
}


/** radmin functions, tables, and callbacks
 *
 */
static fr_time_delta_t start_time;

static int cmd_exit(UNUSED FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	main_loop_signal_self(RADIUS_SIGNAL_SELF_TERM);
	stop = true;

	return 0;
}

static int cmd_help(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	int max = 1;
	int options = FR_COMMAND_OPTION_HELP;

	if (info->argc > 0) {
		if (strcmp(info->argv[0], "all") == 0) {
			max = CMD_MAX_ARGV;
		}
		else if (strcmp(info->argv[0], "commands") == 0) {
			max = CMD_MAX_ARGV;
			options = FR_COMMAND_OPTION_NONE;
		}
	}

	fr_command_list(fp, max, radmin_cmd, options);

	return 0;
}

static int cmd_terminate(UNUSED FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	main_loop_signal_self(RADIUS_SIGNAL_SELF_TERM);
	return 0;
}

static int cmd_uptime(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	fr_time_delta_t uptime;

	uptime = fr_time() - start_time;

	fr_fprintf(fp, "Uptime: %pVs seconds\n", fr_box_time_delta(uptime));

	return 0;
}

static int cmd_stats_memory(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	if (!radmin_main_config->talloc_memory_report) {
		fprintf(fp, "Statistics are only available when the server is started with '-M'.\n");
		return -1;
	}

	if (strcmp(info->argv[0], "total") == 0) {
		fprintf(fp, "%zd\n", talloc_total_size(NULL));
		return 0;
	}

	if (strcmp(info->argv[0], "blocks") == 0) {
		fprintf(fp, "%zd\n", talloc_total_blocks(NULL));
		return 0;
	}

	if (strcmp(info->argv[0], "full") == 0) {
		fprintf(fp, "see stdout of the server for the full report.\n");
		fr_log_talloc_report(NULL);
		return 0;
	}

	/*
	 *	Should never reach here.  The command parser will
	 *	ensure that.
	 */
	fprintf(fp_err, "Must use 'stats memory (blocks|full|total)'\n");
	return -1;
}

static int cmd_set_debug_level(UNUSED FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	int level = atoi(info->argv[0]);

	if ((level < 0) || level > 5) {
		fprintf(fp_err, "Invalid debug level '%s'\n", info->argv[0]);
		return -1;
	}

	fr_debug_lvl = level;
	return 0;
}

static int cmd_show_debug_level(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	fprintf(fp, "%d\n", fr_debug_lvl);
	return 0;
}

#ifdef HAVE_GPERFTOOLS_PROFILER_H
static int cmd_set_profile_status(UNUSED FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	fr_value_box_t box;
	fr_type_t type = FR_TYPE_BOOL;
	struct ProfilerState state;

	if (fr_value_box_from_str(NULL, &box, &type, NULL, info->argv[0], strlen(info->argv[0]), '\0', false) < 0) {
		fprintf(fp_err, "Failed setting profile status '%s' - %s\n", info->argv[0], fr_strerror());
		return -1;
	}

	ProfilerGetCurrentState(&state);

	if (box.vb_bool) {
		char *filename;

		if (state.enabled) {
			fprintf(fp_err, "Profiling is already on, to file %s\n", state.profile_name);
			return -1;
		}

		if (info->argc >= 2) {
			memcpy(&filename, &info->argv[1], sizeof(filename)); /* const issues */
		} else {
			filename = getenv("FR_PROFILE_FILENAME");
		}

		if (filename) {
			ProfilerStart(filename);
		} else {
			pid_t pid = getpid();
			MEM(filename = talloc_asprintf(NULL, "/tmp/freeradius-profile.%u.prof", pid));
			ProfilerStart(filename);
			talloc_free(filename);
		}

	} else if (state.enabled) {
		ProfilerFlush();
		ProfilerStop();
	}
	/*
	 *	Else profiling is already off, allow the admin to turn
	 *	it off again without producing an error
	 */

	return 0;
}

static int cmd_show_profile_status(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	struct ProfilerState state;
	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		fprintf(fp, "off\n");
		return 0;
	}

	fprintf(fp, "on %s\n", state.profile_name);
	return 0;
}
#endif

static int tab_expand_config_thing(TALLOC_CTX *talloc_ctx, UNUSED void *ctx, fr_cmd_info_t *info, int max_expansions, char const **expansions,
				   bool want_section)
{
	int count;
	size_t reflen, offset;
	char *ref;
	char const *text;
	CONF_ITEM *ci;
	CONF_SECTION *cs;

	if (info->argc <= 0) return 0;

	ref = talloc_strdup(talloc_ctx, info->argv[info->argc - 1]);
	text = strrchr(ref, '.');
	if (!text) {
		cs = radmin_main_config->root_cs;
		reflen = 0;
		offset = 0;
		text = ref;

		/*
		 *	If it's a good ref, use that for expansions.
		 */
		ci = cf_reference_item(radmin_main_config->root_cs, radmin_main_config->root_cs, ref);
		if (ci && cf_item_is_section(ci)) {
			cs = cf_item_to_section(ci);
			text = "";
			reflen = strlen(ref);
			offset = 1;
		}

	} else {
		reflen = (text - ref);
		offset = 1;
		ref[reflen] = '\0';
		text++;

		ci = cf_reference_item(radmin_main_config->root_cs, radmin_main_config->root_cs, ref);
		if (!ci) {
		none:
			talloc_free(ref);
			return 0;
		}

		/*
		 *	The ref is to a pair.  Don't allow further
		 *	expansions.
		 */
		if (cf_item_is_pair(ci)) goto none;
		cs = cf_item_to_section(ci);
	}

	count = 0;

	/*
	 *	Walk the reference, allowing for additional expansions.
	 */
	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		char const *name1, *check;
		char *str;
		char buffer[256];

		/*
		 *	@todo - if we want a config pair, AND we have
		 *	partial input, THEN check if the section name
		 *	matches the partial input.  If so, allow it as
		 *	an expansion.
		 */
		if (cf_item_is_section(ci)) {
			char const *name2;

			name1 = cf_section_name1(cf_item_to_section(ci));
			name2 = cf_section_name2(cf_item_to_section(ci));

			if (name2) {
				snprintf(buffer, sizeof(buffer), "%s[%s]", name1, name2);
				check = buffer;
			} else {
				check = name1;
			}

			if (!want_section) {
				if (*text && fr_command_strncmp(text, check)) {
					// @todo - expand the pairs in this section
					goto add;
				}

				continue;
			}

		} else if (!cf_item_is_pair(ci)) {
			continue;

		} else {
			if (want_section) continue;

			name1 = cf_pair_attr(cf_item_to_pair(ci));
			check = name1;
		}

		/*
		 *	Check for a matching name.
		 */
		if (!fr_command_strncmp(text, check)) continue;

	add:
		expansions[count] = str = malloc(reflen + strlen(check) + offset + 1);
		memcpy(str, ref, reflen);
		str[reflen] = '.';
		strcpy(str + reflen + offset, check);

		count++;
		if (count >= max_expansions) return count;
	}

	return count;
}

static int cmd_show_config_section(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	CONF_ITEM *item;

	fr_assert(info->argc > 0);

	item = cf_reference_item(radmin_main_config->root_cs, radmin_main_config->root_cs,
				 info->box[0]->vb_strvalue);
	if (!item || !cf_item_is_section(item)) {
		fprintf(fp_err, "No such configuration section.\n");
		return -1;
	}

	(void) cf_section_write(fp, cf_item_to_section(item), 0);

	return 0;
}


static int tab_expand_config_section(TALLOC_CTX *talloc_ctx, void *ctx, fr_cmd_info_t *info, int max_expansions, char const **expansions)
{
	return tab_expand_config_thing(talloc_ctx, ctx, info, max_expansions, expansions, true);
}

static int tab_expand_config_item(TALLOC_CTX *talloc_ctx, void *ctx, fr_cmd_info_t *info, int max_expansions, char const **expansions)
{
	return tab_expand_config_thing(talloc_ctx, ctx, info, max_expansions, expansions, false);
}

static int cmd_show_config_item(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	FR_TOKEN token;
	CONF_ITEM *item;
	CONF_PAIR *cp;

	fr_assert(info->argc > 0);

	item = cf_reference_item(radmin_main_config->root_cs, radmin_main_config->root_cs,
				 info->box[0]->vb_strvalue);
	if (!item || !cf_item_is_pair(item)) {
		fprintf(fp_err, "No such configuration item.\n");
		return -1;
	}

	cp = cf_item_to_pair(item);
	token = cf_pair_value_quote(cp);

	if (token == T_BARE_WORD) {
	bare:
		fprintf(fp, "%s\n", cf_pair_value(cp));
	} else {
		char quote;
		char *value;

		switch (token) {
		case T_DOUBLE_QUOTED_STRING:
			quote = '"';
			break;

		case T_SINGLE_QUOTED_STRING:
			quote = '\'';
			break;

		case T_BACK_QUOTED_STRING:
			quote = '`';
			break;

		default:
			goto bare;
		}

		value = fr_asprint(NULL, cf_pair_value(cp), -1, quote);
		fprintf(fp, "%c%s%c\n", quote, value, quote);
		talloc_free(value);
	}

	return 0;
}

static int cmd_show_client(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	RADCLIENT *client;

	if (info->argc >= 2) {
		int proto;

		if (strcmp(info->argv[1], "tcp") == 0) {
			proto = IPPROTO_TCP;

		} else if (strcmp(info->argv[1], "udp") == 0) {
			proto = IPPROTO_TCP;

		} else {
			fprintf(fp_err, "Unknown proto '%s'.\n", info->argv[1]);
			return -1;
		}

		client = client_find(NULL, &info->box[0]->vb_ip, proto);
		if (client) goto found;

	not_found:
		fprintf(fp_err, "No such client.\n");
		return -1;
	} else {
		client = client_find(NULL, &info->box[0]->vb_ip, IPPROTO_IP); /* hack */
		if (!client) goto not_found;
	}

found:
	fprintf(fp, "shortname\t%s\n", client->shortname);
	fprintf(fp, "secret\t\t%s\n", client->secret);

	if (client->proto == IPPROTO_UDP) {
		fprintf(fp, "proto\t\tudp\n");

	} else if (client->proto == IPPROTO_TCP) {
		fprintf(fp, "proto\t\ttcp\n");
	} else {
		fprintf(fp, "proto\t\t*\n");
	}

	return 0;
}

//#define CMD_TEST (1)

#ifdef CMD_TEST
static int cmd_test(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	int i;

	fprintf(fp, "TEST %d\n", info->argc);

	for (i = 0; i < info->argc; i++) {
		fprintf(fp, "\t%s\n", info->argv[i]);
	}

	return 0;
}

static int cmd_test_tab_expand(UNUSED TALLOC_CTX *talloc_ctx, UNUSED void *ctx, fr_cmd_info_t *info, UNUSED int max_expansions, char const **expansions)
{
	char const *text;
	char *p;

	if (info->argc == 0) return 0;

	text = info->argv[info->argc - 1];

	/*
	 *	Expand a list of things
	 */
	if (!*text) {
		expansions[0] = strdup("0");
		expansions[1] = strdup("1");
		return 2;
	}

	if ((text[0] < '0') || (text[0] > '9')) {
		return 0;
	}

	/*
	 *	If the user enters a digit, allow it.
	 */
	expansions[0] = p = malloc(2);
	p[0] = text[0];
	p[1] = '\0';

	return 1;
}
#endif

static fr_cmd_table_t cmd_table[] = {
	{
		.name = "exit",
		.func = cmd_exit,
		.help = "Exit from the current context.",
		.read_only = true
	},

	{
		.name = "quit",
		.func = cmd_exit,
		.help = "Quit and close the command line immediately.",
		.read_only = true
	},

	{
		.name = "help",
		.syntax = "[(all|commands)]",
		.func = cmd_help,
		.help = "Display list of commands and their help text.",
		.read_only = true
	},


	{
		.name = "terminate",
		.func = cmd_terminate,
		.help = "Terminate the running server and cause it to exit.",
		.read_only = false
	},


#ifdef CMD_TEST
	{
		.parent = "test",
		.name = "foo"
		.syntax = "INTEGER",
		.func = cmd_test,
		.tab_expand = cmd_test_tab_expand,
		.help = "test foo INTEGER",
		.read_only = true,
	},
#endif

	{
		.name = "uptime",
		.func = cmd_uptime,
		.help = "Show uptime since the server started.",
		.read_only = true
	},

	{
		.name = "set",
		.help = "Change settings in the server.",
		.read_only = false
	},

	{
		.name = "show",
		.help = "Show settings in the server.",
		.read_only = true
	},

	{
		.parent = "show",
		.name = "config",
		.help = "Show configuration settings in the server.",
		.read_only = true
	},

	{
		.parent = "show config",
		.name = "section",
		.syntax = "STRING",
		.help = "Show a named configuration section",
		.func = cmd_show_config_section,
		.tab_expand = tab_expand_config_section,
		.read_only = true
	},

	{
		.parent = "show config",
		.name = "item",
		.syntax = "STRING",
		.help = "Show a named configuration item",
		.func = cmd_show_config_item,
		.tab_expand = tab_expand_config_item,
		.read_only = true
	},

	{
		.parent = "show",
		.name = "client",
		.help = "Show information about a client or clients.",
		.read_only = true
	},

	{
		.parent = "show client",
		.name = "config",
		.syntax = "IPADDR [(udp|tcp)]",
		.help = "Show the configuration for a given client.",
		.func = cmd_show_client,
		.read_only = true
	},

	{
		.name = "stats",
		.help = "Show statistics in the server.",
		.read_only = true
	},

	{
		.parent = "stats",
		.name = "memory",
		.syntax = "(blocks|full|total)",
		.func = cmd_stats_memory,
		.help = "Show memory statistics.",
		.read_only = true,
	},

	{
		.parent = "set",
		.name = "debug",
		.help = "Change debug settings.",
		.read_only = false
	},

	{
		.parent = "set debug",
		.name = "level",
		.syntax = "INTEGER",
		.func = cmd_set_debug_level,
		.help = "Change the debug level.",
		.read_only = false,
	},

	{
		.parent = "show",
		.name = "debug",
		.help = "Show debug settings.",
		.read_only = true
	},

	{
		.parent = "show debug",
		.name = "level",
		.func = cmd_show_debug_level,
		.help = "show debug level",
		.read_only = true,
	},

#ifdef HAVE_GPERFTOOLS_PROFILER_H
	{
		.parent = "set",
		.name = "profile",
		.help = "Change profiler settings.",
		.read_only = false
	},

	{
		.parent = "set profile",
		.name = "status",
		.syntax = "BOOL [STRING]",
		.func = cmd_set_profile_status,
		.help = "Change the profiler status on/off, and potentially the filename",
		.read_only = false,
	},

	{
		.parent = "show",
		.name = "profile",
		.help = "Show profile settings.",
		.read_only = true
	},

	{
		.parent = "show profile",
		.name = "status",
		.func = cmd_show_profile_status,
		.help = "show profile status, including filename if profiling is on.",
		.read_only = true,
	},
#endif

	CMD_TABLE_END
};

int fr_radmin_start(main_config_t *config, bool cli)
{
	radmin_ctx = talloc_init("radmin");
	if (!radmin_ctx) return -1;

	start_time = fr_time();

#ifdef USE_READLINE
	memcpy(&rl_readline_name, &config->name, sizeof(rl_readline_name)); /* const issues on OSX */
#endif

	fr_command_register_hook = fr_radmin_register;
	radmin_main_config = config;

	if (fr_radmin_register(radmin_ctx, NULL, NULL, cmd_table) < 0) {
		PERROR("Failed initializing radmin");
		return -1;
	}

	if (!cli) return 0;

	/*
	 *	Note that the commands are registered by the main
	 *	thread.  That registration is done in a (mostly)
	 *	thread-safe manner.  So that asynchronous searches
	 *	won't go into la-la-land.  They might find unfinished
	 *	commands, but they don't crash.
	 */
	if (fr_schedule_pthread_create(&cli_pthread_id, fr_radmin, NULL) < 0) {
		PERROR("Failed creating radmin thread");
		return -1;
	}
	cli_started = true;

	return 0;
}

void fr_radmin_stop(void)
{
	if (!radmin_ctx) return;

	stop = true;

	if (cli_started) {
		(void) pthread_join(cli_pthread_id, NULL);
		cli_started = false;
	}

	TALLOC_FREE(radmin_ctx);
}

/*
 *	Public registration hooks.
 */
int fr_radmin_register(UNUSED TALLOC_CTX *talloc_ctx, char const *name, void *ctx, fr_cmd_table_t *table)
{
	return fr_command_add_multi(radmin_ctx, &radmin_cmd, name, ctx, table);
}

/** Run a command from an input string.
 *
 * @param info used to stor
 * @param fp standard output
 * @param fp_err error output
 * @param str the command to run.  Note that this command is mangled in-place!
 * @param read_only permissions for the administrator trying to run the command.
 * @return
 *	- <0 on error
 *	- 0 on insufficient arguments to run command
 *	- 1 for successfully running the command
 */
int fr_radmin_run(fr_cmd_info_t *info, FILE *fp, FILE *fp_err, char *str, bool read_only)
{
	int argc, rcode;

	argc = fr_command_str_to_argv(radmin_cmd, info, str);
	if (argc < 0) {
		fprintf(fp_err, "%s\n", fr_strerror());
		return -1;
	}

	if (!info->runnable) {
		return 0;
	}

	rcode = fr_command_run(fp, fp_err, info, read_only);
	fflush(fp);
	fflush(fp_err);

	/*
	 *	reset "info" to be a top-level context again.
	 */
	(void) fr_command_clear(0, info);

	if (rcode < 0) return rcode;

	return 1;
}

/*
 *	Get help for a particular line of text.
 */
void fr_radmin_help(FILE *fp, char const *text)
{
	fr_command_print_help(fp, radmin_cmd, text);
}

void fr_radmin_complete(FILE *fp, const char *text, int start)
{
	int i, num;
	char *my_expansions[CMD_MAX_EXPANSIONS];
	char **expansions = &my_expansions[0];
	char const **expansions_const;

	memcpy(&expansions_const, &expansions, sizeof(expansions)); /* const issues */

	num = fr_command_complete(radmin_cmd, text, start,
				  CMD_MAX_EXPANSIONS, expansions_const);
	if (num <= 0) return;

	for (i = 0; i < num; i++) {
		fprintf(fp, "%s\n", expansions[i]);
		free(expansions[i]);
	}
}
