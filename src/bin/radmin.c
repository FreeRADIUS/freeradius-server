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
 * @copyright 2018 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/radmin.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/rad_assert.h>

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

static pthread_t pthread_id;
static bool stop = false;
static int context;
static fr_cmd_info_t radmin_info;

#ifndef USE_READLINE
/*
 *	@todo - use thread-local storage
 */
static char *readline_buffer[1024];

static char *readline(char const *prompt)
{
	char *line, *p;

	puts(prompt);
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
static char *radmin_buffer = NULL;

#define CMD_MAX_ARGV (32)
#define CMD_MAX_EXPANSIONS (128)

static int cmd_help(FILE *fp, FILE *fp_err, void *ctx, fr_cmd_info_t const *info);
static int cmd_exit(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info);

#ifdef USE_READLINE
/*
 *	Global variables because readline() is stupid.
 */
static int radmin_num_expansions;
static char *radmin_expansions[CMD_MAX_EXPANSIONS] = {0};

static char *
radmin_expansion_walk(const char *text, int state)
{
    static int current, len;
    char *name;

    if (!state) {
	    current = 0;
	    len = strlen(text);
    }

    if (current >= radmin_num_expansions) return NULL;

    while ((name = radmin_expansions[current])) {
	    radmin_expansions[current++] = NULL;

	    if (strncmp(name, text, len) == 0) {
		    return name;
	    }
	    free(name);
    }

    return NULL;
}


static char **
radmin_completion(const char *text, int start, UNUSED int end)
{
	int num;

	rl_attempted_completion_over = 1;

	num = fr_command_complete(radmin_cmd, rl_line_buffer, start, CMD_MAX_EXPANSIONS, radmin_expansions);
	if (num <= 0) return NULL;

	radmin_num_expansions = num;

	return rl_completion_matches(text, radmin_expansion_walk);
}

static int radmin_help(UNUSED int count, UNUSED int key)
{
	char buffer[8192];

	printf("\n");

	/*
	 *	@todo make this not retarded.
	 */
	strlcpy(buffer, radmin_buffer, sizeof(buffer));
	strlcat(buffer, " ", sizeof(buffer));
	strlcat(buffer, rl_line_buffer, sizeof(buffer));

	(void) fr_command_print_help(stdout, radmin_cmd, buffer);
	rl_on_new_line();
	return 0;
}

#endif	/* USE_READLINE */


static void *fr_radmin(UNUSED void *input_ctx)
{
	int argc;
	char *argv_buffer;
	char *current_str, **context_str;
	int *context_exit;
	char const *prompt;
	size_t size, room;
	TALLOC_CTX *ctx;
	fr_cmd_info_t *info = &radmin_info;

	context = 0;
	prompt = "radmin> ";

	ctx = talloc_init("radmin");

	size = room = 8192;
	radmin_buffer = talloc_zero_array(ctx, char, size);
	argv_buffer = talloc_zero_array(ctx, char, size);
	current_str = argv_buffer;

	fr_command_info_init(ctx, info);

	context_exit = talloc_zero_array(ctx, int, CMD_MAX_ARGV + 1);
	context_str = talloc_zero_array(ctx, char *, CMD_MAX_ARGV + 1);
	context_str[0] = argv_buffer;

	fflush(stdout);

#ifdef USE_READLINE
	rl_attempted_completion_function = radmin_completion;

	(void) rl_bind_key('?', radmin_help);
#endif

	while (true) {
		char *line;

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
			 *	We're in a nested command and the user typed
			 *	"help".  Act as if they typed "help ...".
			 *	It's just polite.
			 */
			if (strcmp(line, "help") == 0) {
				cmd_help(stdout, stderr, &radmin_info, info);
				goto next;
			}

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
				current_str = context_str[context];
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
		strlcpy(current_str, line, room);

		/*
		 *	Keep a copy of the full string entered.
		 */
		if (current_str > argv_buffer) {
			radmin_buffer[(current_str - argv_buffer) - 1] = ' ';
		}
		strlcpy(radmin_buffer + (current_str - argv_buffer), line, room);

		argc = fr_command_str_to_argv(radmin_cmd, info, current_str);

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

			rad_assert(argc > 0);
			rad_assert(info->argv[argc - 1] != NULL);
			len = strlen(info->argv[argc - 1]) + 1;

			/*
			 *	Not enough room for more commands, refuse to do it.
			 */
			if (room < (len + 80)) {
				fprintf(stderr, "Too many commands!\n");
				goto next;
			}

			/*
			 *	Move the pointer down the buffer and
			 *	keep reading more.
			 */
			current_str = info->argv[argc - 1] + len;
			room -= len;

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
			context_str[argc] = current_str;
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
			/*
			 *	@todo - send return code to radmin The
			 *	command MUST have already printed the
			 *	error to fp_err.
			 */
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

	return NULL;
}


/** radmin functions, tables, and callbacks
 *
 */
static struct timeval start_time;

static int cmd_exit(UNUSED FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
	stop = true;

	return 0;
}

static int cmd_help(FILE *fp, UNUSED FILE *fp_err, void *ctx, fr_cmd_info_t const *info)
{
	int max = 1;
	fr_cmd_t *cmd = NULL;

	/*
	 *	We're called in a context from `radiusd -r`.  Do magic.
	 */
	if (ctx == &radmin_info) {
		int i;

		rad_assert(radmin_info.argc > 0);

		for (i = radmin_info.argc - 1; i >= 0; i--) {
			if ((cmd = radmin_info.cmd[i]) != NULL) break;
		}

		fr_command_list(fp, 1, cmd, FR_COMMAND_OPTION_LIST_CHILD);
		return 0;
	}

	if ((info->argc > 0) && (strcmp(info->argv[0], "all") == 0)) {
		max = CMD_MAX_ARGV;
	}

	fr_command_list(fp, max, radmin_cmd, FR_COMMAND_OPTION_NONE);

	return 0;
}

static int cmd_uptime(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	fr_timeval_subtract(&now, &now, &start_time);

	fprintf(fp, "Uptime: %u.%06u seconds\n",
		(int) now.tv_sec,
		(int) now.tv_usec);

	return 0;
}

static int cmd_stats_memory(FILE *fp, FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
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
		fprintf(fp_err, "Invalid debug level '%s'", info->argv[0]);
		return -1;
	}

	rad_debug_lvl = fr_debug_lvl = level;
	return 0;
}

static int cmd_show_debug_level(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	fprintf(fp, "%d\n", rad_debug_lvl);
	return 0;
}

#ifdef CMD_TEST
static int cmd_test(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, fr_cmd_info_t const *info)
{
	int i;

	fprintf(fp, "TEST\n");

	for (i = 0; i < info->argc; i++) {
		fprintf(fp, "\t%s\n", info->argv[i]);
	}

	return 0;
}
#endif

static fr_cmd_table_t cmd_table[] = {
	{
		.syntax = "exit",
		.func = cmd_exit,
		.help = "Exit from the current context.",
		.read_only = true
	},

	{
		.syntax = "quit",
		.func = cmd_exit,
		.help = "Quit and close the command line immediately.",
		.read_only = true
	},

	{
		.syntax = "help [all]",
		.func = cmd_help,
		.help = "Display list of commands and their help text.",
		.read_only = true
	},


#ifdef CMD_TEST
	{
		.parent = "test",
		.syntax = "foo (bar|(a|b)|xxx [INTEGER])",
		.func = cmd_test,
		.help = "test foo (bar|(a|b)|xxx [INTEGER])",
		.read_only = true,
	},
#endif

	{
		.syntax = "uptime",
		.func = cmd_uptime,
		.help = "Show uptime since the server started.",
		.read_only = true
	},

	{
		.syntax = "set",
		.help = "Change settings in the server.",
		.read_only = false
	},

	{
		.syntax = "show",
		.help = "Show settings in the server.",
		.read_only = true
	},

	{
		.syntax = "stats",
		.help = "Show statistics in the server.",
		.read_only = true
	},

	{
		.parent = "stats",
		.syntax = "memory (blocks|full|total)",
		.func = cmd_stats_memory,
		.help = "Show memory statistics.",
		.read_only = true,
	},

	{
		.parent = "set",
		.syntax = "debug",
		.help = "Change debug settings.",
		.read_only = false
	},

	{
		.parent = "set debug",
		.syntax = "level INTEGER",
		.func = cmd_set_debug_level,
		.help = "Change the debug level.",
		.read_only = false,
	},

	{
		.parent = "show",
		.syntax = "debug",
		.help = "Show debug settings.",
		.read_only = true
	},

	{
		.parent = "show debug",
		.syntax = "level",
		.func = cmd_show_debug_level,
		.help = "show debug level",
		.read_only = true,
	},

	CMD_TABLE_END
};

int fr_radmin_start(main_config_t *config)
{
	gettimeofday(&start_time, NULL);

#ifdef USE_READLINE
	memcpy(&rl_readline_name, &config->name, sizeof(rl_readline_name)); /* const issues on OSX */
#endif

	fr_command_register_hook = fr_radmin_register;

	if (fr_radmin_register(NULL, NULL, cmd_table) < 0) {
		PERROR("Failed initializing radmin");
		return -1;
	}

	/*
	 *	Note that the commands are registered by the main
	 *	thread.  That registration is done in a (mostly)
	 *	thread-safe manner.  So that asynchronous searches
	 *	won't go into la-la-land.  They might find unfinished
	 *	commands, but they don't crash.
	 */
	if (fr_schedule_pthread_create(&pthread_id, fr_radmin, NULL) < 0) {
		PERROR("Failed creating radmin thread");
		return -1;
	}

	return 0;
}

void fr_radmin_stop(void)
{
	stop = true;

	if (pthread_join(pthread_id, NULL) != 0) {
		fprintf(stderr, "Failed joining radmin thread: %s", fr_syserror(errno));
	}
}

/*
 *	Public registration hooks.
 */
int fr_radmin_register(char const *name, void *ctx, fr_cmd_table_t *table)
{
	return fr_command_add_multi(NULL, &radmin_cmd, name, ctx, table);
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
