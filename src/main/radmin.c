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
 * @file src/main/radmin.c
 * @brief Internal implementation of radmin
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/command.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_LIBREADLINE

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

static pthread_t pthread_id;
static bool stop = false;

#ifndef USE_READLINE
static char *readline_buffer[1024];

static char *readline(char const *prompt)
{
	char *line, *p;

redo:
	puts(prompt);
	fflush(stdout);

	line = fgets(readline_buffer, sizeof(readline_buffer), stdin);
	if (!line) return NULL;

	p = strchr(line, '\n');
	if (!p) {
		fprintf(stderr, "%s: Input line too long\n",
			"XXX");
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
	if (!line) goto redo;

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

#define MAX_ARGV (32)

static int cmd_help(FILE *fp, UNUSED void *ctx, int argc, char const *argv[]);

static void *fr_radmin(UNUSED void *input_ctx)
{
	int argc, context;
	char **argv;
	char const **const_argv;
	char *argv_buffer;
	char *current, *prompt;
	size_t size, room;
	TALLOC_CTX *ctx;

	context = 0;
	prompt = "radmin> ";

	ctx = talloc_init("radmin");

	size = room = 8192;
	argv_buffer = talloc_array(ctx, char, size);
	current = argv_buffer;

	/* -Wincompatible-pointer-types-discards-qualifiers */
	argv = talloc_zero_array(ctx, char *, 32);
	memcpy(&const_argv, &argv, sizeof(argv));

	fflush(stdout);

	while (true) {
		int rcode;
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
				cmd_help(stdout, NULL, context, const_argv);
				goto next;
			}

			/*
			 *	Allow exiting from the current context.
			 */
			if (strcmp(line, "exit") == 0) {
				context--;
				if (context == 0) {
					prompt = "radmin> ";
				} else {
					talloc_free(prompt);
					prompt = talloc_asprintf(ctx, "... %s> ", argv[context - 1]);
				}
				goto next;
			}
		}

		/*
		 *	Splitting the line into words mangles it
		 *	in-place.  So we need to copy the line to an
		 *	intermediate buffer.
		 *
		 *	@todo - add the *full* line to the history,
		 *	not the partial line.
		 */
		strlcpy(current, line, room);
		argc = fr_command_str_to_argv(radmin_cmd, context, argv, MAX_ARGV, current);

		/*
		 *	@todo - show parse error
		 */
		if (argc < 0) {
			fprintf(stderr, "Failed parsing line\n");
			continue;
		}

		/*
		 *	Skip blank lines.
		 */
		if (argc == context) continue;

		/*
		 *	Having split the RHS of the arguments, we now
		 *	pass the whole argument list to see if it's
		 *	runnable.
		 */
		rcode = fr_command_runnable(radmin_cmd, argc, const_argv);
		if (rcode < 0) {
			fprintf(stderr, "Unknown command: %s\n", fr_strerror());
			add_history(line); /* let them up-arrow and retype it */
			goto next;
		}

		/*
		 *	It's a partial command.  Add it to the context
		 *	and continue.
		 *
		 *	Note that we have to update `current`, because
		 *	argv[context] currently points there...
		 */
		if (rcode == 0) {
			size_t len;

			len = strlen(argv[argc - 1]) + 1;

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
			current = current + len;
			room -= len;

			if (context > 0) {
				talloc_free(prompt);
			}

			context = argc;
			prompt = talloc_asprintf(ctx, "... %s> ", argv[context - 1]);
			goto next;
		}

		/*
		 *	Else it's a runnable command.  Add it to the
		 *	history
		 */
		add_history(line);

		if (fr_command_run(stdout, radmin_cmd, argc, const_argv) < 0) {
			fprintf(stderr, "Failing running command: %s\n", fr_strerror());
		}

	next:
		radmin_free(line);

		if (stop) break;
	}

	talloc_free(argv);

	return NULL;
}


/** radmin functions, tables, and callbacks
 *
 */
static struct timeval start_time;

static int cmd_exit(UNUSED FILE *fp, UNUSED void *ctx, UNUSED int argc, UNUSED char const *argv[])
{
	radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
	stop = true;

	return 0;
}

static int cmd_help(FILE *fp, UNUSED void *ctx, int argc, char const *argv[])
{
	char const *help;

	if (argc == 0) {
		fr_command_debug(fp, radmin_cmd);
		return 0;
	}

	help = fr_command_help(radmin_cmd, argc, argv);
	if (help) {
		fprintf(fp, "%s\n", help);
		return 0;
	}

	return 0;
}

static int cmd_uptime(FILE *fp, UNUSED void *ctx, UNUSED int argc, UNUSED char const *argv[])
{
	struct timeval now;

	gettimeofday(&now, NULL);
	fr_timeval_subtract(&now, &now, &start_time);

	fprintf(fp, "Uptime: %u.%06u seconds\n",
		(int) now.tv_sec,
		(int) now.tv_usec);

	return 0;
}

static int cmd_test(FILE *fp, UNUSED void *ctx, UNUSED int argc, UNUSED char const *argv[])
{
	fprintf(fp, "woo!\n");
	return 0;
}

static char const *parents[] = {
	"test",
	NULL
};

static fr_cmd_table_t cmd_table[] = {
	{
		.syntax = "exit",
		.func = cmd_exit,
		.help = "Tell the server to exit immediately.",
		.read_only = false
	},

	{
		.syntax = "help",
		.func = cmd_help,
		.help = "Display list of commands and their help text.",
		.read_only = true
	},

	{
		.syntax = "foo",
		.func = cmd_test,
		.help = "test foo.",
		.read_only = false,
		.parents = parents,
	},

	{
		.syntax = "uptime",
		.func = cmd_uptime,
		.help = "Show uptime since the server started.",
		.read_only = true
	},

	CMD_TABLE_END
};

void fr_radmin_start(void)
{
	int rcode;
	pthread_attr_t attr;

	gettimeofday(&start_time, NULL);

	if (fr_radmin_register(NULL, NULL, cmd_table) < 0) {
		PERROR("Failed initializing radmin");
		fr_exit(EXIT_FAILURE);
	}

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	rcode = pthread_create(&pthread_id, &attr, fr_radmin, NULL);
	if (rcode != 0) {
		fprintf(stderr, "Failed creating radmin thread: %s", fr_syserror(errno));
		fr_exit(EXIT_FAILURE);
	}
}

void fr_radmin_stop(void)
{
	stop = true;

	if (pthread_join(pthread_id, NULL) != 0) {
		fprintf(stderr, "Failed joining radmin thread: %s", fr_syserror(errno));
	}
}


/*
 *	MUST be called before fr_radmin_start()
 */
int fr_radmin_register(char const *name, void *ctx, fr_cmd_table_t *table)
{
	return fr_command_add_multi(NULL, &radmin_cmd, name, ctx, table);
}
