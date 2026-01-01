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
 * @file build/make/fork.c
 * @brief Run long-lived background processes which exit when $MAKE does.
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
#include <gnumake.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "log.h"

extern char **environ;

/*
 *	The only exported symbol
 */
int fork_gmk_setup(void);

/*
 * GNU make insists on this in a loadable object.
 */
extern int plugin_is_GPL_compatible;
int plugin_is_GPL_compatible;

#define READER (0)
#define WRITER (1)

typedef struct {
	char	*name;		//!< used to distinguish processes
	int	stdin[2];      	//!< stdin for the process
	int	stdout[2];     	//!< stdout for the process
				//!< stderr is left to be the same as for GNU Make
	pid_t	pid;		//!< PID of the child
} fork_t;

#define MAX_CHILD (256)

static unsigned int min_child = 0;
static unsigned int max_child = 1;
static fork_t child[MAX_CHILD] = {};

static int fr_cloexec(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0) return -1;

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFL, flags) < 0) return -1;

	return 0;
}

/*
 *	$(fork-bg program,arg1,arg2,arg3,...)
 *
 *	Will run a child process, using a pipe for stdin/stdout.
 *
 *	Will return an opaque key which can later be used to interact with the process.
 */
static char *make_fork_bg(__attribute__((unused)) char const *nm, __attribute__((unused)) unsigned int argc, char **argv)
{
	char	*in;
	pid_t	self;
	unsigned  i, my_argc, envc = 0;
	char	*my_argv[MAX_CHILD];
	char	*env[MAX_CHILD];

	if (max_child == MAX_CHILD) {
		ERROR("Too many children");
		return NULL;
	}

#if 0
	fprintf(stderr, "ARGC = %u\n", argc);
	for (i = 0; i < argc; i++) {
		fprintf(stderr, "[%u] = %s\n", i, argv[i]);
	}
#endif

	/*
	 *	Do all of the splitting in the parent process.  This lets us call ERROR(), which aborts the
	 *	current make process, and doesn't return.
	 *
	 *	Also, calling ERROR() in the child causes all kinds of GNU make insanity.
	 */
	my_argc = 0;
	for (i = 1; i < argc; i++) {
		char *p, *q;
		char *start;
		bool is_env = false;
		bool allow_env = true;

		in = argv[i];

		if (my_argc == MAX_CHILD) {
			ERROR("Too many arguments");	// doesn't return
			return NULL;			// needed to quiet the C compiler
		}

		/*
		 *	Loop over 'in', splitting on spaces.  But NOT on spaces inside of quotes.
		 */
		p = in;
		while (*p) {
			while (isspace((unsigned int) *p)) p++;

			if (*p == '`') {
				ERROR("Unexpected back-tick");
				return NULL;
			}

			/*
			 *	we support only a limited number of quoted strings, and only a limited syntax
			 *	for them.
			 */
			if ((*p == '"') || (*p == '\'')) {
				char quote = *p;

				q = p;
				p++;

				my_argv[my_argc++] = p;
				allow_env = false;

				/*
				 *	Shift the entire string left, and de-quote it.
				 */
				while (*p && (*p != quote)) {
					if (*p == '\\') {
						p++;
					}

					*(q++) = *(p++);
				}

				if (*p != quote) {
					ERROR("Missing end quote %c", quote);
					return NULL;
				}

				p++;
				*q = '\0';

				if (*p && !isspace((unsigned int) *p)) {
					ERROR("Unexpected text after quote %c", quote);
					return NULL;
				}
				continue;
			}

			/*
			 *	Bare word.  Copy it, but don't allow quotes.
			 */
			start = p;

			while (*p) {
				if (isspace((unsigned int) *p)) {
					*p = '\0';
					p++; /* don't leave it pointing at the NUL byte */
					break;
				}

				if ((*p == '"') || (*p == '\'') || (*p == '`')) {
					ERROR("Unexpected quote %c", *p);
					return NULL;
				}

				if (*p == '\\') {
					ERROR("Unexpected escape");
					return NULL;
				}

				if (allow_env && (*p == '=')) {
					is_env = true;
					break;
				}

				p++;
			}

			/*
			 *	We allow environment variables, and it's "foo=...".  Set the environment
			 *	variable appropriately, and skip the rest of the string.  The value of the
			 *	environment variable can contain spaces.
			 */
			if (is_env) {
				if (envc == MAX_CHILD) {
					ERROR("Too many environment variables");
					return NULL;
				}

				env[envc++] = start;
				break;
			}

			my_argv[my_argc++] = start;
			allow_env = false;
		}
	}

	/*
	 *	NULL terminate the array.
	 */
	my_argv[my_argc] = NULL;

#if 0
	fprintf(stderr, "MY_ARGC = %u\n", my_argc);
	for (i = 0; i < my_argc; i++) {
		fprintf(stderr, "[%u] = %s\n", i, my_argv[i]);
	}

	fprintf(stderr, "MY_ENV = %u\n", envc);
	for (i = 0; i < envc; i++) {
		fprintf(stderr, "[%u] = %s\n", i, env[i]);
	}
#endif

	/*
	 *	Open sockets: stdin, stdout.
	 */
	if (pipe(child[min_child].stdin) < 0) {
		ERROR("Failed opening stdin for child - %s", strerror(errno));
		return NULL;
	}
	if (fr_cloexec(child[min_child].stdin[WRITER]) < 0) { /* parents writer FD */
		ERROR("Failed flagging stdin for child - %s", strerror(errno));
		return NULL;
	}

	if (pipe(child[min_child].stdout) < 0) {
		ERROR("Failed opening stdout for child - %s", strerror(errno));
		return NULL;
	}
	if (fr_cloexec(child[min_child].stdout[READER]) < 0) { /* parents reader FD */
		ERROR("Failed flagging stdout for child - %s", strerror(errno));
		return NULL;
	}
	self = getpid();

	child[min_child].name = strdup(argv[0]);

	child[min_child].pid = fork();
	if (child[min_child].pid) {
		char *out;

		/*
		 *	Close the descriptors used by the child, we
		 *	don't need them any more.
		 */
		(void) close(child[min_child].stdin[READER]); /* childs reader FD */
		(void) close(child[min_child].stdout[WRITER]); /* childs writer FD */

		min_child++;
		if (min_child == max_child) {
			max_child++;
		}

		out = gmk_alloc(1);
		out[0] = '\0';

		return out;
	}

	/*
	 *	We're now in the child.
	 */

	/*
	 *	Set any necessary environment variables in the child.
	 */
	for (i = 0; i < envc; i++) {
		if (putenv(env[i]) < 0) {
			fprintf(stderr, "Failed setting environment variable - %s", strerror(errno));
			goto fail;
		}
	}

	(void) close(child[min_child].stdin[WRITER]);			/* parents writer FD */
	if (dup2(child[min_child].stdin[READER], STDIN_FILENO) < 0) {	/* childs reader FD */
		fprintf(stderr, "Failed setting stdin - %s\n", strerror(errno));
		goto fail;
	}
	(void) close(child[min_child].stdin[READER]);			/* childs reader FD, now stdin */

//	(void) close(child[min_child].stdout[READER]);			/* parents reader FD */
	if (dup2(child[min_child].stdout[WRITER], STDOUT_FILENO) < 0) { /* childs writer FD */
		fprintf(stderr, "Failed setting stdin - %s\n", strerror(errno));
		goto fail;
	}
	(void) close(child[min_child].stdout[WRITER]);			/* childs write FD, now stdout */

	/*
	 *	Don't call ERROR() in the child process, or all kinds of bad things happen.
	 */
	if (execve(my_argv[0], my_argv, environ) < 0) {
		fprintf(stderr, "ERROR *** Failed to run %s - %s\n", my_argv[0], strerror(errno));
	}

	/*
	 *	Since we failed to exec a program, we kill the parent, too.
	 *
	 *	Unfortunately, there's no way to print a reasonable message about where this function was
	 *	called from.  So we have to hope that the poor user can figure it out.
	 *
	 *	Maybe we want to make argv[0] into a key, and print that key out on error.  That way the user
	 *	knows where the error is.
	 */
fail:
	kill(self, SIGQUIT);

	/*
	 *	Note that we have to call _exit() and not exit(), as we don't want GNU make to run any
	 *	atexit() handlers.
	 */
	_exit(1);
}

static void cleanup(unsigned int i)
{
	free(child[i].name);
	close(child[i].stdin[WRITER]); /* our writer FD */
	close(child[i].stdout[READER]); /* our reader FD */

	child[i] = (fork_t) {};

	if (i < min_child) {
		min_child = i;

	} else if (i == min_child) {
		min_child++;

	} else if ((i + 1) == max_child) {
		max_child--;
	}

	if (min_child == max_child) {
		min_child = 0;
		max_child = 1;
	}
}

/*
 *	$(kill key)
 *
 *	Will kill a previously forked child
 */
static char *make_kill(__attribute__((unused)) char const *nm, __attribute__((unused))  unsigned int argc, char **argv)
{
	unsigned int	i;

	if (!*argv[0]) {
		ERROR("Empty input to kill");
		return NULL;
	}

	/*
	 *	Find a child of the correct name.
	 */
	for (i = 0; i < max_child; i++) {
		char *out;

		if (!child[i].name) continue;

		/*
		 *	@todo - check if the sockets are usable.  If not, then the child has already died, and
		 *	we don't need to kill it.
		 */
		(void) kill(child[i].pid, SIGKILL);
		cleanup(i);

		out = gmk_alloc(1);
		out[1] = '\0';
		return out;
	}

	/*
	 *	Must have died already.
	 */
	return NULL;
}

int fork_gmk_setup(void)
{
	gmk_add_function("fork-bg", &make_fork_bg, 2, 30, 0); /* min 2, max 30, please expand the input string */
	gmk_add_function("kill-bg", &make_kill, 1, 1, 0); /* min 1, max 1, please expand the input string */

	return 1;
}
