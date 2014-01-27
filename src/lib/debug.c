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
 * @file debug.c
 * @brief Various functions to aid in debugging
 *
 * @copyright 2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/libradius.h>

/*
 *	runtime backtrace functions are not POSIX but are included in
 *	glibc, OSX >= 10.5 and various BSDs
 */
#ifdef HAVE_EXECINFO_H
#  include <execinfo.h>
#  define MAX_BT_FRAMES 128
#endif

static char panic_action[512];

/** Prints a simple backtrace (if execinfo is available) and calls panic_action if set.
 *
 * @param sig caught
 */
static void NEVER_RETURNS _fr_fault(int sig)
{
	char cmd[sizeof(panic_action) + 20];
	char *out = cmd;
	size_t left = sizeof(cmd), ret;

	char const *p = panic_action;
	char const *q;

	int code;

	fprintf(stderr, "FATAL SIGNAL: %s\n", strsignal(sig));

	/*
	 *	Produce a simple backtrace - They've very basic but at least give us an
	 *	idea of the area of the code we hit the issue in.
	 */
#ifdef HAVE_EXECINFO_H
	size_t frame_count, i;
	void *stack[MAX_BT_FRAMES];
	char **frames;

	frame_count = backtrace(stack, MAX_BT_FRAMES);
	frames = backtrace_symbols(stack, frame_count);

	fprintf(stderr, "Backtrace of last %zu frames:\n", frame_count);
	for (i = 0; i < frame_count; i++) {
		fprintf(stderr, "%s\n", frames[i]);
		/* Leak the backtrace strings, freeing may lead to undefined behaviour... */
	}
#endif

	/* No panic action set... */
	if (panic_action[0] == '\0') {
		fprintf(stderr, "No panic action set\n");
		_exit(1);
	}

	/* Substitute %p for the current PID (useful for attaching a debugger) */
	while ((q = strstr(p, "%p"))) {
		out += ret = snprintf(out, left, "%.*s%d", (int) (q - p), p, (int) getpid());
		if (left <= ret) {
		oob:
			fprintf(stderr, "Panic action too long\n");
			_exit(1);
		}
		left -= ret;
		p = q + 2;
	}
	if (strlen(p) >= left) goto oob;
	strlcpy(out, p, left);

	fprintf(stderr, "Calling: %s\n", cmd);
	code = system(cmd);
	fprintf(stderr, "Panic action exited with %i\n", code);

	_exit(1);
}

/** Registers signal handlers to execute panic_action on fatal signal
 *
 * May be called multiple time to change the panic_action/program.
 *
 * @param cmd to execute on fault. If present %p will be substituted
 *        for the parent PID before the command is executed, and %e
 *        will be substituted for the currently running program.
 * @param program Name of program currently executing (argv[0]).
 * @return 0 on success -1 on failure.
 */
int fr_fault_setup(char const *cmd, char const *program)
{
	static int setup = FALSE;

	char *out = panic_action;
	size_t left = sizeof(panic_action), ret;

	char const *p = cmd;
	char const *q;

	if (cmd) {
		/* Substitute %e for the current program */
		while ((q = strstr(p, "%e"))) {
			out += ret = snprintf(out, left, "%.*s%s", (int) (q - p), p, program ? program : "");
			if (left <= ret) {
			oob:
				fr_strerror_printf("Panic action too long");
				return -1;
			}
			left -= ret;
			p = q + 2;
		}
		if (strlen(p) >= left) goto oob;
		strlcpy(out, p, left);
	} else {
		*panic_action = '\0';
	}

	/* Unsure what the side effects of changing the signal handler mid execution might be */
	if (!setup) {
#ifdef SIGSEGV
		if (fr_set_signal(SIGSEGV, _fr_fault) < 0) return -1;
#endif
#ifdef SIGBUS
		if (fr_set_signal(SIGBUS, _fr_fault) < 0) return -1;
#endif
#ifdef SIGABRT
		if (fr_set_signal(SIGABRT, _fr_fault) < 0) return -1;
#endif
#ifdef SIGFPE
		if (fr_set_signal(SIGFPE, _fr_fault) < 0) return -1;
#endif
	}
	setup = TRUE;

	return 0;
}
