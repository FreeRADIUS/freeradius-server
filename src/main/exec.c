/*
 * exec.c	Execute external programs.
 *
 * Version:	$Id$
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Michael J. Hartwick <hartwick@hartwick.com>
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include <sys/file.h>

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

#ifdef HAVE_SYS_WAIT_H
#	include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#	define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#	define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#include "radiusd.h"
#include "rad_assert.h"

/*
 *	Execute a program on successful authentication.
 *	Return 0 if exec_wait == 0.
 *	Return the exit code of the called program if exec_wait != 0.
 *	Return -1 on fork/other errors in the parent process.
 */
int radius_exec_program(const char *cmd, REQUEST *request,
			int exec_wait,
			char *user_msg, int msg_len,
			VALUE_PAIR *input_pairs,
			VALUE_PAIR **output_pairs)
{
	VALUE_PAIR *vp;
	char answer[4096];
	char *argv[256];
	char *buf, *p;
	int pd[2];
	pid_t pid, child_pid;
	int argc = -1;
	int comma = 0;
	int status;
	int n, left, done;

	if (user_msg) *user_msg = '\0';
	if (output_pairs) *output_pairs = NULL;

	/*
	 *	Open a pipe for child/parent communication, if
	 *	necessary.
	 */
	if (exec_wait) {
		if (pipe(pd) != 0) {
			radlog(L_ERR|L_CONS, "Couldn't open pipe: %s",
			       strerror(errno));
			return -1;
		}
	} else {
		/*
		 *	We're not waiting, so we don't look for a
		 *	message, or VP's.
		 */
		user_msg = NULL;
		output_pairs = NULL;
	}

	/*
	 *	Do the translation (as the parent) of the command to
	 *	execute.  This MAY involve calling other modules, so
	 *	we want to do it in the parent.
	 */
	radius_xlat(answer, sizeof(answer), cmd, request, NULL);
	buf = answer;
	
	/*
	 *	Log the command if we are debugging something
	 */
	DEBUG("Exec-Program: %s", buf);
	
	/*
	 *	Build vector list of arguments and execute.
	 *
	 *	FIXME: This parsing gets excited over spaces in
	 *	the translated strings, e.g. User-Name = "aa bb"
	 *	is passed as two seperate arguments, instead of one.
	 *
	 *	What we SHOULD do instead is to split the exec program
	 *	buffer first, and then do the translation on every
	 *	subsequent string.
	 */
	p = strtok(buf, " \t");
	if (p) do {
		argv[++argc] = p;
		p = strtok(NULL, " \t");
	} while(p != NULL);

	argv[++argc] = p;
	if (argc == 0) {
		radlog(L_ERR, "Exec-Program: empty command line.");
		return -1;
	}

	if ((pid = rad_fork(exec_wait)) == 0) {
#define MAX_ENVP 1024
		int i, devnull;
		char *envp[MAX_ENVP];
		int envlen;
		char buffer[1024];

		/*	
		 *	Child process.
		 *
		 *	We try to be fail-safe here.  So if ANYTHING
		 *	goes wrong, we exit with status 1.
		 */

		/*
		 *	Open STDIN to /dev/null
		 */
		devnull = open("/dev/null", O_RDWR);
		if (devnull < 0) {
			radlog(L_ERR|L_CONS, "Failed opening /dev/null: %s\n",
			       strerror(errno));
			exit(1);
		}
		dup2(devnull, STDIN_FILENO);

		/*
		 *	Only massage the pipe handles if the parent
		 *	has created them.
		 */
		if (exec_wait) {
			/*
			 *	pd[0] is the FD the child will read from,
			 *	which we don't want.
			 */
			if (close(pd[0]) != 0) {
				radlog(L_ERR|L_CONS, "Can't close pipe: %s",
				       strerror(errno));
				exit(1);
			}
			
			/*
			 *	pd[1] is the FD that the child will write to,
			 *	so we make it STDOUT.
			 */
			if (dup2(pd[1], STDOUT_FILENO) != 1) {
				radlog(L_ERR|L_CONS, "Can't dup stdout: %s",
				       strerror(errno));
				exit(1);
			}

		} else {	/* no pipe, STDOUT should be /dev/null */
			dup2(devnull, STDOUT_FILENO);
		}

		/*
		 *	If we're not debugging, then we can't do
		 *	anything with the error messages, so we throw
		 *	them away.
		 *
		 *	If we are debugging, then we want the error
		 *	messages to go to the STDERR of the server.
		 */
		if (debug_flag == 0) {
			dup2(devnull, STDERR_FILENO);
		}
		close(devnull);

		/*
		 *	The server may have MANY FD's open.  We don't
		 *	want to leave dangling FD's for the child process
		 *	to play funky games with, so we close them.
		 */
		for (i = 3; i < 256; i++) {
			close(i);
		}

		/*
		 *	Set up the environment variables.
		 *	We're in the child, and it will exit in 4 lines
		 *	anyhow, so memory allocation isn't an issue.
		 */
		envlen = 0;

		for (vp = input_pairs; vp != NULL; vp = vp->next) {
			/*
			 *	Hmm... maybe we shouldn't pass the
			 *	user's password in an environment
			 *	variable...
			 */
			snprintf(buffer, sizeof(buffer), "%s=", vp->name);
			for (p = buffer; *p != '='; p++) {
				if (*p == '-') {
					*p = '_';
				} else if (isalpha((int) *p)) {
					*p = toupper(*p);
				}
			}

			n = strlen(buffer);
			vp_prints_value(buffer+n, sizeof(buffer) - n, vp, 1);

			envp[envlen++] = strdup(buffer);
		}
		envp[envlen] = NULL;
		execve(argv[0], argv, envp);
		radlog(L_ERR, "Exec-Program: FAILED to execute %s: %s",
		       argv[0], strerror(errno));
		exit(1);
	}

	/*
	 *	Parent process.
	 */
	if (pid < 0) {
		radlog(L_ERR|L_CONS, "Couldn't fork %s: %s",
		       argv[0], strerror(errno));
		return -1;
	}

	/*
	 *	We're not waiting, exit, and ignore any child's
	 *	status.
	 */
	if (!exec_wait) {
		return 0;
	}

	/*
	 *	Close the FD to which the child writes it's data.
	 *
	 *	If we can't close it, then we close pd[0], and return an
	 *	error.
	 */
	if (close(pd[1]) != 0) {
		radlog(L_ERR|L_CONS, "Can't close pipe: %s", strerror(errno));
		close(pd[0]);
		return -1;
	}

	/*
	 *	Read from the pipe until we doesn't get any more or
	 *	until the message is full.
	 */
	done = 0;
	left = sizeof(answer) - 1;
	while (1) {
		status = read(pd[0], answer + done, left);
		/*
		 *	Nothing more to read: stop.
		 */
		if (status == 0) {
			break;
		}

		/*
		 *	Error: See if we have to continue.
		 */
		if (status < 0) {
			/*
			 *	We were interrupted: continue reading.
			 */
			if (errno == EINTR) {
				continue;
			}

			/*
			 *	There was another error.  Most likely
			 *	The child process has finished, and
			 *	exited.
			 */
			break;
		}

		done += status;
		left -= status;
		if (left <= 0) break;
	}
	answer[done] = 0;

	/*
	 *	Make sure that the writer can't block while writing to
	 *	a pipe that no one is reading from anymore.
	 */
	close(pd[0]);

	DEBUG2("Exec-Program output: %s", answer);

	/*
	 *	Parse the output, if any.
	 */
	if (done) {
		n = T_INVALID;
		if (output_pairs) {
			/*
			 *	For backwards compatibility, first check
			 *	for plain text (user_msg).
			 */
			vp = NULL;
			n = userparse(answer, &vp);
			if (vp) {
				pairfree(&vp);
			}
		}

		if (n == T_INVALID) {
			radlog(L_DBG, "Exec-Program-Wait: plaintext: %s", answer);
			if (user_msg) {
				strNcpy(user_msg, answer, msg_len);
			}
		} else {
			/*
			 *	HACK: Replace '\n' with ',' so that
			 *	userparse() can parse the buffer in
			 *	one go (the proper way would be to
			 *	fix userparse(), but oh well).
			 */
			for (p = answer; *p; p++) {
				if (*p == '\n') {
					*p = comma ? ' ' : ',';
					p++;
					comma = 0;
				}
				if (*p == ',') comma++;
			}

			/*
			 *  Replace any trailing comma by a NUL.
			 */
			if (answer[strlen(answer) - 1] == ',') {
				answer[strlen(answer) - 1] = '\0';
			}

			radlog(L_DBG,"Exec-Program-Wait: value-pairs: %s", answer);
			if (userparse(answer, &vp) == T_INVALID) {
				radlog(L_ERR, "Exec-Program-Wait: %s: unparsable reply", cmd);

			} else {
				/*
				 *	Tell the caller about the value
				 *	pairs.
				 */
				*output_pairs = vp;
			}
		} /* else the answer was a set of VP's, not a text message */
	} /* else we didn't read anything from the child. */

	/*
	 *	Call rad_waitpid (should map to waitpid on non-threaded
	 *	or single-server systems).
	 */
	child_pid = rad_waitpid(pid, &status, 0);
	if (child_pid == pid) {
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			radlog(L_DBG, "Exec-Program: returned: %d", status);
			return status;
		}
	}

	radlog(L_ERR|L_CONS, "Exec-Program: Abnormal child exit: %s",
	       strerror(errno));
	return 1;
}
