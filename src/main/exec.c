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

#include	"autoconf.h"
#include	"libradius.h"

#include	<sys/file.h>

#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<signal.h>

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#include	"radiusd.h"

/*
 *	Execute a program on successful authentication.
 *	Return 0 if exec_wait == 0.
 *	Return the exit code of the called program if exec_wait != 0.
 *
 */
int radius_exec_program(const char *cmd, REQUEST *request,
			int exec_wait, const char **user_msg)
{
	VALUE_PAIR	*vp;
	static char	message[256];
	char		answer[4096];
	char		*argv[32];
	char		*buf, *p;
	int		pd[2];
	pid_t		pid;
	int		argc = -1;
	int		comma = 0;
	int		status;
	int		n, left, done;
	void		(*oldsig)(int) = NULL;

	/*
	 *	(hs)	- Open a pipe for child/parent communication.
	 *		- Reset the signal handler for SIGCHLD, so
	 *		  we have a chance to notice the dead child here and
	 *  		  not in some signal handler.
	 *		  This has to be done for the exec_wait case only, since
	 *		  if we don't wait we aren't interested in any
	 *		  gone children ...
	 */	
	if (exec_wait) {
		if (pipe(pd) != 0) {
			radlog(L_ERR|L_CONS, "Couldn't open pipe: %m");
			pd[0] = pd[1] = 0;
		}
		if ((oldsig = signal(SIGCHLD, SIG_DFL)) == SIG_ERR) {
			radlog(L_ERR|L_CONS, "Can't reset SIGCHLD: %m");
			oldsig = NULL;
		}
	}

	if ((pid = fork()) == 0) {
#define MAX_ENVP 1024
		char		*envp[MAX_ENVP];
		int		envlen;
		char		buffer[1024];

		/*	
		 *	Child
		 */
		radius_xlat2(answer, sizeof(answer), cmd, request);
		buf = answer;

		/*
		 *	Log the command if we are debugging something
		 */
		DEBUG("Exec-Program: %s", buf);

		/*
		 *	Build vector list and execute.
		 */
		p = strtok(buf, " \t");
		if (p) do {
			argv[++argc] = p;
			p = strtok(NULL, " \t");
		} while(p != NULL);
		argv[++argc] = p;
		if (argc == 0) {
			radlog(L_ERR, "Exec-Program: empty command line.");
			exit(1);
		}

		if (exec_wait) {
			if (close(pd[0]) != 0)
				radlog(L_ERR|L_CONS, "Can't close pipe: %m");
			if (dup2(pd[1], 1) != 1)
				radlog(L_ERR|L_CONS, "Can't dup stdout: %m");
		}

		/*
		 *	Set up the environment variables.
		 *	We're in the child, and it will exit in 4 lines
		 *	anyhow, so memory allocation isn't an issue.
		 */
		envlen = 0;

		for (vp = request->packet->vps; vp->next; vp = vp->next) {
			/*
			 *	Hmm... maybe we shouldn't pass the
			 *	user's password in an environment
			 *	variable...
			 */
			snprintf(buffer, sizeof(buffer), "%s=", vp->name);
			for (p = buffer; *p != '='; p++) {
			  if (*p == '-') {
			    *p = '_';
			  } else if (isalpha(*p)) {
			    *p = toupper(*p);
			  }
			}

			n = strlen(buffer);
			vp_prints_value(buffer+n, sizeof(buffer) - n, vp, 1);

			envp[envlen++] = strdup(buffer);
		}

		envp[envlen] = NULL;
		



		for(n = 32; n >= 3; n--)
			close(n);

		execve(argv[0], argv, envp);

		radlog(L_ERR, "Exec-Program: %s: %m", argv[0]);
		exit(1);
	}

	/*
	 *	Parent 
	 */
	if (pid < 0) {
		radlog(L_ERR|L_CONS, "Couldn't fork: %m");
		return -1;
	}
	if (!exec_wait)
		return 0;

	/*
	 *	(hs) Do we have a pipe?
	 *	--> Close the write side of the pipe 
	 *	--> Read from it.
	 */
	done = 0;
	if (pd[0] || pd[1]) {
		if (close(pd[1]) != 0)
			radlog(L_ERR|L_CONS, "Can't close pipe: %m");

		/*
		 *	(hs) Read until we doesn't get any more
		 *	or until the message is full.
		 */
		done = 0;
		left = sizeof(answer) - 1;
		while ((n = read(pd[0], answer + done, left)) > 0) {
			done += n;
			left -= n;
			if (left <= 0) break;
		}
		answer[done] = 0;

		/*
		 *	(hs) Make sure that the writer can't block
		 *	while writing in a pipe that isn't read anymore.
		 */
		close(pd[0]);
	}

	/*
	 *	Parse the output, if any.
	 */
	if (done) {
		/*
		 *	For backwards compatibility, first check
		 *	for plain text (user_msg).
		 */
		vp = NULL;
		n = userparse(answer, &vp);
		if (vp) pairfree(&vp);

		if (n != 0) {
			radlog(L_DBG, "Exec-Program-Wait: plaintext: %s", answer);
			if (user_msg) {
				strncpy(message, answer, sizeof(message));
				message[sizeof(message) - 1] = 0;
				*user_msg = message;
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
 			if (answer[strlen(answer) - 1] == ',')
 				answer[strlen(answer) - 1] = '\0';

			radlog(L_DBG,"Exec-Program-Wait: value-pairs: %s", answer);
			if (userparse(answer, &vp) != 0)
				radlog(L_ERR,
		"Exec-Program-Wait: %s: unparsable reply", cmd);
			else {
				pairmove(&request->reply->vps, &vp);
				pairfree(&vp);
			}
		}
	}

	while(waitpid(pid, &status, 0) != pid)
		;

	/*
	 *	(hs) Now we let our cleanup_sig handler take care for
	 *	all signals that will arise.
	 */
	if (oldsig && (signal(SIGCHLD, oldsig) == SIG_ERR))
		radlog(L_ERR|L_CONS,
			"Can't set SIGCHLD to the cleanup handler: %m");
	sig_cleanup(SIGCHLD);

	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		radlog(L_INFO, "Exec-Program: returned: %d", status);
		return status;
	}
	radlog(L_ERR|L_CONS, "Exec-Program: Abnormal child exit (killed or coredump)");

	return 1;
}

