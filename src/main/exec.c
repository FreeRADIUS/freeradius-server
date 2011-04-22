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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000-2004,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/file.h>

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

#define MAX_ARGV (256)

#define USEC 1000000
static void tv_sub(struct timeval *end, struct timeval *start,
		   struct timeval *elapsed)
{
	elapsed->tv_sec = end->tv_sec - start->tv_sec;
	if (elapsed->tv_sec > 0) {
		elapsed->tv_sec--;
		elapsed->tv_usec = USEC;
	} else {
		elapsed->tv_usec = 0;
	}
	elapsed->tv_usec += end->tv_usec;
	elapsed->tv_usec -= start->tv_usec;
	
	if (elapsed->tv_usec >= USEC) {
		elapsed->tv_usec -= USEC;
		elapsed->tv_sec++;
	}
}


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
			VALUE_PAIR **output_pairs,
			int shell_escape)
{
	VALUE_PAIR *vp;
	char mycmd[1024];
	const char *from;
	char *p, *to;
	int pd[2];
	pid_t pid, child_pid;
	int argc = -1;
	int comma = 0;
	int status;
	int i;
	int n, left, done;
	char *argv[MAX_ARGV];
	char answer[4096];
	char argv_buf[4096];
#define MAX_ENVP 1024
	char *envp[MAX_ENVP];
	struct timeval start;
#ifdef O_NONBLOCK
	int nonblock = TRUE;
#endif

	if (user_msg) *user_msg = '\0';
	if (output_pairs) *output_pairs = NULL;

	if (strlen(cmd) > (sizeof(mycmd) - 1)) {
		radlog(L_ERR|L_CONS, "Command line is too long");
		return -1;
	}

	/*
	 *	Check for bad escapes.
	 */
	if (cmd[strlen(cmd) - 1] == '\\') {
		radlog(L_ERR|L_CONS, "Command line has final backslash, without a following character");
		return -1;
	}

	strlcpy(mycmd, cmd, sizeof(mycmd));

	/*
	 *	Split the string into argv's BEFORE doing radius_xlat...
	 */
	from = cmd;
	to = mycmd;
	argc = 0;
	while (*from) {
		int length;

		/*
		 *	Skip spaces.
		 */
		if ((*from == ' ') || (*from == '\t')) {
			from++;
			continue;
		}

		argv[argc] = to;
		argc++;

		if (argc >= (MAX_ARGV - 1)) break;

		/*
		 *	Copy the argv over to our buffer.
		 */
		while (*from && (*from != ' ') && (*from != '\t')) {
			if (to >= mycmd + sizeof(mycmd) - 1) {
				return -1; /* ran out of space */
			}

			switch (*from) {
			case '"':
			case '\'':
				length = rad_copy_string(to, from);
				if (length < 0) {
					radlog(L_ERR|L_CONS, "Invalid string passed as argument for external program");
					return -1;
				}
				from += length;
				to += length;
				break;

			case '%':
				if (from[1] == '{') {
					*(to++) = *(from++);

					length = rad_copy_variable(to, from);
					if (length < 0) {
						radlog(L_ERR|L_CONS, "Invalid variable expansion passed as argument for external program");
						return -1;
					}
					from += length;
					to += length;
				} else { /* FIXME: catch %%{ ? */
					*(to++) = *(from++);
				}
				break;

			case '\\':
				if (from[1] == ' ') from++;
				/* FALL-THROUGH */

			default:
				*(to++) = *(from++);
			}
		} /* end of string, or found a space */

		*(to++) = '\0';	/* terminate the string */
	}

	/*
	 *	We have to have SOMETHING, at least.
	 */
	if (argc <= 0) {
		radlog(L_ERR, "Exec-Program: empty command line.");
		return -1;
	}

	/*
	 *	Expand each string, as appropriate.
	 */
	to = argv_buf;
	left = sizeof(argv_buf);
	for (i = 0; i < argc; i++) {
		int sublen;

		/*
		 *	Don't touch argv's which won't be translated.
		 */
		if (strchr(argv[i], '%') == NULL) continue;

		if (!request) continue;

		sublen = radius_xlat(to, left - 1, argv[i], request, NULL);
		if (sublen <= 0) {
			/*
			 *	Fail to be backwards compatible.
			 *
			 *	It's yucky, but it won't break anything,
			 *	and it won't cause security problems.
			 */
			sublen = 0;
		}

		argv[i] = to;
		to += sublen;
		*(to++) = '\0';
		left -= sublen;
		left--;

		if (left <= 0) {
			radlog(L_ERR, "Exec-Program: Ran out of space while expanding arguments.");
			return -1;
		}
	}
	argv[argc] = NULL;

#ifndef __MINGW32__
	/*
	 *	Open a pipe for child/parent communication, if necessary.
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

	envp[0] = NULL;

	if (input_pairs) {
		int envlen;
		char buffer[1024];

		/*
		 *	Set up the environment variables in the
		 *	parent, so we don't call libc functions that
		 *	hold mutexes.  They might be locked when we fork,
		 *	and will remain locked in the child.
		 */
		envlen = 0;

		for (vp = input_pairs; vp != NULL; vp = vp->next) {
			/*
			 *	Hmm... maybe we shouldn't pass the
			 *	user's password in an environment
			 *	variable...
			 */
			snprintf(buffer, sizeof(buffer), "%s=", vp->name);
			if (shell_escape) {
				for (p = buffer; *p != '='; p++) {
					if (*p == '-') {
						*p = '_';
					} else if (isalpha((int) *p)) {
						*p = toupper(*p);
					}
				}
			}

			n = strlen(buffer);
			vp_prints_value(buffer+n, sizeof(buffer) - n, vp, shell_escape);

			envp[envlen++] = strdup(buffer);

			/*
			 *	Don't add too many attributes.
			 */
			if (envlen == (MAX_ENVP - 1)) break;
		}
		envp[envlen] = NULL;
	}

	if (exec_wait) {
		pid = rad_fork();	/* remember PID */
	} else {
		pid = fork();		/* don't wait */
	}

	if (pid == 0) {
		int devnull;

		/*
		 *	Child process.
		 *
		 *	We try to be fail-safe here. So if ANYTHING
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
		closefrom(3);

		execve(argv[0], argv, envp);
		radlog(L_ERR, "Exec-Program: FAILED to execute %s: %s",
		       argv[0], strerror(errno));
		exit(1);
	}

	/*
	 *	Free child environment variables
	 */
	for (i = 0; envp[i] != NULL; i++) {
		free(envp[i]);
	}

	/*
	 *	Parent process.
	 */
	if (pid < 0) {
		radlog(L_ERR|L_CONS, "Couldn't fork %s: %s",
		       argv[0], strerror(errno));
		if (exec_wait) {
			close(pd[0]);
			close(pd[1]);
		}
		return -1;
	}

	/*
	 *	We're not waiting, exit, and ignore any child's status.
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

#ifdef O_NONBLOCK
	/*
	 *	Try to set it non-blocking.
	 */
	do {
		int flags;
		
		if ((flags = fcntl(pd[0], F_GETFL, NULL)) < 0)  {
			nonblock = FALSE;
			break;
		}
		
		flags |= O_NONBLOCK;
		if( fcntl(pd[0], F_SETFL, flags) < 0) {
			nonblock = FALSE;
			break;
		}
	} while (0);
#endif


	/*
	 *	Read from the pipe until we doesn't get any more or
	 *	until the message is full.
	 */
	done = 0;
	left = sizeof(answer) - 1;
	gettimeofday(&start, NULL);
	while (1) {
		int rcode;
		fd_set fds;
		struct timeval when, elapsed, wake;

		FD_ZERO(&fds);
		FD_SET(pd[0], &fds);

		gettimeofday(&when, NULL);
		tv_sub(&when, &start, &elapsed);
		if (elapsed.tv_sec >= 10) goto too_long;
		
		when.tv_sec = 10;
		when.tv_usec = 0;
		tv_sub(&when, &elapsed, &wake);

		rcode = select(pd[0] + 1, &fds, NULL, NULL, &wake);
		if (rcode == 0) {
		too_long:
			radlog(L_ERR, "Child PID %u is taking too much time: forcing failure and killing child.", pid);
			kill(pid, SIGTERM);
			close(pd[0]); /* should give SIGPIPE to child, too */

			/*
			 *	Clean up the child entry.
			 */
			rad_waitpid(pid, &status);
			return 1;			
		}
		if (rcode < 0) {
			if (errno == EINTR) continue;
			break;
		}

#ifdef O_NONBLOCK
		/*
		 *	Read as many bytes as possible.  The kernel
		 *	will return the number of bytes available.
		 */
		if (nonblock) {
			status = read(pd[0], answer + done, left);
		} else 
#endif
			/*
			 *	There's at least 1 byte ready: read it.
			 */
			status = read(pd[0], answer + done, 1);

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
		n = T_OP_INVALID;
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

		if (n == T_OP_INVALID) {
			DEBUG("Exec-Program-Wait: plaintext: %s", answer);
			if (user_msg) {
				strlcpy(user_msg, answer, msg_len);
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
			 *	Replace any trailing comma by a NUL.
			 */
			if (answer[strlen(answer) - 1] == ',') {
				answer[strlen(answer) - 1] = '\0';
			}

			radlog(L_DBG,"Exec-Program-Wait: value-pairs: %s", answer);
			if (userparse(answer, &vp) == T_OP_INVALID) {
				radlog(L_ERR, "Exec-Program-Wait: %s: unparsable reply", cmd);

			} else {
				/*
				 *	Tell the caller about the value
				 *	pairs.
				 */
				*output_pairs = vp;
			}
		} /* else the answer was a set of VP's, not a text message */
	} /* else we didn't read anything from the child */

	/*
	 *	Call rad_waitpid (should map to waitpid on non-threaded
	 *	or single-server systems).
	 */
	child_pid = rad_waitpid(pid, &status);
	if (child_pid == 0) {
		radlog(L_DBG, "Exec-Program: Timeout waiting for child");
		return 2;
	}

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
#else
	msg_len = msg_len;	/* -Wunused */

	if (exec_wait) {
		radlog(L_ERR, "Exec-Program-Wait is not supported");
		return -1;
	}
	
	/*
	 *	We're not waiting, so we don't look for a
	 *	message, or VP's.
	 */
	user_msg = NULL;
	output_pairs = NULL;

	{
		/*
		 *	The _spawn and _exec families of functions are
		 *	found in Windows compiler libraries for
		 *	portability from UNIX. There is a variety of
		 *	functions, including the ability to pass
		 *	either a list or array of parameters, to
		 *	search in the PATH or otherwise, and whether
		 *	or not to pass an environment (a set of
		 *	environment variables). Using _spawn, you can
		 *	also specify whether you want the new process
		 *	to close your program (_P_OVERLAY), to wait
		 *	until the new process is finished (_P_WAIT) or
		 *	for the two to run concurrently (_P_NOWAIT).
		 
		 *	_spawn and _exec are useful for instances in
		 *	which you have simple requirements for running
		 *	the program, don't want the overhead of the
		 *	Windows header file, or are interested
		 *	primarily in portability.
		 */

		/*
		 *	FIXME: check return code... what is it?
		 */
		_spawnve(_P_NOWAIT, argv[0], argv, envp);
	}

	return 0;
#endif
}

void exec_trigger(REQUEST *request, CONF_SECTION *cs, const char *name)
{
	CONF_SECTION *subcs;
	CONF_ITEM *ci;
	CONF_PAIR *cp;
	const char *attr;
	const char *value;
	VALUE_PAIR *vp;

	/*
	 *	Use global "trigger" section if no local config is given.
	 */
	if (!cs) {
		cs = mainconfig.config;
		attr = name;
	} else {
		/*
		 *	Try to use pair name, rather than reference.
		 */
		attr = strrchr(name, '.');
		if (attr) {
			attr++;
		} else {
			attr = name;
		}
	}

	/*
	 *	Find local "trigger" subsection.  If it isn't found,
	 *	try using the global "trigger" section, and reset the
	 *	reference to the full path, rather than the sub-path.
	 */
	subcs = cf_section_sub_find(cs, "trigger");
	if (!subcs && (cs != mainconfig.config)) {
		subcs = cf_section_sub_find(mainconfig.config, "trigger");
		attr = name;
	}

	if (!subcs) {
		DEBUG3("No trigger subsection: ignoring trigger %s", name);
		return;
	}

	ci = cf_reference_item(subcs, mainconfig.config, attr);
	if (!ci) {
		DEBUG3("No such item in trigger section: %s", attr);
		return;
	}

	if (!cf_item_is_pair(ci)) {
		DEBUG2("Trigger is not a configuration variable: %s", attr);
		return;
	}

	cp = cf_itemtopair(ci);
	if (!cp) return;

	value = cf_pair_value(cp);
	if (!value) {
		DEBUG2("Trigger has no value: %s", name);
		return;
	}

	/*
	 *	May be called for Status-Server packets.
	 */
	vp = NULL;
	if (request && request->packet) vp = request->packet->vps;

	DEBUG("Trigger %s -> %s", name, value);
	radius_exec_program(value, request, 0, NULL, 0, vp, NULL, 1);
}
