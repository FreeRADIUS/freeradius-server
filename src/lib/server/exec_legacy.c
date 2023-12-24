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
 * @file src/lib/server/exec_legacy.c
 * @brief Execute external programs.
 *
 * @copyright 2000-2004,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/util.h>
#include <freeradius-devel/server/exec_legacy.h>
#include <freeradius-devel/server/exec_priv.h>

#define MAX_ARGV (256)

static void exec_pair_to_env_legacy(request_t *request, fr_pair_list_t *input_pairs, char **envp,
				    size_t envlen, bool shell_escape)
{
	char			*p;
	size_t			i;
	fr_dcursor_t		cursor;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	char			buffer[1024];

	/*
	 *	Set up the environment variables in the
	 *	parent, so we don't call libc functions that
	 *	hold mutexes.  They might be locked when we fork,
	 *	and will remain locked in the child.
	 */
	for (vp = fr_pair_list_head(input_pairs), i = 0;
	     vp && (i < envlen - 1);
	     vp = fr_pair_list_next(input_pairs, vp)) {
		size_t n;

		/*
		 *	Hmm... maybe we shouldn't pass the
		 *	user's password in an environment
		 *	variable...
		 */
		snprintf(buffer, sizeof(buffer), "%s=", vp->da->name);
		if (shell_escape) {
			for (p = buffer; *p != '='; p++) {
				if (*p == '-') {
					*p = '_';
				} else if (isalpha((uint8_t) *p)) {
					*p = toupper((uint8_t) *p);
				}
			}
		}

		n = strlen(buffer);
		fr_pair_print_value_quoted(&FR_SBUFF_OUT(buffer + n, sizeof(buffer) - n), vp,
					   shell_escape ? T_DOUBLE_QUOTED_STRING : T_BARE_WORD);

		DEBUG3("export %s", buffer);
		envp[i++] = talloc_typed_strdup(envp, buffer);
	}

	if (request) {
		da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_EXEC_EXPORT);
		if (da) {
			for (vp = fr_pair_dcursor_by_da_init(&cursor, &request->control_pairs, da);
			     vp && (i < (envlen - 1));
			     vp = fr_dcursor_next(&cursor)) {
				DEBUG3("export %pV", &vp->data);
				memcpy(&envp[i++], &vp->vp_strvalue, sizeof(*envp));
			}

			/*
			 *	NULL terminate for execve
			 */
			envp[i] = NULL;
		}
	}
}


/*
 *	Child process.
 *
 *	We try to be fail-safe here. So if ANYTHING
 *	goes wrong, we exit with status 1.
 */
static NEVER_RETURNS void exec_child_legacy(request_t *request, char **argv, char **envp,
					    bool exec_wait,
					    int stdin_pipe[static 2], int stdout_pipe[static 2], int stderr_pipe[static 2])
{
	int devnull;

	/*
	 *	Open STDIN to /dev/null
	 */
	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0) {
		fprintf(stderr, "Failed opening /dev/null: %s\n", fr_syserror(errno));

		/*
		 *	Where the status code is interpreted as a module rcode
		 * 	one is subtracted from it, to allow 0 to equal success
		 *
		 *	2 is RLM_MODULE_FAIL + 1
		 */
		exit(2);
	}

	/*
	 *	Only massage the pipe handles if the parent
	 *	has created them.
	 */
	if (exec_wait) {
		if (stdin_pipe[1] >= 0) {
			close(stdin_pipe[1]);
			dup2(stdin_pipe[0], STDIN_FILENO);
		} else {
			dup2(devnull, STDIN_FILENO);
		}

		if (stdout_pipe[1] >= 0) {
			close(stdout_pipe[0]);
			dup2(stdout_pipe[1], STDOUT_FILENO);
		} else {
			dup2(devnull, STDOUT_FILENO);
		}

		if (stderr_pipe[1] >= 0) {
			close(stderr_pipe[0]);
			dup2(stderr_pipe[1], STDERR_FILENO);
		} else {
			dup2(devnull, STDERR_FILENO);
		}
	} else {	/* no pipe, STDOUT should be /dev/null */
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);

		/*
		 *	If we're not debugging, then we can't do
		 *	anything with the error messages, so we throw
		 *	them away.
		 *
		 *	If we are debugging, then we want the error
		 *	messages to go to the STDERR of the server.
		 */
		if (!request || !RDEBUG_ENABLED) dup2(devnull, STDERR_FILENO);
	}

	close(devnull);

	/*
	 *	The server may have MANY FD's open.  We don't
	 *	want to leave dangling FD's for the child process
	 *	to play funky games with, so we close them.
	 */
	fr_closefrom(STDERR_FILENO + 1);

	/*
	 *	Disarm the thread local destructors
	 *
	 *	It's not safe to free memory between fork and exec.
	 */
	fr_atexit_thread_local_disarm_all();

	/*
	 *	I swear the signature for execve is wrong and should
	 *	take 'char const * const argv[]'.
	 *
	 *	Note: execve(), unlike system(), treats all the space
	 *	delimited arguments as literals, so there's no need
	 *	to perform additional escaping.
	 */
	execve(argv[0], argv, envp);
	printf("Failed to execute \"%s\": %s", argv[0], fr_syserror(errno)); /* fork output will be captured */

	/*
	 *	Where the status code is interpreted as a module rcode
	 * 	one is subtracted from it, to allow 0 to equal success
	 *
	 *	2 is RLM_MODULE_FAIL + 1
	 */
	exit(2);
}


/** Start a process
 *
 * @param[out] stdin_fd		pointer to int, receives the stdin file
 *				descriptor. Set to NULL and the child
 *				will have /dev/null on stdin.
 * @param[out] stdout_fd	pointer to int, receives the stdout file
 *				descriptor. Set to NULL and the child
 *				will have /dev/null on stdout.
 * @param[out] stderr_fd	pointer to int, receives the stderr file
 *				descriptor. Set to NULL and the child
 *				will have /dev/null on stderr.
 * @param[in] cmd		Command to execute. This is parsed into argv[]
 *				parts, then each individual argv part is
 *				xlat'ed.
 * @param[in] request		Current request
 * @param[in] exec_wait		set to true to read from or write to child.
 * @param[in] input_pairs	list of value pairs - these will be put into
 *				the environment variables of the child.
 * @param[in] shell_escape	values before passing them as arguments.
 * @return
 *	- PID of the child process.
 *	- -1 on failure.
 */
pid_t radius_start_program_legacy(int *stdin_fd, int *stdout_fd, int *stderr_fd,
				  char const *cmd, request_t *request, bool exec_wait,
				  fr_pair_list_t *input_pairs, bool shell_escape)
{
	int		stdin_pipe[2]  = {-1, -1};
	int		stdout_pipe[2] = {-1, -1};
	int		stderr_pipe[2] = {-1, -1};
	pid_t		pid;
	int		argc;
	int		i;
	char const	**argv_p;
	char		*argv[MAX_ARGV], **argv_start = argv;
	char		argv_buf[4096];
#define MAX_ENVP 1024
	char		**envp;

	/*
	 *	Stupid array decomposition...
	 *
	 *	If we do memcpy(&argv_p, &argv, sizeof(argv_p)) src ends up being a char **
	 *	pointing to the value of the first element.
	 */
	memcpy(&argv_p, &argv_start, sizeof(argv_p));
	argc = rad_expand_xlat(request, cmd, MAX_ARGV, argv_p, true, sizeof(argv_buf), argv_buf);
	if (argc <= 0) {
		ROPTIONAL(RPEDEBUG, PERROR, "Invalid command '%s'", cmd);
		return -1;
	}

	if (DEBUG_ENABLED3) {
		for (i = 0; i < argc; i++) DEBUG3("arg[%d] %s", i, argv[i]);
	}

	/*
	 *	Open a pipe for child/parent communication, if necessary.
	 */
	if (exec_wait) {
		if (stdin_fd) {
			if (pipe(stdin_pipe) != 0) {
				ERROR("Couldn't open pipe to child: %s", fr_syserror(errno));
				return -1;
			}
		}
		if (stdout_fd) {
			if (pipe(stdout_pipe) != 0) {
				ERROR("Couldn't open pipe from child: %s", fr_syserror(errno));
				/* safe because these either need closing or are == -1 */
			error:
				close(stdin_pipe[0]);
				close(stdin_pipe[1]);
				close(stdout_pipe[0]);
				close(stdout_pipe[1]);
				close(stderr_pipe[0]);
				close(stderr_pipe[1]);
				return -1;
			}
		}
		if (stderr_fd) {
			if (pipe(stderr_pipe) != 0) {
				ERROR("Couldn't open pipe from child: %s", fr_syserror(errno));

				goto error;
			}
		}
	}

	MEM(envp = talloc_zero_array(request, char *, MAX_ENVP));
	envp[0] = NULL;
	if (input_pairs) exec_pair_to_env_legacy(request, input_pairs, envp, MAX_ENVP, shell_escape);

	pid = fork();
	if (pid == 0) {
		exec_child_legacy(request, argv, envp, exec_wait, stdin_pipe, stdout_pipe, stderr_pipe);
	}

	/*
	 *	Free child environment variables
	 */
	talloc_free(envp);

	/*
	 *	Parent process.
	 */
	if (pid < 0) {
		ERROR("Couldn't fork %s: %s", argv[0], fr_syserror(errno));
		if (exec_wait) goto error;
	}

	/*
	 *	We're done.  Do any necessary cleanups.
	 */
	if (exec_wait) {
		/*
		 *	Close the ends of the pipe(s) the child is using
		 *	return the ends of the pipe(s) our caller wants
		 *
		 */
		if (stdin_fd) {
			*stdin_fd = stdin_pipe[1];
			close(stdin_pipe[0]);
		}
		if (stdout_fd) {
			*stdout_fd = stdout_pipe[0];
			close(stdout_pipe[1]);
		}
		if (stderr_fd) {
			*stderr_fd = stderr_pipe[0];
			close(stderr_pipe[1]);
		}
	} else {
		fr_event_list_t *el = unlang_interpret_event_list(request);

		(void) fr_event_pid_wait(el, el, NULL, pid, NULL, NULL);
	}

	return pid;
}


/** Read from the child process.
 *
 * @param fd file descriptor to read from.
 * @param pid pid of child, will be reaped if it dies.
 * @param timeout amount of time to wait, in seconds.
 * @param answer buffer to write into.
 * @param left length of buffer.
 * @return
 *	- -1 on failure.
 *	- Length of output.
 */
int radius_readfrom_program_legacy(int fd, pid_t pid, fr_time_delta_t timeout, char *answer, int left)
{
	int done = 0;
	int status;
	fr_time_t start;

	fr_nonblock(fd);

	/*
	 *	Minimum timeout period is one section
	 */
	if (fr_time_delta_unwrap(timeout) < NSEC) timeout = fr_time_delta_from_sec(1);

	/*
	 *	Read from the pipe until we doesn't get any more or
	 *	until the message is full.
	 */
	start = fr_time();
	while (1) {
		int		rcode;
		fd_set		fds;
		fr_time_delta_t	elapsed;

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		elapsed = fr_time_sub(fr_time(), start);
		if (fr_time_delta_gteq(elapsed, timeout)) goto too_long;

		rcode = select(fd + 1, &fds, NULL, NULL, &fr_time_delta_to_timeval(fr_time_delta_sub(timeout, elapsed)));
		if (rcode == 0) {
		too_long:
			DEBUG("Child PID %u is taking too much time: forcing failure and killing child.", pid);
			kill(pid, SIGTERM);
			close(fd); /* should give SIGPIPE to child, too */

			/*
			 *	Clean up the child entry.
			 */
			waitpid(pid, &status, 0);
			return -1;
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
		status = read(fd, answer + done, left);
#else
		/*
		 *	There's at least 1 byte ready: read it.
		 *	This is a terrible hack for non-blocking IO.
		 */
		status = read(fd, answer + done, 1);
#endif

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

	/* Strip trailing new lines */
	while ((done > 0) && (answer[done - 1] == '\n')) {
		answer[--done] = '\0';
	}

	return done;
}

/** Execute a program.
 *
 * @param[out] out buffer to append plaintext (non valuepair) output.
 * @param[in] outlen length of out buffer.
 * @param[in] request Current request (may be NULL).
 * @param[in] cmd Command to execute. This is parsed into argv[] parts, then each individual argv
 *	part is xlat'ed.
 * @param[in] input_pairs list of value pairs - these will be available in the environment of the
 *	child.
 * @param[in] exec_wait set to 1 if you want to read from or write to child.
 * @param[in] shell_escape values before passing them as arguments.
 * @param[in] timeout amount of time to wait, in seconds.
 * @return
 *	- 0 if exec_wait==0.
 *	- exit code if exec_wait!=0.
 *	- -1 on failure.
 */
int radius_exec_program_legacy(char *out, size_t outlen,
			       request_t *request, char const *cmd, fr_pair_list_t *input_pairs,
			       bool exec_wait, bool shell_escape, fr_time_delta_t timeout)
{
	pid_t pid;
	int stdout_pipe;
	pid_t child_pid;
	int status;
	ssize_t len;
	char answer[4096];

	RDEBUG2("Executing: %s", cmd);

	if (out) *out = '\0';

	pid = radius_start_program_legacy(NULL, &stdout_pipe, NULL, cmd, request, exec_wait, input_pairs, shell_escape);
	if (pid < 0) {
		return -1;
	}

	if (!exec_wait) {
		return 0;
	}

	len = radius_readfrom_program_legacy(stdout_pipe, pid, timeout, answer, sizeof(answer));
	if (len < 0) {
		/*
		 *	Failure - radius_readfrom_program_legacy will
		 *	have called close(stdout_pipe) for us
		 */
		RERROR("Failed to read from child output");
		return -1;

	}
	answer[len] = '\0';

	/*
	 *	Make sure that the writer can't block while writing to
	 *	a pipe that no one is reading from anymore.
	 */
	close(stdout_pipe);

	if (len == 0) {
		goto wait;
	}

	if (out) {
		/*
		 *	We've not been told to extract output pairs,
		 *	just copy the programs output to the out
		 *	buffer.
		 */
		strlcpy(out, answer, outlen);
	}

wait:
	child_pid = waitpid(pid, &status, 0);
	if (child_pid == 0) {
		RERROR("Timeout waiting for child");

		return -2;
	}

	if (child_pid == pid) {
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			if (status != 0) {
				RERROR("Program returned code (%d) and output \"%pV\"", status,
				       fr_box_strvalue_len(answer, len));
			} else {
				RDEBUG2("Program returned code (%d) and output \"%pV\"", status,
					fr_box_strvalue_len(answer, len));
			}

			return status;
		}
	}

	RERROR("Abnormal child exit: %s", fr_syserror(errno));

	return -1;
}
