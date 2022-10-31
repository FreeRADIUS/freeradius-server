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
 * @file src/lib/server/exec.c
 * @brief Execute external programs.
 *
 * @copyright 2000-2004,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/util.h>
#include <freeradius-devel/server/exec_priv.h>

#define MAX_ENVP 1024

static _Thread_local char *env_arr[MAX_ENVP];				/* Avoid allocing 8k on the stack */
static _Thread_local char env_buff[NUM_ELEMENTS(env_arr) * 128];	/* Avoid allocing 128k on the stack */
static _Thread_local fr_sbuff_marker_t env_m[NUM_ELEMENTS(env_arr)];

/** Flatten a list into individual "char *" argv-style array
 *
 * @param[in] ctx	to allocate boxes in.
 * @param[out] argv_p	where output strings go
 * @param[in] in	boxes to flatten
 * @return
 *	- >= 0 number of array elements in argv
 *	- <0 on error
 */
static int exec_value_box_list_to_argv(TALLOC_CTX *ctx, char ***argv_p, fr_value_box_list_t const *in)
{
	char		**argv;
	fr_value_box_t	*vb = NULL;
	unsigned int	i = 0;
	size_t		argc = fr_value_box_list_len(in);

	argv = talloc_zero_array(ctx, char *, argc + 1);
	if (!argv) return -1;

	while ((vb = fr_dlist_next(in, vb))) {
		/*
		 *	Print the children of each group into the argv array.
		 */
		argv[i] = fr_value_box_list_aprint(argv, &vb->vb_group, NULL, NULL);
		if (!argv[i]) {
			talloc_free(argv);
			return -1;
		}
		i++;
	}

	*argv_p = argv;

	return argc;
}

/** Convert pairs from a request and a list of pairs into environmental variables
 *
 * @param[out] env_p		Where to write an array of \0 terminated strings.
 * @param[in] env_len		Length of env_p.
 * @param[out] env_sbuff	To write environmental variables too. Each variable
 *				will be written to the buffer, and separated with
 *				a '\0'.
 * @param[in] request		Will look for &control.Exec-Export items to convert to
 *      			env vars.
 * @param[in] env_pairs		Other items to convert to environmental variables.
 *				The dictionary attribute name will be converted to
 *				uppercase, and all '-' converted to '_' and will form
 *				the variable name.
 * @param[in] env_escape	Wrap string values in double quotes, and apply doublequote
 *				escaping to all environmental variable values.
 * @return
 *      - The number of environmental variables created.
 *	- -1 on failure.
 */
static CC_HINT(nonnull(1,3,4,5)) int exec_pair_to_env(char **env_p, size_t env_len, fr_sbuff_t *env_sbuff,
						      request_t *request, fr_pair_list_t *env_pairs, bool env_escape)
{
	char			*p;
	size_t			i, j;
	fr_dcursor_t		cursor;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	fr_sbuff_t		sbuff = FR_SBUFF_BIND_CURRENT(env_sbuff);

	/*
	 *	Set up the environment variables in the
	 *	parent, so we don't call libc functions that
	 *	hold mutexes.  They might be locked when we fork,
	 *	and will remain locked in the child.
	 */
	for (vp = fr_pair_list_head(env_pairs), i = 0;
	     vp && (i < env_len - 1);
	     vp = fr_pair_list_next(env_pairs, vp), i++) {
		fr_sbuff_marker(&env_m[i], &sbuff);

	     	if (fr_sbuff_in_strcpy(&sbuff, vp->da->name) <= 0) {
	     		REDEBUG("Out of buffer space adding attribute name");
	     		return -1;
	     	}

		/*
		 *	POSIX only allows names to contain
		 *	uppercase chars, digits, and
		 *	underscores.  Digits are not allowed
		 *	for the first char.
		 */
		p = fr_sbuff_current(&env_m[i]);
		if (isdigit((int)*p)) *p++ = '_';
		for (; p < fr_sbuff_current(&sbuff); p++) {
			if (isalpha((int)*p)) *p = toupper(*p);
			else if (*p == '-') *p = '_';
			else if (isdigit((int)*p)) continue;
			else *p = '_';
		}

		if (fr_sbuff_in_char(&sbuff, '=') <= 0) {
			REDEBUG("Out of buffer space");
			return -1;
		}

		if (env_escape) {
			if (fr_value_box_print_quoted(&sbuff, &vp->data, T_DOUBLE_QUOTED_STRING) < 0) {
				RPEDEBUG("Out of buffer space adding attribute value for %pV", &vp->data);
				return -1;
			}
		} else {
			/*
			 *	This can be zero length for empty strings
			 *
			 *	Note we don't do double quote escaping here,
			 *	we just escape unprintable chars.
			 *
			 *	Environmental variable values are not
			 *	restricted we likely wouldn't need to do
			 *	any escaping if we weren't dealing with C
			 *	strings.
			 *
			 *	If we end up passing binary data through
			 *	then the user can unescape the octal
			 *	sequences on the other side.
			 *
			 *	We unfortunately still need to escape '\'
			 *	because of this.
			 */
			if (fr_value_box_print(&sbuff, &vp->data, &fr_value_escape_unprintables) < 0) {
				RPEDEBUG("Out of buffer space adding attribute value for %pV", &vp->data);
				return -1;
			}
		}
		if (fr_sbuff_in_char(&sbuff, '\0') <= 0) {
			REDEBUG("Out of buffer space");
			return -1;
		}
	}

	/*
	 *	Do this as a separate step so that if env_sbuff
	 *	is extended at any point during the conversion
	 *	the sbuff we use is the final one.
	 */
	for (j = 0; j < i; j++) {
		env_p[j] = fr_sbuff_current(&env_m[j]);
	}


	da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_EXEC_EXPORT);
	if (da) {
		for (vp = fr_pair_dcursor_by_da_init(&cursor, &request->control_pairs, da);
		     vp && (i < (env_len - 1));
		     vp = fr_dcursor_next(&cursor)) {
			env_p[i++] = UNCONST(char *, vp->vp_strvalue);
		}
	}

	if (unlikely(i == (env_len - 1))) {
		REDEBUG("Out of space for environmental variables");
		return -1;
	}

	/*
	 *	NULL terminate for execve
	 */
	env_p[i] = NULL;

	return i;
}

/*
 *	Child process.
 *
 *	We try to be fail-safe here. So if ANYTHING
 *	goes wrong, we exit with status 1.
 */
static NEVER_RETURNS void exec_child(request_t *request, char **argv, char **envp,
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

/** Execute a program without waiting for the program to finish.
 *
 * @param[in] request		the request
 * @param[in] args		as returned by xlat_frame_eval()
 * @param[in] env_pairs		env_pairs to put into into the environment.  May be NULL.
 * @param[in] env_escape	Wrap string values in double quotes, and apply doublequote
 *				escaping to all environmental variable values.
 * @param[in] env_inherit	Inherit the environment from the current process.
 *				This will be merged with any variables from env_pairs.
 * @return
 *	- <0 on error
 *	- 0 on success
 *
 *  @todo - maybe take an fr_dcursor_t instead of env_pairs?  That
 *  would allow finer-grained control over the attributes to put into
 *  the environment.
 */
int fr_exec_fork_nowait(request_t *request, fr_value_box_list_t *args,
			fr_pair_list_t *env_pairs, bool env_escape, bool env_inherit)
{

	int			argc;
	char			**env;
	char			**argv;
	pid_t			pid;
	fr_value_box_t		*first;

	/*
	 *	Ensure that we don't do anything stupid.
	 */
	first =  fr_dlist_head(args);
	if (first->type == FR_TYPE_GROUP) first = fr_dlist_head(&first->vb_group);
	if (first->tainted) {
		REDEBUG("Program to run comes from tainted source - %pV", first);
		return -1;
	}

	/*
	 *	Get the environment variables.
	 */
	if (env_pairs && !fr_pair_list_empty(env_pairs)) {
		char **env_p, **env_end, **env_in;

		env_p = env_arr;
		env_end = env_p + NUM_ELEMENTS(env_arr);

		if (env_inherit) {
			for (env_in = environ; (env_p < env_end) && *env_in; env_in++, env_p++) *env_p = *env_in;
		}

		if (exec_pair_to_env(env_p, env_end - env_p,
				     &FR_SBUFF_OUT(env_buff, sizeof(env_buff)),
				     request, env_pairs, env_escape) < 0) return -1;

		env = env_arr;
	} else if (env_inherit) {
		env = environ;		/* Our current environment */
	} else {
		env = env_arr;
		env_arr[0] = NULL;
	}

	argc = exec_value_box_list_to_argv(request, &argv, args);
	if (argc < 0) return -1;

	if (RDEBUG_ENABLED3) {
		int i;
		char **env_p = env;

		for (i = 0; i < argc; i++) RDEBUG3("arg[%d] %s", i, argv[i]);
		while (*env_p) RDEBUG3("export %s", *env_p++);
	}

	pid = fork();

	/*
	 *	The child never returns from calling exec_child();
	 */
	if (pid == 0) {
		int unused[2] = { -1, -1 };

		exec_child(request, argv, env, false, unused, unused, unused);
	}

	if (pid < 0) {
		RPEDEBUG("Couldn't fork %s", argv[0]);
		return -1;
	}

	/*
	 *	Ensure that we can clean up any child processes.  We
	 *	don't want them left over as zombies.
	 */
	if (fr_event_pid_reap(unlang_interpret_event_list(request), pid, NULL, NULL) < 0) {
		int status;

		/*
		 *	Try and cleanup... really we have
		 *	no idea what state things are in.
		 */
		kill(pid, SIGKILL);
		waitpid(pid, &status, WNOHANG);

		return -1;
	}

	return 0;
}

/** Execute a program assuming that the caller waits for it to finish.
 *
 *  The caller takes responsibility for calling waitpid() on the returned PID.
 *
 *  The caller takes responsibility for reading from the returned FD,
 *  and closing it.
 *
 * @param[out] pid_p		The PID of the child
 * @param[out] stdin_fd		The stdin FD of the child.
 * @param[out] stdout_fd 	The stdout FD of the child.
 * @param[out] stderr_fd 	The stderr FD of the child.
 * @param[in] request		the request
 * @param[in] args		as returned by xlat_frame_eval()
 * @param[in] env_pairs		env_pairs to put into into the environment.  May be NULL.
 * @param[in] env_escape	Wrap string values in double quotes, and apply doublequote
 *				escaping to all environmental variable values.
 * @param[in] env_inherit	Inherit the environment from the current process.
 *				This will be merged with any variables from env_pairs.
 * @return
 *	- <0 on error
 *	- 0 on success
 *
 *  @todo - maybe take an fr_dcursor_t instead of env_pairs?  That
 *  would allow finer-grained control over the attributes to put into
 *  the environment.
 */
int fr_exec_fork_wait(pid_t *pid_p, int *stdin_fd, int *stdout_fd, int *stderr_fd,
		      request_t *request, fr_value_box_list_t *args,
		      fr_pair_list_t *env_pairs, bool env_escape, bool env_inherit)
{
	int		argc;
	char		**env;
	char		**argv;
	pid_t		pid;
	fr_value_box_t	*first;
	int		stdin_pipe[2] = {-1, -1};
	int		stderr_pipe[2] = {-1, -1};
	int		stdout_pipe[2] = {-1, -1};

	/*
	 *	Ensure that we don't do anything stupid.
	 */
	first =  fr_dlist_head(args);
	if (first->type == FR_TYPE_GROUP) first = fr_dlist_head(&first->vb_group);
	if (first->tainted) {
		fr_strerror_printf("Program to run comes from tainted source - %pV", first);
		return -1;
	}

	/*
	 *	Get the environment variables.
	 */
	if (env_pairs && !fr_pair_list_empty(env_pairs)) {
		char **env_p, **env_end, **env_in;

		env_p = env_arr;
		env_end = env_p + NUM_ELEMENTS(env_arr);

		if (env_inherit) {
			for (env_in = environ; (env_p < env_end) && *env_in; env_in++, env_p++) *env_p = *env_in;
		}

		if (exec_pair_to_env(env_p, env_end - env_p,
				     &FR_SBUFF_OUT(env_buff, sizeof(env_buff)),
				     request, env_pairs, env_escape) < 0) return -1;
		env = env_arr;
	} else if (env_inherit) {
		env = environ;		/* Our current environment */
	} else {
		env = env_arr;
		env[0] = NULL;
	}

	argc = exec_value_box_list_to_argv(request, &argv, args);
	if (argc < 0) {
	error:
		return -1;
	}

	if (DEBUG_ENABLED3) {
		int i;
		char **env_p = env;

		for (i = 0; i < argc; i++) RDEBUG3("arg[%d] %s", i, argv[i]);
		while (*env_p) RDEBUG3("export %s", *env_p++);
	}

	if (stdin_fd) {
		if (pipe(stdin_pipe) < 0) {
		error2:
			fr_strerror_const_push("Failed opening pipe to read to child");
			talloc_free(argv);
			goto error;
		}
		if (fr_nonblock(stdin_pipe[1]) < 0) PERROR("Error setting stdin to nonblock");
	}

	if (stdout_fd) {
		if (pipe(stdout_pipe) < 0) {
		error3:
			close(stdin_pipe[0]);
			close(stdin_pipe[1]);
			goto error2;
		}
		if (fr_nonblock(stdout_pipe[0]) < 0) PERROR("Error setting stdout to nonblock");
	}

	if (stderr_fd) {
		if (pipe(stderr_pipe) < 0) {
			close(stdout_pipe[0]);
			close(stdout_pipe[1]);
			goto error3;
		}
		if (fr_nonblock(stderr_pipe[0]) < 0) PERROR("Error setting stderr to nonblock");
	}

	pid = fork();

	/*
	 *	The child never returns from calling exec_child();
	 */
	if (pid == 0) exec_child(request, argv, env, true, stdin_pipe, stdout_pipe, stderr_pipe);

	if (pid < 0) {
		PERROR("Couldn't fork %s", argv[0]);
		close(stdin_pipe[0]);
		close(stdin_pipe[1]);
		close(stdout_pipe[0]);
		close(stdout_pipe[1]);
		close(stderr_pipe[0]);
		close(stderr_pipe[1]);
		talloc_free(argv);
		return -1;
	}

	/*
	 *	Tell the caller the childs PID, and the FD to read
	 *	from.
	 */
	*pid_p = pid;

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

	return 0;
}

/** Cleans up an exec'd process on error
 *
 * This function is intended to be called at any point after a successful
 * #fr_exec_start call in order to release resources and cleanup
 * zombie processes.
 *
 * @param[in] exec	state to cleanup.
 * @param[in] signal	If non-zero, and we think the process is still
 *			running, send it a signal to cause it to exit.
 *			The PID reaper we insert here will cleanup its
 *			state so it doesn't become a zombie.
 *
 */
void fr_exec_cleanup(fr_exec_state_t *exec, int signal)
{
	request_t	*request = exec->request;
	fr_event_list_t	*el = unlang_interpret_event_list(request);

	if (exec->pid >= 0) {
		RDEBUG3("Cleaning up exec state for pid %u", exec->pid);
	} else {
		RDEBUG3("Cleaning up failed exec", exec->pid);
	}

	/*
	 *	There's still an EV_PROC event installed
	 *	for the PID remove it (there's a destructor).
	 */
	if (exec->ev_pid) {
		talloc_const_free(exec->ev_pid);
		fr_assert(!exec->ev_pid);	/* Should be NULLified by destructor */
	}

	if (exec->stdout_fd >= 0) {
		if (fr_event_fd_delete(el, exec->stdout_fd, FR_EVENT_FILTER_IO) < 0){
			RPERROR("Failed removing stdout handler");
		}
		close(exec->stdout_fd);
		exec->stdout_fd = -1;
	}

	if (exec->stderr_fd >= 0) {
		if (fr_event_fd_delete(el, exec->stderr_fd, FR_EVENT_FILTER_IO) < 0) {
			RPERROR("Failed removing stderr handler");
		}
		close(exec->stderr_fd);
		exec->stderr_fd = -1;
	}

	if (exec->pid >= 0) {
		if (signal > 0) kill(exec->pid, signal);

		if (unlikely(fr_event_pid_reap(el, exec->pid, NULL, NULL) < 0)) {
			int status;

			RPERROR("Failed setting up async PID reaper, PID %u may now be a zombie", exec->pid);

			/*
			 *	Try and cleanup... really we have
			 *	no idea what state things are in.
			 */
			kill(exec->pid, SIGKILL);
			waitpid(exec->pid, &status, WNOHANG);
		}
		exec->pid = -1;
	}

	if (exec->ev) fr_event_timer_delete(&exec->ev);
}

/*
 *	Callback when exec has completed.  Record the status and tidy up.
 */
static void exec_reap(fr_event_list_t *el, pid_t pid, int status, void *uctx)
{
	fr_exec_state_t *exec = uctx;	/* may not be talloced */
	request_t	*request = exec->request;
	int		wait_status = 0;
	int		ret;

	if (!fr_cond_assert(pid == exec->pid)) RWDEBUG("Event PID %u and exec->pid %u do not match", pid, exec->pid);

	/*
	 *	Reap the process.  This is needed so the processes
	 *	don't stick around indefinitely.  libkqueue/kqueue
	 *	does not do this for us!
	 */
	ret = waitpid(exec->pid, &wait_status, WNOHANG);
	if (ret < 0) {
		RWDEBUG("Failed reaping PID %i: %s", exec->pid, fr_syserror(errno));
	/*
	 *	Either something cleaned up the process before us
	 *	(bad!), or the notification system is broken
	 *	(also bad!)
	 *
	 *	This could be caused by 3rd party libraries.
	 */
	} else if (ret == 0) {
		RWDEBUG("Something reaped PID %d before us!", exec->pid);
		wait_status = status;
	}

	/*
	 *	kevent should be returning an identical status value
	 *	to waitpid.
	 */
	if (wait_status != status) RWDEBUG("Exit status from waitpid (%d) and kevent (%d) disagree",
					   wait_status, status);

	if (WIFEXITED(wait_status)) {
		RDEBUG("Program exited with status code %d", WEXITSTATUS(wait_status));
		exec->status = WEXITSTATUS(wait_status);
	} else if (WIFSIGNALED(wait_status)) {
		RDEBUG("Program exited due to signal with status code %d", WTERMSIG(wait_status));
		exec->status = -WTERMSIG(wait_status);
	} else {
		RDEBUG("Program exited due to unknown status %d", wait_status);
		exec->status = -wait_status;
	}
	exec->pid = -1;	/* pid_t is signed */

	if (exec->ev) fr_event_timer_delete(&exec->ev);

	/*
	 *	Process exit notifications (EV_PROC) and file
	 *	descriptor read events (EV_READ) can race.
	 *
	 *	So... If the process has exited, trigger the IO
	 *	handlers manually.
	 *
	 *	This is icky, but the only other option is to
	 *      enhance our event loop so we can look for
	 *	pending events associated with file
	 *	descriptors...
	 *
	 *	Even then we might get the file readable
	 *	notification and the process exited notification
	 *	in different kevent() calls on busy systems.
	 */
	if (exec->stdout_fd >= 0) {
		fr_event_fd_t		*ef;
		fr_event_fd_cb_t	cb;

		ef = fr_event_fd_handle(el, exec->stdout_fd, FR_EVENT_FILTER_IO);
		if (!fr_cond_assert_msg(ef, "no event associated with processes's stdout fd (%i)",
					exec->stdout_fd)) goto close_stdout;

		cb = fr_event_fd_cb(ef, EVFILT_READ, 0);
		if (!fr_cond_assert_msg(cb, "no read callback associated with processes's stdout_fd (%i)",
					exec->stdout_fd)) goto close_stdout;

		/*
		 *	Call the original read callback that
		 *	was setup here to ensure that there's
		 *	no pending data.
		 */
		cb(el, exec->stdout_fd, 0, fr_event_fd_uctx(ef));

		/*
		 *	...and delete the event from the event
		 *	loop.  This should also suppress the
		 *      EVFILT_READ event if there was one.
		 */
		(void) fr_event_fd_delete(el, exec->stdout_fd, FR_EVENT_FILTER_IO);
	close_stdout:
		close(exec->stdout_fd);
		exec->stdout_fd = -1;
	}

	if (exec->stderr_fd >= 0) {
		fr_event_fd_t		*ef;
		fr_event_fd_cb_t	cb;

		ef = fr_event_fd_handle(el, exec->stderr_fd, FR_EVENT_FILTER_IO);
		if (!fr_cond_assert_msg(ef, "no event associated with processes's stderr fd (%i)",
					exec->stderr_fd)) goto close_stderr;

		cb = fr_event_fd_cb(ef, EVFILT_READ, 0);
		if (!fr_cond_assert_msg(cb, "no read callback associated with processes's stderr_fd (%i)",
					exec->stderr_fd)) goto close_stderr;

		cb(el, exec->stderr_fd, 0, fr_event_fd_uctx(ef));
		(void) fr_event_fd_delete(el, exec->stderr_fd, FR_EVENT_FILTER_IO);
	close_stderr:
		close(exec->stderr_fd);
		exec->stderr_fd = -1;
	}

	unlang_interpret_mark_runnable(exec->request);
}

/*
 *	Callback when an exec times out.
 */
static void exec_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_exec_state_t *exec = uctx; /* may not be talloced */
	request_t	*request = exec->request;

	if (exec->stdout_fd < 0) {
		REDEBUG("Timeout waiting for program to exit - killing it and failing the request");
	} else {
		REDEBUG("Timeout running program - killing it and failing the request");
	}
	exec->failed = true;

	fr_exec_cleanup(exec, SIGKILL);
	unlang_interpret_mark_runnable(exec->request);
}

/*
 *	Callback to read stdout from an exec into the pre-prepared extensible sbuff
 */
static void exec_stdout_read(UNUSED fr_event_list_t *el, int fd, int flags, void *uctx) {
	fr_exec_state_t		*exec = uctx;
	request_t		*request = exec->request;
	ssize_t			data_len, remaining;
	fr_sbuff_marker_t	start_m;

	fr_sbuff_marker(&start_m, &exec->stdout_buff);

	do {
		/*
		 *	Read in 128 byte chunks
		 */
		remaining = fr_sbuff_extend_lowat(NULL, &exec->stdout_buff, 128);

		/*
		 *	Ran out of buffer space.
		 */
		if (unlikely(!remaining)) {
			REDEBUG("Too much output from program - killing it and failing the request");

		error:
			exec->failed = true;
			fr_exec_cleanup(exec, SIGKILL);
			break;
		}

		data_len = read(fd, fr_sbuff_current(&exec->stdout_buff), remaining);
		if (data_len < 0) {
			if (errno == EINTR) continue;

			/*
			 *	This can happen when the callback is called
			 *	manually when we're reaping the process.
			 *
			 *	It's pretty much an identical condition to
			 *	data_len == 0.
			 */
			if (errno == EWOULDBLOCK) break;

			REDEBUG("Error reading from child program - %s", fr_syserror(errno));
			goto error;
		}

		/*
		 *	Even if we get 0 now the process may write more data later
		 *	before it completes, so we leave the fd handlers in place.
		 */
		if (data_len == 0) break;

		fr_sbuff_advance(&exec->stdout_buff, data_len);
	} while (remaining == data_len);	/* If process returned maximum output, loop again */

	if (flags & EV_EOF) {
		/*
		 *	We've received EOF - so the process has finished writing
		 *	Remove event and tidy up
		 */
		(void) fr_event_fd_delete(unlang_interpret_event_list(exec->request), fd, FR_EVENT_FILTER_IO);
		close(fd);
		exec->stdout_fd = -1;

		if (exec->pid < 0) {
			/*
			 *	Child has already exited - unlang can resume
			 */
			if (exec->ev) fr_event_timer_delete(&exec->ev);
			unlang_interpret_mark_runnable(exec->request);
		}
	}

	/*
	 *	Only print if we got additional data
	 */
	if (RDEBUG_ENABLED2 && fr_sbuff_behind(&start_m)) {
		RDEBUG2("pid %u (stdout) - %pV", exec->pid,
			fr_box_strvalue_len(fr_sbuff_current(&start_m),
					    fr_sbuff_behind(&start_m)));
	}

	fr_sbuff_marker_release(&start_m);
}

/** Call an child program, optionally reading it's output
 *
 * @note If the caller set need_stdin = true, it is the caller's
 *	 responsibility to close exec->std_in and remove it from any event loops
 *	 if this function returns 0 (success).
 *
 * @param[in] ctx		to allocate events in.
 * @param[in,out] exec		structure holding the state of the external call.
 * @param[in] request		currently being processed.
 * @param[in] args		to call as a fr_value_boc_list_t.  Program will
 *      			be the first box and arguments in the subsequent boxes.
 * @param[in] env_pairs		list of pairs to be presented as evironment variables
 *				to the child.
 * @param[in] env_escape	Wrap string values in double quotes, and apply doublequote
 *				escaping to all environmental variable values.
 * @param[in] env_inherit	Inherit the environment from the current process.
 *				This will be merged with any variables from env_pairs.
 * @param[in] need_stdin	If true, allocate a pipe that will allow us to send data to the
 *      			process.
 * @param[in] store_stdout	if true keep a copy of stdout in addition to logging
 *				it if RDEBUG_ENABLED2.
 * @param[in] stdout_ctx	ctx to alloc stdout data in.
 * @param[in] timeout		to wait for child to complete.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int fr_exec_start(TALLOC_CTX *ctx, fr_exec_state_t *exec, request_t *request,
		  fr_value_box_list_t *args,
		  fr_pair_list_t *env_pairs, bool env_escape, bool env_inherit,
		  bool need_stdin,
		  bool store_stdout, TALLOC_CTX *stdout_ctx,
		  fr_time_delta_t timeout)
{
	int		*stdout_fd = (store_stdout || RDEBUG_ENABLED2) ? &exec->stdout_fd : NULL;
	fr_event_list_t	*el = unlang_interpret_event_list(request);

	*exec = (fr_exec_state_t){
		.request = request,
		.env_pairs = env_pairs,
		.pid = -1,
		.stdout_fd = -1,
		.stderr_fd = -1,
		.stdin_fd = -1,
		.status = -1,				/* default to program didn't work */
		.stdin_used = need_stdin,
		.stdout_used = store_stdout,
		.stdout_ctx = stdout_ctx
	};

	if (fr_exec_fork_wait(&exec->pid, exec->stdin_used ? &exec->stdin_fd : NULL,
			      stdout_fd, &exec->stderr_fd, request, args,
			      exec->env_pairs, env_escape, env_inherit) < 0) {
		RPEDEBUG("Failed executing program");
	fail:
		/*
		 *	Not done in fr_exec_cleanup as it's
		 *	usually the caller's responsibility.
		 */
		if (exec->stdin_fd >= 0) {
			close(exec->stdin_fd);
			exec->stdin_fd = -1;
		}
		fr_exec_cleanup(exec, 0);
		return -1;
	}

	/*
	 *	Tell the event loop that it needs to wait for this PID
	 */
	if (fr_event_pid_wait(ctx, el, &exec->ev_pid, exec->pid, exec_reap, exec) < 0) {
		exec->pid = -1;
		RPEDEBUG("Failed adding watcher for child process");

	fail_and_close:
		/*
		 *	Avoid spurious errors in fr_exec_cleanup
		 *	when it tries to remove FDs from the
		 *	event loop that were never added.
		 */
		if (exec->stdout_fd >= 0) {
			close(exec->stdout_fd);
			exec->stdout_fd = -1;
		}

		if (exec->stderr_fd >= 0) {
			close(exec->stderr_fd);
			exec->stderr_fd = -1;
		}

		goto fail;
	}

	/*
	 *	Setup event to kill the child process after a period of time.
	 */
	if (fr_time_delta_ispos(timeout) &&
	    (fr_event_timer_in(ctx, el, &exec->ev, timeout, exec_timeout, exec) < 0)) goto fail_and_close;

	/*
	 *	If we need to parse stdout, insert a special IO handler that
	 *	aggregates all stdout data into an expandable buffer.
	 */
	if (exec->stdout_used) {
		/*
		 *	Accept a maximum of 32k of data from the process.
		 */
		fr_sbuff_init_talloc(exec->stdout_ctx, &exec->stdout_buff, &exec->stdout_tctx, 128, 32 * 1024);
		if (fr_event_fd_insert(ctx, el, exec->stdout_fd, exec_stdout_read, NULL, NULL, exec) < 0) {
			RPEDEBUG("Failed adding event listening to stdout");
			goto fail_and_close;
		}

	/*
	 *	If the caller doesn't want the output box, we still want to copy stdout
	 *	into the request log if we're logging at a high enough level of verbosity.
	 */
	} else if (RDEBUG_ENABLED2) {
		snprintf(exec->stdout_prefix, sizeof(exec->stdout_prefix), "pid %u (stdout)", exec->pid);
		exec->stdout_uctx = (log_fd_event_ctx_t) {
			.type = L_DBG,
			.lvl = L_DBG_LVL_2,
			.request = request,
			.prefix = exec->stdout_prefix
		};

		if (fr_event_fd_insert(ctx, el, exec->stdout_fd, log_request_fd_event,
				       NULL, NULL, &exec->stdout_uctx) < 0){
			RPEDEBUG("Failed adding event listening to stdout");
			goto fail_and_close;
		}
	}

	/*
	 *	Send stderr to the request log as error messages with a custom prefix
	 */
	snprintf(exec->stderr_prefix, sizeof(exec->stderr_prefix), "pid %u (stderr)", exec->pid);
	exec->stderr_uctx = (log_fd_event_ctx_t) {
		.type = L_DBG_ERR,
		.lvl = L_DBG_LVL_1,
		.request = request,
		.prefix = exec->stderr_prefix
	};

	if (fr_event_fd_insert(ctx, el, exec->stderr_fd, log_request_fd_event,
			       NULL, NULL, &exec->stderr_uctx) < 0) {
		RPEDEBUG("Failed adding event listening to stderr");
		close(exec->stderr_fd);
		exec->stderr_fd = -1;
		goto fail;
	}

	return 0;
}
