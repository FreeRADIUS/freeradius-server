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
 * @copyright 2022-2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000-2004,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <stdint.h>

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/exec_priv.h>
#include <freeradius-devel/server/util.h>

#define MAX_ENVP 1024

static _Thread_local char *env_exec_arr[MAX_ENVP];	/* Avoid allocing 8k on the stack */

/** Flatten a list into individual "char *" argv-style array
 *
 * @param[in] ctx	to allocate boxes in.
 * @param[out] argv_p	where output strings go
 * @param[in] in	boxes to flatten
 * @return
 *	- >= 0 number of array elements in argv
 *	- <0 on error
 */
int fr_exec_value_box_list_to_argv(TALLOC_CTX *ctx, char ***argv_p, fr_value_box_list_t const *in)
{
	char			**argv;
	unsigned int		i = 0;
	size_t			argc = fr_value_box_list_num_elements(in);
	fr_value_box_t const	*first;

	/*
	 *	Check that we're not trying to run a program from
	 *	a tainted source.
	 */
	first = fr_value_box_list_head(in);
	if (first->type == FR_TYPE_GROUP) first = fr_value_box_list_head(&first->vb_group);
	if (first->tainted) {
		fr_strerror_printf("Program to run comes from tainted source - %pV", first);
		return -1;
	}

	argv = talloc_zero_array(ctx, char *, argc + 1);
	if (!argv) return -1;

	fr_value_box_list_foreach(in, vb) {
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

/** Print debug information showing the arguments and environment for a process
 *
 * @param[in] request		The current request, may be NULL.
 * @param[in] argv_in		arguments to pass to process.
 * @param[in] env_in		environment to pass to process.
 * @param[in] env_inherit	print debug for the environment from the environment.
 */
static inline CC_HINT(always_inline) void exec_debug(request_t *request, char **argv_in, char **env_in, bool env_inherit)
{
	char **p;

	if (argv_in) for (p = argv_in; *p; p++) ROPTIONAL(RDEBUG3, DEBUG3, "arg[%d] %s", (unsigned int)(p - argv_in), *p);
	if (env_in) for (p = env_in; *p; p++) ROPTIONAL(RDEBUG3, DEBUG3, "export %s", *p);
	if (env_inherit) for (p = environ; *p; p++) ROPTIONAL(RDEBUG3, DEBUG3, "export %s", *p);
}

/** Convert pairs from a request and a list of pairs into environmental variables
 *
 * @param[out] env_p		Where to write an array of \0 terminated strings.
 * @param[in] env_len		Length of env_p.
 * @param[out] env_sbuff	To write environmental variables too. Each variable
 *				will be written to the buffer, and separated with
 *				a '\0'.
 * @param[in] env_m		an array of markers of the same length as env_len.
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
static inline CC_HINT(nonnull(1,3,4,5)) CC_HINT(always_inline)
int exec_pair_to_env(char **env_p, size_t env_len,
		     fr_sbuff_t *env_sbuff, fr_sbuff_marker_t env_m[],
		     request_t *request, fr_pair_list_t *env_pairs, bool env_escape)
{
	char			*p;
	size_t			i, j;
	fr_dcursor_t		cursor;
	fr_dict_attr_t const	*da;
	fr_sbuff_t		sbuff = FR_SBUFF_BIND_CURRENT(env_sbuff);

	if (!env_pairs) {
		env_p[0] = NULL;
		return 0;
	}

	/*
	 *	Set up the environment variables in the
	 *	parent, so we don't call libc functions that
	 *	hold mutexes.  They might be locked when we fork,
	 *	and will remain locked in the child.
	 */
	i = 0;
	fr_pair_list_foreach_leaf(env_pairs, vp) {
		fr_sbuff_marker(&env_m[i], &sbuff);

	     	if (fr_sbuff_in_strcpy(&sbuff, vp->da->name) <= 0) {
	     		fr_strerror_printf("Out of buffer space adding attribute name");
	     		return -1;
	     	}

		/*
		 *	POSIX only allows names to contain
		 *	uppercase chars, digits, and
		 *	underscores.  Digits are not allowed
		 *	for the first char.
		 */
		p = fr_sbuff_current(&env_m[i]);
		if (isdigit((uint8_t)*p)) *p++ = '_';
		for (; p < fr_sbuff_current(&sbuff); p++) {
			if (isalpha((uint8_t)*p)) *p = toupper((uint8_t) *p);
			else if (*p == '-') *p = '_';
			else if (isdigit((uint8_t)*p)) goto next;
			else *p = '_';
		}

		if (fr_sbuff_in_char(&sbuff, '=') <= 0) {
			fr_strerror_printf("Out of buffer space");
			return -1;
		}

		if (env_escape) {
			if (fr_value_box_print_quoted(&sbuff, &vp->data, T_DOUBLE_QUOTED_STRING) < 0) {
				fr_strerror_printf("Out of buffer space adding attribute value for %pV", &vp->data);
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
				fr_strerror_printf("Out of buffer space adding attribute value for %pV", &vp->data);
				return -1;
			}
		}
		if (fr_sbuff_in_char(&sbuff, '\0') <= 0) {
			fr_strerror_printf("Out of buffer space");
			return -1;
		}

	next:
		i++;
		if (i == (env_len - 1)) break;
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
		fr_pair_t *vp;

		for (vp = fr_pair_dcursor_by_da_init(&cursor, &request->control_pairs, da);
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
			env_p[i++] = UNCONST(char *, vp->vp_strvalue);
		}
	}

	if (unlikely(i == (env_len - 1))) {
		fr_strerror_printf("Out of space for environmental variables");
		return -1;
	}

	/*
	 *	NULL terminate for execve
	 */
	env_p[i] = NULL;

	return i;
}

/** Convert env_pairs into an array of environmental variables using thread local buffers
 *
 * @param[in] request		Will be searched for control.Exec-Export pairs.
 * @param[in] env_pairs		env_pairs to put into into the environment.  May be NULL.
 * @param[in] env_escape	Wrap string values in double quotes, and apply doublequote
 *				escaping to all environmental variable values.
 * @return
 *	- An array of environmental variable definitions, valid until the next call
 *	  to fr_exec_pair_to_env within the same thread.
 *	- NULL on error.  Error retrievable fr_strerror().
 */
char **fr_exec_pair_to_env(request_t *request, fr_pair_list_t *env_pairs, bool env_escape)
{
	static _Thread_local char *env_arr[MAX_ENVP];				/* Avoid allocing 8k on the stack */
	static _Thread_local char env_buff[NUM_ELEMENTS(env_arr) * 128];	/* Avoid allocing 128k on the stack */
	static _Thread_local fr_sbuff_marker_t env_m[NUM_ELEMENTS(env_arr)];

	if (exec_pair_to_env(env_arr, NUM_ELEMENTS(env_arr),
			     &FR_SBUFF_OUT(env_buff, sizeof(env_buff)), env_m,
			     request, env_pairs, env_escape) < 0) return NULL;

	return env_arr;
}

/** Start a child process
 *
 * We try to be fail-safe here. So if ANYTHING goes wrong, we exit with status 1.
 *
 * @param[in] argv		array of arguments to pass to child.
 * @param[in] envp		array of environment variables in form `<attr>=<val>`
 * @param[in] exec_wait		if true, redirect child process' stdin, stdout, stderr
 *				to the pipes provided, redirecting any to /dev/null
 *				where no pipe was provided.  If false redirect
 *				stdin, and stdout to /dev/null.
 * @param[in] debug		If true, and !exec_wait, don't molest stderr.
 * @param[in] stdin_pipe	the pipe used to write data to the process. STDIN will
 *				be set to stdin_pipe[0], stdin_pipe[1] will be closed.
 * @param[in] stdout_pipe	the pipe used to read data from the process.
 *				STDOUT will be set to stdout_pipe[1], stdout_pipe[0]
 *				will be closed.
 * @param[in] stderr_pipe	the pipe used to read error text from the process.
 *				STDERR will be set to stderr_pipe[1], stderr_pip[0]
 *				will be closed.
 */
static NEVER_RETURNS void exec_child(char **argv, char **envp,
				     bool exec_wait, bool debug,
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
		if (!debug) dup2(devnull, STDERR_FILENO);
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
	 *	Disarm the global destructors for the same reason
	 */
	fr_atexit_global_disarm_all();

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

/** Merge extra environmental variables and potentially the inherited environment
 *
 * @param[in] env_in		to merge.
 * @param[in] env_inherit	inherite environment from radiusd.
 * @return merged environmental variables.
 */
static
char **exec_build_env(char **env_in, bool env_inherit)
{
	size_t num_in, num_environ;

	/*
	 *	Not inheriting the radiusd environment, just return whatever we were given.
	 */
	if (!env_inherit) {
		return env_in;
	}

	/*
	 *	No additional environment variables, just return the ones from radiusd.
	 */
	if (!env_in) return environ;

	for (num_environ = 0; environ[num_environ] != NULL; num_environ++) {
		/* nothing */
	}

	/*
	 *	No room to copy anything after the environment variables.
	 */
	if (((num_environ + 1) == NUM_ELEMENTS(env_exec_arr))) {
		return environ;
	}

	/*
	 *	Copy the radiusd environment to the local array
	 */
	memcpy(env_exec_arr, environ, (num_environ + 1) * sizeof(environ[0]));

	for (num_in = 0; env_in[num_in] != NULL; num_in++) {
		if ((num_environ + num_in + 1) >= NUM_ELEMENTS(env_exec_arr)) break;
	}

	memcpy(env_exec_arr + num_environ, env_in, num_in * sizeof(environ[0]));
	env_exec_arr[num_environ + num_in] = NULL;

	return env_exec_arr;
}

/** Execute a program without waiting for the program to finish.
 *
 * @param[in] el		event list to insert reaper child into.
 * @param[in] argv_in		arg[0] is the path to the program, arg[...] are arguments
 *				to pass to the program.
 * @param[in] env_in		any additional environmental variables to pass to the program.
 * @param[in] env_inherit	Inherit the environment from the current process.
 *				This will be merged with any variables from env_pairs.
 * @param[in] debug		If true, STDERR will be left open and pointing to the stderr
 *				descriptor of the parent.
 * @return
 *	- <0 on error.  Error retrievable fr_strerror().
 *	- 0 on success
 *
 *  @todo - maybe take an fr_dcursor_t instead of env_pairs?  That
 *  would allow finer-grained control over the attributes to put into
 *  the environment.
 */
int fr_exec_fork_nowait(fr_event_list_t *el, char **argv_in, char **env_in, bool env_inherit, bool debug)
{
	char		**env;
	pid_t		pid;

	env = exec_build_env(env_in, env_inherit);
	pid = fork();
	/*
	 *	The child never returns from calling exec_child();
	 */
	if (pid == 0) {
		int unused[2] = { -1, -1 };

		exec_child(argv_in, env, false, debug, unused, unused, unused);
	}

	if (pid < 0) {
		fr_strerror_printf("Couldn't fork %s", argv_in[0]);
	error:
		return -1;
	}

	/*
	 *	Ensure that we can clean up any child processes.  We
	 *	don't want them left over as zombies.
	 */
	if (fr_event_pid_reap(el, pid, NULL, NULL) < 0) {
		int status;

		/*
		 *	Try and cleanup... really we have
		 *	no idea what state things are in.
		 */
		kill(pid, SIGKILL);
		waitpid(pid, &status, WNOHANG);
		goto error;
	}

	return 0;
}

/** Execute a program assuming that the caller waits for it to finish.
 *
 * The caller takes responsibility for calling waitpid() on the returned PID.
 *
 * The caller takes responsibility for reading from the returned FD,
 * and closing it.
 *
 * @param[out] pid_p		The PID of the child
 * @param[out] stdin_fd		The stdin FD of the child.
 * @param[out] stdout_fd 	The stdout FD of the child.
 * @param[out] stderr_fd 	The stderr FD of the child.
 * @param[in] argv_in		arg[0] is the path to the program, arg[...] are arguments
 *				to pass to the program.
 * @param[in] env_in		Environmental variables to pass to the program.
 * @param[in] env_inherit	Inherit the environment from the current process.
 *				This will be merged with any variables from env_pairs.
 * @param[in] debug		If true, STDERR will be left open and pointing to the stderr
 *				descriptor of the parent, if no stderr_fd pointer is provided.
 * @return
 *	- <0 on error.  Error retrievable fr_strerror().
 *	- 0 on success.
 *
 *  @todo - maybe take an fr_dcursor_t instead of env_pairs?  That
 *  would allow finer-grained control over the attributes to put into
 *  the environment.
 */
int fr_exec_fork_wait(pid_t *pid_p,
		      int *stdin_fd, int *stdout_fd, int *stderr_fd,
		      char **argv_in, char **env_in, bool env_inherit, bool debug)
{
	char		**env;
	pid_t		pid;
	int		stdin_pipe[2] = {-1, -1};
	int		stderr_pipe[2] = {-1, -1};
	int		stdout_pipe[2] = {-1, -1};

	if (stdin_fd) {
		if (pipe(stdin_pipe) < 0) {
			fr_strerror_const("Failed opening pipe to write to child");

		error1:
			return -1;
		}
		if (fr_nonblock(stdin_pipe[1]) < 0) fr_strerror_const("Error setting stdin to nonblock");
	}

	if (stdout_fd) {
		if (pipe(stdout_pipe) < 0) {
			fr_strerror_const("Failed opening pipe to read from child");

		error2:
			close(stdin_pipe[0]);
			close(stdin_pipe[1]);
			goto error1;
		}
		if (fr_nonblock(stdout_pipe[0]) < 0) fr_strerror_const("Error setting stdout to nonblock");
	}

	if (stderr_fd) {
		if (pipe(stderr_pipe) < 0) {
			fr_strerror_const("Failed opening pipe to read from child");

		error3:
			close(stdout_pipe[0]);
			close(stdout_pipe[1]);
			goto error2;
		}
		if (fr_nonblock(stderr_pipe[0]) < 0) fr_strerror_const("Error setting stderr to nonblock");
	}

	env = exec_build_env(env_in, env_inherit);
	pid = fork();

	/*
	 *	The child never returns from calling exec_child();
	 */
	if (pid == 0) exec_child(argv_in, env, true, debug, stdin_pipe, stdout_pipe, stderr_pipe);
	if (pid < 0) {
		fr_strerror_printf("Couldn't fork %s", argv_in[0]);
		*pid_p = -1;	/* Ensure the PID is set even if the caller didn't check the return code */
		goto error3;
	}

	/*
	 *	Tell the caller the childs PID, and the FD to read from.
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

/** Similar to fr_exec_oneshot, but does not attempt to parse output
 *
 * @param[in] request		currently being processed, may be NULL.
 * @param[in] args		to call as a fr_value_box_list_t.  Program will
 *      			be the first box and arguments in the subsequent boxes.
 * @param[in] env_pairs		list of pairs to be presented as environment variables
 *				to the child.
 * @param[in] env_escape	Wrap string values in double quotes, and apply doublequote
 *				escaping to all environmental variable values.
 * @param[in] env_inherit	Inherit the environment from the current process.
 *				This will be merged with any variables from env_pairs.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_exec_oneshot_nowait(request_t *request,
			   fr_value_box_list_t *args, fr_pair_list_t *env_pairs,
			   bool env_escape, bool env_inherit)
{
	char **argv = NULL;
	char **env = NULL;
	int ret;

	if (unlikely(fr_exec_value_box_list_to_argv(unlang_interpret_frame_talloc_ctx(request), &argv, args) < 0)) {
		RPEDEBUG("Failed converting boxes to argument strings");
		return -1;
	}

	if (env_pairs) {
		env = fr_exec_pair_to_env(request, env_pairs, env_escape);
		if (unlikely(env == NULL)) {
			RPEDEBUG("Failed creating environment pairs");
			return -1;
		}
	}

	if (RDEBUG_ENABLED3) exec_debug(request, argv, env, env_inherit);
	ret = fr_exec_fork_nowait(unlang_interpret_event_list(request), argv, env,
			          env_inherit, ROPTIONAL_ENABLED(RDEBUG_ENABLED2, DEBUG_ENABLED2));
	talloc_free(argv);
	if (unlikely(ret < 0)) RPEDEBUG("Failed executing program");

	return ret;
}

/** Cleans up an exec'd process on error
 *
 * This function is intended to be called at any point after a successful
 * #fr_exec_oneshot call in order to release resources and cleanup
 * zombie processes.
 *
 * @param[in] exec	state to cleanup.
 * @param[in] signal	If non-zero, and we think the process is still
 *			running, send it a signal to cause it to exit.
 *			The PID reaper we insert here will cleanup its
 *			state so it doesn't become a zombie.
 *
 */
void fr_exec_oneshot_cleanup(fr_exec_state_t *exec, int signal)
{
	request_t	*request = exec->request;
	fr_event_list_t	*el = unlang_interpret_event_list(request);

	if (exec->pid >= 0) {
		RDEBUG3("Cleaning up exec state for PID %u", exec->pid);
	} else {
		RDEBUG3("Cleaning up failed exec");
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

	FR_TIMER_DELETE(&exec->ev);
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

	FR_TIMER_DELETE(&exec->ev);

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
static void exec_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	fr_exec_state_t *exec = uctx; /* may not be talloced */
	bool		exit_timeout;

	/*
	 *	Some race conditions cause fr_exec_oneshot_cleanup to insert
	 *	a new event, which calls fr_strerror_clear(), resulting in
	 *	inconsistent error messages.
	 *	Recording the condition to drive the error message here and
	 *	then setting after tidying up keeps things consistent.
	 */
	exit_timeout = (exec->stdout_fd < 0);

	exec->failed = FR_EXEC_FAIL_TIMEOUT;
	fr_exec_oneshot_cleanup(exec, SIGKILL);

	if (exit_timeout) {
		fr_strerror_const("Timeout waiting for program to exit");
	} else {
		fr_strerror_const("Timeout running program");
	}

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
			exec->failed = FR_EXEC_FAIL_TOO_MUCH_DATA;
			fr_exec_oneshot_cleanup(exec, SIGKILL);
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
			FR_TIMER_DELETE(&exec->ev);
			unlang_interpret_mark_runnable(exec->request);
		}
	}

	/*
	 *	Only print if we got additional data
	 */
	if (RDEBUG_ENABLED2 && fr_sbuff_behind(&start_m)) {
		RDEBUG2("pid %u (stdout) - %pV", exec->pid,
			fr_box_strvalue_len(fr_sbuff_current(&start_m), fr_sbuff_behind(&start_m)));
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
 * @param[in] request		currently being processed, may be NULL.
 * @param[in] args		to call as a fr_value_box_list_t.  Program will
 *      			be the first box and arguments in the subsequent boxes.
 * @param[in] env_pairs		list of pairs to be presented as environment variables
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
int fr_exec_oneshot(TALLOC_CTX *ctx, fr_exec_state_t *exec, request_t *request,
		    fr_value_box_list_t *args,
		    fr_pair_list_t *env_pairs, bool env_escape, bool env_inherit,
		    bool need_stdin,
		    bool store_stdout, TALLOC_CTX *stdout_ctx,
		    fr_time_delta_t timeout)
{
	int		*stdout_fd = (store_stdout || RDEBUG_ENABLED2) ? &exec->stdout_fd : NULL;
	fr_event_list_t	*el = unlang_interpret_event_list(request);
	char		**env = NULL;
	char		**argv;
	int		ret;

	if (unlikely(fr_exec_value_box_list_to_argv(unlang_interpret_frame_talloc_ctx(request), &argv, args) < 0)) {
		RPEDEBUG("Failed converting boxes to argument strings");
		return -1;
	}

	if (env_pairs) {
		env = fr_exec_pair_to_env(request, env_pairs, env_escape);
		if (unlikely(!env)) {
			RPEDEBUG("Failed creating environment pairs");
			return -1;
		}
	}

	if (RDEBUG_ENABLED3) exec_debug(request, argv, env, env_inherit);
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
	ret = fr_exec_fork_wait(&exec->pid,
			      exec->stdin_used ? &exec->stdin_fd : NULL,
			      stdout_fd, &exec->stderr_fd,
			      argv, env,
			      env_inherit, ROPTIONAL_ENABLED(RDEBUG_ENABLED2, DEBUG_ENABLED2));
	talloc_free(argv);
	if (ret < 0) {
	fail:
		RPEDEBUG("Failed executing program");

		/*
		 *	Not done in fr_exec_oneshot_cleanup as it's
		 *	usually the caller's responsibility.
		 */
		if (exec->stdin_fd >= 0) {
			close(exec->stdin_fd);
			exec->stdin_fd = -1;
		}
		fr_exec_oneshot_cleanup(exec, 0);
		return -1;
	}

	/*
	 *	First setup I/O events for the child process. This needs
	 *	to be done before we call fr_event_pid_wait, as it may
	 *	immediately trigger the PID callback if there's a race
	 *	between kevent and the child exiting, and that callback
	 *	will expect file descriptor events to have been created.
	 */

	/*
	 *	If we need to parse stdout, insert a special IO handler that
	 *	aggregates all stdout data into an expandable buffer.
	 */
	if (exec->stdout_used) {
		/*
		 *	Accept a maximum of 32k of data from the process.
		 */
		fr_sbuff_init_talloc(exec->stdout_ctx, &exec->stdout_buff, &exec->stdout_tctx, 128, 32 * 1024);
		if (fr_event_fd_insert(ctx, NULL, el, exec->stdout_fd, exec_stdout_read, NULL, NULL, exec) < 0) {
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

		if (fr_event_fd_insert(ctx, NULL, el, exec->stdout_fd, log_request_fd_event,
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

	if (fr_event_fd_insert(ctx, NULL, el, exec->stderr_fd, log_request_fd_event,
			       NULL, NULL, &exec->stderr_uctx) < 0) {
		RPEDEBUG("Failed adding event listening to stderr");
		close(exec->stderr_fd);
		exec->stderr_fd = -1;
		goto fail;
	}

	/*
	 *	Tell the event loop that it needs to wait for this PID
	 */
	if (fr_event_pid_wait(ctx, el, &exec->ev_pid, exec->pid, exec_reap, exec) < 0) {
		exec->pid = -1;
		RPEDEBUG("Failed adding watcher for child process");

	fail_and_close:
		/*
		 *	Avoid spurious errors in fr_exec_oneshot_cleanup
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
		(fr_timer_in(ctx, el->tl, &exec->ev, timeout, true, exec_timeout, exec) < 0)) goto fail_and_close;

	return 0;
}
