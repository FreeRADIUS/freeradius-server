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

#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/util.h>

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/thread_local.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <sys/file.h>

#include <fcntl.h>
#include <ctype.h>

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

static pid_t waitpid_wrapper(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}

pid_t (*rad_waitpid)(pid_t pid, int *status) = waitpid_wrapper;

typedef struct {
	fr_dlist_t	entry;
	pid_t		pid;
} fr_child_t;

static _Thread_local fr_dlist_head_t *fr_children;

static void _fr_children_free(void *arg)
{
	talloc_free(arg);
}


static void fr_reap_children(void)
{
	fr_dlist_head_t *list;
	fr_child_t *child, *next;

	list = fr_children;
	if (!list) {
		MEM(list = talloc_zero(NULL, fr_dlist_head_t));

		fr_dlist_init(list, fr_child_t, entry);

		fr_thread_local_set_destructor(fr_children, _fr_children_free, list);
		return;		/* no children, so no reaping */
	}

	/*
	 *	Clean up the children.  ALL of them.  This is
	 *	slow as heck, but correct. :(
	 */
	for (child = fr_dlist_head(fr_children);
	     child != NULL;
	     child = next) {
		int status;
		pid_t pid;

		next = fr_dlist_next(fr_children, child);
		pid = waitpid(child->pid, &status, WNOHANG);
		if (pid != 0) {
			fr_dlist_remove(fr_children, child);
			talloc_free(child);
		}
	}
}

static void fr_exec_pair_to_env(REQUEST *request, VALUE_PAIR *input_pairs, char **envp, size_t envlen, bool shell_escape)
{
	char			*p;
	size_t			i;
	fr_cursor_t		cursor;
	fr_dict_attr_t const	*da;
	VALUE_PAIR		*vp;
	char			buffer[1024];

	/*
	 *	Set up the environment variables in the
	 *	parent, so we don't call libc functions that
	 *	hold mutexes.  They might be locked when we fork,
	 *	and will remain locked in the child.
	 */
	for (vp = fr_cursor_init(&cursor, &input_pairs), i = 0;
	     vp && (i < envlen - 1);
	     vp = fr_cursor_next(&cursor)) {
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
				} else if (isalpha((int) *p)) {
					*p = toupper(*p);
				}
			}
		}

		n = strlen(buffer);
		fr_pair_value_snprint(buffer + n, sizeof(buffer) - n, vp, shell_escape ? '"' : 0);

		DEBUG3("export %s", buffer);
		envp[i++] = talloc_typed_strdup(envp, buffer);
	}

	if (request) {
		da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_EXEC_EXPORT);
		if (da) {
			for (vp = fr_cursor_iter_by_da_init(&cursor, &request->control, da);
			     vp && (i < (envlen - 1));
			     vp = fr_cursor_next(&cursor)) {
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
static NEVER_RETURNS void fr_exec_child(REQUEST *request, char **argv, char **envp,
					bool exec_wait, int *input_fd, int *output_fd,
					int to_child[static 2], int from_child[static 2])
{
	int devnull;

	/*
	 *	Open STDIN to /dev/null
	 */
	devnull = open("/dev/null", O_RDWR);
	if (devnull < 0) {
		ERROR("Failed opening /dev/null: %s\n", fr_syserror(errno));

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
		if (input_fd) {
			close(to_child[1]);
			dup2(to_child[0], STDIN_FILENO);
		} else {
			dup2(devnull, STDIN_FILENO);
		}

		if (output_fd) {
			close(from_child[0]);
			dup2(from_child[1], STDOUT_FILENO);
		} else {
			dup2(devnull, STDOUT_FILENO);
		}

	} else {	/* no pipe, STDOUT should be /dev/null */
		dup2(devnull, STDIN_FILENO);
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
	if (!request || !RDEBUG_ENABLED) dup2(devnull, STDERR_FILENO);
	close(devnull);

	/*
	 *	The server may have MANY FD's open.  We don't
	 *	want to leave dangling FD's for the child process
	 *	to play funky games with, so we close them.
	 */
	closefrom(3);

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
 * @param cmd Command to execute. This is parsed into argv[] parts, then each individual argv
 *	part is xlat'ed.
 * @param request Current reuqest
 * @param exec_wait set to true to read from or write to child.
 * @param[in,out] input_fd pointer to int, receives the stdin file descriptor. Set to NULL
 *	and the child will have /dev/null on stdin.
 * @param[in,out] output_fd pinter to int, receives the stdout file descriptor. Set to NULL
 *	and child will have /dev/null on stdout.
 * @param input_pairs list of value pairs - these will be put into the environment variables
 *	of the child.
 * @param shell_escape values before passing them as arguments.
 * @return
 *	- PID of the child process.
 *	- -1 on failure.
 */
pid_t radius_start_program(char const *cmd, REQUEST *request, bool exec_wait,
			   int *input_fd, int *output_fd,
			   VALUE_PAIR *input_pairs, bool shell_escape)
{
	int		to_child[2] = {-1, -1};
	int		from_child[2] = {-1, -1};
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

	fr_reap_children();

	/*
	 *	Open a pipe for child/parent communication, if necessary.
	 */
	if (exec_wait) {
		if (input_fd) {
			if (pipe(to_child) != 0) {
				ERROR("Couldn't open pipe to child: %s", fr_syserror(errno));
				return -1;
			}
		}
		if (output_fd) {
			if (pipe(from_child) != 0) {
				ERROR("Couldn't open pipe from child: %s", fr_syserror(errno));
				/* safe because these either need closing or are == -1 */
				close(to_child[0]);
				close(to_child[1]);
				return -1;
			}
		}
	}

	MEM(envp = talloc_zero_array(request, char *, MAX_ENVP));
	envp[0] = NULL;
	if (input_pairs) fr_exec_pair_to_env(request, input_pairs, envp, MAX_ENVP, shell_escape);

	pid = fork();
	if (pid == 0) {
		fr_exec_child(request, argv, envp, exec_wait, input_fd, output_fd, to_child, from_child);
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
		if (exec_wait) {
			/* safe because these either need closing or are == -1 */
			close(to_child[0]);
			close(to_child[1]);
			close(from_child[0]);
			close(from_child[1]);
		}
		return -1;
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
		if (input_fd) {
			*input_fd = to_child[1];
			close(to_child[0]);
		}
		if (output_fd) {
			*output_fd = from_child[0];
			close(from_child[1]);
		}

	} else {
		fr_child_t *child;

		MEM(child = talloc_zero(fr_children, fr_child_t));
		fr_dlist_insert_tail(fr_children, child);
		child->pid = pid;
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
int radius_readfrom_program(int fd, pid_t pid, fr_time_delta_t timeout,
			    char *answer, int left)
{
	int done = 0;
	int status;
	fr_time_t start;

	fr_nonblock(fd);

	/*
	 *	Minimum timeout period is one section
	 */
	if (timeout < NSEC) timeout = fr_time_delta_from_sec(1);

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

		elapsed = fr_time() - start;
		if (elapsed >= timeout) goto too_long;

		rcode = select(fd + 1, &fds, NULL, NULL, &fr_time_delta_to_timeval(timeout - elapsed));
		if (rcode == 0) {
		too_long:
			DEBUG("Child PID %u is taking too much time: forcing failure and killing child.", pid);
			kill(pid, SIGTERM);
			close(fd); /* should give SIGPIPE to child, too */

			/*
			 *	Clean up the child entry.
			 */
			rad_waitpid(pid, &status);
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
 * @param[in,out] ctx to allocate new VALUE_PAIR (s) in.
 * @param[out] out buffer to append plaintext (non valuepair) output.
 * @param[in] outlen length of out buffer.
 * @param[out] output_pairs list of value pairs - Data on child's stdout will be parsed and
 *	added into this list of value pairs.
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
int radius_exec_program(TALLOC_CTX *ctx, char *out, size_t outlen, VALUE_PAIR **output_pairs,
			REQUEST *request, char const *cmd, VALUE_PAIR *input_pairs,
			bool exec_wait, bool shell_escape, fr_time_delta_t timeout)

{
	pid_t pid;
	int from_child;
	char *p;
	pid_t child_pid;
	int comma = 0;
	int status, ret = 0;
	ssize_t len;
	char answer[4096];

	RDEBUG2("Executing: %s", cmd);

	if (out) *out = '\0';

	pid = radius_start_program(cmd, request, exec_wait, NULL, &from_child, input_pairs, shell_escape);
	if (pid < 0) {
		return -1;
	}

	if (!exec_wait) {
		return 0;
	}

	len = radius_readfrom_program(from_child, pid, timeout, answer, sizeof(answer));
	if (len < 0) {
		/*
		 *	Failure - radius_readfrom_program will
		 *	have called close(from_child) for us
		 */
		RERROR("Failed to read from child output");
		return -1;

	}
	answer[len] = '\0';

	/*
	 *	Make sure that the writer can't block while writing to
	 *	a pipe that no one is reading from anymore.
	 */
	close(from_child);

	if (len == 0) {
		goto wait;
	}

	/*
	 *	Parse the output, if any.
	 */
	if (output_pairs) {
		VALUE_PAIR *vps = NULL;

		/*
		 *	HACK: Replace '\n' with ',' so that
		 *	fr_pair_list_afrom_str() can parse the buffer in
		 *	one go (the proper way would be to
		 *	fix fr_pair_list_afrom_str(), but oh well).
		 */
		for (p = answer; *p; p++) {
			if (*p == '\n') {
				*p = comma ? ' ' : ',';
				p++;
				comma = 0;
			}
			if (*p == ',') {
				comma++;
			}
		}

		/*
		 *	Replace any trailing comma by a NUL.
		 */
		if (answer[len - 1] == ',') {
			answer[--len] = '\0';
		}

		if (fr_pair_list_afrom_str(ctx, request->dict, answer, &vps) == T_INVALID) {
			RPERROR("Failed parsing output from: %s", cmd);
			if (out) strlcpy(out, answer, len);
			ret = -1;
		}

		/*
		 *	We want to mark the new attributes as tainted,
		 *	but not the existing ones.
		 */
		fr_pair_list_tainted(vps);
		fr_pair_add(output_pairs, vps);

	} else if (out) {
		/*
		 *	We've not been told to extract output pairs,
		 *	just copy the programs output to the out
		 *	buffer.
		 */
		strlcpy(out, answer, outlen);
	}

	/*
	 *	Call rad_waitpid (should map to waitpid on non-threaded
	 *	or single-server systems).
	 */
wait:
	child_pid = rad_waitpid(pid, &status);
	if (child_pid == 0) {
		RERROR("Timeout waiting for child");

		return -2;
	}

	if (child_pid == pid) {
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			if ((status != 0) || (ret < 0)) {
				RERROR("Program returned code (%d) and output \"%pV\"", status,
				       fr_box_strvalue_len(answer, len));
			} else {
				RDEBUG2("Program returned code (%d) and output \"%pV\"", status,
					fr_box_strvalue_len(answer, len));
			}

			return ret < 0 ? ret : status;
		}
	}

	RERROR("Abnormal child exit: %s", fr_syserror(errno));

	return -1;
}


/** Execute a program without waiting for the program to finish.
 *
 * @param request	the request
 * @param vb		as returned by xlat_frame_eval()
 * @param env_pairs	VPs to put into into the environment.  May be NULL.
 * @return
 *	- <0 on error
 *	- 0 on success
 *
 *  @todo - maybe take an fr_cursor_t instead of env_pairs?  That
 *  would allow finer-grained control over the attributes to put into
 *  the environment.
 *
 *  @todo - make xlat_aeval_compiled_argv() return one value_box of type
 *  FR_TYPE_GROUP instead of argv.  So that function can take synchronous
 *  xlats, too.
 */
int fr_exec_nowait(REQUEST *request, fr_value_box_t *vb, VALUE_PAIR *env_pairs)
{
	int		argc;
	char		**envp;
	char		**argv;
	pid_t		pid;
	fr_child_t	*child;
	fr_value_box_t	*first;

	/*
	 *	Clean up any previous child processes.
	 */
	fr_reap_children();

	/*
	 *	Ensure that we don't do anything stupid.
	 */
	first =  fr_value_box_list_get(vb, 0);
	if (first->type == FR_TYPE_GROUP) first = first->vb_group;
	if (first->tainted) {
		fr_strerror_printf("Program to run comes from tainted source - %pV", first);
		return -1;
	}

	/*
	 *	Get the environment variables.
	 */
	if (env_pairs) {
		MEM(envp = talloc_zero_array(request, char *, MAX_ENVP));
		fr_exec_pair_to_env(request, env_pairs, envp, MAX_ENVP, true);
	} else {
		MEM(envp = talloc_zero_array(request, char *, 1));
		envp[0] = NULL;
	}

	argc = fr_value_box_list_flatten_argv(request, &argv, vb);
	if (argc < 0) return -1;

	pid = fork();

	/*
	 *	The child never returns from calling fr_exec_child();
	 */
	if (pid == 0) {
		int unused[2];

		fr_exec_child(request, argv, envp, false, NULL, NULL, unused, unused);
	}

	/*
	 *	Parent process.  Do all necessary cleanups.
	 */
	talloc_free(envp);

	if (pid < 0) {
		ERROR("Couldn't fork %s: %s", argv[0], fr_syserror(errno));
		talloc_free(argv);
		return -1;
	}

	/*
	 *	Ensure that we can clean up any child processes.  We
	 *	don't want them left over as zombies.
	 */
	MEM(child = talloc_zero(fr_children, fr_child_t));
	fr_dlist_insert_tail(fr_children, child);
	child->pid = pid;

	return 0;
}
