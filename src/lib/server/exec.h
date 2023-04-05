#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/exec.h
 * @brief Asynchronous exec
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(exec_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define EXEC_TIMEOUT		10	//!< Default wait time for exec calls (in seconds).

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	fr_sbuff_t			stdout_buff;	//!< Expandable buffer to store process output.
	fr_sbuff_uctx_talloc_t		stdout_tctx;	//!< sbuff talloc ctx data.

	log_fd_event_ctx_t		stdout_uctx;	//!< Config for the stdout logger.
	log_fd_event_ctx_t		stderr_uctx;	//!< Config for the stderr logger.
	char				stdout_prefix[sizeof("pid -9223372036854775808 (stdout)")];
	char				stderr_prefix[sizeof("pid -9223372036854775808 (stderr)")];

	pid_t				pid;		//!< child PID
	int				stdin_fd;	//!< for writing to the child.
	bool				stdin_used;	//!< use stdin fd?
	int				stdout_fd;	//!< for reading from the child.

	bool				stdout_used;	//!< use stdout fd?
	TALLOC_CTX			*stdout_ctx;	//!< ctx to allocate output buffers

	int				stderr_fd;	//!< for producing error messages.

	fr_event_timer_t const		*ev;		//!< for timing out the child
	fr_event_pid_t const   		*ev_pid;	//!< for cleaning up the process
	bool				failed;		//!< due to exec timeout or buffer overflow

	int				status;		//!< return code of the program

	fr_pair_list_t			*env_pairs;	//!< input VPs.  These are inserted into
							///< the environment of the child as
							///< environmental variables.

	request_t			*request;	//!< request this exec is related to

} fr_exec_state_t;

/** @name Low level interface
 *
 * These functions are used both by fr_exec_oneshot function, and any code which
 * needs a lower level interface for execing external programs.
 *
 * In the case of fr_exec_fork_wait, the caller is responsible for installing
 * I/O handlers, cleaning up file descriptors returned, and reaping the process.
 *
 * @{
 */
int	fr_exec_value_box_list_to_argv(TALLOC_CTX *ctx,
				       char ***argv_p, fr_value_box_list_t const *in);

char	**fr_exec_pair_to_env(request_t *request, fr_pair_list_t *env_pairs, bool env_escape);

int	fr_exec_fork_nowait(fr_event_list_t *el,
			    char **argv_in, char **env_in,
			    bool env_inherit, bool debug);

int 	fr_exec_fork_wait(pid_t *pid_p,
			  int *stdin_fd, int *stdout_fd, int *stderr_fd,
			  char **argv_in, char **env_usr,
			  bool env_inherit, bool debug);
/** @} */

/** @name High level interface
 *
 * These functions allow easy processing of oneshot exec calls.
 *
 * @{
 */
int	fr_exec_oneshot_nowait(request_t *request,
			       fr_value_box_list_t *args, fr_pair_list_t *env_pairs,
			       bool env_escape, bool env_inherit);

void	fr_exec_oneshot_cleanup(fr_exec_state_t *exec, int signal);

int	fr_exec_oneshot(TALLOC_CTX *ctx, fr_exec_state_t *exec, request_t *request,
		        fr_value_box_list_t *args,
		        fr_pair_list_t *env_pairs, bool env_escape, bool env_inherit,
		        bool need_stdin,
		        bool store_stdout, TALLOC_CTX *stdout_ctx,
		        fr_time_delta_t timeout);
/** @} */

#ifdef __cplusplus
}
#endif
