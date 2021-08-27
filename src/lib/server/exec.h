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
 * @file lib/server/exfile.h
 * @brief API for managing concurrent file access.
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(exec_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

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
	int				*status_p;	//!< where we write the return status of the program

	fr_pair_list_t			*vps;		//!< input VPs

	request_t			*request;	//!< request this exec is related to

} fr_exec_state_t;


pid_t	radius_start_program(int *stdin_fd, int *stdout_fd, int *stderr_fd,
			     char const *cmd, request_t *request, bool exec_wait,
			     fr_pair_list_t *input_pairs, bool shell_escape);

int	radius_readfrom_program(int fd, pid_t pid, fr_time_delta_t timeout,
				char *answer, int left);

int	radius_exec_program(TALLOC_CTX *ctx, char *out, size_t outlen, fr_pair_list_t *output_pairs,
			    request_t *request, char const *cmd, fr_pair_list_t *input_pairs,
			    bool exec_wait, bool shell_escape, fr_time_delta_t timeout) CC_HINT(nonnull (5, 6));

int	fr_exec_nowait(request_t *request, fr_value_box_list_t *vb_list, fr_pair_list_t *env_pairs);

int	fr_exec_wait_start(pid_t *pid_p, int *stdin_fd, int *stdout_fd, int *stderr_fd,
			   request_t *request, fr_value_box_list_t *vb_list, fr_pair_list_t *env_pairs);

int	fr_exec_wait_start_io(TALLOC_CTX *ctx, fr_exec_state_t *exec, request_t *request,
			      fr_value_box_list_t *vb_list, fr_pair_list_t *env_pairs,
			      bool need_stdin, bool store_stdout, TALLOC_CTX *stdout_ctx,
			      fr_time_delta_t timeout);
#ifdef __cplusplus
}
#endif
