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

extern pid_t	(*rad_waitpid)(pid_t pid, int *status);

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/pair.h>

#include <sys/types.h>
#include <talloc.h>

#ifdef __cplusplus
extern "C" {
#endif
pid_t	radius_start_program(char const *cmd, REQUEST *request, bool exec_wait,
			     int *input_fd, int *output_fd,
			     VALUE_PAIR *input_pairs, bool shell_escape);

int	radius_readfrom_program(int fd, pid_t pid, fr_time_delta_t timeout,
				char *answer, int left);

int	radius_exec_program(TALLOC_CTX *ctx, char *out, size_t outlen, VALUE_PAIR **output_pairs,
			    REQUEST *request, char const *cmd, VALUE_PAIR *input_pairs,
			    bool exec_wait, bool shell_escape, fr_time_delta_t timeout) CC_HINT(nonnull (5, 6));

int	fr_exec_nowait(REQUEST *request, fr_value_box_t *vb, VALUE_PAIR *env_pairs);

int	fr_exec_wait_start(REQUEST *request, fr_value_box_t *vb, VALUE_PAIR *env_pairs, pid_t *pid_p);

void	fr_exec_waitpid(pid_t pid);

#ifdef __cplusplus
}
#endif
