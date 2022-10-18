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
 * @file lib/server/exec_legacy.h
 * @brief Legacy synchronous exec functions
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(exec_legacy_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

pid_t	radius_start_program_legacy(int *stdin_fd, int *stdout_fd, int *stderr_fd,
			     char const *cmd, request_t *request, bool exec_wait,
			     fr_pair_list_t *input_pairs, bool shell_escape);

int	radius_readfrom_program_legacy(int fd, pid_t pid, fr_time_delta_t timeout,
				char *answer, int left);

int	radius_exec_program_legacy(TALLOC_CTX *ctx, char *out, size_t outlen, fr_pair_list_t *output_pairs,
			    request_t *request, char const *cmd, fr_pair_list_t *input_pairs,
			    bool exec_wait, bool shell_escape, fr_time_delta_t timeout) CC_HINT(nonnull (5, 6));

#ifdef __cplusplus
}
#endif
