#pragma once
/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Various miscellaneous functions to manipulate files and paths
 *
 * @file src/lib/util/file.h
 *
 * @copyright 2019 The FreeRADIUS project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(util_file_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <talloc.h>

/** Callback for allowing additional operations on newly created directories
 *
 * @param[in] fd	Of newly created directory.
 * @param[in] path	Either relative or full to the new directory.
 *			Should only be used for debug messages or functions
 *			that don't have an 'at' variant.
 * @param[in] uctx	User data to pass to callback.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int(*fr_mkdir_func_t)(int fd, char const *path, void *uctx);

ssize_t		fr_mkdir(int *fd_out, char const *path, ssize_t len, mode_t mode,
			 fr_mkdir_func_t func, void *uctx);

char		*fr_realpath(TALLOC_CTX *ctx, char const *path, ssize_t len);

ssize_t		fr_touch(int *fd_out, char const *filename, mode_t mode, bool mkdir, mode_t dir_mode);

int 		fr_unlink(char const *filename);

char const	*fr_cwd_strip(char const *filename);

#ifdef __cplusplus
}
#endif
