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

/** Functions to produce and parse the FreeRADIUS presentation format
 *
 * @file src/lib/util/perm.h
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(perm_h, "$Id$")

#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>

#include <freeradius-devel/util/talloc.h>

#ifdef __cplusplus
extern "C" {
#endif

void		fr_perm_mode_to_str(char out[static 10], mode_t mode);
void		fr_perm_mode_to_oct(char out[static 5], mode_t mode);
int		fr_perm_getpwuid(TALLOC_CTX *ctx, struct passwd **out, uid_t uid);
int		fr_perm_getpwnam(TALLOC_CTX *ctx, struct passwd **out, char const *name);
int		fr_perm_getgrgid(TALLOC_CTX *ctx, struct group **out, gid_t gid);
int		fr_perm_getgrnam(TALLOC_CTX *ctx, struct group **out, char const *name);
int		fr_perm_gid_from_str(TALLOC_CTX *ctx, gid_t *out, char const *name);
char		*fr_perm_uid_to_str(TALLOC_CTX *ctx, uid_t uid);
char		*fr_perm_gid_to_str(TALLOC_CTX *ctx, gid_t gid);
void		fr_perm_file_error(int num);

#ifdef __cplusplus
}
#endif
