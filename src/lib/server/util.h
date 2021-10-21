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
 * @file lib/server/util.h
 * @brief Various utility functions
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSIDH(util_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <pwd.h>
#include <grp.h>
#include <freeradius-devel/util/talloc.h>

void (*reset_signal(int signo, void (*func)(int)))(int);
size_t		rad_filename_make_safe(UNUSED request_t *request, char *out, size_t outlen,
				       char const *in, UNUSED void *arg);
size_t		rad_filename_escape(UNUSED request_t *request, char *out, size_t outlen,
				    char const *in, UNUSED void *arg);
ssize_t		rad_filename_unescape(char *out, size_t outlen, char const *in, size_t inlen);
char		*rad_ajoin(TALLOC_CTX *ctx, char const **argv, int argc, char c);

uint32_t	rad_pps(uint32_t *past, uint32_t *present, time_t *then, struct timeval *now);
int		rad_expand_xlat(request_t *request, char const *cmd,
				int max_argc, char const *argv[], bool can_fail,
				size_t argv_buflen, char *argv_buf);

int		rad_seuid(uid_t uid);
int		rad_segid(gid_t gid);

void		rad_suid_set_down_uid(uid_t uid);
void		rad_suid_up(void);
void		rad_suid_down(void);
void		rad_suid_down_permanent(void);
bool		rad_suid_is_down_permanent(void);

#ifdef __cplusplus
}
#endif
