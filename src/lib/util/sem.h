#pragma once

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/** Functions for establishing and managing low level sockets
 *
 * @file src/lib/util/sem.h
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(sem_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

int	fr_sem_pid(pid_t *pid, int sem_id);

int	fr_sem_uid(uid_t *uid, int sem_id);

int	fr_sem_gid(uid_t *gid, int sem_id);

int	fr_sem_cuid(uid_t *uid, int sem_id);

int	fr_sem_cgid(gid_t *gid, int sem_id);

int	fr_sem_wait(int sem_id, char const *file, bool undo_on_exit, bool nonblock);

int	fr_sem_close(int sem_id, char const *file);

int	fr_sem_get(char const *file, int proj_id, bool check_perm);

#ifdef __cplusplus
}
#endif
