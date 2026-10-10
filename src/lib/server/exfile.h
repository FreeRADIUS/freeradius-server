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
RCSIDH(exfile_h, "$Id$")

#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 *	Multiple threads logging to one or more files.
 */
typedef struct exfile_s exfile_t;

exfile_t	*exfile_init(TALLOC_CTX *ctx, uint32_t entries, fr_time_delta_t idle, bool locking);

void		exfile_enable_triggers(exfile_t *ef, CONF_SECTION *cs, char const *trigger_prefix,
				       fr_pair_list_t *trigger_args);

CC_ACQUIRE_HANDLE("exfile_fd")
int		exfile_open(exfile_t *lf, char const *filename, mode_t permissions, int flags, off_t *offset);

int		exfile_close(exfile_t *lf, CC_RELEASE_HANDLE("exfile_fd") int fd);

#ifdef __COVERITY__
void		__coverity_exclusive_lock_acquire__(void *);
void		__coverity_exclusive_lock_release__(void *);

#  ifndef _EXFILE_PRIVATE
/*
 *	A successful exfile_open() returns holding a lock, which the
 *	caller releases with exfile_close().  Coverity's summary of
 *	exfile_open() loses the link between the lock and the return
 *	value, and reports the error path of every caller as a missing
 *	unlock.
 *
 *	These macros make the contract visible at the call site, where
 *	Coverity can match the lock to the check of the return value.
 *	The lock is identified by ef, because exfile_t is opaque here.
 *	exfile.c tells Coverity that exfile_open() and exfile_close()
 *	leave ef->mutex unchanged.
 */
#  define exfile_open(_ef, ...) ({ \
	int _fd = (exfile_open)(_ef, __VA_ARGS__); \
	if (_fd >= 0) __coverity_exclusive_lock_acquire__(_ef); \
	_fd; \
})

#  define exfile_close(_ef, _fd) ({ \
	__coverity_exclusive_lock_release__(_ef); \
	(exfile_close)(_ef, _fd); \
})
#  endif
#endif

#ifdef __cplusplus
}
#endif
