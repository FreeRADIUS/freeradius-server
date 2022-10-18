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
 * @file lib/server/exec_priv.h
 * @brief Private exec APIs
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(exec_priv_h, "$Id$")

#include <freeradius-devel/server/exec.h>

#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/atexit.h>

#include <sys/types.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <sys/file.h>

#include <fcntl.h>
#include <ctype.h>
#include <signal.h>


#ifdef __cplusplus
extern "C" {
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
extern char **environ;
#else
#  include <unistd.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#  define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#  define WIFEXITED(stat_val) (((stat_val) & 0x7f) == 0)
#endif

#if defined(OpenBSD)
/*
 *	The standard closefrom() returns void.
 *	OpenBSD's closefrom ()returns int and can be EINTR'd.
 *	So we have to keep calling it until it no longer returns EINTR
 */
#define fr_closefrom(_x) do {		\
		errno = 0;		\
		closefrom(_x);		\
	} while (errno == EINTR)	\

#else
#define fr_closefrom closefrom
#endif

#ifdef __cplusplus
}
#endif
