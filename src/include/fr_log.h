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
#ifndef _FR_LOG_H
#define _FR_LOG_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/**
 * $Id$
 *
 * @file include/fr_log.h
 * @brief libfreeradius logging functions
 *
 * @copyright 2016  The FreeRADIUS server project
 */

/*
 *	Error functions.
 */
void		fr_strerror_printf(char const *, ...) CC_HINT(format (printf, 1, 2));
void		fr_perror(char const *, ...) CC_HINT(format (printf, 1, 2));
void		fr_canonicalize_error(TALLOC_CTX *ctx, char **spaces, char **text, ssize_t slen, char const *msg);

char const	*fr_strerror(void);
char const	*fr_syserror(int num);
extern bool	fr_dns_lookups;	/* do IP -> hostname lookups? */
extern bool	fr_hostname_lookups; /* do hostname -> IP lookups? */
extern int	fr_debug_lvl;	/* 0 = no debugging information */

#endif /* _FR_LOG_H */
