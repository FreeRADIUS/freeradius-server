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

exfile_t	*exfile_init(TALLOC_CTX *ctx, uint32_t entries, uint32_t idle, bool locking);

void		exfile_enable_triggers(exfile_t *ef, CONF_SECTION *cs, char const *trigger_prefix,
				       VALUE_PAIR *trigger_args);

int		exfile_open(exfile_t *lf, REQUEST *request, char const *filename,
			    mode_t permissions);

int		exfile_close(exfile_t *lf, REQUEST *request, int fd);

#ifdef __cplusplus
}
#endif
