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
 * @file lib/util/paths.h
 * @brief Default paths
 *
 * @copyright 2020 The FreeRADIUS server project
 */
RCSIDH(util_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

char const	*fr_path_default_log_dir(void);
char const	*fr_path_default_lib_dir(void);
char const	*fr_path_default_raddb_dir(void);
char const	*fr_path_default_run_dir(void);
char const	*fr_path_default_sbin_dir(void);
char const	*fr_path_default_radacct_dir(void);

#ifdef __cplusplus
}
#endif
