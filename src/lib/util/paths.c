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

/** Default paths
 *
 * @file src/lib/util/paths.c
 *
 * @copyright 2020 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/paths.h>

/** Return the default log dir
 *
 * This is set at build time from --prefix
 * @return the value of LOGDIR
 */
char const *fr_path_default_log_dir(void)
{
	return LOGDIR;
}

/** Return the default lib dir
 *
 * This is set at build time from --prefix
 * @return the value of LIBDIR
 */
char const *fr_path_default_lib_dir(void)
{
	return LIBDIR;
}

/** Return the default raddb dir
 *
 * This is set at build time from --prefix
 * @return the value of RADDBDIR
 */
char const *fr_path_default_raddb_dir(void)
{
	return RADDBDIR;
}

/** Return the default run dir
 *
 * This is set at build time from --prefix
 * @return the value of RUNDIR
 */
char const *fr_path_default_run_dir(void)
{
	return RUNDIR;
}

/** Return the default sbin dir
 *
 * This is set at build time from --prefix
 * @return the value of SBINDIR
 */
char const *fr_path_default_sbin_dir(void)
{
	return SBINDIR;
}

/** Return the default radacct dir
 *
 * This is set at build time from --prefix
 * @return the value of RADIR
 */
char const *fr_path_default_radacct_dir(void)
{
	return RADIR;
}
