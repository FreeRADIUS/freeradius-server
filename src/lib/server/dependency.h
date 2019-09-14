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
 * @file lib/server/dependency.h
 * @brief Version checking functions
 *
 * @copyright 2017 The FreeRADIUS server project
 */
RCSIDH(dependency_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

extern char const	*radiusd_version;
extern char const	*radiusd_version_short;

#include <freeradius-devel/server/cf_util.h>

#include <stddef.h>

int		rad_check_lib_magic(uint64_t magic);
int 		ssl_check_consistency(void);
char const	*ssl_version_by_num(uint32_t version);
char const	*ssl_version_num(void);
char const	*ssl_version_range(uint32_t low, uint32_t high);
char const	*ssl_version(void);
int		dependency_feature_add(CONF_SECTION *cs, char const *name, bool enabled);
int		dependency_version_number_add(CONF_SECTION *cs, char const *name, char const *version);
void		dependency_features_init(CONF_SECTION *cs) CC_HINT(nonnull);
void		dependency_version_numbers_init(CONF_SECTION *cs);
void		dependency_version_print(void);

#ifdef __cplusplus
}
#endif
