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

/**
 * $Id$
 *
 * @file protocols/radius/stats/stats.c
 * @brief Functions for RADIUS statistics
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict.h>
#include "stats.h"

static fr_dict_t const *dict_radius;

/*
 *	static fr_dict_attr_t const *attr_foo;
 */
#include "auth_serv_da_def.c"

#include "acc_serv_da_def.c"

extern fr_dict_autoload_t libfreeradius_radius_stats_dict[];
fr_dict_autoload_t libfreeradius_radius_stats_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },

	DICT_AUTOLOAD_TERMINATOR
};

extern fr_dict_attr_autoload_t libfreeradius_radius_stats_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_radius_stats_dict_attr[] = {

#include "auth_serv_da_autoload.c"

#include "acc_serv_da_autoload.c"

	DICT_AUTOLOAD_TERMINATOR
};

/*
 *	Clang accepts this DIAG, but complains about the code unless we have it.
 *
 *	GCC doesn't accept this DIAG, but doesn't complain about the code.
 */
#if defined(__clang__)
DIAG_OFF(gnu-flexible-array-initializer)
#endif

/*
 *	Define the fr_stats_link_t for the statistics data structures.
 */
#include "auth_serv_stats.c"

#include "acc_serv_stats.c"
