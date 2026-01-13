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

/*
 * $Id$
 *
 * @file protocols/radius/stats/stats.h
 * @brief Structures and prototypes for RADIUS statistics
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/stats.h>

/*
 *	The included file defines:
 *
 *	fr_stats_radius_auth_serv_t - the base statistics structure
 *
 *	fr_stats_link_radius_auth_serv - the structure linking the base stats structure to the dictionary
 *	attributes.
 *
 *	fr_stats_radius_auth_serv_instance_t - a structure holding an instance of the statistics.
 */
#include "auth_serv_stats.h"

#include "acc_serv_stats.h"
