/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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

/**
 * $Id$
 *
 * @brief Simple ring buffers for packet contents
 * @file io/time_tracking.c
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/time_tracking.h>

fr_table_num_ordered_t fr_time_tracking_state_table[] = {
	{ L("STOPPED"),		FR_TIME_TRACKING_STOPPED	},
	{ L("RUNNING"),		FR_TIME_TRACKING_RUNNING	},
	{ L("YIELDED"),		FR_TIME_TRACKING_YIELDED	},
};
size_t fr_time_tracking_state_table_len = NUM_ELEMENTS(fr_time_tracking_state_table);
