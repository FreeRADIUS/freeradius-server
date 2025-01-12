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
 * @file lib/server/stats.h
 * @brief Structures and functions for statistics.
 *
 * @copyright 2005, 2006, 2007, 2008  The FreeRADIUS server project
 */
RCSIDH(stats_h, "$Id$")

#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t	total_requests;
	uint64_t	total_invalid_requests;
	uint64_t	total_dup_requests;
	uint64_t	total_responses;
	uint64_t	total_access_accepts;
	uint64_t	total_access_rejects;
	uint64_t	total_access_challenges;
	uint64_t	total_malformed_requests;
	uint64_t	total_bad_authenticators;
	uint64_t	total_packets_dropped;
	uint64_t	total_no_records;
	uint64_t	total_unknown_types;
	uint64_t	total_timeouts;
	time_t		last_packet;
	uint64_t	elapsed[8];
} fr_stats_t;

extern fr_stats_t	radius_auth_stats;
extern fr_stats_t	radius_acct_stats;

void request_stats_final(request_t *request);
void fr_stats_bins(fr_stats_t *stats, fr_time_t start, fr_time_t end);

#define FR_STATS_INC(_x, _y) radius_ ## _x ## _stats._y++;if (listener) listener->stats._y++;if (client) client->_x._y++;
#define FR_STATS_TYPE_INC(_x) _x++

#ifdef __cplusplus
}
#endif
