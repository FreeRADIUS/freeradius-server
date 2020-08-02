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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_STATS_64BIT
typedef uint64_t fr_uint_t;
#else
typedef uint32_t fr_uint_t;
#endif

#ifdef WITH_STATS
typedef struct {
	fr_uint_t	total_requests;
	fr_uint_t	total_invalid_requests;
	fr_uint_t	total_dup_requests;
	fr_uint_t	total_responses;
	fr_uint_t	total_access_accepts;
	fr_uint_t	total_access_rejects;
	fr_uint_t	total_access_challenges;
	fr_uint_t	total_malformed_requests;
	fr_uint_t	total_bad_authenticators;
	fr_uint_t	total_packets_dropped;
	fr_uint_t	total_no_records;
	fr_uint_t	total_unknown_types;
	fr_uint_t	total_timeouts;
	time_t		last_packet;
	fr_uint_t	elapsed[8];
} fr_stats_t;

typedef struct {
	uint32_t	window;

	uint32_t	f1, f10;
	uint32_t	ema1, ema10;
} fr_stats_ema_t;

extern fr_stats_t	radius_auth_stats;
extern fr_stats_t	radius_acct_stats;
#ifdef WITH_PROXY
extern fr_stats_t	proxy_auth_stats;
extern fr_stats_t	proxy_acct_stats;
#endif

void radius_stats_init(int flag);
void request_stats_final(REQUEST *request);
void radius_stats_ema(fr_stats_ema_t *ema,
		      fr_time_t start, fr_time_t end);
void fr_stats_bins(fr_stats_t *stats, fr_time_t start, fr_time_t end);
int fr_snmp_process(REQUEST *request);
int fr_snmp_init(void);
void fr_snmp_free(void);


#define FR_STATS_INC(_x, _y) radius_ ## _x ## _stats._y++;if (listener) listener->stats._y++;if (client) client->_x._y++;
#define FR_STATS_TYPE_INC(_x) _x++

#else  /* WITH_STATS */
#define request_stats_init(_x)
#define request_stats_final(_x)
#define fr_stats_bins(_x, _y, _z)

#define FR_STATS_INC(_x, _y)
#define FR_STATS_TYPE_INC(_x)

#endif

#ifdef __cplusplus
}
#endif
