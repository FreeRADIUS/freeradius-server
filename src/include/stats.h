#ifndef FR_STATS_H
#define FR_STATS_H

/*
 * stats.h	Structures and functions for statistics.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2005,2006,2007,2008  The FreeRADIUS server project
 */

RCSIDH(stats_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_STATS
typedef struct fr_stats_t {
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

typedef struct fr_stats_ema_t {
	uint32_t	window;

	uint32_t	f1, f10;
	uint32_t	ema1, ema10;
} fr_stats_ema_t;

extern fr_stats_t	radius_auth_stats;
#ifdef WITH_ACCOUNTING
extern fr_stats_t	radius_acct_stats;
#endif
#ifdef WITH_COA
extern fr_stats_t	radius_coa_stats;
extern fr_stats_t	radius_dsc_stats;
#endif
#ifdef WITH_PROXY
extern fr_stats_t	proxy_auth_stats;
#ifdef WITH_ACCOUNTING
extern fr_stats_t	proxy_acct_stats;
#endif
#ifdef WITH_COA
extern fr_stats_t	proxy_coa_stats;
extern fr_stats_t	proxy_dsc_stats;
#endif
#endif

void radius_stats_init(int flag);
void request_stats_final(REQUEST *request);
void request_stats_reply(REQUEST *request);
void radius_stats_ema(fr_stats_ema_t *ema,
		      struct timeval *start, struct timeval *end);

#define FR_STATS_INC(_x, _y) radius_ ## _x ## _stats._y++;if (listener) listener->stats._y++;if (client) client->_x._y++;
#define FR_STATS_TYPE_INC(_x) _x++

#else  /* WITH_STATS */
#define request_stats_init(_x)
#define request_stats_final(_x)

#define FR_STATS_INC(_x, _y)
#define FR_STATS_TYPE_INC(_x)

#endif

#ifdef __cplusplus
}
#endif

#endif /* FR_STATS_H */
