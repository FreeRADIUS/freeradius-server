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

#include <freeradius-devel/ident.h>
RCSIDH(stats_h, "$Id$")

#ifdef WITH_STATS_64BIT
typedef uint64_t fr_uint_t;
#else
typedef uint32_t fr_uint_t;
#endif

#ifdef WITH_STATS
typedef struct fr_stats_t {
	fr_uint_t		total_requests;
	fr_uint_t		total_invalid_requests;
	fr_uint_t		total_dup_requests;
	fr_uint_t		total_responses;
	fr_uint_t		total_access_accepts;
	fr_uint_t		total_access_rejects;
	fr_uint_t		total_access_challenges;
	fr_uint_t		total_malformed_requests;
	fr_uint_t		total_bad_authenticators;
	fr_uint_t		total_packets_dropped;
	fr_uint_t		total_no_records;
	fr_uint_t		total_unknown_types;
} fr_stats_t;

typedef struct fr_stats_ema_t {
	int		window;

	int		f1, f10;
	int		ema1, ema10;

} fr_stats_ema_t;

extern fr_stats_t	radius_auth_stats;
extern fr_stats_t	radius_acct_stats;
#ifdef WITH_PROXY
extern fr_stats_t	proxy_auth_stats;
extern fr_stats_t	proxy_acct_stats;
#endif

void radius_stats_init(int flag);
void request_stats_final(REQUEST *request);
void request_stats_reply(REQUEST *request);
void radius_stats_ema(fr_stats_ema_t *ema,
		      struct timeval *start, struct timeval *end);

#define RAD_STATS_INC(_x) _x++
#ifdef WITH_ACCOUNTING
#define RAD_STATS_TYPE_INC(_listener, _x) if (_listener->type == RAD_LISTEN_AUTH) { \
                                       radius_auth_stats._x++; \
				     } else if (_listener->type == RAD_LISTEN_ACCT) { \
                                       radius_acct_stats._x++; } \
				       _listener->stats._x++

#define RAD_STATS_CLIENT_INC(_listener, _client, _x) if (_listener->type == RAD_LISTEN_AUTH) \
                                       _client->auth->_x++; \
				     else if (_listener->type == RAD_LISTEN_ACCT) \
                                       _client->acct->_x++

#else  /* WITH_ACCOUNTING */

#define RAD_STATS_TYPE_INC(_listener, _x) { radius_auth_stats._x++; _listener->stats._x++; }

#define RAD_STATS_CLIENT_INC(_listener, _client, _x) _client->auth->_x++

#endif /* WITH_ACCOUNTING */


#else  /* WITH_STATS */
#define request_stats_init(_x)
#define request_stats_final(_x)

#define  RAD_STATS_INC(_x)
#define RAD_STATS_TYPE_INC(_listener, _x)
#define RAD_STATS_CLIENT_INC(_listener, _client, _x)

#endif

#endif /* FR_STATS_H */
