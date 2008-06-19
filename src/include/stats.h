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

/*
 *  Taken from RFC 2619 and RFC 2621
 */
typedef struct fr_client_stats_t {
	/* IP address */
	/* Client ID (string ) */
	fr_uint_t       	requests;
	fr_uint_t	dup_requests;
	fr_uint_t	responses;
	fr_uint_t	accepts;
	fr_uint_t	rejects;
	fr_uint_t	challenges;
	fr_uint_t	malformed_requests;
	fr_uint_t	bad_authenticators;
	fr_uint_t	packets_dropped;
	fr_uint_t	unknown_types;
} fr_client_stats_t;


void request_stats_final(REQUEST *request);


#else
#define request_stats_final(_x)
#endif

#endif /* FR_STATS_H */
