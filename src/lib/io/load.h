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
 * @file io/load.h
 * @brief Load generation
 *
 * @copyright 2019 Network RADIUS SARL <legal@networkradius.com>
 */
RCSIDH(load_h, "$Id$")

#include <talloc.h>
#include <freeradius-devel/util/event.h>

/** Load generation configuration.
 *
 *  The load generator runs a callback periodically in order to
 *  generate load.  The callback MUST do all of the work, and track
 *  all necessary state itself.  The load generator simply provides a
 *  periodic signal.
 *
 *  The load begins with "start_pps", and ends after ramping up to
 *  "max_pps", no matter how long that takes.  The ramp-up is done by
 *  "step" increments.  Each step is run for "duration" seconds.
 *
 *  The callback is run "1/pps" times per second.
 *
 *  In order to send higher load, it is possible to run the callback
 *  "parallel" times per timeout.  i.e. with "start_pps = 100", and
 *  "parallel = 10", the load generator will run the callback 10
 *  times, wait 1/10s, run the callback another 10 times, and so on.
 *
 *  In order to prevent the load generator from overloading the
 *  backend, we have a configurable maximum backlog.  i.e. packets
 *  sent without reply.  This backlog is expressed in milliseconds of
 *  packets, *not* in numbers of packets.  Expressing the backlog this
 *  way allows it to automatically scale to higher loads.
 *
 *  i.e. if the generator is senting 10K packets/s, and the
 *  "milliseconds" parameter is 1000, then the generator will allow
 *  10K packets in the backlog.
 *
 *  Once the backlog limit is reached, the load generator will switch
 *  to a "gated" method of sending packets. It will only send one new
 *  packet when it has received a reply for one old packet.
 *
 *  If the generator receives many replies and the backlog is lower
 *  than the limit, the generator switches again to sending the
 *  configured "pps" packets
 *
 *  The generator will try to increase the packet rate after
 *  "duration" seconds, even if the maximum backlog is currently
 *  reached.  This increase has the effect of also increasing the
 *  maximum backlog.
 */
typedef struct {
	uint32_t       	start_pps;	//!< start PPS
	uint32_t       	max_pps;	//!< max PPS, 0 for "no limit".
	uint32_t       	duration;	//!< duration of each step
	uint32_t	step;		//!< how much to increase each load test by
	uint32_t	parallel;	//!< how many packets in parallel to send
	uint32_t	milliseconds;	//!< how many milliseconds of backlog to top out at
} fr_load_config_t;

typedef struct {
	fr_time_t	start;		//! when the test started
	fr_time_t	end;		//!< when the test ended, due to last reply received
	fr_time_t	last_send;	//!< last packet we sent
	fr_time_delta_t rtt;		//!< smoothed round trip time
	fr_time_delta_t	rttvar;		//!< RTT variation
	int		pps;		//!< current offered packets/s
	int       	pps_accepted;	//!< Accepted PPS for the last second
	int		sent;		//!< total packets sent
	int		received;      	//!< total packets received (should be == sent)
	int		skipped;	//!< we skipped sending this number of packets
	int		backlog;	//!< current backlog
	int		max_backlog;	//!< maximum backlog we saw during the test
	bool		blocked;	//!< whether or not we're blocked
	int		times[8];	//!< response time in microseconds to tens of seconds
} fr_load_stats_t;

typedef struct fr_load_s fr_load_t;

/** Whether or not the application should continue.
 *
 */
typedef enum {
	FR_LOAD_CONTINUE = 0,		//!< continue sending packets.
	FR_LOAD_DONE			//!< the load generator is done
} fr_load_reply_t;


typedef int (*fr_load_callback_t)(fr_time_t now, void *uctx);

fr_load_t *fr_load_generator_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_load_config_t *config,
				    fr_load_callback_t callback, void *uctx) CC_HINT(nonnull(2,3,4));

int fr_load_generator_start(fr_load_t *l) CC_HINT(nonnull);

int fr_load_generator_stop(fr_load_t *l) CC_HINT(nonnull);

fr_load_reply_t fr_load_generator_have_reply(fr_load_t *l, fr_time_t request_time) CC_HINT(nonnull);

size_t fr_load_generator_stats_sprint(fr_load_t *l, fr_time_t now, char *buffer, size_t buflen);

fr_load_stats_t const * fr_load_generator_stats(fr_load_t const *l) CC_HINT(nonnull);
