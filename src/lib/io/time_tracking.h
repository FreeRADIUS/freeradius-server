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
 * @file lib/io/time_tracking.h
 * @brief Request time tracking
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(time_tracking_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/time.h>

/** A structure to track the time spent processing a request.
 *
 * The same structure is used by threads to track when they are
 * running / waiting.  The functions modifying fr_time_tracking_t all
 * take an explicit "when" parameter.  This parameter allows the
 * thread to update a requests tracking structure, and then use that
 * same fr_time_t to update the threads tracking structure.
 *
 * While fr_time() is fast, it is also called very often.  We should
 * therefore be careful to call it only when necessary.
 */
typedef struct {
	fr_time_t	when;			//!< last time we changed a field
	fr_time_t	start;			//!< time this request started being processed
	fr_time_t	end;			//!< when we stopped processing this request
	fr_time_t	predicted;		//!< predicted processing time for this request
	fr_time_t	yielded;		//!< time this request yielded
	fr_time_t	resumed;		//!< time this request last resumed;
	fr_time_t	running;		//!< total time spent running
	fr_time_t	waiting;		//!< total time spent waiting

	fr_dlist_head_t	list;			//!< for linking a request to various lists
} fr_time_tracking_t;

void fr_time_tracking_start(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_end(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_yield(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_resume(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_debug(fr_time_tracking_t *tt, FILE *fp) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
