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
 * @file lib/util/time.h
 * @brief Simple time functions
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(time_h, "$Id$")

/*
 *	For sys/time.h and time.h
 */
#include <freeradius-devel/missing.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/** "server local" time.  This is the time in nanoseconds since the application started.
 *
 */
typedef int64_t fr_time_t;

/** A time delta, a difference in time measured in nanoseconds.
 *
 * This is easier to distinguish where server epoch time is being
 * used, and where relative time is being used.
 */
typedef int64_t fr_time_delta_t;

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

typedef struct {
	uint64_t	array[8];		//!< 100ns to 100s
} fr_time_elapsed_t;

#define NSEC	(1000000000)
#define USEC	(1000000)

int fr_time_start(void);
fr_time_t fr_time(void);

static inline fr_time_delta_t fr_time_delta_from_usec(uint64_t usec)
{
	return (usec * 1000);
}

static inline fr_time_delta_t fr_time_delta_from_msec(uint64_t msec)
{
	return (msec * 1000000);
}

static inline fr_time_delta_t fr_time_delta_from_sec(uint64_t sec)
{
	return (sec * NSEC);
}

static inline fr_time_delta_t fr_time_delta_from_timeval(struct timeval const *tv)
{
	return (tv->tv_sec * NSEC) + (tv->tv_usec * 1000);
}

static inline fr_time_delta_t fr_time_delta_from_timespec(struct timespec const *ts)
{
	return (ts->tv_sec * NSEC) + ts->tv_nsec;
}

static inline int64_t fr_time_delta_to_usec(fr_time_delta_t delta)
{
	return (delta / 1000);
}

static inline int64_t fr_time_delta_to_msec(fr_time_delta_t delta)
{
	return (delta / 1000000);
}

static inline int64_t fr_time_delta_to_sec(fr_time_delta_t delta)
{
	return (delta / NSEC);
}

static inline void fr_time_delta_to_timeval(struct timeval *tv, fr_time_delta_t delta)
{
	tv->tv_sec = delta / NSEC;
	tv->tv_usec = (delta % NSEC) / 1000;
}

static inline void fr_time_delta_to_timespec(struct timespec *ts, fr_time_delta_t delta)
{
	ts->tv_sec = delta / NSEC;
	ts->tv_nsec = delta % NSEC;
}

/** Compare two fr_time_t values
 *
 * @param[in] a	The first value to compare.
 * @param[in] b The second value to compare.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *      - -1 if a < b
 */
static inline int fr_time_cmp(fr_time_t a, fr_time_t b)
{
	return (a > b) - (a < b);
}

void		fr_time_to_timeval(struct timeval *tv, fr_time_t when) CC_HINT(nonnull);
void		fr_time_to_timespec(struct timespec *ts, fr_time_t when) CC_HINT(nonnull);
int64_t		fr_time_to_usec(fr_time_t when);
int64_t		fr_time_to_msec(fr_time_t when);
int64_t		fr_time_to_sec(fr_time_t when);

fr_time_t	fr_time_from_timeval(struct timeval const *when_tv) CC_HINT(nonnull);
fr_time_t	fr_time_from_timespec(struct timespec const *when_tv) CC_HINT(nonnull);

void fr_time_tracking_start(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_end(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_yield(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_resume(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker) CC_HINT(nonnull);
void fr_time_tracking_debug(fr_time_tracking_t *tt, FILE *fp) CC_HINT(nonnull);
void fr_time_elapsed_update(fr_time_elapsed_t *elapsed, fr_time_t start, fr_time_t end);
void fr_time_elapsed_fprint(FILE *fp, fr_time_elapsed_t const *elapsed, char const *prefix, int tabs);

int fr_time_delta_from_str(fr_time_delta_t *out, char const *in);

#ifdef __cplusplus
}
#endif
