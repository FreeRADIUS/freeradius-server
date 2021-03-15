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
 * @copyright 2016-2019 Alan DeKok (aland@freeradius.org)
 * @copyright 2019-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(time_h, "$Id$")

/*
 *	For sys/time.h and time.h
 */
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/sbuff.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/** "server local" time.  This is the time in nanoseconds since the application started.
 *
 *  This time is our *private* view of time.  It should only be used
 *  for internal timers, events, etc.  It can skew randomly as NTP
 *  plays with the local clock.
 */
typedef int64_t fr_time_t;

/** "Unix" time.  This is the time in nanoseconds since midnight January 1, 1970
 *
 *  Note that it is *unsigned*, as we don't use dates before 1970.  Having it
 *  unsigned also allows the compiler to catch issues where people confuse the
 *  two types of time.
 *
 *  The unix times are *public* times.  i.e. times that we get from
 *  the network, or send to the network.  We have no idea if the other
 *  parties idea of time is correct (or if ours is wrong), so we don't
 *  mangle unix time based on clock skew.
 */
typedef uint64_t fr_unix_time_t;

/** A time delta, a difference in time measured in nanoseconds.
 *
 * This is easier to distinguish where server epoch time is being
 * used, and where relative time is being used.
 */
typedef int64_t fr_time_delta_t;

/** The base resolution for print parse operations
 */
typedef enum {
	FR_TIME_RES_SEC = 0,
	FR_TIME_RES_MSEC,
	FR_TIME_RES_USEC,
	FR_TIME_RES_NSEC
} fr_time_res_t;

typedef struct {
	uint64_t	array[8];		//!< 100ns to 100s
} fr_time_elapsed_t;

#define NSEC	(1000000000)
#define USEC	(1000000)
#define MSEC	(1000)

extern _Atomic int64_t			our_realtime;

#ifdef HAVE_CLOCK_GETTIME
extern int64_t				our_epoch;
#else  /* __MACH__ */
extern mach_timebase_info_data_t	timebase;
extern uint64_t				our_mach_epoch;
#endif

/*
 *	Need cast because of difference in sign
 */
#define fr_unix_time_from_nsec(_x)	(fr_unix_time_t)(_x)
#define fr_unix_time_from_usec(_x)	(fr_unix_time_t)fr_time_delta_from_usec((fr_time_delta_t)(_x))
#define fr_unix_time_from_msec(_x)	(fr_unix_time_t)fr_time_delta_from_msec((fr_time_delta_t)(_x))
#define fr_unix_time_from_sec(_x)	(fr_unix_time_t)fr_time_delta_from_sec((fr_time_delta_t)(_x))

#define fr_unix_time_to_nsec(_x)	(uint64_t)(_x)
#define fr_unix_time_to_usec(_x) 	(uint64_t)fr_time_delta_to_usec(_x)
#define fr_unix_time_to_msec(_x) 	(uint64_t)fr_time_delta_to_msec(_x)
#define fr_unix_time_to_sec(_x)  	(uint64_t)fr_time_delta_to_sec(_x)

static inline CC_HINT(nonnull) fr_unix_time_t fr_unix_time_from_timeval(struct timeval const *tv)
{
	return (((fr_unix_time_t) tv->tv_sec) * NSEC) + (((fr_unix_time_t) tv->tv_usec) * 1000);
}

static inline fr_time_delta_t fr_time_delta_from_nsec(int64_t nsec)
{
	return nsec;
}

static inline fr_time_delta_t fr_time_delta_from_usec(int64_t usec)
{
	return (usec * MSEC);
}

static inline fr_time_delta_t fr_time_delta_from_msec(int64_t msec)
{
	return (msec * USEC);
}

static inline fr_time_delta_t fr_time_delta_from_sec(int64_t sec)
{
	return (sec * NSEC);
}

static inline CC_HINT(nonnull) fr_time_delta_t fr_time_delta_from_timeval(struct timeval const *tv)
{
	return (((fr_time_delta_t) tv->tv_sec) * NSEC) + (((fr_time_delta_t) tv->tv_usec) * 1000);
}

static inline CC_HINT(nonnull) fr_time_delta_t fr_time_delta_from_timespec(struct timespec const *ts)
{
	return (((fr_time_delta_t) ts->tv_sec) * NSEC) + ts->tv_nsec;
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

/** Convert a delta to a timeval
 *
 * @param[in] _delta	in nanoseconds.
 */
#define fr_time_delta_to_timeval(_delta) \
	(struct timeval){ .tv_sec = (_delta) / NSEC, .tv_usec = ((_delta) % NSEC) / 1000 }

/** Convert a delta to a timespec
 *
 * @param[in] _delta	in nanoseconds.
 */
#define fr_time_delta_to_timespec(_delta) \
	(struct timespec){ .tv_sec = (_delta) / NSEC, .tv_nsec = ((_delta) % NSEC) }

/** Convert server epoch time to unix epoch time
 *
 * @param[in] _when	The server epoch time to convert.
 */
#define fr_time_to_timeval(_when) fr_time_delta_to_timeval(fr_time_wallclock_at_last_sync() + _when)

/** Convert server epoch time to unix epoch time
 *
 * @param[in] _when	The server epoch time to convert.
 */
#define fr_time_to_timespec(_when) fr_time_delta_to_timespec(fr_time_wallclock_at_last_sync() + _when)


/** Nanoseconds since the Unix Epoch the last time we synced internal time with wallclock time
 *
 */
static inline int64_t fr_time_wallclock_at_last_sync(void)
{
	return atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert an fr_time_t (internal time) to our version of unix time (wallclock time)
 *
 */
static inline fr_unix_time_t fr_time_to_unix_time(fr_time_t when)
{
	return when + atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert an fr_time_t (internal time) to number of usec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_usec(fr_time_t when)
{
	return ((when + atomic_load_explicit(&our_realtime, memory_order_consume)) / 1000);
}

/** Convert an fr_time_t (internal time) to number of msec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_msec(fr_time_t when)
{
	return ((when + atomic_load_explicit(&our_realtime, memory_order_consume)) / 1000000);
}

/** Convert an fr_time_t (internal time) to number of sec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_sec(fr_time_t when)
{
	return ((when + atomic_load_explicit(&our_realtime, memory_order_consume)) / NSEC);
}

/** Convert a timeval (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when_tv	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- <0 number of nanoseconds before the server started.
 */
static inline CC_HINT(nonnull) fr_time_t fr_time_from_timeval(struct timeval const *when_tv)
{
	return fr_time_delta_from_timeval(when_tv) - atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert a time_t (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- <0 number of nanoseconds before the server started.
 */
static inline fr_time_t fr_time_from_sec(time_t when)
{
	return (((fr_time_t) when) * NSEC) - atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert msec (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- <0 number of nanoseconds before the server started.
 */
static inline fr_time_t fr_time_from_msec(int64_t when)
{
	return (((fr_time_t) when) * MSEC) - atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert usec (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- <0 number of nanoseconds before the server started.
 */
static inline fr_time_t fr_time_from_usec(int64_t when)
{
	return (((fr_time_t) when) * USEC) - atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert a nsec (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- <0 number of nanoseconds before the server started.
 */
static inline fr_time_t fr_time_from_nsec(int64_t when)
{
	return (((fr_time_t) when) * NSEC) - atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert a timespec (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when_ts	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- 0 if when_tv occurred before the server started.
 */
static inline CC_HINT(nonnull) fr_time_t fr_time_from_timespec(struct timespec const *when_ts)
{
	return fr_time_delta_from_timespec(when_ts) - atomic_load_explicit(&our_realtime, memory_order_consume);
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
static inline int8_t fr_time_cmp(fr_time_t a, fr_time_t b)
{
	return (a > b) - (a < b);
}

/** Return a relative time since the server our_epoch
 *
 *  This time is useful for doing time comparisons, deltas, etc.
 *  Human (i.e. printable) time is something else.
 *
 * @returns fr_time_t time in nanoseconds since the server our_epoch.
 *
 * @hidecallergraph
 */
static inline fr_time_t fr_time(void)
{
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
	(void) clock_gettime(CLOCK_MONOTONIC, &ts);
	return fr_time_delta_from_timespec(&ts) - our_epoch;
#else  /* __MACH__ is defined */
	uint64_t when;

	when = mach_absolute_time();
	when -= our_mach_epoch;

	return when * (timebase.numer / timebase.denom);
#endif
}

int		fr_time_start(void);
int		fr_time_sync(void);

int		fr_time_delta_from_time_zone(char const *tz, fr_time_delta_t *delta) CC_HINT(nonnull);
int 		fr_time_delta_from_str(fr_time_delta_t *out, char const *in, fr_time_res_t hint) CC_HINT(nonnull);

size_t		fr_time_strftime_local(fr_sbuff_t *out, fr_time_t time, char const *fmt) CC_HINT(format(strftime, 3, 0));
size_t		fr_time_strftime_utc(fr_sbuff_t *out, fr_time_t time, char const *fmt)  CC_HINT(format(strftime, 3, 0));

void		fr_time_elapsed_update(fr_time_elapsed_t *elapsed, fr_time_t start, fr_time_t end) CC_HINT(nonnull);
void		fr_time_elapsed_fprint(FILE *fp, fr_time_elapsed_t const *elapsed, char const *prefix, int tabs) CC_HINT(nonnull(1,2));
time_t		fr_time_from_utc(struct tm *tm) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
