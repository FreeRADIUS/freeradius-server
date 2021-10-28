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
 * @copyright 2019-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
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
typedef struct fr_time_s {
	int64_t value;		//!< Signed because we need times before the server started
				///< for things like certificate validity checks and cache
				///< entries.
} fr_time_t;

#define fr_time_max() (fr_time_t){ .value = INT64_MAX }
#define fr_time_min() (fr_time_t){ .value = INT64_MIN }
#define fr_time_wrap(_time) (fr_time_t){ .value = (_time) }
static inline int64_t fr_time_unwrap(fr_time_t time) { return time.value; }	/* func to stop mixing with fr_time_delta_t */

/** A time delta, a difference in time measured in nanoseconds.
 *
 * This is easier to distinguish where server epoch time is being
 * used, and where relative time is being used.
 */
typedef struct fr_time_delta_s {
	int64_t value;
} fr_time_delta_t;

#define fr_time_delta_max() (fr_time_delta_t){ .value = INT64_MAX }
#define fr_time_delta_min() (fr_time_delta_t){ .value = INT64_MIN }
#define fr_time_delta_wrap(_time) (fr_time_delta_t){ .value = (_time) }
static inline int64_t fr_time_delta_unwrap(fr_time_delta_t time) { return time.value; }	/* func to stop mixing with fr_time_t */

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
typedef struct fr_unix_time_s {
	uint64_t value;
} fr_unix_time_t;

extern int64_t const			fr_time_multiplier_by_res[];
extern fr_table_num_ordered_t const	fr_time_precision_table[];
extern size_t				fr_time_precision_table_len;
#define fr_unix_time_max() (fr_unix_time_t){ .value = UINT64_MAX }
#define fr_unix_time_min() (fr_unix_time_t){ .value = 0 }
#define fr_unix_time_wrap(_time) (fr_unix_time_t){ .value = (_time) }
static inline uint64_t fr_unix_time_unwrap(fr_unix_time_t time) { return time.value; }	/* func to stop mixing with fr_time_t */

/** @name fr_time_t arithmetic and comparison macros
 *
 * We wrap the 64bit signed time value in a struct to prevent misuse.
 *
 * The macros below allow basic arithmetic and comparisons to be performed.
 * @{
 */
/* Don't add fr_time_add_time_time, it's almost always a type error */
static inline fr_time_t fr_time_add_time_delta(fr_time_t a, fr_time_delta_t b) { return fr_time_wrap(fr_time_unwrap(a) + fr_time_delta_unwrap(b)); }
static inline fr_time_t fr_time_add_delta_time(fr_time_delta_t a, fr_time_t b) { return fr_time_wrap(fr_time_delta_unwrap(a) + fr_time_unwrap(b)); }

/** Add a time/time delta together
 *
 * Types may either be:
 * - fr_time_add((fr_time_t), (fr_time_delta_t))
 * - fr_time_add((fr_time_delta_t), (fr_time_delta_t))
 *
 * Adding two time values together is most likely an error.
 * Adding two time_delta values together can be done with #fr_time_delta_add.
 */
#define fr_time_add(_a, _b) \
	_Generic(_a, \
		fr_time_t	: _Generic(_b, \
					fr_time_delta_t	: fr_time_add_time_delta \
				  ), \
		fr_time_delta_t	: _Generic(_b, \
					fr_time_t	: fr_time_add_delta_time, \
					fr_time_delta_t	: fr_time_delta_add \
				  ) \
	)(_a, _b)

static inline fr_time_delta_t fr_time_sub_time_time(fr_time_t a, fr_time_t b) { return fr_time_delta_wrap(fr_time_unwrap(a) - fr_time_unwrap(b)); }
static inline fr_time_t fr_time_sub_time_delta(fr_time_t a, fr_time_delta_t b) { return fr_time_wrap(fr_time_unwrap(a) - fr_time_delta_unwrap(b)); }

/** Subtract one time from another
 *
 * Types may either be:
 * - fr_time_sub((fr_time_t), (fr_time_t)) - Produces a #fr_time_delta_t
 * - fr_time_sub((fr_time_t), (fr_time_delta_t)) - Produces a #fr_time_t
 *
 * Subtracting time from a delta is most likely an error.
 * Subtracting two time_delta values can be done with #fr_time_delta_sub
 */
#define fr_time_sub(_a, _b) \
	_Generic(_a, \
		fr_time_t	: _Generic(_b, \
					fr_time_t	: fr_time_sub_time_time, \
					fr_time_delta_t	: fr_time_sub_time_delta \
				  ) \
	)(_a, _b)

#define fr_time_gt(_a, _b) (fr_time_unwrap(_a) > fr_time_unwrap(_b))
#define fr_time_gteq(_a, _b) (fr_time_unwrap(_a) >= fr_time_unwrap(_b))
#define fr_time_lt(_a, _b) (fr_time_unwrap(_a) < fr_time_unwrap(_b))
#define fr_time_lteq(_a, _b) (fr_time_unwrap(_a) <= fr_time_unwrap(_b))
#define fr_time_eq(_a, _b) (fr_time_unwrap(_a) == fr_time_unwrap(_b))
#define fr_time_neq(_a, _b) (fr_time_unwrap(_a) != fr_time_unwrap(_b))

#define fr_time_ispos(_a) (fr_time_unwrap(_a) > 0)
#define fr_time_isneg(_a) (fr_time_unwrap(_a) < 0)
/** @} */

/** @name fr_time_delta_t arithmetic and comparison macros
 *
 * We wrap the 64bit signed time delta value in a struct to prevent misuse.
 *
 * The macros below allow basic arithmetic and comparisons to be performed.
 * @{
 */
static inline fr_time_delta_t fr_time_delta_add(fr_time_delta_t a, fr_time_delta_t b) { return fr_time_delta_wrap(fr_time_delta_unwrap(a) + fr_time_delta_unwrap(b)); }
static inline fr_time_delta_t fr_time_delta_sub(fr_time_delta_t a, fr_time_delta_t b) { return fr_time_delta_wrap(fr_time_delta_unwrap(a) - fr_time_delta_unwrap(b)); }
static inline fr_time_delta_t fr_time_delta_div(fr_time_delta_t a, fr_time_delta_t b) { return fr_time_delta_wrap(fr_time_delta_unwrap(a) / fr_time_delta_unwrap(b)); }
static inline fr_time_delta_t fr_time_delta_mul(fr_time_delta_t a, fr_time_delta_t b) { return fr_time_delta_wrap(fr_time_delta_unwrap(a) * fr_time_delta_unwrap(b)); }

#define fr_time_delta_cond(_a, _op, _b) (fr_time_delta_unwrap(_a) _op fr_time_delta_unwrap(_b))
#define fr_time_delta_gt(_a, _b) (fr_time_delta_unwrap(_a) > fr_time_delta_unwrap(_b))
#define fr_time_delta_gteq(_a, _b) (fr_time_delta_unwrap(_a) >= fr_time_delta_unwrap(_b))
#define fr_time_delta_lt(_a, _b) (fr_time_delta_unwrap(_a) < fr_time_delta_unwrap(_b))
#define fr_time_delta_lteq(_a, _b) (fr_time_delta_unwrap(_a) <= fr_time_delta_unwrap(_b))
#define fr_time_delta_eq(_a, _b) (fr_time_delta_unwrap(_a) == fr_time_delta_unwrap(_b))
#define fr_time_delta_neq(_a, _b) (fr_time_delta_unwrap(_a) != fr_time_delta_unwrap(_b))

#define fr_time_delta_ispos(_a) (fr_time_delta_unwrap(_a) > 0)
#define fr_time_delta_isneg(_a) (fr_time_delta_unwrap(_a) < 0)
/** @} */

/** @name fr_unix_time_t arithmetic and comparison macros
 *
 * We wrap the 64bit signed time value in a struct to prevent misuse.
 *
 * The macros below allow basic arithmetic and comparisons to be performed.
 * @{
 */
/* Don't add fr_unix_time_add_time_time, it's almost always a type error */
static inline fr_unix_time_t fr_unix_time_add_time_delta(fr_unix_time_t a, fr_time_delta_t b) { return fr_unix_time_wrap(fr_unix_time_unwrap(a) + fr_time_delta_unwrap(b)); }
static inline fr_unix_time_t fr_unix_time_add_delta_time(fr_time_delta_t a, fr_unix_time_t b) { return fr_unix_time_wrap(fr_time_delta_unwrap(a) + fr_unix_time_unwrap(b)); }

/** Add a time/time delta together
 *
 * Types may either be:
 * - fr_unix_time_add((fr_unix_time_t), (fr_time_delta_t))
 * - fr_unix_time_add((fr_time_delta_t), (fr_time_delta_t))
 *
 * Adding two time values together is most likely an error.
 * Adding two time_delta values together can be done with #fr_time_delta_add.
 */
#define fr_unix_time_add(_a, _b) \
	_Generic(_a, \
		fr_unix_time_t	: _Generic(_b, \
					fr_time_delta_t	: fr_unix_time_add_time_delta \
				  ), \
		fr_time_delta_t	: _Generic(_b, \
					fr_unix_time_t	: fr_unix_time_add_delta_time, \
					fr_time_delta_t	: fr_time_delta_add \
				  ) \
	)(_a, _b)

static inline fr_time_delta_t fr_unix_time_sub_time_time(fr_unix_time_t a, fr_unix_time_t b) { return fr_time_delta_wrap(fr_unix_time_unwrap(a) - fr_unix_time_unwrap(b)); }
static inline fr_unix_time_t fr_unix_time_sub_time_delta(fr_unix_time_t a, fr_time_delta_t b) { return fr_unix_time_wrap(fr_unix_time_unwrap(a) - fr_time_delta_unwrap(b)); }

/** Subtract one time from another
 *
 * Types may either be:
 * - fr_unix_time_sub((fr_unix_time_t), (fr_unix_time_t)) - Produces a #fr_time_delta_t
 * - fr_unix_time_sub((fr_unix_time_t), (fr_time_delta_t)) - Produces a #fr_unix_time_t
 *
 * Subtracting time from a delta is most likely an error.
 * Subtracting two time_delta values can be done with #fr_time_delta_sub
 */
#define fr_unix_time_sub(_a, _b) \
	_Generic(_a, \
		fr_unix_time_t	: _Generic(_b, \
					fr_unix_time_t	: fr_unix_time_sub_time_time, \
					fr_time_delta_t	: fr_unix_time_sub_time_delta \
				  ) \
	)(_a, _b)

#define fr_unix_time_gt(_a, _b) (fr_unix_time_unwrap(_a) > fr_unix_time_unwrap(_b))
#define fr_unix_time_gteq(_a, _b) (fr_unix_time_unwrap(_a) >= fr_unix_time_unwrap(_b))
#define fr_unix_time_lt(_a, _b) (fr_unix_time_unwrap(_a) < fr_unix_time_unwrap(_b))
#define fr_unix_time_lteq(_a, _b) (fr_unix_time_unwrap(_a) <= fr_unix_time_unwrap(_b))
#define fr_unix_time_eq(_a, _b) (fr_unix_time_unwrap(_a) == fr_unix_time_unwrap(_b))
#define fr_unix_time_neq(_a, _b) (fr_unix_time_unwrap(_a) != fr_unix_time_unwrap(_b))

#define fr_unix_time_ispos(_a) (fr_unix_time_unwrap(_a) > 0)
/** @} */

/** The base resolution for print parse operations
 */
typedef enum {
	FR_TIME_RES_SEC = 0,
	FR_TIME_RES_CSEC,
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
#define CSEC	(100)

extern _Atomic int64_t			our_realtime;

#ifdef HAVE_CLOCK_GETTIME
extern int64_t				our_epoch;
#else  /* __MACH__ */
extern mach_timebase_info_data_t	timebase;
extern uint64_t				our_mach_epoch;
#endif

/** @name fr_unix_time_t scale conversion macros/functions
 *
 * @{
 */
static inline fr_unix_time_t fr_unix_time_from_nsec(int64_t nsec)
{
	return fr_unix_time_wrap(nsec);
}

static inline fr_unix_time_t fr_unix_time_from_usec(int64_t usec)
{
	return fr_unix_time_wrap(usec * (NSEC / USEC));
}

static inline fr_unix_time_t fr_unix_time_from_msec(int64_t msec)
{
	return fr_unix_time_wrap(msec * (NSEC / MSEC));
}

static inline fr_unix_time_t fr_unix_time_from_csec(int64_t csec)
{
	return fr_unix_time_wrap(csec * (NSEC / CSEC));
}

static inline fr_unix_time_t fr_unix_time_from_sec(int64_t sec)
{
	return fr_unix_time_wrap(sec * NSEC);
}

static inline CC_HINT(nonnull) fr_unix_time_t fr_unix_time_from_timeval(struct timeval const *tv)
{
	return fr_unix_time_wrap((((typeof_field(fr_unix_time_t, value)) tv->tv_sec) * NSEC) + (((typeof_field(fr_unix_time_t, value)) tv->tv_usec) * (NSEC / USEC)));
}

static inline CC_HINT(nonnull) fr_unix_time_t fr_unix_time_from_timespec(struct timespec const *ts)
{
	return fr_unix_time_wrap((((typeof_field(fr_unix_time_t, value))ts->tv_sec) * NSEC) + ts->tv_nsec);
}

static inline int64_t fr_unix_time_to_usec(fr_unix_time_t delta)
{
	return fr_unix_time_unwrap(delta) / (NSEC / USEC);
}

static inline int64_t fr_unix_time_to_msec(fr_unix_time_t delta)
{
	return fr_unix_time_unwrap(delta) / (NSEC / MSEC);
}

static inline int64_t fr_unix_time_to_csec(fr_unix_time_t delta)
{
	return fr_unix_time_unwrap(delta) / (NSEC / CSEC);
}

static inline int64_t fr_unix_time_to_sec(fr_unix_time_t delta)
{
	return (fr_unix_time_unwrap(delta) / NSEC);
}

/** Covert a time_t into out internal fr_unix_time_t
 *
 * Our internal unix time representation is unsigned and in nanoseconds which
 * is different from time_t which is signed and has seconds resolution.
 *
 * If time is negative we return 0.
 *
 * @param[in] time to convert.
 * @return Unix time in seconds.
 */
static inline CC_HINT(nonnull) fr_unix_time_t fr_unix_time_from_time(time_t time)
{
	if (time < 0) return fr_unix_time_wrap(0);

	return fr_unix_time_wrap(time * NSEC);
}
/** @} */

/** @name fr_time_delta_t scale conversion macros/functions
 *
 * @{
 */
static inline fr_time_delta_t fr_time_delta_from_nsec(int64_t nsec)
{
	return fr_time_delta_wrap(nsec);
}

static inline fr_time_delta_t fr_time_delta_from_usec(int64_t usec)
{
	return fr_time_delta_wrap(usec * (NSEC / USEC));
}

static inline fr_time_delta_t fr_time_delta_from_msec(int64_t msec)
{
	return fr_time_delta_wrap(msec * (NSEC / MSEC));
}

static inline fr_time_delta_t fr_time_delta_from_csec(int64_t csec)
{
	return fr_time_delta_wrap(csec * (NSEC / CSEC));
}

static inline fr_time_delta_t fr_time_delta_from_sec(int64_t sec)
{
	return fr_time_delta_wrap(sec * NSEC);
}

static inline CC_HINT(nonnull) fr_time_delta_t fr_time_delta_from_timeval(struct timeval const *tv)
{
	return fr_time_delta_wrap((((typeof_field(fr_time_delta_t, value))tv->tv_sec) * NSEC) + (((typeof_field(fr_time_delta_t, value)) tv->tv_usec) * (NSEC / USEC)));
}

static inline CC_HINT(nonnull) fr_time_delta_t fr_time_delta_from_timespec(struct timespec const *ts)
{
	return fr_time_delta_wrap((((typeof_field(fr_time_delta_t, value))ts->tv_sec) * NSEC) + ts->tv_nsec);
}

static inline int64_t fr_time_delta_to_usec(fr_time_delta_t delta)
{
	return fr_time_delta_unwrap(delta) / (NSEC / USEC);
}

static inline int64_t fr_time_delta_to_msec(fr_time_delta_t delta)
{
	return fr_time_delta_unwrap(delta) / (NSEC / MSEC);
}

static inline int64_t fr_time_delta_to_csec(fr_time_delta_t delta)
{
	return fr_time_delta_unwrap(delta) / (NSEC / CSEC);
}

static inline int64_t fr_time_delta_to_sec(fr_time_delta_t delta)
{
	return (fr_time_delta_unwrap(delta) / NSEC);
}

/** Convert a delta to a timeval
 *
 * @param[in] delta	in nanoseconds.
 */
#define fr_time_delta_to_timeval(_delta) \
(struct timeval){ \
	.tv_sec = fr_time_delta_unwrap(_delta) / NSEC, \
	.tv_usec = (fr_time_delta_unwrap(_delta) % NSEC) / (NSEC / USEC) \
}

/** Convert a delta to a timespec
 *
 * @param[in] delta	in nanoseconds.
 */
#define fr_time_delta_to_timespec(_delta)\
(struct timespec){ \
	.tv_sec = fr_time_delta_unwrap(_delta) / NSEC, \
	.tv_nsec = (fr_time_delta_unwrap(_delta) % NSEC) \
}
/** @} */

/** @name fr_time_delta_t scale conversion macros/functions
 *
 * @{
 */
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
	return fr_unix_time_wrap(fr_time_unwrap(when) + atomic_load_explicit(&our_realtime, memory_order_consume));
}

/** Convert an fr_time_t (internal time) to number of usec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_usec(fr_time_t when)
{
	return ((fr_time_unwrap(when) + atomic_load_explicit(&our_realtime, memory_order_consume)) / (NSEC / USEC));
}

/** Convert an fr_time_t (internal time) to number of msec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_msec(fr_time_t when)
{
	return ((fr_time_unwrap(when) + atomic_load_explicit(&our_realtime, memory_order_consume)) / (NSEC / MSEC));
}

/** Convert an fr_time_t (internal time) to number of csec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_csec(fr_time_t when)
{
	return ((fr_time_unwrap(when) + atomic_load_explicit(&our_realtime, memory_order_consume)) / (NSEC / CSEC));
}

/** Convert an fr_time_t (internal time) to number of sec since the unix epoch (wallclock time)
 *
 */
static inline int64_t fr_time_to_sec(fr_time_t when)
{
	return ((fr_time_unwrap(when) + atomic_load_explicit(&our_realtime, memory_order_consume)) / NSEC);
}

/** Convert server epoch time to unix epoch time
 *
 * @param[in] _when	The server epoch time to convert.
 */
#define fr_time_to_timeval(_when) fr_time_delta_to_timeval(fr_time_delta_wrap(fr_time_wallclock_at_last_sync() + fr_time_unwrap(_when)))

/** Convert server epoch time to unix epoch time
 *
 * @param[in] _when	The server epoch time to convert.
 */
#define fr_time_to_timespec(_when) fr_time_delta_to_timespec(fr_time_delta_wrap(fr_time_wallclock_at_last_sync() + fr_time_unwrap(_when)))

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
	return fr_time_wrap((when * NSEC) - atomic_load_explicit(&our_realtime, memory_order_consume));
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
	return fr_time_wrap((when * USEC) - atomic_load_explicit(&our_realtime, memory_order_consume));
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
	return fr_time_wrap((when * MSEC) - atomic_load_explicit(&our_realtime, memory_order_consume));
}

/** Convert csec (wallclock time) to a fr_time_t (internal time)
 *
 * @param[in] when	The timestamp to convert.
 * @return
 *	- >0 number of nanoseconds since the server started.
 *	- 0 when the server started.
 *	- <0 number of nanoseconds before the server started.
 */
static inline fr_time_t fr_time_from_csec(int64_t when)
{
	return fr_time_wrap((when * CSEC) - atomic_load_explicit(&our_realtime, memory_order_consume));
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
	return fr_time_wrap((when * NSEC) - atomic_load_explicit(&our_realtime, memory_order_consume));
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
	return fr_time_wrap(fr_time_delta_unwrap(fr_time_delta_from_timespec(when_ts)) - atomic_load_explicit(&our_realtime, memory_order_consume));
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
	return fr_time_wrap(fr_time_delta_unwrap(fr_time_delta_from_timeval(when_tv)) - atomic_load_explicit(&our_realtime, memory_order_consume));
}
/** @} */

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
	return CMP(fr_time_unwrap(a), fr_time_unwrap(b));
}

/** Compare two fr_time_delta_t values
 *
 * @param[in] a	The first value to compare.
 * @param[in] b The second value to compare.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *      - -1 if a < b
 */
static inline int8_t fr_time_delta_cmp(fr_time_delta_t a, fr_time_delta_t b)
{
	return CMP(fr_time_delta_unwrap(a), fr_time_delta_unwrap(b));
}

/** Compare two fr_unix_time_t values
 *
 * @param[in] a	The first value to compare.
 * @param[in] b The second value to compare.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *      - -1 if a < b
 */
static inline int8_t fr_unix_time_cmp(fr_unix_time_t a, fr_unix_time_t b)
{
	return CMP(fr_unix_time_unwrap(a), fr_unix_time_unwrap(b));
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
	return fr_time_wrap(fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts)) - our_epoch);
#else  /* __MACH__ is defined */
	uint64_t when;

	when = mach_absolute_time();
	when -= our_mach_epoch;

	return when * (timebase.numer / timebase.denom);
#endif
}

int		fr_time_start(void);
int		fr_time_sync(void);

int64_t		fr_time_scale(int64_t t, fr_time_res_t hint);

int		fr_time_delta_from_time_zone(char const *tz, fr_time_delta_t *delta) CC_HINT(nonnull);
int 		fr_time_delta_from_str(fr_time_delta_t *out, char const *in, fr_time_res_t hint) CC_HINT(nonnull);

size_t		fr_time_strftime_local(fr_sbuff_t *out, fr_time_t time, char const *fmt) CC_HINT(format(strftime, 3, 0));
size_t		fr_time_strftime_utc(fr_sbuff_t *out, fr_time_t time, char const *fmt)  CC_HINT(format(strftime, 3, 0));

int64_t		fr_time_delta_scale(fr_time_delta_t delta, fr_time_res_t hint);

void		fr_time_elapsed_update(fr_time_elapsed_t *elapsed, fr_time_t start, fr_time_t end) CC_HINT(nonnull);
void		fr_time_elapsed_fprint(FILE *fp, fr_time_elapsed_t const *elapsed, char const *prefix, int tabs) CC_HINT(nonnull(1,2));

fr_unix_time_t	fr_unix_time_from_tm(struct tm *tm) CC_HINT(nonnull);
int		fr_unix_time_from_str(fr_unix_time_t *date, char const *date_str, fr_time_res_t hint);

#ifdef __cplusplus
}
#endif
