/*
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
 */

/**
 * $Id$
 *
 * @brief Platform independent time functions
 * @file util/time.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/util/time.h>

/*
 *	Avoid too many ifdef's later in the code.
 */
#if !defined(HAVE_CLOCK_GETTIME) && !defined(__MACH__)
#error clock_gettime is required
#endif


#if !defined(HAVE_CLOCK_GETTIME) && defined(__MACH__)
/*
 *	AbsoluteToNanoseconds() has been deprecated,
 *	but absolutetime_to_nanoseconds() doesn't
 *	seem to be available, either.
 */
USES_APPLE_DEPRECATED_API
#  include <CoreServices/CoreServices.h>
#  include <mach/mach.h>
#  include <mach/mach_time.h>
#endif

static struct timeval tm_started = { 0, 0};

#ifdef HAVE_CLOCK_GETTIME
static struct timespec ts_started = { 0, 0};

#else  /* __MACH__ */
static mach_timebase_info_data_t timebase;
static uint64_t abs_started;
#endif

/**  Initialize the local time.
 *
 *  MUST be called when the program starts.  MUST NOT be called after
 *  that.
 *
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_time_start(void)
{
	(void) gettimeofday(&tm_started, NULL);

#ifdef HAVE_CLOCK_GETTIME
	return clock_gettime(CLOCK_MONOTONIC, &ts_started);

#else  /* __MACH__ is defined */
	mach_timebase_info(&timebase);
	abs_started = mach_absolute_time();

	return 0;
#endif
}


/** Return a relative time since the server ts_started.
 *
 *  This time is useful for doing time comparisons, deltas, etc.
 *  Human (i.e. printable) time is something else.
 *
 * @returns fr_time_t time in nanoseconds since the server ts_started.
 */
fr_time_t fr_time(void)
{
#ifdef HAVE_CLOCK_GETTIME
	fr_time_t now;
	struct timespec ts;

	(void) clock_gettime(CLOCK_MONOTONIC, &ts);


	ts.tv_sec -= ts_started.tv_sec;
	if (ts.tv_sec > 0) {
		ts.tv_nsec += NANOSEC;
		ts.tv_sec--;

		ts.tv_nsec -= ts_started.tv_nsec;
		if ((fr_time_t)ts.tv_nsec > NANOSEC) {
			ts.tv_nsec -= NANOSEC;
			ts.tv_sec++;
		}
	} else {
		ts.tv_nsec -= ts_started.tv_nsec;
	}

	now = ts.tv_sec * NANOSEC;
	now += ts.tv_nsec;

	return now;

#else  /* __MACH__ is defined */

	uint64_t when;
	Nanoseconds elapsedNano;

	when = mach_absolute_time();
	when -= abs_started;

	elapsedNano = AbsoluteToNanoseconds( *(AbsoluteTime *) &when );
	return *(uint64_t *) &elapsedNano;
#endif
}

/** Convert a fr_time_t to a struct timeval.
 *
 * @param[out] tv the timeval to update
 * @param[in] when the fr_time_t
 */
void fr_time_to_timeval(struct timeval *tv, fr_time_t when)
{
	*tv = tm_started;

	when /= 1000;

	tv->tv_sec += (when / USEC);
	tv->tv_usec += (when % USEC);

	tv->tv_sec += tv->tv_usec / USEC;
	tv->tv_usec = tv->tv_usec % USEC;
}


/** Start time tracking for a request.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 */
void fr_time_tracking_start(fr_time_tracking_t *tt, fr_time_t when)
{
	memset(tt, 0, sizeof(*tt));

	tt->when = when;
	tt->start = when;
	tt->resumed = when;

	FR_DLIST_INIT(tt->list);
}


#define IALPHA (8)
#define RTT(_old, _new) ((_old + ((IALPHA - 1) * _new)) / IALPHA)

/** End time tracking for this request.
 *
 * After this call, all request processing should be finished.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 * @param[out] worker time tracking for the worker thread
 */
void fr_time_tracking_end(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker)
{
	tt->when = when;
	tt->end = when;
	tt->running += (tt->end - tt->resumed);

	/*
	 *	This request cannot be in any list.
	 */
	rad_assert(tt->list.prev = &tt->list);
	rad_assert(tt->list.next = &tt->list);

	/*
	 *	Update the time that the worker spent processing the request.
	 */
	worker->running += tt->running;
	worker->waiting += tt->waiting;
	worker->predicted = RTT(worker->predicted, tt->running);
}


/** Track that a request yielded.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 * @param[out] worker time tracking for the worker thread
 */
void fr_time_tracking_yield(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker)
{
	tt->when = when;
	tt->yielded = when;

	rad_assert(tt->resumed <= tt->yielded);
	tt->running += (tt->yielded - tt->resumed);

	/*
	 *	Insert this request into the TAIL of the worker's list
	 *	of waiting requests.
	 */
	FR_DLIST_INSERT_TAIL(worker->list, tt->list);
}


/** Track that a request resumed.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 */
void fr_time_tracking_resume(fr_time_tracking_t *tt, fr_time_t when)
{
	tt->when = when;
	tt->resumed = when;

	rad_assert(tt->resumed <= tt->yielded);

	tt->waiting += (tt->resumed - tt->yielded);

	/*
	 *	Remove this request into the workers list of waiting
	 *	requests.
	 */
	FR_DLIST_REMOVE(tt->list);
}
