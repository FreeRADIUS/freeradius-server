/*
 * time.c	Platform independent time functions
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
 * Copyright 2016  Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
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

#define NANOSEC (1000000000)
#define USEC	(1000000)


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
		if (ts.tv_nsec > NANOSEC) {
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
