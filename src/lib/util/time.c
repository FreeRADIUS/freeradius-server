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
 * @file lib/util/time.c
 *
 * @copyright 2016-2019 Alan DeKok (aland@freeradius.org)
 * @copyright 2019-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/strerror.h>
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

#include <stdatomic.h>

static _Atomic int64_t			our_realtime;	//!< realtime at the start of the epoch in nanoseconds.
static char const			*tz_names[2] = { NULL, NULL };	//!< normal, DST, from localtime_r(), tm_zone
static long				gmtoff[2] = {0, 0};	       	//!< from localtime_r(), tm_gmtoff
static int				isdst = 0;			//!< from localtime_r(), tm_is_dst

#ifdef HAVE_CLOCK_GETTIME
static int64_t				our_epoch;
#else  /* __MACH__ */
static mach_timebase_info_data_t	timebase;
static uint64_t				our_mach_epoch;
#endif

/** Get a new our_realtime value
 *
 * Should be done regularly to adjust for changes in system time.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_time_sync(void)
{
	struct tm tm;
	time_t now;

	/*
	 *	our_realtime represents system time
	 *	at the start of our epoch.
	 *
	 *	So to convert a realtime timeval
	 *	to fr_time we just subtract
	 *	our_realtime from the timeval,
	 *      which leaves the number of nanoseconds
	 *	elapsed since our epoch.
	 */
#ifdef HAVE_CLOCK_GETTIME
	{
		struct timespec ts_realtime, ts_monotime;

		/*
		 *	Call these consecutively to minimise drift...
		 */
		if (clock_gettime(CLOCK_REALTIME, &ts_realtime) < 0) return -1;
		if (clock_gettime(CLOCK_MONOTONIC, &ts_monotime) < 0) return -1;

		atomic_store_explicit(&our_realtime,
				      fr_time_delta_from_timespec(&ts_realtime) -
				      (fr_time_delta_from_timespec(&ts_monotime) - our_epoch),
				      memory_order_release);

		now = ts_realtime.tv_sec;
	}
#else
	{
		struct timeval	tv_realtime;
		uint64_t	monotime;

		/*
		 *	Call these consecutively to minimise drift...
		 */
		(void) gettimeofday(&tv_realtime, NULL);
		monotime = mach_absolute_time();

		atomic_store_explicit(&our_realtime,
				      fr_time_delta_from_timeval(&tv_realtime) -
				      (monotime - our_mach_epoch) * (timebase.numer / timebase.denom,
				      memory_order_release));

		now = tv_realtime.tv_sec;
	}
#endif

	/*
	 *	Get local time zone name, daylight savings, and GMT
	 *	offsets.
	 */
	(void) localtime_r(&now, &tm);

	isdst = (tm.tm_isdst != 0);
	tz_names[isdst] = tm.tm_zone;
	gmtoff[isdst] = tm.tm_gmtoff * NSEC; /* they store seconds, we store nanoseconds */

	return 0;
}

/** Initialize the local time.
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
	tzset();	/* Populate timezone, daylight and tzname globals */

#ifdef HAVE_CLOCK_GETTIME
	{
		struct timespec ts;

		if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return -1;
		our_epoch = fr_time_delta_from_timespec(&ts);
	}
#else  /* __MACH__ is defined */
	mach_timebase_info(&timebase);
	our_mach_epoch = mach_absolute_time();
#endif

	return fr_time_sync();
}

/** Return a relative time since the server our_epoch
 *
 *  This time is useful for doing time comparisons, deltas, etc.
 *  Human (i.e. printable) time is something else.
 *
 * @returns fr_time_t time in nanoseconds since the server our_epoch.
 */
fr_time_t fr_time(void)
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

/** Nanoseconds since the Unix Epoch the last time we synced internal time with wallclock time
 *
 */
int64_t fr_time_wallclock_at_last_sync(void)
{
	return atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert an fr_time_t (internal time) to our version of unix time (wallclock time)
 *
 */
fr_unix_time_t fr_time_to_unix_time(fr_time_t when)
{
	return when + atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Convert an fr_time_t (internal time) to number of usec since the unix epoch (wallclock time)
 *
 */
int64_t fr_time_to_usec(fr_time_t when)
{
	return ((when + atomic_load_explicit(&our_realtime, memory_order_consume)) / 1000);
}

/** Convert an fr_time_t (internal time) to number of msec since the unix epoch (wallclock time)
 *
 */
int64_t fr_time_to_msec(fr_time_t when)
{
	return ((when + atomic_load_explicit(&our_realtime, memory_order_consume)) / 1000000);
}

/** Convert an fr_time_t (internal time) to number of sec since the unix epoch (wallclock time)
 *
 */
int64_t fr_time_to_sec(fr_time_t when)
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
fr_time_t fr_time_from_timeval(struct timeval const *when_tv)
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
fr_time_t fr_time_from_sec(time_t when)
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
fr_time_t fr_time_from_timespec(struct timespec const *when_ts)
{
	return fr_time_delta_from_timespec(when_ts) - atomic_load_explicit(&our_realtime, memory_order_consume);
}

/** Return time delta from the time zone.
 *
 * Returns the delta between UTC and the timezone specified by tz
 *
 * @param[in] tz	time zone name
 * @param[out] delta	the time delta
 * @return
 *	- 0 converted OK
 *	- <0 on error
 *
 *  @note This function ONLY handles a limited number of time
 *  zones: local and gmt.  It is impossible in general to parse
 *  arbitrary time zone strings, as there are duplicates.
 */
int fr_time_delta_from_time_zone(char const *tz, fr_time_delta_t *delta)
{
	*delta = 0;

	if ((strcmp(tz, "UTC") == 0) ||
	    (strcmp(tz, "GMT") == 0)) {
		return 0;
	}

	/*
	 *	Our local time zone OR time zone with daylight savings.
	 */
	if (tz_names[0] && (strcmp(tz, tz_names[0]) == 0)) {
		*delta = gmtoff[0];
		return 0;
	}

	if (tz_names[1] && (strcmp(tz, tz_names[1]) == 0)) {
		*delta = gmtoff[1];
		return 0;
	}

	return -1;
}

/** Create fr_time_delta_t from a string
 *
 * @param[out] out	Where to write fr_time_delta_t
 * @param[in] in	String to parse.
 * @param[in] hint	scale for the parsing.  Default is "seconds"
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_time_delta_from_str(fr_time_delta_t *out, char const *in, fr_time_res_t hint)
{
	int	sec;
	char	*p, *end;
	fr_time_delta_t delta;

	sec = strtoul(in, &end, 10);
	if (in == end) {
	failed:
		fr_strerror_printf("Failed parsing \"%s\" as time_delta", in);
		return -1;
	}

	/*
	 *	Cast before multiplication to avoid integer overflow
	 *	in 'int' seconds.
	 */
	delta = sec;
	delta *= NSEC;

	/*
	 *	Allow "1ns", etc.
	 */
	if ((*end >= 'a') && (*end <= 'z')) {
		p = end;
		goto parse_precision;
	}

	/*
	 *	Decimal number
	 */
	if (*end == '.') {
		int len;

		len = sec = 0;

		end++;
		p = end;

		/*
		 *	Parse the decimal portion of a number like "0.1".
		 */
		while ((*p >= '0') && (*p <= '9')) {
			if (len > 9) {
				fr_strerror_printf("Too much precision for time_delta");
			}

			sec *= 10;
			sec += *p - '0';
			p++;
			len++;
		}

		/*
		 *	We've just parsed "0.1" as "1".  We need to
		 *	shift it left to convert it to nanoseconds.
		 */
		while (len < 9) {
			sec *= 10;
			len++;
		}

		delta += sec;

	parse_precision:
		/*
		 *	Nothing else, it defaults to whatever scale the caller passed.
		 */
		if (!*p) goto do_scale;

		if ((p[0] == 's') && !p[1]) goto done;

		/*
		 *	Everything else has "ms" or "us" or "ns".
		 *
		 *	"1.1ns" means "parse it as 1.1s, and then
		 *	shift it right 9 orders of magnitude to
		 *	convert it to nanoseconds.
		 */
		if ((p[1] == 's') && (p[2] == '\0')) {
			if (p[0] == 'm') {
				delta /= 1000;
				goto done;
			}

			if (p[0] == 'u') {
				delta /= 1000000;
				goto done;
			}

			if (p[0] == 'n') {
				delta /= NSEC;
				goto done;
			}

		error:
			fr_strerror_printf("Invalid time qualifier in \"%s\"", p);
			return -1;
		}

		if ((p[0] == 'm') && !p[1]) {
			delta *= 60;
			goto done;
		}

		if ((p[0] == 'h') && !p[1]) {
			delta *= 3600;
			goto done;
		}

		if ((p[0] == 'd') && !p[1]) {
			delta *= 86400;
			goto done;
		}

		goto error;

	} else if (*end == ':') {
		/*
		 *	00:01 is at least minutes, potentially hours
		 */
		int minutes = sec;

		p = end + 1;
		sec = strtoul(p, &end, 10);
		if (p == end) goto failed;

		if (*end) goto failed;

		if (sec > 60) {
			fr_strerror_printf("Too many seconds in \"%s\"", in);
			return -1;
		}

		if (minutes > 60) {
			fr_strerror_printf("Too many minutes in \"%s\"", in);
			return -1;
		}

		/*
		 *	@todo - do we want to allow decimals, as in
		 *	"1:30.5"? Perhaps not for now.
		 *
		 *	@todo - support hours, maybe.  Even though
		 *	pretty much nothing needs them right now.
		 */
		if (*end) goto failed;

		delta = minutes * 60 + sec;
		delta *= NSEC;

	} else if (!*end) {
	do_scale:
		switch (hint) {
		case FR_TIME_RES_SEC:
			break;

		case FR_TIME_RES_MSEC:
			delta /= 1000;
			break;

		case FR_TIME_RES_USEC:
			delta /= 1000000;
			break;

		case FR_TIME_RES_NSEC:
			delta /= 1000000000;
			break;

		default:
			fr_strerror_printf("Invalid hint %d for time delta", hint);
			return -1;
		}

	} else {
		goto failed;
	}

done:
	*out = delta;

	return 0;
}

DIAG_OFF(format-nonliteral)
/** Copy a time string (local timezone) to an sbuff
 *
 * @param[in] out	Where to write the formatted time string.
 * @param[in] time	Internal server time to convert to wallclock
 *			time and copy out as formatted string.
 * @param[in] fmt	Time format string.
 * @return
 *	- >0 the number of bytes written to the sbuff.
 *	- 0 if there's insufficient space in the sbuff.
 */
size_t fr_time_strftime_local(fr_sbuff_t *out, fr_time_t time, char const *fmt)
{
	struct tm	tm;
	time_t		utime = fr_time_to_sec(time);
	size_t		len;

	localtime_r(&utime, &tm);

	len = strftime(fr_sbuff_current(out), fr_sbuff_remaining(out), fmt, &tm);
	if (len == 0) return 0;

	return fr_sbuff_advance(out, len);
}

/** Copy a time string (UTC) to an sbuff
 *
 * @param[in] out	Where to write the formatted time string.
 * @param[in] time	Internal server time to convert to wallclock
 *			time and copy out as formatted string.
 * @param[in] fmt	Time format string.
 * @return
 *	- >0 the number of bytes written to the sbuff.
 *	- 0 if there's insufficient space in the sbuff.
 */
size_t fr_time_strftime_utc(fr_sbuff_t *out, fr_time_t time, char const *fmt)
{
	struct tm	tm;
	time_t		utime = fr_time_to_sec(time);
	size_t		len;

	gmtime_r(&utime, &tm);

	len = strftime(fr_sbuff_current(out), fr_sbuff_remaining(out), fmt, &tm);
	if (len == 0) return 0;

	return fr_sbuff_advance(out, len);
}
DIAG_ON(format-nonliteral)

void fr_time_elapsed_update(fr_time_elapsed_t *elapsed, fr_time_t start, fr_time_t end)
{
	fr_time_t delay;

	if (start >= end) {
		delay = 0;
	} else {
		delay = end - start;
	}

	if (delay < 1000) { /* microseconds */
		elapsed->array[0]++;

	} else if (delay < 10000) {
		elapsed->array[1]++;

	} else if (delay < 100000) {
		elapsed->array[2]++;

	} else if (delay < 1000000) { /* milliseconds */
		elapsed->array[3]++;

	} else if (delay < 10000000) {
		elapsed->array[4]++;

	} else if (delay < (fr_time_t) 100000000) {
		elapsed->array[5]++;

	} else if (delay < (fr_time_t) 1000000000) { /* seconds */
		elapsed->array[6]++;

	} else {		/* tens of seconds or more */
		elapsed->array[7]++;

	}
}

static const char *names[8] = {
	"1us", "10us", "100us",
	"1ms", "10ms", "100ms",
	"1s", "10s"
};

static char const *tab_string = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

void fr_time_elapsed_fprint(FILE *fp, fr_time_elapsed_t const *elapsed, char const *prefix, int tab_offset)
{
	int i;
	size_t prefix_len;

	if (!prefix) prefix = "elapsed";

	prefix_len = strlen(prefix);

	for (i = 0; i < 8; i++) {
		size_t len;

		if (!elapsed->array[i]) continue;

		len = prefix_len + strlen(names[i]);

		if (len >= (size_t) (tab_offset * 8)) {
			fprintf(fp, "%s.%s %" PRIu64 "\n",
				prefix, names[i], elapsed->array[i]);

		} else {
			int tabs;

			tabs = ((tab_offset * 8) - len);
			if ((tabs & 0x07) != 0) tabs += 7;
			tabs >>= 3;

			fprintf(fp, "%s.%s%.*s%" PRIu64 "\n",
				prefix, names[i], tabs, tab_string, elapsed->array[i]);
		}
	}
}

/*
 *	Based on https://blog.reverberate.org/2020/05/12/optimizing-date-algorithms.html
 */
time_t fr_time_from_utc(struct tm *tm)
{
	static const uint16_t month_yday[12] = {0,   31,  59,  90,  120, 151,
						181, 212, 243, 273, 304, 334};

	uint32_t year_adj = tm->tm_year + 4800 + 1900;  /* Ensure positive year, multiple of 400. */
	uint32_t febs = year_adj - (tm->tm_mon <= 2 ? 1 : 0);  /* Februaries since base. */
	uint32_t leap_days = 1 + (febs / 4) - (febs / 100) + (febs / 400);
	uint32_t days = 365 * year_adj + leap_days + month_yday[tm->tm_mon] + tm->tm_mday - 1;

	/*
	 *	2472692 adjusts the days for Unix epoch.  It is calculated as
	 *	(365.2425 * (4800 + 1970))
	 */
	return (days - 2472692) * 86400 + (tm->tm_hour * 3600) + (tm->tm_min * 60) + tm->tm_sec;
}
