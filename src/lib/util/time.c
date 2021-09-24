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

_Atomic int64_t			our_realtime;	//!< realtime at the start of the epoch in nanoseconds.
static char const		*tz_names[2] = { NULL, NULL };	//!< normal, DST, from localtime_r(), tm_zone
static long			gmtoff[2] = {0, 0};	       	//!< from localtime_r(), tm_gmtoff
static int			isdst = 0;			//!< from localtime_r(), tm_is_dst

#ifdef HAVE_CLOCK_GETTIME
int64_t				our_epoch;
#else  /* __MACH__ */
mach_timebase_info_data_t	timebase;
uint64_t			our_mach_epoch;
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
				      fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts_realtime)) -
				      (fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts_monotime)) - our_epoch),
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
				      fr_time_delta_unwrap(fr_time_delta_from_timeval(&tv_realtime)) -
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
		our_epoch = fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts));
	}
#else  /* __MACH__ is defined */
	mach_timebase_info(&timebase);
	our_mach_epoch = mach_absolute_time();
#endif

	return fr_time_sync();
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
	*delta = fr_time_delta_wrap(0);

	if ((strcmp(tz, "UTC") == 0) ||
	    (strcmp(tz, "GMT") == 0)) {
		return 0;
	}

	/*
	 *	Our local time zone OR time zone with daylight savings.
	 */
	if (tz_names[0] && (strcmp(tz, tz_names[0]) == 0)) {
		*delta = fr_time_delta_wrap(gmtoff[0]);
		return 0;
	}

	if (tz_names[1] && (strcmp(tz, tz_names[1]) == 0)) {
		*delta = fr_time_delta_wrap(gmtoff[1]);
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
	int64_t	sec;
	uint64_t subsec = 0;
	int	scale = 1;
	char	*p, *end;
	bool	negative = false;

	if (*in == '-') negative = true; /* catch the case of negative zero! */

	sec = strtoll(in, &end, 10);
	if (in == end) {
	failed:
		fr_strerror_printf("Failed parsing \"%s\" as time_delta", in);
		return -1;
	}

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

		len = subsec = 0;

		end++;
		p = end;

		/*
		 *	Parse the decimal portion of a number like "0.1".
		 */
		while ((*p >= '0') && (*p <= '9')) {
			if (len > 9) {
				fr_strerror_const("Too much precision for time_delta");
				return -1;
			}

			subsec *= 10;
			subsec += *p - '0';
			p++;
			len++;
		}

		/*
		 *	We've just parsed the fractional part of "0.1"
		 *	as "1".  We need to shift it left to convert
		 *	it to nanoseconds.
		 */
		while (len < 9) {
			subsec *= 10;
			len++;
		}

	parse_precision:
		/*
		 *	No precision qualifiers, it defaults to
		 *	whatever scale the caller passed as a hint.
		 */
		if (!*p) goto do_scale;

		if ((p[0] == 's') && !p[1]) {
			scale = NSEC;
			goto done;
		}

		/*
		 *	Everything else has "ms" or "us" or "ns".
		 *
		 *	"1.1ns" means "parse it as 1.1s, and then
		 *	shift it right 9 orders of magnitude to
		 *	convert it to nanoseconds.
		 */
		if ((p[1] == 's') && (p[2] == '\0')) {
			if (p[0] == 'm') {
				scale = 1000000; /* 1,000,000 nanoseconds in a millisecond */
				goto done;
			}

			if (p[0] == 'u') {
				scale = 1000; /* 1,000 msec on a used */
				goto done;
			}

			if (p[0] == 'n') {
				scale = 1;
				goto done;
			}
		}

		/*
		 *	minutes, hours, or days.
		 *
		 *	Fractional numbers are not allowed.
		 *
		 *	minutes / hours / days larger than 64K are disallowed.
		 */
		if (sec > 65535) {
			fr_strerror_printf("Invalid value at \"%s\"", in);
			return -1;
		}

		if ((p[0] == 'm') && !p[1]) {
			*out = fr_time_delta_from_sec(sec * 60);
			return 0;
		}

		if ((p[0] == 'h') && !p[1]) {
			*out = fr_time_delta_from_sec(sec * 3600);
			return 0;
		}

		if ((p[0] == 'd') && !p[1]) {
			*out = fr_time_delta_from_sec(sec * 86400);
			return 0;
		}

	error:
		fr_strerror_printf("Invalid time qualifier at \"%s\"", p);
		return -1;

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
		 *	@todo - support hours, maybe.  Even though
		 *	pretty much nothing needs them right now.
		 */
		if (*end) goto failed;

		if (negative) {
			*out = fr_time_delta_from_sec(minutes * 60 - sec);
		} else {
			*out = fr_time_delta_from_sec(minutes * 60 + sec);
		}
		return 0;

	} else if (*end) {
		p = end;
		goto error;

	} else {
	do_scale:
		switch (hint) {
		case FR_TIME_RES_SEC:
			scale = NSEC;
			break;

		case FR_TIME_RES_MSEC:
			scale = 1000000;
			break;

		case FR_TIME_RES_USEC:
			scale = 1000;
			break;

		case FR_TIME_RES_NSEC:
			scale = 1;
			break;

		default:
			fr_strerror_printf("Invalid hint %d for time delta", hint);
			return -1;
		}
	}

done:
	/*
	 *	Subseconds was parsed as if it was nanoseconds.  But
	 *	instead it may be something else, so it should be
	 *	truncated.
	 *
	 *	Note that this operation can't overflow.
	 */
	subsec *= scale;
	subsec /= NSEC;

	/*
	 *	Now sec && subsec are in the same scale.
	 */
	if (negative) {
		if (sec <= (INT64_MIN / scale)) {
			fr_strerror_const("Integer underflow in time_delta value.");
			return -1;
		}

		sec *= scale;
		sec -= subsec;
	} else {
		if (sec >= (INT64_MAX / scale)) {
			fr_strerror_const("Integer overflow in time_delta value.");
			return -1;
		}

		sec *= scale;
		sec += subsec;
	}

	*out = fr_time_delta_wrap(sec);

	return 0;
}

DIAG_OFF(format-nonliteral)
/** Copy a time string (local timezone) to an sbuff
 *
 * @note This function will attempt to extend the sbuff by double the length of
 *	 the fmt string.  It is recommended to either pre-extend the sbuff before
 *	 calling this function, or avoid using format specifiers that expand to
 *	 character strings longer than 4 bytes.
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

	len = strftime(fr_sbuff_current(out), fr_sbuff_extend_lowat(NULL, out, strlen(fmt) * 2), fmt, &tm);
	if (len == 0) return 0;

	return fr_sbuff_advance(out, len);
}

/** Copy a time string (UTC) to an sbuff
 *
 * @note This function will attempt to extend the sbuff by double the length of
 *	 the fmt string.  It is recommended to either pre-extend the sbuff before
 *	 calling this function, or avoid using format specifiers that expand to
 *	 character strings longer than 4 bytes.
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

	len = strftime(fr_sbuff_current(out), fr_sbuff_extend_lowat(NULL, out, strlen(fmt) * 2), fmt, &tm);
	if (len == 0) return 0;

	return fr_sbuff_advance(out, len);
}
DIAG_ON(format-nonliteral)

void fr_time_elapsed_update(fr_time_elapsed_t *elapsed, fr_time_t start, fr_time_t end)
{
	fr_time_delta_t delay;

	if (fr_time_gteq(start, end)) {
		delay = fr_time_delta_wrap(0);
	} else {
		delay = fr_time_sub(end, start);
	}

	if (fr_time_delta_lt(delay, fr_time_delta_wrap(1000))) { /* microseconds */
		elapsed->array[0]++;

	} else if (fr_time_delta_lt(delay, fr_time_delta_wrap(10000))) {
		elapsed->array[1]++;

	} else if (fr_time_delta_lt(delay, fr_time_delta_wrap(100000))) {
		elapsed->array[2]++;

	} else if (fr_time_delta_lt(delay, fr_time_delta_wrap(1000000))) { /* milliseconds */
		elapsed->array[3]++;

	} else if (fr_time_delta_lt(delay, fr_time_delta_wrap(10000000))) {
		elapsed->array[4]++;

	} else if (fr_time_delta_lt(delay, fr_time_delta_wrap(100000000))) {
		elapsed->array[5]++;

	} else if (fr_time_delta_lt(delay, fr_time_delta_wrap(1000000000))) { /* seconds */
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
fr_unix_time_t fr_unix_time_from_tm(struct tm *tm)
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
	return fr_unix_time_from_sec((days - 2472692) * 86400 + (tm->tm_hour * 3600) + (tm->tm_min * 60) + tm->tm_sec + tm->tm_gmtoff);
}

int64_t fr_time_delta_scale(fr_time_delta_t delta, fr_time_res_t hint)
{
	switch (hint) {
	case FR_TIME_RES_SEC:
		return fr_time_delta_to_sec(delta);

	case FR_TIME_RES_CSEC:
		return fr_time_delta_to_csec(delta);

	case FR_TIME_RES_MSEC:
		return fr_time_delta_to_msec(delta);

	case FR_TIME_RES_USEC:
		return fr_time_delta_to_usec(delta);

	case FR_TIME_RES_NSEC:
		return fr_time_delta_unwrap(delta);

	default:
		break;
	}

	return 0;
}
