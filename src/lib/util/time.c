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
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/skip.h>

int64_t const fr_time_multiplier_by_res[] = {
	[FR_TIME_RES_NSEC]	= 1,
	[FR_TIME_RES_USEC]	= NSEC / USEC,
	[FR_TIME_RES_MSEC]	= NSEC / MSEC,
	[FR_TIME_RES_CSEC]	= NSEC / CSEC,
	[FR_TIME_RES_SEC]	= NSEC,
	[FR_TIME_RES_MIN]	= (int64_t)NSEC * 60,
	[FR_TIME_RES_HOUR]	= (int64_t)NSEC * 3600,
	[FR_TIME_RES_DAY]	= (int64_t)NSEC * 86400,
	[FR_TIME_RES_WEEK]	= (int64_t)NSEC * 86400 * 7,
	[FR_TIME_RES_MONTH]	= FR_TIME_DUR_MONTH,
	[FR_TIME_RES_YEAR]	= FR_TIME_DUR_YEAR,
};

fr_table_num_ordered_t const fr_time_precision_table[] = {
	{ L("microseconds"),	FR_TIME_RES_USEC },
	{ L("us"),		FR_TIME_RES_USEC },

	{ L("nanoseconds"),	FR_TIME_RES_NSEC },
	{ L("ns"),		FR_TIME_RES_NSEC },

	{ L("milliseconds"),	FR_TIME_RES_MSEC },
	{ L("ms"),		FR_TIME_RES_MSEC },

	{ L("centiseconds"),	FR_TIME_RES_CSEC },
	{ L("cs"),		FR_TIME_RES_CSEC },

	{ L("seconds"),		FR_TIME_RES_SEC },
	{ L("s"),		FR_TIME_RES_SEC },

	{ L("minutes"),		FR_TIME_RES_MIN },
	{ L("m"),		FR_TIME_RES_MIN },

	{ L("hours"),		FR_TIME_RES_HOUR },
	{ L("h"),		FR_TIME_RES_HOUR },

	{ L("days"),		FR_TIME_RES_DAY },
	{ L("d"),		FR_TIME_RES_DAY },

	{ L("weeks"),		FR_TIME_RES_WEEK },
	{ L("w"),		FR_TIME_RES_WEEK },

	/*
	 *	These use special values FR_TIME_DUR_MONTH and FR_TIME_DUR_YEAR
	 */
	{ L("months"),		FR_TIME_RES_MONTH },
	{ L("M"),		FR_TIME_RES_MONTH },

	{ L("years"),		FR_TIME_RES_YEAR },
	{ L("y"),		FR_TIME_RES_YEAR },

};
size_t fr_time_precision_table_len = NUM_ELEMENTS(fr_time_precision_table);

int64_t				fr_time_epoch;					//!< monotonic clock at boot, i.e. our epoch
_Atomic int64_t			fr_time_monotonic_to_realtime;			//!< difference between the two clocks

static char const		*tz_names[2] = { NULL, NULL };	//!< normal, DST, from localtime_r(), tm_zone
static long			gmtoff[2] = {0, 0};	       	//!< from localtime_r(), tm_gmtoff
static bool			isdst = false;			//!< from localtime_r(), tm_is_dst


/** Get a new fr_time_monotonic_to_realtime value
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
	 *	fr_time_monotonic_to_realtime is the difference in nano
	 *
	 *	So to convert a realtime timeval to fr_time we just subtract fr_time_monotonic_to_realtime from the timeval,
	 *	which leaves the number of nanoseconds elapsed since our epoch.
	 */
	struct timespec ts_realtime, ts_monotime;

	/*
	 *	Call these consecutively to minimise drift...
	 */
	if (clock_gettime(CLOCK_REALTIME, &ts_realtime) < 0) return -1;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts_monotime) < 0) return -1;

	atomic_store_explicit(&fr_time_monotonic_to_realtime,
			      fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts_realtime)) -
			      (fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts_monotime)) - fr_time_epoch),
			      memory_order_release);

	now = ts_realtime.tv_sec;

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
	struct timespec ts;

	tzset();	/* Populate timezone, daylight and tzname globals */

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0) return -1;
	fr_time_epoch = fr_time_delta_unwrap(fr_time_delta_from_timespec(&ts));

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
 * @param[out] out		Where to write fr_time_delta_t
 * @param[in] in		String to parse.
 * @param[in] hint		scale for the parsing.  Default is "seconds".
 * @param[in] no_trailing	asserts that there should be a terminal sequence
 *				after the time delta.  Allows us to produce
 *      			better errors.
 * @param[in] tt		terminal sequences.
 * @return
 *	- >= 0 on success.
 *	- <0 on failure.
 */
fr_slen_t fr_time_delta_from_substr(fr_time_delta_t *out, fr_sbuff_t *in, fr_time_res_t hint,
				    bool no_trailing, fr_sbuff_term_t const *tt)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	int64_t			integer = 0;	/* Whole units */
	double			f = 0.0;
	fr_time_res_t		res;
	bool			do_float;
	bool			negative;
	fr_sbuff_parse_error_t	sberr;
	bool			overflow;
	size_t			match_len;

	negative = fr_sbuff_is_char(&our_in, '-');
	do_float = false;

	if (fr_sbuff_is_char(&our_in, '.')) goto is_float;

	/*
	 *	Look for:
	 *
	 *	<integer>[scale]
	 */
	if (fr_sbuff_out(&sberr, &integer, &our_in) < 0) {
		char const *err;

	num_error:
		if (sberr != FR_SBUFF_PARSE_ERROR_NOT_FOUND) {
			err = fr_table_str_by_value(sbuff_parse_error_table, sberr, "<INVALID>");
		} else {
			err = "Invalid text, input should be a number";
		}

		fr_strerror_printf("Failed parsing time_delta: %s", err);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	hh:mm:ss
	 */
	if (fr_sbuff_next_if_char(&our_in, ':')) goto do_timestamp;

	/*
	 *	If it's a fractional thing, then just parse it as a double.
	 *
	 *	<float>[scale]
	 */
	if (fr_sbuff_is_char(&our_in, '.')) {
		our_in = FR_SBUFF(in);

	is_float:
		if (fr_sbuff_out(&sberr, &f, &our_in) < 0) goto num_error;

		do_float = true;
	}

	/*
	 *	Now look for the time resolution.
	 */
	fr_sbuff_out_by_longest_prefix(&match_len, &res, fr_time_precision_table, &our_in, FR_TIME_RES_INVALID);

	if (fr_sbuff_is_terminal(&our_in, tt)) {
		if (match_len == 0) res = hint;

	} else if (no_trailing) {
	fail_trailing_data:
		/* Got a qualifier but there is more text after it. */
		if (res != FR_TIME_RES_INVALID) {
			fr_strerror_const("Trailing data after time_delta");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		fr_strerror_const("Invalid precision qualifier for time_delta");
		FR_SBUFF_ERROR_RETURN(&our_in);

	} else if (match_len == 0) {
		/*
		 *	There is trailing data, but we don't care about it.  Ensure that we have a time resolution.
		 */
		res = hint;
	}

	fr_assert(res != FR_TIME_RES_INVALID);

	/*
	 *	For floating point numbers, we pre-multiply by the time resolution, and then override the time
	 *	resolution to indicate that no further scaling is necessary.
	 *
	 *	We check for overflow prior to multiplication, as doubles have ~53 bits of precision, while
	 *	int64_t has 64 bits of precision.  That way the comparison is more likely to be accurate.
	 */
	if (do_float) {
		if (f < ((double) INT64_MIN) / (double) fr_time_multiplier_by_res[res])  goto fail_overflow;
		if (f > ((double) INT64_MAX) / (double) fr_time_multiplier_by_res[res]) goto fail_overflow;

		f *= fr_time_multiplier_by_res[res];
		res = FR_TIME_RES_NSEC;
		integer = f;
	}

	/*
	 *	We have a valid time scale.  Let's use that.
	 */
	*out = fr_time_delta_from_integer(&overflow, integer, res);
	if (overflow) {
	fail_overflow:
		fr_strerror_printf("time_delta would %s", negative ? "underflow" : "overflow");
		fr_sbuff_set_to_start(&our_in);
		FR_SBUFF_ERROR_RETURN(&our_in);

	}
	FR_SBUFF_SET_RETURN(in, &our_in);

do_timestamp:
	res = hint;

	/*
	 *	It's a timestamp format
	 *
	 *	[hours:]minutes:seconds
	 */
	{
		uint64_t		hours, minutes, seconds;
		fr_sbuff_marker_t 	m1;

		fr_sbuff_marker(&m1, &our_in);

		if (fr_sbuff_out(&sberr, &seconds, &our_in) < 0) goto num_error;

		/*
		 *	minutes:seconds
		 */
		if (!fr_sbuff_next_if_char(&our_in, ':')) {
			hours = 0;
			minutes = negative ? -(integer) : integer;

			if (minutes > 60) {
				fr_strerror_printf("minutes component of time_delta is too large");
				fr_sbuff_set_to_start(&our_in);
				FR_SBUFF_ERROR_RETURN(&our_in);
			}

		} else {
			/*
			 *	hours:minutes:seconds
			 */
			hours = negative ? -(integer) : integer;
			minutes = seconds;

			if (fr_sbuff_out(&sberr, &seconds, &our_in) < 0) goto num_error;

			/*
			 *	We allow >24 hours.  What the heck.
			 */
			if (hours > UINT16_MAX) {
				fr_strerror_printf("hours component of time_delta is too large");
				fr_sbuff_set_to_start(&our_in);
				FR_SBUFF_ERROR_RETURN(&our_in);
			}

			if (minutes > 60) {
				fr_strerror_printf("minuts component of time_delta is too large");
				FR_SBUFF_ERROR_RETURN(&m1);
			}

			if (seconds > 60) {
				fr_strerror_printf("seconds component of time_delta is too large");
				FR_SBUFF_ERROR_RETURN(&m1);
			}
		}

		if (no_trailing && !fr_sbuff_is_terminal(&our_in, tt)) goto fail_trailing_data;

		/*
		 *	Add all the components together...
		 */
		if (!fr_add(&integer, ((hours * 60) * 60) + (minutes * 60), seconds)) goto fail_overflow;

		/*
		 *	Flip the sign back to negative
		 */
		if (negative) integer = -(integer);
	}

	*out = fr_time_delta_from_sec(integer);
	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Create fr_time_delta_t from a string
 *
 * @param[out] out	Where to write fr_time_delta_t
 * @param[in] in	String to parse.
 * @param[in] inlen	Length of string.
 * @param[in] hint	scale for the parsing.  Default is "seconds"
 * @return
 *	- >0 on success.
 *	- <0 on failure.
 */
fr_slen_t fr_time_delta_from_str(fr_time_delta_t *out, char const *in, size_t inlen, fr_time_res_t hint)
{
	fr_slen_t slen;

	slen = fr_time_delta_from_substr(out, &FR_SBUFF_IN(in, inlen), hint, true, NULL);
	if (slen < 0) return slen;
	if (slen != (fr_slen_t)inlen) {
		fr_strerror_const("trailing data after time_delta");	/* Shouldn't happen with no_trailing */
		return -(inlen + 1);
	}
	return slen;
}

/** Print fr_time_delta_t to a string with an appropriate suffix
 *
 * @param[out] out		Where to write the string version of the time delta.
 * @param[in] delta		to print.
 * @param[in] res		to print resolution with.
 * @param[in] is_unsigned	whether the value should be printed unsigned.
 * @return
 *	- >0 the number of bytes written to out.
 *      - <0 how many additional bytes would have been required.
 */
fr_slen_t fr_time_delta_to_str(fr_sbuff_t *out, fr_time_delta_t delta, fr_time_res_t res, bool is_unsigned)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);
	char		*q;
	int64_t		lhs = 0;
	uint64_t	rhs = 0;

/*
 *	The % operator can return a _signed_ value.  This macro is
 *	correct for both positive and negative inputs.
 */
#define MOD(a,b) (((a<0) ? (-a) : (a))%(b))

	lhs = fr_time_delta_to_integer(delta, res);
	rhs = MOD(fr_time_delta_unwrap(delta), fr_time_multiplier_by_res[res]);

	if (!is_unsigned) {
		/*
		 *	0 is unsigned, but we want to print
		 *	"-0.1" if necessary.
		 */
		if ((lhs == 0) && fr_time_delta_isneg(delta)) {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, '-');
		}

		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%" PRIi64 ".%09" PRIu64, lhs, rhs);
	} else {
		if (fr_time_delta_isneg(delta)) lhs = rhs = 0;

		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%" PRIu64 ".%09" PRIu64, lhs, rhs);
	}
	q = fr_sbuff_current(&our_out) - 1;

	/*
	 *	Truncate trailing zeros.
	 */
	while (*q == '0') *(q--) = '\0';

	/*
	 *	If there's nothing after the decimal point,
	 *	truncate the decimal point.  i.e. Don't print
	 *	"5."
	 */
	if (*q == '.') {
		*q = '\0';
	} else {
		q++;	/* to account for q-- above */
	}

	FR_SBUFF_SET_RETURN(out, q);
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

		len = prefix_len + 1 + strlen(names[i]);

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

	uint32_t year_adj;
	uint32_t febs;
	uint32_t leap_days;
	uint32_t days;

	/* Prevent crash if tm->tm_mon is invalid - seen in clusterfuzz */
	if (unlikely(tm->tm_mon >= (__typeof__(tm->tm_mon))NUM_ELEMENTS(month_yday))) return fr_unix_time_min();

	if (unlikely(tm->tm_year > 10000)) return fr_unix_time_min();

	year_adj = tm->tm_year + 4800 + 1900;  /* Ensure positive year, multiple of 400. */
	febs = year_adj - (tm->tm_mon < 2 ? 1 : 0);  /* Februaries since base. tm_mon is 0 - 11 */
	leap_days = 1 + (febs / 4) - (febs / 100) + (febs / 400);

	days = 365 * year_adj + leap_days + month_yday[tm->tm_mon] + tm->tm_mday - 1;

#define CHECK(_x, _max) if ((tm->tm_ ## _x < 0) || (tm->tm_ ## _x >= _max)) tm->tm_ ## _x = _max - 1

	CHECK(sec, 60);
	CHECK(min, 60);
	CHECK(hour, 24);
	CHECK(mday, 32);
	CHECK(mon, 12);
	CHECK(year, 3000);
	CHECK(wday, 7);
	CHECK(mon, 12);
	CHECK(yday, 366);
	/* don't check gmtoff, it can be negative */

	/*
	 *	2472692 adjusts the days for Unix epoch.  It is calculated as
	 *	(365.2425 * (4800 + 1970))
	 *
	 *	We REMOVE the time zone offset in order to get internal unix times in UTC.
	 */
	return fr_unix_time_from_sec((((days - 2472692) * 86400) + (tm->tm_hour * 3600) +
				     (tm->tm_min * 60) + tm->tm_sec) - tm->tm_gmtoff);
}

/** Scale an input time to NSEC, clamping it at max / min.
 *
 * @param t	input time / time delta
 * @param hint	time resolution hint
 * @return
 *	- INT64_MIN on underflow
 *	- 0 on invalid hint
 *	- INT64_MAX on overflow
 *	- otherwise a valid number, multiplied by the relevant scale,
 *	  so that the result is in nanoseconds.
 */
int64_t	fr_time_scale(int64_t t, fr_time_res_t hint)
{
	int64_t scale;

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
		return t;

	default:
		return 0;
	}

	if (t < 0) {
		if (t < (INT64_MIN / scale)) {
			return INT64_MIN;
		}
	} else if (t > 0) {
		if (t > (INT64_MAX / scale)) {
			return INT64_MAX;
		}
	}

	return t * scale;
}


/*
 *	Sort of strtok/strsep function.
 */
static char *mystrtok(char **ptr, char const *sep)
{
	char	*res;

	if (**ptr == '\0') return NULL;

	while (**ptr && strchr(sep, **ptr)) (*ptr)++;

	if (**ptr == '\0') return NULL;

	res = *ptr;
	while (**ptr && strchr(sep, **ptr) == NULL) (*ptr)++;

	if (**ptr != '\0') *(*ptr)++ = '\0';

	return res;
}

/*
 *	Helper function to get a 2-digit date. With a maximum value,
 *	and a terminating character.
 */
static int get_part(char **str, int *date, int min, int max, char term, char const *name)
{
	char *p = *str;

	if (!isdigit((uint8_t) *p) || !isdigit((uint8_t) p[1])) return -1;
	*date = (p[0] - '0') * 10  + (p[1] - '0');

	if (*date < min) {
		fr_strerror_printf("Invalid %s (too small)", name);
		return -1;
	}

	if (*date > max) {
		fr_strerror_printf("Invalid %s (too large)", name);
		return -1;
	}

	p += 2;
	if (!term) {
		*str = p;
		return 0;
	}

	if (*p != term) {
		fr_strerror_printf("Expected '%c' after %s, got '%c'",
				   term, name, *p);
		return -1;
	}
	p++;

	*str = p;
	return 0;
}

static char const *months[] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec" };


/** Convert string in various formats to a fr_unix_time_t
 *
 * @param date_str input date string.
 * @param date time_t to write result to.
 * @param[in] hint	scale for the parsing.  Default is "seconds"
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_unix_time_from_str(fr_unix_time_t *date, char const *date_str, fr_time_res_t hint)
{
	int		i;
	int64_t		tmp;
	struct tm	*tm, s_tm;
	char		buf[64];
	char		*p;
	char		*f[4];
	char		*tail = NULL;
	unsigned long	l;
	fr_time_delta_t	gmt_delta = fr_time_delta_wrap(0);

	/*
	 *	Test for unix timestamp, which is just a number and
	 *	nothing else.
	 */
	tmp = strtoul(date_str, &tail, 10);
	if (*tail == '\0') {
		*date = fr_unix_time_from_nsec(fr_time_scale(tmp, hint));
		return 0;
	}

	tm = &s_tm;
	memset(tm, 0, sizeof(*tm));
	tm->tm_isdst = -1;	/* don't know, and don't care about DST */

	/*
	 *	Check for RFC 3339 dates.  Note that we only support
	 *	dates in a ~1000 year period.  If the server is being
	 *	used after 3000AD, someone can patch it then.
	 *
	 *	%Y-%m-%dT%H:%M:%S
	 *	[.%d] sub-seconds
	 *	Z | (+/-)%H:%M time zone offset
	 *
	 */
	if ((tmp > 1900) && (tmp < 3000) && *tail == '-') {
		unsigned long subseconds;
		int tz, tz_hour, tz_min;

		p = tail + 1;
		s_tm.tm_year = tmp - 1900; /* 'struct tm' starts years in 1900 */

		if (get_part(&p, &s_tm.tm_mon, 1, 12, '-', "month") < 0) return -1;
		s_tm.tm_mon--;	/* ISO is 1..12, where 'struct tm' is 0..11 */

		if (get_part(&p, &s_tm.tm_mday, 1, 31, 'T', "day") < 0) return -1;
		if (get_part(&p, &s_tm.tm_hour, 0, 23, ':', "hour") < 0) return -1;
		if (get_part(&p, &s_tm.tm_min, 0, 59, ':', "minute") < 0) return -1;
		if (get_part(&p, &s_tm.tm_sec, 0, 60, '\0', "seconds") < 0) return -1;

		if (*p == '.') {
			p++;
			subseconds = strtoul(p, &tail, 10);
			if (subseconds > NSEC) {
				fr_strerror_const("Invalid nanosecond specifier");
				return -1;
			}

			/*
			 *	Scale subseconds to nanoseconds by how
			 *	many digits were parsed/
			 */
			if ((tail - p) < 9) {
				for (i = 0; i < 9 - (tail -p); i++) {
					subseconds *= 10;
				}
			}

			p = tail;
		} else {
			subseconds = 0;
		}

		/*
		 *	Time zone is GMT.  Leave well enough
		 *	alone.
		 */
		if (*p == 'Z') {
			if (p[1] != '\0') {
				fr_strerror_printf("Unexpected text '%c' after time zone", p[1]);
				return -1;
			}
			tz = 0;
			goto done;
		}

		if ((*p != '+') && (*p != '-')) {
			fr_strerror_printf("Invalid time zone specifier '%c'", *p);
			return -1;
		}
		tail = p;	/* remember sign for later */
		p++;

		if (get_part(&p, &tz_hour, 0, 23, ':', "hour in time zone") < 0) return -1;
		if (get_part(&p, &tz_min, 0, 59, '\0', "minute in time zone") < 0) return -1;

		if (*p != '\0') {
			fr_strerror_printf("Unexpected text '%c' after time zone", *p);
			return -1;
		}

		/*
		 *	We set the time zone, but the timegm()
		 *	function ignores it.  Note also that mktime()
		 *	ignores it too, and treats the time zone as
		 *	local.
		 *
		 *	We can't store this value in s_tm.gtmoff,
		 *	because the timegm() function helpfully zeros
		 *	it out.
		 *
		 *	So insyead of using stupid C library
		 *	functions, we just roll our own.
		 */
		tz = tz_hour * 3600 + tz_min;
		if (*tail == '-') tz *= -1;

	done:
		/*
		 *	We REMOVE the time zone offset in order to get internal unix times in UTC.
		 */
		tm->tm_gmtoff = -tz;
		*date = fr_unix_time_add(fr_unix_time_from_tm(tm), fr_time_delta_wrap(subseconds));
		return 0;
	}

	/*
	 *	Try to parse dates via locale-specific names,
	 *	using the same format string as strftime().
	 *
	 *	If that fails, then we fall back to our parsing
	 *	routine, which is much more forgiving.
	 */

#ifdef __APPLE__
	/*
	 *	OSX "man strptime" says it only accepts the local time zone, and GMT.
	 *
	 *	However, when printing dates via strftime(), it prints
	 *	"UTC" instead of "GMT".  So... we have to fix it up
	 *	for stupid nonsense.
	 */
	{
		char const *tz = strstr(date_str, "UTC");
		if (tz) {
			char *my_str;

			my_str = talloc_strdup(NULL, date_str);
			if (my_str) {
				p = my_str + (tz - date_str);
				memcpy(p, "GMT", 3);

				p = strptime(my_str, "%b %e %Y %H:%M:%S %Z", tm);
				if (p && (*p == '\0')) {
					talloc_free(my_str);
					*date = fr_unix_time_from_tm(tm);
					return 0;
				}
				talloc_free(my_str);
			}
		}
	}
#endif

	p = strptime(date_str, "%b %e %Y %H:%M:%S %Z", tm);
	if (p && (*p == '\0')) {
		*date = fr_unix_time_from_tm(tm);
		return 0;
	}

	strlcpy(buf, date_str, sizeof(buf));

	p = buf;
	f[0] = mystrtok(&p, " \t");
	f[1] = mystrtok(&p, " \t");
	f[2] = mystrtok(&p, " \t");
	f[3] = mystrtok(&p, " \t"); /* may, or may not, be present */
	if (!f[0] || !f[1] || !f[2]) {
		fr_strerror_const("Too few fields");
		return -1;
	}

	/*
	 *	Try to parse the time zone.  If it's GMT / UTC or a
	 *	local time zone we're OK.
	 *
	 *	Otherwise, ignore errors and assume GMT.
	 */
	if (*p != '\0') {
		fr_skip_whitespace(p);
		(void) fr_time_delta_from_time_zone(p, &gmt_delta);
	}

	/*
	 *	The time has a colon, where nothing else does.
	 *	So if we find it, bubble it to the back of the list.
	 */
	if (f[3]) {
		for (i = 0; i < 3; i++) {
			if (strchr(f[i], ':')) {
				p = f[3];
				f[3] = f[i];
				f[i] = p;
				break;
			}
		}
	}

	/*
	 *  The month is text, which allows us to find it easily.
	 */
	tm->tm_mon = 12;
	for (i = 0; i < 3; i++) {
		if (isalpha((uint8_t) *f[i])) {
			int j;

			/*
			 *  Bubble the month to the front of the list
			 */
			p = f[0];
			f[0] = f[i];
			f[i] = p;

			for (j = 0; j < 12; j++) {
				if (strncasecmp(months[j], f[0], 3) == 0) {
					tm->tm_mon = j;
					break;
				}
			}
		}
	}

	/* month not found? */
	if (tm->tm_mon == 12) {
		fr_strerror_const("No month found");
		return -1;
	}

	/*
	 *	Check for invalid text, or invalid trailing text.
	 */
	l = strtoul(f[1], &tail, 10);
	if ((l == ULONG_MAX) || (*tail != '\0')) {
		fr_strerror_const("Invalid year string");
		return -1;
	}
	tm->tm_year = l;

	l = strtoul(f[2], &tail, 10);
	if ((l == ULONG_MAX) || (*tail != '\0')) {
		fr_strerror_const("Invalid day of month string");
		return -1;
	}
	tm->tm_mday = l;

	if (tm->tm_year >= 1900) {
		tm->tm_year -= 1900;

	} else {
		/*
		 *  We can't use 2-digit years any more, they make it
		 *  impossible to tell what's the day, and what's the year.
		 */
		if (tm->tm_mday < 1900) {
			fr_strerror_const("Invalid year < 1900");
			return -1;
		}

		/*
		 *  Swap the year and the day.
		 */
		i = tm->tm_year;
		tm->tm_year = tm->tm_mday - 1900;
		tm->tm_mday = i;
	}

	if (tm->tm_year > 10000) {
		fr_strerror_const("Invalid value for year");
		return -1;
	}

	/*
	 *	If the day is out of range, die.
	 */
	if ((tm->tm_mday < 1) || (tm->tm_mday > 31)) {
		fr_strerror_const("Invalid value for day of month");
		return -1;
	}

	/*
	 *	There may be %H:%M:%S.  Parse it in a hacky way.
	 */
	if (f[3]) {
		f[0] = f[3];	/* HH */
		f[1] = strchr(f[0], ':'); /* find : separator */
		if (!f[1]) {
			fr_strerror_const("No ':' after hour");
			return -1;
		}

		*(f[1]++) = '\0'; /* nuke it, and point to MM:SS */

		f[2] = strchr(f[1], ':'); /* find : separator */
		if (f[2]) {
			*(f[2]++) = '\0';	/* nuke it, and point to SS */
			tm->tm_sec = atoi(f[2]);
		}			/* else leave it as zero */

		tm->tm_hour = atoi(f[0]);
		tm->tm_min = atoi(f[1]);
	}

	*date = fr_unix_time_add(fr_unix_time_from_tm(tm), gmt_delta);

	return 0;
}

/** Convert unix time to string
 *
 * @param[out] out	Where to write the string.
 * @param[in] time	to convert.
 * @param[in] res	What base resolution to print the time as.
 * @param[in] utc	If true, use UTC, otherwise local time.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
fr_slen_t fr_unix_time_to_str(fr_sbuff_t *out, fr_unix_time_t time, fr_time_res_t res, bool utc)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);
	int64_t 	subseconds;
	time_t		t;
	struct tm	s_tm;
	size_t		len;
	char		buf[128];

	t = fr_unix_time_to_sec(time);
	if (utc) {
		(void) gmtime_r(&t, &s_tm);
	} else {
		(void) localtime_r(&t, &s_tm);
	}

	len = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &s_tm);
	FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, buf, len);
	subseconds = fr_unix_time_unwrap(time) % NSEC;

	/*
	 *	Use RFC 3339 format, which is a
	 *	profile of ISO8601.  The ISO standard
	 *	allows a much more complex set of date
	 *	formats.  The RFC is much stricter.
	 */
	switch (res) {
	case FR_TIME_RES_INVALID:
	case FR_TIME_RES_YEAR:
	case FR_TIME_RES_MONTH:
	case FR_TIME_RES_WEEK:
	case FR_TIME_RES_DAY:
	case FR_TIME_RES_HOUR:
	case FR_TIME_RES_MIN:
	case FR_TIME_RES_SEC:
		break;

	case FR_TIME_RES_CSEC:
		subseconds /= (NSEC / CSEC);
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%02" PRIi64, subseconds);
		break;

	case FR_TIME_RES_MSEC:
		subseconds /= (NSEC / MSEC);
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%03" PRIi64, subseconds);
		break;

	case FR_TIME_RES_USEC:
		subseconds /= (NSEC / USEC);
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%06" PRIi64, subseconds);
		break;

	case FR_TIME_RES_NSEC:
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, ".%09" PRIi64, subseconds);
		break;
	}

	/*
	 *	And time zone.
	 */
	if (s_tm.tm_gmtoff != 0) {
		int hours, minutes;

		hours = s_tm.tm_gmtoff / 3600;
		minutes = (s_tm.tm_gmtoff / 60) % 60;

		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%+03d:%02u", hours, minutes);
	} else {
		FR_SBUFF_IN_CHAR_RETURN(&our_out, 'Z');
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Get the offset to gmt.
 *
 */
fr_time_delta_t fr_time_gmtoff(void)
{
	return fr_time_delta_wrap(gmtoff[isdst]);
}

/** Whether or not we're daylight savings.
 *
 */
bool fr_time_is_dst(void)
{
	return isdst;
}
