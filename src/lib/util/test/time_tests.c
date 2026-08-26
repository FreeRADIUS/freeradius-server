/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tests for a generic string buffer structure for string printing and parsing
 *
 * @file src/lib/util/test//time_tests.c
 *
 * @copyright 2022 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include "acutest.h"
#include"acutest_helpers.h"
#include <freeradius-devel/util/time.h>

#define ROUNDS (100000)

DIAG_OFF(unused-but-set-variable)
static void time_benchmark(void)
{
	int		i;
	fr_time_t	start, stop;
	uint64_t	rate;

	start = fr_time();
	for (i = 0; i < ROUNDS; i++) {
		volatile fr_time_t now;

		now = fr_time();
	}
	stop = fr_time();

	rate = (uint64_t)((float)NSEC / (fr_time_delta_unwrap(fr_time_sub(stop, start)) / ROUNDS));
	printf("fr_time rate %" PRIu64 "\n", rate);

	/* shared runners are terrible for performance tests */
	if (!getenv("NO_PERFORMANCE_TESTS")) TEST_CHECK(rate > (ROUNDS * 10));
}
DIAG_ON(unused-but-set-variable)

/** Format the most negative delta possible
 *
 *	fr_time_delta_to_str() takes the magnitude of the delta with a MOD()
 *	macro.  INT64_MIN is the awkward case: negating it in a signed type is
 *	undefined (its positive counterpart, 2^63, isn't representable in
 *	int64_t), so the magnitude has to be taken in the unsigned domain.
 *	This checks the boundary formats correctly rather than tripping UBSan.
 */
static void time_delta_to_str_int64_min(void)
{
	char		buf[64];
	fr_sbuff_t	sbuff;
	fr_slen_t	slen;
	fr_time_delta_t	delta = fr_time_delta_wrap(INT64_MIN);

	TEST_CASE("signed INT64_MIN, seconds resolution");
	sbuff = FR_SBUFF_OUT(buf, sizeof(buf));
	slen = fr_time_delta_to_str(&sbuff, delta, FR_TIME_RES_SEC, false);
	TEST_CHECK(slen > 0);
	TEST_MSG("slen %zd", slen);
	TEST_CHECK(strcmp(buf, "-9223372036.854775808") == 0);
	TEST_MSG("got \"%s\"", buf);

	TEST_CASE("unsigned INT64_MIN clamps to zero");
	sbuff = FR_SBUFF_OUT(buf, sizeof(buf));
	slen = fr_time_delta_to_str(&sbuff, delta, FR_TIME_RES_SEC, true);
	TEST_CHECK(slen > 0);
	TEST_MSG("slen %zd", slen);
	TEST_CHECK(strcmp(buf, "0") == 0);
	TEST_MSG("got \"%s\"", buf);
}

/*
 *	Helpers for fr_time_delta_from_str().
 */
static void check_delta_from_str(char const *in, fr_time_res_t hint, int64_t expected)
{
	fr_time_delta_t	delta = fr_time_delta_wrap(0);
	fr_slen_t	slen;

	slen = fr_time_delta_from_str(&delta, in, strlen(in), hint);
	TEST_CHECK(slen > 0);
	TEST_MSG("\"%s\": slen %zd", in, (ssize_t)slen);
	TEST_CHECK(fr_time_delta_unwrap(delta) == expected);
	TEST_MSG("\"%s\": got %" PRIi64 ", expected %" PRIi64,
		 in, fr_time_delta_unwrap(delta), expected);
}

static void check_delta_from_str_fail(char const *in, fr_time_res_t hint)
{
	fr_time_delta_t	delta = fr_time_delta_wrap(0);
	fr_slen_t	slen;

	slen = fr_time_delta_from_str(&delta, in, strlen(in), hint);
	TEST_CHECK(slen < 0);
	TEST_MSG("\"%s\": expected failure, got %" PRIi64, in, fr_time_delta_unwrap(delta));
}

/** Parse time deltas from strings: integers, floats, scale suffixes, timestamps and errors. */
static void time_delta_from_str(void)
{
	TEST_CASE("plain integers with a resolution hint");
	check_delta_from_str("0", FR_TIME_RES_SEC, 0);
	check_delta_from_str("1", FR_TIME_RES_SEC, (int64_t)NSEC);
	check_delta_from_str("-2", FR_TIME_RES_SEC, -2 * (int64_t)NSEC);

	TEST_CASE("explicit scale suffixes override the hint");
	check_delta_from_str("1s", FR_TIME_RES_SEC, (int64_t)NSEC);
	check_delta_from_str("500ms", FR_TIME_RES_SEC, 500 * (NSEC / MSEC));
	check_delta_from_str("250us", FR_TIME_RES_SEC, 250 * (NSEC / USEC));
	check_delta_from_str("7ns", FR_TIME_RES_SEC, 7);

	TEST_CASE("floating point is pre-scaled to nanoseconds");
	check_delta_from_str("1.5", FR_TIME_RES_SEC, 1500 * (NSEC / MSEC));
	check_delta_from_str(".5", FR_TIME_RES_SEC, 500 * (NSEC / MSEC));

	TEST_CASE("[hours:]minutes:seconds timestamps");
	check_delta_from_str("1:30", FR_TIME_RES_SEC, 90 * (int64_t)NSEC);
	check_delta_from_str("01:02:03", FR_TIME_RES_SEC, 3723 * (int64_t)NSEC);

	/*
	 *	A leading '-' negates the whole timestamp.  The first number
	 *	carries the sign (integer == -1 for "-1:30"), the mm:ss / hh:mm:ss
	 *	branches take its magnitude for the component, and the assembled
	 *	total is negated once at the end.
	 */
	TEST_CASE("negative [hours:]minutes:seconds timestamps");
	check_delta_from_str("-1:30", FR_TIME_RES_SEC, -90 * (int64_t)NSEC);
	check_delta_from_str("-0:30", FR_TIME_RES_SEC, -30 * (int64_t)NSEC);	/* negative, zero minutes */
	check_delta_from_str("-1:02:03", FR_TIME_RES_SEC, -3723 * (int64_t)NSEC);

	/*
	 *	The do_timestamp range guard caps the first (hours) component at
	 *	the int16_t bounds.  The negative boundary (INT16_MIN) exercises
	 *	the "negative ? -integer : integer" magnitude step, which must
	 *	not trip signed-negation UB.
	 */
	TEST_CASE("hours component at the int16_t guard boundary");
	check_delta_from_str("32767:00:00", FR_TIME_RES_SEC, (int64_t)32767 * 3600 * NSEC);	/* INT16_MAX */
	check_delta_from_str("-32768:00:00", FR_TIME_RES_SEC, (int64_t)-32768 * 3600 * NSEC);	/* INT16_MIN */
	check_delta_from_str_fail("32768:00:00", FR_TIME_RES_SEC);				/* > INT16_MAX */
	check_delta_from_str_fail("-32769:00:00", FR_TIME_RES_SEC);				/* < INT16_MIN */

	TEST_CASE("invalid input is rejected");
	check_delta_from_str_fail("", FR_TIME_RES_SEC);
	check_delta_from_str_fail("abc", FR_TIME_RES_SEC);
	check_delta_from_str_fail("1abc", FR_TIME_RES_SEC);
	check_delta_from_str_fail("99:30", FR_TIME_RES_SEC);		/* minutes >= 60 (mm:ss) */
	check_delta_from_str_fail("1:99", FR_TIME_RES_SEC);		/* seconds >= 60 (mm:ss) */
	check_delta_from_str_fail("01:02:99", FR_TIME_RES_SEC);		/* seconds >= 60 (hh:mm:ss) */
	check_delta_from_str_fail("-99:30", FR_TIME_RES_SEC);		/* minutes >= 60 (negative mm:ss) */
	check_delta_from_str_fail("-1:02:99", FR_TIME_RES_SEC);		/* seconds >= 60 (negative hh:mm:ss) */

	/*
	 *	Extreme first-component magnitudes must be rejected, and taking
	 *	their magnitude (the "negative ? -integer : integer" step) must
	 *	never overflow or, for INT64_MIN, trigger signed-negation UB.
	 *	These are the raw int64_t bounds fr_sbuff_out() can parse for the
	 *	first number.  They must always be rejected in do_timestamp,
	 *	regardless of the exact range-guard threshold.
	 */
	TEST_CASE("extreme first-component magnitudes are rejected");
	check_delta_from_str_fail("9223372036854775807:00", FR_TIME_RES_SEC);		/* INT64_MAX, mm:ss */
	check_delta_from_str_fail("-9223372036854775808:00", FR_TIME_RES_SEC);		/* INT64_MIN, mm:ss (would-be negation UB) */
	check_delta_from_str_fail("9223372036854775807:00:00", FR_TIME_RES_SEC);	/* INT64_MAX, hh:mm:ss */
	check_delta_from_str_fail("-9223372036854775808:00:00", FR_TIME_RES_SEC);	/* INT64_MIN, hh:mm:ss (would-be negation UB) */

	TEST_CASE("overflow is detected");
	check_delta_from_str_fail("10000000000s", FR_TIME_RES_SEC);	/* 1e10s * 1e9 > INT64_MAX */
}

/** Format time deltas to strings across sign, fraction and the unsigned flag. */
static void time_delta_to_str(void)
{
	char		buf[64] = "";
	fr_sbuff_t	sbuff;
	struct {
		int64_t		delta;		/* nanoseconds */
		fr_time_res_t	res;
		bool		is_unsigned;
		char const	*expected;
	} tests[] = {
		{ 5 * (int64_t)NSEC,	FR_TIME_RES_SEC,	false,	"5" },
		{ 1500 * (NSEC / MSEC),	FR_TIME_RES_SEC,	false,	"1.5" },
		{ -1 * (int64_t)NSEC,	FR_TIME_RES_SEC,	false,	"-1" },
		{ -100 * (NSEC / MSEC),	FR_TIME_RES_SEC,	false,	"-0.1" },	/* lhs == 0 but still negative */
		{ -5 * (int64_t)NSEC,	FR_TIME_RES_SEC,	true,	"0" },		/* unsigned clamps negatives */
	};

	for (size_t i = 0; i < NUM_ELEMENTS(tests); i++) {
		fr_slen_t slen;

		sbuff = FR_SBUFF_OUT(buf, sizeof(buf));
		slen = fr_time_delta_to_str(&sbuff, fr_time_delta_wrap(tests[i].delta),
					    tests[i].res, tests[i].is_unsigned);
		TEST_CHECK(slen > 0);
		TEST_CHECK(strcmp(buf, tests[i].expected) == 0);
		TEST_MSG("delta %" PRIi64 ": got \"%s\", expected \"%s\"",
			 tests[i].delta, buf, tests[i].expected);
	}
}

/** Test fr_time_scale: per-resolution multipliers, clamping and invalid hints. */
static void time_scale(void)
{
	TEST_CASE("each resolution scales to nanoseconds");
	TEST_CHECK(fr_time_scale(5, FR_TIME_RES_SEC) == 5 * (int64_t)NSEC);
	TEST_CHECK(fr_time_scale(5, FR_TIME_RES_MSEC) == 5 * (NSEC / MSEC));
	TEST_CHECK(fr_time_scale(5, FR_TIME_RES_USEC) == 5 * (NSEC / USEC));
	TEST_CHECK(fr_time_scale(5, FR_TIME_RES_NSEC) == 5);

	TEST_CASE("hints the function does not handle return 0");
	TEST_CHECK(fr_time_scale(5, FR_TIME_RES_MIN) == 0);
	TEST_CHECK(fr_time_scale(5, FR_TIME_RES_INVALID) == 0);

	TEST_CASE("overflow and underflow clamp");
	TEST_CHECK(fr_time_scale(INT64_MAX, FR_TIME_RES_SEC) == INT64_MAX);
	TEST_CHECK(fr_time_scale(INT64_MIN, FR_TIME_RES_SEC) == INT64_MIN);
	TEST_CHECK(fr_time_scale(0, FR_TIME_RES_SEC) == 0);
}

/** Test fr_unix_time_from_tm against well-known UTC epochs. */
static void unix_time_from_tm(void)
{
	struct tm	tm;

	TEST_CASE("the unix epoch");
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = 1970 - 1900;
	tm.tm_mon = 0;
	tm.tm_mday = 1;
	TEST_CHECK(fr_unix_time_unwrap(fr_unix_time_from_tm(&tm)) == 0);

	TEST_CASE("2000-01-01T00:00:00Z == 946684800");
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = 2000 - 1900;
	tm.tm_mon = 0;
	tm.tm_mday = 1;
	TEST_CHECK(fr_unix_time_unwrap(fr_unix_time_from_tm(&tm)) == (int64_t)946684800 * NSEC);

	TEST_CASE("the Y2038 boundary, 2038-01-19T03:14:07Z == INT32_MAX");
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = 2038 - 1900;
	tm.tm_mon = 0;
	tm.tm_mday = 19;
	tm.tm_hour = 3;
	tm.tm_min = 14;
	tm.tm_sec = 7;
	TEST_CHECK(fr_unix_time_unwrap(fr_unix_time_from_tm(&tm)) == (int64_t)2147483647 * NSEC);

	TEST_CASE("a positive gmtoff is removed to give UTC");
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = 2000 - 1900;
	tm.tm_mon = 0;
	tm.tm_mday = 1;
	tm.tm_gmtoff = 3600;					/* one hour east of UTC */
	TEST_CHECK(fr_unix_time_unwrap(fr_unix_time_from_tm(&tm)) == ((int64_t)946684800 - 3600) * NSEC);
}

/** Round-trip fr_unix_time_from_str() and fr_unix_time_to_str() in UTC. */
static void unix_time_str(void)
{
	fr_unix_time_t	t;
	char		buf[128];
	fr_sbuff_t	sbuff;

	TEST_CASE("a bare unix timestamp scales by the hint");
	TEST_CHECK(fr_unix_time_from_str(&t, "946684800", FR_TIME_RES_SEC) == 0);
	TEST_CHECK(fr_unix_time_unwrap(t) == (int64_t)946684800 * NSEC);

	TEST_CASE("RFC 3339 in UTC round-trips");
	TEST_CHECK(fr_unix_time_from_str(&t, "2000-01-01T00:00:00Z", FR_TIME_RES_SEC) == 0);
	TEST_CHECK(fr_unix_time_unwrap(t) == (int64_t)946684800 * NSEC);
	sbuff = FR_SBUFF_OUT(buf, sizeof(buf));
	TEST_CHECK(fr_unix_time_to_str(&sbuff, t, FR_TIME_RES_SEC, true) > 0);
	TEST_CHECK(strcmp(buf, "2000-01-01T00:00:00Z") == 0);
	TEST_MSG("got \"%s\"", buf);

	TEST_CASE("RFC 3339 numeric timezone offsets are removed to give UTC");
	TEST_CHECK(fr_unix_time_from_str(&t, "2000-01-01T00:00:00+01:00", FR_TIME_RES_SEC) == 0);
	TEST_CHECK(fr_unix_time_unwrap(t) == ((int64_t)946684800 - 3600) * NSEC);	/* +01:00 is one hour ahead of UTC */
	TEST_CHECK(fr_unix_time_from_str(&t, "2000-01-01T00:00:00-01:00", FR_TIME_RES_SEC) == 0);
	TEST_CHECK(fr_unix_time_unwrap(t) == ((int64_t)946684800 + 3600) * NSEC);	/* -01:00 is one hour behind UTC */

	TEST_CASE("sub-second parsing and millisecond formatting");
	TEST_CHECK(fr_unix_time_from_str(&t, "2000-01-01T00:00:00.5Z", FR_TIME_RES_SEC) == 0);
	TEST_CHECK(fr_unix_time_unwrap(t) == ((int64_t)946684800 * NSEC) + (NSEC / 2));
	sbuff = FR_SBUFF_OUT(buf, sizeof(buf));
	TEST_CHECK(fr_unix_time_to_str(&sbuff, t, FR_TIME_RES_MSEC, true) > 0);
	TEST_CHECK(strcmp(buf, "2000-01-01T00:00:00.500Z") == 0);
	TEST_MSG("got \"%s\"", buf);

	TEST_CASE("malformed input is rejected");
	TEST_CHECK(fr_unix_time_from_str(&t, "", FR_TIME_RES_SEC) < 0);
	TEST_CHECK(fr_unix_time_from_str(&t, "2000-13-01T00:00:00Z", FR_TIME_RES_SEC) < 0);	/* month 13 */
}

/** Test fr_time_elapsed_update sorts delays into the correct histogram bins. */
static void time_elapsed_update(void)
{
	fr_time_elapsed_t	elapsed;
	static int64_t const	delays[8] = {
		500,		/* < 1us   -> [0] */
		5000,		/* < 10us  -> [1] */
		50000,		/* < 100us -> [2] */
		500000,		/* < 1ms   -> [3] */
		5000000,	/* < 10ms  -> [4] */
		50000000,	/* < 100ms -> [5] */
		500000000,	/* < 1s    -> [6] */
		5000000000	/* >= 1s   -> [7] */
	};

	memset(&elapsed, 0, sizeof(elapsed));

	TEST_CASE("one delay lands in each bin");
	for (int i = 0; i < 8; i++) {
		fr_time_elapsed_update(&elapsed, fr_time_wrap(0), fr_time_wrap(delays[i]));
	}
	for (int i = 0; i < 8; i++) {
		TEST_CHECK(elapsed.array[i] == 1);
		TEST_MSG("bin %d: got %" PRIu64, i, elapsed.array[i]);
	}

	TEST_CASE("start >= end is treated as a zero delay");
	fr_time_elapsed_update(&elapsed, fr_time_wrap(10), fr_time_wrap(5));
	TEST_CHECK(elapsed.array[0] == 2);
	TEST_MSG("bin 0: got %" PRIu64, elapsed.array[0]);
}

TEST_LIST = {
	{ "time_const_benchmark",		time_benchmark },
	{ "time_delta_to_str_int64_min",	time_delta_to_str_int64_min },
	{ "time_delta_from_str",		time_delta_from_str },
	{ "time_delta_to_str",			time_delta_to_str },
	{ "time_scale",				time_scale },
	{ "unix_time_from_tm",			unix_time_from_tm },
	{ "unix_time_str",			unix_time_str },
	{ "time_elapsed_update",		time_elapsed_update },

	{ 0 }
};
