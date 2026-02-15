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

/** Tests for the retransmission timer
 *
 * @file src/lib/util/test/retry_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/retry.h>

/*
 *	Test basic initialization.
 */
static void test_retry_init(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_sec(1),
		.mrt = fr_time_delta_from_sec(30),
		.mrd = fr_time_delta_from_sec(60),
		.mrc = 10,
	};
	fr_time_t now = fr_time_wrap(1000000000);

	fr_retry_init(&r, now, &config);

	TEST_CASE("Initial state is CONTINUE");
	TEST_CHECK(r.state == FR_RETRY_CONTINUE);

	TEST_CASE("Count starts at 1");
	TEST_CHECK(r.count == 1);

	TEST_CASE("Start is set to now");
	TEST_CHECK(fr_time_eq(r.start, now));

	TEST_CASE("Next retransmission is after start");
	TEST_CHECK(fr_time_gt(r.next, now));

	TEST_CASE("End is set to start + MRD");
	TEST_CHECK(fr_time_eq(r.end, fr_time_add(now, config.mrd)));
}

/*
 *	RT = IRT + RAND*IRT
 */
static void test_retry_irt(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_msec(100),
		.mrt = fr_time_delta_from_sec(100), /* effectively no limit */
		.mrd = fr_time_delta_from_sec(0),
		.mrc = 0,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_time_delta_t		rt_12;
	fr_time_delta_t		rt_08;

	fr_retry_init(&r, now, &config);

	rt_12 = fr_time_delta_wrap((fr_time_delta_unwrap(config.irt) * 12) / 10);
	rt_08 = fr_time_delta_wrap((fr_time_delta_unwrap(config.irt) * 8) / 10);

	TEST_CASE("Initial bounds for RT = IRT * (1 + RAND[-0.1,+0.1])");
	TEST_CHECK(fr_time_delta_lt(r.rt, rt_12));
	TEST_MSG("rt should be < IRT * 1.2  (i.e. %" PRIi64 ") < (%" PRIi64 ", for IRT %" PRIi64 ")",
		 fr_time_delta_unwrap(r.rt), fr_time_delta_unwrap(rt_12), fr_time_delta_unwrap(config.irt));
	
	TEST_CHECK(fr_time_delta_gt(r.rt, rt_08));
	TEST_MSG("rt should be > IRT * 0.8  (i.e. %" PRIi64 ") > (%" PRIi64 ", for RTprev %" PRIi64 ")",
		 fr_time_delta_unwrap(r.rt), fr_time_delta_unwrap(rt_08), fr_time_delta_unwrap(config.irt));
}

/*
 *	Test RT = RTprev * (2 + RAND[-0.1,+0.1])
 *
 *	We don't set MRC or MRD here.
 */
static void test_retry_rt(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_msec(100),
		.mrt = fr_time_delta_from_sec(100), /* effectively no limit */
		.mrd = fr_time_delta_from_sec(0),
		.mrc = 0,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_time_delta_t		rt_prev = fr_time_delta_wrap(0);
	fr_retry_state_t	state;
	int			i;

	fr_retry_init(&r, now, &config);

	/*
	 *	1.1+2.2x^4 =~ 25, which is smaller than MRT=100.
	 */
	for (i = 0; i < 4; i++) {
		now = r.next;
		state = fr_retry_next(&r, now);
		TEST_CHECK(state == FR_RETRY_CONTINUE);
		TEST_MSG("retry %d should be CONTINUE, got %d", i + 2, state);

		/*
		 *	For zero, RT = IRT + RAND*IRT
		 */
		if (i > 0) {
			fr_time_delta_t rt_220 = fr_time_delta_wrap(
				(fr_time_delta_unwrap(rt_prev) * 22) / 10
				);
			fr_time_delta_t rt_180 = fr_time_delta_wrap(
				(fr_time_delta_unwrap(rt_prev) * 18) / 10
				);

			TEST_CASE("Retry interval bounds RT = RTprev * (2 + RAND[-0.1,+0.1])");
			TEST_CHECK(fr_time_delta_lt(r.rt, rt_220));
			TEST_MSG("rt should be < RT_prev * 2.2  (i.e. %" PRIi64 ") < (%" PRIi64 ", for RTprev %" PRIi64 ")",
				 fr_time_delta_unwrap(r.rt), fr_time_delta_unwrap(rt_220), fr_time_delta_unwrap(rt_prev));

			TEST_CHECK(fr_time_delta_gt(r.rt, rt_180));
			TEST_MSG("rt should be > RT * 1.8  (i.e. %" PRIi64 ") > (%" PRIi64 ", for RTprev %" PRIi64 ")",
				 fr_time_delta_unwrap(r.rt), fr_time_delta_unwrap(rt_180), fr_time_delta_unwrap(rt_prev));
		}

		rt_prev = r.rt;
	}
}

/*
 *	Test that MRC (max retransmission count) is respected.
 */
static void test_retry_mrc(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_msec(100),
		.mrt = fr_time_delta_from_sec(5),
		.mrd = fr_time_delta_from_sec(300),
		.mrc = 3,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_retry_state_t	state;
	int			i;

	fr_retry_init(&r, now, &config);

	/*
	 *	We should get CONTINUE for retransmissions 1 and 2,
	 *	then MRC on the 3th (count > mrc).
	 */
	for (i = 0; i < 2; i++) {
		now = r.next;
		state = fr_retry_next(&r, now);
		TEST_CHECK(state == FR_RETRY_CONTINUE);
		TEST_MSG("retry %d should be CONTINUE, got %d", i + 2, state);

	}

	now = r.next;
	state = fr_retry_next(&r, now);
	TEST_CHECK(state == FR_RETRY_MRC);
	TEST_MSG("retry 3 should be MRC, got %d", state);

	TEST_CHECK(r.state == FR_RETRY_MRC);
}

/*
 *	Test that MRD (max retransmission duration) is respected.
 */
static void test_retry_mrd(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_msec(500),
		.mrt = fr_time_delta_from_sec(2),
		.mrd = fr_time_delta_from_sec(3),
		.mrc = 0,				/* no count limit */
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_retry_state_t	state;
	int			attempts = 0;

	fr_retry_init(&r, now, &config);

	/*
	 *	Keep retrying until we hit MRD.
	 *	With no MRC, we should hit MRD.
	 */
	for (;;) {
		now = r.next;
		state = fr_retry_next(&r, now);
		attempts++;

		if (state != FR_RETRY_CONTINUE) break;

		/*
		 *	Safety valve: shouldn't take more than 10 attempts
		 *	for a 3-second MRD with 500ms IRT.
		 */
		TEST_CHECK(attempts < 10);
		if (attempts >= 10) break;
	}

	TEST_CHECK(state == FR_RETRY_MRD);
	TEST_MSG("expected MRD, got %d after %d attempts", state, attempts);
	TEST_CHECK(r.state == FR_RETRY_MRD);
}

/*
 *	Test single retry (MRC=1) which is just a simple duration timer.
 */
static void test_retry_single(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_sec(0),
		.mrt = fr_time_delta_from_sec(0),
		.mrd = fr_time_delta_from_sec(5),
		.mrc = 1,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_retry_state_t	state;

	fr_retry_init(&r, now, &config);

	TEST_CASE("MRC=1 sets next to end");
	TEST_CHECK(fr_time_eq(r.next, r.end));

	TEST_CASE("First retry exceeds count, returns MRD");
	now = r.next;
	state = fr_retry_next(&r, now);
	TEST_CHECK(state == FR_RETRY_MRD);
}

/*
 *	Test exponential backoff behavior.
 */
static void test_retry_backoff(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_msec(100),
		.mrt = fr_time_delta_from_sec(60),
		.mrd = fr_time_delta_from_sec(600),
		.mrc = 20,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_time_delta_t		prev_rt;
	int			i;
	int			grew = 0;

	fr_retry_init(&r, now, &config);
	prev_rt = r.rt;

	/*
	 *	The retry interval should generally grow (with some randomness).
	 *	Check that it grows in at least half the cases over several iterations.
	 */
	for (i = 0; i < 8; i++) {
		now = r.next;
		fr_retry_next(&r, now);

		if (fr_time_delta_gt(r.rt, prev_rt)) grew++;
		prev_rt = r.rt;
	}

	TEST_CASE("Retry interval grows over time (exponential backoff)");
	TEST_CHECK(grew >= 2);
	TEST_MSG("expected interval to grow at least 2 times, grew %d times", grew);
}

/*
 *	Test MRT capping.
 */
static void test_retry_mrt_cap(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_sec(1),
		.mrt = fr_time_delta_from_sec(4),
		.mrd = fr_time_delta_from_sec(600),
		.mrc = 100,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	int			i;

	fr_retry_init(&r, now, &config);

	/*
	 *	After enough doublings, the interval should be capped near MRT.
	 *	With IRT=1s and doubling, after ~3 iterations we'd exceed MRT=4s.
	 *	Allow some randomness headroom: check rt <= MRT * 1.2.
	 */
	for (i = 0; i < 10; i++) {
		now = r.next;
		if (fr_retry_next(&r, now) != FR_RETRY_CONTINUE) break;
	}

	TEST_CASE("Retry interval bounds RT <= MRT * (1 + RAND[-0.1,+0.1])");
	{
		fr_time_delta_t mrt_120 = fr_time_delta_wrap(
			(fr_time_delta_unwrap(config.mrt) * 12) / 10
		);
		fr_time_delta_t mrt_08 = fr_time_delta_wrap(
			(fr_time_delta_unwrap(config.mrt) * 8) / 10
		);
		TEST_CHECK(fr_time_delta_lt(r.rt, mrt_120));
		TEST_MSG("rt should be < MRT * 1.2  (i.e. %" PRIi64 ") < (%" PRIi64 ", for MRT %" PRIi64 ")",
			 fr_time_delta_unwrap(r.rt), fr_time_delta_unwrap(mrt_120), fr_time_delta_unwrap(config.mrt));

		TEST_CHECK(fr_time_delta_gt(r.rt, mrt_08));
		TEST_MSG("rt should be > MRT * 0.8  (i.e. %" PRIi64 ") > (%" PRIi64 ", for MRT %" PRIi64 ")",
			 fr_time_delta_unwrap(r.rt), fr_time_delta_unwrap(mrt_08), fr_time_delta_unwrap(config.mrt));
	}
}

/*
 *	Test with no MRD and no MRC (defaults to 1-day MRD).
 */
static void test_retry_no_limits(void)
{
	fr_retry_t		r;
	fr_retry_config_t	config = {
		.irt = fr_time_delta_from_sec(1),
		.mrt = fr_time_delta_from_sec(30),
		.mrd = fr_time_delta_from_sec(0),
		.mrc = 0,
	};
	fr_time_t		now = fr_time_wrap(1000000000);
	fr_time_t		expected_end = fr_time_add(now, fr_time_delta_from_sec(86400));

	fr_retry_init(&r, now, &config);

	TEST_CASE("With no MRD/MRC, end defaults to start + 1 day");
	TEST_CHECK(fr_time_eq(r.end, expected_end));

	TEST_CASE("Retransmissions continue normally");
	now = r.next;
	TEST_CHECK(fr_retry_next(&r, now) == FR_RETRY_CONTINUE);
}

TEST_LIST = {
	{ "retry_init",			test_retry_init },
	{ "retry_irt",			test_retry_irt },
	{ "retry_rt",			test_retry_rt },
	{ "retry_mrc",			test_retry_mrc },
	{ "retry_mrd",			test_retry_mrd },
	{ "retry_single",		test_retry_single },
	{ "retry_backoff",		test_retry_backoff },
	{ "retry_mrt_cap",		test_retry_mrt_cap },
	{ "retry_no_limits",		test_retry_no_limits },
	TEST_TERMINATOR
};
