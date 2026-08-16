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

TEST_LIST = {
	{ "time_const_benchmark",		time_benchmark },
	{ "time_delta_to_str_int64_min",	time_delta_to_str_int64_min },

	{ 0 }
};
