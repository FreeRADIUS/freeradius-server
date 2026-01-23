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

TEST_LIST = {
	{ "time_const_benchmark",		time_benchmark },

	{ 0 }
};
