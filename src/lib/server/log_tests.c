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

/** Tests for the rate limited logging macros
 *
 * @file src/lib/server/log_tests.c
 *
 * @copyright 2026 Network RADIUS SAS ("legal@networkradius.com")
 */
#include <freeradius-devel/util/test/acutest.h>
#include <freeradius-devel/util/test/acutest_helpers.h>

#include <freeradius-devel/server/log.h>

/*
 *	The logging macro under test.  Each call records the formatted
 *	message, and counts the call.  RATE_LIMIT_LOCAL() wraps the macro
 *	in parentheses, which requires an expression.
 */
static char	captured[256];
static int	logged;

#define CAPTURE_LOG(_fmt, ...) \
	((void) snprintf(captured, sizeof(captured), _fmt, ## __VA_ARGS__), logged++)

static void capture_reset(void)
{
	captured[0] = '\0';
	logged = 0;
	fr_log_rate_limit = true;
}

/** The first message from a fresh entry is logged, even in the first second of the process
 *
 *  fr_time() counts from fr_time_start().  A fresh entry has last_complained of zero, which
 *  is second 0, and a message in second 0 of the process compared equal to it and was
 *  counted as a repeat instead of being logged.
 */
static void test_first_message_logged(void)
{
	fr_rate_limit_t entry = {};

	capture_reset();
	TEST_ASSERT(fr_time_start() == 0);	/* Places fr_time() in second 0 */

	RATE_LIMIT_LOCAL(&entry, CAPTURE_LOG, "first %d", 1);
	TEST_CHECK(logged == 1);
	TEST_MSG("logged %d, expected 1", logged);
	TEST_CHECK(strcmp(captured, "first 1") == 0);
	TEST_MSG("captured \"%s\"", captured);
}

/** A second message in the same second is counted, not logged
 */
static void test_repeat_suppressed(void)
{
	fr_rate_limit_t entry = {};

	capture_reset();
	RATE_LIMIT_LOCAL(&entry, CAPTURE_LOG, "message");
	RATE_LIMIT_LOCAL(&entry, CAPTURE_LOG, "message");
	TEST_CHECK(logged == 1);
	TEST_MSG("logged %d, expected 1", logged);
	TEST_CHECK(entry.repeated == 1);
	TEST_MSG("repeated %u, expected 1", entry.repeated);
}

/** A message one second after the last one reports the repeats suppressed in between
 *
 *  The macro set last_complained to now before computing the time since the last
 *  complaint, which was then always zero, and the suffix never appeared.
 */
static void test_repeat_count_reported(void)
{
	fr_rate_limit_t entry = {};

	capture_reset();
	entry.last_complained = fr_time_sub(fr_time(), fr_time_delta_from_sec(1));
	entry.repeated = 3;

	RATE_LIMIT_LOCAL(&entry, CAPTURE_LOG, "message");
	TEST_CHECK(logged == 1);
	TEST_CHECK(strcmp(captured, "message - repeated 3 time(s)") == 0);
	TEST_MSG("captured \"%s\"", captured);
	TEST_CHECK(entry.repeated == 0);
}

TEST_LIST = {
	{ "first_message_logged",	test_first_message_logged },
	{ "repeat_suppressed",		test_repeat_suppressed },
	{ "repeat_count_reported",	test_repeat_count_reported },
	TEST_TERMINATOR
};
