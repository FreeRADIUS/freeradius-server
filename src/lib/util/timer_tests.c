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

/** Tests for timer lists
 *
 * @file src/lib/util/timer_tests.c
 *
 * @copyright 2025 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/timer.h>

/** Defines an artificial time source for a test
 *
 * Defines _name + _time() and _name + _set() functions.
 */
#define TIME_SOURCE(_name) \
	static fr_time_t _name##_timer = fr_time_wrap(0); \
	static fr_time_t _name##_time(void) \
	{ \
		return _name##_timer; \
	} \
	static void _name##_set(fr_time_t t) \
	{ \
		_name##_timer = t; \
	}

TIME_SOURCE(basic)

/** Verifies time passed in is not 0, that tl is not NULL, and writes true to uctx (must be a bool)
 *
 */
static void timer_cb(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	bool *fired = (bool *)uctx;

	TEST_CHECK(tl != NULL);
	TEST_CHECK(fr_time_gt(now, fr_time_wrap(0)));

	*fired = true;
}

static void basic_timer_list_tests(fr_timer_list_t *tl)
{
	fr_time_t now;
	fr_timer_t *event1 = NULL, *event1a = NULL, *event2 = NULL, *event3 = NULL, *event4 = NULL;
	bool event1_fired = false, event1a_fired = false, event2_fired = false, event3_fired = false, event4_fired = false;
	int ret;

	/*
	 *	Should fire together
	 */
	ret = fr_timer_in(NULL, tl, &event1, fr_time_delta_from_sec(1), true, timer_cb, &event1_fired);
	TEST_CHECK(ret == 0);

	ret = fr_timer_in(NULL, tl, &event1a, fr_time_delta_from_sec(1), true, timer_cb, &event1a_fired);
	TEST_CHECK(ret == 0);

	ret = fr_timer_in(NULL, tl, &event2, fr_time_delta_from_sec(2), true, timer_cb, &event2_fired);
	TEST_CHECK(ret == 0);

	ret = fr_timer_in(NULL, tl, &event3, fr_time_delta_from_sec(3), true, timer_cb, &event3_fired);
	TEST_CHECK(ret == 0);

	/*
	 *	Will be disarmed before it fires
	 */
	ret = fr_timer_in(NULL, tl, &event4, fr_time_delta_from_sec(3), true, timer_cb, &event4_fired);
	TEST_CHECK(ret == 0);

	/*
	 *	No events should have fired yet
	 */
	TEST_CHECK(fr_timer_list_run(tl, &fr_time_wrap(0)) == 0);

	now = fr_time_from_sec(1);

	/*
	 *	First batch of events
	 */
	TEST_CHECK(fr_timer_list_run(tl, &now) == 2);
	TEST_CHECK(event1_fired == true);
	TEST_CHECK(event1a_fired == true);
	TEST_CHECK(event2_fired == false);

	/*
	 *	Now disarm event 4, so it doesn't fire
	 */
	TEST_CHECK(fr_timer_disarm(event4) == 0);

	now = fr_time_from_sec(2);
}

static void lst_basic_test(void)
{
	fr_timer_list_t *tl;

	tl = fr_timer_list_lst_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);

	fr_timer_list_set_time_func(tl, basic_time);

	basic_timer_list_tests(tl);
}

static void ordered_basic_test(void)
{
	fr_timer_list_t *tl;

	tl = fr_timer_list_ordered_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);

	fr_timer_list_set_time_func(tl, basic_time);

	basic_timer_list_tests(tl);
}

static void ordered_bad_inserts_test(void)
{

}

static void lst_nested(void)
{

}

static void ordered_nested(void)
{

}

TEST_LIST = {
	{ "lst_basic",		lst_basic_test },
	{ "ordered_basic",		ordered_basic_test },
	{ "ordered_bad_inserts",	ordered_bad_inserts_test },
	{ "lst_nested",			lst_nested },
	{ "ordered_nested",		ordered_nested },
	{ NULL }
};
