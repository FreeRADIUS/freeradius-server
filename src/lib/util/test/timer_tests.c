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
 * @file src/lib/util/test//timer_tests.c
 *
 * @copyright 2025 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include "acutest.h"
#include"acutest_helpers.h"
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

static CC_HINT(nonnull) void basic_timer_list_tests(fr_timer_list_t *tl)
{
	fr_time_t now;
	fr_timer_t *event1 = NULL, *event1a = NULL, *event2 = NULL, *event3 = NULL, *event4 = NULL, *event5 = NULL, *event6 = NULL;
	bool event1_fired = false, event1a_fired = false, event2_fired = false, event3_fired = false, event4_fired = false, event5_fired = false, event6_fired = false;
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
	 *	Will be delete before it fires
	 */
	ret = fr_timer_in(NULL, tl, &event5, fr_time_delta_from_sec(4), true, timer_cb, &event5_fired);
	TEST_CHECK(ret == 0);

	ret = fr_timer_in(NULL, tl, &event6, fr_time_delta_from_sec(4), true, timer_cb, &event6_fired);
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
	TEST_CHECK(event1 == NULL);
	TEST_CHECK(event1a == NULL);

	/*
	 *	Second batch of events (single event)
	 */
	TEST_CHECK(fr_timer_list_run(tl, &now) == 1);
	TEST_CHECK(event2 == NULL);
	TEST_CHECK(event2_fired == true);
	TEST_CHECK(event3_fired == false);
	TEST_CHECK(event4_fired == false);

	/*
	 *	Now disarm event 4, so it doesn't fire
	 */
	TEST_CHECK(fr_timer_disarm(event4) == 0);

	now = fr_time_from_sec(3);
	TEST_CHECK(fr_timer_list_run(tl, &now) == 1);

	TEST_CHECK(event3 == NULL);
	TEST_CHECK(event4 != NULL);
	TEST_CHECK(event3_fired == true);
	TEST_CHECK(event4_fired == false);

	/*
	 *	Now free event 5, so it doesn't fire
	 */
	TEST_CHECK(fr_timer_delete(&event5) == 0);

	now = fr_time_from_sec(4);
	TEST_CHECK(fr_timer_list_run(tl, &now) == 1);
	TEST_CHECK(event5_fired == false);
	TEST_CHECK(event6_fired == true);
	TEST_CHECK(event5 == NULL);
	TEST_CHECK(event6 == NULL);

	/*
	 *	Re-arm event 4
	 */
	now = fr_time_from_sec(4);
	ret = fr_timer_at(NULL, tl, &event4, fr_time_from_sec(3), false, timer_cb, &event4_fired);
	TEST_CHECK(ret == 0);
	TEST_CHECK(fr_timer_list_run(tl, &now) == 1);
	TEST_CHECK(event4_fired == true);
	TEST_CHECK(event4 != NULL);

	talloc_free(event4);	/* This needs to be freed before its parent stack memory goes out of scope */
}

static void lst_basic_test(void)
{
	fr_timer_list_t *tl;

	tl = fr_timer_list_lst_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);
	if (tl == NULL) return;

	fr_timer_list_set_time_func(tl, basic_time);

	basic_timer_list_tests(tl);

	talloc_free(tl);
}

typedef struct {
	bool		*fired;
	fr_timer_t	*event;
} deferred_uctx_t;

static void timer_cb_deferred(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	deferred_uctx_t *ctx = (deferred_uctx_t *)uctx;

	TEST_CHECK(fr_timer_at(NULL, tl, &ctx->event, now, true, timer_cb, ctx->fired) == 0);
	TEST_CHECK(fr_timer_list_num_events(tl) == 1);

	TEST_CHECK(fr_timer_list_run(tl, &now) == 0);	/* Event won't run immediately because we're in a callback */
}

static CC_HINT(nonnull) void deferred_timer_list_tests(fr_timer_list_t *tl)
{
	fr_time_t now;
	fr_timer_t *event1 = NULL;
	bool deferred_event_fired = false;

	deferred_uctx_t ctx = { .fired = &deferred_event_fired, .event = NULL };

	fr_timer_list_set_time_func(tl, basic_time);

	now = fr_time_from_sec(1);
	TEST_CHECK(fr_timer_at(NULL, tl, &event1, fr_time_from_sec(1), true, timer_cb_deferred, &ctx) == 0);

	/*
	 *	The inner fr_timer_list_run call moves the event from the deferred
	 *	list into the lst, where it's immediately executed, which is why
	 *	we get 2 events firing here.
	 */
	TEST_CHECK(fr_timer_list_run(tl, &now) == 2);
	TEST_CHECK(deferred_event_fired == true);

	now = fr_time_from_sec(1);
}

static void ordered_basic_test(void)
{
	fr_timer_list_t *tl;

	tl = fr_timer_list_ordered_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);
	if (tl == NULL) return;

	fr_timer_list_set_time_func(tl, basic_time);

	basic_timer_list_tests(tl);

	talloc_free(tl);
}

static void lst_deferred_test(void)
{
	fr_timer_list_t *tl;

	tl = fr_timer_list_lst_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);
	if (tl == NULL) return;

	deferred_timer_list_tests(tl);

	talloc_free(tl);
}

static void ordered_deferred_test(void)
{
	fr_timer_list_t *tl;

	tl = fr_timer_list_ordered_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);
	if (tl == NULL) return;

	deferred_timer_list_tests(tl);

	talloc_free(tl);
}

static void ordered_bad_inserts_test(void)
{
	fr_timer_list_t *tl;
	fr_timer_t *event1 = NULL, *event2 = NULL;
	bool event1_fired = false, event2_fired = false;
	int ret;

	tl = fr_timer_list_ordered_alloc(NULL, NULL);
	TEST_CHECK(tl != NULL);
	if (tl == NULL) return;

	fr_timer_list_set_time_func(tl, basic_time);

	ret = fr_timer_in(NULL, tl, &event1, fr_time_delta_from_sec(5), true, timer_cb, &event1_fired);
	TEST_CHECK(ret == 0);

	/*
	 *	Should fail (wrong order)
	 */
	ret = fr_timer_in(NULL, tl, &event2, fr_time_delta_from_sec(1), true, timer_cb, &event2_fired);
	TEST_CHECK(ret == -1);

	talloc_free(tl);
}

static void nested_test(fr_timer_list_t *tl_outer, fr_timer_list_t *tl_inner)
{
	fr_timer_t *event1_inner = NULL, *event2_inner = NULL;
	bool event1_inner_fired = false, event2_inner_fired = false;
	fr_time_t now;

	int ret;

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 0);

	/*
	 *	Should insert a single event into the outer list
	 */
	ret = fr_timer_in(NULL, tl_inner, &event1_inner, fr_time_delta_from_sec(1), true, timer_cb, &event1_inner_fired);
	TEST_CHECK(ret == 0);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 1);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 1);

	/*
	 *	Disable the event, the outer event count should drop to 0
	 */
	TEST_CHECK(fr_timer_disarm(event1_inner) == 0);
	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 0);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 0);

	/*
	 *	Re-Enable the event
	 */
	ret = fr_timer_in(NULL, tl_inner, &event1_inner, fr_time_delta_from_sec(1), true, timer_cb, &event1_inner_fired);
	TEST_CHECK(ret == 0);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 1);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 1);

	ret = fr_timer_in(NULL, tl_inner, &event2_inner, fr_time_delta_from_sec(1), true, timer_cb, &event2_inner_fired);
	TEST_CHECK(ret == 0);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 1);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 2);

	now = fr_time_from_sec(1);

	/*
	 *	One event should fire, which should run all the events in the inner list
	 */
	TEST_CHECK(fr_timer_list_run(tl_outer, &now) == 1);
	TEST_CHECK(event1_inner_fired == true);
	TEST_CHECK(event2_inner_fired == true);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 0);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 0);
}

static void lst_nested(void)
{
	fr_timer_list_t *tl_outer, *tl_inner;
	fr_timer_t *event1_inner = NULL;
	int ret;

	tl_outer = fr_timer_list_lst_alloc(NULL, NULL);
	TEST_CHECK(tl_outer != NULL);
	if (tl_outer == NULL) return;

	tl_inner = fr_timer_list_lst_alloc(tl_outer, tl_outer);
	TEST_CHECK(tl_inner != NULL);
	if (tl_inner == NULL) return;

	fr_timer_list_set_time_func(tl_outer, basic_time);
	fr_timer_list_set_time_func(tl_inner, basic_time);

	nested_test(tl_outer, tl_inner);

	ret = fr_timer_in(NULL, tl_inner, &event1_inner, fr_time_delta_from_sec(1), true, timer_cb, NULL);
	TEST_CHECK(ret == 0);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 1);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 1);

	talloc_free(tl_inner);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 0);
	TEST_CHECK(event1_inner == NULL);

	talloc_free(tl_outer);
}

static void ordered_nested(void)
{
	fr_timer_list_t *tl_outer, *tl_inner;
	fr_timer_t *event1_inner = NULL;
	int ret;

	tl_outer = fr_timer_list_ordered_alloc(NULL, NULL);
	TEST_CHECK(tl_outer != NULL);
	if (tl_outer == NULL) return;

	tl_inner = fr_timer_list_ordered_alloc(tl_outer, tl_outer);
	TEST_CHECK(tl_inner != NULL);
	if (tl_inner == NULL) return;

	fr_timer_list_set_time_func(tl_outer, basic_time);
	fr_timer_list_set_time_func(tl_inner, basic_time);

	nested_test(tl_outer, tl_inner);

	ret = fr_timer_in(NULL, tl_inner, &event1_inner, fr_time_delta_from_sec(1), true, timer_cb, NULL);
	TEST_CHECK(ret == 0);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 1);
	TEST_CHECK(fr_timer_list_num_events(tl_inner) == 1);

	talloc_free(tl_inner);

	TEST_CHECK(fr_timer_list_num_events(tl_outer) == 0);
	TEST_CHECK(event1_inner == NULL);

	talloc_free(tl_outer);
}

TEST_LIST = {
	{ "lst_basic",		lst_basic_test },
	{ "ordered_basic",		ordered_basic_test },
	{ "lst_deferred",		lst_deferred_test },
	{ "ordered_deferred",		ordered_deferred_test },
	{ "ordered_bad_inserts",	ordered_bad_inserts_test },
	{ "lst_nested",		lst_nested },
	{ "ordered_nested",		ordered_nested },
	TEST_TERMINATOR
};
