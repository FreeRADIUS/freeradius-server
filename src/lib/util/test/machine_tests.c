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

/** Tests for the observable state machine
 *
 * @file src/lib/util/test/machine_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest_common_init.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/machine.h>

/*
 *	A machine shaped like the connection state machine.
 */
typedef enum : unsigned int {
	CONN_INIT = 0,
	CONN_CONNECTING,
	CONN_CONNECTED,
	CONN_FAILED,
	CONN_CLOSED,
	CONN_MAX
} conn_state_t;

static fr_table_num_indexed_t const conn_state_names[] = {
	FR_TABLE_INDEXED_ENTRY(CONN_INIT),
	FR_TABLE_INDEXED_ENTRY(CONN_CONNECTING),
	FR_TABLE_INDEXED_ENTRY(CONN_CONNECTED),
	FR_TABLE_INDEXED_ENTRY(CONN_FAILED),
	FR_TABLE_INDEXED_ENTRY(CONN_CLOSED),
};

#define CONN_ROW(_from, ...)	FR_MACHINE_ROW(conn_state_t, _from, __VA_ARGS__)

FR_MACHINE_VALID(conn, CONN_MAX,
	CONN_ROW(CONN_INIT,		CONN_CONNECTING, CONN_CLOSED),
	CONN_ROW(CONN_CONNECTING,	CONN_CONNECTED, CONN_FAILED, CONN_CLOSED),
	CONN_ROW(CONN_CONNECTED,	CONN_FAILED, CONN_CLOSED),
	CONN_ROW(CONN_FAILED,		CONN_INIT, CONN_CLOSED)
	/* CONN_CLOSED is terminal */
);

FR_MACHINE_TYPES(conn, conn_state_t)
FR_MACHINE_FUNCS(conn, conn_state_t)

/*
 *	Every callback appends one line to the log, and the tests
 *	compare the log against the expected order.
 */
#define LOG_MAX		32
static char const	*event_log[LOG_MAX];
static size_t		event_num;
static int		enter_ret;		/* returned by the CONNECTED entry function */

static void log_reset(void)
{
	event_num = 0;
	enter_ret = 0;
}

static void log_add(char const *event)
{
	TEST_ASSERT(event_num < LOG_MAX);
	event_log[event_num++] = event;
}

static int conn_enter_connected(UNUSED fr_machine_t *m, UNUSED void *uctx)
{
	log_add("enter CONNECTED");
	return enter_ret;
}

static void conn_exit_connecting(UNUSED fr_machine_t *m, UNUSED void *uctx)
{
	log_add("exit CONNECTING");
}

static int conn_enter_connecting(UNUSED fr_machine_t *m, UNUSED void *uctx)
{
	log_add("enter CONNECTING");
	return 0;
}

static fr_machine_state_t const conn_states[CONN_MAX] = {
	[CONN_CONNECTING]	= { .enter = conn_enter_connecting, .exit = conn_exit_connecting },
	[CONN_CONNECTED]	= { .enter = conn_enter_connected },
};

static fr_machine_def_t const conn_def = {
	.name = "conn",
	.state_names = conn_state_names,
	.state_names_len = NUM_ELEMENTS(conn_state_names),
	.valid = &conn_valid,
	.states = conn_states
};

/*
 *	Watchers log their uctx, a string naming the registration.
 */
static void watch_log(UNUSED conn_machine_t *m, UNUSED conn_state_t prev, UNUSED conn_state_t state, void *uctx)
{
	log_add(uctx);
}

/*
 *	A watcher that requests a transition.  uctx is the target.
 */
static void watch_transition(conn_machine_t *m, UNUSED conn_state_t prev, UNUSED conn_state_t state, void *uctx)
{
	conn_state_t to = *(conn_state_t *)uctx;

	log_add("watch requests transition");
	TEST_CHECK(conn_machine_transition(m, to) == FR_MACHINE_QUEUED);
}

static bool log_matches(char const * const expected[], size_t expected_num)
{
	size_t i;

	TEST_CHECK(event_num == expected_num);
	TEST_MSG("logged %zu events, expected %zu", event_num, expected_num);
	if (event_num != expected_num) {
		for (i = 0; i < event_num; i++) TEST_MSG("  logged[%zu] = %s", i, event_log[i]);
		return false;
	}

	for (i = 0; i < expected_num; i++) {
		TEST_CHECK(strcmp(event_log[i], expected[i]) == 0);
		TEST_MSG("event %zu: logged \"%s\", expected \"%s\"", i, event_log[i], expected[i]);
	}

	return true;
}
#define LOG_MATCHES(...) \
	log_matches((char const * const []){ __VA_ARGS__ }, VA_NARG(__VA_ARGS__))

static void test_init(void)
{
	conn_machine_t m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);

	TEST_CASE("init sets the state and prev, and runs nothing");
	TEST_CHECK(conn_machine_state(&m) == CONN_INIT);
	TEST_CHECK(conn_machine_prev(&m) == CONN_INIT);
	TEST_CHECK(event_num == 0);

	TEST_CASE("state names resolve");
	TEST_CHECK(strcmp(conn_machine_state_name(&m, CONN_CONNECTING), "CONN_CONNECTING") == 0);
	TEST_CHECK(strcmp(fr_machine_state_name(&conn_def, FR_MACHINE_STATE_ANY), "<any>") == 0);
	TEST_CHECK(strcmp(fr_machine_state_name(&conn_def, CONN_MAX), "<INVALID>") == 0);

	conn_machine_fini(&m);
}

static void test_table(void)
{
	conn_machine_t m;

	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);

	TEST_CASE("the table allows listed transitions");
	TEST_CHECK(conn_machine_next_valid(&m, CONN_CONNECTING));
	TEST_CHECK(conn_machine_next_valid(&m, CONN_CLOSED));

	TEST_CASE("the table rejects unlisted transitions, self transitions and out of range states");
	TEST_CHECK(!conn_machine_next_valid(&m, CONN_CONNECTED));
	TEST_CHECK(!conn_machine_next_valid(&m, CONN_INIT));
	TEST_CHECK(!conn_machine_next_valid(&m, CONN_MAX));

	TEST_CASE("a terminal state has no exits");
	m.m.state = CONN_CLOSED;
	TEST_CHECK(!conn_machine_next_valid(&m, CONN_INIT));
	TEST_CHECK(!conn_machine_next_valid(&m, CONN_CONNECTING));

	conn_machine_fini(&m);
}

static void test_transition_order(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTED, FR_MACHINE_PRE_ENTER, watch_log, false, "pre CONNECTED");
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTED, FR_MACHINE_POST_ENTER, watch_log, false, "post CONNECTED");

	TEST_CASE("INIT -> CONNECTING runs the entry function");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_state(&m) == CONN_CONNECTING);
	TEST_CHECK(conn_machine_prev(&m) == CONN_INIT);

	TEST_CASE("CONNECTING -> CONNECTED runs exit, pre watchers, enter, post watchers, in that order");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_state(&m) == CONN_CONNECTED);
	TEST_CHECK(conn_machine_prev(&m) == CONN_CONNECTING);
	LOG_MATCHES("enter CONNECTING", "exit CONNECTING", "pre CONNECTED", "enter CONNECTED", "post CONNECTED");

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_transition_invalid(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTED, FR_MACHINE_PRE_ENTER, watch_log, false, "pre CONNECTED");

	TEST_CASE("an unlisted transition is rejected and runs nothing");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTED) == FR_MACHINE_INVALID);
	TEST_CHECK(conn_machine_state(&m) == CONN_INIT);
	TEST_CHECK(conn_machine_prev(&m) == CONN_INIT);
	TEST_CHECK(event_num == 0);

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_enter_failed(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_CONNECTING, NULL);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTED, FR_MACHINE_PRE_ENTER, watch_log, false, "pre CONNECTED");
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTED, FR_MACHINE_POST_ENTER, watch_log, false, "post CONNECTED");
	enter_ret = -1;

	TEST_CASE("a failed entry function reports failure, leaves the machine in the new state, and skips post watchers");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTED) == FR_MACHINE_ENTER_FAILED);
	TEST_CHECK(conn_machine_state(&m) == CONN_CONNECTED);
	LOG_MATCHES("exit CONNECTING", "pre CONNECTED", "enter CONNECTED");

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_watch_edges(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add(&m, ctx, CONN_CONNECTING, CONN_FAILED, FR_MACHINE_POST_ENTER, watch_log, false,
			       "edge CONNECTING->FAILED");
	conn_machine_watch_add(&m, ctx, CONN_CONNECTED, CONN_FAILED, FR_MACHINE_POST_ENTER, watch_log, false,
			       "edge CONNECTED->FAILED");
	conn_machine_watch_add(&m, ctx, CONN_CONNECTING, FR_MACHINE_STATE_ANY, FR_MACHINE_POST_ENTER, watch_log, false,
			       "exit CONNECTING (watch)");
	conn_machine_watch_add_any(&m, ctx, CONN_FAILED, FR_MACHINE_POST_ENTER, watch_log, false, "any->FAILED");

	TEST_CASE("INIT -> CONNECTING matches no watcher");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("enter CONNECTING");

	TEST_CASE("CONNECTING -> FAILED matches the edge, the exit wildcard and the entry wildcard, in registration order");
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("enter CONNECTING", "exit CONNECTING", "edge CONNECTING->FAILED", "exit CONNECTING (watch)", "any->FAILED");

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_watch_oneshot_and_disable(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	conn_machine_t		m;
	fr_machine_watch_entry_t *persistent;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, true, "oneshot");
	persistent = conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false,
						"persistent");

	TEST_CASE("both watchers run on the first entry");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("enter CONNECTING", "oneshot", "persistent");

	TEST_CASE("only the persistent watcher runs on the second entry");
	log_reset();
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_INIT) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("exit CONNECTING", "enter CONNECTING", "persistent");

	TEST_CASE("a disabled watcher is skipped, and runs again once enabled");
	log_reset();
	fr_machine_watch_disable(persistent);
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_INIT) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("exit CONNECTING", "enter CONNECTING");

	log_reset();
	fr_machine_watch_enable(persistent);
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_INIT) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("exit CONNECTING", "enter CONNECTING", "persistent");

	TEST_CASE("freeing the handle removes the watcher");
	log_reset();
	talloc_free(persistent);
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_INIT) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("exit CONNECTING", "enter CONNECTING");

	conn_machine_fini(&m);
	talloc_free(ctx);
}

/*
 *	A watcher that frees the entry in its uctx, which the test
 *	points at itself or at a sibling.
 */
static void watch_free_entry(UNUSED conn_machine_t *m, UNUSED conn_state_t prev, UNUSED conn_state_t state, void *uctx)
{
	fr_machine_watch_entry_t **entry_p = uctx;

	log_add("freeing an entry");
	talloc_free(*entry_p);
	*entry_p = NULL;
}

static void test_watch_free_during_walk(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	conn_machine_t		m;
	fr_machine_watch_entry_t *self = NULL, *sibling = NULL;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);

	TEST_CASE("a watcher that frees itself does not break the walk");
	self = conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_free_entry, false, &self);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false, "after self");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("enter CONNECTING", "freeing an entry", "after self");
	TEST_CHECK(self == NULL);

	TEST_CASE("a watcher that frees the next sibling skips it and continues");
	log_reset();
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_INIT) == FR_MACHINE_TRANSITIONED);
	log_reset();
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_free_entry, false, &sibling);
	sibling = conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false, "sibling");
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false, "after sibling");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("enter CONNECTING", "after self", "freeing an entry", "after sibling");
	TEST_CHECK(sibling == NULL);

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_transition_from_watcher(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;
	conn_state_t	to_connected = CONN_CONNECTED;
	conn_state_t	to_closed = CONN_CLOSED;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_transition, false, &to_connected);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTED, FR_MACHINE_POST_ENTER, watch_log, false, "post CONNECTED");

	TEST_CASE("a transition requested by a watcher runs after the current one completes");
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_state(&m) == CONN_CONNECTED);
	TEST_CHECK(conn_machine_prev(&m) == CONN_CONNECTING);
	LOG_MATCHES("enter CONNECTING", "watch requests transition", "exit CONNECTING", "enter CONNECTED", "post CONNECTED");

	TEST_CASE("two requests from one callback run in order");
	log_reset();
	TEST_CHECK(conn_machine_transition(&m, CONN_FAILED) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_transition(&m, CONN_INIT) == FR_MACHINE_TRANSITIONED);
	log_reset();
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_transition, false, &to_closed);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	TEST_CHECK(conn_machine_state(&m) == CONN_CLOSED);
	TEST_CHECK(conn_machine_prev(&m) == CONN_CONNECTED);
	LOG_MATCHES("enter CONNECTING", "watch requests transition", "watch requests transition",
		    "exit CONNECTING", "enter CONNECTED", "post CONNECTED");

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_pause_resume(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false, "post CONNECTING");

	TEST_CASE("a transition while paused is queued");
	conn_machine_pause(&m);
	conn_machine_pause(&m);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_QUEUED);
	TEST_CHECK(conn_machine_state(&m) == CONN_INIT);
	TEST_CHECK(event_num == 0);

	TEST_CASE("the first resume of two does not run the queue");
	conn_machine_resume(&m);
	TEST_CHECK(conn_machine_state(&m) == CONN_INIT);
	TEST_CHECK(event_num == 0);

	TEST_CASE("the last resume runs the queue");
	conn_machine_resume(&m);
	TEST_CHECK(conn_machine_state(&m) == CONN_CONNECTING);
	LOG_MATCHES("enter CONNECTING", "post CONNECTING");

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_queue_revalidated(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);

	TEST_CASE("a queued transition the table no longer allows is dropped");
	conn_machine_pause(&m);
	TEST_CHECK(conn_machine_transition(&m, CONN_CLOSED) == FR_MACHINE_QUEUED);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_QUEUED);	/* Invalid once CLOSED */
	conn_machine_resume(&m);
	TEST_CHECK(conn_machine_state(&m) == CONN_CLOSED);
	TEST_CHECK(event_num == 0);

	conn_machine_fini(&m);
	talloc_free(ctx);
}

static void test_watch_ctx_free(void)
{
	TALLOC_CTX	*ctx = talloc_init_const("test");
	TALLOC_CTX	*watch_ctx = talloc_init_const("watcher");
	conn_machine_t	m;

	log_reset();
	conn_machine_init(&m, &conn_def, CONN_INIT, NULL);
	conn_machine_watch_add_any(&m, watch_ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false, "from freed ctx");
	conn_machine_watch_add_any(&m, ctx, CONN_CONNECTING, FR_MACHINE_POST_ENTER, watch_log, false, "from live ctx");

	TEST_CASE("freeing the talloc context of a watcher removes it");
	talloc_free(watch_ctx);
	TEST_CHECK(conn_machine_transition(&m, CONN_CONNECTING) == FR_MACHINE_TRANSITIONED);
	LOG_MATCHES("enter CONNECTING", "from live ctx");

	TEST_CASE("fini frees the remaining watchers, and the context they were parented to is then empty");
	conn_machine_fini(&m);
	TEST_CHECK(talloc_total_blocks(ctx) == 1);

	talloc_free(ctx);
}

TEST_LIST = {
	{ "init",			test_init },
	{ "table",			test_table },
	{ "transition_order",		test_transition_order },
	{ "transition_invalid",		test_transition_invalid },
	{ "enter_failed",		test_enter_failed },
	{ "watch_edges",		test_watch_edges },
	{ "watch_oneshot_and_disable",	test_watch_oneshot_and_disable },
	{ "watch_free_during_walk",	test_watch_free_during_walk },
	{ "transition_from_watcher",	test_transition_from_watcher },
	{ "pause_resume",		test_pause_resume },
	{ "queue_revalidated",		test_queue_revalidated },
	{ "watch_ctx_free",		test_watch_ctx_free },
	TEST_TERMINATOR
};
