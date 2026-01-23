#include <freeradius-devel/util/test/acutest.h>
#include <freeradius-devel/util/test/acutest_helpers.h>
#include <freeradius-devel/util/syserror.h>
#include <sys/socket.h>

#define TRUNK_TESTS 1
#include "trunk.c"

//#include <gperftools/profiler.h>
typedef struct {
	trunk_request_t	*treq;			//!< Trunk request.
	bool			cancelled;		//!< Seen by the cancelled callback.
	bool			completed;		//!< Seen by the complete callback.
	bool			failed;			//!< Seen by the failed callback.
	bool			freed;			//!< Seen by the free callback.
	bool			signal_partial;		//!< Muxer should signal that this request is partially written.
	bool			signal_cancel_partial;	//!< Muxer should signal that this request is partially cancelled.
	int			priority;		//!< Priority of request
} test_proto_request_t;

typedef struct {
	uint64_t		cancelled;		//!< Count of tests in this run that were cancelled.
	uint64_t		completed;		//!< Count of tests in this run that completed.
	uint64_t		failed;			//!< Count of tests in this run that failed.
	uint64_t		freed;			//!< Count of tests in this run that were freed.
} test_proto_stats_t;

#define DEBUG_LVL_SET if (acutest_verbose_level_ >= 3) fr_debug_lvl = L_DBG_LVL_4 + 1

static void test_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t	*treq;
	size_t			count = 0;
	int			fd = *(talloc_get_type_abort(conn->h, int));
	ssize_t			slen;

	while (trunk_connection_pop_request(&treq, tconn) == 0) {
		test_proto_request_t	*preq = treq->pub.preq;
		count++;

		/*
		 *	Simulate a partial write
		 */
		if (preq && preq->signal_partial) {
			trunk_request_signal_partial(treq);
			preq->signal_partial = false;
			break;
		}

		if (acutest_verbose_level_ >= 3) printf("%s - Wrote %p\n", __FUNCTION__, preq);

		slen = write(fd, &preq, sizeof(preq));
		if (slen < 0) return;
		if (slen == 0) return;
		if (slen < (ssize_t)sizeof(preq)) abort();

		trunk_request_signal_sent(treq);
	}
	TEST_CHECK(count > 0);
}

static void test_cancel_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t	*treq;
	size_t			count = 0;
	int			fd = *(talloc_get_type_abort(conn->h, int));
	ssize_t			slen;

	/*
	 *	For cancellation we just do
	 */
	while ((trunk_connection_pop_cancellation(&treq, tconn) == 0)) {
		test_proto_request_t	*preq = treq->pub.preq;
		count++;

		/*
		 *	Simulate a partial cancel write
		 */
		if (preq && preq->signal_cancel_partial) {
			trunk_request_signal_cancel_partial(treq);
			preq->signal_cancel_partial = false;
			break;
		}

		if (acutest_verbose_level_ >= 3) printf("%s - Wrote %p\n", __FUNCTION__, preq);
		slen = write(fd, &preq, sizeof(preq));
		if (slen < 0) {
			fr_perror("%s - %s", __FUNCTION__, fr_syserror(errno));
			return;
		}
		if (slen == 0) return;
		if (slen < (ssize_t)sizeof(preq)) abort();

		trunk_request_signal_cancel_sent(treq);
	}
	TEST_CHECK(count > 0);
}

static void test_demux(UNUSED fr_event_list_t *el, UNUSED trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	int			fd = *(talloc_get_type_abort(conn->h, int));
	test_proto_request_t	*preq;
	ssize_t			slen;

	for (;;) {
		slen = read(fd, &preq, sizeof(preq));
		if (slen <= 0) break;

		if (acutest_verbose_level_ >= 3) printf("%s - Read %p (%zu)\n", __FUNCTION__, preq, (size_t)slen);

		/*
		 * 	Coverity considers data read from a file to be tainted,
		 * 	and considers its use to be a defect--but almost all the
		 * 	rest of the loop validates the pointer to the extent
		 * 	possible--all of the pointer should be read, its talloc
		 * 	"dynamic type" had better be right, and it should either
		 * 	be freed or have a statethe demuxer can handle or ignore.
		 * 	This isn't like a range check on a numeric value;
		 * 	Coverity doesn't recognize it as validation.
		 */
		TEST_CHECK(slen == sizeof(preq));
		talloc_get_type_abort(preq, test_proto_request_t);

		if (preq->freed) continue;

		/*
		 *	Demuxer can handle both normal requests and cancelled ones
		 */
		switch (preq->treq->pub.state) {
		case TRUNK_REQUEST_STATE_CANCEL:
			break;		/* Hack - just ignore it */

		case TRUNK_REQUEST_STATE_CANCEL_SENT:
			/* coverity[tainted_data] */
			trunk_request_signal_cancel_complete(preq->treq);
			break;

		case TRUNK_REQUEST_STATE_SENT:
			/* coverity[tainted_data] */
			trunk_request_signal_complete(preq->treq);
			break;

		default:
			fr_assert(0);
			break;
		}
	}
}

static void _conn_io_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags,
			   UNUSED int fd_errno, void *uctx)
{

	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
}

static void _conn_io_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	trunk_connection_t *tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_connection_signal_readable(tconn);
}

static void _conn_io_write(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	trunk_connection_t *tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	trunk_connection_signal_writable(tconn);
}

static void _conn_notify(trunk_connection_t *tconn, connection_t *conn,
			 fr_event_list_t *el,
			 trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	int fd = *(talloc_get_type_abort(conn->h, int));

	switch (notify_on) {
	case TRUNK_CONN_EVENT_NONE:
		fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);
		break;

	case TRUNK_CONN_EVENT_READ:
		TEST_CHECK(fr_event_fd_insert(conn, NULL, el, fd, _conn_io_read, NULL, _conn_io_error, tconn) == 0);
		break;

	case TRUNK_CONN_EVENT_WRITE:
		TEST_CHECK(fr_event_fd_insert(conn, NULL, el, fd, NULL, _conn_io_write, _conn_io_error, tconn) == 0);
		break;

	case TRUNK_CONN_EVENT_BOTH:
		TEST_CHECK(fr_event_fd_insert(conn, NULL, el, fd, _conn_io_read, _conn_io_write, _conn_io_error, tconn) == 0);
		break;

	default:
		fr_assert(0);
	}
}

static void test_request_cancel(UNUSED connection_t *conn, void *preq,
				UNUSED trunk_cancel_reason_t reason, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->cancelled = true;
	if (stats) stats->cancelled++;
}

static void test_request_complete(UNUSED request_t *request, void *preq, UNUSED void *rctx, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->completed = true;
	if (stats) stats->completed++;
}

static void test_request_fail(UNUSED request_t *request, void *preq, UNUSED void *rctx, UNUSED trunk_request_state_t state, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->failed = true;
	if (stats) stats->failed++;
}

static void test_request_free(UNUSED request_t *request, void *preq, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->freed = true;
	if (stats) stats->freed++;
}

/** Whenever the second socket in a socket pair is readable, read all pending data, and write it back
 *
 */
static void _conn_io_loopback(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	int		*our_h = talloc_get_type_abort(uctx, int);
	static uint8_t	buff[1024];
	static size_t	to_write;
	ssize_t		slen;

	fr_assert(fd == our_h[1]);

	while (true) {
		slen = read(fd, buff, sizeof(buff));
		if (slen <= 0) return;

		to_write = (size_t)slen;

		if (acutest_verbose_level_ >= 3) printf("%s - Read %zu bytes of data\n", __FUNCTION__, slen);
		slen = write(our_h[1], buff, (size_t)to_write);
		if (slen < 0) return;

		if (slen < (ssize_t)to_write) {
			to_write -= slen;
			if (acutest_verbose_level_ >= 3) {
				printf("%s - Partial write %zu bytes left\n", __FUNCTION__, to_write);
			}
			return;
		} else {
			if (acutest_verbose_level_ >= 3) printf("%s - Wrote %zu bytes of data\n", __FUNCTION__, slen);
		}
	}
}

static void _conn_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	int *our_h = talloc_get_type_abort(h, int);

	talloc_free_children(our_h);	/* Clear the IO handlers */

	close(our_h[0]);
	close(our_h[1]);

	talloc_free(our_h);
}

/** Insert I/O handlers that loop any data back round
 *
 */
static connection_state_t _conn_open(fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	int *our_h = talloc_get_type_abort(h, int);

	/*
	 *	This always needs to be inserted
	 */
	TEST_CHECK(fr_event_fd_insert(our_h, NULL, el, our_h[1], _conn_io_loopback, NULL, NULL, our_h) == 0);

	return CONNECTION_STATE_CONNECTED;
}

/** Allocate a basic socket pair
 *
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_state_t _conn_init(void **h_out, connection_t *conn, UNUSED void *uctx)
{
	int *h;

	h = talloc_array(conn, int, 2);
	socketpair(AF_UNIX, SOCK_STREAM, 0, h);

	fr_nonblock(h[0]);
	fr_nonblock(h[1]);
	connection_signal_on_fd(conn, h[0]);
	*h_out = h;

	return CONNECTION_STATE_CONNECTING;
}

static connection_t *test_setup_socket_pair_connection_alloc(trunk_connection_t *tconn,
								fr_event_list_t *el,
								connection_conf_t const *conn_conf,
								char const *log_prefix, UNUSED void *uctx)
{
	connection_conf_t cstat;

	if (!conn_conf) {
		memset(&cstat, 0, sizeof(cstat));
		conn_conf = &cstat;
	}
	return connection_alloc(tconn, el,
				   &(connection_funcs_t){
				   	.init = _conn_init,
				   	.open = _conn_open,
				   	.close = _conn_close
				   },
				   conn_conf,
				   log_prefix, tconn);
}

static int8_t test_preq_cmp(void const *a, void const *b)
{
	test_proto_request_t const	*preq_a = a;
	test_proto_request_t const	*preq_b = b;
	return CMP(preq_a->priority, preq_b->priority);
}

static trunk_t *test_setup_trunk(TALLOC_CTX *ctx, fr_event_list_t *el, trunk_conf_t *conf, bool with_cancel_mux, void *uctx)
{
	trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.connection_notify = _conn_notify,
					.request_prioritise = test_preq_cmp,
					.request_mux = test_mux,
					.request_demux = test_demux,
					.request_cancel = test_request_cancel,
					.request_complete = test_request_complete,
					.request_fail = test_request_fail,
					.request_free = test_request_free
				};

	/*
	 *	Function list is copied, so this is OK.
	 */
	if (with_cancel_mux) io_funcs.request_cancel_mux = test_cancel_mux;

	return trunk_alloc(ctx, el, &io_funcs, conf, "test_socket_pair", uctx, false, NULL);
}

static void test_socket_pair_alloc_then_free(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;

	trunk_conf_t		conf = {
					.start = 2,
					.min = 2
				};
	trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);

	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false, NULL);
	TEST_CHECK(trunk != NULL);
	if (!trunk) return;

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 2);
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	fr_event_service(el);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(ctx);
}

static void test_socket_pair_alloc_then_reconnect_then_free(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	trunk_conf_t		conf = {
					.start = 2,
					.min = 2,
					.conn_conf = &(connection_conf_t){
						.reconnection_delay = fr_time_delta_from_nsec(NSEC / 2)
					}
				};
	trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};
	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);

	if (!el) return;

	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false, NULL);
	TEST_CHECK(trunk != NULL);
	if (!trunk) return;

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 2);
	fr_event_service(el);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */
	TEST_MSG("Got %u events", events);

	trunk_reconnect(trunk, TRUNK_CONN_ACTIVE, CONNECTION_FAILED);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);	/* Two timer events but event loops only adds one to the total*/
	TEST_MSG("Got %u events", events);
	fr_event_service(el);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 2);

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	fr_event_service(el);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 2);
	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(ctx);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_state_t _conn_init_no_signal(void **h_out, connection_t *conn, UNUSED void *uctx)
{
	int *h;

	h = talloc_array(conn, int, 2);
	socketpair(AF_UNIX, SOCK_STREAM, 0, h);
	*h_out = h;

	return CONNECTION_STATE_CONNECTING;
}

static connection_t *test_setup_socket_pair_1s_timeout_connection_alloc(trunk_connection_t *tconn,
									   fr_event_list_t *el,
									   UNUSED connection_conf_t const *conf,
									   char const *log_prefix, void *uctx)
{
	return connection_alloc(tconn, el,
				   &(connection_funcs_t){
				   	.init = _conn_init_no_signal,
				   	.open = _conn_open,
				   	.close = _conn_close
				   },
				   &(connection_conf_t){
				   	.connection_timeout = fr_time_delta_from_sec(1),
				   	.reconnection_delay = fr_time_delta_from_sec(1)
				   },
				   log_prefix, uctx);
}

static void test_socket_pair_alloc_then_connect_timeout(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	trunk_connection_t		*tconn;
	trunk_conf_t		conf = {
					.start = 1,
					.min = 1
				};
	trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_1s_timeout_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);

	fr_timer_list_set_time_func(el->tl, test_time);


	trunk = trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false, NULL);
	TEST_CHECK(trunk != NULL);
	if (!trunk) return;

	/*
	 *	Trigger connection timeout
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 1.5));
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for the connection timeout */
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);	/* We didn't install the I/O events */

	tconn = fr_dlist_head(&trunk->connecting);
	TEST_CHECK(tconn != NULL);
	if (tconn == NULL) return;

	TEST_CHECK(connection_get_num_timed_out(tconn->pub.conn) == 0);
	TEST_CHECK(connection_get_num_reconnected(tconn->pub.conn) == 0);

	/*
	 *	Timeout should now fire
	 */
	fr_event_service(el);

	/*
	 *	Connection delay not implemented for timed out connections
	 */
	TEST_CHECK(connection_get_num_timed_out(tconn->pub.conn) == 1);
	TEST_CHECK(connection_get_num_reconnected(tconn->pub.conn) == 1);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(ctx);
}

static connection_t *test_setup_socket_pair_1s_reconnection_delay_alloc(trunk_connection_t *tconn,
									   fr_event_list_t *el,
									   UNUSED connection_conf_t const *conn_conf,
									   char const *log_prefix, void *uctx)
{
	return connection_alloc(tconn, el,
				   &(connection_funcs_t){
				   	.init = _conn_init,
				   	.open = _conn_open,
				   	.close = _conn_close
				   },
				   &(connection_conf_t){
				   	.connection_timeout = fr_time_delta_from_sec(1),
				   	.reconnection_delay = fr_time_delta_from_sec(1)
				   },
				   log_prefix, uctx);
}

static void test_socket_pair_alloc_then_reconnect_check_delay(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	trunk_connection_t	*tconn;
	trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.conn_conf = &(connection_conf_t){
						.reconnection_delay = fr_time_delta_from_sec(1),
						.connection_timeout = fr_time_delta_from_sec(1)
					}
				};
	trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_1s_reconnection_delay_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false, NULL);
	TEST_CHECK(trunk != NULL);
	if (!trunk) return;

	/*
	 *	Trigger connection timeout
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 1.5));
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for the connection timeout */
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* We didn't install the I/O events */
	fr_event_service(el);

	tconn = fr_minmax_heap_min_peek(trunk->active);
	TEST_CHECK(tconn != NULL);
	if (tconn == NULL) return;

	TEST_CHECK(connection_get_num_timed_out(tconn->pub.conn) == 0);
	TEST_CHECK(connection_get_num_reconnected(tconn->pub.conn) == 0);

	/*
	 *	Trigger reconnection
	 */
	connection_signal_reconnect(tconn->pub.conn, CONNECTION_FAILED);
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 0.5));

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* Reconnect delay not ready to fire yet, no I/O handlers installed */
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for reconnect delay */

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 1);	/* Reconnect delay should now be ready to fire */

	fr_event_service(el);		/* Services the timer, which then triggers init */

	TEST_CHECK(connection_get_num_timed_out(tconn->pub.conn) == 0);
	TEST_CHECK(connection_get_num_reconnected(tconn->pub.conn) == 1);

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);	/* Should have a pending I/O event and a timer */

	talloc_free(trunk);
	talloc_free(ctx);
}

/*
 *	Test basic enqueue and dequeue
 */
static void test_enqueue_basic(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	test_proto_request_t	*preq;
	trunk_request_t	*treq = NULL;
	trunk_enqueue_t	rcode;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);

	/*
	 *	Our preq is a pointer to the trunk
	 *	request so we don't have to manage
	 *	a tree of requests and responses.
	 */
	preq = talloc_zero(NULL, test_proto_request_t);

	/*
	 *	The trunk is active, but there's no
	 *	connections.
	 *
	 *	We're under the current request limit
	 *      so the request should enter the
	 *	backlog.
	 */
	rcode = trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;
	TEST_CHECK(rcode == TRUNK_ENQUEUE_IN_BACKLOG);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_BACKLOG) == 1);

	/*
	 *	Allow the connection to establish
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_BACKLOG) == 0);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING) == 1);

	/*
	 *	Should now be active and have a write event
	 *	inserted into the event loop.
	 */
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 1);

	/*
	 *	Trunk should be signalled the connection is
	 *	writable.
	 *
	 *	We should then:
	 *	- Pop a request from the pending queue.
	 *	- Write the request to the socket pair
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);

	/*
	 *	Gives the loopback function a chance
	 *	to read the data, and write it back.
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Trunk should be signalled the connection is
	 *	readable.
	 *
	 *	We should then:
	 *	- Read the (looped back) response.
	 *	- Signal the trunk that the connection is readable.
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq->completed == true);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == false);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	talloc_free(trunk);
	talloc_free(ctx);
}

/*
 *	Test request cancellations when the connection is in various states
 */
static void test_enqueue_cancellation_points(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	test_proto_request_t	*preq;
	trunk_request_t	*treq = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);

	TEST_CASE("cancellation via trunk free - TRUNK_REQUEST_STATE_BACKLOG");
	talloc_free(trunk);
	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == false);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - TRUNK_REQUEST_STATE_BACKLOG");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;
	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);	/* Request/rctx not guaranteed after signal, so can't call fail */
	TEST_CHECK(preq->cancelled == false);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);
	talloc_free(trunk);

	TEST_CASE("cancellation via trunk free - TRUNK_REQUEST_STATE_PARTIAL");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PARTIAL));

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - TRUNK_REQUEST_STATE_PARTIAL");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PARTIAL) == 1);
	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);	/* Request/rctx not guaranteed after signal, so can't call fail */
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);
	talloc_free(trunk);

	TEST_CASE("cancellation via trunk free - TRUNK_REQUEST_STATE_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);
	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - TRUNK_REQUEST_STATE_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);
	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);	/* Request/rctx not guaranteed after signal, so can't call fail */
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);
	talloc_free(trunk);

	TEST_CASE("cancellation via trunk free - TRUNK_REQUEST_STATE_CANCEL_PARTIAL");
	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_cancel_partial = true;
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);
	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL) == 1);

	fr_event_corral(el, test_time_base, false);	/* Send the cancellation request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_PARTIAL) == 1);

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via trunk free - TRUNK_REQUEST_STATE_CANCEL_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);
	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL) == 1);

	fr_event_corral(el, test_time_base, false);	/* Send the cancellation request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_SENT) == 1);

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("trunk free after TRUNK_REQUEST_STATE_CANCEL_COMPLETE");
	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);
	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL) == 1);

	fr_event_corral(el, test_time_base, false);	/* Send the cancellation request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_SENT) == 1);

	fr_event_corral(el, test_time_base, false);	/* Loop the cancel request back round */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Read the cancel ACK (such that it is) */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);


	talloc_free(ctx);
}

/*
 *	Test PARTIAL -> SENT and CANCEL-PARTIAL -> CANCEL-SENT
 */
static void test_partial_to_complete_states(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	test_proto_request_t	*preq;
	trunk_request_t	*treq = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	preq->signal_cancel_partial = true;

	TEST_CASE("TRUNK_REQUEST_STATE_PARTIAL -> TRUNK_REQUEST_STATE_SENT");

	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PARTIAL) == 1);

	fr_event_corral(el, test_time_base, false);	/* Complete the partial request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 1);

	trunk_request_signal_cancel(treq);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL) == 1);

	TEST_CASE("TRUNK_REQUEST_STATE_CANCEL_PARTIAL -> TRUNK_REQUEST_STATE_CANCEL_SENT");

	fr_event_corral(el, test_time_base, false);	/* Send partial cancel request */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_PARTIAL) == 1);

	fr_event_corral(el, test_time_base, false);	/* Complete the partial cancellation */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_SENT) == 1);

	fr_event_corral(el, test_time_base, false);	/* Loop the cancellation request back */
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	talloc_free(ctx);
}

/*
 *	Test calling reconnect with requests in each different state
 */
static void test_requeue_on_reconnect(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 2,
					.min = 2,
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5),
					.conn_conf = &(connection_conf_t){
						.reconnection_delay = fr_time_delta_from_nsec(NSEC / 10)
					},
					.backlog_on_failed_conn = true
				};
	test_proto_request_t	*preq;
	trunk_request_t	*treq = NULL;
	trunk_connection_t	*tconn;

	DEBUG_LVL_SET;
	fr_talloc_fault_setup();

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(ctx, test_proto_request_t);
	preq->signal_partial = true;
	preq->signal_cancel_partial = true;

	fr_event_corral(el, test_time_base, false);	/* Connect the connection(s) */
	fr_event_service(el);

	TEST_CASE("dequeue on reconnect - TRUNK_REQUEST_STATE_PENDING");

	TEST_CHECK_LEN(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE), 2);

	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	tconn = treq->pub.tconn;	/* Store the conn the request was assigned to */
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);

	trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);

	/*
	 *	Should be reassigned to the other connection
	 */
	TEST_CHECK(tconn != treq->pub.tconn);
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);

	/*
	 *	Should be reassigned to the backlog
	 */
	trunk_connection_signal_reconnect(treq->pub.tconn, CONNECTION_FAILED);
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_BACKLOG), 1);
	TEST_CHECK(!treq->pub.tconn);

	TEST_CASE("cancel on reconnect - TRUNK_REQUEST_STATE_PARTIAL");

	/*
	 *	Allow the connections to reconnect
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);	/* run management function */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);	/* service any I/O callbacks */

	/*
	 *	Request should now be assigned back to one of the reconnected
	 *	connections.
	 */
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);
	TEST_CHECK(treq->pub.tconn != NULL);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);	/* Send the request (partially) */
	fr_event_service(el);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PARTIAL), 1);

	/*
	 *	Reconnect the connection.
	 *
	 *	preq should pass through the cancel function,
	 *	then be re-assigned.
	 */
	tconn = treq->pub.tconn;
	trunk_connection_signal_reconnect(treq->pub.tconn, CONNECTION_FAILED);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == false);

	preq->cancelled = false;		/* Reset */

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);
	TEST_CHECK(tconn != treq->pub.tconn);	/* Ensure it moved */

	TEST_CASE("cancel on reconnect - TRUNK_REQUEST_STATE_SENT");

	/*
	 *	Sent the request (fully)
	 */
	fr_event_corral(el, test_time_base, false);	/* Send the request (partially) */
	fr_event_service(el);

	/*
	 *	The above indeed appears to send the request partially;
	 *	this appears to be required to send it fully, judging by
	 *	the following check, which fails without it.
	 */
	fr_event_corral(el, test_time_base, false);	/* Send the request (partially) */
	fr_event_service(el);
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT), 1);

	tconn = treq->pub.tconn;
	trunk_connection_signal_reconnect(treq->pub.tconn, CONNECTION_FAILED);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);

	/*
	 *	Allow the connections to reconnect
	 *	and send the request.
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);
	TEST_CHECK(tconn != treq->pub.tconn);	/* Ensure it moved */

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == false);

	preq->cancelled = false;		/* Reset */

	TEST_CASE("free on reconnect - TRUNK_REQUEST_STATE_CANCEL");

	/*
	 *	Signal the request should be cancelled
	 */
	trunk_request_signal_cancel(treq);
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL), 1);

	/*
	 *	Requests in the cancel state, are
	 *	freed instead of being moved between
	 *	connections.
	 */
	trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);	/* treq->pub.tconn, now invalid due to cancel */

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);

	/*
	 *	Allow the connection we just reconnected
	 *	to open so it doesn't interfere with
	 *	the next test.
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("free on reconnect - TRUNK_REQUEST_STATE_CANCEL_PARTIAL");

	/*
	 *	Queue up a new request, and get it to the cancel-partial state.
	 */
	preq = talloc_zero(ctx, test_proto_request_t);
	preq->signal_cancel_partial = true;
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);

	/*
	 *	Sent the request (fully)
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);	/* Send the request (fully) */
	fr_event_service(el);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT), 1);
	trunk_request_signal_cancel(treq);			/* Cancel the request */

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL), 1);

	/*
	 *	Transition to cancel partial
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_PARTIAL), 1);

	/*
	 *	Trigger a reconnection
	 */
	trunk_connection_signal_reconnect(treq->pub.tconn, CONNECTION_FAILED);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);

	/*
	 *	Allow the connection we just reconnected
	 *	top open so it doesn't interfere with
	 *	the next test.
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("free on reconnect - TRUNK_REQUEST_STATE_CANCEL_SENT");

	/*
	 *	Queue up a new request, and get it to the cancel-sent state.
	 */
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 1);

	/*
	 *	Sent the request (fully)
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);	/* Send the request (fully) */
	fr_event_service(el);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT), 1);
	trunk_request_signal_cancel(treq);		/* Cancel the request */

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL), 1);

	/*
	 *	Transition to cancel
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_CANCEL_SENT), 1);

	/*
	 *	Trigger a reconnection
	 */
	trunk_connection_signal_reconnect(treq->pub.tconn, CONNECTION_FAILED);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);

	talloc_free(preq);

	talloc_free(ctx);
}

static void test_connection_start_on_enqueue(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 0,
					.min = 0,	/* No connections on start */
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	test_proto_request_t	*preq;
	trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	/* Need to provide a timer starting value above zero */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 0.5));

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);

	TEST_CASE("C0 - Enqueue should spawn");
	trunk_request_enqueue(&treq_a, trunk, NULL, preq, NULL);

	/*
	 *	This causes the event associated with the request left on
	 *	the backlog queue to be handled, which (along with the other
	 *	corral; service sequence, makes the checks all pass.
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, !max_req_per_conn - Enqueue MUST NOT spawn");
	trunk_request_enqueue(&treq_b, trunk, NULL, preq, NULL);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Allow the connections to open
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 1);

	TEST_CASE("C1 active, !max_req_per_conn - Enqueue MUST NOT spawn");
	trunk_request_enqueue(&treq_c, trunk, NULL, preq, NULL);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING) == 3);

	talloc_free(ctx);
	talloc_free(preq);
}

static void test_connection_rebalance_requests(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 2,
					.min = 2,	/* No connections on start */
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	test_proto_request_t	*preq;
	trunk_connection_t	*tconn;
	trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	printf("Rebalance %p\n", preq);

	/*
	 *	Allow the connections to open
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Mark one of the connections as full, and
	 *	enqueue three requests on the other.
	 */
	tconn = fr_minmax_heap_min_peek(trunk->active);

	TEST_CASE("C2 connected, R0 - Signal inactive");
	trunk_connection_signal_inactive(tconn);


	trunk_request_enqueue(&treq_a, trunk, NULL, preq, NULL);
	trunk_request_enqueue(&treq_b, trunk, NULL, preq, NULL);
	trunk_request_enqueue(&treq_c, trunk, NULL, preq, NULL);

	TEST_CASE("C1 connected, C2 inactive, R3 - Enqueued");
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING) == 3);
	TEST_CHECK(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) == 0);

	/*
	 *	Now mark the previous connection as
	 *	active.  It should receive at least
	 *	one of the requests.
	 */
	TEST_CASE("C2 active, R3 - Signal active, should balance");
	trunk_connection_signal_active(tconn);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING) == 3);
	TEST_CHECK(trunk_request_count_by_connection(tconn, TRUNK_REQUEST_STATE_ALL) >= 1);

	talloc_free(ctx);
	talloc_free(preq);
}

#define ALLOC_REQ(_id) \
do { \
	treq_##_id = trunk_request_alloc(trunk, NULL); \
	preq_##_id = talloc_zero(ctx, test_proto_request_t); \
	preq_##_id->treq = treq_##_id; \
	preq_##_id->priority = next_prio++; \
} while (0)

static void test_connection_levels_max(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 0, 		/* No connections on start */
					.min = 0,
					.max = 2,
					.max_req_per_conn = 2,
					.target_req_per_conn = 2,	/* One request per connection */
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	test_proto_request_t	*preq_a, *preq_b, *preq_c, *preq_d, *preq_e;
	trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL, *treq_d = NULL, *treq_e = NULL;
	int			next_prio = 0;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	/* Need to provide a timer starting value above zero */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 0.5));

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	TRUNK_VERIFY(trunk);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0, R1 - Enqueue should spawn");
	ALLOC_REQ(a);
	TEST_CHECK(trunk_request_enqueue(&treq_a, trunk, NULL, preq_a, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TRUNK_VERIFY(trunk);

	/*
	 *	Like test_connection_start_on_enqueue(), you have to process the backlog
	 *	to start the chain of events.
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK_LEN(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING), 1);
	TRUNK_VERIFY(trunk);

	/*
	 *	Queuing another request should *NOT* start another connection
	 */
	TEST_CASE("C1 connecting, R2 - MUST NOT spawn");
	ALLOC_REQ(b);
	TEST_CHECK(trunk_request_enqueue(&treq_b, trunk, NULL, preq_b, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK_LEN(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING), 1);
	TRUNK_VERIFY(trunk);

	TEST_CASE("C1 connecting, R3 - MUST NOT spawn");
	ALLOC_REQ(c);
	TEST_CHECK(trunk_request_enqueue(&treq_c, trunk, NULL, preq_c, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK_LEN(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING), 1);
	TRUNK_VERIFY(trunk);

	TEST_CASE("C1 connecting, R4 - MUST NOT spawn");
	ALLOC_REQ(d);
	TEST_CHECK(trunk_request_enqueue(&treq_d, trunk, NULL, preq_d, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK_LEN(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING), 1);
	TRUNK_VERIFY(trunk);

	TEST_CASE("C1 connecting, R5 - MUST NOT spawn, NO CAPACITY");
	ALLOC_REQ(e);
	TEST_CHECK(trunk_request_enqueue(&treq_e, trunk, NULL, preq_e, NULL) == TRUNK_ENQUEUE_NO_CAPACITY);
	TEST_CHECK_LEN(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING), 1);
	TRUNK_VERIFY(trunk);

	/*
	 *	Allowing connection to open
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("C1 active, R4 - Check pending 2");
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 2);
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_BACKLOG), 2);
	TRUNK_VERIFY(trunk);

	/*
	 *	Sending requests
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("C1 active, R4 - Check sent 2");
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT), 2);
	TRUNK_VERIFY(trunk);

	/*
	 *	Looping I/O
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Receiving responses
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq_a->completed == true);
	TEST_CHECK(preq_a->failed == false);
	TEST_CHECK(preq_a->cancelled == false);
	TEST_CHECK(preq_a->freed == true);

	TEST_CHECK(preq_b->completed == true);
	TEST_CHECK(preq_b->failed == false);
	TEST_CHECK(preq_b->cancelled == false);
	TEST_CHECK(preq_b->freed == true);

	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING), 2);
	TEST_CHECK_LEN(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_BACKLOG), 0);
	TRUNK_VERIFY(trunk);

	TEST_CASE("C1 active, R0 - Check complete 2, pending 0");

	/*
	 *	Sending requests
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Looping I/O
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Receiving responses
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq_c->completed == true);
	TEST_CHECK(preq_c->failed == false);
	TEST_CHECK(preq_c->cancelled == false);
	TEST_CHECK(preq_c->freed == true);

	TEST_CHECK(preq_d->completed == true);
	TEST_CHECK(preq_d->failed == false);
	TEST_CHECK(preq_d->cancelled == false);
	TEST_CHECK(preq_d->freed == true);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);
	TRUNK_VERIFY(trunk);

	talloc_free(trunk);
	talloc_free(ctx);
}

static void test_connection_levels_alternating_edges(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	trunk_conf_t		conf = {
					.start = 0, 			/* No connections on start */
					.min = 0,
					.max = 0,
					.max_req_per_conn = 0,
					.target_req_per_conn = 2,	/* One request per connection */
					.manage_interval = fr_time_delta_from_nsec(NSEC / 10)
				};

	test_proto_request_t	*preq_a, *preq_b, *preq_c;
	trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL;
	test_proto_stats_t	stats;
	int			next_prio = 0;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	/* Need to provide a timer starting value above zero */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 0.5));

	memset(&stats, 0, sizeof(stats));
	trunk = test_setup_trunk(ctx, el, &conf, true, &stats);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0, R1 - Enqueue should spawn");
	ALLOC_REQ(a);
	TEST_CHECK(trunk_request_enqueue(&treq_a, trunk, NULL, preq_a, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);

	/*
	 *	Processing the event associated with the backlog creates
	 *	the connection in connecting state..
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, R2 - MUST NOT spawn");
	ALLOC_REQ(b);
	TEST_CHECK(trunk_request_enqueue(&treq_b, trunk, NULL, preq_b, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	/*
	 *	Open connection
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING) == 2);

	TEST_CASE("C1 connected, R3 - should spawn");
	ALLOC_REQ(c);
	TEST_CHECK(trunk_request_enqueue(&treq_c, trunk, NULL, preq_c, NULL) == TRUNK_ENQUEUE_OK);
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 3);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Complete requests
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	TEST_CASE("C1 connected, C2 connecting, R2 - MUST NOT spawn");
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 3);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 2);

	/*
	 *	Finish the last request, should close one connection
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	TEST_CASE("C1 connected, R0");
	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_ALL) == 0);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 1);

	/*
	 *	Requests now done, should close another connection
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	TEST_CASE("C0, R0");
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 0);

	TEST_CHECK(stats.completed == 3);
	TEST_CHECK(stats.failed == 0);
	TEST_CHECK(stats.cancelled == 0);
	TEST_CHECK(stats.freed == 3);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0, R1 - Enqueue should spawn");
	ALLOC_REQ(a);
	TEST_CHECK(trunk_request_enqueue(&treq_a, trunk, NULL, preq_a, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);

	/*
	 *	...once the event associated with the backlogged request is handled.
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, R2 - MUST NOT spawn");
	ALLOC_REQ(b);
	TEST_CHECK(trunk_request_enqueue(&treq_b, trunk, NULL, preq_b, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	/*
	 *	Open connection
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_PENDING) == 2);

	TEST_CASE("C1 connected, R3 - should spawn");
	ALLOC_REQ(c);
	TEST_CHECK(trunk_request_enqueue(&treq_c, trunk, NULL, preq_c, NULL) == TRUNK_ENQUEUE_OK);
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(1));

	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(trunk_request_count_by_state(trunk, TRUNK_CONN_ALL, TRUNK_REQUEST_STATE_SENT) == 3);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(trunk_connection_count_by_state(trunk, TRUNK_CONN_CONNECTING) == 1);

	talloc_free(trunk);
	talloc_free(ctx);
}

#undef fr_time	/* Need to the real time */
static void test_enqueue_and_io_speed(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.max = 0,
					.max_req_per_conn = 0,
					.target_req_per_conn = 0,	/* One request per connection */
					.req_pool_headers = 1,
					.req_pool_size = sizeof(test_proto_request_t),
					.manage_interval = fr_time_delta_from_nsec(NSEC * 0.5)
				};
	size_t			i = 0, requests = 100000;
	fr_time_t		enqueue_start, enqueue_stop, io_start, io_stop;
	fr_time_delta_t		enqueue_time, io_time, total_time;
	trunk_request_t	**treq_array;
	test_proto_request_t	**preq_array;
	test_proto_stats_t	stats;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_timer_list_set_time_func(el->tl, test_time);

	/* Need to provide a timer starting value above zero */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 0.5));

	memset(&stats, 0, sizeof(stats));
	trunk = test_setup_trunk(ctx, el, &conf, true, &stats);

	/*
	 *	Open the connections
	 */
	fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Build up a cache of requests
	 *	This prevents all mallocs on request enqueue.
	 *
	 *	When the server's running, this does represent
	 *	close to what we'd have as a steady state.
	 */
	MEM(treq_array = talloc_array(ctx, trunk_request_t *, requests));
	for (i = 0; i < requests; i++) treq_array[i] = trunk_request_alloc(trunk, NULL);
	for (i = 0; i < requests; i++) trunk_request_free(&treq_array[i]);

	MEM(preq_array = talloc_array(ctx, test_proto_request_t *, requests));

	DEBUG_LVL_SET;

	TEST_CASE("Enqueue requests");
	enqueue_start = fr_time();
//	ProfilerStart(getenv("FR_PROFILE"));
	for (i = 0; i < requests; i++) {
		trunk_request_t	*treq;
		test_proto_request_t	*preq = NULL;

		treq = trunk_request_alloc(trunk, NULL);
		preq = talloc_zero(treq, test_proto_request_t);
		preq->treq = treq;
		trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	}
	enqueue_stop = fr_time();
	enqueue_time = fr_time_sub(enqueue_stop, enqueue_start);
	if (acutest_verbose_level_ >= 1) {
		INFO("Enqueue time %pV (%u rps) (%"PRIu64"/%"PRIu64")",
		     fr_box_time_delta(enqueue_time),
		     (uint32_t)(requests / ((float)(fr_time_delta_unwrap(enqueue_time)) / NSEC)),
		     trunk->pub.req_alloc_new, trunk->pub.req_alloc_reused);
	}

	TEST_CASE("Perform I/O operations");
	io_start = fr_time();
	while (true) {
		events = fr_event_corral(el, test_time_base, false);
		if (!events) break;
		fr_event_service(el);
		test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_nsec(NSEC * 0.25));
	}
	io_stop = fr_time();
	io_time = fr_time_sub(io_stop, io_start);

	if (acutest_verbose_level_ >= 1) {
		INFO("I/O time %pV (%u rps)",
		     fr_box_time_delta(io_time),
		     (uint32_t)(requests / ((float)(fr_time_delta_unwrap(io_time)) / NSEC)));
	}

	if (acutest_verbose_level_ >= 1) {
		total_time = fr_time_sub(io_stop, enqueue_start);
		INFO("Total time %pV (%u rps)",
		     fr_box_time_delta(total_time),
		     (uint32_t)(requests / ((float)(fr_time_delta_unwrap(total_time)) / NSEC)));
	}

	TEST_CHECK_LEN(stats.completed, requests);
	TEST_CHECK_LEN(stats.failed, 0);
	TEST_CHECK_LEN(stats.cancelled, 0);
	TEST_CHECK_LEN(stats.freed, requests);

//	ProfilerStop();

	talloc_free(ctx);
}

/*
 *	Connection spawning
 */
TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "Basic - Alloc then free",			test_socket_pair_alloc_then_free },
	{ "Basic - Alloc then reconnect then free",	test_socket_pair_alloc_then_reconnect_then_free },

	/*
	 *	Connection timeout
	 */
	{ "Timeouts - Connection",			test_socket_pair_alloc_then_connect_timeout },
	{ "Timeouts - Reconnect delay", 		test_socket_pair_alloc_then_reconnect_check_delay },

	/*
	 *	Basic enqueue/dequeue
	 */
	{ "Enqueue - Basic",				test_enqueue_basic },
	{ "Enqueue - Cancellation points",		test_enqueue_cancellation_points },
	{ "Enqueue - Partial state transitions",	test_partial_to_complete_states },
	{ "Requeue - On reconnect",			test_requeue_on_reconnect },

	/*
	 *	Rebalance
	 */
	{ "Rebalance - Connection rebalance",		test_connection_rebalance_requests },

	/*
	 *	Connection spawning tests
	 */
	{ "Spawn - Test connection start on enqueue",	test_connection_start_on_enqueue },
	{ "Spawn - Connection levels max",		test_connection_levels_max },
	{ "Spawn - Connection levels alternating edges",test_connection_levels_alternating_edges },

	/*
	 *	Performance tests
	 */
	{ "Speed Test - Enqueue, and I/O",		test_enqueue_and_io_speed },
	TEST_TERMINATOR
};
