
#include <freeradius-devel/util/acutest.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <gperftools/profiler.h>
typedef struct {
	fr_trunk_request_t	*treq;			//!< Trunk request.
	bool			cancelled;		//!< Seen by the cancelled callback.
	bool			completed;		//!< Seen by the complete callback.
	bool			failed;			//!< Seen by the failed callback.
	bool			freed;			//!< Seen by the free callback.
	bool			signal_partial;		//!< Muxer should signal that this request is partially written.
	bool			signal_cancel_partial;	//!< Muxer should signal that this request is partially cancelled.
} test_proto_request_t;

typedef struct {
	uint64_t		cancelled;		//!< Count of tests in this run that were cancelled.
	uint64_t		completed;		//!< Count of tests in this run that completed.
	uint64_t		failed;			//!< Count of tests in this run that failed.
	uint64_t		freed;			//!< Count of tests in this run that were freed.
} test_proto_stats_t;

#define DEBUG_LVL_SET if (test_verbose_level__ >= 3) fr_debug_lvl = L_DBG_LVL_4 + 1

static void test_mux(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx)
{
	fr_trunk_request_t	*treq;
	void			*preq;
	size_t			count = 0;
	int			fd = *(talloc_get_type_abort(fr_connection_get_handle(conn), int));
	ssize_t			slen;

	while ((treq = fr_trunk_connection_pop_request(NULL, &preq, NULL, tconn))) {
		test_proto_request_t	*our_preq = preq;
		count++;

		/*
		 *	Simulate a partial write
		 */
		if (our_preq && our_preq->signal_partial) {
			fr_trunk_request_signal_partial(treq);
			our_preq->signal_partial = false;
			break;
		}

		if (test_verbose_level__ >= 3) printf("%s - Wrote %p\n", __FUNCTION__, preq);

		slen = write(fd, &preq, sizeof(preq));
		if (slen < 0) return;
		if (slen == 0) return;
		if (slen < sizeof(preq)) abort();

		fr_trunk_request_signal_sent(treq);
	}
	TEST_CHECK(count > 0);
}

static void test_cancel_mux(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx)
{
	fr_trunk_request_t	*treq;
	void			*preq;
	size_t			count = 0;
	int			fd = *(talloc_get_type_abort(fr_connection_get_handle(conn), int));
	ssize_t			slen;

	/*
	 *	For cancellation we just do
	 */
	while ((treq = fr_trunk_connection_pop_cancellation(&preq, tconn))) {
		test_proto_request_t	*our_preq = preq;
		count++;

		/*
		 *	Simulate a partial cancel write
		 */
		if (our_preq && our_preq->signal_cancel_partial) {
			fr_trunk_request_signal_cancel_partial(treq);
			our_preq->signal_cancel_partial = false;
			break;
		}

		if (test_verbose_level__ >= 3) printf("%s - Wrote %p\n", __FUNCTION__, preq);
		slen = write(fd, &preq, sizeof(preq));
		if (slen < 0) {
			fr_perror("%s - %s", __FUNCTION__, fr_syserror(errno));
			return;
		}
		if (slen < 0) return;
		if (slen == 0) return;
		if (slen < sizeof(preq)) abort();

		fr_trunk_request_signal_cancel_sent(treq);
	}
	TEST_CHECK(count > 0);
}

static void test_demux(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx)
{
	int			fd = *(talloc_get_type_abort(fr_connection_get_handle(conn), int));
	test_proto_request_t	*preq;
	ssize_t			slen;

	do {
		slen = read(fd, &preq, sizeof(preq));
		if (slen <= 0) return;

		if (test_verbose_level__ >= 3) printf("%s - Read %p (%zu)\n", __FUNCTION__, preq, (size_t)slen);
		TEST_CHECK(slen == sizeof(preq));
		talloc_get_type_abort(preq, test_proto_request_t);

		if (preq->freed) continue;

		/*
		 *	Demuxer can handle both normal requests and cancelled ones
		 */
		switch (preq->treq->state) {
		case FR_TRUNK_REQUEST_CANCEL:
			break;		/* Hack - just ignore it */

		case FR_TRUNK_REQUEST_CANCEL_SENT:
			fr_trunk_request_signal_cancel_complete(preq->treq);
			break;

		case FR_TRUNK_REQUEST_SENT:
			fr_trunk_request_signal_complete(preq->treq);
			break;

		default:
			rad_assert(0);
			break;
		}
	} while (slen >= 0);
}

static void _conn_io_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags,
			   UNUSED int fd_errno, UNUSED void *uctx)
{

	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);

	fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
}

static void _conn_io_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t *tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_connection_signal_readable(tconn);
}

static void _conn_io_write(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t *tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_connection_signal_writable(tconn);
}

static void _conn_notify(fr_trunk_connection_t *tconn, fr_connection_t *conn,
			 fr_event_list_t *el,
			 fr_trunk_connection_event_t notify_on, void *uctx)
{
	int fd = *(talloc_get_type_abort(fr_connection_get_handle(conn), int));

	switch (notify_on) {
	case FR_TRUNK_CONN_EVENT_NONE:
		fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);
		break;

	case FR_TRUNK_CONN_EVENT_READ:
		fr_event_fd_insert(conn, el, fd, _conn_io_read, NULL, _conn_io_error, tconn);
		break;

	case FR_TRUNK_CONN_EVENT_WRITE:
		fr_event_fd_insert(conn, el, fd, NULL, _conn_io_write, _conn_io_error, tconn);
		break;

	case FR_TRUNK_CONN_EVENT_BOTH:
		fr_event_fd_insert(conn, el, fd, _conn_io_read, _conn_io_write, _conn_io_error, tconn);
		break;

	default:
		rad_assert(0);
	}
}

static void test_request_cancel(UNUSED fr_connection_t *conn, UNUSED fr_trunk_request_t *treq, void *preq,
				UNUSED fr_trunk_cancel_reason_t reason, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->cancelled = true;
	if (stats) stats->cancelled++;
}

static void test_request_complete(REQUEST *request, void *preq, void *rctx, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->completed = true;
	if (stats) stats->completed++;
}

static void test_request_fail(REQUEST *request, void *preq, void *rctx, void *uctx)
{
	test_proto_stats_t	*stats = uctx;
	test_proto_request_t	*our_preq;

	if (!preq) return;

	our_preq = talloc_get_type_abort(preq, test_proto_request_t);
	our_preq->failed = true;
	if (stats) stats->failed++;
}

static void test_request_free(REQUEST *request, void *preq, void *uctx)
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
static void _conn_io_loopback(fr_event_list_t *el, int fd, int flags, void *uctx)
{
	int		*our_h = talloc_get_type_abort(uctx, int);
	static uint8_t	buff[1024];
	static size_t	to_write;
	ssize_t		slen;

	rad_assert(fd == our_h[1]);

	while (true) {
		slen = read(fd, buff, sizeof(buff));
		if (slen <= 0) return;

		to_write = (size_t)slen;

		if (test_verbose_level__ >= 3) printf("%s - Read %zu bytes of data\n", __FUNCTION__, slen);
		slen = write(our_h[1], buff, (size_t)to_write);
		if (slen < 0) return;

		if (slen < to_write) {
			to_write -= slen;
			if (test_verbose_level__ >= 3) {
				printf("%s - Partial write %zu bytes left\n", __FUNCTION__, to_write);
			}
			return;
		} else {
			if (test_verbose_level__ >= 3) printf("%s - Wrote %zu bytes of data\n", __FUNCTION__, slen);
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
static fr_connection_state_t _conn_open(fr_event_list_t *el, void *h, void *uctx)
{
	int *our_h = talloc_get_type_abort(h, int);

	/*
	 *	This always needs to be inserted
	 */
	fr_event_fd_insert(our_h, el, our_h[1], _conn_io_loopback, NULL, NULL, our_h);

	return FR_CONNECTION_STATE_CONNECTED;
}

/** Allocate a basic socket pair
 *
 */
static fr_connection_state_t _conn_init(void **h_out, fr_connection_t *conn, UNUSED void *uctx)
{
	int *h;

	h = talloc_array(conn, int, 2);
	socketpair(AF_UNIX, SOCK_STREAM, 0, h);

	fr_nonblock(h[0]);
	fr_nonblock(h[1]);
	fr_connection_signal_on_fd(conn, h[0]);
	*h_out = h;

	return FR_CONNECTION_STATE_CONNECTING;
}

static fr_connection_t *test_setup_socket_pair_connection_alloc(fr_trunk_connection_t *tconn,
								fr_event_list_t *el,
								fr_connection_conf_t const *conn_conf,
								char const *log_prefix, void *uctx)
{
	fr_connection_conf_t cstat;

	if (!conn_conf) {
		memset(&cstat, 0, sizeof(cstat));
		conn_conf = &cstat;
	}
	return fr_connection_alloc(tconn, el,
				   &(fr_connection_funcs_t){
				   	.init = _conn_init,
				   	.open = _conn_open,
				   	.close = _conn_close
				   },
				   conn_conf,
				   log_prefix, tconn);
}

static fr_trunk_t *test_setup_trunk(TALLOC_CTX *ctx, fr_event_list_t *el, fr_trunk_conf_t *conf, bool with_cancel_mux, void *uctx)
{
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.connection_notify = _conn_notify,
					.request_prioritise = fr_pointer_cmp,
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

	return fr_trunk_alloc(ctx, el, &io_funcs, conf, "test_socket_pair", uctx, false);
}

static void test_socket_pair_alloc_then_free(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;

	fr_trunk_conf_t		conf = {
					.start = 2,
					.min = 2
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = fr_trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false);
	TEST_CHECK(trunk != NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	fr_event_service(el);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(ctx);
}

static void test_socket_pair_alloc_then_reconnect_then_free(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 2,
					.min = 2
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};
	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = fr_trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false);
	TEST_CHECK(trunk != NULL);

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);
	fr_event_service(el);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	fr_trunk_reconnect(trunk, FR_TRUNK_CONN_ACTIVE, FR_CONNECTION_FAILED);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);
	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(ctx);
}

static fr_connection_state_t _conn_init_no_signal(void **h_out, fr_connection_t *conn, void *uctx)
{
	int *h;

	h = talloc_array(conn, int, 2);
	socketpair(AF_UNIX, SOCK_STREAM, 0, h);
	*h_out = h;

	return FR_CONNECTION_STATE_CONNECTING;
}

static fr_connection_t *test_setup_socket_pair_1s_timeout_connection_alloc(fr_trunk_connection_t *tconn,
									   fr_event_list_t *el,
									   UNUSED fr_connection_conf_t const *conf,
									   char const *log_prefix, void *uctx)
{
	return fr_connection_alloc(tconn, el,
				   &(fr_connection_funcs_t){
				   	.init = _conn_init_no_signal,
				   	.open = _conn_open,
				   	.close = _conn_close
				   },
				   &(fr_connection_conf_t){
				   	.connection_timeout = NSEC * 1,
				   	.reconnection_delay = NSEC * 1
				   },
				   log_prefix, uctx);
}

static void test_socket_pair_alloc_then_connect_timeout(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_connection_t		*tconn;
	fr_trunk_conf_t		conf = {
					.start = 1,
					.min = 1
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_1s_timeout_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	TEST_CHECK(el != NULL);
	trunk = fr_trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false);
	TEST_CHECK(trunk != NULL);

	/*
	 *	Trigger connection timeout
	 */
	test_time_base += NSEC * 1.5;
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for the connection timeout */
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);	/* We didn't install the I/O events */

	tconn = fr_dlist_head(&trunk->connecting);
	TEST_CHECK(tconn != NULL);
	TEST_CHECK(fr_connection_get_num_timed_out(tconn->conn) == 0);
	TEST_CHECK(fr_connection_get_num_reconnected(tconn->conn) == 0);

	/*
	 *	Timeout should now fire
	 */
	fr_event_service(el);

	/*
	 *	Connection delay not implemented for timed out connections
	 */
	TEST_CHECK(fr_connection_get_num_timed_out(tconn->conn) == 1);
	TEST_CHECK(fr_connection_get_num_reconnected(tconn->conn) == 1);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(ctx);
}

static fr_connection_t *test_setup_socket_pair_1s_reconnection_delay_alloc(fr_trunk_connection_t *tconn,
									   fr_event_list_t *el,
									   UNUSED fr_connection_conf_t const *conn_conf,
									   char const *log_prefix, void *uctx)
{
	return fr_connection_alloc(tconn, el,
				   &(fr_connection_funcs_t){
				   	.init = _conn_init,
				   	.open = _conn_open,
				   	.close = _conn_close
				   },
				   &(fr_connection_conf_t){
				   	.connection_timeout = NSEC * 1,
				   	.reconnection_delay = NSEC * 1
				   },
				   log_prefix, uctx);
}

static void test_socket_pair_alloc_then_reconnect_check_delay(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_connection_t	*tconn;
	fr_trunk_conf_t		conf = {
					.start = 1,
					.min = 1
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_1s_reconnection_delay_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = fr_trunk_alloc(ctx, el, &io_funcs, &conf, "test_socket_pair", NULL, false);
	TEST_CHECK(trunk != NULL);

	/*
	 *	Trigger connection timeout
	 */
	test_time_base += NSEC * 1.5;
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for the connection timeout */
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* We didn't install the I/O events */
	fr_event_service(el);

	tconn = fr_heap_peek(trunk->active);
	TEST_CHECK(tconn != NULL);
	TEST_CHECK(fr_connection_get_num_timed_out(tconn->conn) == 0);
	TEST_CHECK(fr_connection_get_num_reconnected(tconn->conn) == 0);

	/*
	 *	Trigger reconnection
	 */
	fr_connection_signal_reconnect(tconn->conn, FR_CONNECTION_FAILED);
	test_time_base += NSEC * 0.5;

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* Reconnect delay not ready to fire yet, no I/O handlers installed */
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for reconnect delay */

	test_time_base += NSEC * 1;
	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 1);	/* Reconnect delay should now be ready to fire */

	fr_event_service(el);		/* Services the timer, which then triggers init */

	TEST_CHECK(fr_connection_get_num_timed_out(tconn->conn) == 0);
	TEST_CHECK(fr_connection_get_num_reconnected(tconn->conn) == 1);

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Should have a pending I/O event and a timer */

	talloc_free(trunk);
	talloc_free(ctx);
}

/*
 *	Test basic enqueue and dequeue
 */
static void test_enqueue_basic(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq = NULL;
	fr_trunk_enqueue_t	rcode;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

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
	rcode = fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;
	TEST_CHECK(rcode == FR_TRUNK_ENQUEUE_IN_BACKLOG);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_BACKLOG) == 1);

	/*
	 *	Allow the connection to establish
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_BACKLOG) == 0);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	/*
	 *	Should now be active and have a write event
	 *	inserted into the event loop.
	 */
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);

	/*
	 *	Trunk should be signalled the connection is
	 *	writable.
	 *
	 *	We should then:
	 *	- Pop a request from the pending queue.
	 *	- Write the request to the socket pair
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);

	/*
	 *	Gives the loopback function a chance
	 *	to read the data, and write it back.
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Trunk should be signalled the connection is
	 *	readable.
	 *
	 *	We should then:
	 *	- Read the (looped back) response.
	 *	- Signal the trunk that the connection is readable.
	 */
	events = fr_event_corral(el, test_time_base, false);
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
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_BACKLOG");
	talloc_free(trunk);
	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == false);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - FR_TRUNK_REQUEST_BACKLOG");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);	/* Request/rctx not guaranteed after signal, so can't call fail */
	TEST_CHECK(preq->cancelled == false);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);
	talloc_free(trunk);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_PARTIAL");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PARTIAL));

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - FR_TRUNK_REQUEST_PARTIAL");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PARTIAL) == 1);
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);	/* Request/rctx not guaranteed after signal, so can't call fail */
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);
	talloc_free(trunk);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - FR_TRUNK_REQUEST_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, false, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);	/* Request/rctx not guaranteed after signal, so can't call fail */
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);
	talloc_free(trunk);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_CANCEL_PARTIAL");
	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_cancel_partial = true;
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Send the cancellation request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_PARTIAL) == 1);

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_CANCEL_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Send the cancellation request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_SENT) == 1);

	talloc_free(trunk);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("trunk free after FR_TRUNK_REQUEST_CANCEL_COMPLETE");
	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Send the cancellation request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_SENT) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Loop the cancel request back round */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Read the cancel ACK (such that it is) */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);

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
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	preq->signal_cancel_partial = true;

	TEST_CASE("FR_TRUNK_REQUEST_PARTIAL -> FR_TRUNK_REQUEST_SENT");

	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection */
	fr_event_service(el);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PARTIAL) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Complete the partial request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);

	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	TEST_CASE("FR_TRUNK_REQUEST_CANCEL_PARTIAL -> FR_TRUNK_REQUEST_CANCEL_SENT");

	events = fr_event_corral(el, test_time_base, false);	/* Send partial cancel request */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_PARTIAL) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Complete the partial cancellation */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_SENT) == 1);

	events = fr_event_corral(el, test_time_base, false);	/* Loop the cancellation request back */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);

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
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 2,
					.min = 2,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq = NULL;
	fr_trunk_connection_t	*tconn;

	DEBUG_LVL_SET;
	fr_talloc_fault_setup();

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	preq->signal_cancel_partial = true;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection(s) */
	fr_event_service(el);

	TEST_CASE("dequeue on reconnect - FR_TRUNK_REQUEST_PENDING");

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	preq->treq = treq;

	tconn = treq->tconn;	/* Store the conn the request was assigned to */
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);

	/*
	 *	Should be reassigned to the other connection
	 */
	TEST_CHECK(tconn != treq->tconn);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	/*
	 *	Should be reassigned to the backlog
	 */
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_BACKLOG) == 1);
	TEST_CHECK(!treq->tconn);

	TEST_CASE("cancel on reconnect - FR_TRUNK_REQUEST_PARTIAL");

	/*
	 *	Allow the connections to reconnect
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Request should now be assigned back to one of the reconnected
	 *	connections.
	 */
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);
	TEST_CHECK(treq->tconn != NULL);

	events = fr_event_corral(el, test_time_base, false);	/* Send the request (partially) */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PARTIAL) == 1);

	/*
	 *	Reconnect the connection.
	 *
	 *	preq should pass through the cancel function,
	 *	then be re-assigned.
	 */
	tconn = treq->tconn;
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == false);

	preq->cancelled = false;		/* Reset */

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);
	TEST_CHECK(tconn != treq->tconn);	/* Ensure it moved */

	TEST_CASE("cancel on reconnect - FR_TRUNK_REQUEST_SENT");

	/*
	 *	Sent the request (fully)
	 */
	events = fr_event_corral(el, test_time_base, false);	/* Send the request (partially) */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);

	tconn = treq->tconn;
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	/*
	 *	Allow the connections to reconnect
	 *	and send the request.
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);
	TEST_CHECK(tconn != treq->tconn);	/* Ensure it moved */

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == false);

	preq->cancelled = false;		/* Reset */

	TEST_CASE("free on reconnect - FR_TRUNK_REQUEST_CANCEL");

	/*
	 *	Signal the request should be cancelled
	 */
	fr_trunk_request_signal_cancel(treq);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	/*
	 *	Requests in the cancel state, are
	 *	freed instead of being moved between
	 *	connections.
	 */
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);

	talloc_free(preq);

	/*
	 *	Allow the connection we just reconnected
	 *	top open so it doesn't interfere with
	 *	the next test.
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("free on reconnect - FR_TRUNK_REQUEST_CANCEL_PARTIAL");

	/*
	 *	Queue up a new request, and get it to the cancel-partial state.
	 */
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_cancel_partial = true;
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	/*
	 *	Sent the request (fully)
	 */
	events = fr_event_corral(el, test_time_base, false);	/* Send the request (fully) */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	fr_trunk_request_signal_cancel(treq);			/* Cancel the request */

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	/*
	 *	Transition to cancel partial
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_PARTIAL) == 1);

	/*
	 *	Trigger a reconnection
	 */
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);

	talloc_free(preq);

	/*
	 *	Allow the connection we just reconnected
	 *	top open so it doesn't interfere with
	 *	the next test.
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("free on reconnect - FR_TRUNK_REQUEST_CANCEL_SENT");

	/*
	 *	Queue up a new request, and get it to the cancel-sent state.
	 */
	preq = talloc_zero(NULL, test_proto_request_t);
	treq = NULL;
	fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	/*
	 *	Sent the request (fully)
	 */
	events = fr_event_corral(el, test_time_base, false);	/* Send the request (fully) */
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 1);
	fr_trunk_request_signal_cancel(treq);			/* Cancel the request */

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL) == 1);

	/*
	 *	Transition to cancel
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_CANCEL_SENT) == 1);

	/*
	 *	Trigger a reconnection
	 */
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);

	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == false);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);

	talloc_free(preq);

	talloc_free(ctx);
}

static void test_connection_start_on_enqueue(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 0,
					.min = 0,	/* No connections on start */
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	test_time_base += NSEC * 0.5;	/* Need to provide a timer starting value above zero */

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);

	TEST_CASE("C0 - Enqueue should spawn");
	fr_trunk_request_enqueue(&treq_a, trunk, NULL, preq, NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, !max_req_per_conn - Enqueue MUST NOT spawn");
	fr_trunk_request_enqueue(&treq_b, trunk, NULL, preq, NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Allow the connections to open
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);

	TEST_CASE("C1 active, !max_req_per_conn - Enqueue MUST NOT spawn");
	fr_trunk_request_enqueue(&treq_c, trunk, NULL, preq, NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 3);

	talloc_free(ctx);
	talloc_free(preq);
}

static void test_connection_rebalance_requests(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 2,
					.min = 2,	/* No connections on start */
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_connection_t	*tconn;
	fr_trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);
	preq = talloc_zero(NULL, test_proto_request_t);
	printf("Rebalance %p\n", preq);

	/*
	 *	Allow the connections to open
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Mark one of the connections as full, and
	 *	enqueue three requests on the other.
	 */
	tconn = fr_heap_peek(trunk->active);

	TEST_CASE("C2 connected, R0 - Signal inactive");
	fr_trunk_connection_signal_inactive(tconn);


	fr_trunk_request_enqueue(&treq_a, trunk, NULL, preq, NULL);
	fr_trunk_request_enqueue(&treq_b, trunk, NULL, preq, NULL);
	fr_trunk_request_enqueue(&treq_c, trunk, NULL, preq, NULL);

	TEST_CASE("C1 connected, C2 inactive, R3 - Enqueued");
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 3);
	TEST_CHECK(fr_trunk_request_count_by_connection(tconn, FR_TRUNK_REQUEST_ALL) == 0);

	/*
	 *	Now mark the previous connection as
	 *	active.  It should receive at least
	 *	one of the requests.
	 */
	TEST_CASE("C2 active, R3 - Signal active, should balance");
	fr_trunk_connection_signal_active(tconn);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 3);
	TEST_CHECK(fr_trunk_request_count_by_connection(tconn, FR_TRUNK_REQUEST_ALL) >= 1);

	talloc_free(ctx);
	talloc_free(preq);
}

#define ALLOC_REQ(_id) \
do { \
	treq_##_id = fr_trunk_request_alloc(trunk, NULL); \
	preq_##_id = talloc_zero(ctx, test_proto_request_t); \
	preq_##_id->treq = treq_##_id; \
} while (0)

static void test_connection_levels_max(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 0, 		/* No connections on start */
					.min = 0,
					.max = 2,
					.max_req_per_conn = 2,
					.target_req_per_conn = 2,	/* One request per connection */
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq_a, *preq_b, *preq_c, *preq_d, *preq_e;
	fr_trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL, *treq_d = NULL, *treq_e = NULL;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	test_time_base += NSEC * 0.5;	/* Need to provide a timer starting value above zero */

	trunk = test_setup_trunk(ctx, el, &conf, true, NULL);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0, R1 - Enqueue should spawn");
	ALLOC_REQ(a);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_a, trunk, NULL, preq_a, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Queuing another request should *NOT* start another connection
	 */
	TEST_CASE("C1 connecting, R2 - MUST NOT spawn");
	ALLOC_REQ(b);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_b, trunk, NULL, preq_b, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, R3 - MUST NOT spawn");
	ALLOC_REQ(c);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_c, trunk, NULL, preq_c, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, R4 - MUST NOT spawn");
	ALLOC_REQ(d);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_d, trunk, NULL, preq_d, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) ==1);

	TEST_CASE("C1 connecting, R5 - MUST NOT spawn, NO CAPACITY");
	ALLOC_REQ(e);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_e, trunk, NULL, preq_e, NULL) == FR_TRUNK_ENQUEUE_NO_CAPACITY);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Allowing connection to open
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("C1 active, R4 - Check pending 2");
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 2);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_BACKLOG) == 2);

	/*
	 *	Sending requests
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CASE("C1 active, R4 - Check sent 2");
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 2);

	/*
	 *	Looping I/O
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Receiving responses
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq_a->completed == true);
	TEST_CHECK(preq_a->failed == false);
	TEST_CHECK(preq_a->cancelled == false);
	TEST_CHECK(preq_a->freed == true);

	TEST_CHECK(preq_b->completed == true);
	TEST_CHECK(preq_b->failed == false);
	TEST_CHECK(preq_b->cancelled == false);
	TEST_CHECK(preq_b->freed == true);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 2);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_BACKLOG) == 0);

	TEST_CASE("C1 active, R0 - Check complete 2, pending 0");

	/*
	 *	Sending requests
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Looping I/O
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Receiving responses
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(preq_c->completed == true);
	TEST_CHECK(preq_c->failed == false);
	TEST_CHECK(preq_c->cancelled == false);
	TEST_CHECK(preq_c->freed == true);

	TEST_CHECK(preq_d->completed == true);
	TEST_CHECK(preq_d->failed == false);
	TEST_CHECK(preq_d->cancelled == false);
	TEST_CHECK(preq_d->freed == true);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);

	talloc_free(trunk);
	talloc_free(ctx);
}

static void test_connection_levels_alternating_edges(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.start = 0, 			/* No connections on start */
					.min = 0,
					.max = 0,
					.max_req_per_conn = 0,
					.target_req_per_conn = 2,	/* One request per connection */
					.manage_interval = NSEC * 0.1
				};

	test_proto_request_t	*preq_a, *preq_b, *preq_c;
	fr_trunk_request_t	*treq_a = NULL, *treq_b = NULL, *treq_c = NULL;
	test_proto_stats_t	stats;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	test_time_base += NSEC * 0.5;	/* Need to provide a timer starting value above zero */

	memset(&stats, 0, sizeof(stats));
	trunk = test_setup_trunk(ctx, el, &conf, true, &stats);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0, R1 - Enqueue should spawn");
	ALLOC_REQ(a);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_a, trunk, NULL, preq_a, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, R2 - MUST NOT spawn");
	ALLOC_REQ(b);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_b, trunk, NULL, preq_b, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);
	test_time_base += NSEC * 1;

	/*
	 *	Open connection
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 2);

	TEST_CASE("C1 connected, R3 - should spawn");
	ALLOC_REQ(c);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_c, trunk, NULL, preq_c, NULL) == FR_TRUNK_ENQUEUE_OK);
	test_time_base += NSEC * 1;

	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 3);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Complete requests
	 */
	test_time_base += NSEC * 1;

	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base += NSEC * 1;

	TEST_CASE("C1 connected, C2 connecting, R2 - MUST NOT spawn");
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 3);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	/*
	 *	Finish the last request, should close one connection
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base += NSEC * 1;

	TEST_CASE("C1 connected, R0");
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_ALL) == 0);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);

	/*
	 *	Requests now done, should close another connection
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	test_time_base += NSEC * 1;

	TEST_CASE("C0, R0");
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 0);

	TEST_CHECK(stats.completed == 3);
	TEST_CHECK(stats.failed == 0);
	TEST_CHECK(stats.cancelled == 0);
	TEST_CHECK(stats.freed == 3);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0, R1 - Enqueue should spawn");
	ALLOC_REQ(a);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_a, trunk, NULL, preq_a, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, R2 - MUST NOT spawn");
	ALLOC_REQ(b);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_b, trunk, NULL, preq_b, NULL) == FR_TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);
	test_time_base += NSEC * 1;

	/*
	 *	Open connection
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 2);

	TEST_CASE("C1 connected, R3 - should spawn");
	ALLOC_REQ(c);
	TEST_CHECK(fr_trunk_request_enqueue(&treq_c, trunk, NULL, preq_c, NULL) == FR_TRUNK_ENQUEUE_OK);
	test_time_base += NSEC * 1;

	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 3);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	talloc_free(trunk);
	talloc_free(ctx);
}

#undef fr_time	/* Need to the real time */
static void test_enqueue_and_io_speed(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	fr_trunk_conf_t		conf = {
					.start = 1,
					.min = 1,
					.max = 0,
					.max_req_per_conn = 0,
					.target_req_per_conn = 0,	/* One request per connection */
					.req_pool_headers = 1,
					.req_pool_size = sizeof(test_proto_request_t),
					.manage_interval = NSEC * 0.5
				};
	size_t			i = 0, requests = 100000;
	fr_time_t		enqueue_start = 0, enqueue_stop = 0, io_start = 0, io_stop = 0;
	fr_time_delta_t		enqueue_time, io_time, total_time;
	int			events;
	fr_trunk_request_t	**treq_array;
	test_proto_request_t	**preq_array;
	test_proto_stats_t	stats;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	test_time_base += NSEC * 0.5;	/* Need to provide a timer starting value above zero */

	memset(&stats, 0, sizeof(stats));
	trunk = test_setup_trunk(ctx, el, &conf, true, &stats);

	/*
	 *	Open the connections
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	/*
	 *	Build up a cache of requests
	 *	This prevents all mallocs on request enqueue.
	 *
	 *	When the server's running, this does represent
	 *	close to what we'd have as a steady state.
	 */
	MEM(treq_array = talloc_array(ctx, fr_trunk_request_t *, requests));
	for (i = 0; i < requests; i++) treq_array[i] = fr_trunk_request_alloc(trunk, NULL);
	for (i = 0; i < requests; i++) fr_trunk_request_free(treq_array[i]);

	MEM(preq_array = talloc_array(ctx, test_proto_request_t *, requests));

	TEST_CASE("Enqueue requests");
	enqueue_start = fr_time();
//	ProfilerStart(getenv("FR_PROFILE"));
	for (i = 0; i < requests; i++) {
		fr_trunk_request_t	*treq;
		test_proto_request_t	*preq = NULL;

		treq = fr_trunk_request_alloc(trunk, NULL);
		preq = talloc_zero(treq, test_proto_request_t);
		preq->treq = treq;
		fr_trunk_request_enqueue(&treq, trunk, NULL, preq, NULL);
	}
	enqueue_stop = fr_time();
	enqueue_time = enqueue_stop - enqueue_start;
	if (test_verbose_level__ >= 1) {
		INFO("Enqueue time %pV (%u rps) (%"PRIu64"/%"PRIu64")",
		     fr_box_time_delta(enqueue_time),
		     (uint32_t)(requests / ((float)enqueue_time / NSEC)),
		     trunk->req_alloc_new, trunk->req_alloc_reused);
	}

	TEST_CASE("Perform I/O operations");
	io_start = fr_time();
	while (true) {
		events = fr_event_corral(el, test_time_base, false);
		if (!events) break;
		fr_event_service(el);
	}
	io_stop = fr_time();
	io_time = io_stop - io_start;

	if (test_verbose_level__ >= 1) {
		INFO("I/O time %pV (%u rps)",
		     fr_box_time_delta(io_time),
		     (uint32_t)(requests / ((float)io_time / NSEC)));
	}

	if (test_verbose_level__ >= 1) {
		total_time = io_stop - enqueue_start;
		INFO("Total time %pV (%u rps)",
		     fr_box_time_delta(total_time),
		     (uint32_t)(requests / ((float)total_time / NSEC)));
	}

	TEST_CHECK(stats.completed == requests);
	TEST_CHECK(stats.failed == 0);
	TEST_CHECK(stats.cancelled == 0);
	TEST_CHECK(stats.freed == requests);

//	ProfilerStop();

	talloc_free(ctx);
}
#define fr_time test_time

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
	{ NULL }
};
