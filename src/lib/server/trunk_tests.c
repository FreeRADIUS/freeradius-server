static void *dummy_uctx = NULL;

#include <freeradius-devel/util/acutest.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef struct {
	fr_trunk_request_t	*treq;			//!< Trunk request.
	bool			cancelled;		//!< Seen by the cancelled callback.
	bool			completed;		//!< Seen by the complete callback.
	bool			failed;			//!< Seen by the failed callback.
	bool			freed;			//!< Seen by the free callback.
	bool			signal_partial;		//!< Muxer should signal that this request is partially written.
	bool			signal_cancel_partial;	//!< Muxer should signal that this request is partially cancelled.
} test_proto_request_t;

#define DEBUG_LVL_SET if (test_verbose_level__ >= 3) fr_debug_lvl = L_DBG_LVL_4 + 1

static void test_mux(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx)
{
	fr_trunk_request_t	*treq;
	void			*preq;
	size_t			count = 0;
	int			fd = *(talloc_get_type_abort(fr_connection_get_handle(conn), int));

	while ((treq = fr_trunk_connection_pop_request(&preq, NULL, tconn))) {
		test_proto_request_t	*our_preq = preq;
		count++;

		/*
		 *	Simulate a partial write
		 */
		if (our_preq->signal_partial) {
			fr_trunk_request_signal_partial(treq);
			our_preq->signal_partial = false;
			break;
		}

		write(fd, &preq, talloc_array_length(preq));
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

	/*
	 *	For cancellation we just do
	 */
	while ((treq = fr_trunk_connection_pop_cancellation(&preq, tconn))) {
		test_proto_request_t	*our_preq = preq;
		count++;

		/*
		 *	Simulate a partial cancel write
		 */
		if (our_preq->signal_cancel_partial) {
			fr_trunk_request_signal_cancel_partial(treq);
			our_preq->signal_cancel_partial = false;
			break;
		}

		write(fd, &preq, talloc_array_length(preq));
		fr_trunk_request_signal_cancel_sent(treq);
	}
	TEST_CHECK(count > 0);
}

static void test_demux(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx)
{
	int			fd = *(talloc_get_type_abort(fr_connection_get_handle(conn), int));
	test_proto_request_t	*preq;

	TEST_CHECK(read(fd, &preq, sizeof(preq)) == sizeof(preq));

	talloc_get_type_abort(preq, test_proto_request_t);

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
}

static void _conn_io_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags,
			   UNUSED int fd_errno, void *uctx)
{
	fr_trunk_connection_t *tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_connection_signal_reconnect(tconn);
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
				UNUSED fr_trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	test_proto_request_t	*our_preq = talloc_get_type_abort(preq, test_proto_request_t);

	our_preq->cancelled = true;
}

static void test_request_complete(REQUEST *request, void *preq, void *rctx, void *uctx)
{
	test_proto_request_t	*our_preq = talloc_get_type_abort(preq, test_proto_request_t);

	our_preq->completed = true;
}

static void test_request_fail(REQUEST *request, void *preq, void *rctx, void *uctx)
{
	test_proto_request_t	*our_preq = talloc_get_type_abort(preq, test_proto_request_t);

	our_preq->failed = true;
}

static void test_request_free(REQUEST *request, void *preq, void *uctx)
{
	test_proto_request_t	*our_preq = talloc_get_type_abort(preq, test_proto_request_t);

	our_preq->freed = true;
}

/** Whenever the second socket in a socket pair is readable, read all pending data, and write it back
 *
 */
static void _conn_io_loopback(fr_event_list_t *el, int fd, int flags, void *uctx)
{
	int		*our_h = talloc_get_type_abort(uctx, int);
	uint8_t		buff[1024];
	ssize_t		slen;

	rad_assert(fd == our_h[1]);

	slen = read(fd, buff, sizeof(buff));
	if (test_verbose_level__ >= 3) printf("Received %zu bytes of data, sending it back\n", slen);
	write(our_h[1], buff, (size_t)slen);
}

static void _conn_close(void *h, UNUSED void *uctx)
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

	rad_assert(h = talloc_array(conn, int, 2));
	rad_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, h) >= 0);
	rad_assert(h[0] >= 0);
	rad_assert(h[1] >= 0);
	fr_connection_signal_on_fd(conn, h[0]);
	*h_out = h;

	return FR_CONNECTION_STATE_CONNECTING;
}

static fr_connection_t *test_setup_socket_pair_connection_alloc(fr_trunk_connection_t *tconn, fr_event_list_t *el,
								char const *log_prefix, void *uctx)
{
	TEST_CHECK(uctx == &dummy_uctx);

	return fr_connection_alloc(tconn, el, 0, 0, _conn_init, _conn_open, _conn_close, log_prefix, tconn);
}

static fr_trunk_t *test_setup_trunk(TALLOC_CTX *ctx, fr_event_list_t *el, fr_trunk_conf_t *conf, bool with_cancel_mux)
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

	return fr_trunk_alloc(ctx, el, "test_socket_pair", false, conf, &io_funcs, &dummy_uctx);
}

static void test_socket_pair_alloc_then_free(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;

	fr_trunk_conf_t		conf = {
					.min_connections = 2
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
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
					.min_connections = 2
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_connection_alloc,
					.request_prioritise = fr_pointer_cmp,
				};
	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
	TEST_CHECK(trunk != NULL);

	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);
	fr_event_service(el);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, test_time_base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	fr_trunk_reconnect(trunk, FR_TRUNK_CONN_ACTIVE);
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

	rad_assert(h = talloc_array(conn, int, 2));
	rad_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, h) >= 0);
	rad_assert(h[0] >= 0);
	rad_assert(h[1] >= 0);
	*h_out = h;

	return FR_CONNECTION_STATE_CONNECTING;
}

static fr_connection_t *test_setup_socket_pair_1s_timeout_connection_alloc(fr_trunk_connection_t *tconn,
									   fr_event_list_t *el,
									   char const *log_prefix, void *uctx)
{
	TEST_CHECK(uctx == &dummy_uctx);

	return fr_connection_alloc(tconn, el, NSEC * 1, NSEC * 1, _conn_init_no_signal,
				   _conn_open, _conn_close, log_prefix, uctx);
}

static void test_socket_pair_alloc_then_connect_timeout(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_connection_t		*tconn;
	fr_trunk_conf_t		conf = {
					.min_connections = 1
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
	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
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
									   char const *log_prefix, void *uctx)
{
	TEST_CHECK(uctx == &dummy_uctx);

	return fr_connection_alloc(tconn, el, NSEC * 1, NSEC * 1,
				   _conn_init, _conn_open, _conn_close, log_prefix, uctx);
}

static void test_socket_pair_alloc_then_reconnect_check_delay(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_connection_t	*tconn;
	fr_trunk_conf_t		conf = {
					.min_connections = 1
				};
	fr_trunk_io_funcs_t	io_funcs = {
					.connection_alloc = test_setup_socket_pair_1s_reconnection_delay_alloc,
					.request_prioritise = fr_pointer_cmp,
				};

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	TEST_CHECK(el != NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
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
	fr_connection_signal_reconnect(tconn->conn);
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
					.min_connections = 1,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq;
	fr_trunk_enqueue_t	rcode;
	REQUEST			*request;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	trunk = test_setup_trunk(ctx, el, &conf, true);

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
	request = request_alloc(ctx);
	rcode = fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
	preq->treq = treq;
	TEST_CHECK(rcode == TRUNK_ENQUEUE_IN_BACKLOG);

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
					.min_connections = 1,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq;
	REQUEST			*request;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	request = request_alloc(ctx);

	trunk = test_setup_trunk(ctx, el, &conf, false);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_BACKLOG");
	talloc_free(trunk);
	TEST_CHECK(preq->completed == false);
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == false);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via signal - FR_TRUNK_REQUEST_BACKLOG");
	trunk = test_setup_trunk(ctx, el, &conf, false);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	trunk = test_setup_trunk(ctx, el, &conf, false);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	trunk = test_setup_trunk(ctx, el, &conf, false);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	trunk = test_setup_trunk(ctx, el, &conf, false);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	trunk = test_setup_trunk(ctx, el, &conf, false);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_cancel_partial = true;
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("cancellation via trunk free - FR_TRUNK_REQUEST_CANCEL_SENT");
	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
	TEST_CHECK(preq->failed == true);
	TEST_CHECK(preq->cancelled == true);
	TEST_CHECK(preq->freed == true);
	talloc_free(preq);

	TEST_CASE("trunk free after FR_TRUNK_REQUEST_CANCEL_COMPLETE");
	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);
	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
					.min_connections = 1,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq;
	REQUEST			*request;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	request = request_alloc(ctx);

	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	preq->signal_cancel_partial = true;

	TEST_CASE("FR_TRUNK_REQUEST_PARTIAL -> FR_TRUNK_REQUEST_SENT");

	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
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
					.min_connections = 2,
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq;
	REQUEST			*request;
	fr_trunk_connection_t	*tconn;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	request = request_alloc(ctx);

	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);
	preq->signal_partial = true;
	preq->signal_cancel_partial = true;

	events = fr_event_corral(el, test_time_base, false);	/* Connect the connection(s) */
	fr_event_service(el);

	TEST_CASE("dequeue on reconnect - FR_TRUNK_REQUEST_PENDING");

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);
	preq->treq = treq;

	tconn = treq->tconn;	/* Store the conn the request was assigned to */
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	fr_trunk_connection_signal_reconnect(tconn);

	/*
	 *	Should be reassigned to the other connection
	 */
	TEST_CHECK(tconn != treq->tconn);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 1);

	/*
	 *	Should be reassigned to the backlog
	 */
	fr_trunk_connection_signal_reconnect(treq->tconn);
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
	fr_trunk_connection_signal_reconnect(treq->tconn);

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
	fr_trunk_connection_signal_reconnect(treq->tconn);

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
	fr_trunk_connection_signal_reconnect(treq->tconn);

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

	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);

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
	fr_trunk_connection_signal_reconnect(treq->tconn);

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

	fr_trunk_request_enqueue(&treq, trunk, request, preq, NULL);

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
	fr_trunk_connection_signal_reconnect(treq->tconn);

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
					.min_connections = 0,	/* No connections on start */
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq_a, *treq_b, *treq_c;
	REQUEST			*request;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	request = request_alloc(ctx);

	test_time_base += NSEC * 0.5;	/* Need to provide a timer starting value above zero */

	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);

	TEST_CASE("C0 - Enqueue should spawn");
	fr_trunk_request_enqueue(&treq_a, trunk, request, preq, NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	TEST_CASE("C1 connecting, !max_requests_per_conn - Enqueue MUST NOT spawn");
	fr_trunk_request_enqueue(&treq_b, trunk, request, preq, NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Allow the connections to open
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);

	TEST_CASE("C1 active, !max_requests_per_conn - Enqueue MUST NOT spawn");
	fr_trunk_request_enqueue(&treq_c, trunk, request, preq, NULL);

	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_ACTIVE) == 1);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 3);

	talloc_free(ctx);
}

static void test_connection_rebalance_requests(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.min_connections = 2,	/* No connections on start */
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_connection_t	*tconn;
	fr_trunk_request_t	*treq_a, *treq_b, *treq_c;
	REQUEST			*request;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	request = request_alloc(ctx);

	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);

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
	fr_trunk_connection_signal_inactive(tconn);

	fr_trunk_request_enqueue(&treq_a, trunk, request, preq, NULL);
	fr_trunk_request_enqueue(&treq_b, trunk, request, preq, NULL);
	fr_trunk_request_enqueue(&treq_c, trunk, request, preq, NULL);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 3);
	TEST_CHECK(fr_trunk_request_count_by_connection(tconn, FR_TRUNK_REQUEST_ALL) == 0);

	/*
	 *	Now mark the previous connection as
	 *	active.  It should receive at least
	 *	one of the requests.
	 */
	fr_trunk_connection_signal_active(tconn);

	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 3);
	TEST_CHECK(fr_trunk_request_count_by_connection(tconn, FR_TRUNK_REQUEST_ALL) >= 1);

	talloc_free(ctx);
}

static void test_connection_levels(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_trunk_conf_t		conf = {
					.min_connections = 0,		/* No connections on start */
					.max_connections = 2,
					.max_requests_per_conn = 2,
					.req_per_conn_target = 2,	/* One request per connection */
					.manage_interval = NSEC * 0.5
				};
	test_proto_request_t	*preq;
	fr_trunk_request_t	*treq_a, *treq_b, *treq_c, *treq_d, *treq_e;
	REQUEST			*request;

	DEBUG_LVL_SET;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	request = request_alloc(ctx);

	test_time_base += NSEC * 0.5;	/* Need to provide a timer starting value above zero */

	trunk = test_setup_trunk(ctx, el, &conf, true);
	preq = talloc_zero(NULL, test_proto_request_t);

	/*
	 *	Queuing a request should start a connection.
	 */
	TEST_CASE("C0 - Enqueue should spawn");
	TEST_CHECK(fr_trunk_request_enqueue(&treq_a, trunk, request, preq, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Queuing another request should *NOT* start another connection
	 */
	TEST_CASE("C1 connecting, max_requests_per_conn 2 - Enqueue MUST NOT spawn");
	TEST_CHECK(fr_trunk_request_enqueue(&treq_b, trunk, request, preq, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 1);

	/*
	 *	Queuing another request should start another connection
	 *	as we're over the max_requests_per_conn value.
	 */
	TEST_CHECK(fr_trunk_request_enqueue(&treq_c, trunk, request, preq, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);

	/*
	 *	...and again
	 */
	TEST_CHECK(fr_trunk_request_enqueue(&treq_d, trunk, request, preq, NULL) == TRUNK_ENQUEUE_IN_BACKLOG);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);

	/*
	 *	Should fail.  We're at capacity.
	 */
	TEST_CHECK(fr_trunk_request_enqueue(&treq_e, trunk, request, preq, NULL) == TRUNK_ENQUEUE_NO_CAPACITY);
	TEST_CHECK(fr_trunk_connection_count_by_state(trunk, FR_TRUNK_CONN_CONNECTING) == 2);

	/*
	 *	Allow the connections to open
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_PENDING) == 4);

	/*
	 *	Send the requests
	 */
	events = fr_event_corral(el, test_time_base, false);
	fr_event_service(el);
	TEST_CHECK(fr_trunk_request_count_by_state(trunk, FR_TRUNK_CONN_ALL, FR_TRUNK_REQUEST_SENT) == 4);

	talloc_free(trunk);
	talloc_free(preq);
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
	{ "Spawn - Connection levels",			test_connection_levels },
	{ NULL }
};
