/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/**
 * $Id$
 *
 * @file src/lib/server/trunk.c
 * @brief A management API for bonding multiple connections together.
 *
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2019 The FreeRADIUS server project
 */

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS trunk->log_prefix

#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/trunk.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/table.h>

/** Used for sanity checks and to simplify freeing
 *
 * Allows us to track which
 */
typedef enum {
	FR_TRUNK_REQUEST_INIT		= 0x0000,	//!< Initial state.
	FR_TRUNK_REQUEST_BACKLOG	= 0x0001,	//!< In the backlog.
	FR_TRUNK_REQUEST_PENDING	= 0x0002,	//!< In the queue of a connection
							///< and is pending writing.
	FR_TRUNK_REQUEST_PARTIAL	= 0x0004,	//!< Some of the request was written to the socket,
							///< more of it should be written later.
	FR_TRUNK_REQUEST_SENT		= 0x0008,	//!< Was written to a socket.  Waiting for a response.
	FR_TRUNK_REQUEST_COMPLETE	= 0x0080,	//!< The request is complete.
	FR_TRUNK_REQUEST_FAILED		= 0x0100,	//!< The request failed.
	FR_TRUNK_REQUEST_CANCEL		= 0x0200,	//!< A request on a particular socket was cancel.
	FR_TRUNK_REQUEST_CANCEL_SENT	= 0x0400,	//!< We've informed the remote server that
							///< the request has been cancel.
	FR_TRUNK_REQUEST_CANCEL_COMPLETE= 0x0800,	//!< Remote server has acknowledged our cancellation.
} fr_trunk_request_state_t;

/** All request states
 *
 */
#define FR_TRUNK_REQUEST_ALL \
(\
	FR_TRUNK_REQUEST_BACKLOG | \
	FR_TRUNK_REQUEST_PENDING | \
	FR_TRUNK_REQUEST_PARTIAL | \
	FR_TRUNK_REQUEST_SENT | \
	FR_TRUNK_REQUEST_COMPLETE | \
	FR_TRUNK_REQUEST_FAILED | \
	FR_TRUNK_REQUEST_CANCEL | \
	FR_TRUNK_REQUEST_CANCEL_SENT | \
	FR_TRUNK_REQUEST_CANCEL_COMPLETE \
)

/** Wraps a normal request
 *
 */
struct fr_trunk_request_s {
	int32_t			heap_id;		//!< Used to track the request conn->pending heap.

	fr_dlist_t		list;			//!< Used to track the trunk request in the conn->sent
							///< or trunk->backlog request.

	fr_trunk_request_state_t state;			//!< Which list the request is currently located in.

	fr_trunk_t		*trunk;			//!< Trunk this request belongs to.

	fr_trunk_connection_t		*tconn;			//!< Connection this request belongs to.

	uint8_t			requeued;		//!< How many times this request has been re-enqueued.

	void			*preq;			//!< Data for the muxer to write to the connection.

	void			*rctx;			//!< Resume ctx of the module.

	REQUEST		        *request;		//!< The request that we're writing the data on behalf of.

	fr_trunk_cancel_reason_t cancel_reason;		//!< Why this request was cancelled.
};

/** Used for sanity checks and to track which list the connection is in
 *
 */
typedef enum {
	FR_TRUNK_CONN_INIT		= 0x00,		//!< In the initial state.
	FR_TRUNK_CONN_CONNECTING	= 0x01,		//!< Connection is connecting.
	FR_TRUNK_CONN_ACTIVE		= 0x02,		//!< Connection is connected and ready to service requests.
							///< This is active and not 'connected', because a connection
							///< can be 'connected' and 'full' or 'connected' and 'active'.
	FR_TRUNK_CONN_FAILED		= 0x04,		//!< Connection failed.  We now wait for it to enter the
							///< connecting and connected states.
	FR_TRUNK_CONN_FULL		= 0x08,		//!< Connection is full and can't accept any more requests.
	FR_TRUNK_CONN_DRAINING		= 0x10		//!< Connection will be closed once it has no more outstanding
							///< requests.
} fr_trunk_connection_state_t;

/** All connection states
 *
 */
#define FR_TRUNK_CONN_ALL \
(\
	FR_TRUNK_CONN_CONNECTING | \
	FR_TRUNK_CONN_ACTIVE | \
	FR_TRUNK_CONN_FAILED | \
	FR_TRUNK_CONN_FULL | \
	FR_TRUNK_CONN_DRAINING \
)

/** Associates sent and pending queues with a connection
 *
 */
struct fr_trunk_connection_s {
	int32_t			heap_id;		//!< Used to track the connection in the connected
							///< heap.

	fr_dlist_t		list;			//!< Used to track the connection in the connecting,
							///< full and failed lists.

	fr_trunk_connection_state_t	state;			//!< What state the connection is in.

	fr_trunk_t		*trunk;			//!< Trunk this connection belongs to.

	fr_connection_t		*conn;			//!< Connection we're wrapping.  This is the handle
							///< we use to register watchers, and control
							///< the connection.


	fr_heap_t		*pending;		//!< Requests waiting to be sent.

	fr_trunk_request_t	*partial;		//!< Partially written request.

	fr_dlist_head_t		sent;			//!< Sent request.

	fr_dlist_head_t		cancel;			//!< Requests in the cancel state.

	fr_dlist_head_t		cancel_sent;		//!< Requests we need to inform a remote server about.

	bool			signalled_full;		//!< Connection marked full because of signal.
							///< Will not automatically be marked active if
							///< the number of requests associated with it
							///< falls below max_requests_per_conn.

	bool			freeing;		//!< Conn is being freed, cancel_sent state should
							///< be skipped.
};

/** Main trunk management handle
 *
 */
struct fr_trunk_s {
	char const		*log_prefix;		//!< What to prepend to messages.

	fr_event_list_t		*el;			//!< Event list used by this trunk and the connection.

	fr_trunk_conf_t	const	*conf;			//!< Trunk common configuration.

	fr_heap_t		*backlog;		//!< The request backlog.  Requests we couldn't
							///< immediately assign to a connection.

	/** @name Connection lists
	 *
	 * A connection must always be in exactly one of these lists
	 * or trees.
	 *
	 * @{
 	 */
 	fr_dlist_head_t		connecting;		//!< Connections which are not yet in the open state.

	fr_heap_t		*active;		//!< Connections which can service requests.

	fr_dlist_head_t		full;			//!< Connections which have too many outstanding
							///< requests.

	fr_dlist_head_t		draining;		//!< Connections that will be freed once all their
							///< requests are complete.

	fr_dlist_head_t		failed;			//!< Connections that'll be reconnected shortly.
	/** @} */

	/** @name Last time an event occurred
	 * @{
 	 */
	fr_time_t		last_above_target;	//!< Last time average utilisation went above
							///< the target value.

	fr_time_t		last_below_target;	//!< Last time average utilisation went below
							///< the target value.

	fr_time_t		last_open;		//!< Last time the connection management
							///< function opened a connection.

	fr_time_t		last_closed;		//!< Last time the connection management
							///< function closed a connection.

	fr_time_t		last_connected;		//!< Last time a connection connected.

	fr_time_t		last_failed;		//!< Last time a connection failed.
	/** @} */

	/** @name Callbacks
	 * @{
 	 */
	fr_trunk_io_funcs_t	funcs;			//!< I/O functions.

	void			*in_handler;		//!< Which handler we're inside.

	void			*uctx;			//!< Uctx data to pass to alloc.
	/** @} */

	/** @name Timers
	 * @{
 	 */
 	fr_event_timer_t const	*manage_ev;		//!< Periodic connection management event.

	bool			freeing;		//!< Trunk is being freed, don't spawn new
							///< connections or re-enqueue.
};

static fr_table_num_ordered_t const fr_trunk_request_states[] = {
	{ "INIT",		FR_TRUNK_REQUEST_INIT		},
	{ "BACKLOG",		FR_TRUNK_REQUEST_BACKLOG	},
	{ "PENDING",		FR_TRUNK_REQUEST_PENDING	},
	{ "PARTIAL",		FR_TRUNK_REQUEST_PARTIAL	},
	{ "SENT",		FR_TRUNK_REQUEST_SENT		},
	{ "COMPLETE",		FR_TRUNK_REQUEST_COMPLETE	},
	{ "FAILED",		FR_TRUNK_REQUEST_FAILED		},
	{ "CANCEL",		FR_TRUNK_REQUEST_CANCEL		},
	{ "CANCEL-SENT",	FR_TRUNK_REQUEST_CANCEL_SENT	},
	{ "CANCEL-COMPLETE",	FR_TRUNK_REQUEST_CANCEL_COMPLETE}
};
static size_t fr_trunk_request_states_len = NUM_ELEMENTS(fr_trunk_request_states);

static fr_table_num_ordered_t const fr_trunk_connection_states[] = {
	{ "INIT",		FR_TRUNK_CONN_INIT		},
	{ "CONNECTING",		FR_TRUNK_CONN_CONNECTING	},
	{ "ACTIVE",		FR_TRUNK_CONN_ACTIVE		},
	{ "FULL",		FR_TRUNK_CONN_FULL		},
	{ "FAILED",		FR_TRUNK_CONN_FAILED		},
	{ "DRAINING",		FR_TRUNK_CONN_DRAINING		}
};
static size_t fr_trunk_connection_states_len = NUM_ELEMENTS(fr_trunk_connection_states);

static fr_table_num_ordered_t const fr_trunk_cancellation_reasons[] = {
	{ "none",		FR_TRUNK_CANCEL_REASON_NONE	},
	{ "signal",		FR_TRUNK_CANCEL_REASON_SIGNAL	},
	{ "move",		FR_TRUNK_CANCEL_REASON_MOVE	},
};
static size_t fr_trunk_cancellation_reasons_len = NUM_ELEMENTS(fr_trunk_cancellation_reasons);

#define CONN_STATE_TRANSITION(_new) \
do { \
	DEBUG4("Trunk connection changed state %s -> %s", \
	       fr_table_str_by_value(fr_trunk_connection_states, tconn->state, "<INVALID>"), \
	       fr_table_str_by_value(fr_trunk_connection_states, _new, "<INVALID>")); \
	tconn->state = _new; \
	trunk_requests_per_connnection(NULL, NULL, trunk, fr_time()); \
} while (0)

#define REQUEST_STATE_TRANSITION(_new) \
do { \
	DEBUG4("Trunk request changed state %s -> %s", \
	       fr_table_str_by_value(fr_trunk_request_states, treq->state, "<INVALID>"), \
	       fr_table_str_by_value(fr_trunk_request_states, _new, "<INVALID>")); \
	treq->state = _new; \
} while (0)

typedef enum {
	TRUNK_ENQUEUE_IN_BACKLOG = 1,		//!< Request should be enqueued in backlog
	TRUNK_ENQUEUE_OK = 0,			//!< Operation was successful.
	TRUNK_ENQUEUE_NO_CAPACITY = -1,		//!< At maximum number of connections,
						///< and no connection has capacity.
	TRUNK_ENQUEUE_DST_UNAVAILABLE = -2	//!< Destination is down
} fr_trunk_enqueue_t;

/** Call the cancel callback if set
 *
 */
#define DO_REQUEST_CANCEL(_treq, _reason) \
do { \
	if ((_treq)->trunk->funcs.request_cancel) { \
		(_treq)->trunk->in_handler = (void *)(_treq)->trunk->funcs.request_cancel; \
		DEBUG4("Calling funcs.request_cancel(%p, %p, %s, %p)", (_treq)->tconn->conn, (_treq), fr_table_str_by_value(fr_trunk_cancellation_reasons, (_reason), "<INVALID>"), (_treq)->trunk->uctx); \
		(_treq)->trunk->funcs.request_cancel((_treq)->tconn->conn, (_treq), (_reason), (_treq)->trunk->uctx); \
		(_treq)->trunk->in_handler = NULL; \
	} \
} while(0)

/** Call the complete callback (if set)
 *
 */
#define DO_REQUEST_COMPLETE(_treq) \
do { \
	if ((_treq)->trunk->funcs.request_complete) { \
		DEBUG4("Calling funcs.request_complete(%p, %p, %p, %p)", (_treq)->request, (_treq)->preq, (_treq)->rctx, (_treq)->trunk->uctx); \
		(_treq)->trunk->in_handler = (void *)(_treq)->trunk->funcs.request_complete; \
		(_treq)->trunk->funcs.request_complete((_treq)->request, (_treq)->preq, (_treq)->rctx, (_treq)->trunk->uctx); \
		(_treq)->trunk->in_handler = NULL; \
	} \
} while(0)

/** Call the fail callback (if set)
 *
 */
#define DO_REQUEST_FAIL(_treq) \
do { \
	if ((_treq)->trunk->funcs.request_fail) { \
		DEBUG4("Calling funcs.request_fail(%p, %p, %p, %p)", (_treq)->request, (_treq)->preq, (_treq)->rctx, (_treq)->trunk->uctx); \
		(_treq)->trunk->in_handler = (void *)(_treq)->trunk->funcs.request_fail; \
		(_treq)->trunk->funcs.request_fail((_treq)->request, (_treq)->preq, (_treq)->rctx, (_treq)->trunk->uctx); \
		(_treq)->trunk->in_handler = NULL; \
	} \
} while(0)

/** Write one or more requests to a connection
 *
 */
#define DO_REQUEST_MUX(_tconn) \
do { \
	DEBUG4("Calling funcs.request_mux(%p, %p, %p)", (_tconn), (_tconn)->conn, (_tconn)->trunk->uctx); \
	(_tconn)->trunk->in_handler = (void *)(_tconn)->trunk->funcs.request_mux; \
	(_tconn)->trunk->funcs.request_mux((_tconn), (_tconn)->conn, (_tconn)->trunk->uctx); \
	(_tconn)->trunk->in_handler = NULL; \
} while(0)

/** Read one or more requests from a connection
 *
 */
#define DO_REQUEST_DEMUX(_tconn) \
do { \
	DEBUG4("Calling funcs.request_demux(%p, %p, %p)", (_tconn), (_tconn)->conn, (_tconn)->trunk->uctx); \
	(_tconn)->trunk->in_handler = (void *)(_tconn)->trunk->funcs.request_demux; \
	(_tconn)->trunk->funcs.request_demux((_tconn), (_tconn)->conn, (_tconn)->trunk->uctx); \
	(_tconn)->trunk->in_handler = NULL; \
} while(0)

/** Write one or more cancellation requests to a connection
 *
 */
#define DO_REQUEST_CANCEL_MUX(_tconn) \
do { \
	DEBUG4("Calling funcs.request_cancel_mux(%p, %p, %p)", (_tconn), (_tconn)->conn, (_tconn)->trunk->uctx); \
	(_tconn)->trunk->in_handler = (void *)(_tconn)->trunk->funcs.request_cancel_mux; \
	(_tconn)->trunk->funcs.request_cancel_mux((_tconn), (_tconn)->conn, (_tconn)->trunk->uctx); \
	(_tconn)->trunk->in_handler = NULL; \
} while(0)

#define IN_HANDLER(_trunk)		(((_trunk)->in_handler) != NULL)
#define IN_REQUEST_MUX(_trunk)		(((_trunk)->funcs.request_mux) && ((_trunk)->in_handler == (void *)(_trunk)->funcs.request_mux))
#define IN_REQUEST_DEMUX(_trunk)	(((_trunk)->funcs.request_demux) && ((_trunk)->in_handler == (void *)(_trunk)->funcs.request_demux))
#define IN_REQUEST_CANCEL_MUX(_trunk)	(((_trunk)->funcs.request_cancel_mux) && ((_trunk)->in_handler == (void *)(_trunk)->funcs.request_cancel_mux))

/** Remove the current request from the partial slot
 *
 */
#define REQUEST_EXTRACT_PARTIAL(_treq) \
do { \
	rad_assert((_treq)->tconn->partial == treq); \
	tconn->partial = NULL; \
} while (0)

/** Remove the current request from the pending list
 *
 */
#define REQUEST_EXTRACT_PENDING(_treq) \
do { \
	int _ret; \
	_ret = fr_heap_extract((_treq)->tconn->pending, _treq); \
	if (!fr_cond_assert(_ret == 0)) return; \
} while (0)

/** Remove the current request from the backlog
 *
 */
#define REQUEST_EXTRACT_BACKLOG(_treq) \
do { \
	int _ret; \
	_ret = fr_heap_extract((_treq)->trunk->backlog, _treq); \
	if (!fr_cond_assert(_ret == 0)) return; \
} while (0)

/** Reorder the connections in the active heap
 *
 */
#define CONN_REORDER(_tconn) \
do { \
	int _ret; \
	_ret = fr_heap_extract((_tconn)->trunk->active, (_tconn)); \
	if (!fr_cond_assert(_ret == 0)) return; \
	fr_heap_insert((_tconn)->trunk->active, (_tconn)); \
} while (0)

static void trunk_request_enter_backlog(fr_trunk_request_t *treq);
static void trunk_request_enter_pending(fr_trunk_request_t *treq, fr_trunk_connection_t *tconn);
static void trunk_request_enter_partial(fr_trunk_request_t *treq);
static void trunk_request_enter_sent(fr_trunk_request_t *treq);
static void trunk_request_enter_failed(fr_trunk_request_t *treq);
static void trunk_request_enter_complete(fr_trunk_request_t *treq);
static void trunk_request_enter_cancel(fr_trunk_request_t *treq, fr_trunk_cancel_reason_t reason);
static void trunk_request_enter_cancel_sent(fr_trunk_request_t *treq);
static void trunk_request_enter_cancel_complete(fr_trunk_request_t *treq);

static uint32_t trunk_requests_per_connnection(uint16_t *conn_count_out, uint32_t *req_conn_out,
					       fr_trunk_t *trunk, fr_time_t now);

static int trunk_connection_spawn(fr_trunk_t *trunk, fr_time_t now);
static inline void trunk_connection_auto_full(fr_trunk_connection_t *tconn);
static inline void trunk_connection_auto_active(fr_trunk_connection_t *tconn);
static inline void trunk_connection_readable(fr_trunk_connection_t *tconn);
static inline void trunk_connection_writable(fr_trunk_connection_t *tconn);
static void trunk_connection_enter_full(fr_trunk_connection_t *tconn);
static void trunk_connection_enter_draining(fr_trunk_connection_t *tconn);
static void trunk_connection_enter_active(fr_trunk_connection_t *tconn);

static void trunk_manage(fr_trunk_t *trunk, fr_time_t now);
static void _trunk_manage_timer(fr_event_list_t *el, fr_time_t now, void *uctx);
static inline uint16_t trunk_connection_total(fr_trunk_t *trunk, int states);
static inline uint64_t trunk_requests_total(fr_trunk_t *trunk, int states);
static void trunk_backlog_drain(fr_trunk_t *trunk);

/** Remove a request from all connection lists
 *
 * A common function used by init, fail, complete state functions
 * to disassociate a request from a connection in preparation for
 * freeing or reassignment.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_remove_from_conn(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t	*tconn = treq->tconn;
	fr_trunk_t		*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_INIT:
		return;	/* Not associated with connection */

	case FR_TRUNK_REQUEST_BACKLOG:
		REQUEST_EXTRACT_BACKLOG(treq);
		break;

	case FR_TRUNK_REQUEST_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case FR_TRUNK_REQUEST_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		break;

	case FR_TRUNK_REQUEST_SENT:
		fr_dlist_remove(&tconn->sent, treq);
		break;

	case FR_TRUNK_REQUEST_CANCEL:
		fr_dlist_remove(&tconn->cancel, treq);
		break;

	case FR_TRUNK_REQUEST_CANCEL_SENT:
		fr_dlist_remove(&tconn->cancel_sent, treq);
		break;

	default:
		rad_assert(0);
		break;
	}

	switch (tconn->state){
	case FR_TRUNK_CONN_FULL:
		trunk_connection_auto_active(tconn);	/* Check if we can switch back to active */
		/* FALL-THROUGH */

	case FR_TRUNK_CONN_ACTIVE:
		CONN_REORDER(tconn);
		break;

	default:
		break;
	}

	treq->tconn = NULL;
}

/** Transition a request back to the init state, in preparation for re-assignment
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_init(fr_trunk_request_t *treq)
{
	fr_trunk_t	*trunk = treq->trunk;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_INIT:
		return;

	case FR_TRUNK_REQUEST_BACKLOG:
		REQUEST_EXTRACT_BACKLOG(treq);
		break;

	case FR_TRUNK_REQUEST_PENDING:
	case FR_TRUNK_REQUEST_CANCEL:
	case FR_TRUNK_REQUEST_CANCEL_SENT:
		trunk_request_remove_from_conn(treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_INIT);
}

/** Transition a request to the backlog state, adding it to the backlog of the trunk
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_backlog(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_INIT:
		break;

	case FR_TRUNK_REQUEST_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case FR_TRUNK_REQUEST_CANCEL:
		fr_dlist_remove(&tconn->cancel, treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_BACKLOG);
	fr_heap_insert(trunk->backlog, treq);	/* Insert into the backlog heap */

	/*
	 *	To reduce latency, if there's no connections
	 *      in the connecting state, call the trunk manage
	 *	function immediately.
	 *
	 *	Likewise, if there's draining connections
	 *	which could be moved back to active.
	 */
	if ((trunk_connection_total(treq->trunk, FR_TRUNK_CONN_CONNECTING) == 0) ||
	    (trunk_connection_total(treq->trunk, FR_TRUNK_CONN_DRAINING) > 0)) trunk_manage(treq->trunk, fr_time());
}

/** Transition a request to the pending state, adding it to the backlog of an active connection
 *
 * @param[in] treq	to trigger a state change for.
 * @param[in] tconn	to enqueue the request on.
 */
static void trunk_request_enter_pending(fr_trunk_request_t *treq, fr_trunk_connection_t *tconn)
{
	fr_trunk_t	*trunk = treq->trunk;

	rad_assert(tconn->trunk == trunk);
	rad_assert(tconn->state == FR_TRUNK_CONN_ACTIVE);

	switch (treq->state) {
	case FR_TRUNK_REQUEST_INIT:
		break;

	case FR_TRUNK_REQUEST_BACKLOG:
		REQUEST_EXTRACT_BACKLOG(treq);
		break;

	case FR_TRUNK_REQUEST_CANCEL:	/* Moved from another connection */
		fr_dlist_remove(&tconn->cancel, treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_PENDING);
	fr_heap_insert(tconn->pending, treq);
	treq->tconn = tconn;

	/*
	 *	Check if we need to automatically transition the
	 *	connection to full.
	 */
	trunk_connection_auto_full(tconn);

	/*
	 *	Reorder the connection in the heap
	 *	now it has an additional request.
	 */
	CONN_REORDER(tconn);
}

/** Transition a request to the partial state, indicating that is has been partially sent
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_partial(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_INIT:
		break;

	case FR_TRUNK_REQUEST_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	rad_assert(!tconn->partial);
	tconn->partial = treq;

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_PARTIAL);
}

/** Transition a request to the sent state, indicating that it's been sent in its entirety
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_sent(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_PENDING:
		REQUEST_EXTRACT_PENDING(treq);
		break;

	case FR_TRUNK_REQUEST_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_SENT);
	fr_dlist_insert_tail(&tconn->sent, treq);
}

/** Transition a request to the cancel state, placing it in a connection's cancellation list
 *
 * If a request_cancel_send callback is provided, that callback will
 * be called periodically for requests which were cancelled due to
 * a signal.
 *
 * The request_cancel_send callback will dequeue cancelled requests
 * and inform a remote server that the result is no longer required.
 *
 * A request must enter this state before being added to the backlog
 * of another connection if it's been sent or partially sent.
 *
 * @param[in] treq	to trigger a state change for.
 * @param[in] reason	Why the request was cancelled.
 *			Should be one of:
 *			- FR_TRUNK_CANCEL_REASON_SIGNAL request cancelled
 *			  because of a signal from the interpreter.
 *			- FR_TRUNK_CANCEL_REASON_MOVE request cancelled
 *			  because the connection failed and it needs
 *			  to be assigned to a new connection.
 */
static void trunk_request_enter_cancel(fr_trunk_request_t *treq, fr_trunk_cancel_reason_t reason)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_PARTIAL:
		REQUEST_EXTRACT_PARTIAL(treq);
		DO_REQUEST_CANCEL(treq, reason);
		break;

	case FR_TRUNK_REQUEST_SENT:
		fr_dlist_remove(&tconn->sent, treq);
		DO_REQUEST_CANCEL(treq, reason);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_CANCEL);
	fr_dlist_insert_tail(&tconn->cancel, treq);
	treq->cancel_reason = reason;

	/*
	 *	Our treq is no longer bound to an actual
	 *      REQUEST *, as we can't guarantee the
	 *	lifetime of the original REQUEST *.
	 */
	if (treq->cancel_reason == FR_TRUNK_CANCEL_REASON_SIGNAL) treq->request = NULL;
}

/** Transition a request to the cancel_sent state, placing it in a connection's cancel_sent list
 *
 * The request_demux function is then responsible for signalling
 * that the cancel request is complete when the remote server
 * acknowledges the cancellation request.
 *
 * @param[in] treq	to trigger a state change for.
 */
static void trunk_request_enter_cancel_sent(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;
	rad_assert(trunk->funcs.request_cancel_mux);
	rad_assert(treq->cancel_reason == FR_TRUNK_CANCEL_REASON_SIGNAL);

	switch (treq->state) {
	case FR_TRUNK_REQUEST_CANCEL:	/* The only valid state cancel_sent can be reached from */
		fr_dlist_remove(&tconn->cancel, treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_CANCEL_SENT);
	fr_dlist_insert_tail(&tconn->cancel_sent, treq);
}

/** Cancellation was acked, the request is complete, free it
 *
 * The API client will not be informed, as the original REQUEST *
 * will likely have been freed by this point.
 *
 * @param[in] treq	to mark as complete.
 */
static void trunk_request_enter_cancel_complete(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;
	if (!fr_cond_assert(!treq->request)) return;	/* Only a valid state for REQUEST * which have been cancelled */

	switch (treq->state) {
	case FR_TRUNK_REQUEST_CANCEL_SENT:		/* The only valid state cancel_sent can be reached from */
		fr_dlist_remove(&tconn->cancel_sent, treq);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	trunk_request_remove_from_conn(treq);

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_CANCEL_COMPLETE);
	talloc_free(treq);	/* Free the request */
}

/** Request completed successfully, inform the API client and free the request
 *
 * @param[in] treq	to mark as complete.
 */
static void trunk_request_enter_complete(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;

	trunk_request_remove_from_conn(treq);

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_COMPLETE);
	DO_REQUEST_COMPLETE(treq);
	talloc_free(treq);	/* Free the request */
}

/** Request failed, inform the API client and free the request
 *
 * @param[in] treq	to mark as failed.
 */
static void trunk_request_enter_failed(fr_trunk_request_t *treq)
{
	fr_trunk_connection_t *tconn = treq->tconn;
	fr_trunk_t	*trunk = treq->trunk;

	if (!fr_cond_assert(!tconn || (tconn->trunk == trunk))) return;

	trunk_request_remove_from_conn(treq);

	REQUEST_STATE_TRANSITION(FR_TRUNK_REQUEST_FAILED);
	DO_REQUEST_FAIL(treq);
	talloc_free(treq);	/* Free the request */
}

/** Shift requests in the specified states onto new connections
 *
 */
static void trunk_connection_requests_dequeue(fr_dlist_head_t *out, fr_trunk_connection_t *tconn, int states)
{
	fr_trunk_request_t	*treq;

#define DEQUEUE_ALL(_src_list) \
	while ((treq = fr_dlist_head(_src_list))) { \
		trunk_request_enter_init(treq); \
		fr_dlist_insert_head(out, treq); \
	}

	/*
	 *	Don't need to do anything with
	 *	cancellation requests.
	 */
	if (states & FR_TRUNK_REQUEST_CANCEL) DEQUEUE_ALL(&tconn->cancel);

	/*
	 *	...same with cancel inform
	 */
	if (states & FR_TRUNK_REQUEST_CANCEL_SENT) DEQUEUE_ALL(&tconn->cancel_sent);

	/*
	 *	...and pending.
	 */
	if (states & FR_TRUNK_REQUEST_PENDING) DEQUEUE_ALL(&tconn->cancel_sent);

	/*
	 *	Cancel partially sent requests
	 */
	if (states & FR_TRUNK_REQUEST_PARTIAL) {
		treq = tconn->partial;
		if (treq) {
			trunk_request_enter_cancel(treq, FR_TRUNK_CANCEL_REASON_MOVE);
			trunk_request_enter_init(treq);
		}
	}

	/*
	 *	Cancel sent requests
	 */
	if (states & FR_TRUNK_REQUEST_SENT) {
		while ((treq = fr_dlist_head(&tconn->sent))) {
			trunk_request_enter_cancel(treq, FR_TRUNK_CANCEL_REASON_MOVE);
		}
		DEQUEUE_ALL(&tconn->cancel);	/* Dequeue the now cancelled requests */
	}
}

/** Check to see if a trunk request can be enqueued
 *
 * @param[out] tconn_out	Connection the request may be enqueued on.
 * @param[in] trunk		To enqueue requests on.
 * @param[in] request		associated with the treq (if any).
 * @return
 *	- TRUNK_ENQUEUE_OK			caller should enqueue request on provided tconn.
 *	- TRUNK_ENQUEUE_IN_BACKLOG		Request should be queued in the backlog.
 *	- TRUNK_ENQUEUE_NO_CAPACITY		Unable to enqueue request as we have no spare
 *						connections or backlog space.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE		Can't enqueue because the destination is
 *						unreachable.
 */
static fr_trunk_enqueue_t trunk_request_check_enqueue(fr_trunk_connection_t **tconn_out, fr_trunk_t *trunk,
						      REQUEST *request)
{
	fr_trunk_connection_t		*tconn;
	uint64_t		limit;

	/*
	 *	If we have an active connection then
	 *	return that.
	 */
	tconn = fr_heap_peek(trunk->active);
	if (tconn) {
		*tconn_out = tconn;
		return TRUNK_ENQUEUE_OK;
	}

	/*
	 *	Unlike the connection pool, we don't need
	 *	to drive any internal processes by feeding
	 *	it requests.
	 *
	 *	If the last event to occur was a failure
	 *	we refuse to enqueue new requests until
	 *	one or more connections comes online.
	 */
	if (trunk->last_failed >= trunk->last_connected) {
		ROPTIONAL(RWARN, WARN, "Refusing to enqueue requests or drain backlog - "
			  "No active connections and last event was a connection failure");

		return TRUNK_ENQUEUE_DST_UNAVAILABLE;
	}

	/*
	 *	Only enforce if we're limiting maximum
	 *	number of connections, and maximum
	 *	number of requests per connection.
	 */
	limit = trunk->conf->max_connections * (uint64_t)trunk->conf->max_requests_per_conn;
	if ((limit > 0) && (trunk_requests_total(trunk, FR_TRUNK_CONN_ALL) >= limit)) {
		ROPTIONAL(RWARN, WARN, "Refusing to enqueue requests or drain backlog - "
			  "No active connections and limit of %"PRIu64" requests reached", limit);

		return TRUNK_ENQUEUE_NO_CAPACITY;
	}

	return TRUNK_ENQUEUE_IN_BACKLOG;
}

/** Enqueue a request which has never been assigned to a connection or was previously cancelled
 *
 * @param[in] treq	to re enqueue.  Muse have been removed
 *			from its existing connection with
 *			#trunk_connection_requests_dequeue.
 * @return
 *	- TRUNK_ENQUEUE_OK			Request was re-enqueued.
 *	- TRUNK_ENQUEUE_NO_CAPACITY		Request enqueueing failed because we're at capacity.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE		Enqueuing failed for some reason.
 *      					Usually because the connection to the resource is down.
 */
static fr_trunk_enqueue_t trunk_request_enqueue_existing(fr_trunk_request_t *treq)
{
	fr_trunk_t			*trunk = treq->trunk;
	fr_trunk_connection_t			*tconn = NULL;
	fr_trunk_enqueue_t	rcode;

	/*
	 *	Must *NOT* still be assigned to another connection
	 */
	rad_assert(!treq->tconn);

	rcode = trunk_request_check_enqueue(&tconn, trunk, treq->request);
	switch (rcode) {
	case TRUNK_ENQUEUE_OK:
		trunk_request_enter_pending(treq, tconn);
		if (trunk->conf->always_writable) trunk_connection_writable(tconn);
		break;

	case TRUNK_ENQUEUE_IN_BACKLOG:
		/*
		 *	No more connections and request
		 *	is already in the backlog.
		 *
		 *	Signal our caller it should stop
		 *	trying to drain the backlog.
		 */
		if (treq->state == FR_TRUNK_REQUEST_BACKLOG) return TRUNK_ENQUEUE_NO_CAPACITY;
		trunk_request_enter_backlog(treq);
		break;

	default:
		break;
	}

	return rcode;
}

/** Remove requests in specified states from a connection, attempting to distribute them to new connections
 *
 * @param[in] tconn	To remove requests from.
 * @param[in] states	One or more states or'd together.
 */
static void trunk_connection_requests_requeue(fr_trunk_connection_t *tconn, int states)
{
	fr_dlist_head_t		to_requeue;
	fr_trunk_request_t	*treq = NULL;

	fr_dlist_talloc_init(&to_requeue, fr_trunk_request_t, list);

	/*
	 *	Remove requests from the connection
	 */
	trunk_connection_requests_dequeue(&to_requeue, tconn, states);

	/*
	 *	Loop over all the requests we gathered
	 *	and redistribute them to new connections.
	 */
	while ((treq = fr_dlist_next(&to_requeue, treq))) {
		fr_trunk_request_t *prev;

		prev = fr_dlist_remove(&to_requeue, treq);
		switch (trunk_request_enqueue_existing(treq)) {
		case TRUNK_ENQUEUE_OK:
			break;

		case TRUNK_ENQUEUE_IN_BACKLOG:
			rad_assert(0);
			/* FALL-THROUGH */
		/*
		 *	If we fail to re-enqueue then
		 *	there's nothing to do except
		 *	fail the request.
		 */
		case TRUNK_ENQUEUE_DST_UNAVAILABLE:
		case TRUNK_ENQUEUE_NO_CAPACITY:
			trunk_request_enter_failed(treq);
			break;
		}
		treq = prev;
	}

	/*
	 *	If the trunk was draining, it wasn't counted
	 *	in the requests per connection stats, so
	 *	we need to update those values now.
	 */
	if (tconn->state == FR_TRUNK_CONN_DRAINING) {
		trunk_requests_per_connnection(NULL, NULL, tconn->trunk, fr_time());
	}
}

/** If the trunk request is freed then update the target requests
 *
 * @param[in] treq	request.
 */
static int _trunk_request_free(fr_trunk_request_t *treq)
{
	fr_trunk_t	*trunk = treq->trunk;

	/*
	 *	The only valid states a trunk request can be
	 *	freed from.
	 */
	switch (treq->state) {
	case FR_TRUNK_REQUEST_INIT:
	case FR_TRUNK_REQUEST_COMPLETE:
	case FR_TRUNK_REQUEST_FAILED:
		break;

	case FR_TRUNK_REQUEST_CANCEL:
	case FR_TRUNK_REQUEST_CANCEL_SENT:
		break;

	default:
		if (!fr_cond_assert(0)) return 1;
	}

	/*
	 *	There should usually always be a trunk...
	 */
	if (unlikely(!treq->trunk)) return 0;

	/*
	 *	Update the last above/below target stats
	 *	We only do this when we alloc or free
	 *	connections, or on connection
	 *      state changes.
	 */
	trunk_requests_per_connnection(NULL, NULL, treq->trunk, fr_time());

	/*
	 *	Finally, free the protocol request.
	 */
	if (trunk->funcs.request_free) trunk->funcs.request_free(treq->request, treq->preq, treq->trunk->uctx);

	return 0;
}

/** Allocates a new trunk request
 *
 * @param[in] trunk	to add request to.
 * @param[in] request	to wrap in a trunk request (treq).
 * @param[in] preq	The we need to write to the connection.
 *			This is separate to the rctx, as the rctx may
 *			be used to track state across multiple calls,
 *			whereas the preq is specific to a single request
 * @param[in] rctx	Used to store the current state of the module
 */
static fr_trunk_request_t *trunk_request_alloc(fr_trunk_t *trunk, REQUEST *request, void *preq, void *rctx)
{
	fr_trunk_request_t *treq;

	MEM(treq = talloc_zero(request, fr_trunk_request_t));
	treq->trunk = trunk;
	treq->preq = preq;
	treq->rctx = rctx;
	treq->state = FR_TRUNK_REQUEST_INIT;
	talloc_set_destructor(treq, _trunk_request_free);

	/*
	 *	Update the last above/below target stats
	 *	We only do this when we alloc or free
	 *	connections, or on connection
	 *      state changes.
	 */
	trunk_requests_per_connnection(NULL, NULL, trunk, fr_time());

	return treq;
}

/** Signal a partial write
 *
 * Where there's high load, and the outbound write buffer is full
 *
 * @param[in] treq	to signal state change for.
 */
void fr_trunk_request_signal_partial(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->trunk),
				"%s can only be called from within request_mux handler", __FUNCTION__)) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_SENT:
		trunk_request_enter_partial(treq);
		break;

	default:
		return;
	}
}

/** Signal that the request was written to a connection successfully
 *
 * @param[in] treq	to signal state change for.
 */
void fr_trunk_request_signal_sent(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->trunk),
				"%s can only be called from within request_mux handler", __FUNCTION__)) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_SENT:
		trunk_request_enter_sent(treq);
		break;

	default:
		return;
	}
}

/** Signal that a trunk request is complete
 *
 * The API client will be informed that the request is now complete.
 */
void fr_trunk_request_signal_complete(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->trunk) || IN_REQUEST_DEMUX(treq->trunk),
				"%s can only be called from within request_mux or request_demux handlers",
				__FUNCTION__)) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_SENT:
	case FR_TRUNK_REQUEST_PENDING:	/* Got immediate response, i.e. cached */
		trunk_request_enter_complete(treq);
		break;

	default:
		return;
	}
}

/** Signal that a trunk request failed
 *
 * The API client will be informed that the request has failed.
 */
void fr_trunk_request_signal_fail(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(IN_REQUEST_MUX(treq->trunk) || IN_REQUEST_DEMUX(treq->trunk),
				"%s can only be called from within request_mux or request_demux handlers",
				__FUNCTION__)) return;

	trunk_request_enter_failed(treq);
}

/** Cancel a trunk request
 *
 * Request can be in any state, but requests to cancel if the request
 * is not in the FR_TRUNK_REQUEST_PARTIAL or FR_TRUNK_REQUEST_SENT state
 * will be ignored.
 *
 * @param[in] treq	to signal state change for.
 */
void fr_trunk_request_signal_cancel(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(!IN_HANDLER(treq->trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_PARTIAL:
	case FR_TRUNK_REQUEST_SENT:
		trunk_request_enter_cancel(treq, FR_TRUNK_CANCEL_REASON_SIGNAL);
		break;

	default:
		break;
	}
}

/** Signal that a remote server has been notified of the cancellation
 *
 * Called from request_cancel_mux to indicate that the datastore has
 * been informed that the response is no longer needed.
 *
 * @param[in] treq	to signal state change for.
 */
void fr_trunk_request_signal_cancel_sent(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(IN_REQUEST_CANCEL_MUX(treq->trunk),
				"%s can only be called from within request_cancel_mux handler", __FUNCTION__)) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_CANCEL:
		trunk_request_enter_cancel_sent(treq);
		break;

	default:
		break;
	}
}

/** Signal that a remote server acked our cancellation
 *
 * Called from request_demux to indicate that it got an
 * ack for the cancellation.
 *
 * @param[in] treq	to signal state change for.
 */
void fr_trunk_request_signal_cancel_complete(fr_trunk_request_t *treq)
{
	if (!fr_cond_assert_msg(IN_REQUEST_DEMUX(treq->trunk) || IN_REQUEST_CANCEL_MUX(treq->trunk),
				"%s can only be called from within request_demux or request_cancel_mux handlers",
				__FUNCTION__)) return;

	switch (treq->state) {
	case FR_TRUNK_REQUEST_CANCEL_SENT:
		trunk_request_enter_cancel_complete(treq);
		break;

	default:
		break;
	}
}

/** Pop a cancellation request off a connection's cancellation queue
 *
 * The request we return is advanced by the request moving out of the
 * cancel state and into the cancel_sent or cancel_complete state.
 *
 * One of these signalling functions must be called after the request
 * has been popped:
 *
 * - #fr_trunk_request_signal_cancel_sent
 *   The remote datastore has been informed, but we need to wait for
 *   acknowledgement.  The #request_demux function must handle the
 *   acks calling #fr_trunk_request_signal_cancel_complete when an
 *   ack is received.
 *
 * - #fr_trunk_request_signal_cancel_complete
 *   The request was cancelled and we don't need to wait, clean it
 *   up immediately.
 *
 * @param[out] treq_out		The dequeued cancellation request.
 * @param[in] tconn		Connection to drain cancellation request from.
 */
fr_trunk_request_t *fr_trunk_connection_pop_cancellation(fr_trunk_connection_t *tconn)
{
	if (!fr_cond_assert_msg(IN_REQUEST_CANCEL_MUX(tconn->trunk),
				"%s can only be called from within request_cancel_mux handler",
				__FUNCTION__)) return NULL;

	return fr_dlist_head(&tconn->cancel);
}

/** Pop a request off a connection's pending queue
 *
 * The request we return is advanced by the request moving out of the
 * partial or pending states, when the mux function signals us.
 *
 * If the same request is returned again and again, it means the muxer
 * isn't actually doing anything with the request we returned, and it's
 * and error in the muxer code.
 *
 * One of these signalling functions must be used after the request has
 * been popped:
 *
 * - #fr_trunk_request_signal_complete
 *   The request was completed. Either we got a synchronous response,
 *   or we knew the response without contacting an external server (cache).
 *
 * - #fr_trunk_request_signal_fail
 *   Failed muxing the request due to a permanent issue, i.e. an invalid
 *   request.
 *
 * - #fr_trunk_request_signal_partial
 *   Wrote part of a request.  This request will be returned on the next
 *   call to this function so that the request_mux function can finish
 *   sending it.
 *
 * - #fr_trunk_request_signal_sent
 *   Successfully sent a request.
 *
 * @param[in] tconn	to pop a request from.
 */
fr_trunk_request_t *fr_trunk_connection_pop_request(fr_trunk_connection_t *tconn)
{
	if (!fr_cond_assert_msg(IN_REQUEST_MUX(tconn->trunk),
				"%s can only be called from within request_mux handler",
				__FUNCTION__)) return NULL;

	if (tconn->partial) return tconn->partial;
	return fr_heap_peek(tconn->pending);
}

/** Enqueue a request that needs data written to the trunk
 *
 * @param[out] treq_out	A trunk request handle.  Should be stored and used to
 *			cancel the trunk request on signal.
 * @param[in] trunk	to enqueue request on.
 * @param[in] request	to enqueue.
 * @param[in] preq	Protocol request to write out.  Will be freed when
 *			treq is freed. MUST NOT BE PARENTED.
 * @param[in] data	to write.
 * @return
 *	- TRUNK_ENQUEUE_OK.
 *	- TRUNK_ENQUEUE_IN_BACKLOG.
 *	- TRUNK_ENQUEUE_NO_CAPACITY.
 *	- TRUNK_ENQUEUE_DST_UNAVAILABLE
 */
fr_trunk_enqueue_t fr_trunk_request_enqueue(fr_trunk_request_t **treq_out, fr_trunk_t *trunk,
					    REQUEST *request, void *preq, void *rctx)
{
	fr_trunk_connection_t		*tconn;
	fr_trunk_request_t	*treq;
	fr_trunk_enqueue_t	rcode;

	if (!fr_cond_assert_msg(!IN_HANDLER(trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return -2;

	/*
	 *	If delay_spawn was set, we may need
	 *	to insert the timer for the connection manager.
	 */
	if (unlikely(!trunk->manage_ev)) {
		fr_event_timer_in(trunk, trunk->el, &trunk->manage_ev, trunk->conf->manage_interval,
				  _trunk_manage_timer, trunk);
	}

	rcode = trunk_request_check_enqueue(&tconn, trunk, request);
	switch (rcode) {
	case TRUNK_ENQUEUE_OK:
		MEM(treq = trunk_request_alloc(trunk, request, preq, rctx));
		trunk_request_enter_pending(treq, tconn);
		if (trunk->conf->always_writable) trunk_connection_writable(tconn);
		break;

	case TRUNK_ENQUEUE_IN_BACKLOG:
		MEM(treq = trunk_request_alloc(trunk, request, preq, rctx));
		trunk_request_enter_backlog(treq);
		break;

	default:
		return rcode;
	}
	*treq_out = treq;

	return rcode;
}

/** Return the total number of requests associated with a trunk connection
 *
 * @param[in] tconn	to return request count for.
 * @return The number of requests in any state, associated with a tconn.
 */
static inline uint32_t trunk_connection_requests_total(fr_trunk_connection_t const *tconn)
{
	uint32_t total = 0;

	total += fr_heap_num_elements(tconn->pending);
	total += tconn->partial ? 1 : 0;
	total += fr_dlist_num_elements(&tconn->sent);
	total += fr_dlist_num_elements(&tconn->cancel);
	total += fr_dlist_num_elements(&tconn->cancel_sent);	/* Contentious ? */

	return total;
}

/** Return the total number of connections in the specified states
 *
 * @param[in] trunk	to retrieve counts for.
 * @param[in] states	One or more states or'd together.
 */
static inline uint16_t trunk_connection_total(fr_trunk_t *trunk, int states)
{
	uint16_t total = 0;

	if (states & FR_TRUNK_CONN_CONNECTING) total += fr_dlist_num_elements(&trunk->connecting);
	if (states & FR_TRUNK_CONN_ACTIVE) total += fr_heap_num_elements(trunk->active);
	if (states & FR_TRUNK_CONN_FULL) total += fr_dlist_num_elements(&trunk->full);
	if (states & FR_TRUNK_CONN_FAILED) total += fr_dlist_num_elements(&trunk->failed);
	if (states & FR_TRUNK_CONN_DRAINING) total += fr_dlist_num_elements(&trunk->draining);

	return total;
}

/** Automatically mark a connection as full
 *
 * @param[in] tconn	to potentially mark as full.
 */
static inline void trunk_connection_auto_full(fr_trunk_connection_t *tconn)
{
	fr_trunk_t	*trunk = tconn->trunk;
	uint32_t	total;

	if (!trunk->conf->max_requests_per_conn ||
	    tconn->signalled_full ||
	    (tconn->state != FR_TRUNK_CONN_ACTIVE)) return;

	total = trunk_connection_requests_total(tconn);
	if (total >= trunk->conf->max_requests_per_conn) trunk_connection_enter_full(tconn);
}

/** Automatically mark a connection as active
 *
 * @param[in] tconn	to potentially mark as active.
 */
static inline void trunk_connection_auto_active(fr_trunk_connection_t *tconn)
{
	fr_trunk_t	*trunk = tconn->trunk;
	uint32_t	total;

	if (!trunk->conf->max_requests_per_conn ||
	    tconn->signalled_full ||
	    (tconn->state != FR_TRUNK_CONN_FULL)) return;

	total = trunk_connection_requests_total(tconn);
	if (total < trunk->conf->max_requests_per_conn) trunk_connection_enter_active(tconn);
}

/** A connection is readable.  Call the request_demux function to read pending requests
 *
 */
static inline void trunk_connection_readable(fr_trunk_connection_t *tconn)
{
	fr_trunk_t *trunk = tconn->trunk;

	DO_REQUEST_DEMUX(tconn);
}

/** A connection is writable.  Call the request_mux function to write pending requests
 *
 */
static inline void trunk_connection_writable(fr_trunk_connection_t *tconn)
{
	fr_trunk_t *trunk = tconn->trunk;

	/*
	 *	Call the cancel_sent function (if we have one)
	 *      to inform a backend datastore we no longer
	 *	care about the result
	 */
	if (trunk->funcs.request_cancel_mux && !fr_dlist_empty(&tconn->cancel)) DO_REQUEST_CANCEL_MUX(tconn);

	if (!tconn->partial && !fr_heap_num_elements(tconn->pending)) return;

	DO_REQUEST_MUX(tconn);
}

/** Transition a connection to the full state
 *
 * Called whenever a trunk connection is at the maximum number of requests.
 * Removes the connection from the connected heap, and places it in the
 * full list.
 */
static void trunk_connection_enter_full(fr_trunk_connection_t *tconn)
{
	fr_trunk_t		*trunk = tconn->trunk;
	int			ret;

	switch (tconn->state) {
	case FR_TRUNK_CONN_ACTIVE:
		ret = fr_heap_extract(trunk->active, tconn);
		if (!fr_cond_assert(ret == 0)) return;
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	CONN_STATE_TRANSITION(FR_TRUNK_CONN_FULL);
	fr_dlist_insert_head(&trunk->full, tconn);
}

/** Transition a connection to the draining state
 *
 * Removes the connection from the active heap so it won't
 * be assigned any new connections.
 */
static void trunk_connection_enter_draining(fr_trunk_connection_t *tconn)
{
	fr_trunk_t		*trunk = tconn->trunk;
	int			ret;

	switch (tconn->state) {
	case FR_TRUNK_CONN_ACTIVE:
		ret = fr_heap_extract(trunk->active, tconn);
		if (!fr_cond_assert(ret == 0)) return;
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	CONN_STATE_TRANSITION(FR_TRUNK_CONN_DRAINING);
	fr_dlist_insert_head(&trunk->draining, tconn);

	/*
	 *	Immediately re-enqueue all pending
	 *	requests, so the connection is drained
	 *	quicker.
	 */
	trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_PENDING);
}

/** Transition a connection back to the active state
 *
 * This should only be called on a connection which is in the
 * full state.  This is *NOT* to signal the a connection has
 * just become active from the connecting state.
 */
static void trunk_connection_enter_active(fr_trunk_connection_t *tconn)
{
	fr_trunk_t		*trunk = tconn->trunk;

	switch (tconn->state) {
	case FR_TRUNK_CONN_FULL:
		fr_dlist_remove(&trunk->full, tconn);
		break;

	case FR_TRUNK_CONN_DRAINING:
		fr_dlist_remove(&trunk->draining, tconn);
		break;

	case FR_TRUNK_CONN_CONNECTING:
		fr_dlist_remove(&trunk->connecting, tconn);
		rad_assert(trunk_connection_requests_total(tconn) == 0);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	CONN_STATE_TRANSITION(FR_TRUNK_CONN_ACTIVE);
	MEM(fr_heap_insert(trunk->active, tconn) == 0);	/* re-insert into the active heap*/

	/*
	 *	We place requests into the backlog
	 *      because there were no connections
	 *	available to handle them.
	 *
	 *	If a connection has become active
	 *	chances are those backlogged requests
	 *      can now be enqueued, so try and do
	 *	that now.
	 *
	 *	If there's requests sitting in the
	 *	backlog indefinitely, it's because
	 *	they were inserted there erroneously
	 *	when there were active connections
	 *	which could have handled them.
	 */
	trunk_backlog_drain(trunk);
}

/** Connection transitioned to the connecting state
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The fr_trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_connecting(UNUSED fr_connection_t *conn, UNUSED fr_connection_state_t state, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_t	*trunk = tconn->trunk;

	switch (tconn->state) {
	case FR_TRUNK_CONN_INIT:
		break;

	case FR_TRUNK_CONN_FAILED:
		fr_dlist_remove(&trunk->failed, tconn);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	/*
	 *	If a connection just entered the
	 *	connecting state, it should have
	 *	no requests associated with it.
	 */
	rad_assert(trunk_connection_requests_total(tconn) == 0);

	CONN_STATE_TRANSITION(FR_TRUNK_CONN_CONNECTING);
	fr_dlist_insert_head(&trunk->connecting, tconn);	/* MUST remain a head insertion for reconnect logic */
}

/** Connection transitioned to the connected state
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The fr_trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_connected(UNUSED fr_connection_t *conn, UNUSED fr_connection_state_t state, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_t	*trunk = tconn->trunk;

	/*
	 *	If a connection was just connected,
	 *	it should have no requests associated
	 *	with it.
	 */
	rad_assert(trunk_connection_requests_total(tconn) == 0);

 	trunk_connection_enter_active(tconn);

 	/*
	 *	Set here, as the active state can
	 *	be transitioned to from full and
	 *	draining too.
	 */
	trunk->last_connected = fr_time();
}

/** Connection failed after it was connected
 *
 * Reflect the connection state change in the lists we use to track connections.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The fr_trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_closed(UNUSED fr_connection_t *conn, UNUSED fr_connection_state_t state, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_t	*trunk = tconn->trunk;
	int		ret;

	switch (tconn->state) {
	case FR_TRUNK_CONN_INIT:			/* Failed during handle initialisation */
		break;

	case FR_TRUNK_CONN_ACTIVE:
		ret = fr_heap_extract(trunk->active, tconn);
		if (!fr_cond_assert(ret == 0)) return;
		trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_ALL);
		break;

	case FR_TRUNK_CONN_CONNECTING:
		fr_dlist_remove(&trunk->connecting, tconn);
		rad_assert(trunk_connection_requests_total(tconn) == 0);
		break;

	case FR_TRUNK_CONN_FULL:
		fr_dlist_remove(&trunk->full, tconn);
		trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_ALL);
		break;

	case FR_TRUNK_CONN_DRAINING:
		fr_dlist_remove(&trunk->draining, tconn);
		trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_ALL);
		break;

	default:
		if (!fr_cond_assert(0)) return;
	}

	/*
	 *	There should be no requests left on this
	 *	connection.  They should have all been
	 *	moved off or failed.
	 */
	rad_assert(trunk_connection_requests_total(tconn) == 0);

	CONN_STATE_TRANSITION(FR_TRUNK_CONN_FAILED);
	fr_dlist_insert_head(&trunk->failed, tconn);	/* MUST remain a head insertion for reconnect logic */
}

/** Connection failed to connect before it was connected
 *
 */
static void _trunk_connection_on_failed(UNUSED fr_connection_t *conn, UNUSED fr_connection_state_t state, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_t	*trunk = tconn->trunk;

	/*
	 *	Other conditions will be handled by on_closed
	 */
	if (tconn->state != FR_TRUNK_CONN_CONNECTING) return;
	fr_dlist_remove(&trunk->connecting, tconn);

	/*
	 *	As the connection never actually connected
	 *	it shouldn't have any requests.
	 */
	rad_assert(trunk_connection_requests_total(tconn) == 0);

	CONN_STATE_TRANSITION(FR_TRUNK_CONN_FAILED);
	fr_dlist_insert_head(&trunk->failed, tconn);	/* MUST remain a head insertion for reconnect logic */

	trunk->last_failed = fr_time();
}

/** Connection transitioned to the halted state
 *
 * Remove the connection remove all lists, as it's likely about to be freed.
 *
 * Setting the trunk back to the init state ensures that if the code is ever
 * refactored and #fr_connection_signal_reconnect is used after a connection
 * is halted, then everything is maintained in a valid state.
 *
 * @note This function is only called from the connection API as a watcher.
 *
 * @param[in] conn	The connection which changes state.
 * @param[in] state	The connection is now in.
 * @param[in] uctx	The fr_trunk_connection_t wrapping the connection.
 */
static void _trunk_connection_on_halted(UNUSED fr_connection_t *conn, UNUSED fr_connection_state_t state, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_trunk_t	*trunk = tconn->trunk;
	int		ret;

	switch (tconn->state) {
	case FR_TRUNK_CONN_ACTIVE:
		ret = fr_heap_extract(trunk->active, tconn);
		if (!fr_cond_assert(ret == 0)) return;
		trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_ALL);
		break;

	case FR_TRUNK_CONN_FULL:
		fr_dlist_remove(&trunk->full, tconn);
		trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_ALL);
		break;

	case FR_TRUNK_CONN_CONNECTING:
		fr_dlist_remove(&trunk->connecting, tconn);
		break;

	case FR_TRUNK_CONN_FAILED:
		fr_dlist_remove(&trunk->failed, tconn);
		break;

	case FR_TRUNK_CONN_DRAINING:
		fr_dlist_remove(&trunk->draining, tconn);
		trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_ALL);
		break;

	case FR_TRUNK_CONN_INIT:	/* Nothing to do */
		break;
	}

	/*
	 *	There should be no requests left on this
	 *	connection.  They should have all been
	 *	moved off or failed.
	 */
	rad_assert(trunk_connection_requests_total(tconn) == 0);

	/*
	 *	It began life in the init state,
	 *	and will end life in the init state.
	 */
	CONN_STATE_TRANSITION(FR_TRUNK_CONN_INIT);
}

/** Free a connection
 *
 * Enforces orderly free order of children of the tconn
 */
static int _trunk_connection_free(fr_trunk_connection_t *tconn)
{

	int		ret;

	/*
	 *	Loop over all the requests we gathered
	 *	and transition them to the failed state,
	 *	freeing them.
	 *
	 *	Usually, requests will be re-queued when
	 *	a connection enters the closed state,
	 *	but in this case because the whole trunk
	 *	is being freed, we don't bother, and
	 *	just signal to the API client that the
	 *	requests failed.
	 */
	if (tconn->trunk->freeing) {
		fr_dlist_head_t	to_fail;
		fr_trunk_request_t *treq = NULL;

		fr_dlist_talloc_init(&to_fail, fr_trunk_request_t, list);

		/*
		 *	Remove requests from this connection
		 */
		trunk_connection_requests_dequeue(&to_fail, tconn, FR_TRUNK_REQUEST_ALL);
		while ((treq = fr_dlist_next(&to_fail, treq))) {
			fr_trunk_request_t *prev;

			prev = fr_dlist_remove(&to_fail, treq);
			trunk_request_enter_failed(treq);
			treq = prev;
		}
	}

	tconn->freeing = true;
	ret = talloc_free(tconn->conn);
	tconn->conn = NULL;
	if (ret != 0) tconn->freeing = false;

	return ret;
}

/** Attempt to spawn a new connection
 *
 * Calls the API client's alloc() callback to create a new fr_connection_t,
 * then inserts the connection into the 'connecting' list.
 *
 * @param[in] trunk	to spawn connection in.
 */
static int trunk_connection_spawn(fr_trunk_t *trunk, fr_time_t now)
{
	fr_trunk_connection_t	*tconn;

	/*
	 *	Call the API client's callback to create
	 *	a new fr_connection_t.
	 */
	MEM(tconn = talloc_zero(trunk, fr_trunk_connection_t));
	tconn->trunk = trunk;

	DEBUG4("Calling funcs.connection_alloc(%p, %p, \"%s\", %p)", tconn, trunk->el, trunk->log_prefix, trunk->uctx);
	tconn->conn = trunk->funcs.connection_alloc(tconn, trunk->el, trunk->log_prefix, trunk->uctx);
	if (!tconn->conn) {
		ERROR("Failed creating new connection");
		talloc_free(tconn);
		return -1;
	}
	tconn->state = FR_TRUNK_CONN_INIT;

	MEM(tconn->pending = fr_heap_talloc_create(tconn, trunk->funcs.request_prioritise,
						   fr_trunk_request_t, heap_id));
	fr_dlist_talloc_init(&tconn->sent, fr_trunk_request_t, list);
	fr_dlist_talloc_init(&tconn->cancel_sent, fr_trunk_request_t, list);

	/*
	 *	OK, we have the connection, now setup watch
	 *	points so we know when it changes state.
	 *
	 *	This lets us automatically move the tconn
	 *	between the different lists in the trunk
	 *	with minimum extra code.
	 */
	fr_connection_add_watch_post(tconn->conn, FR_CONNECTION_STATE_CONNECTING,
				     _trunk_connection_on_connecting, false, tconn);	/* After init() has been called */

	fr_connection_add_watch_post(tconn->conn, FR_CONNECTION_STATE_CONNECTED,
				     _trunk_connection_on_connected, false, tconn);	/* After open() has been called */

	fr_connection_add_watch_pre(tconn->conn, FR_CONNECTION_STATE_CLOSED,
				    _trunk_connection_on_closed, false, tconn);	/* Before close() has been called */

	fr_connection_add_watch_pre(tconn->conn, FR_CONNECTION_STATE_FAILED,
				    _trunk_connection_on_failed, false, tconn);

	fr_connection_add_watch_post(tconn->conn, FR_CONNECTION_STATE_HALTED,
				     _trunk_connection_on_halted, false, tconn);	/* About to be freed */

	fr_connection_signal_init(tconn->conn);	/* annnnd GO! */

	talloc_set_destructor(tconn, _trunk_connection_free);

	trunk->last_open = now;

	return 0;
}

/** Signal that a trunk connection is writable
 *
 * Should be called from the 'write' I/O handler to signal that requests should be enqueued.
 *
 * @param[in] tconn to signal.
 */
void fr_trunk_connection_signal_writable(fr_trunk_connection_t *tconn)
{
	if (!fr_cond_assert_msg(!IN_HANDLER(tconn->trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return;

	trunk_connection_writable(tconn);
}

/** Signal that a trunk connection is readable
 *
 * Should be called from the 'read' I/O handler to signal that requests should be dequeued.
 *
 * @param[in] tconn to signal.
 */
void fr_trunk_connection_signal_readable(fr_trunk_connection_t *tconn)
{
	if (!fr_cond_assert_msg(!IN_HANDLER(tconn->trunk),
				"%s cannot be called within a handler", __FUNCTION__)) return;

	trunk_connection_readable(tconn);
}

/** Signal a trunk connection is full and cannot accept more requests
 *
 * @param[in] tconn to signal.
 */
void fr_trunk_connection_signal_full(fr_trunk_connection_t *tconn)
{
	/* Can be called anywhere */

	switch (tconn->state) {
	case FR_TRUNK_CONN_ACTIVE:
		tconn->signalled_full = true;		/* Prevent tconn from automatically being marked as active */
		trunk_connection_enter_full(tconn);
		break;

	default:
		return;
	}
}

/** Signal a trunk connection is no longer full
 *
 * @param[in] tconn to signal.
 */
void fr_trunk_connection_signal_active(fr_trunk_connection_t *tconn)
{
	/* Can be called anywhere */

	tconn->signalled_full = false;			/* Allow full/active state to be changed automatically again */
	switch (tconn->state) {
	case FR_TRUNK_CONN_FULL:
		trunk_connection_auto_active(tconn);	/* Mark as active if it should be active */
		break;

	default:
		return;
	}
}

/** Implements the algorithm we use to manage requests per connection levels
 *
 * This is executed periodically using a timer event, and opens/closes
 * connections.
 *
 * The aim is to try and keep the request per connection level in a sweet spot,
 * where there's enough outstanding work for the connection/pipelining to work
 * efficiently, but not so much so that we encounter increased latency.
 *
 * In the request enqueue and dequeue functions we record every time the
 * average number of requests per connection goes above the target count
 * and record every time the average number of requests per connection goes
 * below the target count.
 *
 * This may sound expensive, but in all cases we're just summing counters.
 * CPU time required does not increase with additional requests, only with
 * large numbers of connections.
 *
 * If we do encounter scaling issues, we can always maintain the counters
 * as aggregates as an optimisation later.
 *
 * If when the management function runs, the trunk was above the target
 * most recently, we:
 * - Return if we've been in this state for a shorter period than 'open_delay'.
 * - Return if we're at max_connections.
 * - Return if opening a new connection will take us below the load target.
 * - Return if we last opened a connection within 'open_delay'.
 * - Otherwise we attempt to open a new connection.
 *
 * If the trunk we below the target most recently, we:
 * - Return if we've been in this state for a shorter period than 'close_delay'.
 * - Return if we're at min_connections.
 * - Return if we have no connections.
 * - Close a connection if min_connections is 0, and we have no outstanding
 *   requests.  Then return.
 * - Return if closing a new connection will take us above the load target.
 * - Return if we last closed a connection within 'closed_delay'.
 * - Otherwise we move a connection to draining state.
 */
static void trunk_manage(fr_trunk_t *trunk, fr_time_t now)
{
	fr_trunk_connection_t	*tconn = NULL;
	uint32_t		average;
	uint32_t		req_count;
	uint16_t		conn_count;

	/*
	 *	We're above the target requests per connection
	 *	spawn more connections!
	 */
	if ((trunk->last_above_target > trunk->last_below_target)) {
		if ((now - trunk->last_above_target) < trunk->conf->open_delay) {
			DEBUG4("Not opening connection - Need %pVs above threshold, have %pVs",
			       fr_box_time_delta(trunk->conf->open_delay),
			       fr_box_time_delta(now - trunk->last_above_target));
			goto done;	/* too soon */
		}

		trunk_requests_per_connnection(&conn_count, &req_count, trunk, now);
		/*
		 *	If this assert is triggered it means
		 *	that a call to trunk_requests_per_connnection
		 *	was missed.
		 */
		rad_assert(trunk->last_above_target > trunk->last_below_target);

		/*
		 *	We don't consider 'draining' connections
		 *	in the max calculation, as if we do
		 *	determine that we need to spawn a new
		 *	request, then we'd move all 'draining'
		 *	connections to active before spawning
		 *	any new connections.
		 */
		if (conn_count >= trunk->conf->max_connections) {
			DEBUG4("Not opening connection - Have %u connections, need %u or below",
			       conn_count, trunk->conf->max_connections);
			goto done;
		}

		/*
		 *	We consider requests pending on all connections
		 *      and the trunk's backlog as that's the current total
		 *	load.
		 */
		if (!req_count) {
			DEBUG4("Not opening connection - No outstanding requests");
			goto done;
		}

		/*
		 *	Do the n+1 check, i.e. if we open one connection
		 *	will that take us below our target threshold.
		 */
		average = req_count / (conn_count + 1);
		if (average < trunk->conf->req_per_conn_target) {
			DEBUG4("Not opening connection - Would leave us below our target req per conn "
			       "(%u vs %u)", average, trunk->conf->req_per_conn_target);
			goto done;
		}


		/*
		 *	If we've got a connection in the draining list
		 *      move it back into the active list if we've
		 *      been requested to add a connection back in.
		 */
		tconn = fr_dlist_head(&trunk->draining);
		if (tconn) {
			trunk_connection_enter_active(tconn);
			goto done;
		}

		/*
		 *	Implement delay if there's no connections that
		 *	could be immediately re-activated.
		 */
		if ((now - trunk->last_open) < trunk->conf->open_delay) {
			DEBUG4("Not opening connection - Need to wait %pVs, waited %pVs",
			       fr_box_time_delta(trunk->conf->open_delay),
			       fr_box_time_delta(now - trunk->last_open));
			goto done;
		}

		/* last_open set by trunk_connection_spawn */
		(void)trunk_connection_spawn(trunk, now);
		goto done;
	}

	/*
	 *	We're below the target requests per connection.
	 *	Free some connections...
	 */
	if (trunk->last_below_target > trunk->last_above_target) {
		if ((now - trunk->last_below_target) < trunk->conf->close_delay) {
			DEBUG4("Not closing connection - Need %pVs below threshold, have %pVs",
			       fr_box_time_delta(trunk->conf->close_delay),
			       fr_box_time_delta(now - trunk->last_below_target));
			goto done;	/* too soon */
		}

		trunk_requests_per_connnection(&conn_count, &req_count, trunk, now);
		/*
		 *	If this assert is triggered it means
		 *	that a call to trunk_requests_per_connnection
		 *	was missed.
		 */
		rad_assert(trunk->last_below_target > trunk->last_above_target);

		if (conn_count == 0) {
			DEBUG4("Not closing connection - Have 0 active connections");
			goto done;
		}

		/*
		 *	The minimum number of connections must be set
		 *	to zero for this to work.
		 *	min == 0, no requests, close all the connections.
		 *      This is useful for backup databases, when
		 *	maintaining the connection would lead to lots of
		 *	log file churn.
		 */
		if (!req_count) goto close;

		if (conn_count == 1) {
			DEBUG4("Not closing connection - Would leave connections "
			       "and there are still %u outstanding requests", req_count);
			goto done;
		}

		/*
		 *	Do the n-1 check, i.e. if we close one connection
		 *	will that take us above our target threshold.
		 */
		average = req_count / (conn_count - 1);
		if (average > trunk->conf->req_per_conn_target) {
			DEBUG4("Not closing connection - Would leave us above our target req per conn "
			       "(%u vs %u)", average, trunk->conf->req_per_conn_target);
			goto done;
		}

	close:
		if ((now - trunk->last_closed) < trunk->conf->close_delay) {
			DEBUG4("Not closing connection - Need to wait %pVs, waited %pVs",
			       fr_box_time_delta(trunk->conf->close_delay),
			       fr_box_time_delta(now - trunk->last_closed));
			goto done;
		}

		tconn = fr_heap_peek_tail(trunk->active);
		rad_assert(tconn);
		trunk->last_closed = now;
		trunk_connection_enter_draining(tconn);

		goto done;
	}

done:
	/*
	 *	Free any connections which have drained
	 *	and we didn't reactivate during the last
	 *	round of management.
	 */
	tconn = NULL;
	while ((tconn = fr_dlist_next(&trunk->draining, tconn))) {
		if (trunk_connection_requests_total(tconn) == 0) {
			fr_trunk_connection_t *prev;

			prev = fr_dlist_prev(&trunk->draining, tconn);
			talloc_free(tconn);
			tconn = prev;
		}
	}
}

/** Event to periodically call the connection management function
 *
 * @param[in] el	this event belongs to.
 * @param[in] now	current time.
 * @param[in] uctx	The trunk.
 */
static void _trunk_manage_timer(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_trunk_t *trunk = talloc_get_type_abort(uctx, fr_trunk_t);

	trunk_manage(trunk, now);
	fr_event_timer_in(trunk, el, &trunk->manage_ev, trunk->conf->manage_interval,
			  _trunk_manage_timer, trunk);
}

/** Return a count of requests on connections in the specified states
 *
 * @parma[in] trunk	to retrieve counts for.
 * @param[in] states	One or more states or'd together.
 * @return The total number of requests on connections in a particular state.
 */
static inline uint64_t trunk_requests_total(fr_trunk_t *trunk, int states)
{
	uint64_t		total = 0;
	fr_trunk_connection_t	*tconn;

	if (states & FR_TRUNK_CONN_CONNECTING) {
		tconn = NULL;
		while ((tconn = fr_dlist_next(&trunk->connecting, tconn))) {
			total += trunk_connection_requests_total(tconn);
		}
	}
	if (states & FR_TRUNK_CONN_ACTIVE) {
		fr_heap_iter_t iter;

		for (tconn = fr_heap_iter_init(trunk->active, &iter);
		     tconn;
		     tconn = fr_heap_iter_next(trunk->active, &iter)) {
			total += trunk_connection_requests_total(tconn);
		}
	}
	if (states & FR_TRUNK_CONN_FULL) {
		tconn = NULL;
		while ((tconn = fr_dlist_next(&trunk->full, tconn))) {
			total += trunk_connection_requests_total(tconn);
		}
	}
	if (states & FR_TRUNK_CONN_FAILED) {
		tconn = NULL;
		while ((tconn = fr_dlist_next(&trunk->failed, tconn))) {
			total += trunk_connection_requests_total(tconn);
		}
	}
	if (states & FR_TRUNK_CONN_DRAINING) {
		tconn = NULL;
		while ((tconn = fr_dlist_next(&trunk->draining, tconn))) {
			total += trunk_connection_requests_total(tconn);
		}
	}

	return total;
}

/** Update timestamps for when we last had a transition from above target to below target or vice versa
 *
 * Should be called on every time a connection or request is allocated or freed.
 *
 * @param[out] conn_count_out	How many connections we considered.
 * @param[out] req_count_out	How many requests we considered.
 * @param[in] trunk		to operate on.
 * @param[in] now		The current time.
 * @return
 *	- 0 if the average couldn't be calculated (no requests or no connections).
 *	- The average number of requests per connection.
 */
static uint32_t trunk_requests_per_connnection(uint16_t *conn_count_out, uint32_t *req_count_out,
					       fr_trunk_t *trunk, fr_time_t now)
{
	uint32_t	req_count = 0;
	uint16_t	conn_count = 0;
	uint32_t	average = 0;

	/*
	 *	No need to update these as the trunk is being freed
	 */
	if (trunk->freeing) goto done;

	/*
	 *	All states except draining.
	 */
	conn_count = trunk_connection_total(trunk, FR_TRUNK_CONN_ALL ^ FR_TRUNK_CONN_DRAINING);

	/*
	 *	Requests on all connections
	 */
	req_count = trunk_requests_total(trunk, FR_TRUNK_CONN_ALL) + fr_heap_num_elements(trunk->backlog);

	/*
	 *	No connections, but we do have requests
	 */
	if (conn_count == 0) {
		if ((req_count > 0) && (trunk->conf->req_per_conn_target > 0)) goto above_target;
		goto done;
	}

	if (req_count == 0) {
		if (trunk->conf->req_per_conn_target > 0) goto below_target;
		goto done;
	}

	/*
	 *	Calculate the average
	 */
	average = req_count / conn_count;
	if (average > trunk->conf->req_per_conn_target) {
	above_target:
		/*
		 *	Edge - Below target to above target (too many requests per conn)
		 */
		if (trunk->last_above_target >= trunk->last_below_target) trunk->last_above_target = now;
	} else if (average < trunk->conf->req_per_conn_target) {
	below_target:
		/*
		 *	Edge - Above target to below target (too few requests per conn)
		 */
		if (trunk->last_below_target <= trunk->last_above_target) trunk->last_below_target = now;
	}

done:
	if (conn_count_out) *conn_count_out = conn_count;
	if (req_count_out) *req_count_out = req_count;

	return average;
}

/** Drain the backlog of as many requests as possible
 *
 * @param[in] trunk	To drain backlog requests for.
 */
static void trunk_backlog_drain(fr_trunk_t *trunk)
{
	fr_trunk_request_t *treq;

	if (fr_heap_num_elements(trunk->backlog) == 0) return;

	DEBUG2("Draining backlog of requests");

	/*
	 *	Do *NOT* add an artificial limit
	 *	here.  We rely on all available
	 *	connections entering the full
	 *	state and transitioning back to
	 *	active in order to drain the
	 *	backlog.
	 */
	while ((treq = fr_heap_peek(trunk->backlog))) {
		switch (trunk_request_enqueue_existing(treq)) {
		case TRUNK_ENQUEUE_OK:
			continue;

		/*
		 *	Signal to stop
		 */
		case TRUNK_ENQUEUE_IN_BACKLOG:
			break;

		/*
		 *	Failed enqueueing the request,
		 *	have it enter the failed state
		 *	which will free it and
		 *	re-enliven the yielded request.
		 */
		case TRUNK_ENQUEUE_DST_UNAVAILABLE:
			trunk_request_enter_failed(treq);
			continue;

		case TRUNK_ENQUEUE_NO_CAPACITY:
			rad_assert(fr_heap_num_elements(trunk->active) == 0);
			return;
		}
	}
}

/** Force the trunk to re-establish its connections
 *
 * @param[in] trunk		to signal.
 * @param[in] states		One or more states or'd together.
 */
void fr_trunk_reconnect(fr_trunk_t *trunk, int states)
{
	size_t i;

	/*
	 *	Connections in the 'connecting' state
	 *	may re-enter that state, so we need to
	 *	be careful not to enter an infinite
	 *	loop, as we iterate over the list
	 *	again and again.
	 */
	if (states & FR_TRUNK_CONN_CONNECTING) {
		/*
		 *	Connections are always reinserted at
	 	 *	the head so this should be ok.
		 */
		for (i = fr_dlist_num_elements(&trunk->full); i > 0; i--) {
			fr_connection_signal_reconnect(((fr_trunk_connection_t *)fr_dlist_tail(&trunk->connecting))->conn);
		}
	}

	if (states & FR_TRUNK_CONN_ACTIVE) {
		fr_trunk_connection_t *tconn;

		while ((tconn = fr_heap_peek(trunk->active))) {
			fr_connection_signal_reconnect(tconn->conn);
		}
	}

	if (states & FR_TRUNK_CONN_FULL) {
		for (i = fr_dlist_num_elements(&trunk->full); i > 0; i--) {
			fr_connection_signal_reconnect(((fr_trunk_connection_t *)fr_dlist_tail(&trunk->full))->conn);
		}
	}

	if (states & FR_TRUNK_CONN_FAILED) {
		for (i = fr_dlist_num_elements(&trunk->full); i > 0; i--) {
			fr_connection_signal_reconnect(((fr_trunk_connection_t *)fr_dlist_tail(&trunk->failed))->conn);
		}
	}

	if (states & FR_TRUNK_CONN_DRAINING) {
		for (i = fr_dlist_num_elements(&trunk->draining); i > 0; i--) {
			fr_connection_signal_reconnect(((fr_trunk_connection_t *)fr_dlist_tail(&trunk->draining))->conn);
		}
	}
}

/** Order connections by queue depth
 *
 */
static int8_t _trunk_connection_order_by_shortest_queue(void const *one, void const *two)
{
	fr_trunk_connection_t	const *a = talloc_get_type_abort_const(one, fr_trunk_connection_t);
	fr_trunk_connection_t	const *b = talloc_get_type_abort_const(two, fr_trunk_connection_t);

	if (trunk_connection_requests_total(a) > trunk_connection_requests_total(b)) return +1;
	if (trunk_connection_requests_total(a) < trunk_connection_requests_total(b)) return -1;

	return 0;
}

/** Free a trunk, gracefully closing all connections.
 *
 */
static int _trunk_free(fr_trunk_t *trunk)
{
	fr_connection_t *tconn;

	DEBUG4("Trunk free %p", trunk);

	trunk->freeing = true;	/* Prevent re-enqueuing */

	/*
	 *	We really don't want this firing whilst
	 *	we're trying to free everything.
	 */
	fr_event_timer_delete(trunk->el, &trunk->manage_ev);

	/*
	 *	Now free the connections in each
	 *	of the lists.
	 *
	 *	Each time a connection is freed
	 *	it removes itself from the list
	 *	its in, which means the head
	 *	should keep advancing automatically.
	 */
	while ((tconn = fr_heap_peek(trunk->active))) talloc_free(tconn);
	while ((tconn = fr_dlist_head(&trunk->connecting))) talloc_free(tconn);
	while ((tconn = fr_dlist_head(&trunk->full))) talloc_free(tconn);
	while ((tconn = fr_dlist_head(&trunk->failed))) talloc_free(tconn);
	while ((tconn = fr_dlist_head(&trunk->draining))) talloc_free(tconn);

	return 0;
}

/** Allocate a new collection of connections
 *
 * @param[in] ctx		To use for any memory allocations.  Must be thread local.
 * @param[in] el		to use for I/O and timer events.
 * @param[in] log_prefix	To prepend to global messages.
 * @param[in] delay_spawn	If true, then we will not spawn any connections
 *				until the first request is enqueued.
 * @param[in] conf		Common user configurable parameters
 * @param[in] funcs		Callback functions.
 * @param[in] uctx		User data to pass to the alloc function.

 * @return
 *	- New trunk handle on success.
 *	- NULL on error.
 */
fr_trunk_t *fr_trunk_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, char const *log_prefix, bool delay_spawn,
			   fr_trunk_conf_t const *conf, fr_trunk_io_funcs_t const *funcs,
			   void const *uctx)
{
	fr_trunk_t	*trunk;
	uint16_t	i;

	/*
	 *	Check we have the functions we need
	 */
	if (!fr_cond_assert(funcs->request_prioritise)) return NULL;
	if (!fr_cond_assert(funcs->request_mux)) return NULL;
	if (!fr_cond_assert(funcs->request_demux)) return NULL;
	if (!fr_cond_assert(funcs->connection_alloc)) return NULL;

	MEM(trunk = talloc_zero(ctx, fr_trunk_t));
	trunk->el = el;
	trunk->log_prefix = talloc_strdup(trunk, log_prefix);
	trunk->conf = conf;
	memcpy(&trunk->funcs, funcs, sizeof(trunk->funcs));
	memcpy(&trunk->uctx, &uctx, sizeof(trunk->uctx));
	talloc_set_destructor(trunk, _trunk_free);

	/*
	 *	Request backlog queue
	 */
	MEM(trunk->backlog = fr_heap_talloc_create(trunk, trunk->funcs.request_prioritise,
						   fr_trunk_request_t, heap_id));

	/*
	 *	Connection queues and trees
	 */
	MEM(trunk->active = fr_heap_talloc_create(trunk, _trunk_connection_order_by_shortest_queue,
						  fr_trunk_connection_t, heap_id));
	fr_dlist_talloc_init(&trunk->connecting, fr_trunk_connection_t, list);
	fr_dlist_talloc_init(&trunk->full, fr_trunk_connection_t, list);
	fr_dlist_talloc_init(&trunk->failed, fr_trunk_connection_t, list);
	fr_dlist_talloc_init(&trunk->draining, fr_trunk_connection_t, list);

	DEBUG4("Trunk allocated %p", trunk);

	if (delay_spawn) return trunk;

	/*
	 *	Spawn the initial set of connections
	 */
	for (i = 0; i < trunk->conf->min_connections; i++) {
		fr_trunk_enqueue_t rcode;

		rcode = trunk_connection_spawn(trunk, fr_time());
		if (rcode != TRUNK_ENQUEUE_OK) {
			talloc_free(trunk);
			return NULL;
		}
	}

	/*
	 *	Insert the event timer to manage
	 *	the interval between managing connections.
	 */
	if (trunk->conf->manage_interval > 0) {
		fr_event_timer_in(trunk, el, &trunk->manage_ev, trunk->conf->manage_interval,
				  _trunk_manage_timer, trunk);
	}

	return trunk;
}

#ifdef TESTING_TRUNK

static void *dummy_uctx = NULL;

/*
 *  cc  -g3 -Wall -DHAVE_DLFCN_H -DTESTING_TRUNK -I../../../src -include freeradius-devel/build.h -L../../../build/lib/local/.libs -ltalloc -lfreeradius-util -lfreeradius-server -o test_trunk trunk.c
 */
#include <freeradius-devel/util/acutest.h>
#include <sys/types.h>
#include <sys/socket.h>

#define DEBUG_LVL_SET if (test_verbose_level__ >= 3) fr_debug_lvl = L_DBG_LVL_4 + 1

static void _conn_close(void *h, UNUSED void *uctx)
{
	int *our_h = talloc_get_type_abort(h, int);

	close(our_h[0]);
	close(our_h[1]);

	talloc_free(our_h);
}

/** Allocate a basic socket pair
 *
 */
static fr_connection_state_t _conn_init(void **h_out, fr_connection_t *conn, void *uctx)
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


static fr_connection_t *test_setup_socket_pair_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, char const *log_prefix, void *uctx)
{
	TEST_CHECK(uctx == &dummy_uctx);

	return fr_connection_alloc(ctx, el, 0, 0, _conn_init, NULL, _conn_close, log_prefix, uctx);
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
	fr_event_list_relative_mode(el);

	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
	TEST_CHECK(trunk != NULL);

	TEST_CHECK(trunk_connection_total(trunk, FR_TRUNK_CONN_CONNECTING) == 2);
	events = fr_event_corral(el, fr_time(), true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	fr_event_service(el);
	TEST_CHECK(trunk_connection_total(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, fr_time(), false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(el);
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
	fr_event_list_relative_mode(el);

	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
	TEST_CHECK(trunk != NULL);

	events = fr_event_corral(el, fr_time(), true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	TEST_CHECK(trunk_connection_total(trunk, FR_TRUNK_CONN_CONNECTING) == 2);
	fr_event_service(el);
	TEST_CHECK(trunk_connection_total(trunk, FR_TRUNK_CONN_ACTIVE) == 2);

	events = fr_event_corral(el, fr_time(), false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	fr_trunk_reconnect(trunk, FR_TRUNK_CONN_ACTIVE);
	TEST_CHECK(trunk_connection_total(trunk, FR_TRUNK_CONN_CONNECTING) == 2);

	events = fr_event_corral(el, fr_time(), true);
	TEST_CHECK(events == 2);	/* Two I/O write events, no timers */
	fr_event_service(el);

	TEST_CHECK(trunk_connection_total(trunk, FR_TRUNK_CONN_ACTIVE) == 2);
	events = fr_event_corral(el, fr_time(), false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(el);
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

static fr_connection_t *test_setup_socket_pair_1s_timeout_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, char const *log_prefix, void *uctx)
{
	TEST_CHECK(uctx == &dummy_uctx);

	return fr_connection_alloc(ctx, el, NSEC * 1, NSEC * 1, _conn_init_no_signal, NULL, _conn_close, log_prefix, uctx);
}

static void test_socket_pair_alloc_then_connect_timeout(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_time_t		base = fr_time();
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
	fr_event_list_relative_mode(el);

	TEST_CHECK(el != NULL);
	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
	TEST_CHECK(trunk != NULL);

	/*
	 *	Trigger connection timeout
	 */
	base += NSEC * 1.5;
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for the connection timeout */
	events = fr_event_corral(el, base, true);
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

	events = fr_event_corral(el, base, false);
	TEST_CHECK(events == 0);	/* I/O events should have been cleared */

	talloc_free(trunk);
	talloc_free(el);
}

static fr_connection_t *test_setup_socket_pair_1s_reconnection_delay_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, char const *log_prefix, void *uctx)
{
	TEST_CHECK(uctx == &dummy_uctx);

	return fr_connection_alloc(ctx, el, NSEC * 1, NSEC * 1, _conn_init, NULL, _conn_close, log_prefix, uctx);
}

static void test_socket_pair_alloc_then_reconnect_check_delay(void)
{
	TALLOC_CTX		*ctx = talloc_init("test");
	fr_trunk_t		*trunk;
	fr_event_list_t		*el;
	int			events;
	fr_time_t		base = fr_time();
	fr_trunk_connection_t		*tconn;
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
	fr_event_list_relative_mode(el);

	TEST_CHECK(el != NULL);
	trunk = fr_trunk_alloc(ctx, el, "test_socket_pair", false, &conf, &io_funcs, &dummy_uctx);
	TEST_CHECK(trunk != NULL);

	/*
	 *	Trigger connection timeout
	 */
	base += NSEC * 1.5;
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for the connection timeout */
	events = fr_event_corral(el, base, true);
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
	base += NSEC * 0.5;

	events = fr_event_corral(el, base, false);
	TEST_CHECK(events == 0);	/* Reconnect delay not ready to fire yet, no I/O handlers installed */
	TEST_CHECK(fr_event_list_num_timers(el) == 1);	/* One timer event for reconnect delay */

	base += NSEC * 1;
	events = fr_event_corral(el, base, false);
	TEST_CHECK(events == 1);	/* Reconnect delay should now be ready to fire */

	fr_event_service(el);		/* Services the timer, which then triggers init */

	TEST_CHECK(fr_connection_get_num_timed_out(tconn->conn) == 0);
	TEST_CHECK(fr_connection_get_num_reconnected(tconn->conn) == 1);

	events = fr_event_corral(el, base, true);
	TEST_CHECK(events == 2);	/* Should have a pending I/O event and a timer */

	talloc_free(trunk);
	talloc_free(el);
}


TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "Basic - Alloc then free",			test_socket_pair_alloc_then_free },
	{ "Basic - Alloc then reconnect then free",	test_socket_pair_alloc_then_reconnect_then_free },

	/*
	 *	Connection timeout
	 */
	{ "Timeouts - Connection",			 test_socket_pair_alloc_then_connect_timeout },
	{ "Timeouts - Reconnect delay", 		test_socket_pair_alloc_then_reconnect_check_delay},

	{ NULL }
};
#endif

