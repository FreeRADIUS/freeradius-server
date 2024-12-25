#pragma once
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
 * @copyright 2019-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2019-2020 The FreeRADIUS server project
 */
RCSIDH(server_trunk_h, "$Id$")

#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/cf_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _TRUNK_PRIVATE
typedef struct trunk_request_pub_s trunk_request_t;
typedef struct trunk_connection_pub_s trunk_connection_t;
typedef struct trunk_pub_s trunk_t;
#  define _CONST const
#else
#  define _CONST
#endif

/** Reasons for a request being cancelled
 *
 */
typedef enum {
	TRUNK_CANCEL_REASON_NONE = 0,			//!< Request has not been cancelled.
	TRUNK_CANCEL_REASON_SIGNAL,			//!< Request cancelled due to a signal.
	TRUNK_CANCEL_REASON_MOVE,			//!< Request cancelled because it's being moved.
	TRUNK_CANCEL_REASON_REQUEUE			//!< A previously sent request is being requeued.
} trunk_cancel_reason_t;

typedef enum {
	TRUNK_STATE_IDLE = 0,				//!< Trunk has no connections
	TRUNK_STATE_ACTIVE,				//!< Trunk has active connections
	TRUNK_STATE_PENDING,				//!< Trunk has connections, but none are active
	TRUNK_STATE_MAX
} trunk_state_t;

/** What type of I/O events the trunk connection is currently interested in receiving
 *
 */
typedef enum {
	TRUNK_CONN_EVENT_NONE	= 0x00,			//!< Don't notify the trunk on connection state
							///< changes.
	TRUNK_CONN_EVENT_READ 	= 0x01,			//!< Trunk should be notified if a connection is
							///< readable.
	TRUNK_CONN_EVENT_WRITE	= 0x02,			//!< Trunk should be notified if a connection is
							///< writable.
	TRUNK_CONN_EVENT_BOTH	= 0x03,			//!< Trunk should be notified if a connection is
							///< readable or writable.

} trunk_connection_event_t;

/** Used for sanity checks and to track which list the connection is in
 *
 */
typedef enum {
	TRUNK_CONN_HALTED		= 0x0000,	//!< Halted, ready to be freed.
	TRUNK_CONN_INIT			= 0x0001,	//!< In the initial state.
	TRUNK_CONN_CONNECTING		= 0x0002,	//!< Connection is connecting.
	TRUNK_CONN_ACTIVE		= 0x0004,	//!< Connection is connected and ready to service requests.
							///< This is active and not 'connected', because a connection
							///< can be 'connected' and 'full' or 'connected' and 'active'.
	TRUNK_CONN_CLOSED		= 0x0008,	//!< Connection was closed, either explicitly or due to failure.
	TRUNK_CONN_FULL			= 0x0010,	//!< Connection is full and can't accept any more requests.
	TRUNK_CONN_INACTIVE		= 0x0020,	//!< Connection is inactive and can't accept any more requests.
	TRUNK_CONN_INACTIVE_DRAINING	= 0x0040,	//!< Connection is inactive, can't accept any more requests,
							///< and will be closed once it has no more outstanding
							///< requests.  Connections in this state can transition to
							///< #TRUNK_CONN_DRAINING.
	TRUNK_CONN_DRAINING		= 0x0080,	//!< Connection will be closed once it has no more outstanding
							///< requests, if it's not reactivated.
	TRUNK_CONN_DRAINING_TO_FREE	= 0x0100,	//!< Connection will be closed once it has no more outstanding
							///< requests.

} trunk_connection_state_t;

/** All connection states
 *
 */
#define TRUNK_CONN_ALL \
(\
	TRUNK_CONN_INIT | \
	TRUNK_CONN_CONNECTING | \
	TRUNK_CONN_ACTIVE | \
	TRUNK_CONN_CLOSED | \
	TRUNK_CONN_FULL | \
	TRUNK_CONN_INACTIVE | \
	TRUNK_CONN_DRAINING | \
	TRUNK_CONN_DRAINING_TO_FREE \
)

/** States where the connection may potentially be used to send requests
 *
 */
#define TRUNK_CONN_SERVICEABLE \
(\
	TRUNK_CONN_ACTIVE | \
	TRUNK_CONN_INACTIVE | \
	TRUNK_CONN_DRAINING | \
	TRUNK_CONN_INACTIVE_DRAINING | \
	TRUNK_CONN_DRAINING_TO_FREE \
)

/** States where the connection may be processing requests
 *
 */
#define TRUNK_CONN_PROCESSING \
(\
	TRUNK_CONN_ACTIVE | \
	TRUNK_CONN_FULL | \
	TRUNK_CONN_INACTIVE | \
	TRUNK_CONN_DRAINING | \
	TRUNK_CONN_INACTIVE_DRAINING | \
	TRUNK_CONN_DRAINING_TO_FREE \
)

typedef enum {
	TRUNK_ENQUEUE_IN_BACKLOG = 1,				//!< Request should be enqueued in backlog
	TRUNK_ENQUEUE_OK = 0,					//!< Operation was successful.
	TRUNK_ENQUEUE_NO_CAPACITY = -1,				//!< At maximum number of connections,
								///< and no connection has capacity.
	TRUNK_ENQUEUE_DST_UNAVAILABLE = -2,			//!< Destination is down.
	TRUNK_ENQUEUE_FAIL = -3					//!< General failure.
} trunk_enqueue_t;

/** Used for sanity checks and to simplify freeing
 *
 * Allows us to track which
 */
typedef enum {
	TRUNK_REQUEST_STATE_INIT		= 0x0000,	//!< Initial state.  Requests in this state
								///< were never assigned, and the request_t should
								///< not have been yielded.
	TRUNK_REQUEST_STATE_UNASSIGNED		= 0x0001,	//!< Transition state - Request currently
								///< not assigned to any connection.
	TRUNK_REQUEST_STATE_BACKLOG		= 0x0002,	//!< In the backlog.
	TRUNK_REQUEST_STATE_PENDING		= 0x0004,	//!< In the queue of a connection
								///< and is pending writing.
	TRUNK_REQUEST_STATE_PARTIAL		= 0x0008,	//!< Some of the request was written to the socket,
								///< more of it should be written later.
	TRUNK_REQUEST_STATE_SENT		= 0x0010,	//!< Was written to a socket.  Waiting for a response.
	TRUNK_REQUEST_STATE_REAPABLE		= 0x0020,	//!< Request has been written, needs to persist, but we
								///< are not currently waiting for any response.
								///< This is primarily useful where the connection only
								///< allows a single outstanding request, and writing
								///< additional requests would cause the previous result
								///< to be lost.
								///< Requests in this state count towards the outstanding
								///< number of requests on a connection, and prevent new
								///< requests from being enqueued until they complete.
	TRUNK_REQUEST_STATE_COMPLETE		= 0x0040,	//!< The request is complete.
	TRUNK_REQUEST_STATE_FAILED		= 0x0080,	//!< The request failed.
	TRUNK_REQUEST_STATE_CANCEL		= 0x0100,	//!< A request on a particular socket was cancel.
	TRUNK_REQUEST_STATE_CANCEL_SENT		= 0x0200,	//!< We've informed the remote server that
								///< the request has been cancelled.
	TRUNK_REQUEST_STATE_CANCEL_PARTIAL	= 0x0400,	//!< We partially wrote a cancellation request.
	TRUNK_REQUEST_STATE_CANCEL_COMPLETE	= 0x0800,	//!< Remote server has acknowledged our cancellation.

} trunk_request_state_t;

/** All request states
 *
 */
#define TRUNK_REQUEST_STATE_ALL \
(\
	TRUNK_REQUEST_STATE_BACKLOG | \
	TRUNK_REQUEST_STATE_PENDING | \
	TRUNK_REQUEST_STATE_PARTIAL | \
	TRUNK_REQUEST_STATE_SENT | \
	TRUNK_REQUEST_STATE_REAPABLE | \
	TRUNK_REQUEST_STATE_COMPLETE | \
	TRUNK_REQUEST_STATE_FAILED | \
	TRUNK_REQUEST_STATE_CANCEL | \
	TRUNK_REQUEST_STATE_CANCEL_PARTIAL | \
	TRUNK_REQUEST_STATE_CANCEL_SENT | \
	TRUNK_REQUEST_STATE_CANCEL_COMPLETE \
)

/** All requests in various cancellation states
 *
 */
#define TRUNK_REQUEST_STATE_CANCEL_ALL \
(\
	TRUNK_REQUEST_STATE_CANCEL | \
	TRUNK_REQUEST_STATE_CANCEL_PARTIAL | \
	TRUNK_REQUEST_STATE_CANCEL_SENT | \
	TRUNK_REQUEST_STATE_CANCEL_COMPLETE \
)

/** Common configuration parameters for a trunk
 *
 */
typedef struct {
	connection_conf_t const *conn_conf;		//!< Connection configuration.

	uint16_t		start;			//!< How many connections to start.

	uint16_t		min;			//!< Shouldn't let connections drop below this number.

	uint16_t		max;			//!< Maximum number of connections in the trunk.

	uint16_t		connecting;		//!< Maximum number of connections that can be in the
							///< connecting state.  Used to throttle connection spawning.

	uint32_t		target_req_per_conn;	//!< How many pending requests should ideally be
							///< running on each connection.  Averaged across
							///< the 'active' set of connections.

	uint32_t		max_req_per_conn;	//!< Maximum requests per connection.
							///< Used to determine if we need to create new connections
							///< and whether we can enqueue new requests.

	uint32_t		max_backlog;		//!< Maximum number of requests that can be in the backlog.

	uint64_t		max_uses;		//!< The maximum time a connection can be used.

	fr_time_delta_t		lifetime;		//!< Time between reconnects.

	fr_time_delta_t		idle_timeout;		//!< how long a connection can remain idle for

	fr_time_delta_t		open_delay;		//!< How long we must be above target utilisation
							///< to spawn a new connection.

	fr_time_delta_t		close_delay;		//!< How long we must be below target utilisation
							///< to close an existing connection.


	fr_time_delta_t		req_cleanup_delay;	//!< How long must a request in the unassigned (free)
							///< list not have been used for before it's cleaned up
							///< and actually freed.

	fr_time_delta_t		manage_interval;	//!< How often we run the management algorithm to
							///< open/close connections.

	unsigned		req_pool_headers;	//!< How many chunk headers the talloc pool allocated
							///< with the treq should contain.

	size_t			req_pool_size;		//!< The size of the talloc pool allocated with the treq.

	bool			always_writable;	//!< Set to true if our ability to write requests to
							///< a connection handle is not dependent on the state
							///< of the underlying connection, i.e. if the library
							///< used to implement the connection can always receive
							///< and buffer new requests irrespective of the state
							///< of the underlying socket.
							///< If this is true, #trunk_connection_signal_writable
							///< does not need to be called, and requests will be
							///< enqueued as soon as they're received.

	bool			backlog_on_failed_conn;	//!< Assign requests to the backlog when there are no
							//!< available connections and the last connection event
							//!< was a failure, instead of failing them immediately.
} trunk_conf_t;

/** Public fields for the trunk
 *
 * This saves the overhead of using accessors for commonly used fields in
 * the trunk.
 *
 * Though these fields are public, they should _NOT_ be modified by clients of
 * the trunk API.
 */
struct trunk_pub_s {
	/** @name Last time an event occurred
	 * @{
 	 */
	fr_time_t _CONST	last_above_target;	//!< Last time average utilisation went above
							///< the target value.

	fr_time_t _CONST	last_below_target;	//!< Last time average utilisation went below
							///< the target value.

	fr_time_t _CONST	last_open;		//!< Last time the connection management
							///< function opened a connection.

	fr_time_t _CONST	last_closed;		//!< Last time the connection management
							///< function closed a connection.

	fr_time_t _CONST	last_connected;		//!< Last time a connection connected.

	fr_time_t _CONST	last_failed;		//!< Last time a connection failed.

	fr_time_t _CONST	last_write_success;	//!< Last time we wrote to the connection

	fr_time_t _CONST	last_read_success;	//!< Last time we read a response.
	/** @} */

	/** @name Statistics
	 * @{
 	 */
 	uint64_t _CONST		req_alloc;		//!< The number of requests currently
 							///< allocated that have not been freed
 							///< or returned to the free list.

	uint64_t _CONST		req_alloc_new;		//!< How many requests we've allocated.

	uint64_t _CONST		req_alloc_reused;	//!< How many requests were reused.
	/** @} */

	bool _CONST		triggers;		//!< do we run the triggers?

	trunk_state_t _CONST	state;			//!< Current state of the trunk.
};

/** Public fields for the trunk request
 *
 * This saves the overhead of using accessors for commonly used fields in trunk
 * requests.
 *
 * Though these fields are public, they should _NOT_ be modified by clients of
 * the trunk API.
 */
struct trunk_request_pub_s {
	trunk_request_state_t _CONST state;		//!< Which list the request is now located in.

	trunk_t		* _CONST trunk;			//!< Trunk this request belongs to.

	trunk_connection_t	* _CONST tconn;		//!< Connection this request belongs to.

	void			* _CONST preq;		//!< Data for the muxer to write to the connection.

	void			* _CONST rctx;		//!< Resume ctx of the module.

	request_t		* _CONST request;	//!< The request that we're writing the data on behalf of.
};

/** Public fields for the trunk connection
 *
 * This saves the overhead of using accessors for commonly used fields in trunk
 * connections.
 *
 * Though these fields are public, they should _NOT_ be modified by clients of
 * the trunk API.
 */
struct trunk_connection_pub_s {
	trunk_connection_state_t _CONST state;		//!< What state the connection is in.

	connection_t		* _CONST conn;		//!< The underlying connection.

	fr_time_t _CONST	last_write_success;	//!< Last time we wrote to the connection

	fr_time_t _CONST	last_read_success;	//!< Last time we read from the connection

	trunk_t			* _CONST trunk;		//!< Trunk this connection belongs to.
};

#ifndef TRUNK_TESTS
/** Config parser definitions to populate a trunk_conf_t
 *
 */
extern conf_parser_t const trunk_config[];
#endif

/** Allocate a new connection for the trunk
 *
 * The trunk code only interacts with underlying connections via the connection API.
 * As a result the trunk API is shielded from the implementation details of opening
 * and closing connections.
 *
 * When creating new connections, this callback is used to allocate and configure
 * a new #connection_t, this #connection_t and the connection API is how the
 * trunk signals the underlying connection that it should start, reconnect, and halt (stop).
 *
 * The trunk must be informed when the underlying connection is readable, and,
 * if `always_writable == false`, when the connection is writable.
 *
 * When the connection is readable, a read I/O handler installed by the init()
 * callback of the #connection_t must either:
 *
 * - If there's no underlying I/O library, call `trunk_connection_signal_readable(tconn)`
 *   immediately, relying on the trunk demux callback to perform decoding and demuxing.
 * - If there is an underlying I/O library, feed any incoming data to that library and
 *   then call #trunk_connection_signal_readable if the underlying I/O library
 *   indicates complete responses are ready for processing.
 *
 * When the connection is writable a write I/O handler installed by the open() callback
 * of the #connection_t must either:
 *
 * - If `always_writable == true` - Inform the underlying I/O library that the connection
 *   is writable.  The trunk API does not need to be informed as it will immediately pass
 *   through any enqueued requests to the I/O library.
 * - If `always_writable == false` and there's an underlying I/O library,
 *   call `trunk_connection_signal_writable(tconn)` to allow the trunk mux callback
 *   to pass requests to the underlying I/O library and (optionally) signal the I/O library
 *   that the connection is writable.
 * - If `always_writable == false` and there's no underlying I/O library,
 *   call `trunk_connection_signal_writable(tconn)` to allow the trunk mux callback
 *   to encode and write requests to a socket.
 *
 * @param[in] tconn		The trunk connection this connection will be bound to.
 *				Should be used as the context for any #connection_t
 *				allocated.
 * @param[in] el		The event list to use for I/O and timer events.
 * @param[in] conf		Configuration of the #connection_t.
 * @param[in] log_prefix	What to prefix connection log messages with.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 * @return
 *	- A new connection_t on success (should be in the halted state - the default).
 *	- NULL on error.
 */
typedef connection_t *(*trunk_connection_alloc_t)(trunk_connection_t *tconn, fr_event_list_t *el,
							connection_conf_t const *conf,
							char const *log_prefix, void *uctx);

/** Inform the trunk API client which I/O events the trunk wants to receive
 *
 * I/O handlers installed by this callback should call one or more of the following
 * functions to signal that an I/O event has occurred:
 *
 * - trunk_connection_signal_writable - Connection is now writable.
 * - trunk_connection_signal_readable - Connection is now readable.
 * - trunk_connection_signal_inactive - Connection is full or congested.
 * - trunk_connection_signal_active - Connection is no longer full or congested.
 * - trunk_connection_signal_reconnect - Connection is inviable and should be reconnected.
 *
 * @param[in] tconn		That should be notified of I/O events.
 * @param[in] conn		The #connection_t bound to the tconn.
 *				Use conn->h to access the
 *				connection handle or file descriptor.
 * @param[in] el		to insert I/O events into.
 * @param[in] notify_on		I/O events to signal the trunk connection on.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_connection_notify_t)(trunk_connection_t *tconn, connection_t *conn,
					     fr_event_list_t *el,
					     trunk_connection_event_t notify_on, void *uctx);

/** Multiplex one or more requests into a single connection
 *
 * This callback should:
 *
 * - Pop one or more requests from the trunk connection's pending queue using
 *   #trunk_connection_pop_request.
 * - Serialize the protocol request data contained within the trunk request's (treq's)
 *   pctx, writing it to the provided #connection_t (or underlying connection handle).
 * - Insert the provided treq
 *   into a tracking structure associated with the #connection_t or uctx.
 *   This tracking structure will be used later in the trunk demux callback to match
 *   protocol requests with protocol responses.
 *
 * If working at the socket level and a write on a file descriptor indicates
 * less data was written than was needed, the trunk API client should track the
 * amount of data written in the protocol request (preq), and should call
 * `trunk_request_signal_partial(treq)`.
 * #trunk_request_signal_partial will move the request out of the pending
 * queue, and store it in the partial slot of the trunk connection.
 * The next time #trunk_connection_pop_request is called, the partially written
 * treq will be returned first.  The API client should continue writing the partially
 * written request to the socket.
 *
 * After calling #trunk_request_signal_partial this callback *MUST NOT*
 * call #trunk_connection_pop_request again, and should immediately return.
 *
 * If the request can't be written to the connection because it the connection
 * has become unusable, this callback should call
 * `connection_signal_reconnect(conn)` to notify the connection API that the
 * connection is unusable. The current request will either fail, or be
 * re-enqueued depending on the trunk configuration.
 *
 * After calling #connection_signal_reconnect this callback *MUST NOT*
 * call #trunk_connection_pop_request again, and should immediately return.
 *
 * If the protocol request data can't be written to the connection because the
 * data is invalid or because some other error occurred, this callback should
 * call `trunk_request_signal_fail(treq)`, this callback may then continue
 * popping/processing other requests.
 *
 * @param[in] el		For timer management.
 * @param[in] tconn		The trunk connection to dequeue trunk
 *      			requests from.
 * @param[in] conn		Connection to write the request to.
 *				Use conn->h to access the
 *				connection handle or file descriptor.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_request_mux_t)(fr_event_list_t *el,
				       trunk_connection_t *tconn, connection_t *conn, void *uctx);

/** Demultiplex on or more responses, reading them from a connection, decoding them, and matching them with their requests
 *
 * This callback should either:
 *
 * - If an underlying I/O library is used, request complete responses from
 *   the I/O library, and match the responses with a treq (trunk request)
 *   using a tracking structure associated with the #connection_t or uctx.
 * - If no underlying I/O library is used, read responses from the #connection_t,
 *   decode those responses, and match those responses with a treq using a tracking
 *   structure associated with the #connection_t or uctx.
 *
 * The result (positive or negative), should be written to the rctx structure.
 *
 * #trunk_request_signal_complete should be used to inform the trunk
 * that the request is now complete.
 *
 * If a connection appears to have become unusable, this callback should call
 * #connection_signal_reconnect and immediately return.  The current
 * treq will either fail, or be re-enqueued depending on the trunk configuration.
 *
 * #trunk_request_signal_fail should *NOT* be called as this function is only
 * used for reporting failures at an I/O layer level not failures of queries or
 * external services.
 *
 * @param[in] el		For timer management.
 * @param[in] tconn		The trunk connection.
 * @param[in] conn		Connection to read the request from.
 *				Use conn->h to access the
 *				connection handle or file descriptor.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_request_demux_t)(fr_event_list_t *el,
					 trunk_connection_t *tconn, connection_t *conn, void *uctx);

/** Inform a remote service like a datastore that a request should be cancelled
 *
 * This callback will be called any time there are one or more requests to be
 * cancelled and a #connection_t is writable, or as soon as a request is
 * cancelled if `always_writable == true`.
 *
 * For efficiency, this callback should call #trunk_connection_pop_cancellation
 * multiple times, and process all outstanding cancellation requests.
 *
 * If the response (cancel ACK) from the remote service needs to be tracked,
 * then the treq should be inserted into a tracking tree shared with the demuxer,
 * and #trunk_request_signal_cancel_sent should be called to move the treq into
 * the cancel_sent state.
 *
 * As with the main mux callback, if a cancellation request is partially written
 * #trunk_request_signal_cancel_partial should be called, and the amount
 * of data written should be tracked in the preq (protocol request).
 *
 * When the demuxer finds a matching (cancel ACK) response, the demuxer should
 * remove the entry from the tracking tree and call
 * #trunk_request_signal_cancel_complete.
 *
 * @param[in] el		To insert any timers into.
 *
 * @param[in] tconn		The trunk connection used to dequeue
 *				cancellation requests.
 * @param[in] conn		Connection to write the request to.
 *				Use conn->h to access the
 *				connection handle or file descriptor.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_request_cancel_mux_t)(fr_event_list_t *el,
					      trunk_connection_t *tconn, connection_t *conn, void *uctx);

/** Remove an outstanding "sent" request from a tracking/matching structure
 *
 * If the treq (trunk request) is in the TRUNK_REQUEST_STATE_PARTIAL or
 * TRUNK_REQUEST_STATE_SENT states, this callback will be called prior
 * to moving the treq to a new connection, requeueing the treq or freeing
 * the treq.
 *
 * The treq, and any associated resources, should be
 * removed from the the matching structure associated with the
 * #connection_t or uctx.
 *
 * Which resources should be freed depends on the cancellation reason:
 *
 * - TRUNK_CANCEL_REASON_REQUEUE - If an encoded request can be
 *   reused, then it should be kept, otherwise it should be freed.
 *   Any resources like ID allocations bound to that request should
 *   also be freed.
 *   #trunk_request_conn_release_t callback will not be called in this
 *   instance and cannot be used as an alternative.
 * - TRUNK_CANCEL_REASON_MOVE - If an encoded request can be reused
 *   it should be kept.  The trunk mux callback should be aware that
 *   an encoded request may already be associated with a preq and use
 *   that instead of re-encoding the preq.
 *   If the encoded request cannot be reused it should be freed, and
 *   any fields in the preq that were modified during the last mux call
 *   (other than perhaps counters) should be reset to their initial values.
 *   Alternatively the #trunk_request_conn_release_t callback can be used for
 *   the same purpose, as that will be called before the request is moved.
 * - TRUNK_CANCEL_REASON_SIGNAL - The encoded request and any I/O library
 *   request handled may be freed though that may (optionally) be left to
 *   another callback like #trunk_request_conn_release_t, as that will be
 *   called as the treq is removed from the conn.
 *   Note that the #trunk_request_complete_t and
 *   #trunk_request_fail_t callbacks will not be called in this
 *   instance.
 *
 * After this callback is complete one of several actions will be taken:
 *
 * - If the cancellation reason was TRUNK_CANCEL_REASON_REQUEUE the
 *   treq will be placed back into the pending list of the connection it
 *   was previously associated with.
 * - If the cancellation reason was TRUNK_CANCEL_REASON_MOVE, the treq
 *   will move to the unassigned state, and then either be placed in the
 *   trunk backlog, or immediately enqueued on another trunk connection.
 * - If the reason was TRUNK_CANCEL_SIGNAL
 *   - ...and a request_cancel_mux callback was provided, the
 *     the request_cancel_mux callback will be called when the connection
 *     is next writable (or immediately if `always_writable == true`) and
 *     the request_cancel_mux callback will send an explicit cancellation
 *     request to terminate any outstanding queries on remote datastores.
 *   - ...and no request_cancel_mux callback was provided, the
 *     treq will enter the unassigned state and then be freed.
 *
 * @note TRUNK_CANCEL_REASON_MOVE will only be set if the underlying
 * connection is bad. A 'sent' treq will never be moved due to load
 * balancing.
 *
 * @note There is no need to signal request state changes in the cancellation
 * function.  The trunk will move the request into the correct state.
 * This callback is only to allow the API client to cleanup the preq in
 * preparation for the cancellation event.
 *
 * @note Cancellation requests to a remote datastore should not be made
 * here.  If that is required, a cancel_mux function should be provided.
 *
 * @param[in] conn		to remove request from.
 * @param[in] preq_to_reset	Preq to reset.
 * @param[in] reason		Why the request was cancelled.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_request_cancel_t)(connection_t *conn, void *preq_to_reset,
					  trunk_cancel_reason_t reason, void *uctx);

/** Free connection specific resources from a treq, as the treq is being removed from a connection
 *
 * Any connection specific resources that the treq currently holds must be
 * released.  Examples are connection-specific handles, ID allocations,
 * and connection specific packets.
 *
 * The treq may be about to be freed or it may be being re-assigned to a new connection.
 *
 * @param[in] conn		request will be removed from.
 * @param[in] preq_to_reset	Preq to remove connection specified resources
 *      			from.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_request_conn_release_t)(connection_t *conn, void *preq_to_reset,
						 void *uctx);

/** Write a successful result to the rctx so that the trunk API client is aware of the result
 *
 * The rctx should be modified in such a way that indicates to the trunk API client
 * that the request was sent using the trunk and a response was received.
 *
 * This function should not free any resources associated with the preq.  That should
 * be done in the request_free callback.  This function should only be used to translate
 * the contents of the preq into a result, and write it to the rctx.
 *
 * After this callback is complete, the request_free callback will be called if provided.
 */
typedef void (*trunk_request_complete_t)(request_t *request, void *preq, void *rctx, void *uctx);

/** Write a failure result to the rctx so that the trunk API client is aware that the request failed
 *
 * The rctx should be modified in such a way that indicates to the trunk API client
 * that the request could not be sent using the trunk.
 *
 * This function should not free any resources associated with the preq.  That should
 * be done in the request_free callback.  This function should only be used to write
 * a "canned" failure to the rctx.
 *
 * @note If a cancel function is provided, the cancel function should be used to remove
 *       active requests from any request/response matching, not the fail function.
 *	 Both the cancel and fail functions will be called for a request that has been
 *	 sent or partially sent.
 *
 * After this callback is complete, the request_free callback will be called if provided.
 */
typedef void (*trunk_request_fail_t)(request_t *request, void *preq, void *rctx,
					trunk_request_state_t state, void *uctx);

/** Free resources associated with a trunk request
 *
 * The trunk request is complete.  If there's a request still associated with the
 * trunk request, that will be provided so that it can be marked runnable, but
 * be aware that the request_t * value will be NULL if the request was cancelled due
 * to a signal.
 *
 * The preq and any associated data such as encoded packets or I/O library request
 * handled *SHOULD* be explicitly freed by this function.
 * The exception to this is if the preq is parented by the treq, in which case the
 * preq will be explicitly freed when the treq is returned to the free list.
 *
 * @param[in] request		to mark as runnable if no further processing is required.
 * @param[in] preq_to_free	As per the name.
 * @param[in] uctx		User context data passed to #trunk_alloc.
 */
typedef void (*trunk_request_free_t)(request_t *request, void *preq_to_free, void *uctx);

/** Receive a notification when a trunk enters a particular state
 *
 * @param[in] trunk	Being watched.
 * @param[in] prev	State we came from.
 * @param[in] state	State that was entered (the current state)
 * @param[in] uctx	that was passed to trunk_add_watch_*.
 */
typedef void(*trunk_watch_t)(trunk_t *trunk,
				trunk_state_t prev, trunk_state_t state, void *uctx);

typedef struct trunk_watch_entry_s trunk_watch_entry_t;

/** I/O functions to pass to trunk_alloc
 *
 */
typedef struct {
	trunk_connection_alloc_t	connection_alloc;	//!< Allocate a new connection_t.

	trunk_connection_notify_t	connection_notify;	//!< Update the I/O event registrations for

	fr_heap_cmp_t			connection_prioritise;	//!< Ordering function for connections.

	fr_heap_cmp_t			request_prioritise;	//!< Ordering function for requests.  Controls
								///< where in the outbound queues they're inserted.

	trunk_request_mux_t		request_mux;		///!< Write one or more requests to a connection.

	trunk_request_demux_t		request_demux;		///!< Read one or more requests from a connection.

	trunk_request_cancel_mux_t	request_cancel_mux;	//!< Inform an external resource that we no longer
								///< care about the result of any queries we
								///< issued for this request.

	trunk_request_cancel_t		request_cancel;		//!< Request should be removed from tracking
								///< and should be reset to its initial state.

	trunk_request_conn_release_t	request_conn_release;	//!< Any connection specific resources should be
								///< removed from the treq as it's about to be
								///< moved or freed.

	trunk_request_complete_t	request_complete;	//!< Request is complete, interpret the response
								///< contained in preq.

	trunk_request_fail_t		request_fail;		//!< Request failed, write out a canned response.

	trunk_request_free_t		request_free;		//!< Free the preq and any resources it holds and
								///< provide a chance to mark the request as runnable.
} trunk_io_funcs_t;

/** @name Statistics
 * @{
 */
uint16_t	trunk_connection_count_by_state(trunk_t *trunk, int conn_state) CC_HINT(nonnull);

uint32_t	trunk_request_count_by_connection(trunk_connection_t const *tconn, int req_state) CC_HINT(nonnull);

uint64_t	trunk_request_count_by_state(trunk_t *trunk, int conn_state, int req_state) CC_HINT(nonnull);
/** @} */

/** @name Request state signalling
 * @{
 */
void		trunk_request_signal_partial(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_sent(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_reapable(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_complete(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_fail(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_cancel(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_cancel_partial(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_cancel_sent(trunk_request_t *treq) CC_HINT(nonnull);

void		trunk_request_signal_cancel_complete(trunk_request_t *treq) CC_HINT(nonnull);
/** @} */

/** @name (R)enqueue and alloc requests
 * @{
 */
uint64_t 	trunk_connection_requests_requeue(trunk_connection_t *tconn, int states, uint64_t max,
						     bool fail_bound) CC_HINT(nonnull);

void		trunk_request_free(trunk_request_t **treq);

trunk_request_t *trunk_request_alloc(trunk_t *trunk, request_t *request) CC_HINT(nonnull(1));

trunk_enqueue_t trunk_request_enqueue(trunk_request_t **treq, trunk_t *trunk, request_t *request,
					    void *preq, void *rctx) CC_HINT(nonnull(2));

trunk_enqueue_t trunk_request_requeue(trunk_request_t *treq) CC_HINT(nonnull);

trunk_enqueue_t trunk_request_enqueue_on_conn(trunk_request_t **treq_out, trunk_connection_t *tconn,
						    request_t *request, void *preq, void *rctx,
						    bool ignore_limits) CC_HINT(nonnull(2));

#ifndef NDEBUG
void		trunk_request_state_log(fr_log_t const *log, fr_log_type_t log_type, char const *file, int line,
					   trunk_request_t const *treq);
#endif
/** @} */

/** @name Dequeue protocol requests and cancellations
 * @{
 */
int trunk_connection_pop_cancellation(trunk_request_t **treq_out, trunk_connection_t *tconn);

int trunk_connection_pop_request(trunk_request_t **treq_out, trunk_connection_t *tconn);
/** @} */

/** @name Connection state signalling
 *
 * The following states are signalled from I/O event handlers:
 *
 * - writable - The connection is writable (the muxer will be called).
 * - readable - The connection is readable (the demuxer will be called).
 * - reconnect - The connection is likely bad and should be reconnected.
 *   If the code signalling has access to the conn, connection_signal_reconnect
 *   can be used instead of trunk_connection_signal_reconnect.
 *
 * The following states are signalled to control whether a connection may be
 * assigned new requests:
 *
 * - inactive - The connection cannot accept any new requests.  Either due to
 *   congestion or some other administrative reason.
 * - active - The connection can, once again, accept new requests.
 *
 * Note: In normal operation a connection will automatically transition between
 * the active and inactive states if conf->max_req_per_conn is specified and the
 * number of pending requests on that connection are equal to that number.
 * If however, the connection has previously been signalled inactive, it will not
 * automatically be reactivated once the number of requests drops below
 * max_req_per_conn.
 *
 * For other connection states the trunk API should not be signalled directly.
 * It will be informed by "watch" callbacks inserted into the #connection_t as
 * to when the connection changes state.
 *
 * #trunk_connection_signal_active does not need to be called in any of the
 * #connection_t state callbacks.  It is only used to activate a connection
 * which has been previously marked inactive using
 * #trunk_connection_signal_inactive.
 *
 * If #trunk_connection_signal_inactive is being used to remove a congested
 * connection from the active list (i.e. on receipt of an explicit protocol level
 * congestion notification), consider calling #trunk_connection_requests_requeue
 * with the TRUNK_REQUEST_STATE_PENDING state to redistribute that connection's
 * backlog to other connections in the trunk.
 *
 * @{
 */
void		trunk_connection_signal_writable(trunk_connection_t *tconn) CC_HINT(nonnull);

void		trunk_connection_signal_readable(trunk_connection_t *tconn) CC_HINT(nonnull);

void		trunk_connection_signal_inactive(trunk_connection_t *tconn) CC_HINT(nonnull);

void		trunk_connection_signal_active(trunk_connection_t *tconn) CC_HINT(nonnull);

void		trunk_connection_signal_reconnect(trunk_connection_t *tconn, connection_reason_t reason) CC_HINT(nonnull);

bool		trunk_connection_in_state(trunk_connection_t *tconn, int state);
/** @} */

/** @name Connection Callbacks
 * @{
 */
void		trunk_connection_callback_writable(fr_event_list_t *el, int fd, int flags, void *uctx);

void		trunk_connection_callback_readable(fr_event_list_t *el, int fd, int flags, void *uctx);
/** @} */

/** @name Connection management
 * @{
 */
void		trunk_reconnect(trunk_t *trunk, int state, connection_reason_t reason) CC_HINT(nonnull);
/** @} */

/** @name Trunk allocation
 * @{
 */
int		trunk_start(trunk_t *trunk) CC_HINT(nonnull);

void		trunk_connection_manage_start(trunk_t *trunk) CC_HINT(nonnull);

void		trunk_connection_manage_stop(trunk_t *trunk) CC_HINT(nonnull);

int		trunk_connection_manage_schedule(trunk_t *trunk) CC_HINT(nonnull);

trunk_t	*trunk_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
				trunk_io_funcs_t const *funcs, trunk_conf_t const *conf,
				char const *log_prefix, void const *uctx, bool delay_start) CC_HINT(nonnull(2, 3, 4));
/** @} */

/** @name Watchers
 * @{
 */
trunk_watch_entry_t *trunk_add_watch(trunk_t *trunk, trunk_state_t state,
					   trunk_watch_t watch, bool oneshot, void const *uctx) CC_HINT(nonnull(1));

int		trunk_del_watch(trunk_t *trunk, trunk_state_t state, trunk_watch_t watch);
/** @} */

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
void CC_HINT(nonnull(1))	trunk_verify(char const *file, int line, trunk_t *trunk);
void CC_HINT(nonnull(1))	trunk_connection_verify(char const *file, int line, trunk_connection_t *tconn);
void CC_HINT(nonnull(1))	trunk_request_verify(char const *file, int line, trunk_request_t *treq);

#  define TRUNK_VERIFY(_trunk)		trunk_verify(__FILE__, __LINE__, _trunk)
#  define TRUNK_CONNECTION_VERIFY(_tconn)	trunk_connection_verify(__FILE__, __LINE__, _tconn)
#  define TRUNK_REQUEST_VERIFY(_treq)	trunk_request_verify(__FILE__, __LINE__, _treq)
#elif !defined(NDEBUG)
#  define TRUNK_VERIFY(_trunk)		fr_assert(_trunk)
#  define TRUNK_CONNECTION_VERIFY(_tconn)	fr_assert(_tconn)
#  define TRUNK_REQUEST_VERIFY(_treq)	fr_assert(_treq)
#else
#  define TRUNK_VERIFY(_trunk)
#  define TRUNK_CONNECTION_VERIFY(_tconn)
#  define TRUNK_REQUEST_VERIFY(_treq)
#endif

bool trunk_search(trunk_t *trunk, void *ptr);
bool trunk_connection_search(trunk_connection_t *tconn, void *ptr);
bool trunk_request_search(trunk_request_t *treq, void *ptr);

#undef _CONST

/** Helper macro for building generic trunk notify callback
 *
 * @param _name	of the callback function to build
 * @param _type of the conn->h handle.  Needs to contain an fd element.
 */
#define TRUNK_NOTIFY_FUNC(_name, _type) \
static void _conn_writeable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx) \
{ \
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t); \
	trunk_connection_signal_writable(tconn); \
} \
static void _conn_readable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx) \
{ \
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t); \
	trunk_connection_signal_readable(tconn); \
} \
static void _conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx) \
{ \
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t); \
	ERROR("%s - Connection failed: %s", tconn->conn->name, fr_syserror(fd_errno)); \
	connection_signal_reconnect(tconn->conn, CONNECTION_FAILED); \
} \
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/ \
static void _name(trunk_connection_t *tconn, connection_t *conn, \
		  fr_event_list_t *el, trunk_connection_event_t notify_on, UNUSED void *uctx) \
{ \
	_type			*c = talloc_get_type_abort(conn->h, _type); \
	fr_event_fd_cb_t	read_fn = NULL, write_fn = NULL; \
	switch (notify_on) { \
	case TRUNK_CONN_EVENT_NONE: \
		fr_event_fd_delete(el, c->fd, FR_EVENT_FILTER_IO); \
		return; \
	case TRUNK_CONN_EVENT_READ: \
		read_fn = _conn_readable; \
		break; \
	case TRUNK_CONN_EVENT_WRITE: \
		write_fn = _conn_writeable; \
		break; \
	case TRUNK_CONN_EVENT_BOTH: \
		read_fn = _conn_readable; \
		write_fn = _conn_writeable; \
		break; \
	} \
	if (fr_event_fd_insert(c, NULL, el, c->fd, read_fn, write_fn, _conn_error, tconn) <0) { \
		PERROR("Failed inserting FD event"); \
		trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED); \
	} \
}

#ifdef __cplusplus
}
#endif
