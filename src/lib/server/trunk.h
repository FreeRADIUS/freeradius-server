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
RCSIDH(server_trunk_h, "$Id$")

#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/cf_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_trunk_request_s fr_trunk_request_t;
typedef struct fr_trunk_connection_s fr_trunk_connection_t;
typedef struct fr_trunk_s fr_trunk_t;

/** Common configuration parameters for a trunk
 *
 */
typedef struct {
	uint16_t		start;			//!< How many connections to start.

	uint16_t		min;			//!< Shouldn't let connections drop below this number.

	uint16_t		max;			//!< Maximum number of connections in the trunk.

	uint32_t		target_req_per_conn;	//!< How many pending requests should ideally be
							///< running on each connection.  Averaged across
							///< the 'active' set of connections.

	uint32_t		max_req_per_conn;	//!< Maximum connections per request.
							///< Used to determine if we need to create new connections.

	uint64_t		max_uses;		//!< The maximum time a connection can be used.

	fr_time_delta_t		lifetime;		//!< Time between reconnects.

	fr_time_delta_t		connect_timeout;	//!< How long to wait for a connection to establish.

	fr_time_delta_t		reconnect_delay;	//!< How long to wait before reconnecting failed
							///< connection attempts.

	fr_time_delta_t		open_delay;		//!< How long we must be above target utilisation
							///< to spawn a new connection.

	fr_time_delta_t		close_delay;		//!< How long we must be below target utilisation
							///< to close an existing connection.


	fr_time_delta_t		req_cleanup_delay;	//!< How long must a request in the unassigned list
							///< not have been used for, before it's cleaned up.

	fr_time_delta_t		manage_interval;	//!< How often we run the management algorithm to
							///< open/close connections.

	unsigned		req_pool_headers;	//!< How many chunk headers the pool should contain.

	size_t			req_pool_size;		//!< How big the pool should be.

	bool			always_writable;	//!< Set to true if our ability to write requests to
							///< a connection handle is not dependant on the state
							///< of the underlying connection, i.e. if the library
							///< used to implement the connection can always receive
							///< and buffer new requests irrespective of the state
							///< of the underlying socket.
							///< If this is true, #fr_trunk_connection_signal_writable
							///< does not need to be called, and requests will be
							///< enqueued as soon as they're received.
} fr_trunk_conf_t;

/** Reasons for a request being cancelled
 *
 */
typedef enum {
	FR_TRUNK_CANCEL_REASON_NONE = 0,		//!< Request has not been cancelled.
	FR_TRUNK_CANCEL_REASON_SIGNAL,			//!< Request cancelled due to a signal.
	FR_TRUNK_CANCEL_REASON_MOVE			//!< Request cancelled because it's being moved.
} fr_trunk_cancel_reason_t;

/** What type of I/O events the trunk connection is currently interested in receiving
 *
 */
typedef enum {
	FR_TRUNK_CONN_EVENT_NONE = 0x00,		//!< Don't notify the trunk on connection state
							///< changes.
	FR_TRUNK_CONN_EVENT_READ = 0x01,		//!< Trunk should be notified if a connection is
							///< readable.
	FR_TRUNK_CONN_EVENT_WRITE = 0x02,		//!< Trunk should be notified if a connection is
							///< writable.
	FR_TRUNK_CONN_EVENT_BOTH = 0x03,		//!< Trunk should be notified if a connection is
							///< readable or writable.

} fr_trunk_connection_event_t;

/** Config parser definitions to populate a fr_trunk_conf_t
 *
 */
extern CONF_PARSER const fr_trunk_config[];

/** Allocate a new connection for the trunk
 *
 * The trunk code only interacts with the connections via the connection API.
 * Which means its shielded from all the implementation details of opening
 * and closing connections.
 *
 * When allocating a new connection, the trunk connection should specify an
 * open callback which installs read/write handlers.
 *
 * The trunk API must be informed when a connection is readable, and, if
 * `always_writable == false`, when the connection is writable.
 *
 * When the connection is readable, a read I/O handler installed in the open()
 * callback of the fr_connection_t, must either call
 * `fr_trunk_connection_signal_readable(tconn)` immediately, or feed any incoming
 * data to the underlying library, and _then_ call #fr_trunk_connection_signal_readable.
 *
 * When the connection is writable, if `always_writable == true` then the
 * underlying library should be informed the connection is writable.
 *
 * When the connection is writable, if `always_writable == false` then the
 * underlying library should be informed the connection is writable, with any
 * pending data written, then `fr_trunk_connection_signal_writable(tconn)` should be
 * called.
 *
 * @param[in] tconn		The trunk connection this connection will be bound to.
 *				Should be used as the context for any connections
 *				allocated.
 * @param[in] el		The event list to use for I/O and timer events.
 * @param[in] connect_timeout	How long to wait in the connecting state before giving up.
 * @param[in] reconnect_delay	How long to wait before attempting to connect after a
 *				failure.
 * @param[in] log_prefix	What to prefix connection log messages with.
 * @param[in] uctx		User data to pass to the alloc callback.
 * @return
 *	- A new fr_connection_t on success (should be in the halted state).
 *	- NULL on error.
 */
typedef fr_connection_t *(*fr_trunk_connection_alloc_t)(fr_trunk_connection_t *tconn, fr_event_list_t *el,
							fr_time_delta_t connect_timeout, fr_time_delta_t reconnect_delay,
							char const *log_prefix, void *uctx);

/** Inform the API client which connections the trunk API wants to be notified of I/O events on
 *
 * I/O handlers may call one or more of the following functions to signal
 * that an event has occurred.
 *
 * - fr_trunk_connection_signal_writable - Connection is now writable.
 * - fr_trunk_connection_signal_readable - Connection is now readable.
 * - fr_trunk_connection_signal_active - Connection is full or congested.
 * - fr_trunk_connection_signal_active - Connection is no longer full or congested.
 * - fr_trunk_connection_signal_reconnect - Connection is inviable and should be reconnected.
 *
 * @param[in] tconn		That wants to be notified.
 * @param[in] conn		The underlying connection.
 * @param[in] el		to insert FD events into.
 * @param[in] notify_on		When to signal the trunk connection.
 * @param[in] uctx		User data to pass to the notify callback.
 */
typedef void (*fr_trunk_connection_notify_t)(fr_trunk_connection_t *tconn, fr_connection_t *conn,
					     fr_event_list_t *el,
					     fr_trunk_connection_event_t notify_on, void *uctx);

/** Multiplex one or more requests into a single connection
 *
 * In most cases this function should pop requests from the pending
 * queue of the connection using #fr_trunk_connection_pop_request.
 *
 * This function should then serialize the protocol request data contained
 * within the request's rctx, writing it to the provided conn.
 * This function should then insert the treq (fr_trunk_request_t)
 * into a tracking structure stored in the conn (either in the handle or the
 * uctx).
 * This tracking structure will be used later in the demux function to match
 * protocol requests with protocol responses.
 *
 * If working at the socket level, and a write on a file descriptor indicates
 * less data was written than was needed, the API client should track the
 * amount of data written, and should call `fr_trunk_request_signal_partial(treq)`
 * this will move the request out of the pending queue, and store it in the
 * partial field of the connection.  The next time #fr_trunk_connection_pop_request
 * is called, the treq will be returned first.  The API client should continue
 * writing the partially written request to the socket.
 *
 * After calling #fr_trunk_request_signal_partial this function *MUST NOT*
 * call #fr_trunk_connection_pop_request again, and should immediately return.
 *
 * If the request can't be written to the connection because it the connection
 * has become unusable, this function should call
 * `fr_connection_signal_reconnect(conn)` to notify the connection API that the
 * connection is unusable. The current request will either fail, or be
 * re-enqueued depending on the trunk configuration.
 *
 * After calling #fr_connection_signal_reconnect this function *MUST NOT*
 * call #fr_trunk_connection_pop_request again, and should immediately return.
 *
 * If the protocol request data can't be written to the connection because the
 * data is invalid, or because some other error occurred, this function should
 * call `fr_trunk_request_signal_fail(treq)`, this function may then continue
 * processing other requests.
 *
 * @param[in] tconn		The trunk connection used to dequeue trunk
 *      			requests.
 * @param[in] conn		Connection to write the request to.
 *				Use #fr_connection_get_handle to access the
 *				connection handle or file descriptor.
 * @param[in] uctx		User context data passed to #fr_trunk_alloc.
 */
typedef void (*fr_trunk_request_mux_t)(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx);

/** Demultiplex on or more responses, reading them from a connection, decoding them, and matching them with their requests
 *
 * This function should read responses from the connection, decode them,
 * and match them with a treq (fr_trunk_request_t) using a tracking structure
 * stored in the conn (either in the handle or the uctx).
 *
 * Once the treq has been retrieved from the tracking structure, the original
 * REQUEST * and rctx may be retrieved with
 * #fr_trunk_request_get_resumption_data.
 *
 * The result (positive or negative), should be written to the rctx structure.
 *
 * `fr_trunk_request_signal_success(treq)` should be used to inform the trunk
 * that the request should be placed back into the worker thread's runnable
 * queue and should continue being processed.
 *
 * If a connection appears to have become unusable, this function should call
 * `fr_connection_signal_reconnect(conn)` and immediately return.  The current
 * request will either fail, or be re-enqueued depending on the trunk
 * configuration.
 *
 * #tr_trunk_request_signal_fail should *NOT* be called in any circumstances
 * as this function is only used for reporting failures at an I/O layer level
 * not failures of queries or external services.
 *
 * @param[in] tconn		The trunk connection.
 * @param[in] conn		Connection to read the request from.
 *				Use #fr_connection_get_handle to access the
 *				connection handle or file descriptor.
 * @param[in] uctx		User context data passed to #fr_trunk_alloc.
 */
typedef void (*fr_trunk_request_demux_t)(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx);

/** Inform a remote service like a database that a request should be cancelled
 *
 * This function will be called any time there are one or more requests to be
 * cancelled and the conn is writable.  For efficiency, this function should
 * call #fr_trunk_connection_pop_cancellation multiple times, and process all
 * outstanding cancellation requests.
 *
 * If the response from the datastore needs to be tracked, then the treq should
 * be inserted into a tracking tree shared with the demuxer, and
 * #fr_trunk_request_signal_cancel_sent should be called to move the request into
 * the cancel_sent state.
 *
 * When the demuxer finds a matching response, it should remove the entry
 * from the tracking tree.
 *
 * @param[in] tconn		The trunk connection used to dequeue
 *				cancellation requests.
 * @param[in] conn		Connection to write the request to.
 *				Use #fr_connection_get_handle to access the
 *				connection handle or file descriptor.
 * @param[in] uctx		User context data passed to #fr_trunk_alloc.
 */
typedef void (*fr_trunk_request_cancel_mux_t)(fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx);

/** Remove an outstanding request from a matching structure
 *
 * The treq (fr_trunk_request_t), and any associated resources should be
 * removed from the the matching structure in the conn, and resources that do
 * were generated whilst encoding the protocol request should be freed.
 *
 * Once this function has returned, if a cancel_sent callback has been
 * provided, the treq will enter the FR_TRUNK_REQUEST_CANCEL_EVENTED
 * state, and be placed on the connection's cancellation queue.
 *
 * The cancellation queue will be drained the next time the connection becomes
 * writable.
 *
 * @param[in] conn		to remove request from.
 * @param[in] treq		Trunk request to cancel.
 * @param[in] preq		Preq to cancel.
 * @param[in] reason		Why the request was cancelled.
 * @param[in] uctx		User context data passed to #fr_trunk_alloc.
 */
typedef void (*fr_trunk_request_cancel_t)(fr_connection_t *conn, fr_trunk_request_t *treq, void *preq,
					  fr_trunk_cancel_reason_t reason, void *uctx);

/** Write a successful result to the rctx so that the API client is aware of the result
 *
 * This function should free any memory not bound to the lifetime of the rctx
 * or request, or that was allocated explicitly to prepare for the REQUEST *
 * being used by a trunk, this may include library request handles and
 * encoded packets.
 *
 * The rctx should be modified in such a way that indicates to the API client
 * that the request could not be sent using the trunk.
 *
 * After this function returns the REQUEST * will be marked as runnable.
 */
typedef void (*fr_trunk_request_complete_t)(REQUEST *request, void *preq, void *rctx, void *uctx);

/** Write a failure result to the rctx so that the API client is aware that the request failed
 *
 * This function should free any memory not bound to the lifetime of the rctx
 * or request, or that was allocated explicitly to prepare for the REQUEST *
 * being used by a trunk, this may include library request handles and
 * (partially-)encoded packets.
 *
 * The rctx should be modified in such a way that indicates to the API client
 * that the request could not be sent using the trunk.
 *
 * After this function returns the REQUEST * will be marked as runnable.
 *
 * @note If a cancel function is provided, this function should be used to remove
 *       active requests from any request/response matching, not the fail function.
 */
typedef void (*fr_trunk_request_fail_t)(REQUEST *request, void *preq, void *rctx, void *uctx);

/** Free resources associated with a trunk request
 *
 * The trunk request is complete.  If there's a request still associated with the
 * trunk request, that will be provided, so that i can be marked runnable if there's
 * no further processing required.
 *
 * The preq *MUST* be explicitly freed by this function.
 *
 * @param[in] request		to mark as runnable if no further processing is required.
 * @param[in] preq_to_free	As per the name.
 * @param[in] uctx		User context data passed to #fr_trunk_alloc.
 */
typedef void (*fr_trunk_request_free_t)(REQUEST *request, void *preq_to_free, void *uctx);

/** I/O functions to pass to fr_trunk_alloc
 *
 */
typedef struct {
	fr_trunk_connection_alloc_t	connection_alloc;	//!< Allocate a new fr_connection_t.

	fr_trunk_connection_notify_t	connection_notify;	//!< Update the I/O event registrations for

	fr_heap_cmp_t			connection_prioritise;	//!< Ordering function for connections.

	fr_heap_cmp_t			request_prioritise;	//!< Ordering function for requests.  Controls
								///< where in the outbound queues they're inserted.

	fr_trunk_request_mux_t		request_mux;		///!< Write one or more requests to a connection.

	fr_trunk_request_demux_t	request_demux;		///!< Read one or more requests from a connection.

	fr_trunk_request_cancel_mux_t	request_cancel_mux;	//!< Inform an external resource that we no longer
								///< care about the result of any queries we
								///< issued for this request.

	fr_trunk_request_cancel_t	request_cancel;		//!< Request should be removed from tracking
								///< and should be reset to its initial state.

	fr_trunk_request_complete_t	request_complete;	//!< Request is complete.

	fr_trunk_request_fail_t		request_fail;		//!< Cleanup all resources, and inform the caller.

	fr_trunk_request_free_t		request_free;		//!< Free the preq and provide a chance
								///< to mark the request as runnable.
} fr_trunk_io_funcs_t;

/** @name Statistics
 * @{
 */
uint16_t	fr_trunk_connection_count_by_state(fr_trunk_t *trunk, int conn_state);

uint32_t	fr_trunk_request_count_by_connection(fr_trunk_connection_t const *tconn, int req_state);

uint64_t	fr_trunk_request_count_by_state(fr_trunk_t *trunk, int conn_state, int req_state);
/** @} */

/** @name Request state signalling
 * @{
 */
void		fr_trunk_request_signal_partial(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_sent(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_complete(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_fail(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_cancel(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_cancel_partial(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_cancel_sent(fr_trunk_request_t *treq);

void		fr_trunk_request_signal_cancel_complete(fr_trunk_request_t *treq);
/** @} */

/** @name (R)enqueue and alloc requests
 * @{
 */
uint64_t 	fr_trunk_connection_requests_requeue(fr_trunk_connection_t *tconn, int states, uint64_t max);

void		fr_trunk_request_free(fr_trunk_request_t *treq);

fr_trunk_request_t *fr_trunk_request_alloc(fr_trunk_t *trunk, REQUEST *request);

int		fr_trunk_request_enqueue(fr_trunk_request_t **treq, fr_trunk_t *trunk, REQUEST *request,
					 void *preq, void *rctx);
/** @} */

/** @name Dequeue protocol requests and cancellations
 * @{
 */
fr_trunk_request_t *fr_trunk_connection_pop_cancellation(void **preq, fr_trunk_connection_t *tconn);

fr_trunk_request_t *fr_trunk_connection_pop_request(void **preq, void **rctx, fr_trunk_connection_t *tconn);
/** @} */

/** @name Connection state signalling
 *
 * - writable means the connection is writable and the muxer should be called.
 * - readable means the connection is readable and the demuxer should be called.
 * - full means the connection cannot accept any new requests.
 * - active means the connection can accept requests again.
 * - reconnect means the connection is likely bad, and should be reconnected.
 * @{
 */
void		fr_trunk_connection_signal_writable(fr_trunk_connection_t *tconn);

void		fr_trunk_connection_signal_readable(fr_trunk_connection_t *tconn);

void		fr_trunk_connection_signal_inactive(fr_trunk_connection_t *tconn);

void		fr_trunk_connection_signal_active(fr_trunk_connection_t *tconn);

void		fr_trunk_connection_signal_reconnect(fr_trunk_connection_t *tconn);
/** @} */

/** @name Connection management
 * @{
 */
void		fr_trunk_reconnect(fr_trunk_t *trunk, int state);
/** @} */

/** @name Trunk allocation
 * @{
 */
int		fr_trunk_start(fr_trunk_t *trunk);

fr_trunk_t	*fr_trunk_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, char const *log_prefix, bool delay_start,
				fr_trunk_conf_t const *conf, fr_trunk_io_funcs_t const *funcs,
				void const *uctx);
/** @} */

#ifdef __cplusplus
}
#endif
