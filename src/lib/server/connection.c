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
 * @file src/lib/server/connection.c
 * @brief Simple state machine for managing connection states.
 *
 * @copyright 2017-2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#define LOG_PREFIX "%s - [%" PRIu64 "] "
#define LOG_PREFIX_ARGS conn->pub.log_prefix, conn->pub.id

typedef struct fr_connection_s fr_connection_t;
#define _CONNECTION_PRIVATE 1
#include <freeradius-devel/server/connection.h>

#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/cond_eval.h>

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/event.h>

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/util/stdatomic.h>
#endif
#include <talloc.h>

fr_table_num_ordered_t const fr_connection_states[] = {
	{ "INIT",		FR_CONNECTION_STATE_INIT	},
	{ "CONNECTING",		FR_CONNECTION_STATE_CONNECTING	},
	{ "TIMEOUT",		FR_CONNECTION_STATE_TIMEOUT	},
	{ "CONNECTED",		FR_CONNECTION_STATE_CONNECTED	},
	{ "SHUTDOWN",		FR_CONNECTION_STATE_SHUTDOWN	},
	{ "CLOSED",		FR_CONNECTION_STATE_CLOSED	},
	{ "FAILED",		FR_CONNECTION_STATE_FAILED	},
	{ "HALTED",		FR_CONNECTION_STATE_HALTED	},
};
size_t fr_connection_states_len = NUM_ELEMENTS(fr_connection_states);

static atomic_uint_fast64_t connection_counter = ATOMIC_VAR_INIT(1);

/** An entry in a watch function list
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< List entry.
	fr_connection_watch_t	func;			//!< Function to call when a connection enters
							///< the state this list belongs to
	bool			oneshot;		//!< Remove the function after it's called once.
	void			*uctx;			//!< User data to pass to the function.
} fr_connection_watch_entry_t;

struct fr_connection_s {
	struct fr_connection_pub_s pub;			//!< Public fields

	fr_connection_state_t	state;			//!< Current connection state.

	void			*uctx;			//!< User data.

	void			*in_handler;		//!< Connection is currently in a callback.
	bool			is_closed;		//!< The close callback has previously been called.

	fr_dlist_head_t		watch_pre[FR_CONNECTION_STATE_MAX];	//!< Function called before state callback.
	fr_dlist_head_t		watch_post[FR_CONNECTION_STATE_MAX];	//!< Function called after state callback.
	fr_connection_watch_entry_t *next_watcher;	//!< Hack to insulate watcher iterator from deletions.

	fr_connection_init_t	init;			//!< Callback for initialising a connection.
	fr_connection_open_t	open;			//!< Callback for 'open' notification.
	fr_connection_close_t	close;			//!< Callback to close a connection.
	fr_connection_shutdown_t shutdown;		//!< Signal the connection handle to start shutting down.
	fr_connection_failed_t	failed;			//!< Callback for 'failed' notification.

	fr_event_timer_t const	*ev;			//!< State transition timer.

	fr_time_delta_t		connection_timeout;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_CONNECTING state.
	fr_time_delta_t		reconnection_delay;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_FAILED state.

	fr_dlist_head_t		deferred_signals;	//!< A list of signals we received whilst we were in
							///< a handler.
};

#define STATE_TRANSITION(_new) \
do { \
	DEBUG2("Connection changed state %s -> %s", \
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"), \
	       fr_table_str_by_value(fr_connection_states, _new, "<INVALID>")); \
	conn->state = _new; \
} while (0)

#define BAD_STATE_TRANSITION(_new) \
do { \
	if (!fr_cond_assert_msg(0, "Connection %" PRIu64 " invalid transition %s -> %s", \
				conn->pub.id, \
				fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"), \
				fr_table_str_by_value(fr_connection_states, _new, "<INVALID>"))) return; \
} while (0)

/** Deferred signals
 *
 */
typedef enum {
	CONNECTION_DSIGNAL_INIT,			//!< Restart a halted connection.
	CONNECTION_DSIGNAL_CONNECTED,			//!< Signal that a connection is connected.
	CONNECTION_DSIGNAL_RECONNECT_FAILED,		//!< Reconnect a failed connection.
	CONNECTION_DSIGNAL_RECONNECT_EXPIRED,		//!< Reconnect an expired connection (gracefully).
	CONNECTION_DSIGNAL_SHUTDOWN,			//!< Close a connection (gracefully).
	CONNECTION_DSIGNAL_HALT,			//!< Close a connection (ungracefully).
	CONNECTION_DSIGNAL_FREE				//!< Free a connection (no further dsignals processed).
} connection_dsignal_t;

static fr_table_num_ordered_t const connection_dsignals[] = {
	{ "INIT",		CONNECTION_DSIGNAL_INIT			},
	{ "CONNECTING",		CONNECTION_DSIGNAL_CONNECTED		},
	{ "RECONNECT-FAILED",	CONNECTION_DSIGNAL_RECONNECT_FAILED	},
	{ "RECONNECT-EXPIRED",	CONNECTION_DSIGNAL_RECONNECT_EXPIRED	},
	{ "SHUTDOWN",		CONNECTION_DSIGNAL_SHUTDOWN		},
	{ "HALT",		CONNECTION_DSIGNAL_HALT			},
	{ "FREE",		CONNECTION_DSIGNAL_FREE			}
};
static size_t connection_dsignals_len = NUM_ELEMENTS(connection_dsignals);

/** Holds a signal from a handler until it's safe to process it
 *
 */
typedef struct {
	fr_dlist_t		entry;		//!< Entry in the signals list.
	connection_dsignal_t	signal;		//!< Signal that was deferred.
} connection_dsignal_entry_t;

/*
 *	State transition functions
 */
static void connection_state_closed_enter(fr_connection_t *conn);
static void connection_state_failed_enter(fr_connection_t *conn);
static void connection_state_timeout_enter(fr_connection_t *conn);
static void connection_state_connected_enter(fr_connection_t *conn);
static void connection_state_shutdown_enter(fr_connection_t *conn);
static void connection_state_connecting_enter(fr_connection_t *conn);
static void connection_state_halted_enter(fr_connection_t *conn);
static void connection_state_init_enter(fr_connection_t *conn);

/** Add a deferred signal to the signal list
 *
 * Processing signals whilst in handlers usually leads to weird
 * inconsistent states within the connection.
 *
 * If a public signal function is called, and detects its being called
 * from within the handler, it instead adds a deferred signal entry
 * and immediately returns.
 *
 * Once the handler is complete, and all pending C stack state changes
 * are complete, the deferred signals are drained and processed.
 */
static inline void connection_deferred_signal_add(fr_connection_t *conn, connection_dsignal_t signal)
{
	connection_dsignal_entry_t *dsignal;

	dsignal = talloc_zero(conn, connection_dsignal_entry_t);
	dsignal->signal = signal;
	fr_dlist_insert_tail(&conn->deferred_signals, dsignal);

//	DEBUG4("Adding deferred signal - %s", fr_table_str_by_value(connection_dsignals, signal, "<INVALID>"));
}

/** Process any deferred signals
 *
 */
static void connection_deferred_signal_process(fr_connection_t *conn)
{
	connection_dsignal_entry_t *dsignal;

	while ((dsignal = fr_dlist_head(&conn->deferred_signals))) {
		connection_dsignal_t signal;
		fr_dlist_remove(&conn->deferred_signals, dsignal);
		signal = dsignal->signal;
		talloc_free(dsignal);

		DEBUG4("Processing deferred signal - %s",
		       fr_table_str_by_value(connection_dsignals, signal, "<INVALID>"));

		switch (signal) {
		case CONNECTION_DSIGNAL_INIT:
			fr_connection_signal_init(conn);
			break;

		case CONNECTION_DSIGNAL_CONNECTED:
			fr_connection_signal_connected(conn);
			break;

		case CONNECTION_DSIGNAL_RECONNECT_FAILED:		/* Reconnect - Failed */
			fr_connection_signal_reconnect(conn, FR_CONNECTION_FAILED);
			break;

		case CONNECTION_DSIGNAL_RECONNECT_EXPIRED:		/* Reconnect - Expired */
			fr_connection_signal_reconnect(conn, FR_CONNECTION_EXPIRED);
			break;

		case CONNECTION_DSIGNAL_SHUTDOWN:
			fr_connection_signal_shutdown(conn);
			break;

		case CONNECTION_DSIGNAL_HALT:
			fr_connection_signal_halt(conn);
			break;

		case CONNECTION_DSIGNAL_FREE:				/* Freed */
			talloc_free(conn);
			return;
		}
	}
}

/** Called when we enter a handler
 *
 */
#define HANDLER_BEGIN(_conn, _func) \
void *_prev_handler = (_conn)->in_handler; \
do { \
	(_conn)->in_handler = (void *)(_func); \
} while (0)

/** Called when we exit a handler
 *
 */
#define HANDLER_END(_conn) \
do { \
	(_conn)->in_handler = _prev_handler; \
} while(0)


/** Call a list of watch functions associated with a state
 *
 */
static inline void connection_watch_call(fr_connection_t *conn, fr_dlist_head_t *list)
{
	/*
	 *	Nested watcher calls are not allowed
	 *	and shouldn't be possible because of
	 *	deferred signal processing.
	 */
	rad_assert(conn->next_watcher == NULL);

	while ((conn->next_watcher = fr_dlist_next(list, conn->next_watcher))) {
		fr_connection_watch_entry_t	*entry = conn->next_watcher;
		bool				oneshot = entry->oneshot;	/* Watcher could be freed, so store now */

		if (oneshot) conn->next_watcher = fr_dlist_remove(list, entry);

/*
		DEBUG4("Notifying %swatcher - (%p)(conn=%p, state=%s, uctx=%p)",
		       entry->oneshot ? "oneshot " : "",
		       entry->func,
		       conn,
		       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"),
		       entry->uctx);
*/

		entry->func(conn, conn->state, entry->uctx);

		if (oneshot) talloc_free(entry);
	}
	conn->next_watcher = NULL;
}

/** Call the pre handler watch functions
 *
 */
#define WATCH_PRE(_conn) \
do { \
	if (fr_dlist_empty(&(_conn)->watch_pre[(_conn)->state])) break; \
	HANDLER_BEGIN(conn, &(_conn)->watch_pre[(_conn)->state]); \
	connection_watch_call((_conn), &(_conn)->watch_pre[(_conn)->state]); \
	HANDLER_END(conn); \
} while(0)

/** Call the post handler watch functions
 *
 */
#define WATCH_POST(_conn) \
do { \
	if (fr_dlist_empty(&(_conn)->watch_post[(_conn)->state])) break; \
	HANDLER_BEGIN(conn, &(_conn)->watch_post[(_conn)->state]); \
	connection_watch_call((_conn), &(_conn)->watch_post[(_conn)->state]); \
	HANDLER_END(conn); \
} while(0)

/** Remove a watch function from a pre/post[state] list
 *
 */
static int connection_del_watch(fr_connection_t *conn, fr_dlist_head_t *state_lists,
				fr_connection_state_t state, fr_connection_watch_t watch)
{
	fr_connection_watch_entry_t	*entry = NULL;
	fr_dlist_head_t		        *list = &state_lists[state];

	while ((entry = fr_dlist_next(list, entry))) {
		if (entry->func == watch) {
/*
			DEBUG4("Removing %s watcher %p",
			       fr_table_str_by_value(fr_connection_states, state, "<INVALID>"),
			       watch);
*/
			if (conn->next_watcher == entry) {
				conn->next_watcher = fr_dlist_remove(list, entry);
			} else {
				fr_dlist_remove(list, entry);
			}
			talloc_free(entry);
			return 0;
		}
	}

	return -1;
}

/** Remove a watch function from a pre list
 *
 * @param[in] conn	The connection to remove the watcher from.
 * @param[in] state	to remove the watch from.
 * @param[in] watch	Function to remove.
 * @return
 *	- 0 if the function was removed successfully.
 *	- -1 if the function wasn't present in the watch list.
 *	- -2 an invalid state was passed.
 */
int fr_connection_del_watch_pre(fr_connection_t *conn, fr_connection_state_t state, fr_connection_watch_t watch)
{
	if (state >= FR_CONNECTION_STATE_MAX) return -2;

	return connection_del_watch(conn, conn->watch_pre, state, watch);
}

/** Remove a watch function from a post list
 *
 * @param[in] conn	The connection to remove the watcher from.
 * @param[in] state	to remove the watch from.
 * @param[in] watch	Function to remove.
 * @return
 *	- 0 if the function was removed successfully.
 *	- -1 if the function wasn't present in the watch list.
 *	- -2 an invalid state was passed.
 */
int fr_connection_del_watch_post(fr_connection_t *conn, fr_connection_state_t state, fr_connection_watch_t watch)
{
	if (state >= FR_CONNECTION_STATE_MAX) return -2;

	return connection_del_watch(conn, conn->watch_post, state, watch);
}

/** Add a watch entry to the pre/post[state] list
 *
 */
static void connection_add_watch(fr_connection_t *conn, fr_dlist_head_t *list,
				 fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	fr_connection_watch_entry_t *entry;

	MEM(entry = talloc_zero(conn, fr_connection_watch_entry_t));

	entry->func = watch;
	entry->oneshot = oneshot;
	memcpy(&entry->uctx, &uctx, sizeof(entry->uctx));

	fr_dlist_insert_tail(list, entry);
}

/** Add a callback to be executed before a state function has been called
 *
 * @param[in] conn	to add watcher to.
 * @param[in] state	to call watcher on entering.
 * @param[in] watch	function to call.
 * @param[in] oneshot	If true, remove the function after calling.
 * @param[in] uctx	to pass to callbacks.
 */
void fr_connection_add_watch_pre(fr_connection_t *conn, fr_connection_state_t state,
				 fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	if (state >= FR_CONNECTION_STATE_MAX) return;

	connection_add_watch(conn, &conn->watch_pre[state], watch, oneshot, uctx);
}

/** Add a callback to be executed after a state function has been called
 *
 * Where a user callback is executed on state change, the post function
 * is only called if the callback succeeds.
 *
 * @param[in] conn	to add watcher to.
 * @param[in] state	to call watcher on entering.
 * @param[in] watch	function to call.
 * @param[in] oneshot	If true, remove the function after calling.
 * @param[in] uctx	to pass to callbacks.
 */
void fr_connection_add_watch_post(fr_connection_t *conn, fr_connection_state_t state,
				  fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	if (state >= FR_CONNECTION_STATE_MAX) return;

	connection_add_watch(conn, &conn->watch_post[state], watch, oneshot, uctx);
}

/** Return the number of times we've attempted to establish or re-establish this connection
 *
 * @param[in] conn	to get count from.
 * @return the number of times the connection has reconnected.
 */
uint64_t fr_connection_get_num_reconnected(fr_connection_t const *conn)
{
	if (conn->pub.reconnected == 0) return 0;	/* Has never been initialised */

	return conn->pub.reconnected - 1;		/* We don't count the first connection attempt */
}

/** Return the number of times this connection has timed out whilst connecting
 *
 * @param[in] conn	to get count from.
 * @return the number of times the connection has timed out whilst connecting.
 */
uint64_t fr_connection_get_num_timed_out(fr_connection_t const *conn)
{
	return conn->pub.timed_out;
}

/** The requisite period of time has passed, try and re-open the connection
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	The current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _reconnect_delay_done(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	switch (conn->state) {
	case FR_CONNECTION_STATE_FAILED:
	case FR_CONNECTION_STATE_CLOSED:
		connection_state_init_enter(conn);
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_INIT);
		break;
	}
}

/** Close the connection, then wait for another state change
 *
 */
static void connection_state_closed_enter(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_FAILED:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_CLOSED);
		return;
	}

	STATE_TRANSITION(FR_CONNECTION_STATE_CLOSED);

	fr_event_timer_delete(&conn->ev);

	/*
	 *	If there's a close callback, call it, so that the
	 *	API client can free any resources associated
	 *	with the connection handle.
	 */
	WATCH_PRE(conn);
	if (conn->close && !conn->is_closed) {
		HANDLER_BEGIN(conn, conn->close);
		DEBUG4("Calling close(el=%p, h=%p, uctx=%p)", conn->pub.el, conn->pub.h, conn->uctx);
		conn->close(conn->pub.el, conn->pub.h, conn->uctx);
		conn->is_closed = true;		/* Ensure close doesn't get called twice if the connection is freed */
		HANDLER_END(conn);
	} else {
		conn->is_closed = true;
	}
	WATCH_POST(conn);
}

/** Connection timeout
 *
 * Connection wasn't opened within the configured period of time
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	The current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _connection_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	connection_state_timeout_enter(conn);
}

/** Gracefully shutdown the handle
 *
 */
static void connection_state_shutdown_enter(fr_connection_t *conn)
{
	fr_connection_state_t ret;

	switch (conn->state) {
	case FR_CONNECTION_STATE_CONNECTED:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_SHUTDOWN);
		return;
	}

	STATE_TRANSITION(FR_CONNECTION_STATE_SHUTDOWN);

	WATCH_PRE(conn);
	{
		HANDLER_BEGIN(conn, conn->shutdown);
		DEBUG4("Calling shutdown(el=%p, h=%p, uctx=%p)", conn->pub.el, conn->pub.h, conn->uctx);
		ret = conn->shutdown(conn->pub.el, conn->pub.h, conn->uctx);
		HANDLER_END(conn);
	}
	switch (ret) {
	case FR_CONNECTION_STATE_SHUTDOWN:
		break;

	default:
		connection_state_failed_enter(conn);
		return;
	}
	WATCH_POST(conn);

	/*
	 *	If there's a connection timeout,
	 *	set, then add the timer.
	 *
	 *	The connection may be bad, in which
	 *	case we want to automatically fail
	 *	if it doesn't shutdown within the
	 *	timeout period.
	 */
	if (conn->connection_timeout) {
		if (fr_event_timer_in(conn, conn->pub.el, &conn->ev,
				      conn->connection_timeout, _connection_timeout, conn) < 0) {
			/*
			 *	Can happen when the event loop is exiting
			 */
			PERROR("Failed setting connection_timeout timer, closing connection");
			connection_state_closed_enter(conn);
		}
	}
}

/** Connection failed
 *
 * Transition to the FR_CONNECTION_STATE_FAILED state.
 *
 * If the connection we being opened, close, then immediately transition back to init.
 *
 * If the connection was open, or couldn't be opened wait for reconnection_delay before transitioning
 * back to init.
 *
 * @param[in] conn	that failed.
 */
static void connection_state_failed_enter(fr_connection_t *conn)
{
	fr_connection_state_t prev;
	fr_connection_state_t ret = FR_CONNECTION_STATE_INIT;

	rad_assert(conn->state != FR_CONNECTION_STATE_FAILED);

	/*
	 *	Explicit error occurred, delete the connection timer
	 */
	fr_event_timer_delete(&conn->ev);

	/*
	 *	Record what state the connection is currently in
	 *	so we can figure out what to do next.
	 */
	prev = conn->state;

	/*
	 *	Now transition to failed
	 */
	STATE_TRANSITION(FR_CONNECTION_STATE_FAILED);

	/*
	 *	If there's a failed callback, give it the
	 *	opportunity to suspend/destroy the
	 *	connection.
	 */
	WATCH_PRE(conn);
	if (conn->failed) {
		HANDLER_BEGIN(conn, conn->failed);
		DEBUG4("Calling failed(h=%p, state=%s, uctx=%p)", conn->pub.h,
		       fr_table_str_by_value(fr_connection_states, prev, "<INVALID>"), conn->uctx);
		ret = conn->failed(conn->pub.h, prev, conn->uctx);
		HANDLER_END(conn);
	}
	WATCH_POST(conn);

	/*
	 *	Enter the closed state if we failed during
	 *	connecting, or when we were connected.
	 */
	switch (prev) {
	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_CONNECTING:
		connection_state_closed_enter(conn);
		break;

	default:
		break;
	}

	if (conn->failed) {
		switch (ret) {
		/*
		 *	The callback signalled it wants the
		 *	connection to be reinitialised
		 *	after reconnection_delay, or
		 *	immediately if the failure was due
		 *	to a connection timeout.
		 */
		case FR_CONNECTION_STATE_INIT:
			break;

		/*
		 *	The callback signalled it wants the
		 *	connection to stop.
		 */
		case FR_CONNECTION_STATE_HALTED:
		default:
			connection_state_halted_enter(conn);
			return;
		}
	}

	/*
	 *	What previous state we were in
	 *	determines if we need to apply the
	 *	reconnect timeout.
	 */
	switch (prev) {
	case FR_CONNECTION_STATE_INIT:				/* Failed during initialisation */
	case FR_CONNECTION_STATE_CONNECTED:			/* Failed after connecting */
	case FR_CONNECTION_STATE_CONNECTING:			/* Failed during connecting */
		if (conn->reconnection_delay) {
			DEBUG2("Delaying reconnection by %pVs", fr_box_time_delta(conn->reconnection_delay));
			if (fr_event_timer_in(conn, conn->pub.el, &conn->ev,
					      conn->reconnection_delay, _reconnect_delay_done, conn) < 0) {
				/*
				 *	Can happen when the event loop is exiting
				 */
				PERROR("Failed inserting reconnection_delay timer event, halting connection");
				connection_state_halted_enter(conn);
			}
			return;
		}

		/*
		 *	If there's no reconnection
		 *	delay, then don't automatically
		 *	reconnect, and wait to be
		 *	signalled.
		 */
		connection_state_halted_enter(conn);
		break;

	case FR_CONNECTION_STATE_TIMEOUT:			/* Failed during connecting due to timeout */
		connection_state_init_enter(conn);
		break;

	default:
		rad_assert(0);
	}
}

/** Enter the timeout state
 *
 * The connection took took long to open.  Timeout the attempt and transition
 * to the failed state.
 */
static void connection_state_timeout_enter(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_SHUTDOWN:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_TIMEOUT);
	}

	ERROR("Connection failed - timed out after %pVs", fr_box_time_delta(conn->connection_timeout));

	STATE_TRANSITION(FR_CONNECTION_STATE_TIMEOUT);

	conn->pub.timed_out++;

	connection_state_failed_enter(conn);
}

/** Enter the halted state
 *
 * Here we wait, until signalled by fr_connection_signal_reconnect.
 */
static void connection_state_halted_enter(fr_connection_t *conn)
{
	rad_assert(conn->is_closed);

	fr_event_timer_delete(&conn->ev);

	STATE_TRANSITION(FR_CONNECTION_STATE_HALTED);
	WATCH_PRE(conn);
	WATCH_POST(conn);
}

/** Enter the connected state
 *
 * The connection is now fully connected.  At this point we call the open callback
 * so that the API client can install its normal set of I/O callbacks to deal with
 * sending/receiving actual data.
 *
 * After this, the connection will only transition states if an API client
 * explicitly calls fr_connection_signal_reconnect.
 *
 * The connection API cannot monitor the connection for failure conditions.
 *
 * @param[in] conn	Entering the connecting state.
 */
static void connection_state_connected_enter(fr_connection_t *conn)
{
	int	ret;

	rad_assert(conn->state == FR_CONNECTION_STATE_CONNECTING);

	STATE_TRANSITION(FR_CONNECTION_STATE_CONNECTED);

	fr_event_timer_delete(&conn->ev);
	WATCH_PRE(conn);
	if (conn->open) {
		HANDLER_BEGIN(conn, conn->open);
		DEBUG4("Calling open(el=%p, h=%p, uctx=%p)", conn->pub.el, conn->pub.h, conn->uctx);
		ret = conn->open(conn->pub.el, conn->pub.h, conn->uctx);
		HANDLER_END(conn);
	} else {
		ret = FR_CONNECTION_STATE_CONNECTED;
	}

	switch (ret) {
	/*
	 *	Callback agrees everything is connected
	 */
	case FR_CONNECTION_STATE_CONNECTED:
		DEBUG2("Connection established");
		WATCH_POST(conn);	/* Only call if we successfully connected */
		return;

	/*
	 *	Open callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
	default:
		PERROR("Connection failed");
		connection_state_failed_enter(conn);
		return;
	}
}

/** Enter the connecting state
 *
 * After this function returns we wait to be signalled with fr_connection_singal_connected
 * or for the connection timer to expire.
 *
 * @param[in] conn	Entering the connecting state.
 */
static void connection_state_connecting_enter(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_INIT:
	case FR_CONNECTION_STATE_CLOSED:
	case FR_CONNECTION_STATE_FAILED:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_CONNECTING);
		return;
	}

	STATE_TRANSITION(FR_CONNECTION_STATE_CONNECTING);

	WATCH_PRE(conn);
	WATCH_POST(conn);

	/*
	 *	If there's a connection timeout,
	 *	set, then add the timer.
	 */
	if (conn->connection_timeout) {
		if (fr_event_timer_in(conn, conn->pub.el, &conn->ev,
				      conn->connection_timeout, _connection_timeout, conn) < 0) {
			PERROR("Failed setting connection_timeout event, failing connection");

			/*
			 *	This can happen when the event loop
			 *	is exiting.
			 *
			 *	Entering fail will close partially
			 *	open connection and then, if we still
			 *	can't insert a timer, then the connection
			 *	will be halted and sit idle until its
			 *	freed.
			 */
			connection_state_failed_enter(conn);
		}
	}
}

/** Initial state of the connection
 *
 * Calls the init function we were passed to allocate a library specific handle or
 * file descriptor.
 *
 * @param[in] conn	To initialise.
 */
static void connection_state_init_enter(fr_connection_t *conn)
{
	fr_connection_state_t	ret;

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
	case FR_CONNECTION_STATE_CLOSED:
	case FR_CONNECTION_STATE_FAILED:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_INIT);
		return;
	}

	/*
	 *	Increment every time we enter
	 *	We have to do this, as we don't know
	 *	whether the connection was halted by
	 *	the failed callback, and is now being
	 *	reconnected, or was automatically
	 *	reconnected.
	 */
	conn->pub.reconnected++;

	STATE_TRANSITION(FR_CONNECTION_STATE_INIT);

	/*
	 *	If we have an init callback, call it.
	 */
	WATCH_PRE(conn);
	if (conn->init) {
		HANDLER_BEGIN(conn, conn->init);
		DEBUG4("Calling init(h_out=%p, conn=%p, uctx=%p)", &conn->pub.h, conn, conn->uctx);
		ret = conn->init(&conn->pub.h, conn, conn->uctx);
		HANDLER_END(conn);
	} else {
		ret = FR_CONNECTION_STATE_CONNECTING;
	}

	switch (ret) {
	case FR_CONNECTION_STATE_CONNECTING:
		conn->is_closed = false;	/* We now have a handle */
		WATCH_POST(conn);		/* Only call if we successfully initialised the handle */
		connection_state_connecting_enter(conn);
		return;

	/*
	 *	Initialisation callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
	default:
		PERROR("Connection initialisation failed");
		connection_state_failed_enter(conn);
		break;
	}
}

/** Asynchronously signal a halted connection to start
 *
 */
void fr_connection_signal_init(fr_connection_t *conn)
{
	DEBUG2("Signalled to start from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"));

	if (conn->in_handler) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_INIT);
		return;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		connection_state_init_enter(conn);
		break;

	default:
		break;
	}

	connection_deferred_signal_process(conn);
}

/** Asynchronously signal that the connection is open
 *
 * Some libraries like libldap are extremely annoying and only return control
 * to the caller after a connection is open.
 *
 * For these libraries, we can't use an I/O handler to determine when the
 * connection is open so we rely on callbacks built into the library to
 * signal that the transition has occurred.
 *
 */
void fr_connection_signal_connected(fr_connection_t *conn)
{
	rad_assert(!conn->open);	/* Use one or the other not both! */

	DEBUG2("Signalled connected from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"));

	if (conn->in_handler) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_CONNECTED);
		return;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_CONNECTING:
		connection_state_connected_enter(conn);
		break;

	default:
		break;
	}

	connection_deferred_signal_process(conn);
}

/** Asynchronously signal the connection should be reconnected
 *
 * Should be called if the caller has knowledge that the connection is bad
 * and should be reconnected.
 *
 * @param[in] conn		to reconnect.
 * @param[in] reason		Why the connection was signalled to reconnect.
 */
void fr_connection_signal_reconnect(fr_connection_t *conn, fr_connection_reason_t reason)
{
	DEBUG2("Signalled to reconnect from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"));

	if (conn->in_handler) {
		if ((reason == FR_CONNECTION_EXPIRED) && conn->shutdown) {
			connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_RECONNECT_EXPIRED);
			return;
		}

		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_RECONNECT_FAILED);
		return;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_FAILED:	/* Don't circumvent reconnection_delay */
	case FR_CONNECTION_STATE_CLOSED:	/* Don't circumvent reconnection_delay */
	case FR_CONNECTION_STATE_INIT:		/* Already initialising */
		break;

	case FR_CONNECTION_STATE_HALTED:
		fr_connection_signal_init(conn);
		break;

	case FR_CONNECTION_STATE_SHUTDOWN:
		if (reason == FR_CONNECTION_EXPIRED) break;
		connection_state_failed_enter(conn);
		break;

	case FR_CONNECTION_STATE_CONNECTED:
		if ((reason == FR_CONNECTION_EXPIRED) && conn->shutdown) connection_state_shutdown_enter(conn);
		/* FALL-THROUGH */

	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_TIMEOUT:
		connection_state_failed_enter(conn);
		break;

	case FR_CONNECTION_STATE_MAX:
		rad_assert(0);
		return;
	}

	connection_deferred_signal_process(conn);
}

/** Shuts down a connection gracefully
 *
 * If a shutdown function has been provided, it is called.
 * It's then up to the shutdown function to install I/O handlers to signal
 * when the connection has finished shutting down and should be closed
 * via #fr_connection_signal_halt.
 *
 * @param[in] conn	to shutdown.
 */
void fr_connection_signal_shutdown(fr_connection_t *conn)
{
	DEBUG2("Signalled to shutdown from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"));

	if (conn->in_handler) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_SHUTDOWN);
		return;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
	case FR_CONNECTION_STATE_SHUTDOWN:
		break;

	case FR_CONNECTION_STATE_INIT:
		connection_state_halted_enter(conn);
		break;

	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_CONNECTING:
		if (conn->shutdown) {
			connection_state_shutdown_enter(conn);
			break;
		}

	/* FALL-THROUGH */
	case FR_CONNECTION_STATE_FAILED:
		connection_state_closed_enter(conn);
		connection_state_halted_enter(conn);
		break;

	case FR_CONNECTION_STATE_TIMEOUT:
	case FR_CONNECTION_STATE_CLOSED:
		connection_state_halted_enter(conn);
		break;

	case FR_CONNECTION_STATE_MAX:
		rad_assert(0);
		return;
	}

	connection_deferred_signal_process(conn);
}

/** Shuts down a connection ungracefully
 *
 * If a connection is in an open or connection state it will be closed immediately.
 * Otherwise the connection will transition directly to the halted state.
 *
 * @param[in] conn	to halt.
 */
void fr_connection_signal_halt(fr_connection_t *conn)
{
	DEBUG2("Signalled to halt from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"));

	if (conn->in_handler) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_HALT);
		return;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		break;

	case FR_CONNECTION_STATE_INIT:
	case FR_CONNECTION_STATE_SHUTDOWN:
	case FR_CONNECTION_STATE_TIMEOUT:
	case FR_CONNECTION_STATE_CLOSED:
		connection_state_halted_enter(conn);
		break;

	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_CONNECTING:
	/*
	 *	Failed connections need closing too
	 *	else we assert on conn->is_closed
	 */
	case FR_CONNECTION_STATE_FAILED:
		connection_state_closed_enter(conn);
		connection_state_halted_enter(conn);
		break;

	case FR_CONNECTION_STATE_MAX:
		rad_assert(0);
		return;
	}

	connection_deferred_signal_process(conn);
}
/** Receive an error notification when we're connecting a socket
 *
 * @param[in] el	event list the I/O event occurred on.
 * @param[in] fd	the I/O even occurred for.
 * @param[in] flags	from_kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] uctx	The #fr_connection_t this fd is associated with.
 */
static void _connection_error(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	ERROR("Connection failed for fd (%u): %s", fd, fr_syserror(fd_errno));
	connection_state_failed_enter(conn);

	connection_deferred_signal_process(conn);
}

/** Receive a write notification after a socket is connected
 *
 * @param[in] el	event list the I/O event occurred on.
 * @param[in] fd	the I/O even occurred for.
 * @param[in] flags	from kevent.
 * @param[in] uctx	The #fr_connection_t this fd is associated with.
 */
static void _connection_writable(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_connection_t		*conn = talloc_get_type_abort(uctx, fr_connection_t);

	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);
	connection_state_connected_enter(conn);

	connection_deferred_signal_process(conn);
}

/** Remove the FD we were watching for connection open/fail from the event loop
 *
 */
static void _connection_signal_on_fd_cleanup(fr_connection_t *conn, fr_connection_state_t state, void *uctx)
{
	int fd = *(talloc_get_type_abort(uctx, int));

	/*
	 *	Two states can trigger a cleanup
	 *	Remove the watch on the one that didn't
	 */
	switch (state) {
	case FR_CONNECTION_STATE_CLOSED:
		fr_connection_del_watch_pre(conn, FR_CONNECTION_STATE_CONNECTED, _connection_signal_on_fd_cleanup);
		break;

	case FR_CONNECTION_STATE_CONNECTED:
		fr_connection_del_watch_pre(conn, FR_CONNECTION_STATE_CLOSED, _connection_signal_on_fd_cleanup);
		break;

	default:
		rad_assert(0);
		break;
	}

	fr_event_fd_delete(conn->pub.el, fd, FR_EVENT_FILTER_IO);
	talloc_free(uctx);
}

/** Setup the connection to change states to connected or failed based on I/O events
 *
 * Will automatically cleanup after itself, in preparation for
 * new I/O handlers to be installed in the open() callback.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_connection_signal_on_fd(fr_connection_t *conn, int fd)
{
	int		*fd_s;

	/*
	 *	If connection becomes writable we
	 *	assume it's open.
	 */
	if (fr_event_fd_insert(conn, conn->pub.el, fd,
			       NULL,
			       _connection_writable,
			       _connection_error,
			       conn) < 0) {
		PERROR("Failed inserting fd (%u) into event loop %p",
		       fd, conn->pub.el);
		connection_state_failed_enter(conn);
		return -1;
	}

	/*
	 *	Stop the static analysis tools
	 *	complaining about assigning ints
	 *	to pointers.
	 */
	MEM(fd_s = talloc_zero(conn, int));
	*fd_s = fd;

	/*
	 *	Add a oneshot watcher to remove
	 *	the I/O handlers if the connection
	 *      fails, or is connected.
	 */
	fr_connection_add_watch_pre(conn, FR_CONNECTION_STATE_CLOSED,
				    _connection_signal_on_fd_cleanup, true, fd_s);
	fr_connection_add_watch_pre(conn, FR_CONNECTION_STATE_CONNECTED,
				    _connection_signal_on_fd_cleanup, true, fd_s);
	return 0;
}

/** Close a connection if it's freed
 *
 * @param[in] conn to free.
 * @return
 *	- 0 connection was freed immediately.
 *	- 1 connection free was deferred.
 */
static int _connection_free(fr_connection_t *conn)
{
	/*
	 *	Explicitly cancel any pending events
	 */
	fr_event_timer_delete(&conn->ev);

	/*
	 *	Don't allow the connection to be
	 *	arbitrarily freed by a callback.
	 *
	 *	Add a deferred signal to free the
	 *	connection later.
	 */
	if (conn->in_handler) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_FREE);
		return -1;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		break;

	/*
	 *	Need to close the connection first
	 */
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_CONNECTED:
		connection_state_closed_enter(conn);
		/* FALL-THROUGH */

	default:
		connection_state_halted_enter(conn);
		break;
	}
	return 0;
}

/** Allocate a new connection
 *
 * After the connection has been allocated, it should be started with a call to #fr_connection_signal_init.
 *
 * The connection state machine can detect when the connection is open in one of two ways.
 * - You can install a generic socket open/fail callback, using fr_connection_signal_on_fd.
 * - You can call either #fr_connection_signal_connected or fr_connection_signal_recommend.
 *   This allows the connection state machine to work with more difficult library APIs,
 *   which may not return control to the caller as connections are opened.
 *
 * @param[in] ctx		to allocate connection handle in.  If the connection
 *				handle is freed, and the #fr_connection_state_t is
 *				#FR_CONNECTION_STATE_CONNECTING or #FR_CONNECTION_STATE_CONNECTED the
 *				close callback will be called.
 * @param[in] el		to use for timer events, and to pass to the #fr_connection_open_t callback.
 * @param[in] funcs		callback functions.
 * @param[in] conf		our configuration.
 * @param[in] log_prefix	To prepend to log messages.
 * @param[in] uctx		User context to pass to callbacks.
 * @return
 *	- A new #fr_connection_t on success.
 *	- NULL on failure.
 */
fr_connection_t *fr_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
				     fr_connection_funcs_t const *funcs,
				     fr_connection_conf_t const *conf,
				     char const *log_prefix,
				     void const *uctx)
{
	size_t i;
	fr_connection_t *conn;

	rad_assert(el);

	conn = talloc_zero(ctx, fr_connection_t);
	if (!conn) return NULL;
	talloc_set_destructor(conn, _connection_free);

	conn->pub.id = atomic_fetch_add_explicit(&connection_counter, 1, memory_order_relaxed);
	conn->state = FR_CONNECTION_STATE_HALTED;
	conn->pub.el = el;
	conn->pub.h = NULL;
	conn->reconnection_delay = conf->reconnection_delay;
	conn->connection_timeout = conf->connection_timeout;
	conn->init = funcs->init;
	conn->open = funcs->open;
	conn->close = funcs->close;
	conn->failed = funcs->failed;
	conn->shutdown = funcs->shutdown;
	conn->is_closed = true;		/* Starts closed */
	conn->pub.log_prefix = talloc_typed_strdup(conn, log_prefix);
	memcpy(&conn->uctx, &uctx, sizeof(conn->uctx));

	for (i = 0; i < NUM_ELEMENTS(conn->watch_pre); i++) {
		fr_dlist_talloc_init(&conn->watch_pre[i], fr_connection_watch_entry_t, entry);
	}
	for (i = 0; i < NUM_ELEMENTS(conn->watch_post); i++) {
		fr_dlist_talloc_init(&conn->watch_post[i], fr_connection_watch_entry_t, entry);
	}
	fr_dlist_talloc_init(&conn->deferred_signals, connection_dsignal_entry_t, entry);

	return conn;
}
