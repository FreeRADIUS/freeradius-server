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
#define LOG_PREFIX conn->pub.name

typedef struct fr_connection_s fr_connection_t;
#define _CONNECTION_PRIVATE 1
#include <freeradius-devel/server/connection.h>

#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/trigger.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/log.h>

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/util/stdatomic.h>
#endif

fr_table_num_ordered_t const fr_connection_states[] = {
	{ L("HALTED"),		FR_CONNECTION_STATE_HALTED	},
	{ L("INIT"),		FR_CONNECTION_STATE_INIT	},
	{ L("CONNECTING"),	FR_CONNECTION_STATE_CONNECTING	},
	{ L("TIMEOUT"),		FR_CONNECTION_STATE_TIMEOUT	},
	{ L("CONNECTED"),	FR_CONNECTION_STATE_CONNECTED	},
	{ L("SHUTDOWN"),	FR_CONNECTION_STATE_SHUTDOWN	},
	{ L("FAILED"),		FR_CONNECTION_STATE_FAILED	},
	{ L("CLOSED"),		FR_CONNECTION_STATE_CLOSED	},
};
size_t fr_connection_states_len = NUM_ELEMENTS(fr_connection_states);

/** Map connection states to trigger names
 *
 */
static fr_table_num_indexed_t const fr_connection_trigger_names[] = {
	[FR_CONNECTION_STATE_HALTED]	=	{ L("connection.halted"),	FR_CONNECTION_STATE_HALTED	},
	[FR_CONNECTION_STATE_INIT]	=	{ L("connection.init"),		FR_CONNECTION_STATE_INIT	},
	[FR_CONNECTION_STATE_CONNECTING]=	{ L("connection.connecting"),	FR_CONNECTION_STATE_CONNECTING	},
	[FR_CONNECTION_STATE_TIMEOUT]	=	{ L("connection.timeout"),	FR_CONNECTION_STATE_TIMEOUT	},
	[FR_CONNECTION_STATE_CONNECTED]	=	{ L("connection.connected"),	FR_CONNECTION_STATE_CONNECTED	},
	[FR_CONNECTION_STATE_SHUTDOWN]	=	{ L("connection.shutdown"),	FR_CONNECTION_STATE_SHUTDOWN	},
	[FR_CONNECTION_STATE_FAILED]	=	{ L("connection.failed"),	FR_CONNECTION_STATE_FAILED	},
	[FR_CONNECTION_STATE_CLOSED]	=	{ L("connection.closed"),	FR_CONNECTION_STATE_CLOSED	}
};
static size_t fr_connection_trigger_names_len = NUM_ELEMENTS(fr_connection_trigger_names);

static atomic_uint_fast64_t connection_counter = ATOMIC_VAR_INIT(1);

/** An entry in a watch function list
 *
 */
typedef struct fr_connection_watch_entry_s {
	fr_dlist_t		entry;			//!< List entry.
	fr_connection_watch_t	func;			//!< Function to call when a connection enters
							///< the state this list belongs to
	bool			oneshot;		//!< Remove the function after it's called once.
	bool			enabled;		//!< Whether the watch entry is enabled.
	void			*uctx;			//!< User data to pass to the function.
} fr_connection_watch_entry_t;

struct fr_connection_s {
	struct fr_connection_pub_s pub;			//!< Public fields

	void			*uctx;			//!< User data.

	void			*in_handler;		//!< Connection is currently in a callback.
	bool			is_closed;		//!< The close callback has previously been called.
	bool			processing_signals;	//!< Processing deferred signals, don't let the deferred
							///< signal processor be called multiple times.

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



	fr_connection_watch_entry_t *on_halted;		//!< Used by the deferred signal processor to learn
							///< if a function deeper in the call stack freed
							///< the connection.

	unsigned int		signals_pause;		//!< Temporarily stop processing of signals.
};

#define CONN_TRIGGER(_state) do { \
	if (conn->pub.triggers) { \
		trigger_exec(unlang_interpret_get_thread_default(), \
			     NULL, fr_table_str_by_value(fr_connection_trigger_names, _state, "<INVALID>"), true, NULL); \
	} \
} while (0)

#define STATE_TRANSITION(_new) \
do { \
	DEBUG2("Connection changed state %s -> %s", \
	       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"), \
	       fr_table_str_by_value(fr_connection_states, _new, "<INVALID>")); \
	conn->pub.prev = conn->pub.state; \
	conn->pub.state = _new; \
	CONN_TRIGGER(_new); \
} while (0)

#define BAD_STATE_TRANSITION(_new) \
do { \
	if (!fr_cond_assert_msg(0, "Connection %" PRIu64 " invalid transition %s -> %s", \
				conn->pub.id, \
				fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"), \
				fr_table_str_by_value(fr_connection_states, _new, "<INVALID>"))) return; \
} while (0)

#define DEFER_SIGNALS(_conn)	((_conn)->in_handler || (_conn)->signals_pause)

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
	{ L("INIT"),			CONNECTION_DSIGNAL_INIT			},
	{ L("CONNECTING"),		CONNECTION_DSIGNAL_CONNECTED		},
	{ L("RECONNECT-FAILED"),	CONNECTION_DSIGNAL_RECONNECT_FAILED	},
	{ L("RECONNECT-EXPIRED"),	CONNECTION_DSIGNAL_RECONNECT_EXPIRED	},
	{ L("SHUTDOWN"),		CONNECTION_DSIGNAL_SHUTDOWN		},
	{ L("HALT"),			CONNECTION_DSIGNAL_HALT			},
	{ L("FREE"),			CONNECTION_DSIGNAL_FREE			}
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
static void connection_state_enter_closed(fr_connection_t *conn);
static void connection_state_enter_failed(fr_connection_t *conn);
static void connection_state_enter_timeout(fr_connection_t *conn);
static void connection_state_enter_connected(fr_connection_t *conn);
static void connection_state_enter_shutdown(fr_connection_t *conn);
static void connection_state_enter_connecting(fr_connection_t *conn);
static void connection_state_enter_halted(fr_connection_t *conn);
static void connection_state_enter_init(fr_connection_t *conn);

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
	connection_dsignal_entry_t *dsignal, *prev;

	prev = fr_dlist_tail(&conn->deferred_signals);
	if (prev && (prev->signal == signal)) return;		/* Don't insert duplicates */

	dsignal = talloc_zero(conn, connection_dsignal_entry_t);
	dsignal->signal = signal;
	fr_dlist_insert_tail(&conn->deferred_signals, dsignal);

//	DEBUG4("Adding deferred signal - %s", fr_table_str_by_value(connection_dsignals, signal, "<INVALID>"));
}

/** Notification function to tell connection_deferred_signal_process that the connection has been freed
 *
 */
static void _deferred_signal_connection_on_halted(UNUSED fr_connection_t *conn,
						  UNUSED fr_connection_state_t prev,
						  UNUSED fr_connection_state_t state, void *uctx)
{
	bool *freed = uctx;
	*freed = true;
}

/** Process any deferred signals
 *
 */
static void connection_deferred_signal_process(fr_connection_t *conn)
{
	connection_dsignal_entry_t	*dsignal;
	bool				freed = false;

	/*
	 *	We're inside and an instance of this function
	 *	higher in the call stack.  Don't do anything.
	 */
	if (conn->processing_signals) return;

	/*
	 *	Get notified if the connection gets freed
	 *	out from under us...
	 */
	fr_connection_watch_enable_set_uctx(conn->on_halted, &freed);
	conn->processing_signals = true;

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

		/*
		 *	One of the signal handlers freed the connection
		 *	return immediately.
		 */
		/* coverity[dead_error_line] */
		if (freed) return;
	}

	conn->processing_signals = false;
	fr_connection_watch_disable(conn->on_halted);
}

/** Pause processing of deferred signals
 *
 * @param[in] conn to pause signal processing for.
 */
void fr_connection_signals_pause(fr_connection_t *conn)
{
	conn->signals_pause++;
}

/** Resume processing of deferred signals
 *
 * @param[in] conn to resume signal processing for.
 */
void fr_connection_signals_resume(fr_connection_t *conn)
{
	if (conn->signals_pause > 0) conn->signals_pause--;
	if (conn->signals_pause > 0) return;

	/*
	 *	If we're not in a handler process the
	 *	deferred signals now.
	 */
	if (!conn->in_handler) {
		connection_deferred_signal_process(conn);
		return;
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
	if (!(_conn)->signals_pause && (!(_conn)->in_handler)) connection_deferred_signal_process(_conn); \
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
	fr_assert(conn->next_watcher == NULL);

	while ((conn->next_watcher = fr_dlist_next(list, conn->next_watcher))) {
		fr_connection_watch_entry_t	*entry = conn->next_watcher;
		bool				oneshot = entry->oneshot;	/* Watcher could be freed, so store now */

		if (!entry->enabled) continue;
		if (oneshot) conn->next_watcher = fr_dlist_remove(list, entry);

/*
		DEBUG4("Notifying %swatcher - (%p)(conn=%p, prev=%s, state=%s, uctx=%p)",
		       entry->oneshot ? "oneshot " : "",
		       entry->func,
		       conn,
		       fr_table_str_by_value(fr_connection_states, conn->pub.prev, "<INVALID>"),
		       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"),
		       entry->uctx);
*/

		entry->func(conn, conn->pub.prev, conn->pub.state, entry->uctx);

		if (oneshot) talloc_free(entry);
	}
	conn->next_watcher = NULL;
}

/** Call the pre handler watch functions
 *
 */
#define WATCH_PRE(_conn) \
do { \
	if (fr_dlist_empty(&(_conn)->watch_pre[(_conn)->pub.state])) break; \
	HANDLER_BEGIN(conn, &(_conn)->watch_pre[(_conn)->pub.state]); \
	connection_watch_call((_conn), &(_conn)->watch_pre[(_conn)->pub.state]); \
	HANDLER_END(conn); \
} while(0)

/** Call the post handler watch functions
 *
 */
#define WATCH_POST(_conn) \
do { \
	if (fr_dlist_empty(&(_conn)->watch_post[(_conn)->pub.state])) break; \
	HANDLER_BEGIN(conn, &(_conn)->watch_post[(_conn)->pub.state]); \
	connection_watch_call((_conn), &(_conn)->watch_post[(_conn)->pub.state]); \
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
static fr_connection_watch_entry_t *connection_add_watch(fr_connection_t *conn, fr_dlist_head_t *list,
							 fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	fr_connection_watch_entry_t *entry;

	MEM(entry = talloc_zero(conn, fr_connection_watch_entry_t));

	entry->func = watch;
	entry->oneshot = oneshot;
	entry->enabled = true;
	memcpy(&entry->uctx, &uctx, sizeof(entry->uctx));

	fr_dlist_insert_tail(list, entry);

	return entry;
}

/** Add a callback to be executed before a state function has been called
 *
 * @param[in] conn	to add watcher to.
 * @param[in] state	to call watcher on entering.
 * @param[in] watch	function to call.
 * @param[in] oneshot	If true, remove the function after calling.
 * @param[in] uctx	to pass to callbacks.
 * @return
 *	- NULL if state value is invalid.
 *	- A new watch entry handle.
 */
fr_connection_watch_entry_t *fr_connection_add_watch_pre(fr_connection_t *conn, fr_connection_state_t state,
				 			 fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	if (state >= FR_CONNECTION_STATE_MAX) return NULL;

	return connection_add_watch(conn, &conn->watch_pre[state], watch, oneshot, uctx);
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
 * @return
 *	- NULL if state value is invalid.
 *	- A new watch entry handle.
 */
fr_connection_watch_entry_t *fr_connection_add_watch_post(fr_connection_t *conn, fr_connection_state_t state,
							  fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	if (state >= FR_CONNECTION_STATE_MAX) return NULL;

	return connection_add_watch(conn, &conn->watch_post[state], watch, oneshot, uctx);
}

/** Enable a watcher
 *
 * @param[in] entry	to enabled.
 */
void fr_connection_watch_enable(fr_connection_watch_entry_t *entry)
{
	(void)talloc_get_type_abort(entry, fr_connection_watch_entry_t);
	entry->enabled = true;
}

/** Disable a watcher
 *
 * @param[in] entry	to disable.
 */
void fr_connection_watch_disable(fr_connection_watch_entry_t *entry)
{
	(void)talloc_get_type_abort(entry, fr_connection_watch_entry_t);
	entry->enabled = false;
}

/** Enable a watcher and replace the uctx
 *
 * @param[in] entry	to enabled.
 * @param[in] uctx	Opaque data to pass to the callback.
 */
void fr_connection_watch_enable_set_uctx(fr_connection_watch_entry_t *entry, void const *uctx)
{
	(void)talloc_get_type_abort(entry, fr_connection_watch_entry_t);
	entry->enabled = true;
	memcpy(&entry->uctx, &uctx, sizeof(entry->uctx));
}

/** Change the uctx of an entry
 *
 * @param[in] entry	to enabled.
 * @param[in] uctx	Opaque data to pass to the callback.
 */
void fr_connection_watch_set_uctx(fr_connection_watch_entry_t *entry, void const *uctx)
{
	(void)talloc_get_type_abort(entry, fr_connection_watch_entry_t);
	memcpy(&entry->uctx, &uctx, sizeof(entry->uctx));
}

/** Return the state of a watch entry
 *
 * @param[in] entry	to return state of.
 * @return
 *	- true if enabled.
 *      - false if disabled.
 */
bool fr_connection_watch_is_enabled(fr_connection_watch_entry_t *entry)
{
	(void)talloc_get_type_abort(entry, fr_connection_watch_entry_t);
	return entry->enabled;
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

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_FAILED:
	case FR_CONNECTION_STATE_CLOSED:
		connection_state_enter_init(conn);
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_INIT);
		break;
	}
}

/** Close the connection, then wait for another state change
 *
 */
static void connection_state_enter_closed(fr_connection_t *conn)
{
	switch (conn->pub.state) {
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

	/*
	 *	is_closed is for pure paranoia.  If everything
	 *	is working correctly this state should never
	 *	be entered if the connection is closed.
	 */
	fr_assert(!conn->is_closed);
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

	connection_state_enter_timeout(conn);
}

/** Gracefully shutdown the handle
 *
 */
static void connection_state_enter_shutdown(fr_connection_t *conn)
{
	fr_connection_state_t ret;

	switch (conn->pub.state) {
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
		connection_state_enter_failed(conn);
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
	if (fr_time_delta_ispos(conn->connection_timeout)) {
		if (fr_event_timer_in(conn, conn->pub.el, &conn->ev,
				      conn->connection_timeout, _connection_timeout, conn) < 0) {
			/*
			 *	Can happen when the event loop is exiting
			 */
			PERROR("Failed setting connection_timeout timer, closing connection");
			connection_state_enter_closed(conn);
		}
	}
}

/** Connection failed
 *
 * Transition to the FR_CONNECTION_STATE_FAILED state.
 *
 * If the connection was open, or couldn't be opened wait for reconnection_delay before transitioning
 * back to init.
 *
 * If no reconnection_delay was set, transition to halted.
 *
 * @param[in] conn	that failed.
 */
static void connection_state_enter_failed(fr_connection_t *conn)
{
	fr_connection_state_t prev;
	fr_connection_state_t ret = FR_CONNECTION_STATE_INIT;

	fr_assert(conn->pub.state != FR_CONNECTION_STATE_FAILED);

	/*
	 *	Explicit error occurred, delete the connection timer
	 */
	fr_event_timer_delete(&conn->ev);

	/*
	 *	Record what state the connection is currently in
	 *	so we can figure out what to do next.
	 */
	prev = conn->pub.state;

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
	case FR_CONNECTION_STATE_TIMEOUT:		/* Timeout means the connection progress past init */
	case FR_CONNECTION_STATE_SHUTDOWN:		/* Shutdown means the connection failed whilst shutting down */
		connection_state_enter_closed(conn);
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
			connection_state_enter_halted(conn);
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
	case FR_CONNECTION_STATE_SHUTDOWN:			/* Failed during shutdown */
		if (fr_time_delta_ispos(conn->reconnection_delay)) {
			DEBUG2("Delaying reconnection by %pVs", fr_box_time_delta(conn->reconnection_delay));
			if (fr_event_timer_in(conn, conn->pub.el, &conn->ev,
					      conn->reconnection_delay, _reconnect_delay_done, conn) < 0) {
				/*
				 *	Can happen when the event loop is exiting
				 */
				PERROR("Failed inserting reconnection_delay timer event, halting connection");
				connection_state_enter_halted(conn);
			}
			return;
		}

		/*
		 *	If there's no reconnection
		 *	delay, then don't automatically
		 *	reconnect, and wait to be
		 *	signalled.
		 */
		connection_state_enter_halted(conn);
		break;

	case FR_CONNECTION_STATE_TIMEOUT:			/* Failed during connecting due to timeout */
		connection_state_enter_init(conn);
		break;

	default:
		fr_assert(0);
	}
}

/** Enter the timeout state
 *
 * The connection took took long to open.  Timeout the attempt and transition
 * to the failed state.
 */
static void connection_state_enter_timeout(fr_connection_t *conn)
{
	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_SHUTDOWN:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_TIMEOUT);
	}

	ERROR("Connection failed - timed out after %pVs", fr_box_time_delta(conn->connection_timeout));

	STATE_TRANSITION(FR_CONNECTION_STATE_TIMEOUT);

	conn->pub.timed_out++;

	connection_state_enter_failed(conn);
}

/** Enter the halted state
 *
 * Here we wait, until signalled by fr_connection_signal_reconnect.
 */
static void connection_state_enter_halted(fr_connection_t *conn)
{
	fr_assert(conn->is_closed);

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_FAILED:	/* Init failure */
	case FR_CONNECTION_STATE_CLOSED:
		break;

	default:
		BAD_STATE_TRANSITION(FR_CONNECTION_STATE_HALTED);
	}

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
static void connection_state_enter_connected(fr_connection_t *conn)
{
	int	ret;

	fr_assert(conn->pub.state == FR_CONNECTION_STATE_CONNECTING);

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
		connection_state_enter_failed(conn);
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
static void connection_state_enter_connecting(fr_connection_t *conn)
{
	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_INIT:
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
	if (fr_time_delta_ispos(conn->connection_timeout)) {
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
			connection_state_enter_failed(conn);
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
static void connection_state_enter_init(fr_connection_t *conn)
{
	fr_connection_state_t	ret;

	switch (conn->pub.state) {
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
		connection_state_enter_connecting(conn);
		return;

	/*
	 *	Initialisation callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
	default:
		PERROR("Connection initialisation failed");
		connection_state_enter_failed(conn);
		break;
	}
}

/** Asynchronously signal a halted connection to start
 *
 */
void fr_connection_signal_init(fr_connection_t *conn)
{
	DEBUG2("Signalled to start from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"));

	if (DEFER_SIGNALS(conn)) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_INIT);
		return;
	}

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_HALTED:
		connection_state_enter_init(conn);
		break;

	default:
		break;
	}
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
	fr_assert(!conn->open);	/* Use one or the other not both! */

	DEBUG2("Signalled connected from %s state",
	       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"));

	if (DEFER_SIGNALS(conn)) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_CONNECTED);
		return;
	}

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_CONNECTING:
		connection_state_enter_connected(conn);
		break;

	default:
		break;
	}
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
	       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"));

	if (DEFER_SIGNALS(conn)) {
		if ((reason == FR_CONNECTION_EXPIRED) && conn->shutdown) {
			connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_RECONNECT_EXPIRED);
			return;
		}

		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_RECONNECT_FAILED);
		return;
	}

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_CLOSED:			/* Don't circumvent reconnection_delay */
	case FR_CONNECTION_STATE_INIT:				/* Already initialising */
		break;

	case FR_CONNECTION_STATE_HALTED:
		fr_connection_signal_init(conn);
		break;

	case FR_CONNECTION_STATE_SHUTDOWN:
		if (reason == FR_CONNECTION_EXPIRED) break;	/* Already shutting down */
		connection_state_enter_failed(conn);
		break;

	case FR_CONNECTION_STATE_CONNECTED:
		if (reason == FR_CONNECTION_EXPIRED) {
		 	if (conn->shutdown) {
		 		connection_state_enter_shutdown(conn);
		 		break;
		 	}
		 	connection_state_enter_closed(conn);
		 	break;
		}
		FALL_THROUGH;

	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_TIMEOUT:
	case FR_CONNECTION_STATE_FAILED:
		connection_state_enter_failed(conn);
		break;

	case FR_CONNECTION_STATE_MAX:
		fr_assert(0);
		return;
	}
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
	       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"));

	if (DEFER_SIGNALS(conn)) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_SHUTDOWN);
		return;
	}

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_HALTED:
	case FR_CONNECTION_STATE_SHUTDOWN:
		break;

	case FR_CONNECTION_STATE_INIT:
		connection_state_enter_halted(conn);
		break;

	/*
	 *	If the connection is connected it needs to be
	 *	shutdown first.
	 *
	 *	The shutdown callback or an FD event it inserts then
	 *	to signal that the connection should be closed.
	 */
	case FR_CONNECTION_STATE_CONNECTED:
		if (conn->shutdown) {
			connection_state_enter_shutdown(conn);
			break;
		}
	FALL_THROUGH;

	/*
	 *	If the connection is any of these states it
	 *	must have completed INIT which means it has
	 *	an active handle which needs to be closed before
	 *	the connection is halted.
	 */
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_TIMEOUT:
	case FR_CONNECTION_STATE_FAILED:
		connection_state_enter_closed(conn);
		fr_assert(conn->is_closed);

	FALL_THROUGH;
	case FR_CONNECTION_STATE_CLOSED:
		connection_state_enter_halted(conn);
		break;

	case FR_CONNECTION_STATE_MAX:
		fr_assert(0);
		return;
	}
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
	       fr_table_str_by_value(fr_connection_states, conn->pub.state, "<INVALID>"));

	if (DEFER_SIGNALS(conn)) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_HALT);
		return;
	}

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_HALTED:
		break;

	case FR_CONNECTION_STATE_INIT:
	case FR_CONNECTION_STATE_CLOSED:
		connection_state_enter_halted(conn);
		break;

	/*
	 *	If the connection is any of these states it
	 *	must have completed INIT which means it has
	 *	an active handle which needs to be closed before
	 *	the connection is halted.
	 */
	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_SHUTDOWN:
	case FR_CONNECTION_STATE_TIMEOUT:
	case FR_CONNECTION_STATE_FAILED:
		connection_state_enter_closed(conn);
		fr_assert(conn->is_closed);
		connection_state_enter_halted(conn);
		break;

	case FR_CONNECTION_STATE_MAX:
		fr_assert(0);
		return;
	}
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
	connection_state_enter_failed(conn);
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
	connection_state_enter_connected(conn);
}

/** Remove the FD we were watching for connection open/fail from the event loop
 *
 */
static void _connection_signal_on_fd_cleanup(fr_connection_t *conn,
					     UNUSED fr_connection_state_t prev, fr_connection_state_t state, void *uctx)
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
		fr_assert(0);
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
		connection_state_enter_failed(conn);
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
	if (DEFER_SIGNALS(conn)) {
		connection_deferred_signal_add(conn, CONNECTION_DSIGNAL_FREE);
		return -1;
	}

	switch (conn->pub.state) {
	case FR_CONNECTION_STATE_HALTED:
		break;

	/*
	 *	Need to close the connection first
	 */
	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_CONNECTED:
		connection_state_enter_closed(conn);
		FALL_THROUGH;

	default:
		connection_state_enter_halted(conn);
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
	uint64_t id;

	fr_assert(el);

	conn = talloc(ctx, fr_connection_t);
	if (!conn) return NULL;
	talloc_set_destructor(conn, _connection_free);

	id = atomic_fetch_add_explicit(&connection_counter, 1, memory_order_relaxed);

	*conn = (fr_connection_t){
		.pub = {
			.id = id,
			.state = FR_CONNECTION_STATE_HALTED,
			.el = el
		},
		.reconnection_delay = conf->reconnection_delay,
		.connection_timeout = conf->connection_timeout,
		.init = funcs->init,
		.open = funcs->open,
		.close = funcs->close,
		.failed = funcs->failed,
		.shutdown = funcs->shutdown,
		.is_closed = true,		/* Starts closed */
		.pub.name = talloc_asprintf(conn, "%s - [%" PRIu64 "]", log_prefix, id)
	};
	memcpy(&conn->uctx, &uctx, sizeof(conn->uctx));

	for (i = 0; i < NUM_ELEMENTS(conn->watch_pre); i++) {
		fr_dlist_talloc_init(&conn->watch_pre[i], fr_connection_watch_entry_t, entry);
	}
	for (i = 0; i < NUM_ELEMENTS(conn->watch_post); i++) {
		fr_dlist_talloc_init(&conn->watch_post[i], fr_connection_watch_entry_t, entry);
	}
	fr_dlist_talloc_init(&conn->deferred_signals, connection_dsignal_entry_t, entry);

	/*
	 *	Pre-allocate a on_halt watcher for deferred signal processing
	 */
	conn->on_halted = fr_connection_add_watch_post(conn, FR_CONNECTION_STATE_HALTED,
						       _deferred_signal_connection_on_halted, true, NULL);
	fr_connection_watch_disable(conn->on_halted);	/* Start disabled */

	return conn;
}
