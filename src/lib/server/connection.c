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
#define LOG_PREFIX "[%" PRIu64 "] %s - "
#define LOG_PREFIX_ARGS conn->id, conn->log_prefix

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

fr_table_num_sorted_t const fr_connection_states[] = {
	{ "CONNECTED",		FR_CONNECTION_STATE_CONNECTED	},
	{ "CONNECTING",		FR_CONNECTION_STATE_CONNECTING	},
	{ "FAILED",		FR_CONNECTION_STATE_FAILED	},
	{ "HALTED",		FR_CONNECTION_STATE_HALTED	},
	{ "INIT",		FR_CONNECTION_STATE_INIT	},
	{ "TIMEOUT",		FR_CONNECTION_STATE_TIMEOUT	}
};
size_t fr_connection_states_len = NUM_ELEMENTS(fr_connection_states);

static atomic_uint_fast64_t connection_counter = ATOMIC_VAR_INIT(1);

/** An entry in a watch function list
 *
 */
typedef struct {
	fr_dlist_t		list;			//!< List entry.
	fr_connection_watch_t	func;			//!< Function to call when a connection enters
							///< the state this list belongs to
	bool			oneshot;		//!< Remove the function after it's called once.
	void			*uctx;			//!< User data to pass to the function.
} fr_connection_watch_entry_t;

struct fr_conn {
	uint64_t		id;			//!< Unique identifier for the connection.
	fr_connection_state_t	state;			//!< Current connection state.
	void			*h;			//!< Connection handle
	fr_event_list_t		*el;			//!< Event list for timers and I/O events.
	char const		*log_prefix;		//!< Prefix to add to log messages.
	void			*uctx;			//!< User data.

	bool			in_handler;		//!< Connection is currently in a callback.
	bool			deferred_free;		//!< Something freed the connection.
	bool			is_closed;		//!< The close callback has previously been called.

	fr_dlist_head_t		watch_pre[FR_CONNECTION_STATE_MAX];	//!< Function called before state callback.
	fr_dlist_head_t		watch_post[FR_CONNECTION_STATE_MAX];	//!< Function called after state callback.

	fr_connection_init_t	init;			//!< Callback for initialising a connection.
	fr_connection_open_t	open;			//!< Callback for 'open' notification.
	fr_connection_close_t	close;			//!< Callback to close a connection.
	fr_connection_failed_t	failed;			//!< Callback for 'failed' notification.



	fr_event_timer_t const	*connection_timer;	//!< Timer to prevent connections going on indefinitely.
	fr_event_timer_t const	*reconnection_timer;	//!< Timer to delay retries.

	fr_time_delta_t		connection_timeout;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_CONNECTING state.
	fr_time_delta_t		reconnection_delay;	//!< How long to wait in the
							//!< #FR_CONNECTION_STATE_FAILED state.
};

#define STATE_TRANSITION(_new) \
do { \
	DEBUG4("Changed state %s -> %s", \
	       fr_table_str_by_value(fr_connection_states, conn->state, "<INVALID>"), \
	       fr_table_str_by_value(fr_connection_states, _new, "<INVALID>")); \
	conn->state = _new; \
} while (0)

/** Called when we enter a handler
 *
 */
#define HANDLER_BEGIN(_conn) (_conn)->in_handler = true

/** Called when we exit a handler
 *
 */
#define HANDLER_END(_conn) \
do { \
	(_conn)->in_handler = false; \
	if ((_conn)->deferred_free) { \
		talloc_free(_conn); \
		return; \
	} \
} while(0)

/** Call a list of watch functions associated with a state
 *
 */
static inline void connection_watch_call(fr_connection_t *conn, fr_dlist_head_t *list)
{
	fr_connection_watch_entry_t *entry = NULL;

	if (conn->deferred_free) return;	/* If something freed the connection then don't call more watchers */

	while ((entry = fr_dlist_next(list, entry))) {
		entry->func(conn, conn->state, entry->uctx);
		if (entry->oneshot) {
			fr_connection_watch_entry_t *to_free = entry;
			entry = fr_dlist_remove(list, entry);
			talloc_free(to_free);
		}
	}
}

/** Call the pre handler watch functions
 *
 */
#define WATCH_PRE(_conn) \
do { \
	if (fr_dlist_empty(&(_conn)->watch_pre[(_conn)->state])) break; \
	HANDLER_BEGIN(conn); \
	connection_watch_call((_conn), &(_conn)->watch_pre[(_conn)->state]); \
	HANDLER_END(conn); \
} while(0)

/** Call the post handler watch functions
 *
 */
#define WATCH_POST(_conn) \
do { \
	if (fr_dlist_empty(&(_conn)->watch_post[(_conn)->state])) break; \
	HANDLER_BEGIN(conn); \
	connection_watch_call((_conn), &(_conn)->watch_post[(_conn)->state]); \
	HANDLER_END(conn); \
} while(0)

/*
 *	State transition functions
 */
static void connection_state_failed_enter(fr_connection_t *conn, fr_time_t now);
static void connection_state_timeout_enter(fr_connection_t *conn, fr_time_t now);
static void connection_state_connected_enter(fr_connection_t *conn, fr_time_t now);
static void connection_state_connecting_enter(fr_connection_t *conn, fr_time_t now);
static void connection_state_halted_enter(fr_connection_t *conn, fr_time_t now);
static void connection_state_init_enter(fr_connection_t *conn, fr_time_t now);

/** Get the event list associated with the connection
 *
 * @param[in] conn	to retrieve the event list from.
 * @return the event list associated with the connection.
 */
fr_event_list_t *fr_connection_get_el(fr_connection_t const *conn)
{
	return conn->el;
}

/** Get the handle associated with a connection
 *
 * @param[in] conn	to retrieve fd from.
 * @return the active connection handle.
 */
void *fr_connection_get_handle(fr_connection_t const *conn)
{
	return conn->h;
}

/** Set the handle associated with a connection
 *
 * Will not free the previous handle.  This must be done manually.
 *
 * @param[in] conn	to set fd for.
 * @param[in] handle	to set.
 */
void fr_connection_set_handle(fr_connection_t *conn, void *handle)
{
	conn->h = handle;
}

/** Set an (optional) callback to be called on connection timeout/failure
 *
 */
void fr_connection_set_failed_func(fr_connection_t *conn, fr_connection_failed_t func)
{
	conn->failed = func;
}

/** Remove a watch function from a pre/post[state] list
 *
 */
static int connection_del_watch(fr_dlist_head_t *list, fr_connection_watch_t watch)
{
	fr_connection_watch_entry_t	*entry = NULL;

	while ((entry = fr_dlist_next(list, entry))) {
		if (entry->func == watch) {
			fr_dlist_remove(list, entry);
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

	return connection_del_watch(&conn->watch_pre[state], watch);
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

	return connection_del_watch(&conn->watch_post[state], watch);
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
 */
void fr_connection_add_watch_pre(fr_connection_t *conn, fr_connection_state_t state,
				 fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	if (state >= FR_CONNECTION_STATE_MAX) return;

	connection_add_watch(conn, &conn->watch_pre[state], watch, oneshot, uctx);
}

/** Add a callback to be executed after a state function has been called
 *
 * @param[in] conn	to add watcher to.
 * @param[in] state	to call watcher on entering.
 * @param[in] watch	function to call.
 * @param[in] oneshot	If true, remove the function after calling.
 */
void fr_connection_add_watch_post(fr_connection_t *conn, fr_connection_state_t state,
				  fr_connection_watch_t watch, bool oneshot, void const *uctx)
{
	if (state >= FR_CONNECTION_STATE_MAX) return;

	connection_add_watch(conn, &conn->watch_pre[state], watch, oneshot, uctx);
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
	 *	Don't allow the connection to be
	 *	arbitrarily freed by a callback.
	 *
	 *	Set the deferred free flag, and
	 *	free the connection afterwards.
	 */
	if (conn->in_handler) {
		conn->deferred_free = true;
		return 1;
	}

	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		break;

	default:
		connection_state_halted_enter(conn, fr_time());
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
 * @param[in] connection_timeout	(optional) how long to wait for a connection to open.
 * @param[in] reconnection_delay	How long to wait on connection failure before retrying.
 * @param[in] init		(optional) callback to initialise a new file descriptor.
 * @param[in] open		(optional) callback to receive notifications that the connection is open.
 * @param[in] close		(optional) Callback to close the connection.
 * @param[in] log_prefix	To prepend to log messages.
 * @param[in] uctx		User context to pass to callbacks.
 * @return
 *	- A new #fr_connection_t on success.
 *	- NULL on failure.
 */
fr_connection_t *fr_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
				     fr_time_delta_t connection_timeout,
				     fr_time_delta_t reconnection_delay,
				     fr_connection_init_t init, fr_connection_open_t open, fr_connection_close_t close,
				     char const *log_prefix,
				     void const *uctx)
{
	size_t i;
	fr_connection_t *conn;

	rad_assert(el);

	conn = talloc_zero(ctx, fr_connection_t);
	if (!conn) return NULL;
	talloc_set_destructor(conn, _connection_free);

	conn->id = atomic_fetch_add_explicit(&connection_counter, 1, memory_order_relaxed);
	conn->state = FR_CONNECTION_STATE_HALTED;
	conn->el = el;
	conn->h = NULL;
	conn->reconnection_delay = reconnection_delay;
	conn->connection_timeout = connection_timeout;
	conn->init = init;
	conn->open = open;
	conn->close = close;
	conn->log_prefix = talloc_typed_strdup(conn, log_prefix);
	memcpy(&conn->uctx, &uctx, sizeof(conn->uctx));

	for (i = 0; i < NUM_ELEMENTS(conn->watch_pre); i++) {
		fr_dlist_talloc_init(&conn->watch_pre[i], fr_connection_watch_entry_t, list);
	}
	for (i = 0; i < NUM_ELEMENTS(conn->watch_post); i++) {
		fr_dlist_talloc_init(&conn->watch_post[i], fr_connection_watch_entry_t, list);
	}

	return conn;
}

/** The requisite period of time has passed, try and re-open the connection
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	the current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _reconnect_delay_done(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	connection_state_init_enter(conn, now);
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
 * @param[in] now	The current time.
 */
static void connection_state_failed_enter(fr_connection_t *conn, fr_time_t now)
{
	fr_connection_state_t prev;

	rad_assert(conn->state != FR_CONNECTION_STATE_FAILED);

	/*
	 *	Explicit error occurred, delete the connection timer
	 */
	fr_event_timer_delete(conn->el, &conn->connection_timer);

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
	 *	If there's a close callback, call it, so that the
	 *	API client can free any resources associated
	 *	with the connection handle.
	 */
	WATCH_PRE(conn);
	if (conn->close && !conn->is_closed) {
		HANDLER_BEGIN(conn);
		DEBUG4("Calling close(%p, %p)", conn->h, conn->uctx);
		conn->close(conn->h, conn->uctx);
		conn->is_closed = true;		/* Ensure close doesn't get called twice if the connection is freed */
		HANDLER_END(conn);
	} else {
		conn->is_closed = true;
	}
	WATCH_POST(conn);

	/*
	 *	If there's a failed callback, give it the
	 *	opportunity to suspend/destroy the
	 *	connection.
	 */
	if (conn->failed) {
		fr_connection_state_t ret;

		HANDLER_BEGIN(conn);
		DEBUG4("Calling failed(%p, %s, %p)", conn->h,
		       fr_table_str_by_value(fr_connection_states, prev, "<INVALID>"), conn->uctx);
		ret = conn->failed(conn->h, prev, conn->uctx);
		HANDLER_END(conn);
		switch (ret) {
		case FR_CONNECTION_STATE_INIT:
			break;

		case FR_CONNECTION_STATE_HALTED:
		default:
			connection_state_halted_enter(conn, now);
			return;
		}
	}

	switch (prev) {
	case FR_CONNECTION_STATE_INIT:				/* Failed during initialisation */
	case FR_CONNECTION_STATE_CONNECTED:			/* Failed after connecting */
	case FR_CONNECTION_STATE_CONNECTING:			/* Failed during connecting */
		if (fr_event_timer_at(conn, conn->el, &conn->reconnection_timer,
				      now + conn->reconnection_delay, _reconnect_delay_done, conn) < 0) {
			PERROR("Failed inserting delay timer event");
			rad_assert(0);
		}
		break;

	case FR_CONNECTION_STATE_TIMEOUT:			/* Failed during connecting */
		connection_state_init_enter(conn, now);
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
static void connection_state_timeout_enter(fr_connection_t *conn, fr_time_t now)
{
	ERROR("Connection failed - timed out after %pVs", fr_box_time_delta(conn->connection_timeout));

	STATE_TRANSITION(FR_CONNECTION_STATE_TIMEOUT);

	connection_state_failed_enter(conn, now);
}

/** Enter the halted state
 *
 * Here we wait, until signalled by fr_connection_signal_reconnect.
 */
static void connection_state_halted_enter(fr_connection_t *conn, UNUSED fr_time_t now)
{
	STATE_TRANSITION(FR_CONNECTION_STATE_HALTED);

	WATCH_PRE(conn);
	if (conn->close && !conn->is_closed) {
		DEBUG4("Calling close(%p, %p)", conn->h, conn->uctx);
		conn->close(conn->h, conn->uctx);
	}
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
 * @param[in] now	The current time.
 */
static void connection_state_connected_enter(fr_connection_t *conn, UNUSED fr_time_t now)
{
	int	ret;

	rad_assert(conn->state == FR_CONNECTION_STATE_CONNECTING);

	STATE_TRANSITION(FR_CONNECTION_STATE_CONNECTED);

	fr_event_timer_delete(conn->el, &conn->connection_timer);

	WATCH_PRE(conn);
	if (conn->open) {
		HANDLER_BEGIN(conn);
		DEBUG4("Calling open(%p, %p, %p)", conn->el, conn->h, conn->uctx);
		ret = conn->open(conn->el, conn->h, conn->uctx);
		HANDLER_END(conn);
	} else {
		ret = FR_CONNECTION_STATE_CONNECTED;
	}
	WATCH_POST(conn);


	switch (ret) {
	/*
	 *	Callback agrees everything is connected
	 */
	case FR_CONNECTION_STATE_CONNECTED:
		DEBUG2("Connection established");
		return;

	/*
	 *	Open callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
	default:
		PERROR("Connection failed");
		connection_state_failed_enter(conn, fr_time());
		return;
	}
}

/** Connection timeout
 *
 * Connection wasn't opened within the configured period of time
 *
 * @param[in] el	the time event ocurred on.
 * @param[in] now	the current time.
 * @param[in] uctx	The #fr_connection_t the fd is associated with.
 */
static void _connection_timeout(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_connection_t *conn = talloc_get_type_abort(uctx, fr_connection_t);

	connection_state_timeout_enter(conn, now);
}

/** Enter the connecting state
 *
 * After this function returns we wait to be signalled with fr_connection_singal_connected
 * or for the connection timer to expire.
 *
 * @param[in] conn	Entering the connecting state.
 * @param[in] now	The current time.
 */
static void connection_state_connecting_enter(fr_connection_t *conn, fr_time_t now)
{
	rad_assert(conn->state == FR_CONNECTION_STATE_INIT);

	STATE_TRANSITION(FR_CONNECTION_STATE_CONNECTING);

	WATCH_PRE(conn);
	WATCH_POST(conn);

	/*
	 *	If there's a connection timeout,
	 *	set, then add the timer.
	 */
	if (conn->connection_timeout) {
		if (fr_event_timer_at(conn, conn->el, &conn->connection_timer,
				      now + conn->connection_timeout,
				      _connection_timeout, conn) < 0) {
			PERROR("Failed inserting connection timeout event");
			rad_assert(0);
		}
	}
}

/** Initial state of the connection
 *
 * Calls the init function we were passed to allocate a library specific handle or
 * file descriptor.
 *
 * @param[in] conn	To initialise.
 * @param[in] now	The current time.
 */
static void connection_state_init_enter(fr_connection_t *conn, fr_time_t now)
{
	fr_connection_state_t	ret;

	rad_assert((conn->state == FR_CONNECTION_STATE_HALTED) || (conn->state == FR_CONNECTION_STATE_FAILED));

	STATE_TRANSITION(FR_CONNECTION_STATE_INIT);

	/*
	 *	If we have an init callback, call it.
	 */
	WATCH_PRE(conn);
	if (conn->init) {
		HANDLER_BEGIN(conn);
		DEBUG4("Calling init(%p, %p, %p)", &conn->h, conn, conn->uctx);
		ret = conn->init(&conn->h, conn, conn->uctx);
		HANDLER_END(conn);
	} else {
		ret = FR_CONNECTION_STATE_CONNECTING;
	}
	WATCH_POST(conn);

	switch (ret) {
	case FR_CONNECTION_STATE_CONNECTING:
		conn->is_closed = false;	/* We now have a handle */
		connection_state_connecting_enter(conn, now);
		return;

	/*
	 *	Initialisation callback failed
	 */
	case FR_CONNECTION_STATE_FAILED:
	default:
		PERROR("Connection initialisation failed");
		connection_state_failed_enter(conn, now);
		break;
	}
}

/** Asynchronously signal a halted connection to start
 *
 */
void fr_connection_signal_init(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_HALTED:
		connection_state_init_enter(conn, fr_time());
		return;

	default:
		return;
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
	rad_assert(!conn->open);	/* Use one or the other not both! */

	switch (conn->state) {
	case FR_CONNECTION_STATE_CONNECTING:
		DEBUG2("Connection established");
		connection_state_connected_enter(conn, fr_time());
		return;

	default:
		return;
	}
}

/** Asynchronously signal the connection should be reconnected
 *
 * Should be called if the caller has knowledge that the connection is bad
 * and should be reconnected.
 *
 * @param[in] conn		to reconnect.
 */
void fr_connection_signal_reconnect(fr_connection_t *conn)
{
	switch (conn->state) {
	case FR_CONNECTION_STATE_FAILED:	/* Don't circumvent reconnection_delay */
	case FR_CONNECTION_STATE_INIT:		/* Already initialising */
		break;

	case FR_CONNECTION_STATE_HALTED:
		fr_connection_signal_init(conn);
		return;

	case FR_CONNECTION_STATE_CONNECTING:
	case FR_CONNECTION_STATE_CONNECTED:
	case FR_CONNECTION_STATE_TIMEOUT:
		DEBUG2("Reconnecting...");
		connection_state_failed_enter(conn, fr_time());
		return;

	case FR_CONNECTION_STATE_MAX:
		rad_assert(0);
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
	connection_state_failed_enter(conn, fr_time());
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
	connection_state_connected_enter(conn, fr_time());
}

/** Remove the FD we were watching for connection open/fail from the event loop
 *
 */
static void _connection_signal_on_fd_cleanup(fr_connection_t *conn, fr_connection_state_t state, void *uctx)
{
	int fd = *((int *)uctx);

	/*
	 *	Two states can trigger a cleanup
	 *	Remove the watch on the one that didn't
	 */
	switch (state) {
	case FR_CONNECTION_STATE_FAILED:
		fr_connection_del_watch_pre(conn, FR_CONNECTION_STATE_CONNECTED, _connection_signal_on_fd_cleanup);
		break;

	case FR_CONNECTION_STATE_CONNECTED:
		fr_connection_del_watch_pre(conn, FR_CONNECTION_STATE_FAILED, _connection_signal_on_fd_cleanup);
		break;

	default:
		rad_assert(0);
		break;
	}

	fr_event_fd_delete(conn->el, fd, FR_EVENT_FILTER_IO);
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
	fr_time_t	now = fr_time();
	int		*fd_s;

	/*
	 *	If connection becomes writable we
	 *	assume it's open.
	 */
	if (fr_event_fd_insert(conn, conn->el, fd,
			       NULL,
			       _connection_writable,
			       _connection_error,
			       conn) < 0) {
		PERROR("Failed inserting fd (%u) into event loop %p",
		       fd, conn->el);
		connection_state_failed_enter(conn, now);
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
	fr_connection_add_watch_pre(conn, FR_CONNECTION_STATE_FAILED,
				    _connection_signal_on_fd_cleanup, true, fd_s);
	fr_connection_add_watch_pre(conn, FR_CONNECTION_STATE_CONNECTED,
				    _connection_signal_on_fd_cleanup, true, fd_s);

	return 0;
}
